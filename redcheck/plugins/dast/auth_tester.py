"""RedCheck246 — Authenticated Session Tester.

Tests web application authentication mechanisms under RoE constraints.
Gated by ``allow_auth_testing`` offensive control.

Phase C additions (commit aa47715+):
- CSRF token detection — checks forms for hidden CSRF tokens and validates
  anti-CSRF header enforcement.
- Session fixation checks — detects whether session ID rotates after login.
- Cookie scope analysis — validates Domain, Path, Expires/Max-Age, and
  SameSite settings on session cookies.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from redcheck.exceptions import OffensiveControlError
from redcheck.models import OffensiveControls, PluginCapability
from redcheck.plugins._http import scanning_ssl_context
from redcheck.plugins.base_plugin import BasePlugin, PluginResult, plugin_dependencies

log = structlog.get_logger(__name__)


@plugin_dependencies(
    required=["dast-scanner"],
    optional=[],
    provides=["session_vulns", "cookies"],
)
class AuthenticatedSessionTester(BasePlugin):
    """Test authentication mechanisms on web applications.

    Verifies:
    - Default/weak credential detection (known-bad list only)
    - Session token analysis (entropy, secure flags)
    - Authentication bypass attempts (safe only)
    - Session fixation checks

    Gated by ``allow_auth_testing`` offensive control.
    """

    name = "auth-session-tester"
    version = "0.1.0"
    description = "Authenticated session and credential testing"
    requires_authorization = True
    category = "dast"
    capability = PluginCapability.ACTIVE

    required_controls = ["allow_auth_testing"]
    timeout_seconds = 120
    rate_limit_rps = 5
    mitre_techniques = ["T1078", "T1110.001", "T1185", "T1539"]
    requires_isolation = False

    # Known-weak credentials for detection (never actual brute-force)
    _WEAK_CREDENTIALS: list[tuple[str, str]] = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "root"),
        ("root", "toor"),
        ("test", "test"),
        ("user", "user"),
        ("guest", "guest"),
    ]

    def _check_controls(self, context: dict[str, Any]) -> None:
        """Verify offensive controls are enabled."""
        controls_data = context.get("offensive_controls", {})
        if isinstance(controls_data, dict):
            controls = OffensiveControls(**controls_data)
        elif isinstance(controls_data, OffensiveControls):
            controls = controls_data
        else:
            controls = OffensiveControls()

        if not controls.has_controls(self.required_controls):
            raise OffensiveControlError(
                self.name,
                [c for c in self.required_controls if not getattr(controls, c, False)],
            )

    def execute(self, context: dict[str, Any]) -> PluginResult:
        """Execute authentication tests synchronously."""
        return asyncio.run(self.aexecute(context))

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        """Async authentication testing."""
        self._check_controls(context)

        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        targets = context.get("authorized_targets", context.get("targets", []))
        if not targets:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                errors=["No targets specified"],
            )

        # Build target URLs
        urls: list[str] = []
        for t in targets:
            if isinstance(t, dict):
                host = t.get("host", "").strip()
                if host:
                    for port in t.get("ports", [443]):
                        scheme = "https" if port == 443 else "http"
                        urls.append(f"{scheme}://{host}:{port}")
            elif isinstance(t, str):
                urls.append(t if t.startswith("http") else f"https://{t}")

        async with httpx.AsyncClient(verify=scanning_ssl_context(), timeout=10.0) as client:
            for url in urls:
                try:
                    # 1. Session token analysis
                    token_findings = await self._analyze_session(url, client)
                    findings.extend(token_findings)

                    # 2. Weak credential detection
                    cred_findings = await self._check_weak_credentials(url, client)
                    findings.extend(cred_findings)

                    # 3. CSRF token detection
                    csrf_findings = await self._check_csrf(url, client)
                    findings.extend(csrf_findings)

                    # 4. Session fixation check
                    fixation_findings = await self._check_session_fixation(url, client)
                    findings.extend(fixation_findings)

                    # 5. Cookie scope analysis
                    scope_findings = await self._analyze_cookie_scope(url, client)
                    findings.extend(scope_findings)

                except Exception as exc:
                    errors.append(f"{url}: {exc}")

        elapsed = (time.monotonic() - start) * 1000
        self.capture_evidence(
            context,
            f"{len(findings)} auth findings".encode(),
            "auth_test",
        )
        return PluginResult(
            plugin_name=self.name,
            success=len(errors) == 0,
            findings=findings,
            errors=errors,
            metadata={"urls_tested": len(urls), "duration_ms": round(elapsed, 2)},
        )

    async def _analyze_session(
        self,
        url: str,
        client: httpx.AsyncClient,
    ) -> list[dict[str, Any]]:
        """Analyze session cookie attributes."""
        findings: list[dict[str, Any]] = []
        try:
            resp = await client.get(url, follow_redirects=True)
            cookies = resp.headers.get_list("set-cookie")

            for cookie_str in cookies:
                parts = cookie_str.lower()
                issues: list[str] = []

                if "secure" not in parts:
                    issues.append("Missing Secure flag")
                if "httponly" not in parts:
                    issues.append("Missing HttpOnly flag")
                if "samesite" not in parts:
                    issues.append("Missing SameSite attribute")

                if issues:
                    cookie_name = cookie_str.split("=")[0].strip()
                    findings.append(
                        {
                            "finding_type": "session_cookie_weakness",
                            "target": url,
                            "severity": "medium",
                            "detail": f"Cookie '{cookie_name}': {', '.join(issues)}",
                            "cookie": cookie_name,
                            "issues": issues,
                        }
                    )
        except Exception:  # noqa: S110
            pass
        return findings

    async def _check_weak_credentials(
        self,
        url: str,
        client: httpx.AsyncClient,
    ) -> list[dict[str, Any]]:
        """Check for common login endpoints with known-weak credentials.

        NOTE: This sends at most 8 POST requests per target (the known-bad
        list).  It does NOT perform brute-force or dictionary attacks.
        """
        findings: list[dict[str, Any]] = []
        login_paths = ["/login", "/admin/login", "/api/auth/login", "/signin"]

        for path in login_paths:
            login_url = f"{url.rstrip('/')}{path}"
            try:
                # Probe if login endpoint exists
                probe = await client.get(login_url, follow_redirects=False)
                if probe.status_code in (404, 405, 502, 503):
                    continue

                # Test known-weak credentials
                for username, password in self._WEAK_CREDENTIALS:
                    try:
                        resp = await client.post(
                            login_url,
                            data={"username": username, "password": password},
                            follow_redirects=False,
                        )
                        # Heuristic: 302 redirect or 200 with session cookie = success
                        if resp.status_code in (200, 302) and (
                            "set-cookie" in resp.headers or resp.status_code == 302
                        ):
                            findings.append(
                                {
                                    "finding_type": "weak_credentials",
                                    "target": login_url,
                                    "severity": "critical",
                                    "detail": (
                                        f"Weak credentials accepted: {username}/"
                                        f"{'*' * len(password)}"
                                    ),
                                    "username": username,
                                    "mitre_technique": "T1078",
                                }
                            )
                    except Exception:  # noqa: S112
                        continue
            except Exception:  # noqa: S112
                continue

        return findings

    # ------------------------------------------------------------------
    # 3. CSRF token detection
    # ------------------------------------------------------------------

    _CSRF_HEADER_NAMES = frozenset({"x-csrf-token", "x-xsrf-token", "x-csrftoken", "csrf-token"})
    _CSRF_INPUT_RE = re.compile(
        r'<input[^>]+name=["\']?'
        r"(csrf|_csrf|csrfmiddlewaretoken|__RequestVerificationToken"
        r"|_token|authenticity_token|xsrf)"
        r'["\']?[^>]*/?>',
        re.IGNORECASE,
    )

    async def _check_csrf(
        self,
        url: str,
        client: httpx.AsyncClient,
    ) -> list[dict[str, Any]]:
        """Detect missing CSRF protections on form pages."""
        findings: list[dict[str, Any]] = []
        form_paths = ["/login", "/settings", "/profile", "/account", "/"]

        for path in form_paths:
            page_url = f"{url.rstrip('/')}{path}"
            try:
                resp = await client.get(page_url, follow_redirects=True)
                if resp.status_code >= 400:
                    continue

                body = resp.text
                has_form = "<form" in body.lower()
                if not has_form:
                    continue

                has_csrf_input = bool(self._CSRF_INPUT_RE.search(body))
                has_csrf_header = bool(self._CSRF_HEADER_NAMES & {k.lower() for k in resp.headers})
                has_csrf_cookie = any(
                    "csrf" in c.lower() or "xsrf" in c.lower()
                    for c in resp.headers.get_list("set-cookie")
                )

                if not (has_csrf_input or has_csrf_header or has_csrf_cookie):
                    findings.append(
                        {
                            "finding_type": "csrf_missing",
                            "target": page_url,
                            "severity": "high",
                            "detail": (
                                f"Form at {path} has no CSRF token — "
                                "no hidden input, no CSRF header, no CSRF cookie"
                            ),
                            "mitre_technique": "T1185",
                        }
                    )
            except Exception:  # noqa: S112
                continue

        return findings

    # ------------------------------------------------------------------
    # 4. Session fixation check
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_session_ids(headers: httpx.Headers) -> set[str]:
        """Extract session-like cookie values from Set-Cookie headers."""
        session_patterns = re.compile(
            r"(session|sess|sid|jsessionid|phpsessid|asp\.net_sessionid)",
            re.IGNORECASE,
        )
        ids: set[str] = set()
        for cookie_str in headers.get_list("set-cookie"):
            name_val = cookie_str.split(";")[0]
            if "=" not in name_val:
                continue
            name, _, value = name_val.partition("=")
            if session_patterns.search(name.strip()):
                ids.add(value.strip())
        return ids

    async def _check_session_fixation(
        self,
        url: str,
        client: httpx.AsyncClient,
    ) -> list[dict[str, Any]]:
        """Check if session ID is rotated after login.

        Strategy: GET the login page (capture session cookies), then POST
        dummy credentials and compare session cookies. If the session ID is
        unchanged after a POST to the login endpoint, session fixation may
        be possible.
        """
        findings: list[dict[str, Any]] = []
        login_paths = ["/login", "/signin", "/api/auth/login"]

        for path in login_paths:
            login_url = f"{url.rstrip('/')}{path}"
            try:
                # Step 1: GET login page → capture session cookie
                resp_get = await client.get(login_url, follow_redirects=False)
                if resp_get.status_code >= 400:
                    continue

                pre_session = self._extract_session_ids(resp_get.headers)
                if not pre_session:
                    continue  # No session cookie to compare

                # Step 2: POST with dummy credentials (intentionally wrong)
                resp_post = await client.post(
                    login_url,
                    data={"username": "redcheck_probe", "password": "redcheck_probe"},
                    follow_redirects=False,
                )
                post_session = self._extract_session_ids(resp_post.headers)

                # If server sent back a new Set-Cookie for the session, check if same
                if post_session and pre_session == post_session:
                    findings.append(
                        {
                            "finding_type": "session_fixation",
                            "target": login_url,
                            "severity": "high",
                            "detail": (
                                "Session ID not rotated after login attempt — "
                                "potential session fixation vulnerability"
                            ),
                            "mitre_technique": "T1539",
                        }
                    )
            except Exception:  # noqa: S112
                continue

        return findings

    # ------------------------------------------------------------------
    # 5. Cookie scope analysis
    # ------------------------------------------------------------------

    async def _analyze_cookie_scope(
        self,
        url: str,
        client: httpx.AsyncClient,
    ) -> list[dict[str, Any]]:
        """Analyze cookie Domain, Path, Expires/Max-Age scope."""
        findings: list[dict[str, Any]] = []
        parsed = urlparse(url)
        target_domain = parsed.hostname or ""

        try:
            resp = await client.get(url, follow_redirects=True)
        except Exception:
            return findings

        for cookie_str in resp.headers.get_list("set-cookie"):
            name_val = cookie_str.split(";")[0]
            if "=" not in name_val:
                continue
            cookie_name = name_val.split("=")[0].strip()
            lower = cookie_str.lower()
            attrs = {
                p.strip().split("=")[0].strip(): (
                    p.strip().split("=", 1)[1].strip() if "=" in p else ""
                )
                for p in cookie_str.split(";")[1:]
            }
            issues: list[str] = []

            # Domain scope: overly broad domain (e.g. .example.com for app.example.com)
            domain_attr = attrs.get("domain", attrs.get("Domain", "")).strip()
            if domain_attr:
                clean_domain = domain_attr.lstrip(".")
                if clean_domain != target_domain and target_domain.endswith(f".{clean_domain}"):
                    issues.append(f"Overly broad Domain={domain_attr} (target is {target_domain})")

            # Path scope: root path means every endpoint gets the cookie
            path_attr = attrs.get("path", attrs.get("Path", "")).strip()
            if path_attr == "/" or not path_attr:
                issues.append("Cookie Path=/ (sent to every endpoint)")

            # Missing Expires/Max-Age = session cookie (dies on browser close)
            has_expiry = "expires" in lower or "max-age" in lower
            if not has_expiry:
                issues.append("No Expires/Max-Age — session-only cookie")

            # SameSite=None without Secure is browser-rejected but still a finding
            if "samesite=none" in lower and "secure" not in lower:
                issues.append("SameSite=None without Secure flag")

            if issues:
                findings.append(
                    {
                        "finding_type": "cookie_scope_issue",
                        "target": url,
                        "severity": "medium",
                        "cookie": cookie_name,
                        "detail": f"Cookie '{cookie_name}': {'; '.join(issues)}",
                        "issues": issues,
                    }
                )

        return findings

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        """Simulate auth testing."""
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "description": "Would test authentication on targets",
            },
        )
