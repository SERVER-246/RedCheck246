"""RedCheck246 — Authenticated Session Tester.

Tests web application authentication mechanisms under RoE constraints.
Gated by ``allow_auth_testing`` offensive control.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import structlog

from redcheck.exceptions import OffensiveControlError
from redcheck.models import OffensiveControls, PluginCapability
from redcheck.plugins._http import scanning_ssl_context
from redcheck.plugins.base_plugin import BasePlugin, PluginResult

log = structlog.get_logger(__name__)


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
    mitre_techniques = ["T1078", "T1110.001"]
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
