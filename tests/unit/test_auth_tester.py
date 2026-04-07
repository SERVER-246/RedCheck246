"""Tests for redcheck.plugins.dast.auth_tester — AuthenticatedSessionTester.

Coverage: control gating, session cookie analysis, weak credential detection,
dry run, URL building, error handling.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from redcheck.exceptions import OffensiveControlError
from redcheck.models import OffensiveControls, PluginCapability
from redcheck.plugins.dast.auth_tester import AuthenticatedSessionTester

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _context(
    *,
    allow_auth: bool = True,
    targets: list[Any] | None = None,
) -> dict[str, Any]:
    """Build a plugin context dict."""
    ctx: dict[str, Any] = {
        "offensive_controls": {"allow_auth_testing": allow_auth},
    }
    if targets is not None:
        ctx["targets"] = targets
    else:
        ctx["targets"] = ["https://target.local:443"]
    return ctx


class _FakeTransport(httpx.AsyncBaseTransport):
    """Transport returning canned responses keyed by (method, path)."""

    def __init__(self, responses: dict[tuple[str, str], httpx.Response]) -> None:
        self._responses = responses

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path or "/"
        method = request.method.upper()
        key = (method, path)

        if key in self._responses:
            return self._responses[key]
        # Fallback to GET
        if ("GET", path) in self._responses:
            return self._responses[("GET", path)]
        return httpx.Response(404, text="Not found")


# ---------------------------------------------------------------------------
# Control gating
# ---------------------------------------------------------------------------


class TestAuthTesterControlGating:
    """Auth tester must reject execution without offensive controls."""

    def test_rejects_without_allow_auth_testing(self):
        plugin = AuthenticatedSessionTester()
        ctx = _context(allow_auth=False)
        with pytest.raises(OffensiveControlError):
            plugin.execute(ctx)

    def test_accepts_with_allow_auth_testing(self):
        plugin = AuthenticatedSessionTester()
        # No targets → returns success=False with "No targets specified"
        ctx = _context(allow_auth=True, targets=[])
        result = plugin.execute(ctx)
        assert not result.success
        assert "No targets specified" in result.errors

    def test_rejects_empty_controls(self):
        plugin = AuthenticatedSessionTester()
        with pytest.raises(OffensiveControlError):
            plugin.execute({"offensive_controls": {}})

    def test_accepts_controls_object(self):
        plugin = AuthenticatedSessionTester()
        ctx = {
            "offensive_controls": OffensiveControls(allow_auth_testing=True),
            "targets": [],
        }
        result = plugin.execute(ctx)
        assert not result.success


# ---------------------------------------------------------------------------
# Plugin metadata
# ---------------------------------------------------------------------------


class TestAuthTesterMetadata:
    def test_name(self):
        assert AuthenticatedSessionTester.name == "auth-session-tester"

    def test_capability(self):
        assert AuthenticatedSessionTester.capability == PluginCapability.ACTIVE

    def test_required_controls(self):
        assert "allow_auth_testing" in AuthenticatedSessionTester.required_controls

    def test_mitre_techniques(self):
        plugin = AuthenticatedSessionTester()
        assert "T1078" in plugin.mitre_techniques
        assert "T1110.001" in plugin.mitre_techniques


# ---------------------------------------------------------------------------
# Session cookie analysis
# ---------------------------------------------------------------------------


class TestSessionCookieAnalysis:
    """Tests for _analyze_session via mock transport."""

    def _run_session_analysis(
        self,
        cookies: list[str],
    ) -> list[dict[str, Any]]:
        """Run session analysis with mock cookies."""

        async def run():
            responses = {
                ("GET", "/"): httpx.Response(
                    200,
                    text="<html></html>",
                    headers=[("set-cookie", c) for c in cookies],
                ),
            }
            transport = _FakeTransport(responses)
            async with httpx.AsyncClient(transport=transport) as client:
                plugin = AuthenticatedSessionTester()
                return await plugin._analyze_session("https://target.local", client)

        return asyncio.run(run())

    def test_detects_missing_secure_flag(self):
        findings = self._run_session_analysis(["session=abc; HttpOnly; SameSite=Lax"])
        assert any("Secure" in f["detail"] for f in findings)

    def test_detects_missing_httponly(self):
        findings = self._run_session_analysis(["session=abc; Secure; SameSite=Lax"])
        assert any("HttpOnly" in f["detail"] for f in findings)

    def test_detects_missing_samesite(self):
        findings = self._run_session_analysis(["session=abc; Secure; HttpOnly"])
        assert any("SameSite" in f["detail"] for f in findings)

    def test_all_flags_present_no_findings(self):
        findings = self._run_session_analysis(["session=abc; Secure; HttpOnly; SameSite=Strict"])
        assert len(findings) == 0

    def test_no_cookies_no_findings(self):
        findings = self._run_session_analysis([])
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Weak credentials (mock)
# ---------------------------------------------------------------------------


class TestWeakCredentialDetection:
    """Tests for _check_weak_credentials via mock transport."""

    def _run_cred_check(
        self,
        login_probe_status: int = 200,
        post_status: int = 401,
    ) -> list[dict[str, Any]]:
        async def run():
            responses: dict[tuple[str, str], httpx.Response] = {}
            # Probe login endpoint
            responses[("GET", "/login")] = httpx.Response(login_probe_status, text="Login")
            responses[("GET", "/admin/login")] = httpx.Response(404, text="Not found")
            responses[("GET", "/api/auth/login")] = httpx.Response(404, text="Not found")
            responses[("GET", "/signin")] = httpx.Response(404, text="Not found")
            # POST login
            responses[("POST", "/login")] = httpx.Response(post_status, text="")

            transport = _FakeTransport(responses)
            async with httpx.AsyncClient(transport=transport) as client:
                plugin = AuthenticatedSessionTester()
                return await plugin._check_weak_credentials("https://target.local", client)

        return asyncio.run(run())

    def test_no_findings_when_login_returns_401(self):
        findings = self._run_cred_check(login_probe_status=200, post_status=401)
        assert len(findings) == 0

    def test_no_findings_when_login_404(self):
        findings = self._run_cred_check(login_probe_status=404)
        assert len(findings) == 0

    def test_detects_weak_creds_on_302(self):
        """302 redirect = likely successful login."""
        findings = self._run_cred_check(login_probe_status=200, post_status=302)
        assert len(findings) > 0
        assert all(f["finding_type"] == "weak_credentials" for f in findings)


# ---------------------------------------------------------------------------
# Dry run & URL building
# ---------------------------------------------------------------------------


class TestAuthTesterDryRun:
    def test_dry_run(self):
        plugin = AuthenticatedSessionTester()
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata["mode"] == "dry-run"

    def test_url_from_dict_targets(self):
        """Dict-style targets build URLs correctly."""
        plugin = AuthenticatedSessionTester()
        ctx = _context(
            targets=[{"host": "example.com", "ports": [443]}],
        )
        # Execute will try to connect but we just verify no crash
        # (httpx will fail DNS, producing an error but not exception)
        result = plugin.execute(ctx)
        assert result.plugin_name == "auth-session-tester"

    def test_url_from_string_targets(self):
        plugin = AuthenticatedSessionTester()
        ctx = _context(targets=["https://example.com"])
        result = plugin.execute(ctx)
        assert result.plugin_name == "auth-session-tester"


# ---------------------------------------------------------------------------
# CSRF token detection
# ---------------------------------------------------------------------------


class TestCSRFDetection:
    """Tests for _check_csrf — detects missing CSRF tokens on form pages."""

    def _run_csrf_check(
        self,
        body: str,
        *,
        status: int = 200,
        headers: list[tuple[str, str]] | None = None,
    ) -> list[dict[str, Any]]:
        headers = headers or []

        async def run():
            responses = {
                ("GET", "/login"): httpx.Response(status, text=body, headers=headers),
                ("GET", "/settings"): httpx.Response(404, text="Not found"),
                ("GET", "/profile"): httpx.Response(404, text="Not found"),
                ("GET", "/account"): httpx.Response(404, text="Not found"),
                ("GET", "/"): httpx.Response(404, text="Not found"),
            }
            transport = _FakeTransport(responses)
            async with httpx.AsyncClient(transport=transport) as client:
                plugin = AuthenticatedSessionTester()
                return await plugin._check_csrf("https://target.local", client)

        return asyncio.run(run())

    def test_no_form_no_finding(self):
        findings = self._run_csrf_check("<html><body>No forms</body></html>")
        assert len(findings) == 0

    def test_form_without_csrf_token(self):
        body = (
            '<html><body><form action="/login" method="POST">'
            '<input name="username"/></form></body></html>'
        )
        findings = self._run_csrf_check(body)
        assert len(findings) == 1
        assert findings[0]["finding_type"] == "csrf_missing"
        assert findings[0]["severity"] == "high"

    def test_form_with_csrf_hidden_input(self):
        body = (
            '<html><body><form action="/login" method="POST">'
            '<input type="hidden" name="csrf" value="tok123"/>'
            "</form></body></html>"
        )
        findings = self._run_csrf_check(body)
        assert len(findings) == 0

    def test_form_with_csrf_header(self):
        body = '<html><body><form method="POST"><input name="q"/></form></body></html>'
        findings = self._run_csrf_check(body, headers=[("X-CSRF-Token", "abc123")])
        assert len(findings) == 0

    def test_form_with_csrf_cookie(self):
        body = '<html><body><form method="POST"><input name="q"/></form></body></html>'
        findings = self._run_csrf_check(body, headers=[("set-cookie", "csrftoken=abc123; Path=/")])
        assert len(findings) == 0

    def test_404_page_ignored(self):
        findings = self._run_csrf_check("<form></form>", status=404)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Session fixation
# ---------------------------------------------------------------------------


class TestSessionFixation:
    """Tests for _check_session_fixation — detects non-rotating session IDs."""

    def _run_fixation_check(
        self,
        *,
        get_cookies: list[str],
        post_cookies: list[str],
        get_status: int = 200,
        post_status: int = 200,
    ) -> list[dict[str, Any]]:
        async def run():
            responses = {
                ("GET", "/login"): httpx.Response(
                    get_status,
                    text="Login",
                    headers=[("set-cookie", c) for c in get_cookies],
                ),
                ("POST", "/login"): httpx.Response(
                    post_status,
                    text="OK",
                    headers=[("set-cookie", c) for c in post_cookies],
                ),
                ("GET", "/signin"): httpx.Response(404, text="Not found"),
                ("GET", "/api/auth/login"): httpx.Response(404, text="Not found"),
            }
            transport = _FakeTransport(responses)
            async with httpx.AsyncClient(transport=transport) as client:
                plugin = AuthenticatedSessionTester()
                return await plugin._check_session_fixation("https://target.local", client)

        return asyncio.run(run())

    def test_session_rotated_no_finding(self):
        findings = self._run_fixation_check(
            get_cookies=["session=aaa111; Path=/"],
            post_cookies=["session=bbb222; Path=/"],
        )
        assert len(findings) == 0

    def test_session_not_rotated(self):
        findings = self._run_fixation_check(
            get_cookies=["session=aaa111; Path=/"],
            post_cookies=["session=aaa111; Path=/"],
        )
        assert len(findings) == 1
        assert findings[0]["finding_type"] == "session_fixation"
        assert findings[0]["severity"] == "high"

    def test_no_session_cookie_skipped(self):
        findings = self._run_fixation_check(
            get_cookies=["theme=dark; Path=/"],
            post_cookies=["theme=dark; Path=/"],
        )
        assert len(findings) == 0

    def test_login_404_skipped(self):
        findings = self._run_fixation_check(
            get_cookies=["session=aaa; Path=/"],
            post_cookies=["session=aaa; Path=/"],
            get_status=404,
        )
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Cookie scope analysis
# ---------------------------------------------------------------------------


class TestCookieScopeAnalysis:
    """Tests for _analyze_cookie_scope — Domain, Path, Expires, SameSite."""

    def _run_scope_analysis(
        self,
        cookies: list[str],
    ) -> list[dict[str, Any]]:
        async def run():
            responses = {
                ("GET", "/"): httpx.Response(
                    200,
                    text="<html></html>",
                    headers=[("set-cookie", c) for c in cookies],
                ),
            }
            transport = _FakeTransport(responses)
            async with httpx.AsyncClient(transport=transport) as client:
                plugin = AuthenticatedSessionTester()
                return await plugin._analyze_cookie_scope("https://app.example.com", client)

        return asyncio.run(run())

    def test_overly_broad_domain(self):
        findings = self._run_scope_analysis(
            ["session=abc; Domain=.example.com; Path=/app; Secure; HttpOnly"]
        )
        assert any("Overly broad Domain" in f["detail"] for f in findings)

    def test_root_path(self):
        findings = self._run_scope_analysis(
            ["session=abc; Path=/; Expires=Thu, 01 Dec 2026 00:00:00 GMT"]
        )
        assert any("Path=/" in f["detail"] for f in findings)

    def test_no_expiry(self):
        findings = self._run_scope_analysis(["session=abc; Path=/app; Secure"])
        assert any("No Expires/Max-Age" in f["detail"] for f in findings)

    def test_samesite_none_without_secure(self):
        findings = self._run_scope_analysis(["session=abc; SameSite=None; Path=/app; Max-Age=3600"])
        assert any("SameSite=None without Secure" in f["detail"] for f in findings)

    def test_well_scoped_cookie_no_finding(self):
        findings = self._run_scope_analysis(
            [
                "session=abc; Domain=app.example.com; Path=/app; "
                "Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
            ]
        )
        # Only Path=/ or overly broad domain trigger — this should be clean
        # Domain matches target exactly, Path is /app, has Max-Age
        assert not any(f["finding_type"] == "cookie_scope_issue" for f in findings)

    def test_no_cookies_no_findings(self):
        findings = self._run_scope_analysis([])
        assert len(findings) == 0
