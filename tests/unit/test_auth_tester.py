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
