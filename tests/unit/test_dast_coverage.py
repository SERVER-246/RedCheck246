"""Tests for DAST scanner — security headers, SSL, methods, cookies, paths, redirects."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import httpx

from redcheck.plugins.dast.dast_scanner import (
    DASTPlugin,
    _extract_targets,
    check_cookies,
    check_http_methods,
    check_redirects,
    check_security_headers,
    check_ssl_tls,
    discover_paths,
)


class _MockTransport(httpx.BaseTransport):
    def __init__(self, handler):
        self._handler = handler

    def handle_request(self, request):
        return self._handler(request)


class TestExtractTargets:
    def test_string_targets(self) -> None:
        ctx = {"authorized_targets": ["host1", "host2"]}
        result = _extract_targets(ctx)
        assert len(result) == 2
        assert result[0]["host"] == "host1"

    def test_dict_targets(self) -> None:
        ctx = {"authorized_targets": [{"host": "h1", "ports": [80]}]}
        result = _extract_targets(ctx)
        assert result[0]["host"] == "h1"

    def test_empty(self) -> None:
        assert _extract_targets({}) == []


class TestCheckSecurityHeaders:
    def test_missing_headers(self) -> None:
        async def _run() -> None:
            transport = httpx.MockTransport(
                lambda req: httpx.Response(200, headers={}, text="ok")
            )
            with patch(
                "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                findings = await check_security_headers("https://example.com")
            assert len(findings) >= 6  # Most headers missing

        asyncio.run(_run())

    def test_weak_hsts(self) -> None:
        async def _run() -> None:
            headers = {
                "Strict-Transport-Security": "max-age=3600",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
            }
            transport = httpx.MockTransport(
                lambda req: httpx.Response(200, headers=headers, text="ok")
            )
            with patch(
                "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                findings = await check_security_headers("https://example.com")
            weak_hsts = [f for f in findings if f["type"] == "dast_weak_hsts"]
            assert len(weak_hsts) == 1

        asyncio.run(_run())

    def test_weak_csp(self) -> None:
        async def _run() -> None:
            headers = {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
            }
            transport = httpx.MockTransport(
                lambda req: httpx.Response(200, headers=headers, text="ok")
            )
            with patch(
                "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                findings = await check_security_headers("https://example.com")
            weak_csp = [f for f in findings if f["type"] == "dast_weak_csp"]
            assert len(weak_csp) >= 1

        asyncio.run(_run())

    def test_xss_protection_disabled(self) -> None:
        async def _run() -> None:
            headers = {
                "X-XSS-Protection": "0",
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
            }
            transport = httpx.MockTransport(
                lambda req: httpx.Response(200, headers=headers, text="ok")
            )
            with patch(
                "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                findings = await check_security_headers("https://example.com")
            xss = [f for f in findings if f["type"] == "dast_xss_protection_disabled"]
            assert len(xss) == 1

        asyncio.run(_run())

    def test_connection_error(self) -> None:
        async def _run() -> None:
            def _raise(*a: object, **kw: object) -> httpx.Response:
                raise httpx.ConnectError("fail")

            transport = httpx.MockTransport(_raise)
            with patch(
                "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                findings = await check_security_headers("https://example.com")
            assert any("error" in f["type"] for f in findings)

        asyncio.run(_run())


class TestCheckHttpMethods:
    def test_dangerous_methods(self) -> None:
        async def _run() -> None:
            transport = httpx.MockTransport(
                lambda req: httpx.Response(
                    200, headers={"Allow": "GET, POST, PUT, DELETE, TRACE"}, text=""
                )
            )
            with patch(
                "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                findings = await check_http_methods("https://example.com")
            assert any("dangerous" in f["type"] for f in findings)

        asyncio.run(_run())


class TestCheckCookies:
    def test_insecure_cookies(self) -> None:
        async def _run() -> None:
            resp = httpx.Response(
                200,
                headers=[("set-cookie", "session=abc; Path=/")],
                text="ok",
            )
            transport = httpx.MockTransport(lambda req: resp)
            with patch(
                "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                findings = await check_cookies("https://example.com")
            types = {f["type"] for f in findings}
            assert "dast_cookie_no_secure" in types
            assert "dast_cookie_no_httponly" in types
            assert "dast_cookie_no_samesite" in types

        asyncio.run(_run())


class TestCheckRedirects:
    def test_redirect_to_https(self) -> None:
        async def _run() -> None:
            transport = httpx.MockTransport(
                lambda req: httpx.Response(
                    301, headers={"location": "https://example.com/"}, text=""
                )
            )
            with patch(
                "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                findings = await check_redirects("example.com")
            assert any("redirect_ok" in f["type"] for f in findings)

        asyncio.run(_run())

    def test_no_https_redirect(self) -> None:
        async def _run() -> None:
            transport = httpx.MockTransport(
                lambda req: httpx.Response(200, text="plain http")
            )
            with patch(
                "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                findings = await check_redirects("example.com")
            assert any("no_https" in f["type"] for f in findings)

        asyncio.run(_run())

    def test_redirect_non_https(self) -> None:
        async def _run() -> None:
            transport = httpx.MockTransport(
                lambda req: httpx.Response(
                    302, headers={"location": "http://other.com/"}, text=""
                )
            )
            with patch(
                "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                findings = await check_redirects("example.com")
            assert any("no_https" in f["type"] for f in findings)

        asyncio.run(_run())


class TestDASTPlugin:
    def test_dry_run(self) -> None:
        plugin = DASTPlugin()
        result = plugin.dry_run({"authorized_targets": ["host1"]})
        assert result.success
        assert result.metadata["mode"] == "dry-run"

    def test_execute_empty_targets(self) -> None:
        plugin = DASTPlugin()
        result = plugin.execute({"authorized_targets": []})
        assert result.success
        assert len(result.findings) == 0

    def test_execute_with_mock(self) -> None:
        plugin = DASTPlugin()
        with patch.object(plugin, "_scan_target", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = [{"type": "finding", "target": "h1", "detail": "x"}]
            result = plugin.execute(
                {"authorized_targets": [{"host": "h1", "ports": [443]}]}
            )
        assert result.success
        assert len(result.findings) == 1

    def test_execute_error_handling(self) -> None:
        plugin = DASTPlugin()
        with patch.object(plugin, "_scan_target", side_effect=RuntimeError("boom")):
            result = plugin.execute(
                {"authorized_targets": [{"host": "h1", "ports": [443]}]}
            )
        assert result.success
        assert len(result.errors) > 0
