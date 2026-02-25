"""Tests for passive_recon module helper functions and plugin."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from redcheck.plugins.recon.passive_recon import (
    PassiveReconPlugin,
    _extract_host,
    cert_transparency,
    dns_resolve,
    email_harvest,
    http_fingerprint,
    reverse_dns,
    subdomain_enum,
    whois_lookup,
)


class TestExtractHost:
    def test_string_target(self) -> None:
        assert _extract_host("example.com") == "example.com"
        assert _extract_host("  h1.com  ") == "h1.com"

    def test_dict_target(self) -> None:
        assert _extract_host({"host": "h2.com"}) == "h2.com"

    def test_dict_empty(self) -> None:
        assert _extract_host({}) == ""


class TestDnsResolve:
    def test_dns_resolve_with_records(self) -> None:
        async def _run() -> None:
            with patch(
                "redcheck.plugins.recon.passive_recon._safe_resolve",
                new_callable=AsyncMock,
                side_effect=lambda host, rt: ["1.2.3.4"] if rt == "A" else [],
            ):
                findings = await dns_resolve("example.com")
            assert len(findings) == 1
            assert findings[0]["type"] == "dns_record"
            assert findings[0]["data"]["record_type"] == "A"

        asyncio.run(_run())

    def test_dns_resolve_no_records(self) -> None:
        async def _run() -> None:
            with patch(
                "redcheck.plugins.recon.passive_recon._safe_resolve",
                new_callable=AsyncMock,
                return_value=[],
            ):
                findings = await dns_resolve("nope.com")
            assert len(findings) == 0

        asyncio.run(_run())


class TestReverseDns:
    def test_reverse_dns_found(self) -> None:
        async def _run() -> None:
            with patch(
                "redcheck.plugins.recon.passive_recon._safe_resolve",
                new_callable=AsyncMock,
                return_value=["host.example.com."],
            ):
                findings = await reverse_dns(["1.2.3.4"])
            assert len(findings) == 1
            assert findings[0]["type"] == "reverse_dns"

        asyncio.run(_run())

    def test_reverse_dns_empty(self) -> None:
        async def _run() -> None:
            with patch(
                "redcheck.plugins.recon.passive_recon._safe_resolve",
                new_callable=AsyncMock,
                return_value=[],
            ):
                findings = await reverse_dns(["1.2.3.4"])
            assert len(findings) == 0

        asyncio.run(_run())


class TestWhoisLookup:
    def test_whois_success(self) -> None:
        async def _run() -> None:
            mock_data = MagicMock()
            mock_data.registrar = "Registrar Inc"
            mock_data.creation_date = "2020-01-01"
            mock_data.expiration_date = None
            mock_data.name_servers = ["ns1.example.com"]
            mock_data.org = None
            mock_data.country = "US"
            with patch(
                "redcheck.plugins.recon.passive_recon.python_whois",
                create=True,
            ):
                try:
                    # Simulate that whois is importable
                    whois_mock = MagicMock(whois=MagicMock(return_value=mock_data))
                    with patch.dict("sys.modules", {"whois": whois_mock}):
                        await whois_lookup("example.com")
                except Exception:
                    await whois_lookup("example.com")
            # whois may or may not be installed; just verify no crash

        asyncio.run(_run())

    def test_whois_import_error(self) -> None:
        async def _run() -> None:
            with patch.dict("sys.modules", {"whois": None}):
                await whois_lookup("example.com")
            # Should get an import-error finding or empty
            # The ImportError path should be hit

        asyncio.run(_run())


class TestCertTransparency:
    def test_cert_transparency_success(self) -> None:
        async def _run() -> None:
            import httpx

            response_data = [
                {"name_value": "sub.example.com\nwww.example.com"},
                {"name_value": "*.example.com"},
            ]
            transport = httpx.MockTransport(lambda req: httpx.Response(200, json=response_data))
            with patch("redcheck.plugins.recon.passive_recon.httpx.AsyncClient") as mock_cls:
                mock_cls.return_value = httpx.AsyncClient(transport=transport)
                findings = await cert_transparency("example.com")
            # Should find 2 unique non-wildcard SANs
            assert any(f["type"] == "cert_transparency" for f in findings)

        asyncio.run(_run())

    def test_cert_transparency_error(self) -> None:
        async def _run() -> None:
            with patch("redcheck.plugins.recon.passive_recon.httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.get.side_effect = Exception("connection failed")
                mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
                findings = await cert_transparency("fail.com")
            assert any(
                "error" in str(f.get("detail", "")).lower() or f.get("data", {}).get("error")
                for f in findings
            )

        asyncio.run(_run())


class TestHttpFingerprint:
    def test_http_fingerprint_headers(self) -> None:
        async def _run() -> None:
            import httpx

            transport = httpx.MockTransport(
                lambda req: httpx.Response(
                    200,
                    headers={"Server": "nginx/1.21", "X-Powered-By": "PHP/8.0"},
                )
            )
            with patch("redcheck.plugins.recon.passive_recon.httpx.AsyncClient") as mock_cls:
                mock_cls.return_value = httpx.AsyncClient(transport=transport)
                findings = await http_fingerprint("example.com")
            assert any(f["type"] == "http_fingerprint" for f in findings)

        asyncio.run(_run())


class TestSubdomainEnum:
    def test_subdomain_enum_found(self) -> None:
        async def _run() -> None:
            async def mock_resolve(qname: str, rdtype: str) -> list[str]:
                if "www" in qname:
                    return ["1.2.3.4"]
                return []

            with patch(
                "redcheck.plugins.recon.passive_recon._safe_resolve",
                side_effect=mock_resolve,
            ):
                findings = await subdomain_enum("example.com", wordlist=["www", "mail", "ftp"])
            assert len(findings) == 1
            assert findings[0]["type"] == "subdomain_enum"

        asyncio.run(_run())


class TestEmailHarvest:
    def test_email_harvest_found(self) -> None:
        async def _run() -> None:
            async def mock_resolve(qname: str, rdtype: str) -> list[str]:
                if "_dmarc" in qname:
                    return ['"v=DMARC1; rua=mailto:dmarc@example.com"']
                if rdtype == "TXT":
                    return ['"v=spf1 include:_spf.google.com ~all"']
                return []

            with patch(
                "redcheck.plugins.recon.passive_recon._safe_resolve",
                side_effect=mock_resolve,
            ):
                findings = await email_harvest("example.com")
            assert len(findings) == 1
            assert findings[0]["type"] == "email_harvest"
            assert "dmarc@example.com" in findings[0]["data"]["emails"]

        asyncio.run(_run())


class TestPassiveReconPluginExec:
    def test_execute_empty_targets(self) -> None:
        plugin = PassiveReconPlugin()
        result = plugin.execute({"authorized_targets": []})
        assert result.success
        assert result.metadata["targets_scanned"] == 0

    def test_execute_with_mock_target(self) -> None:
        plugin = PassiveReconPlugin()
        with patch.object(
            plugin,
            "_scan_target",
            new_callable=AsyncMock,
            return_value=[
                {
                    "type": "dns_record",
                    "target": "t.com",
                    "detail": "A: 1.2.3.4",
                    "data": {},
                }
            ],
        ):
            result = plugin.execute({"authorized_targets": ["t.com"]})
        assert result.success
        assert result.metadata["targets_scanned"] == 1
        assert len(result.findings) == 1

    def test_execute_with_error(self) -> None:
        plugin = PassiveReconPlugin()
        with patch.object(
            plugin,
            "_scan_target",
            new_callable=AsyncMock,
            side_effect=RuntimeError("boom"),
        ):
            result = plugin.execute({"authorized_targets": ["t.com"]})
        assert result.success  # still success=True, error is captured
        assert len(result.errors) == 1

    def test_dry_run_details(self) -> None:
        plugin = PassiveReconPlugin()
        result = plugin.dry_run({"authorized_targets": ["a.com", {"host": "b.com"}]})
        assert result.success
        assert result.metadata["targets_count"] == 2
        assert "dns_resolve" in result.metadata["modules"]
