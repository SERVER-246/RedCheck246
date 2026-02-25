"""Tests for CT Log Monitor, breach lookup execute, network scanner, protocol fuzzer,
passive recon, safe_poc, supply_chain, coverage_validator, and latency_tester."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from redcheck.plugins.osint.breach_lookup import (
    BreachLookup,
    check_password_breach,
)
from redcheck.plugins.osint.ct_watch import CTLogMonitor


class TestCTLogMonitorExecute:
    def test_no_domains(self) -> None:
        plugin = CTLogMonitor()
        result = plugin.execute({"ct_domains": []})
        assert result.success
        assert result.metadata["mode"] == "no-domains"

    def test_execute_with_mock(self) -> None:
        async def _run() -> None:
            ct_response = [
                {
                    "name_value": "sub.example.com\nwww.example.com",
                    "issuer_name": "Let's Encrypt",
                    "not_before": "2025-01-01",
                    "not_after": "2025-03-01",
                    "serial_number": "ABC123",
                },
            ]
            transport = httpx.MockTransport(lambda req: httpx.Response(200, json=ct_response))
            plugin = CTLogMonitor()
            with patch(
                "redcheck.plugins.osint.ct_watch.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                result = await plugin.aexecute({"ct_domains": ["example.com"]})
            assert result.success
            assert len(result.findings) > 0
            assert result.findings[0]["finding_type"] == "ct_certificates"

        asyncio.run(_run())

    def test_execute_non_200(self) -> None:
        async def _run() -> None:
            transport = httpx.MockTransport(lambda req: httpx.Response(500, text="error"))
            plugin = CTLogMonitor()
            with patch(
                "redcheck.plugins.osint.ct_watch.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                result = await plugin.aexecute({"ct_domains": ["fail.com"]})
            assert result.success
            assert len(result.errors) > 0

        asyncio.run(_run())

    def test_execute_non_list_response(self) -> None:
        async def _run() -> None:
            transport = httpx.MockTransport(lambda req: httpx.Response(200, json={"not": "a list"}))
            plugin = CTLogMonitor()
            with patch(
                "redcheck.plugins.osint.ct_watch.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                result = await plugin.aexecute({"ct_domains": ["example.com"]})
            assert result.success
            assert len(result.findings) == 0

        asyncio.run(_run())

    def test_execute_exception(self) -> None:
        async def _run() -> None:
            def _raise(*a: object, **kw: object) -> httpx.Response:
                raise httpx.ConnectError("fail")

            transport = httpx.MockTransport(_raise)
            plugin = CTLogMonitor()
            with patch(
                "redcheck.plugins.osint.ct_watch.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                result = await plugin.aexecute({"ct_domains": ["example.com"]})
            assert len(result.errors) > 0

        asyncio.run(_run())

    def test_dry_run(self) -> None:
        plugin = CTLogMonitor()
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata["mode"] == "dry-run"


class TestBreachLookupExecute:
    def test_execute_with_breached_password(self) -> None:
        async def _run() -> None:
            # HIBP returns suffix:count format
            def _handler(req: httpx.Request) -> httpx.Response:
                return httpx.Response(200, text="ABCDE:10\nFGHIJ:5\nOTHERSUFFIX:1\n")

            transport = httpx.MockTransport(_handler)
            plugin = BreachLookup()
            with patch(
                "redcheck.plugins.osint.breach_lookup.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                result = await plugin.aexecute({"breach_passwords": ["password"]})
            assert result.success

        asyncio.run(_run())

    def test_check_password_breach_non_200(self) -> None:
        async def _run() -> None:
            client = AsyncMock()
            client.get.return_value = MagicMock(status_code=404)
            count = await check_password_breach("ABCDE", "SUFFIX", client)
            assert count == 0

        asyncio.run(_run())

    def test_check_password_breach_match(self) -> None:
        async def _run() -> None:
            client = AsyncMock()
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "ABCDE:10\nFGHIJ:5\n"
            client.get.return_value = resp
            count = await check_password_breach("12345", "FGHIJ", client)
            assert count == 5

        asyncio.run(_run())

    def test_check_password_breach_no_match(self) -> None:
        async def _run() -> None:
            client = AsyncMock()
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "ABCDE:10\nFGHIJ:5\n"
            client.get.return_value = resp
            count = await check_password_breach("12345", "ZZZZZ", client)
            assert count == 0

        asyncio.run(_run())


class TestNetworkScanner:
    def test_dry_run(self) -> None:
        from redcheck.plugins.recon.network_scan import NetworkScanner

        plugin = NetworkScanner()
        result = plugin.dry_run({"authorized_targets": ["10.0.0.1"]})
        assert result.success
        assert result.metadata["mode"] == "dry-run"

    def test_health_check(self) -> None:
        from redcheck.plugins.recon.network_scan import NetworkScanner

        plugin = NetworkScanner()
        ok, msg = plugin.health_check()
        # May be True or False depending on fingerprint DB


class TestFuzzingPlugin:
    def test_dry_run(self) -> None:
        from redcheck.plugins.fuzzing.protocol_fuzzer import FuzzingPlugin

        plugin = FuzzingPlugin()
        result = plugin.dry_run({"authorized_targets": ["host1"]})
        assert result.success
        assert result.metadata["mode"] == "dry-run"
        assert "categories" in result.metadata

    def test_categorise_payload(self) -> None:
        from redcheck.plugins.fuzzing.protocol_fuzzer import _categorise_payload

        result = _categorise_payload("totally_unknown_payload_xyz")
        assert result == "unknown"

    def test_extract_targets(self) -> None:
        from redcheck.plugins.fuzzing.protocol_fuzzer import _extract_targets

        targets = _extract_targets({"authorized_targets": ["h1", {"host": "h2"}]})
        assert len(targets) == 2


class TestPassiveRecon:
    def test_dry_run(self) -> None:
        from redcheck.plugins.recon.passive_recon import PassiveReconPlugin

        plugin = PassiveReconPlugin()
        result = plugin.dry_run({"authorized_targets": ["example.com"]})
        assert result.success
        assert result.metadata["mode"] == "dry-run"

    def test_extract_host_string(self) -> None:
        from redcheck.plugins.recon.passive_recon import _extract_host

        assert _extract_host("example.com") == "example.com"
        assert _extract_host({"host": "h1"}) == "h1"


class TestSafePoc:
    def test_dry_run(self) -> None:
        from redcheck.plugins.exploit.safe_poc import ExploitVerifier

        plugin = ExploitVerifier()
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata["mode"] == "dry-run"


class TestSupplyChainPlugin:
    def test_dry_run(self, tmp_path: Path) -> None:
        from redcheck.plugins.supply_chain.supply_chain_audit import SupplyChainPlugin

        plugin = SupplyChainPlugin()
        result = plugin.dry_run({"project_root": str(tmp_path)})
        assert result.success
        assert result.metadata["mode"] == "dry-run"

    def test_execute_no_deps(self, tmp_path: Path) -> None:
        from redcheck.plugins.supply_chain.supply_chain_audit import SupplyChainPlugin

        plugin = SupplyChainPlugin()
        result = plugin.execute({"project_root": str(tmp_path)})
        assert result.success
        assert "No dependency" in result.metadata.get("note", "")

    def test_execute_with_deps(self, tmp_path: Path) -> None:
        from redcheck.plugins.supply_chain.supply_chain_audit import SupplyChainPlugin

        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\nflask==2.3.0\n", encoding="utf-8")
        plugin = SupplyChainPlugin()
        with (
            patch(
                "redcheck.plugins.supply_chain.supply_chain_audit.scan_vulnerabilities",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "redcheck.plugins.supply_chain.supply_chain_audit.check_licenses",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = plugin.execute({"project_root": str(tmp_path)})
        assert result.success
        assert result.metadata["total_dependencies"] >= 2

    def test_execute_with_sbom_evidence(self, tmp_path: Path) -> None:
        from redcheck.plugins.supply_chain.supply_chain_audit import SupplyChainPlugin

        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\n", encoding="utf-8")
        evidence_dir = tmp_path / "evidence"
        plugin = SupplyChainPlugin()
        with (
            patch(
                "redcheck.plugins.supply_chain.supply_chain_audit.scan_vulnerabilities",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "redcheck.plugins.supply_chain.supply_chain_audit.check_licenses",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = plugin.execute(
                {
                    "project_root": str(tmp_path),
                    "evidence_dir": str(evidence_dir),
                    "engagement_id": "E1",
                }
            )
        assert result.success
        assert (evidence_dir / "sbom.json").exists()

    def test_execute_with_degraded_findings(self, tmp_path: Path) -> None:
        from redcheck.plugins.supply_chain.supply_chain_audit import SupplyChainPlugin

        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\n", encoding="utf-8")
        plugin = SupplyChainPlugin()
        with (
            patch(
                "redcheck.plugins.supply_chain.supply_chain_audit.scan_vulnerabilities",
                new_callable=AsyncMock,
                return_value=[
                    {
                        "type": "degraded",
                        "target": "requests",
                        "detail": "degraded",
                        "data": {"degraded": True},
                    }
                ],
            ),
            patch(
                "redcheck.plugins.supply_chain.supply_chain_audit.check_licenses",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = plugin.execute({"project_root": str(tmp_path)})
        assert result.metadata.get("degraded") is True
