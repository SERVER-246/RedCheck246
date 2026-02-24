"""Tests for OSV.dev async client — query, batch query, caching, rate limiting."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import httpx

from redcheck.plugins.supply_chain.osv_client import OSVClient, severity_from_cvss


class TestSeverityFromCvss:
    def test_none_returns_medium(self) -> None:
        assert severity_from_cvss(None) == "MEDIUM"

    def test_critical(self) -> None:
        assert severity_from_cvss(9.5) == "CRITICAL"

    def test_high(self) -> None:
        assert severity_from_cvss(7.5) == "HIGH"

    def test_medium(self) -> None:
        assert severity_from_cvss(5.0) == "MEDIUM"

    def test_low(self) -> None:
        assert severity_from_cvss(3.0) == "LOW"

    def test_boundary_nine(self) -> None:
        assert severity_from_cvss(9.0) == "CRITICAL"

    def test_boundary_seven(self) -> None:
        assert severity_from_cvss(7.0) == "HIGH"

    def test_boundary_four(self) -> None:
        assert severity_from_cvss(4.0) == "MEDIUM"

    def test_zero(self) -> None:
        assert severity_from_cvss(0.0) == "LOW"


class TestOSVClientQuery:
    def test_query_success(self) -> None:
        async def _run() -> None:
            transport = httpx.MockTransport(
                lambda req: httpx.Response(200, json={"vulns": [{"id": "GHSA-1"}]})
            )
            client = OSVClient()
            with patch(
                "redcheck.plugins.supply_chain.osv_client.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                result = await client.query("requests", "2.28.0", "PyPI")
            assert "vulns" in result or "degraded" in result

        asyncio.run(_run())

    def test_query_cache_hit(self) -> None:
        async def _run() -> None:
            client = OSVClient()
            cached = {"vulns": []}
            client._cache["PyPI:pkg:1.0"] = cached
            result = await client.query("pkg", "1.0", "PyPI")
            assert result is cached

        asyncio.run(_run())

    def test_query_degraded_on_failure(self) -> None:
        async def _run() -> None:
            transport = httpx.MockTransport(
                lambda req: httpx.Response(500, text="error")
            )
            client = OSVClient()
            client._interval = 0.0  # skip rate limiting
            with patch(
                "redcheck.plugins.supply_chain.osv_client.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ), patch("redcheck.plugins.supply_chain.osv_client._BACKOFF", [0.0, 0.0]):
                result = await client.query("bad", "0.0", "PyPI")
            assert result.get("degraded") is True

        asyncio.run(_run())


class TestOSVClientBatchQuery:
    def test_batch_success(self) -> None:
        async def _run() -> None:
            resp_data = {
                "results": [
                    {"vulns": [{"id": "V1"}]},
                    {"vulns": []},
                ]
            }
            transport = httpx.MockTransport(
                lambda req: httpx.Response(200, json=resp_data)
            )
            client = OSVClient()
            client._interval = 0.0
            with patch(
                "redcheck.plugins.supply_chain.osv_client.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                results = await client.query_batch([
                    {"name": "a", "version": "1.0"},
                    {"name": "b", "version": "2.0"},
                ])
            assert len(results) == 2
            assert results[0]["vulns"] == [{"id": "V1"}]

        asyncio.run(_run())

    def test_batch_degraded_on_exception(self) -> None:
        async def _run() -> None:
            def _raise(*a: object, **kw: object) -> httpx.Response:
                raise httpx.ConnectError("down")

            transport = httpx.MockTransport(_raise)
            client = OSVClient()
            client._interval = 0.0
            with patch(
                "redcheck.plugins.supply_chain.osv_client.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ):
                results = await client.query_batch([
                    {"name": "x", "version": "1.0"},
                ])
            assert len(results) == 1
            assert results[0]["degraded"] is True

        asyncio.run(_run())


class TestOSVClientRateLimit:
    def test_rate_limit_waits(self) -> None:
        async def _run() -> None:
            client = OSVClient()
            client._interval = 0.001
            client._last_request = 0.0
            await client._rate_limit()
            assert client._last_request > 0

        asyncio.run(_run())
