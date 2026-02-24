"""Tests targeting async execute paths in low-coverage modules.

Covers:
- DetectionCoverageValidator.aexecute (coverage_validator.py 65%)
- AlertLatencyTester.aexecute (latency_tester.py 75%)
- ExploitVerifier.aexecute (safe_poc.py 72%)
- IDORValidator.aexecute (idor_checker.py 73%)
- DASTPlugin._scan_target + standalone functions (dast_scanner.py 77%)
- ActivationEngine.set_code / verify_code (activation_engine.py 78%)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

# Save reference to real AsyncClient BEFORE any patching occurs
_RealAsyncClient = httpx.AsyncClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_transport(
    *,
    status: int = 200,
    json_body: Any = None,
    text: str = "",
    headers: dict[str, str] | None = None,
) -> httpx.MockTransport:
    """Build an httpx MockTransport that returns a fixed response."""

    def _handler(request: httpx.Request) -> httpx.Response:
        content_headers = dict(headers or {})
        if json_body is not None:
            return httpx.Response(status, json=json_body, headers=content_headers)
        return httpx.Response(status, text=text, headers=content_headers)

    return httpx.MockTransport(_handler)


def _mock_client(transport: httpx.MockTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=transport)


# ===================================================================
# DetectionCoverageValidator — aexecute with endpoints
# ===================================================================


class TestCoverageValidatorAexecute:
    """Test async execution path that injects markers and queries alerts."""

    @pytest.mark.asyncio
    async def test_aexecute_with_alert_endpoint(self) -> None:
        from redcheck.plugins.detection.coverage_validator import (
            DetectionCoverageValidator,
            technique_ids,
        )

        transport = _make_transport(status=200, json_body={"status": "ok"})

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "alert_endpoint": "https://siem.local/api/inject",
            "alert_query_endpoint": "https://siem.local/api/query",
            "detection_wait_seconds": 0,
            "detection_seed": "test-seed",
        }

        # Mock both inject (POST) and query (GET) returning detected techniques
        tids = list(technique_ids())

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(200, json={"ok": True})
            # GET — return all techniques as detected
            return httpx.Response(
                200,
                json=[{"technique_id": t} for t in tids],
            )

        transport = httpx.MockTransport(_handler)
        plugin = DetectionCoverageValidator()

        with patch(
            "redcheck.plugins.detection.coverage_validator.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert result.metadata["coverage_percentage"] == 100.0

    @pytest.mark.asyncio
    async def test_aexecute_with_alert_endpoint_partial_detection(self) -> None:
        from redcheck.plugins.detection.coverage_validator import (
            DetectionCoverageValidator,
            technique_ids,
        )

        tids = list(technique_ids())

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(200, json={"ok": True})
            # Return only dict format with partial detection
            return httpx.Response(
                200,
                json={"detected_techniques": tids[:2]},
            )

        transport = httpx.MockTransport(_handler)
        plugin = DetectionCoverageValidator()

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "alert_endpoint": "https://siem.local/inject",
            "alert_query_endpoint": "https://siem.local/query",
            "detection_wait_seconds": 0,
        }

        with patch(
            "redcheck.plugins.detection.coverage_validator.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        # Only 2 techniques detected so coverage < 100
        assert result.metadata["coverage_percentage"] < 100.0
        # Should have detection_gap findings for uncovered techniques
        gap_findings = [f for f in result.findings if f["finding_type"] == "detection_gap"]
        assert len(gap_findings) > 0

    @pytest.mark.asyncio
    async def test_aexecute_inject_failure(self) -> None:
        """Inject POST returns error status."""
        from redcheck.plugins.detection.coverage_validator import DetectionCoverageValidator

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(500, text="Server error")
            return httpx.Response(200, json=[])

        transport = httpx.MockTransport(_handler)
        plugin = DetectionCoverageValidator()

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "alert_endpoint": "https://siem.local/inject",
            "alert_query_endpoint": "https://siem.local/query",
            "detection_wait_seconds": 0,
        }

        with patch(
            "redcheck.plugins.detection.coverage_validator.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success  # Still succeeds, just with 0 coverage
        assert result.metadata["coverage_percentage"] == 0.0

    @pytest.mark.asyncio
    async def test_aexecute_query_exception(self) -> None:
        """Query endpoint raises exception."""
        from redcheck.plugins.detection.coverage_validator import DetectionCoverageValidator

        call_count = 0

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if request.method == "POST":
                return httpx.Response(200, json={"ok": True})
            raise httpx.ConnectError("Connection refused")

        transport = httpx.MockTransport(_handler)
        plugin = DetectionCoverageValidator()

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "alert_endpoint": "https://siem.local/inject",
            "alert_query_endpoint": "https://siem.local/query",
            "detection_wait_seconds": 0,
        }

        with patch(
            "redcheck.plugins.detection.coverage_validator.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success


# ===================================================================
# AlertLatencyTester — aexecute with endpoints
# ===================================================================


class TestLatencyTesterAexecute:
    @pytest.mark.asyncio
    async def test_aexecute_with_endpoints(self) -> None:
        """Inject probes and poll for alerts via mock endpoints."""
        from redcheck.plugins.detection.latency_tester import AlertLatencyTester

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(200, json={"ok": True})
            # Polling query — return "found"
            return httpx.Response(200, json={"found": True})

        transport = httpx.MockTransport(_handler)
        plugin = AlertLatencyTester()

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "alert_endpoint": "https://siem.local/inject",
            "alert_query_endpoint": "https://siem.local/query",
            "latency_probe_count": 2,
            "expected_latency_ms": 5000,
            "latency_timeout_s": 0.1,
            "latency_poll_interval": 0.01,
        }

        with patch(
            "redcheck.plugins.detection.latency_tester.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert result.metadata["probe_count"] == 2

    @pytest.mark.asyncio
    async def test_aexecute_inject_fails(self) -> None:
        """Inject POST raises exception — probe skipped."""
        from redcheck.plugins.detection.latency_tester import AlertLatencyTester

        def _handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        transport = httpx.MockTransport(_handler)
        plugin = AlertLatencyTester()

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "alert_endpoint": "https://siem.local/inject",
            "latency_probe_count": 1,
            "expected_latency_ms": 5000,
            "latency_timeout_s": 0.1,
        }

        with patch(
            "redcheck.plugins.detection.latency_tester.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert len(result.errors) >= 1

    @pytest.mark.asyncio
    async def test_aexecute_poll_timeout(self) -> None:
        """Query endpoint returns not-found, so probe times out."""
        from redcheck.plugins.detection.latency_tester import AlertLatencyTester

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(200)
            # GET returns empty (not found)
            return httpx.Response(200, json={"found": False})

        transport = httpx.MockTransport(_handler)
        plugin = AlertLatencyTester()

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "alert_endpoint": "https://siem.local/inject",
            "alert_query_endpoint": "https://siem.local/query",
            "latency_probe_count": 1,
            "expected_latency_ms": 5000,
            "latency_timeout_s": 0.05,
            "latency_poll_interval": 0.01,
        }

        with patch(
            "redcheck.plugins.detection.latency_tester.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert result.metadata.get("timeout_count", 0) >= 1

    @pytest.mark.asyncio
    async def test_aexecute_poll_list_response(self) -> None:
        """Query endpoint returns list (alternative detected format)."""
        from redcheck.plugins.detection.latency_tester import AlertLatencyTester

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(200)
            return httpx.Response(200, json=[{"alert": True}])

        transport = httpx.MockTransport(_handler)
        plugin = AlertLatencyTester()

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "alert_endpoint": "https://siem.local/inject",
            "alert_query_endpoint": "https://siem.local/query",
            "latency_probe_count": 1,
            "expected_latency_ms": 50000,
            "latency_timeout_s": 0.1,
            "latency_poll_interval": 0.01,
        }

        with patch(
            "redcheck.plugins.detection.latency_tester.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success

    @pytest.mark.asyncio
    async def test_aexecute_simulated_offline(self) -> None:
        """Offline mode with simulated latencies."""
        from redcheck.plugins.detection.latency_tester import AlertLatencyTester

        plugin = AlertLatencyTester()
        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "latency_probe_count": 3,
            "expected_latency_ms": 1000,
            "simulated_latencies_ms": [100.0, 200.0, 300.0],
        }
        result = await plugin.aexecute(ctx)
        assert result.success
        assert result.metadata["probe_count"] == 3
        assert result.metadata["sla_met"] is True


# ===================================================================
# ExploitVerifier — aexecute with PoC library
# ===================================================================


class TestSafePocAexecute:
    @pytest.mark.asyncio
    async def test_aexecute_version_check_match(self) -> None:
        """PoC version_check finds a vulnerable version."""
        from redcheck.plugins.exploit.safe_poc import ExploitVerifier

        plugin = ExploitVerifier()
        transport = _make_transport(status=200, text="ok")
        library = {
            "pocs": [
                {
                    "cve_id": "CVE-2024-0001",
                    "type": "version_check",
                    "service": "nginx",
                    "version_min": "1.0.0",
                    "version_max": "1.9.9",
                    "severity": "critical",
                    "mitre": "T1203",
                }
            ]
        }

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "offensive_controls": {
                "allow_exploit_validation": True,
            },
            "confirm_exploit": True,
            "isolation_verified": True,
            "target_cves": ["CVE-2024-0001"],
            "exploit_targets": ["https://test.local"],
            "detected_versions": {"nginx": "1.5.0"},
        }

        with (
            patch(
                "redcheck.plugins.exploit.safe_poc._load_poc_library",
                return_value=library,
            ),
            patch(
                "redcheck.plugins.exploit.safe_poc.httpx.AsyncClient",
                side_effect=lambda **kw: _RealAsyncClient(transport=transport),
            ),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert len(result.findings) == 1
        assert result.findings[0]["finding_type"] == "exploitable_version"

    @pytest.mark.asyncio
    async def test_aexecute_http_probe_match(self) -> None:
        """PoC http_probe finds indicator in response."""
        from redcheck.plugins.exploit.safe_poc import ExploitVerifier

        plugin = ExploitVerifier()

        library = {
            "pocs": [
                {
                    "cve_id": "CVE-2024-0002",
                    "type": "http_probe",
                    "probe_path": "/debug",
                    "indicator": "DEBUG_MODE=true",
                    "severity": "high",
                    "mitre": "T1190",
                }
            ]
        }

        transport = _make_transport(status=200, text="DEBUG_MODE=true enabled")

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "offensive_controls": {
                "allow_exploit_validation": True,
            },
            "confirm_exploit": True,
            "isolation_verified": True,
            "target_cves": ["CVE-2024-0002"],
            "exploit_targets": ["https://test.local"],
        }

        with (
            patch(
                "redcheck.plugins.exploit.safe_poc._load_poc_library",
                return_value=library,
            ),
            patch(
                "redcheck.plugins.exploit.safe_poc.httpx.AsyncClient",
                side_effect=lambda **kw: _RealAsyncClient(transport=transport),
            ),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert len(result.findings) == 1
        assert result.findings[0]["finding_type"] == "exploitable_endpoint"

    @pytest.mark.asyncio
    async def test_aexecute_header_check_missing(self) -> None:
        """PoC header_check detects missing security header."""
        from redcheck.plugins.exploit.safe_poc import ExploitVerifier

        plugin = ExploitVerifier()

        library = {
            "pocs": [
                {
                    "cve_id": "CVE-2024-0003",
                    "type": "header_check",
                    "header": "X-Frame-Options",
                    "absent": False,
                    "severity": "medium",
                }
            ]
        }

        # Response has NO X-Frame-Options header
        transport = _make_transport(status=200, text="ok")

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "offensive_controls": {
                "allow_exploit_validation": True,
            },
            "confirm_exploit": True,
            "isolation_verified": True,
            "target_cves": ["CVE-2024-0003"],
            "exploit_targets": ["https://test.local"],
        }

        with (
            patch(
                "redcheck.plugins.exploit.safe_poc._load_poc_library",
                return_value=library,
            ),
            patch(
                "redcheck.plugins.exploit.safe_poc.httpx.AsyncClient",
                side_effect=lambda **kw: _RealAsyncClient(transport=transport),
            ),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert len(result.findings) == 1
        assert result.findings[0]["finding_type"] == "missing_security_header"

    @pytest.mark.asyncio
    async def test_aexecute_header_check_present_should_be_absent(self) -> None:
        """PoC header_check detects header that should be absent."""
        from redcheck.plugins.exploit.safe_poc import ExploitVerifier

        plugin = ExploitVerifier()

        library = {
            "pocs": [
                {
                    "cve_id": "CVE-2024-0004",
                    "type": "header_check",
                    "header": "X-Powered-By",
                    "absent": True,
                    "severity": "medium",
                }
            ]
        }

        transport = _make_transport(
            status=200,
            text="ok",
            headers={"X-Powered-By": "Express"},
        )

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "offensive_controls": {
                "allow_exploit_validation": True,
            },
            "confirm_exploit": True,
            "isolation_verified": True,
            "target_cves": ["CVE-2024-0004"],
            "exploit_targets": ["https://test.local"],
        }

        with (
            patch(
                "redcheck.plugins.exploit.safe_poc._load_poc_library",
                return_value=library,
            ),
            patch(
                "redcheck.plugins.exploit.safe_poc.httpx.AsyncClient",
                side_effect=lambda **kw: _RealAsyncClient(transport=transport),
            ),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert len(result.findings) == 1
        assert result.findings[0]["finding_type"] == "vulnerable_header"

    @pytest.mark.asyncio
    async def test_aexecute_unknown_poc_type(self) -> None:
        """Unknown PoC type generates an error."""
        from redcheck.plugins.exploit.safe_poc import ExploitVerifier

        plugin = ExploitVerifier()
        transport = _make_transport(status=200, text="ok")
        library = {
            "pocs": [
                {
                    "cve_id": "CVE-2024-0005",
                    "type": "unknown_type",
                }
            ]
        }

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "offensive_controls": {
                "allow_exploit_validation": True,
            },
            "confirm_exploit": True,
            "isolation_verified": True,
            "target_cves": ["CVE-2024-0005"],
        }

        with (
            patch(
                "redcheck.plugins.exploit.safe_poc._load_poc_library",
                return_value=library,
            ),
            patch(
                "redcheck.plugins.exploit.safe_poc.httpx.AsyncClient",
                side_effect=lambda **kw: _RealAsyncClient(transport=transport),
            ),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert "unknown_type" in result.errors[0].lower() or "Unknown" in result.errors[0]

    @pytest.mark.asyncio
    async def test_aexecute_no_cves(self) -> None:
        """No target CVEs — returns early."""
        from redcheck.plugins.exploit.safe_poc import ExploitVerifier

        plugin = ExploitVerifier()

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "offensive_controls": {
                "allow_exploit_validation": True,
            },
            "confirm_exploit": True,
            "isolation_verified": True,
            "target_cves": [],
        }

        result = await plugin.aexecute(ctx)
        assert result.success
        assert result.metadata.get("mode") == "no-cves"

    @pytest.mark.asyncio
    async def test_aexecute_version_check_no_match(self) -> None:
        """PoC version_check — detected version outside vulnerable range."""
        from redcheck.plugins.exploit.safe_poc import ExploitVerifier

        plugin = ExploitVerifier()
        transport = _make_transport(status=200, text="ok")
        library = {
            "pocs": [
                {
                    "cve_id": "CVE-2024-0006",
                    "type": "version_check",
                    "service": "nginx",
                    "version_min": "1.0.0",
                    "version_max": "1.9.9",
                }
            ]
        }

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "offensive_controls": {
                "allow_exploit_validation": True,
            },
            "confirm_exploit": True,
            "isolation_verified": True,
            "target_cves": ["CVE-2024-0006"],
            "detected_versions": {"nginx": "2.0.0"},
        }

        with (
            patch(
                "redcheck.plugins.exploit.safe_poc._load_poc_library",
                return_value=library,
            ),
            patch(
                "redcheck.plugins.exploit.safe_poc.httpx.AsyncClient",
                side_effect=lambda **kw: _RealAsyncClient(transport=transport),
            ),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_aexecute_version_check_no_version_detected(self) -> None:
        """PoC version_check — service not detected."""
        from redcheck.plugins.exploit.safe_poc import ExploitVerifier

        plugin = ExploitVerifier()
        transport = _make_transport(status=200, text="ok")
        library = {
            "pocs": [
                {
                    "cve_id": "CVE-2024-0007",
                    "type": "version_check",
                    "service": "nginx",
                    "version_min": "1.0.0",
                    "version_max": "1.9.9",
                }
            ]
        }

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "offensive_controls": {
                "allow_exploit_validation": True,
            },
            "confirm_exploit": True,
            "isolation_verified": True,
            "target_cves": ["CVE-2024-0007"],
            "detected_versions": {},
        }

        with (
            patch(
                "redcheck.plugins.exploit.safe_poc._load_poc_library",
                return_value=library,
            ),
            patch(
                "redcheck.plugins.exploit.safe_poc.httpx.AsyncClient",
                side_effect=lambda **kw: _RealAsyncClient(transport=transport),
            ),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert len(result.findings) == 0


# ===================================================================
# IDORValidator — aexecute with endpoints
# ===================================================================


class TestIDORAexecute:
    @pytest.mark.asyncio
    async def test_aexecute_finds_accessible_objects(self) -> None:
        """IDOR check returns 200 for test object IDs."""
        from redcheck.plugins.dast.idor_checker import IDORValidator

        plugin = IDORValidator()
        transport = _make_transport(status=200, text="secret data")

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "offensive_controls": {
                "allow_auth_testing": True,
            },
            "idor_test_ids": ["123", "456"],
            "idor_endpoints": ["https://test.local/api/users/{id}"],
        }

        with patch(
            "redcheck.plugins.dast.idor_checker.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert len(result.findings) == 2  # 2 IDs × 1 endpoint
        assert result.findings[0]["finding_type"] == "idor_accessible"

    @pytest.mark.asyncio
    async def test_aexecute_403_no_findings(self) -> None:
        """IDOR check returns 403 — no findings."""
        from redcheck.plugins.dast.idor_checker import IDORValidator

        plugin = IDORValidator()
        transport = _make_transport(status=403, text="Forbidden")

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "offensive_controls": {"allow_auth_testing": True},
            "idor_test_ids": ["123"],
            "idor_endpoints": ["https://test.local/api/users/{id}"],
        }

        with patch(
            "redcheck.plugins.dast.idor_checker.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_aexecute_connection_error(self) -> None:
        """IDOR check — connection error generates error entry."""
        from redcheck.plugins.dast.idor_checker import IDORValidator

        def _handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        transport = httpx.MockTransport(_handler)
        plugin = IDORValidator()

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "offensive_controls": {"allow_auth_testing": True},
            "idor_test_ids": ["123"],
            "idor_endpoints": ["https://test.local/api/users/{id}"],
        }

        with patch(
            "redcheck.plugins.dast.idor_checker.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        assert len(result.errors) >= 1

    @pytest.mark.asyncio
    async def test_aexecute_deterministic_ids(self) -> None:
        """No test IDs provided — generates deterministic IDs."""
        from redcheck.plugins.dast.idor_checker import IDORValidator

        plugin = IDORValidator()
        transport = _make_transport(status=200, text="data")

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "offensive_controls": {"allow_auth_testing": True},
            # No idor_test_ids — will auto-generate
            "idor_endpoints": ["https://test.local/api/items/{id}"],
        }

        with patch(
            "redcheck.plugins.dast.idor_checker.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            result = await plugin.aexecute(ctx)

        assert result.success
        # Should have auto-generated 5 IDs
        assert len(result.findings) == 5

    def test_execute_sync(self) -> None:
        """Sync execute wraps async."""
        from redcheck.plugins.dast.idor_checker import IDORValidator

        plugin = IDORValidator()
        transport = _make_transport(status=200, text="data")

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
            "offensive_controls": {"allow_auth_testing": True},
            "idor_test_ids": ["1"],
            "idor_endpoints": ["https://test.local/api/x/{id}"],
        }

        with patch(
            "redcheck.plugins.dast.idor_checker.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            result = plugin.execute(ctx)

        assert result.success


# ===================================================================
# DASTPlugin — _scan_target and standalone functions
# ===================================================================


class TestDASTStandalone:
    @pytest.mark.asyncio
    async def test_discover_paths(self) -> None:
        """discover_paths finds sensitive paths."""
        from redcheck.plugins.dast.dast_scanner import discover_paths

        transport = _make_transport(status=200, text="admin panel")

        with patch(
            "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            findings = await discover_paths("https://test.local")

        # Should find some paths with status 200
        assert len(findings) > 0
        assert findings[0]["type"] == "dast_path_found"

    @pytest.mark.asyncio
    async def test_discover_paths_all_404(self) -> None:
        """discover_paths — all paths return 404."""
        from redcheck.plugins.dast.dast_scanner import discover_paths

        transport = _make_transport(status=404, text="Not Found")

        with patch(
            "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            findings = await discover_paths("https://test.local")

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_check_redirects_https(self) -> None:
        """check_redirects — proper HTTP→HTTPS redirect."""
        from redcheck.plugins.dast.dast_scanner import check_redirects

        transport = _make_transport(
            status=301,
            text="",
            headers={"location": "https://test.local/"},
        )

        with patch(
            "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            findings = await check_redirects("test.local")

        redirect_ok = [f for f in findings if f["type"] == "dast_redirect_ok"]
        assert len(redirect_ok) == 1

    @pytest.mark.asyncio
    async def test_check_redirects_no_https(self) -> None:
        """check_redirects — redirect NOT to HTTPS."""
        from redcheck.plugins.dast.dast_scanner import check_redirects

        transport = _make_transport(
            status=302,
            text="",
            headers={"location": "http://other.local/"},
        )

        with patch(
            "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            findings = await check_redirects("test.local")

        no_https = [f for f in findings if f["type"] == "dast_no_https_redirect"]
        assert len(no_https) == 1

    @pytest.mark.asyncio
    async def test_check_redirects_200_no_redirect(self) -> None:
        """check_redirects — HTTP serves content without redirect."""
        from redcheck.plugins.dast.dast_scanner import check_redirects

        transport = _make_transport(status=200, text="Hello")

        with patch(
            "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            findings = await check_redirects("test.local")

        assert any(f["type"] == "dast_no_https_redirect" for f in findings)

    @pytest.mark.asyncio
    async def test_check_cookies_insecure(self) -> None:
        """check_cookies — missing Secure, HttpOnly, SameSite."""
        from redcheck.plugins.dast.dast_scanner import check_cookies

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                text="ok",
                headers={"set-cookie": "session=abc123; Path=/"},
            )

        transport = httpx.MockTransport(_handler)

        with patch(
            "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            findings = await check_cookies("https://test.local")

        types = [f["type"] for f in findings]
        assert "dast_cookie_no_secure" in types
        assert "dast_cookie_no_httponly" in types
        assert "dast_cookie_no_samesite" in types

    @pytest.mark.asyncio
    async def test_check_http_methods_dangerous(self) -> None:
        """check_http_methods — dangerous methods allowed."""
        from redcheck.plugins.dast.dast_scanner import check_http_methods

        transport = _make_transport(
            status=200,
            text="ok",
            headers={"Allow": "GET, POST, PUT, DELETE, TRACE"},
        )

        with patch(
            "redcheck.plugins.dast.dast_scanner.httpx.AsyncClient",
            side_effect=lambda **kw: _RealAsyncClient(transport=transport),
        ):
            findings = await check_http_methods("https://test.local")

        assert len(findings) == 1
        assert findings[0]["type"] == "dast_dangerous_methods"

    def test_dast_plugin_execute(self) -> None:
        """DASTPlugin.execute with mocked _scan_target."""
        from redcheck.plugins.dast.dast_scanner import DASTPlugin

        plugin = DASTPlugin()

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local", "ports": [443]}],
        }

        # Mock _scan_target to return canned findings
        async def mock_scan(host: str, ports: list[int]) -> list[dict[str, Any]]:
            return [{"type": "dast_test", "target": host, "detail": "test"}]

        with patch.object(plugin, "_scan_target", side_effect=mock_scan):
            result = plugin.execute(ctx)

        assert result.success
        assert len(result.findings) == 1

    def test_dast_plugin_execute_exception(self) -> None:
        """DASTPlugin.execute handles scan error."""
        from redcheck.plugins.dast.dast_scanner import DASTPlugin

        plugin = DASTPlugin()

        ctx = {
            "roe_validated": True,
            "authorized_targets": [{"host": "test.local"}],
        }

        async def mock_scan(host: str, ports: list[int]) -> list[dict[str, Any]]:
            raise ConnectionError("refused")

        with patch.object(plugin, "_scan_target", side_effect=mock_scan):
            result = plugin.execute(ctx)

        assert result.success
        assert len(result.errors) >= 1


# ===================================================================
# ActivationEngine — set_code / verify_code
# ===================================================================


class TestActivationEngine:
    def test_set_code_success(self, tmp_path: Path) -> None:
        from redcheck.core.activation_engine import ActivationEngine

        eng = ActivationEngine(activation_path=tmp_path / "act.enc")
        ok, msg = eng.set_code("MyP@ss123!")
        assert ok
        assert "success" in msg.lower()
        assert eng.is_configured

    def test_set_code_too_short(self, tmp_path: Path) -> None:
        from redcheck.core.activation_engine import ActivationEngine

        eng = ActivationEngine(activation_path=tmp_path / "act.enc")
        ok, msg = eng.set_code("short")
        assert not ok
        assert "short" in msg.lower() or "minimum" in msg.lower()

    def test_set_code_no_special(self, tmp_path: Path) -> None:
        from redcheck.core.activation_engine import ActivationEngine

        eng = ActivationEngine(activation_path=tmp_path / "act.enc")
        ok, msg = eng.set_code("Password123")
        assert not ok
        assert "special" in msg.lower()

    def test_verify_code_success(self, tmp_path: Path) -> None:
        from redcheck.core.activation_engine import ActivationEngine

        eng = ActivationEngine(activation_path=tmp_path / "act.enc")
        eng.set_code("MyP@ss123!")
        assert eng.verify_code("MyP@ss123!") is True

    def test_verify_code_wrong(self, tmp_path: Path) -> None:
        from redcheck.core.activation_engine import ActivationEngine

        eng = ActivationEngine(activation_path=tmp_path / "act.enc")
        eng.set_code("MyP@ss123!")
        assert eng.verify_code("WrongP@ss1") is False

    def test_verify_not_configured(self, tmp_path: Path) -> None:
        from redcheck.core.activation_engine import ActivationEngine

        eng = ActivationEngine(activation_path=tmp_path / "act.enc")
        assert eng.verify_code("anything") is False

    def test_verify_lockout(self, tmp_path: Path) -> None:
        from redcheck.core.activation_engine import ActivationEngine, ActivationError

        eng = ActivationEngine(activation_path=tmp_path / "act.enc")
        eng.set_code("MyP@ss123!")
        # Force lockout
        eng._lockout_until = 9999999999.0
        with pytest.raises(ActivationError, match="[Ll]ock"):
            eng.verify_code("anycode")

    def test_verify_cooldown(self, tmp_path: Path) -> None:
        import time

        from redcheck.core.activation_engine import ActivationEngine, ActivationError

        eng = ActivationEngine(activation_path=tmp_path / "act.enc")
        eng.set_code("MyP@ss123!")
        eng._last_attempt = time.monotonic()  # Just now
        with pytest.raises(ActivationError, match="[Tt]oo fast|[Ww]ait"):
            eng.verify_code("MyP@ss123!")

    def test_verify_corrupted_file(self, tmp_path: Path) -> None:
        from redcheck.core.activation_engine import ActivationEngine

        act_file = tmp_path / "act.enc"
        act_file.write_text("not json{{{")
        eng = ActivationEngine(activation_path=act_file)
        assert eng.verify_code("anycode") is False

    def test_clear(self, tmp_path: Path) -> None:
        from redcheck.core.activation_engine import ActivationEngine

        eng = ActivationEngine(activation_path=tmp_path / "act.enc")
        eng.set_code("MyP@ss123!")
        assert eng.clear() is True
        assert not eng.is_configured

    def test_clear_nonexistent(self, tmp_path: Path) -> None:
        from redcheck.core.activation_engine import ActivationEngine

        eng = ActivationEngine(activation_path=tmp_path / "act.enc")
        assert eng.clear() is False

    def test_get_activation_engine_singleton(self, tmp_path: Path) -> None:
        from redcheck.core.activation_engine import (
            ActivationEngine,
            get_activation_engine,
        )

        ActivationEngine.reset()
        eng1 = get_activation_engine(str(tmp_path / "act.enc"))
        eng2 = get_activation_engine()
        assert eng1 is eng2
        ActivationEngine.reset()

    def test_base_dir_constructor(self, tmp_path: Path) -> None:
        from redcheck.core.activation_engine import ActivationEngine

        eng = ActivationEngine(base_dir=tmp_path)
        assert ".activation" in str(eng._path)

    def test_verify_lockout_after_max_attempts(self, tmp_path: Path) -> None:
        """Failed attempts trigger lockout."""
        from redcheck.core.activation_engine import ActivationEngine, ActivationError

        eng = ActivationEngine(activation_path=tmp_path / "act.enc")
        eng.set_code("MyP@ss123!")

        # Simulate rapid fails (bypass cooldown)
        locked = False
        for _ in range(10):
            eng._last_attempt = 0.0
            try:
                eng.verify_code("WrongP@ss!")
            except ActivationError:
                locked = True
                break

        # After max attempts, should be locked out
        assert locked or eng._failed_attempts >= 5
