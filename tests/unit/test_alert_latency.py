"""Tests for redcheck.plugins.detection.latency_tester.

Covers:
- Marker generation (uniqueness, prefix)
- LatencyResult (SLA pass/fail, timeout, to_dict)
- Latency statistics (avg, min, max, p95, SLA pass rate)
- AlertLatencyTester plugin (offline mode with simulated latencies)
- Timeout enforcement
"""

from __future__ import annotations

from typing import Any

import pytest

from redcheck.plugins.detection.latency_tester import (
    DEFAULT_EXPECTED_LATENCY_MS,
    LATENCY_POLL_TIMEOUT_CAP,
    MAX_POLL_INTERVAL,
    MIN_POLL_INTERVAL,
    TIMEOUT_MULTIPLIER,
    AlertLatencyTester,
    LatencyResult,
    compute_latency_stats,
    generate_latency_marker,
)

# =====================================================================
# Marker Generation
# =====================================================================


class TestLatencyMarkerGeneration:
    """Verify latency marker generation."""

    def test_marker_has_prefix(self) -> None:
        marker = generate_latency_marker()
        assert marker.startswith("REDCHECK-LAT-")

    def test_markers_are_unique(self) -> None:
        """Different nonces → different markers."""
        m1 = generate_latency_marker(nonce="a")
        m2 = generate_latency_marker(nonce="b")
        assert m1 != m2

    def test_marker_length(self) -> None:
        marker = generate_latency_marker()
        # Prefix (13 chars) + 24-char hex digest
        assert len(marker) == 13 + 24


# =====================================================================
# LatencyResult
# =====================================================================


class TestLatencyResult:
    """Verify LatencyResult SLA logic."""

    def test_within_sla_when_latency_below_expected(self) -> None:
        r = LatencyResult("m1", 50.0, 100.0)
        assert r.within_sla is True
        assert r.timed_out is False

    def test_within_sla_when_latency_equals_expected(self) -> None:
        r = LatencyResult("m1", 100.0, 100.0)
        assert r.within_sla is True

    def test_not_within_sla_when_latency_above_expected(self) -> None:
        r = LatencyResult("m1", 200.0, 100.0)
        assert r.within_sla is False

    def test_not_within_sla_when_timed_out(self) -> None:
        r = LatencyResult("m1", 50.0, 100.0, timed_out=True)
        assert r.within_sla is False

    def test_latency_rounded(self) -> None:
        r = LatencyResult("m1", 99.9999, 100.0)
        assert r.latency_ms == 100.0  # rounded to 2 decimal

    def test_to_dict_structure(self) -> None:
        r = LatencyResult("marker-1", 150.0, 200.0)
        d = r.to_dict()
        assert d["marker"] == "marker-1"
        assert d["latency_ms"] == 150.0
        assert d["expected_ms"] == 200.0
        assert d["within_sla"] is True
        assert d["timed_out"] is False

    def test_to_dict_timed_out(self) -> None:
        r = LatencyResult("m1", 5000.0, 100.0, timed_out=True)
        d = r.to_dict()
        assert d["timed_out"] is True
        assert d["within_sla"] is False


# =====================================================================
# Statistics Computation
# =====================================================================


class TestLatencyStats:
    """Verify aggregated latency statistics."""

    def test_empty_results(self) -> None:
        stats = compute_latency_stats([])
        assert stats["probe_count"] == 0
        assert stats["avg_latency_ms"] == 0.0

    def test_single_result(self) -> None:
        r = LatencyResult("m1", 100.0, 200.0)
        stats = compute_latency_stats([r])
        assert stats["probe_count"] == 1
        assert stats["avg_latency_ms"] == 100.0
        assert stats["min_latency_ms"] == 100.0
        assert stats["max_latency_ms"] == 100.0
        assert stats["sla_pass_rate"] == 100.0

    def test_multiple_results_avg(self) -> None:
        results = [
            LatencyResult("m1", 100.0, 200.0),
            LatencyResult("m2", 200.0, 200.0),
            LatencyResult("m3", 300.0, 200.0),
        ]
        stats = compute_latency_stats(results)
        assert stats["probe_count"] == 3
        assert stats["avg_latency_ms"] == 200.0
        assert stats["min_latency_ms"] == 100.0
        assert stats["max_latency_ms"] == 300.0

    def test_sla_pass_rate_partial(self) -> None:
        results = [
            LatencyResult("m1", 50.0, 100.0),  # pass
            LatencyResult("m2", 150.0, 100.0),  # fail
            LatencyResult("m3", 80.0, 100.0),  # pass
        ]
        stats = compute_latency_stats(results)
        assert stats["sla_pass_rate"] == pytest.approx(66.67, abs=0.01)

    def test_timeout_count(self) -> None:
        results = [
            LatencyResult("m1", 100.0, 200.0),
            LatencyResult("m2", 5000.0, 200.0, timed_out=True),
        ]
        stats = compute_latency_stats(results)
        assert stats["timeout_count"] == 1

    def test_p95_latency(self) -> None:
        """p95 is the 95th percentile latency."""
        results = [LatencyResult(f"m{i}", float(i * 10), 500.0) for i in range(1, 21)]
        stats = compute_latency_stats(results)
        # 20 items, p95_idx = int(20 * 0.95) - 1 = 18 → sorted[18] = 190.0
        assert stats["p95_latency_ms"] == 190.0


# =====================================================================
# AlertLatencyTester Plugin
# =====================================================================


class TestAlertLatencyTesterPlugin:
    """Verify the plugin in offline mode with simulated latencies."""

    def _make_context(self, **overrides: Any) -> dict[str, Any]:
        ctx: dict[str, Any] = {
            "engagement_id": "test-engagement",
            "targets": ["10.0.0.1"],
        }
        ctx.update(overrides)
        return ctx

    def test_plugin_metadata(self) -> None:
        p = AlertLatencyTester()
        assert p.name == "alert-latency"
        assert p.version == "0.1.0"
        assert p.category == "detection"
        assert p.capability.value == "active"
        assert "allow_auth_testing" in p.required_controls
        assert p.timeout_seconds == 180
        assert p.mitre_techniques == ["T1562.006"]

    def test_offline_simulated_latencies_within_sla(self) -> None:
        """Simulated latencies all within SLA → sla_met = True."""
        p = AlertLatencyTester()
        ctx = self._make_context(
            expected_latency_ms=200.0,
            latency_probe_count=3,
            simulated_latencies_ms=[50.0, 80.0, 120.0],
        )
        result = p.execute(ctx)
        assert result.success is True
        assert result.metadata["sla_met"] is True
        assert result.metadata["probe_count"] == 3

    def test_offline_simulated_latencies_exceed_sla(self) -> None:
        """Simulated latencies exceed expected → sla_met = False."""
        p = AlertLatencyTester()
        ctx = self._make_context(
            expected_latency_ms=100.0,
            latency_probe_count=3,
            simulated_latencies_ms=[200.0, 300.0, 400.0],
        )
        result = p.execute(ctx)
        assert result.success is True
        assert result.metadata["sla_met"] is False

    def test_offline_mixed_sla(self) -> None:
        """Mixed pass/fail — 2/3 pass → 66.67% < 80% → sla_met=False."""
        p = AlertLatencyTester()
        ctx = self._make_context(
            expected_latency_ms=100.0,
            latency_probe_count=3,
            simulated_latencies_ms=[50.0, 80.0, 200.0],
        )
        result = p.execute(ctx)
        assert result.success is True
        assert result.metadata["sla_met"] is False
        assert result.metadata["sla_pass_rate"] == pytest.approx(66.67, abs=0.01)

    def test_probe_count_capped(self) -> None:
        """Probe count is capped at 20."""
        p = AlertLatencyTester()
        ctx = self._make_context(
            expected_latency_ms=100.0,
            latency_probe_count=50,
            simulated_latencies_ms=[50.0] * 20,
        )
        result = p.execute(ctx)
        assert result.metadata["probe_count"] == 20

    def test_probe_count_minimum(self) -> None:
        """Probe count has minimum of 1."""
        p = AlertLatencyTester()
        ctx = self._make_context(
            expected_latency_ms=100.0,
            latency_probe_count=0,
            simulated_latencies_ms=[50.0],
        )
        result = p.execute(ctx)
        assert result.metadata["probe_count"] == 1

    def test_findings_contain_latency_data(self) -> None:
        p = AlertLatencyTester()
        ctx = self._make_context(
            expected_latency_ms=200.0,
            latency_probe_count=2,
            simulated_latencies_ms=[100.0, 150.0],
        )
        result = p.execute(ctx)
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding["finding_type"] == "alert_latency"
        assert "stats" in finding
        assert "probes" in finding
        assert len(finding["probes"]) == 2

    def test_severity_high_when_sla_not_met(self) -> None:
        p = AlertLatencyTester()
        ctx = self._make_context(
            expected_latency_ms=50.0,
            latency_probe_count=2,
            simulated_latencies_ms=[200.0, 300.0],
        )
        result = p.execute(ctx)
        assert result.findings[0]["severity"] == "high"

    def test_severity_info_when_sla_met(self) -> None:
        p = AlertLatencyTester()
        ctx = self._make_context(
            expected_latency_ms=500.0,
            latency_probe_count=3,
            simulated_latencies_ms=[100.0, 150.0, 200.0],
        )
        result = p.execute(ctx)
        assert result.findings[0]["severity"] == "info"

    def test_dry_run(self) -> None:
        p = AlertLatencyTester()
        ctx = self._make_context()
        result = p.dry_run(ctx)
        assert result.success is True
        assert result.metadata.get("mode") == "dry-run"

    def test_no_simulated_data_no_endpoints(self) -> None:
        """No endpoints and no simulated data → PARTIAL."""
        p = AlertLatencyTester()
        ctx = self._make_context(
            expected_latency_ms=100.0,
            latency_probe_count=2,
        )
        result = p.execute(ctx)
        assert result.success is False
        assert result.metadata.get("contract_status") == "PARTIAL"
        assert result.metadata.get("mode") == "no-input"


# =====================================================================
# Constants Validation
# =====================================================================


class TestLatencyConstants:
    """Verify module-level constants are sensible."""

    def test_default_expected_latency(self) -> None:
        assert DEFAULT_EXPECTED_LATENCY_MS == 1000.0

    def test_timeout_multiplier(self) -> None:
        assert TIMEOUT_MULTIPLIER == 5

    def test_poll_timeout_cap(self) -> None:
        assert LATENCY_POLL_TIMEOUT_CAP == 300

    def test_min_poll_interval(self) -> None:
        assert MIN_POLL_INTERVAL == 0.1

    def test_max_poll_interval(self) -> None:
        assert MAX_POLL_INTERVAL == 5.0
