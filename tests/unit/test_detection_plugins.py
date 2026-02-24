"""Tests for detection plugins — coverage_validator and latency_tester."""

from __future__ import annotations

from redcheck.plugins.detection.coverage_validator import (
    CoverageResult,
    DetectionCoverageValidator,
    compute_coverage,
    generate_all_markers,
    generate_traffic_marker,
    technique_ids,
)
from redcheck.plugins.detection.latency_tester import (
    AlertLatencyTester,
    LatencyResult,
    compute_latency_stats,
    generate_latency_marker,
)


# ── Coverage Validator ────────────────────────────────────────────────

class TestTechniqueIds:
    def test_returns_frozenset(self) -> None:
        ids = technique_ids()
        assert isinstance(ids, frozenset)
        assert len(ids) > 0

    def test_contains_known_techniques(self) -> None:
        ids = technique_ids()
        assert "T1046" in ids
        assert "T1190" in ids


class TestTrafficMarker:
    def test_deterministic(self) -> None:
        m1 = generate_traffic_marker("T1046", seed="abc")
        m2 = generate_traffic_marker("T1046", seed="abc")
        assert m1 == m2

    def test_different_seeds(self) -> None:
        m1 = generate_traffic_marker("T1046", seed="a")
        m2 = generate_traffic_marker("T1046", seed="b")
        assert m1 != m2

    def test_prefix(self) -> None:
        m = generate_traffic_marker("T1046")
        assert m.startswith("REDCHECK-DET-")


class TestGenerateAllMarkers:
    def test_generates_all(self) -> None:
        markers = generate_all_markers()
        ids = technique_ids()
        assert len(markers) == len(ids)

    def test_custom_scope(self) -> None:
        scope = frozenset(["T1046", "T1190"])
        markers = generate_all_markers(scope)
        assert len(markers) == 2
        assert "T1046" in markers
        assert "T1190" in markers


class TestCoverageResult:
    def test_to_dict(self) -> None:
        cr = CoverageResult(
            total_techniques=4,
            detected_techniques=["T1046", "T1190"],
            undetected_techniques=["T1596", "T1593"],
            per_technique={"T1046": True, "T1190": True, "T1596": False, "T1593": False},
        )
        d = cr.to_dict()
        assert d["total_techniques"] == 4
        assert d["detected_count"] == 2
        assert d["undetected_count"] == 2
        assert d["coverage_percentage"] == 50.0

    def test_zero_techniques(self) -> None:
        cr = CoverageResult(
            total_techniques=0,
            detected_techniques=[],
            undetected_techniques=[],
            per_technique={},
        )
        assert cr.coverage_percentage == 0.0


class TestComputeCoverage:
    def test_full_coverage(self) -> None:
        scope = frozenset(["T1046", "T1190"])
        result = compute_coverage({"T1046", "T1190"}, scope=scope)
        assert result.coverage_percentage == 100.0
        assert len(result.undetected_techniques) == 0

    def test_partial_coverage(self) -> None:
        scope = frozenset(["T1046", "T1190", "T1596"])
        result = compute_coverage({"T1046"}, scope=scope)
        assert 30 <= result.coverage_percentage <= 34
        assert len(result.detected_techniques) == 1
        assert len(result.undetected_techniques) == 2

    def test_no_coverage(self) -> None:
        scope = frozenset(["T1046"])
        result = compute_coverage(set(), scope=scope)
        assert result.coverage_percentage == 0.0

    def test_default_scope(self) -> None:
        result = compute_coverage(set())
        assert result.total_techniques == len(technique_ids())


class TestDetectionCoverageValidator:
    def test_dry_run(self) -> None:
        plugin = DetectionCoverageValidator()
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata["mode"] == "dry-run"

    def test_execute_offline(self) -> None:
        plugin = DetectionCoverageValidator()
        result = plugin.execute({
            "detected_techniques": ["T1046", "T1190"],
            "detection_scope": ["T1046", "T1190", "T1596"],
            "detection_wait_seconds": 0,
        })
        assert result.success
        assert result.metadata["coverage_percentage"] > 0
        assert result.metadata["detected_count"] == 2

    def test_execute_full_detection(self) -> None:
        plugin = DetectionCoverageValidator()
        scope = ["T1046", "T1190"]
        result = plugin.execute({
            "detected_techniques": scope,
            "detection_scope": scope,
            "detection_wait_seconds": 0,
        })
        assert result.metadata["coverage_percentage"] == 100.0

    def test_execute_no_scope(self) -> None:
        plugin = DetectionCoverageValidator()
        result = plugin.execute({
            "detected_techniques": [],
            "detection_wait_seconds": 0,
        })
        assert result.success
        assert result.metadata["coverage_percentage"] == 0.0


# ── Latency Tester ────────────────────────────────────────────────────

class TestLatencyMarker:
    def test_prefix(self) -> None:
        m = generate_latency_marker(nonce="test")
        assert m.startswith("REDCHECK-LAT-")

    def test_unique(self) -> None:
        m1 = generate_latency_marker(nonce="a")
        m2 = generate_latency_marker(nonce="b")
        assert m1 != m2


class TestLatencyResult:
    def test_within_sla(self) -> None:
        r = LatencyResult("marker", 50.0, 100.0)
        assert r.within_sla is True
        assert r.timed_out is False
        d = r.to_dict()
        assert d["latency_ms"] == 50.0
        assert d["within_sla"] is True

    def test_outside_sla(self) -> None:
        r = LatencyResult("marker", 200.0, 100.0)
        assert r.within_sla is False

    def test_timed_out(self) -> None:
        r = LatencyResult("marker", 50.0, 100.0, timed_out=True)
        assert r.within_sla is False
        assert r.timed_out is True


class TestComputeLatencyStats:
    def test_empty(self) -> None:
        stats = compute_latency_stats([])
        assert stats["probe_count"] == 0
        assert stats["avg_latency_ms"] == 0.0

    def test_basic_stats(self) -> None:
        results = [
            LatencyResult("m1", 100.0, 200.0),
            LatencyResult("m2", 200.0, 200.0),
            LatencyResult("m3", 150.0, 200.0),
        ]
        stats = compute_latency_stats(results)
        assert stats["probe_count"] == 3
        assert stats["min_latency_ms"] == 100.0
        assert stats["max_latency_ms"] == 200.0
        assert stats["sla_pass_rate"] == 100.0
        assert stats["timeout_count"] == 0

    def test_with_timeouts(self) -> None:
        results = [
            LatencyResult("m1", 100.0, 200.0),
            LatencyResult("m2", 300.0, 200.0, timed_out=True),
        ]
        stats = compute_latency_stats(results)
        assert stats["timeout_count"] == 1
        assert stats["sla_pass_rate"] == 50.0


class TestAlertLatencyTester:
    def test_dry_run(self) -> None:
        plugin = AlertLatencyTester()
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata["mode"] == "dry-run"

    def test_execute_offline(self) -> None:
        plugin = AlertLatencyTester()
        result = plugin.execute({
            "simulated_latencies_ms": [50.0, 100.0, 150.0],
            "expected_latency_ms": 200.0,
            "latency_probe_count": 3,
        })
        assert result.success
        assert result.metadata["probe_count"] == 3
        assert result.metadata["sla_met"] is True

    def test_execute_offline_failure(self) -> None:
        plugin = AlertLatencyTester()
        result = plugin.execute({
            "simulated_latencies_ms": [500.0, 600.0, 700.0],
            "expected_latency_ms": 100.0,
            "latency_probe_count": 3,
        })
        assert result.success
        assert result.metadata["sla_met"] is False
