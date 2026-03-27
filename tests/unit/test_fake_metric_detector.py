"""Tests for redcheck.core.fake_metric_detector — cover FM-1/2/3 + downgrade."""

from __future__ import annotations

from unittest.mock import MagicMock

from redcheck.core.fake_metric_detector import (
    _check_fm1_zero_values,
    _check_fm2_duration_cross,
    _check_fm3_evidence_free_measurement,
    _downgrade_finding,
    detect_fake_metrics,
)
from redcheck.models import FindingSeverity


def _make_finding(detail="", severity=FindingSeverity.HIGH, evidence_ref=None, metadata=None):
    f = MagicMock()
    f.detail = detail
    f.severity = severity
    f.evidence_ref = evidence_ref
    f.metadata = metadata if metadata is not None else {}
    f.finding_type = "test"
    return f


def _make_result(plugin_name="test", findings=None, metadata=None):
    r = MagicMock()
    r.plugin_name = plugin_name
    r.findings = findings or []
    r.metadata = metadata if metadata is not None else {}
    return r


class TestFM1ZeroValues:
    def test_alert_latency_avg_zero(self):
        f = _make_finding(detail="avg=0.0ms p95=2.3ms")
        assert _check_fm1_zero_values("alert-latency", f) is True

    def test_alert_latency_p95_zero(self):
        f = _make_finding(detail="avg=1.2ms p95=0.0ms")
        assert _check_fm1_zero_values("alert-latency", f) is True

    def test_alert_latency_nonzero(self):
        f = _make_finding(detail="avg=1.2ms p95=3.4ms")
        assert _check_fm1_zero_values("alert-latency", f) is False

    def test_detection_coverage_zero(self):
        f = _make_finding(detail="Coverage: 0.0% (0/5)")
        assert _check_fm1_zero_values("detection-coverage", f) is True

    def test_detection_coverage_nonzero(self):
        f = _make_finding(detail="Coverage: 80% (4/5)")
        assert _check_fm1_zero_values("detection-coverage", f) is False

    def test_persistence_validator_not_detected_no_evidence(self):
        f = _make_finding(detail="NOT detected", evidence_ref=None)
        assert _check_fm1_zero_values("persistence-validator", f) is True

    def test_persistence_validator_detected(self):
        f = _make_finding(detail="Detected persistence", evidence_ref="ev/1")
        assert _check_fm1_zero_values("persistence-validator", f) is False

    def test_unknown_plugin_no_match(self):
        f = _make_finding(detail="avg=0.0ms")
        assert _check_fm1_zero_values("unknown-plugin", f) is False


class TestFM2DurationCross:
    def test_short_duration_with_measurement_keyword(self):
        r = _make_result(metadata={"duration_seconds": 0.5})
        f = _make_finding(detail="latency measurement: 5ms")
        assert _check_fm2_duration_cross(r, f) is True

    def test_long_duration_ok(self):
        r = _make_result(metadata={"duration_seconds": 5.0})
        f = _make_finding(detail="latency measurement: 5ms")
        assert _check_fm2_duration_cross(r, f) is False

    def test_short_duration_no_keywords(self):
        r = _make_result(metadata={"duration_seconds": 0.1})
        f = _make_finding(detail="simple check passed")
        assert _check_fm2_duration_cross(r, f) is False

    def test_coverage_keyword(self):
        r = _make_result(metadata={"duration_seconds": 0.3})
        f = _make_finding(detail="coverage is 80%")
        assert _check_fm2_duration_cross(r, f) is True

    def test_response_time_keyword(self):
        r = _make_result(metadata={"duration_seconds": 0.2})
        f = _make_finding(detail="response time 100ms")
        assert _check_fm2_duration_cross(r, f) is True


class TestFM3EvidenceFree:
    def test_measurement_no_evidence_non_info(self):
        f = _make_finding(detail="found 5 bytes leaked", severity=FindingSeverity.HIGH)
        assert _check_fm3_evidence_free_measurement(f) is True

    def test_measurement_with_evidence(self):
        f = _make_finding(
            detail="found 5 bytes leaked",
            severity=FindingSeverity.HIGH,
            evidence_ref="ev/1",
        )
        assert _check_fm3_evidence_free_measurement(f) is False

    def test_info_severity_no_flag(self):
        f = _make_finding(detail="found 90% coverage", severity=FindingSeverity.INFO)
        assert _check_fm3_evidence_free_measurement(f) is False

    def test_no_measurement_tokens(self):
        f = _make_finding(detail="just a plain finding", severity=FindingSeverity.HIGH)
        assert _check_fm3_evidence_free_measurement(f) is False

    def test_percentage_token(self):
        f = _make_finding(detail="80% of endpoints", severity=FindingSeverity.MEDIUM)
        assert _check_fm3_evidence_free_measurement(f) is True


class TestDowngradeFinding:
    def test_downgrades_severity_to_info(self):
        f = _make_finding(severity=FindingSeverity.HIGH)
        _downgrade_finding(f, "FM-1:test")
        assert f.metadata["fake_metric_detected"] is True
        assert f.metadata["fake_reason"] == "FM-1:test"
        assert f.metadata["original_severity"] == "high"

    def test_info_severity_not_stored_as_original(self):
        f = _make_finding(severity=FindingSeverity.INFO)
        _downgrade_finding(f, "FM-2:test")
        assert f.metadata["fake_metric_detected"] is True
        assert "original_severity" not in f.metadata


class TestDetectFakeMetrics:
    def test_fm1_triggers(self):
        f = _make_finding(detail="avg=0.0ms p95=0.0ms")
        r = _make_result(plugin_name="alert-latency", findings=[f])
        count = detect_fake_metrics(r)
        assert count == 1
        assert f.metadata["fake_metric_detected"] is True

    def test_fm2_triggers_when_fm1_doesnt(self):
        f = _make_finding(detail="latency check: 5ms", severity=FindingSeverity.HIGH)
        r = _make_result(
            plugin_name="some-plugin",
            findings=[f],
            metadata={"duration_seconds": 0.1},
        )
        count = detect_fake_metrics(r)
        assert count == 1
        assert f.metadata["fake_reason"].startswith("FM-2")

    def test_fm3_triggers_when_fm1_and_fm2_dont(self):
        f = _make_finding(
            detail="found 5 bytes of data",
            severity=FindingSeverity.MEDIUM,
            evidence_ref=None,
        )
        r = _make_result(
            plugin_name="other-plugin",
            findings=[f],
            metadata={"duration_seconds": 10.0},
        )
        count = detect_fake_metrics(r)
        assert count == 1
        assert f.metadata["fake_reason"].startswith("FM-3")

    def test_clean_findings_no_flags(self):
        f = _make_finding(
            detail="clean finding",
            severity=FindingSeverity.INFO,
            evidence_ref="ev/1",
        )
        r = _make_result(plugin_name="clean", findings=[f])
        count = detect_fake_metrics(r)
        assert count == 0

    def test_multiple_findings_mixed(self):
        f1 = _make_finding(detail="avg=0.0ms", severity=FindingSeverity.HIGH)
        f2 = _make_finding(detail="clean", severity=FindingSeverity.INFO, evidence_ref="x")
        r = _make_result(plugin_name="alert-latency", findings=[f1, f2])
        count = detect_fake_metrics(r)
        assert count == 1

    def test_no_findings(self):
        r = _make_result(findings=[])
        assert detect_fake_metrics(r) == 0
