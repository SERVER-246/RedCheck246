"""Tests for contract checks C7 and C9 (Phase H)."""

from __future__ import annotations

from unittest.mock import MagicMock

from redcheck.core.contract_validator import (
    _check_c7_failure_transparency,
    _check_c9_no_fabrication,
)


def _make_result(success=True, error_type=None, failure_stage=None, metadata=None, findings=None):
    r = MagicMock()
    r.success = success
    r.error_type = error_type
    r.failure_stage = failure_stage
    r.error_message = "some error" if not success else None
    r.metadata = metadata if metadata is not None else {}
    r.findings = findings or []
    return r


class TestC7FailureTransparency:
    def test_successful_result_passes(self):
        result = _make_result(success=True)
        _check_c7_failure_transparency(result)
        # No exception or modification expected

    def test_failed_result_with_fields_passes(self):
        result = _make_result(
            success=False,
            error_type="network_error",
            failure_stage="execution",
        )
        _check_c7_failure_transparency(result)
        # Should pass — fields are set

    def test_failed_result_without_fields_gets_unknown(self):
        result = _make_result(success=False, error_type=None, failure_stage=None)
        _check_c7_failure_transparency(result)
        assert result.error_type == "unknown"
        assert result.failure_stage == "unknown"

    def test_failed_result_with_metadata_fallback(self):
        result = _make_result(
            success=False,
            error_type=None,
            failure_stage=None,
            metadata={"error_type": "policy_denied", "failure_stage": "pre_execution"},
        )
        _check_c7_failure_transparency(result)
        assert result.error_type == "policy_denied"
        assert result.failure_stage == "pre_execution"


class TestC9NoFabrication:
    def test_clean_finding_passes(self):
        finding = MagicMock()
        finding.detail = "Real finding with 5 results"
        finding.metadata = {}
        result = _make_result(findings=[finding])
        _check_c9_no_fabrication(result)
        assert "c9_replaced" not in finding.metadata

    def test_finding_with_zero_ms_gets_replaced(self):
        finding = MagicMock()
        finding.detail = "Response time: 0.0ms average"
        finding.metadata = {"fake_metric_detected": True}
        result = _make_result(findings=[finding])
        _check_c9_no_fabrication(result)
        assert finding.metadata.get("c9_replaced") is True
        assert "UNKNOWN" in finding.detail

    def test_finding_with_zero_percent_gets_replaced(self):
        finding = MagicMock()
        finding.detail = "Coverage: 0.0% of targets"
        finding.metadata = {"fake_metric_detected": True}
        result = _make_result(findings=[finding])
        _check_c9_no_fabrication(result)
        assert finding.metadata.get("c9_replaced") is True
