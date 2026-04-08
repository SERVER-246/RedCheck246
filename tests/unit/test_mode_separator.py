"""Tests for redcheck.core.mode_separator (Phase E)."""

from __future__ import annotations

from redcheck.core.mode_separator import (
    FIDELITY_HIGH,
    FIDELITY_LOW,
    FIDELITY_MEDIUM,
    SegregatedFindings,
    classify_finding,
    segregate_findings,
    stamp_simulation_metadata,
)
from redcheck.models import Finding, FindingSeverity, PluginResult


def _finding(
    execution_mode: str | None = None,
    finding_type: str = "test_finding",
    target: str = "10.0.0.1",
) -> Finding:
    meta: dict = {}
    if execution_mode is not None:
        meta["execution_mode"] = execution_mode
    return Finding(
        finding_type=finding_type,
        target=target,
        severity=FindingSeverity.MEDIUM,
        detail="test",
        metadata=meta,
    )


# ---------------------------------------------------------------------------
# classify_finding
# ---------------------------------------------------------------------------


class TestClassifyFinding:
    def test_defaults_to_real(self):
        assert classify_finding(_finding()) == "real"

    def test_real(self):
        assert classify_finding(_finding("real")) == "real"

    def test_simulated(self):
        assert classify_finding(_finding("simulated")) == "simulated"

    def test_dry_run(self):
        assert classify_finding(_finding("dry_run")) == "dry_run"

    def test_unknown_mode_falls_back_to_real(self):
        assert classify_finding(_finding("unknown_garbage")) == "real"


# ---------------------------------------------------------------------------
# stamp_simulation_metadata
# ---------------------------------------------------------------------------


class TestStampSimulationMetadata:
    def _result_with_findings(self, n: int = 2) -> PluginResult:
        return PluginResult(
            plugin_name="test-plugin",
            success=True,
            findings=[_finding(target=f"host-{i}") for i in range(n)],
        )

    def test_marks_result_metadata(self):
        result = self._result_with_findings(1)
        stamp_simulation_metadata(result)
        assert result.metadata["execution_mode"] == "simulated"

    def test_marks_each_finding(self):
        result = self._result_with_findings(2)
        stamp_simulation_metadata(result)
        for f in result.findings:
            assert f.metadata["simulation_flag"] is True
            assert f.metadata["execution_mode"] == "simulated"
            assert f.metadata["simulation_fidelity"] == FIDELITY_MEDIUM

    def test_default_fidelity_medium(self):
        result = self._result_with_findings(1)
        stamp_simulation_metadata(result)
        assert result.findings[0].metadata["simulation_fidelity"] == FIDELITY_MEDIUM

    def test_custom_fidelity(self):
        result = self._result_with_findings(1)
        stamp_simulation_metadata(result, fidelity=FIDELITY_HIGH)
        assert result.findings[0].metadata["simulation_fidelity"] == FIDELITY_HIGH

        result2 = self._result_with_findings(1)
        stamp_simulation_metadata(result2, fidelity=FIDELITY_LOW)
        assert result2.findings[0].metadata["simulation_fidelity"] == FIDELITY_LOW

    def test_simulated_input_from_target(self):
        result = self._result_with_findings(1)
        stamp_simulation_metadata(result)
        assert result.findings[0].metadata["simulated_input"] == "host-0"

    def test_simulated_input_not_overwritten(self):
        result = self._result_with_findings(1)
        result.findings[0].metadata["simulated_input"] = "custom"
        stamp_simulation_metadata(result)
        assert result.findings[0].metadata["simulated_input"] == "custom"

    def test_expected_real_behavior_set(self):
        result = self._result_with_findings(1)
        stamp_simulation_metadata(result)
        assert "expected_real_behavior" in result.findings[0].metadata
        assert "host-0" in result.findings[0].metadata["expected_real_behavior"]

    def test_expected_real_behavior_not_overwritten(self):
        result = self._result_with_findings(1)
        result.findings[0].metadata["expected_real_behavior"] = "kept"
        stamp_simulation_metadata(result)
        assert result.findings[0].metadata["expected_real_behavior"] == "kept"

    def test_empty_findings(self):
        result = PluginResult(plugin_name="empty", success=True, findings=[])
        stamp_simulation_metadata(result)
        assert result.metadata["execution_mode"] == "simulated"


# ---------------------------------------------------------------------------
# SegregatedFindings
# ---------------------------------------------------------------------------


class TestSegregatedFindings:
    def test_total(self):
        seg = SegregatedFindings(
            real=[_finding()],
            simulated=[_finding(), _finding()],
            dry_run=[_finding()],
        )
        assert seg.total == 4

    def test_total_empty(self):
        seg = SegregatedFindings(real=[], simulated=[], dry_run=[])
        assert seg.total == 0

    def test_to_dict(self):
        seg = SegregatedFindings(
            real=[_finding()] * 3,
            simulated=[_finding()] * 2,
            dry_run=[_finding()],
        )
        d = seg.to_dict()
        assert d == {"real": 3, "simulated": 2, "dry_run": 1}


# ---------------------------------------------------------------------------
# segregate_findings
# ---------------------------------------------------------------------------


class TestSegregatefindings:
    def test_all_real(self):
        findings = [_finding("real"), _finding()]
        seg = segregate_findings(findings)
        assert len(seg.real) == 2
        assert len(seg.simulated) == 0
        assert len(seg.dry_run) == 0

    def test_all_simulated(self):
        findings = [_finding("simulated"), _finding("simulated")]
        seg = segregate_findings(findings)
        assert len(seg.real) == 0
        assert len(seg.simulated) == 2

    def test_all_dry_run(self):
        findings = [_finding("dry_run")]
        seg = segregate_findings(findings)
        assert len(seg.dry_run) == 1
        assert len(seg.real) == 0

    def test_mixed(self):
        findings = [
            _finding("real"),
            _finding("simulated"),
            _finding("dry_run"),
            _finding("simulated"),
        ]
        seg = segregate_findings(findings)
        assert len(seg.real) == 1
        assert len(seg.simulated) == 2
        assert len(seg.dry_run) == 1
        assert seg.total == 4

    def test_empty(self):
        seg = segregate_findings([])
        assert seg.total == 0
