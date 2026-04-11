"""Tests for SystemTrustAssessor (Phase I)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from redcheck.core.trust_assessor import (
    _compute_evidence_coverage,
    _count_contract_violations,
    _count_fake_metrics,
    assess,
)
from redcheck.models import Finding, FindingSeverity, PluginResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FakeQualityScore:
    total: float
    grade: str

    def to_dict(self) -> dict[str, Any]:
        return {"total": self.total, "grade": self.grade}


def _make_result(
    findings: list[Finding] | None = None,
    violations: list[dict[str, str]] | None = None,
) -> PluginResult:
    meta: dict[str, Any] = {}
    if violations:
        meta["contract_violations"] = violations
    return PluginResult(
        plugin_name="test-plugin",
        success=True,
        findings=findings or [],
        metadata=meta,
    )


def _high_finding(*, evidence: bool = True, fake: bool = False) -> Finding:
    meta: dict[str, Any] = {}
    if fake:
        meta["fake_metric_detected"] = True
    return Finding(
        finding_type="vuln",
        target="example.com",
        severity=FindingSeverity.HIGH,
        detail="test",
        evidence_ref="ev-001" if evidence else None,
        metadata=meta,
    )


# ---------------------------------------------------------------------------
# Trust level boundary tests
# ---------------------------------------------------------------------------


class TestAssessTrustLevel:
    """Verify the three trust level thresholds."""

    def test_high_trust(self):
        qs = FakeQualityScore(total=92.0, grade="A")
        results = [_make_result(findings=[_high_finding()])]
        assessment = assess(results, qs)
        assert assessment.trust_level == "HIGH"
        assert assessment.safe_to_use_for_decision is True

    def test_medium_trust(self):
        qs = FakeQualityScore(total=80.0, grade="B")
        viol = [{"rule": "C1", "type": "test", "action": "test"}]
        results = [_make_result(violations=viol)]
        assessment = assess(results, qs)
        assert assessment.trust_level == "MEDIUM"
        assert assessment.safe_to_use_for_decision is True

    def test_low_trust_quality_below_75(self):
        qs = FakeQualityScore(total=60.0, grade="D")
        results = [_make_result()]
        assessment = assess(results, qs)
        assert assessment.trust_level == "LOW"
        assert assessment.safe_to_use_for_decision is False

    def test_low_trust_many_violations(self):
        qs = FakeQualityScore(total=85.0, grade="B")
        viols = [{"rule": f"C{i}", "type": "t", "action": "a"} for i in range(4)]
        results = [_make_result(violations=viols)]
        assessment = assess(results, qs)
        assert assessment.trust_level == "LOW"

    def test_high_quality_but_low_evidence(self):
        """High quality score but evidence below 80% → not HIGH."""
        qs = FakeQualityScore(total=95.0, grade="A")
        findings = [_high_finding(evidence=False) for _ in range(5)]
        results = [_make_result(findings=findings)]
        assessment = assess(results, qs)
        assert assessment.trust_level != "HIGH"

    def test_no_quality_score_gives_low(self):
        results = [_make_result()]
        assessment = assess(results, quality_score=None)
        assert assessment.trust_level == "LOW"

    def test_medium_with_exactly_2_violations(self):
        qs = FakeQualityScore(total=78.0, grade="C")
        viols = [
            {"rule": "C1", "type": "t", "action": "a"},
            {"rule": "C2", "type": "t", "action": "a"},
        ]
        results = [_make_result(violations=viols)]
        assessment = assess(results, qs)
        assert assessment.trust_level == "MEDIUM"


# ---------------------------------------------------------------------------
# Contributing factors
# ---------------------------------------------------------------------------


class TestContributingFactors:
    def test_factors_contain_required_keys(self):
        qs = FakeQualityScore(total=90.0, grade="A")
        results = [_make_result(findings=[_high_finding()])]
        assessment = assess(results, qs)
        factors = assessment.contributing_factors
        assert "quality_grade" in factors
        assert "contract_violations" in factors
        assert "evidence_coverage_pct" in factors
        assert "fake_metrics_detected" in factors

    def test_to_dict_roundtrip(self):
        qs = FakeQualityScore(total=90.0, grade="A")
        results = [_make_result(findings=[_high_finding()])]
        assessment = assess(results, qs)
        d = assessment.to_dict()
        assert d["trust_level"] == assessment.trust_level
        assert d["safe_to_use_for_decision"] == assessment.safe_to_use_for_decision


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_count_violations_empty(self):
        assert _count_contract_violations([_make_result()]) == 0

    def test_count_violations_multiple(self):
        viols = [{"rule": "C1"}, {"rule": "C2"}]
        assert _count_contract_violations([_make_result(violations=viols)]) == 2

    def test_evidence_coverage_all(self):
        f = [_high_finding(evidence=True)]
        assert _compute_evidence_coverage([_make_result(findings=f)]) == 100.0

    def test_evidence_coverage_none(self):
        f = [_high_finding(evidence=False)]
        assert _compute_evidence_coverage([_make_result(findings=f)]) == 0.0

    def test_evidence_coverage_no_findings(self):
        assert _compute_evidence_coverage([_make_result()]) == 100.0

    def test_count_fake_metrics(self):
        f = [_high_finding(fake=True), _high_finding(fake=False)]
        assert _count_fake_metrics([_make_result(findings=f)]) == 1
