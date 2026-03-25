"""Tests for redcheck.core.quality_scorer."""

from __future__ import annotations

import pytest

from redcheck.core.quality_scorer import (
    QualityScore,
    _compute_grade,
    _detection_realism,
    _enrichment_completeness,
    _evidence_coverage,
    _is_detection_plugin,
    _plugin_success_rate,
    _plugin_weight,
    score_engagement,
)
from redcheck.models import Evidence, Finding, FindingSeverity, PluginResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "finding_type": "test",
        "target": "10.0.0.1",
        "severity": FindingSeverity.HIGH,
        "detail": "test finding",
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def _evidence() -> Evidence:
    return Evidence(
        evidence_type="capture",
        path="/tmp/ev.pcap",
        sha256="a" * 64,
        collected_at="2025-01-01T00:00:00Z",
    )


def _result(
    name: str = "test-plugin",
    success: bool = True,
    findings: list[Finding] | None = None,
    evidence: list[Evidence] | None = None,
    errors: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> PluginResult:
    return PluginResult(
        plugin_name=name,
        success=success,
        findings=findings or [],
        evidence=evidence or [],
        errors=errors or [],
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# Grade thresholds
# ---------------------------------------------------------------------------

class TestComputeGrade:
    def test_grade_a(self) -> None:
        assert _compute_grade(100.0) == "A"
        assert _compute_grade(90.0) == "A"

    def test_grade_b(self) -> None:
        assert _compute_grade(89.9) == "B"
        assert _compute_grade(75.0) == "B"

    def test_grade_c(self) -> None:
        assert _compute_grade(74.9) == "C"
        assert _compute_grade(50.0) == "C"

    def test_grade_d(self) -> None:
        assert _compute_grade(49.9) == "D"
        assert _compute_grade(25.0) == "D"

    def test_grade_f(self) -> None:
        assert _compute_grade(24.9) == "F"
        assert _compute_grade(0.0) == "F"


# ---------------------------------------------------------------------------
# Evidence Coverage
# ---------------------------------------------------------------------------

class TestEvidenceCoverage:
    def test_no_findings(self) -> None:
        score, details = _evidence_coverage([])
        assert score == 0.0
        assert details["total_findings"] == 0

    def test_all_have_evidence(self) -> None:
        findings = [_finding(evidence_ref="ev-1"), _finding(evidence_ref="ev-2")]
        score, details = _evidence_coverage(findings)
        assert score == 25.0
        assert details["with_evidence"] == 2

    def test_half_have_evidence(self) -> None:
        findings = [_finding(evidence_ref="ev-1"), _finding()]
        score, _ = _evidence_coverage(findings)
        assert score == pytest.approx(12.5)

    def test_none_have_evidence(self) -> None:
        findings = [_finding(), _finding()]
        score, details = _evidence_coverage(findings)
        assert score == 0.0
        assert details["with_evidence"] == 0


# ---------------------------------------------------------------------------
# Enrichment Completeness
# ---------------------------------------------------------------------------

class TestEnrichmentCompleteness:
    def test_no_findings(self) -> None:
        score, _ = _enrichment_completeness([])
        assert score == 0.0

    def test_fully_enriched(self) -> None:
        f = _finding(
            cvss_score=9.8,
            cwe_id="CWE-79",
            remediation="patch it",
            mitre_technique="T1059",
        )
        score, details = _enrichment_completeness([f])
        assert score == 25.0
        assert details["avg_population_ratio"] == 1.0

    def test_half_enriched(self) -> None:
        f = _finding(cvss_score=7.0, cwe_id="CWE-89")
        score, details = _enrichment_completeness([f])
        assert score == pytest.approx(12.5)
        assert details["avg_population_ratio"] == 0.5

    def test_not_enriched(self) -> None:
        score, _ = _enrichment_completeness([_finding()])
        assert score == 0.0


# ---------------------------------------------------------------------------
# Plugin Weight
# ---------------------------------------------------------------------------

class TestPluginWeight:
    def test_success_with_findings_and_evidence(self) -> None:
        r = _result(findings=[_finding()], evidence=[_evidence()])
        assert _plugin_weight(r) == 1.0

    def test_success_with_findings_no_evidence(self) -> None:
        r = _result(findings=[_finding()])
        assert _plugin_weight(r) == 0.5

    def test_success_no_findings(self) -> None:
        r = _result()
        assert _plugin_weight(r) == 0.3

    def test_partial_contract(self) -> None:
        r = _result(metadata={"contract_status": "PARTIAL"})
        assert _plugin_weight(r) == 0.3

    def test_failed_with_errors(self) -> None:
        r = _result(success=False, errors=["timeout"])
        assert _plugin_weight(r) == 0.1

    def test_failed_empty(self) -> None:
        r = _result(success=False)
        assert _plugin_weight(r) == 0.0


# ---------------------------------------------------------------------------
# Plugin Success Rate
# ---------------------------------------------------------------------------

class TestPluginSuccessRate:
    def test_empty(self) -> None:
        score, details = _plugin_success_rate([])
        assert score == 0.0
        assert details["total_plugins"] == 0

    def test_all_perfect(self) -> None:
        results = [
            _result(name="a", findings=[_finding()], evidence=[_evidence()]),
            _result(name="b", findings=[_finding()], evidence=[_evidence()]),
        ]
        score, _ = _plugin_success_rate(results)
        assert score == 25.0

    def test_mixed(self) -> None:
        results = [
            _result(name="a", findings=[_finding()], evidence=[_evidence()]),  # 1.0
            _result(name="b", success=False),  # 0.0
        ]
        score, _ = _plugin_success_rate(results)
        assert score == pytest.approx(12.5)


# ---------------------------------------------------------------------------
# Detection Plugin Matching
# ---------------------------------------------------------------------------

class TestIsDetectionPlugin:
    def test_alert_latency(self) -> None:
        assert _is_detection_plugin("alert-latency") is True

    def test_detection_coverage(self) -> None:
        assert _is_detection_plugin("detection-coverage") is True

    def test_persistence_validator(self) -> None:
        assert _is_detection_plugin("persistence-validator") is True

    def test_response_recorder(self) -> None:
        assert _is_detection_plugin("detection-response-recorder") is True

    def test_underscore_variant(self) -> None:
        assert _is_detection_plugin("alert_latency") is True

    def test_non_detection(self) -> None:
        assert _is_detection_plugin("network-scanner") is False


# ---------------------------------------------------------------------------
# Detection Realism
# ---------------------------------------------------------------------------

class TestDetectionRealism:
    def test_no_detection_plugins(self) -> None:
        score, details = _detection_realism([_result(name="network-scanner")])
        assert score == 0.0
        assert details["detection_plugins_found"] == 0

    def test_depth_2_with_evidence(self) -> None:
        r = _result(
            name="alert-latency",
            findings=[_finding()],
            evidence=[_evidence()],
            metadata={"simulation_depth": 2},
        )
        score, details = _detection_realism([r])
        assert score == 6.25
        assert details["per_plugin"]["alert-latency"]["points"] == 6.25

    def test_depth_1(self) -> None:
        r = _result(
            name="detection-coverage",
            findings=[_finding()],
            metadata={"simulation_depth": 1},
        )
        score, _ = _detection_realism([r])
        assert score == 3.0

    def test_depth_0_with_findings_is_fake(self) -> None:
        r = _result(
            name="persistence-validator",
            findings=[_finding()],
            metadata={"simulation_depth": 0},
        )
        score, _ = _detection_realism([r])
        assert score == 0.0

    def test_depth_0_no_findings_honest(self) -> None:
        r = _result(name="detection-response-recorder")
        score, _ = _detection_realism([r])
        assert score == 1.0

    def test_all_four_perfect(self) -> None:
        names = [
            "alert-latency",
            "detection-coverage",
            "persistence-validator",
            "detection-response-recorder",
        ]
        results = [
            _result(
                name=n,
                findings=[_finding()],
                evidence=[_evidence()],
                metadata={"simulation_depth": 3},
            )
            for n in names
        ]
        score, _ = _detection_realism(results)
        assert score == 25.0

    def test_capped_at_25(self) -> None:
        # Even if >4 detection plugins somehow, cap at 25
        names = ["alert-latency", "detection-coverage", "persistence-validator",
                 "detection-response-recorder", "response-recorder-custom"]
        results = [
            _result(
                name=n,
                findings=[_finding()],
                evidence=[_evidence()],
                metadata={"simulation_depth": 5},
            )
            for n in names
        ]
        score, _ = _detection_realism(results)
        assert score == 25.0


# ---------------------------------------------------------------------------
# Full Scoring
# ---------------------------------------------------------------------------

class TestScoreEngagement:
    def test_empty_results(self) -> None:
        qs = score_engagement([])
        assert qs.total == 0.0
        assert qs.grade == "F"

    def test_perfect_score(self) -> None:
        detection_names = [
            "alert-latency",
            "detection-coverage",
            "persistence-validator",
            "detection-response-recorder",
        ]
        results: list[PluginResult] = []
        for name in detection_names:
            results.append(
                _result(
                    name=name,
                    findings=[
                        _finding(
                            evidence_ref="ev-1",
                            cvss_score=9.8,
                            cwe_id="CWE-79",
                            remediation="fix",
                            mitre_technique="T1059",
                        ),
                    ],
                    evidence=[_evidence()],
                    metadata={"simulation_depth": 3},
                )
            )
        qs = score_engagement(results)
        assert qs.evidence_coverage == 25.0
        assert qs.enrichment_completeness == 25.0
        assert qs.plugin_success_rate == 25.0
        assert qs.detection_realism == 25.0
        assert qs.total == 100.0
        assert qs.grade == "A"

    def test_to_dict(self) -> None:
        qs = score_engagement([])
        d = qs.to_dict()
        assert "total" in d
        assert "grade" in d
        assert "details" in d
        assert d["grade"] == "F"

    def test_grade_b_scenario(self) -> None:
        # Some enrichment, some evidence, decent plugin success
        results = [
            _result(
                name="scanner-a",
                findings=[
                    _finding(evidence_ref="ev-1", cvss_score=8.0, cwe_id="CWE-89"),
                    _finding(cvss_score=5.0, cwe_id="CWE-79"),
                ],
                evidence=[_evidence()],
            ),
            _result(
                name="alert-latency",
                findings=[_finding(evidence_ref="ev-2", cvss_score=7.0)],
                evidence=[_evidence()],
                metadata={"simulation_depth": 2},
            ),
            _result(
                name="detection-coverage",
                findings=[_finding(evidence_ref="ev-3", cvss_score=6.0)],
                evidence=[_evidence()],
                metadata={"simulation_depth": 2},
            ),
            _result(
                name="persistence-validator",
                findings=[_finding(evidence_ref="ev-4", cvss_score=5.0)],
                evidence=[_evidence()],
                metadata={"simulation_depth": 2},
            ),
            _result(
                name="detection-response-recorder",
                findings=[_finding(evidence_ref="ev-5", cvss_score=4.0)],
                evidence=[_evidence()],
                metadata={"simulation_depth": 2},
            ),
        ]
        qs = score_engagement(results)
        # All detection perfect → 25, high plugin rate, good evidence coverage
        assert qs.total >= 75.0
        assert qs.grade in ("A", "B")


class TestQualityScoreDataclass:
    def test_immutable(self) -> None:
        qs = QualityScore(
            evidence_coverage=10.0,
            enrichment_completeness=10.0,
            plugin_success_rate=10.0,
            detection_realism=10.0,
            total=40.0,
            grade="C",
        )
        with pytest.raises(AttributeError):
            qs.total = 99.0  # type: ignore[misc]

    def test_to_dict_rounding(self) -> None:
        qs = QualityScore(
            evidence_coverage=12.333333,
            enrichment_completeness=8.666666,
            plugin_success_rate=20.123456,
            detection_realism=6.25,
            total=47.373455,
            grade="C",
        )
        d = qs.to_dict()
        assert d["evidence_coverage"] == 12.33
        assert d["enrichment_completeness"] == 8.67
        assert d["plugin_success_rate"] == 20.12
        assert d["detection_realism"] == 6.25
        assert d["total"] == 47.37
