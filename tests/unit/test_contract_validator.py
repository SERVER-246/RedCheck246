"""Tests for redcheck.core.contract_validator — cover C3, C4, C5, C6."""

from __future__ import annotations

from unittest.mock import MagicMock

from redcheck.core.contract_validator import (
    _check_c1_no_empty_output,
    _check_c2_no_zero_duration,
    _check_c3_evidence_required,
    _check_c4_enrichment_completeness,
    _check_c5_fake_metric,
    _check_c6_mode_declaration,
    validate_contract,
)
from redcheck.models import FindingSeverity


def _make_finding(severity=FindingSeverity.INFO, evidence_ref=None, metadata=None, **kw):
    f = MagicMock()
    f.severity = severity
    f.evidence_ref = evidence_ref
    f.metadata = metadata if metadata is not None else {}
    f.finding_type = kw.get("finding_type", "test")
    f.cvss_score = kw.get("cvss_score")
    f.cwe_id = kw.get("cwe_id")
    f.remediation = kw.get("remediation")
    return f


def _make_result(success=True, findings=None, metadata=None):
    r = MagicMock()
    r.success = success
    r.findings = findings or []
    r.metadata = metadata if metadata is not None else {}
    return r


class TestC1NoEmptyOutput:
    def test_success_with_no_findings_downgrades(self):
        r = _make_result(success=True, findings=[])
        v = _check_c1_no_empty_output(r)
        assert len(v) == 1
        assert v[0]["rule"] == "C1"
        assert r.metadata["contract_status"] == "PARTIAL"

    def test_success_with_findings_no_violation(self):
        r = _make_result(success=True, findings=[_make_finding()])
        v = _check_c1_no_empty_output(r)
        assert v == []

    def test_failure_no_violation(self):
        r = _make_result(success=False, findings=[])
        v = _check_c1_no_empty_output(r)
        assert v == []


class TestC2NoZeroDuration:
    def test_zero_duration_flags(self):
        r = _make_result(metadata={"duration_seconds": 0.0})
        v = _check_c2_no_zero_duration(r)
        assert len(v) == 1
        assert v[0]["rule"] == "C2"
        assert r.metadata["timing_unverified"] is True

    def test_missing_duration_flags(self):
        r = _make_result(metadata={})
        v = _check_c2_no_zero_duration(r)
        assert len(v) == 1

    def test_positive_duration_ok(self):
        r = _make_result(metadata={"duration_seconds": 5.0})
        v = _check_c2_no_zero_duration(r)
        assert v == []


class TestC3EvidenceRequired:
    def test_medium_finding_without_evidence_downgrades(self):
        f = _make_finding(severity=FindingSeverity.MEDIUM)
        r = _make_result(findings=[f])
        v = _check_c3_evidence_required(r)
        assert len(v) == 1
        assert v[0]["rule"] == "C3"
        assert f.metadata["unverified"] is True
        assert f.metadata["confidence"] == "low"

    def test_high_finding_without_evidence(self):
        f = _make_finding(severity=FindingSeverity.HIGH)
        r = _make_result(findings=[f])
        v = _check_c3_evidence_required(r)
        assert len(v) == 1

    def test_critical_finding_without_evidence(self):
        f = _make_finding(severity=FindingSeverity.CRITICAL)
        r = _make_result(findings=[f])
        v = _check_c3_evidence_required(r)
        assert len(v) == 1

    def test_medium_with_evidence_ok(self):
        f = _make_finding(severity=FindingSeverity.MEDIUM, evidence_ref="ev/001")
        r = _make_result(findings=[f])
        v = _check_c3_evidence_required(r)
        assert v == []

    def test_info_finding_no_violation(self):
        f = _make_finding(severity=FindingSeverity.INFO)
        r = _make_result(findings=[f])
        v = _check_c3_evidence_required(r)
        assert v == []

    def test_low_finding_no_violation(self):
        f = _make_finding(severity=FindingSeverity.LOW)
        r = _make_result(findings=[f])
        v = _check_c3_evidence_required(r)
        assert v == []


class TestC4EnrichmentCompleteness:
    def test_non_info_missing_all_enrichment(self):
        f = _make_finding(severity=FindingSeverity.HIGH)
        r = _make_result(findings=[f])
        v = _check_c4_enrichment_completeness(r)
        assert len(v) == 1
        assert v[0]["rule"] == "C4"
        assert "cvss" in v[0]["missing"]
        assert "cwe" in v[0]["missing"]
        assert "remediation" in v[0]["missing"]

    def test_info_finding_skipped(self):
        f = _make_finding(severity=FindingSeverity.INFO)
        r = _make_result(findings=[f])
        v = _check_c4_enrichment_completeness(r)
        assert v == []

    def test_fully_enriched_no_violation(self):
        f = _make_finding(
            severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            cwe_id="CWE-79",
            remediation="fix",
        )
        r = _make_result(findings=[f])
        v = _check_c4_enrichment_completeness(r)
        assert v == []

    def test_metadata_enrichment_counts(self):
        f = _make_finding(
            severity=FindingSeverity.MEDIUM,
            metadata={"cvss_score": 5.0, "cwe_id": "CWE-89", "remediation": "r"},
        )
        r = _make_result(findings=[f])
        v = _check_c4_enrichment_completeness(r)
        assert v == []

    def test_partial_enrichment_gaps(self):
        f = _make_finding(
            severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            # missing cwe_id and remediation
        )
        r = _make_result(findings=[f])
        v = _check_c4_enrichment_completeness(r)
        assert len(v) == 1
        assert "cwe" in v[0]["missing"]
        assert "remediation" in v[0]["missing"]
        assert "cvss" not in v[0]["missing"]


class TestC5FakeMetric:
    def test_flagged_finding(self):
        f = _make_finding(metadata={"fake_metric_detected": True})
        r = _make_result(findings=[f])
        v = _check_c5_fake_metric(r)
        assert len(v) == 1
        assert v[0]["rule"] == "C5"

    def test_clean_finding_no_violation(self):
        f = _make_finding()
        r = _make_result(findings=[f])
        v = _check_c5_fake_metric(r)
        assert v == []


class TestC6ModeDeclaration:
    def test_missing_mode_infers(self):
        r = _make_result(metadata={})
        v = _check_c6_mode_declaration(r)
        assert len(v) == 1
        assert v[0]["rule"] == "C6"
        assert r.metadata["execution_mode"] == "inferred"
        assert r.metadata["mode_inferred"] is True

    def test_mode_present_no_violation(self):
        r = _make_result(metadata={"execution_mode": "live"})
        v = _check_c6_mode_declaration(r)
        assert v == []


class TestValidateContract:
    def test_all_violations_collected(self):
        r = _make_result(success=True, findings=[], metadata={})
        violations = validate_contract(r)
        # C1 (success + no findings) + C2 (zero duration) + C6 (no mode)
        rules = {v["rule"] for v in violations}
        assert "C1" in rules
        assert "C2" in rules
        assert "C6" in rules
        assert r.metadata["contract_violations"] == violations

    def test_clean_result_no_violations(self):
        f = _make_finding(
            severity=FindingSeverity.INFO,
            evidence_ref="ev/1",
        )
        r = _make_result(
            success=True,
            findings=[f],
            metadata={"duration_seconds": 5.0, "execution_mode": "live"},
        )
        violations = validate_contract(r)
        assert violations == []

    def test_multiple_findings_violations(self):
        f1 = _make_finding(severity=FindingSeverity.HIGH, finding_type="xss")
        f2 = _make_finding(severity=FindingSeverity.CRITICAL, finding_type="sqli")
        r = _make_result(
            success=True,
            findings=[f1, f2],
            metadata={"duration_seconds": 2.0, "execution_mode": "live"},
        )
        violations = validate_contract(r)
        c3_violations = [v for v in violations if v["rule"] == "C3"]
        c4_violations = [v for v in violations if v["rule"] == "C4"]
        assert len(c3_violations) == 2  # both need evidence
        assert len(c4_violations) == 2  # both missing enrichment
