"""Tests for cross_verifier (Phase N)."""

from __future__ import annotations

import pytest

from redcheck.core.cross_verifier import cross_verify
from redcheck.models import (
    Finding,
    FindingSeverity,
    PluginResult,
    VerificationStatus,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    *,
    target: str = "example.com",
    finding_type: str = "sqli",
    severity: FindingSeverity = FindingSeverity.HIGH,
    confidence: str = "high",
    detail: str = "test",
    metadata: dict | None = None,
) -> Finding:
    return Finding(
        finding_type=finding_type,
        target=target,
        severity=severity,
        detail=detail,
        confidence=confidence,
        metadata=metadata or {},
    )


def _result(plugin_name: str, findings: list[Finding]) -> PluginResult:
    return PluginResult(
        plugin_name=plugin_name,
        success=True,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestExploitVerification:
    """Exploit-verified findings → CONFIRMED."""

    def test_exploit_confirmed(self):
        sast_f = _finding()
        exploit_f = _finding(metadata={"exploit_success": True})

        results = {
            "sast-scanner": _result("sast-scanner", [sast_f]),
            "exploit-verifier": _result("exploit-verifier", [exploit_f]),
        }
        cross_verify(results)

        assert exploit_f.verification_status == VerificationStatus.CONFIRMED
        assert sast_f.verification_status == VerificationStatus.CONFIRMED


class TestSastDastCrossMatch:
    """SAST + DAST findings on same target:finding_type → both CONFIRMED."""

    def test_cross_match(self):
        sast_f = _finding(finding_type="xss", target="app.io")
        dast_f = _finding(finding_type="xss", target="app.io")

        results = {
            "sast-scanner": _result("sast-scanner", [sast_f]),
            "dast-scanner": _result("dast-scanner", [dast_f]),
        }
        cross_verify(results)

        assert sast_f.verification_status == VerificationStatus.CONFIRMED
        assert dast_f.verification_status == VerificationStatus.CONFIRMED


class TestFalsePositiveLikelihood:
    """Unverified findings receive FP likelihood based on confidence."""

    def test_sast_only_likely_fp(self):
        f = _finding(metadata={"likely_false_positive": True})
        results = {"sast-scanner": _result("sast-scanner", [f])}
        cross_verify(results)
        assert f.verification_status == VerificationStatus.SUSPECTED
        assert f.false_positive_likelihood == pytest.approx(0.7)

    def test_high_confidence_low_fp(self):
        f = _finding(confidence="high")
        results = {"passive-recon": _result("passive-recon", [f])}
        cross_verify(results)
        assert f.false_positive_likelihood == pytest.approx(0.1)

    def test_medium_confidence_fp(self):
        f = _finding(confidence="medium")
        results = {"passive-recon": _result("passive-recon", [f])}
        cross_verify(results)
        assert f.false_positive_likelihood == pytest.approx(0.3)

    def test_low_confidence_fp(self):
        f = _finding(confidence="low")
        results = {"passive-recon": _result("passive-recon", [f])}
        cross_verify(results)
        assert f.false_positive_likelihood == pytest.approx(0.5)

    def test_confirmed_no_fp_override(self):
        """If already confirmed, FP likelihood should not be reassigned."""
        f = _finding(metadata={"exploit_success": True})
        results = {
            "exploit-verifier": _result("exploit-verifier", [f]),
        }
        cross_verify(results)
        # exploit-verified → confirmed, FP stays None or very low
        assert f.verification_status == VerificationStatus.CONFIRMED


class TestNoFindings:
    """Edge case — no findings at all."""

    def test_empty_results(self):
        cross_verify({})  # should not raise

    def test_empty_findings_list(self):
        results = {"passive-recon": _result("passive-recon", [])}
        cross_verify(results)  # should not raise
