"""Tests for redcheck.core.production_readiness (Phase J)."""

from __future__ import annotations

from redcheck.core.production_readiness import (
    _check_attack_chains,
    _check_detection_uses_real_signals,
    _check_enrichment,
    _check_evidence_coverage,
    _check_failures_explained,
    _check_no_fake_metrics,
    _check_reports_reproducible,
    check_production_readiness,
)
from redcheck.models import Finding, FindingSeverity
from redcheck.plugins.base_plugin import PluginResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(**overrides) -> Finding:
    defaults = {
        "finding_type": "vuln",
        "target": "10.0.0.1",
        "severity": FindingSeverity.HIGH,
        "detail": "test detail",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def _result(name="plug-a", success=True, findings=None, evidence=None, **kw) -> PluginResult:
    return PluginResult(
        plugin_name=name,
        success=success,
        findings=findings or [],
        evidence=evidence or [],
        **kw,
    )


# ---------------------------------------------------------------------------
# Evidence coverage
# ---------------------------------------------------------------------------


class TestEvidenceCoverage:
    def test_no_findings_vacuous_true(self):
        results = {"a": _result()}
        assert _check_evidence_coverage(results) is True

    def test_all_have_evidence_ref(self):
        f = _finding(evidence_ref="ref-1")
        results = {"a": _result(findings=[f])}
        assert _check_evidence_coverage(results) is True

    def test_all_have_evidence_digest(self):
        f = _finding(evidence_digest="sha256:abc")
        results = {"a": _result(findings=[f])}
        assert _check_evidence_coverage(results) is True

    def test_below_threshold(self):
        with_ev = _finding(evidence_ref="ref-1")
        no_ev = [_finding() for _ in range(5)]
        results = {"a": _result(findings=[with_ev] + no_ev)}
        assert _check_evidence_coverage(results) is False

    def test_at_threshold(self):
        with_ev = [_finding(evidence_ref=f"r{i}") for i in range(4)]
        no_ev = _finding()
        results = {"a": _result(findings=with_ev + [no_ev])}
        assert _check_evidence_coverage(results) is True


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------


class TestEnrichment:
    def test_no_findings_vacuous_true(self):
        results = {"a": _result()}
        assert _check_enrichment(results) is True

    def test_all_enriched_cwe(self):
        f = _finding(cwe_id="CWE-79")
        results = {"a": _result(findings=[f])}
        assert _check_enrichment(results) is True

    def test_all_enriched_cvss(self):
        f = _finding(cvss_score=7.5)
        results = {"a": _result(findings=[f])}
        assert _check_enrichment(results) is True

    def test_below_threshold(self):
        enriched = _finding(cwe_id="CWE-79")
        plain = [_finding() for _ in range(5)]
        results = {"a": _result(findings=[enriched] + plain)}
        assert _check_enrichment(results) is False


# ---------------------------------------------------------------------------
# Fake metrics
# ---------------------------------------------------------------------------


class TestNoFakeMetrics:
    def test_no_fakes(self):
        assert _check_no_fake_metrics({"fake_metric_count": 0}) is True

    def test_fakes_detected(self):
        assert _check_no_fake_metrics({"fake_metric_count": 3}) is False

    def test_missing_key_treated_as_zero(self):
        assert _check_no_fake_metrics({}) is True


# ---------------------------------------------------------------------------
# Failures explained
# ---------------------------------------------------------------------------


class TestFailuresExplained:
    def test_all_failures_have_types(self):
        r = _result(success=False, error_type="network_error", failure_stage="execution")
        results = {"a": r}
        assert _check_failures_explained(results) is True

    def test_missing_error_type(self):
        r = _result(success=False, error_type=None, failure_stage="execution")
        results = {"a": r}
        assert _check_failures_explained(results) is False

    def test_missing_failure_stage(self):
        r = _result(success=False, error_type="network_error", failure_stage=None)
        results = {"a": r}
        assert _check_failures_explained(results) is False

    def test_successful_plugins_ignored(self):
        r = _result(success=True)
        results = {"a": r}
        assert _check_failures_explained(results) is True


# ---------------------------------------------------------------------------
# Detection uses real signals
# ---------------------------------------------------------------------------


class TestDetectionRealSignals:
    def test_live_mode_always_ok(self):
        f = _finding()
        r = _result(mode="live", findings=[f])
        results = {"a": r}
        assert _check_detection_uses_real_signals(results) is True

    def test_simulated_with_evidence_ok(self):
        from redcheck.models import Evidence

        f = _finding()
        ev = Evidence(evidence_type="file", path="/tmp/x", sha256="abc123")
        r = _result(mode="simulated", findings=[f], evidence=[ev])
        results = {"a": r}
        assert _check_detection_uses_real_signals(results) is True

    def test_simulated_without_evidence_fail(self):
        f = _finding()
        r = _result(mode="simulated", findings=[f])
        results = {"a": r}
        assert _check_detection_uses_real_signals(results) is False


# ---------------------------------------------------------------------------
# Attack chains
# ---------------------------------------------------------------------------


class TestAttackChains:
    def test_has_source_chain(self):
        f = _finding(source_chain=["recon", "exploit"])
        results = {"a": _result(findings=[f])}
        assert _check_attack_chains(results) is True

    def test_no_source_chain(self):
        f = _finding()
        results = {"a": _result(findings=[f])}
        assert _check_attack_chains(results) is False

    def test_no_findings_vacuous_true(self):
        results = {"a": _result()}
        assert _check_attack_chains(results) is True


# ---------------------------------------------------------------------------
# Reports reproducible
# ---------------------------------------------------------------------------


class TestReportsReproducible:
    def test_high_trust_passes(self):
        assert _check_reports_reproducible({"level": "HIGH"}) is True

    def test_medium_trust_passes(self):
        assert _check_reports_reproducible({"level": "MEDIUM"}) is True

    def test_low_trust_fails(self):
        assert _check_reports_reproducible({"level": "LOW"}) is False

    def test_missing_trust_defaults_low(self):
        assert _check_reports_reproducible({}) is False


# ---------------------------------------------------------------------------
# Integration — check_production_readiness
# ---------------------------------------------------------------------------


class TestCheckProductionReadiness:
    def test_all_pass_scenario(self):
        f = _finding(
            evidence_ref="ref-1",
            cwe_id="CWE-79",
            source_chain=["recon", "exploit"],
        )
        r = _result(findings=[f])
        result = check_production_readiness(
            results={"a": r},
            quality_score={"fake_metric_count": 0},
            trust={"level": "HIGH"},
            chain_mode_enabled=True,
        )
        assert result["all_pass"] is True
        assert result["evidence_coverage_ge_80"] is True
        assert result["enrichment_ge_80"] is True
        assert result["no_fake_metrics"] is True
        assert result["chain_mode_enabled"] is True

    def test_not_all_pass_when_chain_disabled(self):
        f = _finding(
            evidence_ref="ref-1",
            cwe_id="CWE-79",
            source_chain=["recon"],
        )
        r = _result(findings=[f])
        result = check_production_readiness(
            results={"a": r},
            quality_score={"fake_metric_count": 0},
            trust={"level": "HIGH"},
            chain_mode_enabled=False,
        )
        assert result["chain_mode_enabled"] is False
        assert result["all_pass"] is False

    def test_empty_results(self):
        result = check_production_readiness(
            results={},
            quality_score={"fake_metric_count": 0},
            trust={"level": "HIGH"},
            chain_mode_enabled=True,
        )
        # All vacuously true except reports_reproducible uses trust
        assert result["evidence_coverage_ge_80"] is True
        assert result["enrichment_ge_80"] is True
        assert result["all_failures_explained"] is True

    def test_none_defaults(self):
        """None quality_score and trust default gracefully."""
        result = check_production_readiness(results={})
        assert isinstance(result, dict)
        assert "all_pass" in result
