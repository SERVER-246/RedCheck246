"""RedCheck246 — Production Readiness Auto-Check (Phase J).

Automated checklist that evaluates whether a scan run meets production
quality thresholds.  Returns a structured dict suitable for embedding
in the final report.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from redcheck.plugins.base_plugin import PluginResult

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Threshold constants
# ---------------------------------------------------------------------------
_EVIDENCE_COVERAGE_THRESHOLD = 0.80
_ENRICHMENT_THRESHOLD = 0.80


def check_production_readiness(
    results: dict[str, PluginResult],
    quality_score: dict[str, Any] | None = None,
    trust: dict[str, Any] | None = None,
    *,
    chain_mode_enabled: bool = False,
) -> dict[str, Any]:
    """Evaluate production-readiness criteria against scan results.

    Args:
        results: Plugin name → PluginResult mapping from the orchestrator.
        quality_score: Pre-computed quality score dict (from QualityScorer).
        trust: System trust assessment dict (from TrustAssessor).
        chain_mode_enabled: Whether the pipeline ran in chain mode.

    Returns:
        Dict with boolean checks and an ``all_pass`` aggregate.
    """
    quality_score = quality_score or {}
    trust = trust or {}

    evidence_coverage = _check_evidence_coverage(results)
    enrichment_adequate = _check_enrichment(results)
    no_fake_metrics = _check_no_fake_metrics(quality_score)
    all_failures_explained = _check_failures_explained(results)
    detection_real_signals = _check_detection_uses_real_signals(results)
    attack_chains_generated = _check_attack_chains(results)
    reports_reproducible = _check_reports_reproducible(trust)

    checks = {
        "evidence_coverage_ge_80": evidence_coverage,
        "enrichment_ge_80": enrichment_adequate,
        "no_fake_metrics": no_fake_metrics,
        "all_failures_explained": all_failures_explained,
        "chain_mode_enabled": chain_mode_enabled,
        "detection_uses_real_signals": detection_real_signals,
        "attack_chains_generated": attack_chains_generated,
        "reports_reproducible": reports_reproducible,
    }

    checks["all_pass"] = all(checks.values())

    log.info(
        "production_readiness_check",
        all_pass=checks["all_pass"],
        passed=sum(1 for v in checks.values() if v is True),
        total=len(checks) - 1,  # exclude all_pass from count
    )

    return checks


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------


def _check_evidence_coverage(results: dict[str, PluginResult]) -> bool:
    """At least 80% of findings have evidence references."""
    total_findings = 0
    with_evidence = 0
    for pr in results.values():
        for f in pr.findings:
            total_findings += 1
            if f.evidence_ref or f.evidence_digest:
                with_evidence += 1
    if total_findings == 0:
        return True  # vacuously true
    return (with_evidence / total_findings) >= _EVIDENCE_COVERAGE_THRESHOLD


def _check_enrichment(results: dict[str, PluginResult]) -> bool:
    """At least 80% of findings have CWE or CVSS enrichment."""
    total_findings = 0
    enriched = 0
    for pr in results.values():
        for f in pr.findings:
            total_findings += 1
            if f.cwe_id or f.cvss_score is not None:
                enriched += 1
    if total_findings == 0:
        return True
    return (enriched / total_findings) >= _ENRICHMENT_THRESHOLD


def _check_no_fake_metrics(quality_score: dict[str, Any]) -> bool:
    """Quality score reports no fake metrics detected."""
    fake_count = quality_score.get("fake_metric_count", 0)
    return fake_count == 0


def _check_failures_explained(results: dict[str, PluginResult]) -> bool:
    """Every failed plugin has error_type and failure_stage set."""
    for pr in results.values():
        if not pr.success and (not pr.error_type or not pr.failure_stage):
            return False
    return True


def _check_detection_uses_real_signals(results: dict[str, PluginResult]) -> bool:
    """No findings are from simulated/dry-run mode without real evidence."""
    for pr in results.values():
        # Simulated results with findings but no evidence = not real signals
        if pr.mode in ("simulated", "dry-run") and pr.findings and not pr.evidence:
            return False
    return True


def _check_attack_chains(results: dict[str, PluginResult]) -> bool:
    """At least one finding has a source_chain (populated during chain mode)."""
    for pr in results.values():
        for f in pr.findings:
            if f.source_chain:
                return True
    # If no findings at all, vacuously true
    total = sum(len(pr.findings) for pr in results.values())
    return total == 0


def _check_reports_reproducible(trust: dict[str, Any]) -> bool:
    """Trust assessment level is not LOW."""
    level = trust.get("level", "LOW")
    return level != "LOW"
