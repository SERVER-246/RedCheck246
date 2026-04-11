"""RedCheck246 — System Trust Assessor (Phase I).

Computes a trust level for every scan report based on quality score,
contract violations, and evidence coverage.  Consumers use
``safe_to_use_for_decision`` to decide whether to act on the results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from redcheck.core.quality_scorer import QualityScore
    from redcheck.models import PluginResult


@dataclass(frozen=True)
class SystemTrustAssessment:
    """Immutable trust assessment for a completed scan."""

    trust_level: Literal["LOW", "MEDIUM", "HIGH"]
    reason: str
    safe_to_use_for_decision: bool
    contributing_factors: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust_level": self.trust_level,
            "reason": self.reason,
            "safe_to_use_for_decision": self.safe_to_use_for_decision,
            "contributing_factors": dict(self.contributing_factors),
        }


def _count_contract_violations(results: list[PluginResult]) -> int:
    """Count total unique contract violations across all plugin results."""
    count = 0
    for r in results:
        violations = r.metadata.get("contract_violations", [])
        count += len(violations)
    return count


def _compute_evidence_coverage(results: list[PluginResult]) -> float:
    """Compute percentage of medium+ findings that have evidence_ref."""
    from redcheck.models import FindingSeverity

    _require_evidence = {FindingSeverity.MEDIUM, FindingSeverity.HIGH, FindingSeverity.CRITICAL}
    total = 0
    with_evidence = 0
    for r in results:
        for f in r.findings:
            if f.severity in _require_evidence:
                total += 1
                if f.evidence_ref:
                    with_evidence += 1
    if total == 0:
        return 100.0  # No findings requiring evidence → full coverage
    return (with_evidence / total) * 100


def _count_fake_metrics(results: list[PluginResult]) -> int:
    """Count findings flagged as fake metrics."""
    count = 0
    for r in results:
        for f in r.findings:
            if f.metadata.get("fake_metric_detected"):
                count += 1
    return count


def assess(
    results: list[PluginResult],
    quality_score: QualityScore | None = None,
) -> SystemTrustAssessment:
    """Compute the system trust assessment for a set of plugin results.

    Rules:
      HIGH   — quality ≥ 90 AND 0 contract violations AND evidence ≥ 80%
      MEDIUM — quality ≥ 75 AND ≤ 2 contract violations
      LOW    — everything else
    """
    total_score = quality_score.total if quality_score else 0.0
    grade = quality_score.grade if quality_score else "F"
    violations = _count_contract_violations(results)
    evidence_pct = _compute_evidence_coverage(results)
    fake_metrics = _count_fake_metrics(results)

    factors: dict[str, Any] = {
        "quality_grade": grade,
        "quality_score": round(total_score, 2),
        "contract_violations": violations,
        "evidence_coverage_pct": round(evidence_pct, 2),
        "fake_metrics_detected": fake_metrics,
    }

    if total_score >= 90 and violations == 0 and evidence_pct >= 80:
        level: Literal["LOW", "MEDIUM", "HIGH"] = "HIGH"
        reason = (
            f"Quality score {total_score:.0f}/100, "
            f"0 contract violations, evidence {evidence_pct:.0f}%"
        )
    elif total_score >= 75 and violations <= 2:
        level = "MEDIUM"
        reason = f"Quality score {total_score:.0f}/100, {violations} contract violation(s)"
    else:
        level = "LOW"
        parts = []
        if total_score < 75:
            parts.append(f"quality score {total_score:.0f}/100 (below 75)")
        if violations > 2:
            parts.append(f"{violations} contract violations (above 2)")
        if evidence_pct < 80:
            parts.append(f"evidence coverage {evidence_pct:.0f}% (below 80%)")
        reason = "; ".join(parts) if parts else "Insufficient quality metrics"

    return SystemTrustAssessment(
        trust_level=level,
        reason=reason,
        safe_to_use_for_decision=level in ("MEDIUM", "HIGH"),
        contributing_factors=factors,
    )
