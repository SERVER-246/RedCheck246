"""Quality scorer for RedCheck engagement results.

Computes a 0–100 quality score across four equally-weighted components:

  1. Evidence Coverage      (0–25)
  2. Enrichment Completeness (0–25)
  3. Plugin Success Rate     (0–25)
  4. Detection Realism       (0–25)

Grade thresholds: A (90-100), B (75-89), C (50-74), D (25-49), F (0-24).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from redcheck.models import Finding, PluginResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ENRICHMENT_FIELDS: tuple[str, ...] = (
    "cvss_score",
    "cwe_id",
    "remediation",
    "mitre_technique",
)

_DETECTION_PLUGIN_PATTERNS: tuple[str, ...] = (
    "alert-latency",
    "detection-coverage",
    "persistence-validator",
    "response-recorder",
)

_GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A"),
    (75, "B"),
    (50, "C"),
    (25, "D"),
    (0, "F"),
]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QualityScore:
    """Immutable result of a quality scoring run."""

    evidence_coverage: float
    enrichment_completeness: float
    plugin_success_rate: float
    detection_realism: float
    total: float
    grade: str
    component_details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        return {
            "evidence_coverage": round(self.evidence_coverage, 2),
            "enrichment_completeness": round(self.enrichment_completeness, 2),
            "plugin_success_rate": round(self.plugin_success_rate, 2),
            "detection_realism": round(self.detection_realism, 2),
            "total": round(self.total, 2),
            "grade": self.grade,
            "details": self.component_details,
        }


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------


def _compute_grade(total: float) -> str:
    for threshold, grade in _GRADE_THRESHOLDS:
        if total >= threshold:
            return grade
    return "F"


def _evidence_coverage(findings: list[Finding]) -> tuple[float, dict[str, Any]]:
    if not findings:
        return 0.0, {"total_findings": 0, "with_evidence": 0}
    with_evidence = sum(1 for f in findings if f.evidence_ref)
    ratio = with_evidence / len(findings)
    return ratio * 25.0, {
        "total_findings": len(findings),
        "with_evidence": with_evidence,
    }


def _enrichment_completeness(
    findings: list[Finding],
) -> tuple[float, dict[str, Any]]:
    if not findings:
        return 0.0, {"total_findings": 0, "avg_population_ratio": 0.0}
    total_ratio = 0.0
    for f in findings:
        populated = sum(
            1 for field_name in _ENRICHMENT_FIELDS if getattr(f, field_name, None) is not None
        )
        total_ratio += populated / len(_ENRICHMENT_FIELDS)
    avg = total_ratio / len(findings)
    return avg * 25.0, {
        "total_findings": len(findings),
        "avg_population_ratio": round(avg, 4),
    }


def _plugin_weight(result: PluginResult) -> float:
    contract_status = result.metadata.get("contract_status", "")
    if contract_status == "PARTIAL":
        return 0.3
    if not result.success:
        if result.errors:
            return 0.1
        return 0.0
    if result.findings and result.evidence:
        return 1.0
    if result.findings:
        return 0.5
    # Success but no findings (clean scan target).
    return 0.3


def _plugin_success_rate(
    results: list[PluginResult],
) -> tuple[float, dict[str, Any]]:
    if not results:
        return 0.0, {"total_plugins": 0}
    weights = [_plugin_weight(r) for r in results]
    avg = sum(weights) / len(weights)
    return avg * 25.0, {
        "total_plugins": len(results),
        "avg_weight": round(avg, 4),
        "per_plugin": {r.plugin_name: round(w, 2) for r, w in zip(results, weights, strict=True)},
    }


def _is_detection_plugin(name: str) -> bool:
    lower = name.lower().replace("_", "-")
    return any(pat in lower for pat in _DETECTION_PLUGIN_PATTERNS)


def _detection_realism(
    results: list[PluginResult],
) -> tuple[float, dict[str, Any]]:
    detection_results = [r for r in results if _is_detection_plugin(r.plugin_name)]
    if not detection_results:
        return 0.0, {"detection_plugins_found": 0}

    score = 0.0
    per_plugin: dict[str, dict[str, Any]] = {}

    for r in detection_results:
        depth = int(r.metadata.get("simulation_depth", 0))
        has_evidence = bool(r.evidence)
        has_findings = bool(r.findings)

        if depth >= 2 and has_evidence:
            earned = 6.25
        elif depth >= 1:
            earned = 3.0
        elif has_findings:
            earned = 0.0  # findings without depth → fabricated
        else:
            earned = 1.0  # honest failure

        score += earned
        per_plugin[r.plugin_name] = {
            "simulation_depth": depth,
            "has_evidence": has_evidence,
            "has_findings": has_findings,
            "points": round(earned, 2),
        }

    return min(score, 25.0), {
        "detection_plugins_found": len(detection_results),
        "per_plugin": per_plugin,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def score_engagement(results: list[PluginResult]) -> QualityScore:
    """Compute a quality score for a completed engagement.

    Parameters
    ----------
    results:
        All ``PluginResult`` objects produced during the engagement.

    Returns
    -------
    QualityScore:
        An immutable dataclass with per-component scores, total, and grade.
    """
    all_findings: list[Finding] = []
    for r in results:
        all_findings.extend(r.findings)

    ev_score, ev_details = _evidence_coverage(all_findings)
    en_score, en_details = _enrichment_completeness(all_findings)
    ps_score, ps_details = _plugin_success_rate(results)
    dr_score, dr_details = _detection_realism(results)

    total = ev_score + en_score + ps_score + dr_score
    grade = _compute_grade(total)

    return QualityScore(
        evidence_coverage=ev_score,
        enrichment_completeness=en_score,
        plugin_success_rate=ps_score,
        detection_realism=dr_score,
        total=total,
        grade=grade,
        component_details={
            "evidence_coverage": ev_details,
            "enrichment_completeness": en_details,
            "plugin_success_rate": ps_details,
            "detection_realism": dr_details,
        },
    )
