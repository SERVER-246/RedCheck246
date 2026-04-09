"""RedCheck246 — Fake Metric Detection.

Identifies unmeasured default values that masquerade as real
observations.  Applied by the contract validator (C5) and can
also be invoked standalone on a PluginResult.

Detection rules (FM-1 through FM-4) from the improvement plan.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from redcheck.models import FindingSeverity

if TYPE_CHECKING:
    from collections.abc import Callable

log = structlog.get_logger(__name__)

# ------------------------------------------------------------------
# FM-1: Zero-value metric patterns per plugin
# ------------------------------------------------------------------

_ZERO_PATTERNS: dict[str, Callable[[Any], bool]] = {
    "alert-latency": lambda f: (
        "avg=0.0ms" in getattr(f, "detail", "") or "p95=0.0ms" in getattr(f, "detail", "")
    ),
    "detection-coverage": lambda f: (
        "0.0%" in getattr(f, "detail", "") and "0/" in getattr(f, "detail", "")
    ),
    "persistence-validator": lambda f: (
        "NOT detected" in getattr(f, "detail", "") and not getattr(f, "evidence_ref", None)
    ),
}


def _check_fm1_zero_values(
    plugin_name: str,
    finding: Any,
) -> bool:
    """FM-1: Zero-value metric detection."""
    checker = _ZERO_PATTERNS.get(plugin_name)
    return bool(checker and checker(finding))


def _check_fm2_duration_cross(
    result: Any,
    finding: Any,
) -> bool:
    """FM-2: Findings claim network observations but execution < 1s."""
    duration = result.metadata.get("duration_seconds", 0.0)
    if duration >= 1.0:
        return False
    detail = getattr(finding, "detail", "")
    # Measurement keywords that imply network activity
    return any(kw in detail.lower() for kw in ("ms", "latency", "response time", "coverage"))


def _check_fm3_evidence_free_measurement(finding: Any) -> bool:
    """FM-3: Measurement claim without evidence."""
    detail = getattr(finding, "detail", "")
    has_measurement = any(tok in detail for tok in ("ms", "%", "/", "bytes", "count"))
    if has_measurement and not getattr(finding, "evidence_ref", None):
        sev = getattr(finding, "severity", None)
        if sev and sev != FindingSeverity.INFO:
            return True
    return False


def _downgrade_finding(finding: Any, reason: str) -> None:
    """Downgrade a finding flagged as fake."""
    meta = finding.metadata if hasattr(finding, "metadata") else {}
    meta["fake_metric_detected"] = True
    meta["fake_reason"] = reason
    original = getattr(finding, "severity", None)
    if original and original != FindingSeverity.INFO:
        meta["original_severity"] = original.value if hasattr(original, "value") else str(original)
        try:
            finding.severity = FindingSeverity.INFO
        except (AttributeError, ValueError):
            log.warning(
                "fake_metric_downgrade_failed",
                finding_type=getattr(finding, "finding_type", ""),
                reason=reason,
            )


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------


def detect_fake_metrics(result: Any) -> int:
    """Run FM-1 through FM-3 on all findings in *result*.

    Returns count of findings flagged as fake.  Flagged findings have
    ``finding.metadata["fake_metric_detected"] = True`` and severity
    downgraded to INFO.
    """
    plugin_name = getattr(result, "plugin_name", "")
    flagged = 0
    for finding in getattr(result, "findings", []):
        reason: str | None = None

        if _check_fm1_zero_values(plugin_name, finding):
            reason = "FM-1:zero_value_metric"
        elif _check_fm2_duration_cross(result, finding):
            reason = "FM-2:duration_cross_check"
        elif _check_fm3_evidence_free_measurement(finding):
            reason = "FM-3:evidence_free_measurement"

        if reason:
            _downgrade_finding(finding, reason)
            flagged += 1

    if flagged:
        log.warning(
            "fake_metrics_detected",
            plugin=plugin_name,
            flagged=flagged,
            total=len(result.findings),
        )
    return flagged
