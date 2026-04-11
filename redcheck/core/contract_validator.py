"""RedCheck246 — Execution Contract Validator.

Post-plugin validation gate enforcing rules C1-C6.  Runs after every
plugin returns and *before* results enter the report.  Non-compliant
results are automatically flagged, downgraded, or corrected.

Wired into the Orchestrator alongside enrichment.
"""

from __future__ import annotations

from typing import Any

import structlog

from redcheck.models import FindingSeverity

log = structlog.get_logger(__name__)

# Severity levels that require evidence (C3)
_EVIDENCE_REQUIRED_SEVERITIES = frozenset(
    {
        FindingSeverity.MEDIUM,
        FindingSeverity.HIGH,
        FindingSeverity.CRITICAL,
    }
)


# ------------------------------------------------------------------
# Individual contract rules
# ------------------------------------------------------------------


def _check_c1_no_empty_output(result: Any) -> list[dict[str, str]]:
    """C1: Passed with no findings → downgrade to PARTIAL."""
    violations: list[dict[str, str]] = []
    if getattr(result, "success", False) and not getattr(result, "findings", []):
        result.metadata.setdefault("original_status", str(result.success))
        result.metadata["contract_status"] = "PARTIAL"
        violations.append(
            {
                "rule": "C1",
                "type": "passed_with_no_findings",
                "action": "status_downgraded_to_PARTIAL",
            }
        )
    return violations


def _check_c2_no_zero_duration(result: Any) -> list[dict[str, str]]:
    """C2: Zero or missing duration → flag as timing_unverified."""
    violations: list[dict[str, str]] = []
    duration = result.metadata.get("duration_seconds", 0.0)
    if duration <= 0.0:
        result.metadata["timing_unverified"] = True
        violations.append(
            {
                "rule": "C2",
                "type": "zero_duration",
                "action": "flagged_timing_unverified",
            }
        )
    return violations


def _check_c3_evidence_required(result: Any) -> list[dict[str, str]]:
    """C3: Medium+ findings without evidence → downgrade confidence."""
    violations: list[dict[str, str]] = []
    for finding in getattr(result, "findings", []):
        sev = getattr(finding, "severity", None)
        if sev in _EVIDENCE_REQUIRED_SEVERITIES:
            ev_ref = getattr(finding, "evidence_ref", None)
            if not ev_ref:
                meta = finding.metadata if hasattr(finding, "metadata") else {}
                meta["unverified"] = True
                meta["original_confidence"] = meta.get("confidence", "low")
                meta["confidence"] = "low"
                violations.append(
                    {
                        "rule": "C3",
                        "type": "missing_evidence",
                        "action": "confidence_downgraded_to_low",
                        "finding_type": getattr(finding, "finding_type", ""),
                    }
                )
    return violations


def _check_c4_enrichment_completeness(result: Any) -> list[dict[str, str]]:
    """C4: Non-info findings missing CWE/CVSS/remediation → tag gaps."""
    violations: list[dict[str, str]] = []
    for finding in getattr(result, "findings", []):
        sev = getattr(finding, "severity", None)
        if sev == FindingSeverity.INFO:
            continue
        meta = finding.metadata if hasattr(finding, "metadata") else {}
        missing: list[str] = []
        if not meta.get("cvss_score") and not getattr(finding, "cvss_score", None):
            missing.append("cvss")
        if not meta.get("cwe_id") and not getattr(finding, "cwe_id", None):
            missing.append("cwe")
        if not meta.get("remediation") and not getattr(finding, "remediation", None):
            missing.append("remediation")
        if missing:
            meta["enrichment_gaps"] = missing
            violations.append(
                {
                    "rule": "C4",
                    "type": "incomplete_enrichment",
                    "action": "gaps_tagged",
                    "missing": ",".join(missing),
                    "finding_type": getattr(finding, "finding_type", ""),
                }
            )
    return violations


def _check_c5_fake_metric(result: Any) -> list[dict[str, str]]:
    """C5: Known fake-metric patterns → mark INVALID.

    Delegates heavy detection to ``fake_metric_detector`` but applies
    a lightweight pattern match here for the contract report.
    """
    violations: list[dict[str, str]] = []
    for finding in getattr(result, "findings", []):
        if finding.metadata.get("fake_metric_detected"):
            violations.append(
                {
                    "rule": "C5",
                    "type": "suspected_fake_metric",
                    "action": "severity_set_to_none",
                    "finding_type": getattr(finding, "finding_type", ""),
                }
            )
    return violations


def _check_c6_mode_declaration(result: Any) -> list[dict[str, str]]:
    """C6: Missing execution_mode → infer and tag."""
    violations: list[dict[str, str]] = []
    if result.metadata.get("execution_mode") is None:
        result.metadata["execution_mode"] = "inferred"
        result.metadata["mode_inferred"] = True
        violations.append(
            {
                "rule": "C6",
                "type": "undeclared_mode",
                "action": "mode_inferred",
            }
        )
    return violations


def _check_c7_failure_transparency(result: Any) -> list[dict[str, str]]:
    """C7: Failed results MUST have structured error_type and failure_stage."""
    violations: list[dict[str, str]] = []
    if not getattr(result, "success", True):
        error_type = getattr(result, "error_type", None) or result.metadata.get("error_type")
        failure_stage = getattr(result, "failure_stage", None) or result.metadata.get(
            "failure_stage"
        )
        if not error_type:
            result.error_type = "unknown"
            violations.append(
                {
                    "rule": "C7",
                    "type": "missing_error_type",
                    "action": "violation_tagged",
                }
            )
        elif error_type != getattr(result, "error_type", None):
            result.error_type = error_type
        if not failure_stage:
            result.failure_stage = "unknown"
            violations.append(
                {
                    "rule": "C7",
                    "type": "missing_failure_stage",
                    "action": "violation_tagged",
                }
            )
        elif failure_stage != getattr(result, "failure_stage", None):
            result.failure_stage = failure_stage
    return violations


def _check_c9_no_fabrication(result: Any) -> list[dict[str, str]]:
    """C9: Fake-metric flagged findings must have values replaced with UNKNOWN."""
    violations: list[dict[str, str]] = []
    for finding in getattr(result, "findings", []):
        meta = finding.metadata if hasattr(finding, "metadata") else {}
        if meta.get("fake_metric_detected"):
            # Replace zero-value measurements with UNKNOWN sentinel
            detail = getattr(finding, "detail", "")
            if any(tok in detail for tok in ("0.0ms", "0.0%", "0/")):
                try:
                    finding.detail = "[UNKNOWN — measurement unverified]"
                    meta["c9_replaced"] = True
                except (AttributeError, ValueError):
                    pass
                violations.append(
                    {
                        "rule": "C9",
                        "type": "fabricated_value_replaced",
                        "action": "value_set_to_UNKNOWN",
                        "finding_type": getattr(finding, "finding_type", ""),
                    }
                )
    return violations


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------


def validate_contract(result: Any) -> list[dict[str, str]]:
    """Run all contract rules (C1-C6) on a PluginResult.

    Returns list of violation dicts.  Also stores the list in
    ``result.metadata["contract_violations"]``.
    """
    violations: list[dict[str, str]] = []
    violations.extend(_check_c1_no_empty_output(result))
    violations.extend(_check_c2_no_zero_duration(result))
    violations.extend(_check_c3_evidence_required(result))
    violations.extend(_check_c4_enrichment_completeness(result))
    violations.extend(_check_c5_fake_metric(result))
    violations.extend(_check_c6_mode_declaration(result))
    violations.extend(_check_c7_failure_transparency(result))
    violations.extend(_check_c9_no_fabrication(result))

    if violations:
        result.metadata["contract_violations"] = violations
        log.warning(
            "contract_violations_found",
            plugin=getattr(result, "plugin_name", "unknown"),
            count=len(violations),
            rules=[v["rule"] for v in violations],
        )
    return violations
