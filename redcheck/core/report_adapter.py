"""RedCheck246 — Report Adapter (S3-2).

Bridges the plugin-layer ``PluginResult`` (dataclass, dict-based findings)
to the reporting-layer ``ScanReport`` (Pydantic, ``Finding`` objects) so
that the existing ``ReportExporter`` can consume scan results produced by
any plugin.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from redcheck.models import Finding, FindingSeverity, ScanReport

log = structlog.get_logger(__name__)

# Map free-text severity strings emitted by plugins to FindingSeverity enum
_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "CRITICAL": FindingSeverity.CRITICAL,
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
    "INFO": FindingSeverity.INFO,
}


def _dict_to_finding(raw: dict[str, Any], plugin_name: str) -> Finding:
    """Convert a single plugin finding dict to a Pydantic ``Finding``.

    Plugins emit dicts with varying shapes.  This function normalises
    them into the strict ``Finding`` model used by the reporting layer.
    """
    data = raw.get("data", {})
    severity_str = (data.get("severity", "") or raw.get("severity", "") or "INFO").upper()
    severity = _SEVERITY_MAP.get(severity_str, FindingSeverity.INFO)

    return Finding(
        finding_type=raw.get("type", "unknown"),
        target=raw.get("target", "unknown"),
        severity=severity,
        detail=raw.get("detail", ""),
        plugin=plugin_name,
        cwe_id=data.get("cwe_id"),
        cvss_score=data.get("cvss_score"),
        remediation=data.get("remediation"),
        mitre_technique=data.get("mitre_technique"),
    )


def plugin_result_to_scan_report(
    plugin_name: str,
    findings: list[dict[str, Any]],
    metadata: dict[str, Any],
    engagement_id: str,
    duration_ms: int | None = None,
) -> ScanReport:
    """Convert a plugin-layer result into a ``ScanReport`` for reporting.

    Parameters
    ----------
    plugin_name:
        The name of the plugin that produced the result.
    findings:
        Raw finding dicts from ``PluginResult.findings``.
    metadata:
        Plugin metadata dict.
    engagement_id:
        The engagement ID from the loaded RoE.
    duration_ms:
        Elapsed time in milliseconds (optional).

    Returns
    -------
    ScanReport
        A fully-formed Pydantic model ready for ``ReportExporter``.
    """
    now = datetime.now(timezone.utc)

    converted_findings: list[Finding] = []
    for raw in findings:
        try:
            converted_findings.append(_dict_to_finding(raw, plugin_name))
        except Exception:
            log.warning(
                "finding_conversion_failed",
                plugin=plugin_name,
                raw_type=raw.get("type", "?"),
            )

    return ScanReport(
        engagement_id=engagement_id,
        scanner=plugin_name,
        start_time=now,
        end_time=now,
        findings=converted_findings,
        summary={
            "total_findings": len(converted_findings),
            "duration_ms": duration_ms,
        },
        metadata=metadata,
    )
