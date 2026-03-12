"""RedCheck246 — Detection Response Recorder.

Records and analyzes defensive monitoring responses by cross-referencing
upstream findings with detection coverage results to build a detection
effectiveness matrix.

Consumes ``upstream_findings`` from the pipeline context and
detection coverage results to identify blind spots where findings
exist but no corresponding detection is in place.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog

from redcheck.models import PluginCapability
from redcheck.plugins.base_plugin import BasePlugin, PluginResult

log = structlog.get_logger(__name__)


class DetectionResponseRecorder(BasePlugin):
    """Record and analyze defensive monitoring responses.

    Workflow:
    1. Read upstream_findings from pipeline context.
    2. For each finding with a mitre_technique value, check if the
       detection coverage results show that technique as detected.
    3. Generate a detection effectiveness matrix.
    """

    name = "detection-response-recorder"
    version = "0.1.0"
    description = "Record and analyze defensive monitoring responses"
    requires_authorization = True
    category = "detection"
    capability = PluginCapability.ACTIVE

    required_controls: list[str] = ["allow_auth_testing"]
    timeout_seconds = 120
    rate_limit_rps = 10
    mitre_techniques = ["T1562.001", "T1562.006"]
    requires_isolation = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return asyncio.run(self.aexecute(context))

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []

        upstream = context.get("upstream_findings", [])
        # Detection coverage can come from upstream_plugins results
        detected_techniques: set[str] = set()
        upstream_plugins = context.get("upstream_plugins", {})

        # Extract detected techniques from detection-coverage plugin results
        if isinstance(upstream_plugins, dict):
            cov_result = upstream_plugins.get("detection-coverage")
            if cov_result is not None:
                cov_findings = (
                    cov_result.get("findings", [])
                    if isinstance(cov_result, dict)
                    else getattr(cov_result, "findings", [])
                )
                for f in cov_findings:
                    if isinstance(f, dict):
                        ft = f.get("finding_type", "")
                        meta = f.get("metadata", {})
                    else:
                        ft = getattr(f, "finding_type", "")
                        meta = getattr(f, "metadata", {})
                    if ft == "detection_coverage":
                        det_list = meta.get("detected_techniques", [])
                        detected_techniques.update(det_list)

        # Build technique → finding map from upstream findings
        technique_findings: dict[str, list[dict[str, Any]]] = {}
        for f in upstream:
            mitre = (
                f.get("mitre_technique", "")
                if isinstance(f, dict)
                else getattr(f, "mitre_technique", "")
            )
            if mitre:
                if isinstance(f, dict):
                    entry = f
                else:
                    entry = {
                        "finding_type": getattr(f, "finding_type", ""),
                        "target": getattr(f, "target", ""),
                    }
                technique_findings.setdefault(mitre, []).append(entry)

        # Generate effectiveness matrix
        effective_count = 0
        blind_spot_count = 0
        target = "unknown"
        if upstream:
            first = upstream[0]
            if isinstance(first, dict):
                target = first.get("target", "unknown")
            else:
                target = getattr(first, "target", "unknown")

        for technique, associated_findings in sorted(technique_findings.items()):
            if technique in detected_techniques:
                effective_count += 1
                findings.append(
                    {
                        "finding_type": "detection_effective",
                        "target": target,
                        "severity": "info",
                        "detail": (
                            f"Technique {technique} has both findings and detection — "
                            f"effective monitoring"
                        ),
                        "metadata": {
                            "technique_id": technique,
                            "detected": True,
                            "finding_count": len(associated_findings),
                        },
                    }
                )
            else:
                blind_spot_count += 1
                findings.append(
                    {
                        "finding_type": "detection_blind_spot",
                        "target": target,
                        "severity": "high",
                        "detail": (
                            f"Technique {technique} has {len(associated_findings)} "
                            f"finding(s) but NO detection coverage — blind spot"
                        ),
                        "metadata": {
                            "technique_id": technique,
                            "detected": False,
                            "finding_count": len(associated_findings),
                        },
                    }
                )

        # Overall matrix finding
        total = effective_count + blind_spot_count
        findings.append(
            {
                "finding_type": "detection_response_matrix",
                "target": target,
                "severity": "info",
                "detail": (
                    f"Detection effectiveness matrix: "
                    f"{effective_count}/{total} techniques with findings "
                    f"are detected, {blind_spot_count} blind spots"
                ),
                "metadata": {
                    "total_techniques_with_findings": total,
                    "effective_count": effective_count,
                    "blind_spot_count": blind_spot_count,
                    "effectiveness_percent": (
                        round(effective_count / total * 100, 1) if total else 0.0
                    ),
                },
            }
        )

        duration_ms = (time.monotonic() - start) * 1000
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
            metadata={
                "duration_ms": round(duration_ms, 2),
                "techniques_analyzed": total,
                "blind_spots": blind_spot_count,
            },
        )
