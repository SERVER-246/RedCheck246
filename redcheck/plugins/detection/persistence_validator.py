"""RedCheck246 — Persistence Validator.

Validates detection of persistence techniques by injecting benign
markers into the monitoring pipeline and checking whether the
detection layer identifies them.

Uses the same marker-injection pattern as ``DetectionCoverageValidator``:
deterministic SHA-256 digests, no persistent artifacts on target,
no evasion logic.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any

import httpx
import structlog

from redcheck import constants
from redcheck.models import PluginCapability
from redcheck.plugins._http import scanning_ssl_context
from redcheck.plugins.base_plugin import BasePlugin, PluginResult

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Persistence technique catalog
# ---------------------------------------------------------------------------

PERSISTENCE_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1053.005": {
        "name": "Scheduled Task",
        "description": "Persistence via scheduled tasks",
    },
    "T1547.001": {
        "name": "Registry Run Keys",
        "description": "Persistence via registry run keys / startup folder",
    },
    "T1136.001": {
        "name": "Local Account",
        "description": "Persistence via local account creation",
    },
    "T1505.003": {
        "name": "Web Shell",
        "description": "Persistence via web shell deployment",
    },
    "T1543.003": {
        "name": "Windows Service",
        "description": "Persistence via Windows service creation",
    },
}

_MARKER_PREFIX = "REDCHECK-PERSIST-"


def generate_persistence_marker(
    technique_id: str,
    *,
    seed: str = "default",
) -> str:
    """Create a deterministic, benign marker for a persistence technique."""
    data = f"{_MARKER_PREFIX}{technique_id}:{seed}".encode()
    digest_len = constants.DETECTION_MARKER_DIGEST_LEN
    return f"{_MARKER_PREFIX}{hashlib.sha256(data).hexdigest()[:digest_len]}"


# ---------------------------------------------------------------------------
# Persistence Validator Plugin
# ---------------------------------------------------------------------------


class PersistenceValidator(BasePlugin):
    """Validate detection of persistence techniques.

    Workflow:
    1. For each persistence technique in scope, generate a unique marker.
    2. POST the marker to the alert endpoint.
    3. Wait for detection (bounded by ``detection_wait_seconds``).
    4. Query alert endpoint for detection of each marker.
    5. Report which techniques were detected and which were not.
    """

    name = "persistence-validator"
    version = "0.1.0"
    description = "Validate detection of persistence techniques"
    requires_authorization = True
    category = "detection"
    capability = PluginCapability.ACTIVE

    required_controls: list[str] = ["allow_auth_testing"]
    timeout_seconds = 60
    rate_limit_rps = 5
    mitre_techniques = ["T1053.005", "T1547.001", "T1136.001", "T1505.003", "T1543.003"]
    requires_isolation = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return asyncio.run(self.aexecute(context))

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        alert_endpoint: str | None = context.get("alert_endpoint")
        alert_query_endpoint: str | None = context.get("alert_query_endpoint")
        seed: str = context.get("detection_seed", "default")
        wait_seconds: float = min(context.get("detection_wait_seconds", 5.0), 60.0)
        custom_scope: list[str] | None = context.get("persistence_scope")

        # No detection infrastructure → PARTIAL (Rule 2: no fabricated metrics)
        if not alert_endpoint and not alert_query_endpoint:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                findings=[],
                errors=[
                    "No alert_endpoint or alert_query_endpoint in context"
                    " — configure detection endpoints to validate persistence"
                ],
                metadata={"mode": "no-input", "contract_status": "PARTIAL"},
            )

        scope = (
            {t: PERSISTENCE_TECHNIQUES[t] for t in custom_scope if t in PERSISTENCE_TECHNIQUES}
            if custom_scope
            else dict(PERSISTENCE_TECHNIQUES)
        )

        # Generate markers for all techniques in scope
        markers: dict[str, str] = {
            tid: generate_persistence_marker(tid, seed=seed) for tid in scope
        }

        # Phase 1: Inject markers
        injected: set[str] = set()
        if alert_endpoint:
            async with httpx.AsyncClient(verify=scanning_ssl_context(), timeout=30.0) as client:
                for tid, marker in markers.items():
                    try:
                        payload = {
                            "marker": marker,
                            "technique_id": tid,
                            "source": "redcheck-persistence-test",
                            "category": "persistence",
                        }
                        resp = await client.post(alert_endpoint, json=payload)
                        if resp.status_code < 400:
                            injected.add(tid)
                    except httpx.HTTPError as exc:
                        errors.append(f"Inject failed for {tid}: {exc}")
        else:
            # Offline mode — all markers are "injected" (simulated)
            injected = set(markers.keys())

        # Phase 2: Wait for detection
        if injected and alert_endpoint:
            await asyncio.sleep(wait_seconds)

        # Phase 3: Query for detected markers
        detected: set[str] = set()
        if alert_query_endpoint and injected:
            async with httpx.AsyncClient(verify=scanning_ssl_context(), timeout=30.0) as client:
                for tid in injected:
                    try:
                        resp = await client.get(
                            alert_query_endpoint,
                            params={"marker": markers[tid]},
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            if data.get("detected", False):
                                detected.add(tid)
                    except httpx.HTTPError as exc:
                        errors.append(f"Query failed for {tid}: {exc}")

        # Phase 4: Generate findings
        for tid, info in scope.items():
            if tid not in injected:
                continue

            if tid in detected:
                findings.append(
                    {
                        "finding_type": "persistence_detected",
                        "target": context.get("targets", ["unknown"])[0]
                        if isinstance(context.get("targets"), list)
                        else "unknown",
                        "severity": "info",
                        "detail": (
                            f"Persistence technique {tid} ({info['name']}) "
                            f"was correctly detected by monitoring"
                        ),
                        "metadata": {
                            "technique_id": tid,
                            "technique_name": info["name"],
                            "detected": True,
                            "marker": markers[tid],
                        },
                    }
                )
            else:
                findings.append(
                    {
                        "finding_type": "persistence_undetected",
                        "target": context.get("targets", ["unknown"])[0]
                        if isinstance(context.get("targets"), list)
                        else "unknown",
                        "severity": "high",
                        "detail": (
                            f"Persistence technique {tid} ({info['name']}) "
                            f"was NOT detected by monitoring"
                        ),
                        "metadata": {
                            "technique_id": tid,
                            "technique_name": info["name"],
                            "detected": False,
                            "marker": markers[tid],
                        },
                    }
                )

        # Overall coverage finding
        coverage_pct = round(len(detected) / len(injected) * 100, 1) if injected else 0.0
        if coverage_pct >= 80:
            coverage_severity = "info"
        elif coverage_pct < 50:
            coverage_severity = "high"
        else:
            coverage_severity = "medium"
        findings.append(
            {
                "finding_type": "persistence_coverage",
                "target": context.get("targets", ["unknown"])[0]
                if isinstance(context.get("targets"), list)
                else "unknown",
                "severity": coverage_severity,
                "detail": (
                    f"Persistence detection coverage: {coverage_pct}% "
                    f"({len(detected)}/{len(injected)} techniques detected)"
                ),
                "metadata": {
                    "coverage_percent": coverage_pct,
                    "detected_count": len(detected),
                    "total_count": len(injected),
                    "detected_techniques": sorted(detected),
                    "undetected_techniques": sorted(injected - detected),
                },
            }
        )

        duration_ms = (time.monotonic() - start) * 1000
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
            metadata={
                "duration_ms": round(duration_ms, 2),
                "techniques_in_scope": len(scope),
                "techniques_injected": len(injected),
                "techniques_detected": len(detected),
            },
        )
