"""RedCheck246 — Detection Coverage Validator.

Evaluates SIEM / EDR detection coverage against the framework's
MITRE ATT&CK technique catalog.  For each mapped technique the
validator generates a deterministic traffic pattern, queries the
detection layer for alerts, and computes a coverage percentage.

Hard rules:
- No evasion techniques (no payload morphing, encoding bypass).
- All traffic patterns are benign markers — they trigger detection
  without causing harm.
- Deterministic: same input fixtures produce identical output.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any

import httpx
import structlog

from redcheck.models import PluginCapability
from redcheck.plugins._http import scanning_ssl_context
from redcheck.plugins.base_plugin import BasePlugin, PluginResult, plugin_dependencies

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Full MITRE ATT&CK technique catalog — every technique mapped by any
# RedCheck246 plugin.  Used as the ground truth for coverage calculation.
# ---------------------------------------------------------------------------

MITRE_TECHNIQUE_CATALOG: dict[str, dict[str, str]] = {
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "plugin": "network-scanner",
    },
    "T1595.001": {
        "name": "Active Scanning: IP Blocks",
        "tactic": "Reconnaissance",
        "plugin": "network-scanner",
    },
    "T1596": {
        "name": "Search Open Technical Databases",
        "tactic": "Reconnaissance",
        "plugin": "passive-recon",
    },
    "T1593": {
        "name": "Search Open Websites/Domains",
        "tactic": "Reconnaissance",
        "plugin": "passive-recon",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "plugin": "exploit-verifier",
    },
    "T1595.002": {
        "name": "Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "plugin": "crawler",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Persistence",
        "plugin": "auth-session-tester",
    },
    "T1078.003": {
        "name": "Local Accounts",
        "tactic": "Persistence",
        "plugin": "idor-validator",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "plugin": "injection-poc-simulator",
    },
    "T1110.002": {
        "name": "Password Cracking",
        "tactic": "Credential Access",
        "plugin": "hash-strength-analyzer",
    },
    "T1203": {
        "name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "plugin": "exploit-verifier",
    },
    "T1562.001": {
        "name": "Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "plugin": "detection-coverage",
    },
    "T1562.006": {
        "name": "Indicator Blocking",
        "tactic": "Defense Evasion",
        "plugin": "alert-latency",
    },
    "T1596.003": {
        "name": "Digital Certificates",
        "tactic": "Reconnaissance",
        "plugin": "ct-log-monitor",
    },
    "T1583.001": {
        "name": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "plugin": "typosquat-detector",
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "plugin": "protocol-fuzzer",
    },
    "T1195.002": {
        "name": "Supply Chain Compromise",
        "tactic": "Initial Access",
        "plugin": "supply-chain-audit",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "plugin": "password-entropy-scorer",
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "plugin": "auth-session-tester",
    },
    "T1589.001": {
        "name": "Credentials",
        "tactic": "Reconnaissance",
        "plugin": "breach-lookup",
    },
}


def technique_ids() -> frozenset[str]:
    """Return the immutable set of all MITRE technique IDs in the catalog."""
    return frozenset(MITRE_TECHNIQUE_CATALOG)


# ---------------------------------------------------------------------------
# Traffic pattern generator — deterministic, benign markers
# ---------------------------------------------------------------------------

_MARKER_PREFIX = "REDCHECK-DET-"


def generate_traffic_marker(technique_id: str, *, seed: str = "default") -> str:
    """Create a deterministic, benign traffic marker for a technique.

    The marker is a hex digest that detection systems can be configured
    to alert on.  No payload morphing or evasion is performed — this
    is intentionally easy to detect.
    """
    data = f"{_MARKER_PREFIX}{technique_id}:{seed}".encode()
    return f"{_MARKER_PREFIX}{hashlib.sha256(data).hexdigest()[:24]}"


def generate_all_markers(
    techniques: frozenset[str] | None = None,
    *,
    seed: str = "default",
) -> dict[str, str]:
    """Return ``{technique_id: marker}`` for every technique in scope."""
    scope = techniques if techniques is not None else technique_ids()
    return {tid: generate_traffic_marker(tid, seed=seed) for tid in sorted(scope)}


# ---------------------------------------------------------------------------
# Coverage result
# ---------------------------------------------------------------------------


class CoverageResult:
    """Holds detection coverage analysis results."""

    __slots__ = (
        "total_techniques",
        "detected_techniques",
        "undetected_techniques",
        "coverage_percentage",
        "per_technique",
    )

    def __init__(
        self,
        total_techniques: int,
        detected_techniques: list[str],
        undetected_techniques: list[str],
        per_technique: dict[str, bool],
    ) -> None:
        self.total_techniques = total_techniques
        self.detected_techniques = detected_techniques
        self.undetected_techniques = undetected_techniques
        self.per_technique = per_technique
        if total_techniques > 0:
            self.coverage_percentage = round(len(detected_techniques) / total_techniques * 100, 2)
        else:
            self.coverage_percentage = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_techniques": self.total_techniques,
            "detected_count": len(self.detected_techniques),
            "undetected_count": len(self.undetected_techniques),
            "coverage_percentage": self.coverage_percentage,
            "detected_techniques": self.detected_techniques,
            "undetected_techniques": self.undetected_techniques,
            "per_technique": self.per_technique,
        }


def compute_coverage(
    detected: set[str],
    *,
    scope: frozenset[str] | None = None,
) -> CoverageResult:
    """Compute coverage percentage given a set of detected technique IDs.

    Parameters
    ----------
    detected:
        Set of technique IDs that the detection system flagged.
    scope:
        The technique catalog to measure against.  Defaults to the
        full ``MITRE_TECHNIQUE_CATALOG``.
    """
    all_ids = sorted(scope if scope is not None else technique_ids())
    per: dict[str, bool] = {tid: tid in detected for tid in all_ids}
    det = sorted(tid for tid, hit in per.items() if hit)
    undet = sorted(tid for tid, hit in per.items() if not hit)
    return CoverageResult(
        total_techniques=len(all_ids),
        detected_techniques=det,
        undetected_techniques=undet,
        per_technique=per,
    )


# ---------------------------------------------------------------------------
# Detection Coverage Validator Plugin
# ---------------------------------------------------------------------------


@plugin_dependencies(
    required=[],
    optional=["alert-latency"],
    provides=["coverage_metrics"],
)
class DetectionCoverageValidator(BasePlugin):
    """Validate SIEM / EDR detection coverage against MITRE ATT&CK.

    Workflow:
    1. Generate deterministic traffic markers for every mapped technique.
    2. Inject markers to the configured alert ingestion endpoint.
    3. Query the alert API for matching alerts.
    4. Compare alert set against technique catalog → coverage %.

    No evasion logic — markers are intentionally easy to detect.
    """

    name = "detection-coverage"
    version = "0.1.0"
    description = "MITRE ATT&CK detection coverage validation"
    requires_authorization = True
    category = "detection"
    capability = PluginCapability.ACTIVE

    required_controls: list[str] = ["allow_auth_testing"]
    timeout_seconds = 180
    rate_limit_rps = 5
    mitre_techniques = ["T1562.001"]
    requires_isolation = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return asyncio.run(self.aexecute(context))

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        # Configuration from context
        alert_endpoint: str | None = context.get("alert_endpoint")
        alert_query_endpoint: str | None = context.get("alert_query_endpoint")
        seed: str = context.get("detection_seed", "default")
        wait_seconds: float = context.get("detection_wait_seconds", 5.0)
        custom_scope: list[str] | None = context.get("detection_scope")
        pre_detected: list[str] = context.get("detected_techniques", [])

        # No detection infrastructure and no pre-populated results → PARTIAL
        if not alert_endpoint and not alert_query_endpoint and not pre_detected:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                findings=[],
                errors=[
                    "No alert_endpoint, alert_query_endpoint, or detected_techniques in context"
                ],
                metadata={"mode": "no-input", "contract_status": "PARTIAL"},
            )

        scope = frozenset(custom_scope) if custom_scope else technique_ids()
        markers = generate_all_markers(scope, seed=seed)

        # Phase 1: Inject traffic markers
        injected: set[str] = set()
        if alert_endpoint:
            async with httpx.AsyncClient(verify=scanning_ssl_context(), timeout=30.0) as client:
                for tid, marker in markers.items():
                    try:
                        payload = {
                            "marker": marker,
                            "technique_id": tid,
                            "source": "redcheck-detection-coverage",
                        }
                        resp = await client.post(alert_endpoint, json=payload)
                        if resp.status_code < 400:
                            injected.add(tid)
                    except Exception as exc:
                        errors.append(f"inject {tid}: {exc}")
        else:
            # No endpoint — use pre-populated alert data from context
            injected = set(markers.keys())

        # Phase 2: Wait for detection pipeline processing
        if alert_endpoint and wait_seconds > 0:
            await asyncio.sleep(min(wait_seconds, 60.0))

        # Phase 3: Query for alerts
        detected: set[str] = set()
        if alert_query_endpoint:
            async with httpx.AsyncClient(verify=scanning_ssl_context(), timeout=30.0) as client:
                try:
                    resp = await client.get(
                        alert_query_endpoint,
                        params={"source": "redcheck-detection-coverage"},
                    )
                    if resp.status_code == 200:
                        alert_data = resp.json()
                        if isinstance(alert_data, list):
                            for alert in alert_data:
                                tid = alert.get("technique_id", "")
                                if tid in scope:
                                    detected.add(tid)
                        elif isinstance(alert_data, dict):
                            for tid in alert_data.get("detected_techniques", []):
                                if tid in scope:
                                    detected.add(tid)
                except Exception as exc:
                    errors.append(f"query alerts: {exc}")
        else:
            # Offline mode — use pre-populated detection results from context
            detected = {t for t in pre_detected if t in scope}

        # Phase 4: Compute coverage
        result = compute_coverage(detected, scope=scope)

        findings.append(
            {
                "finding_type": "detection_coverage",
                "severity": "high" if result.coverage_percentage < 50.0 else "info",
                "detail": (
                    f"Detection coverage: {result.coverage_percentage}% "
                    f"({len(result.detected_techniques)}/{result.total_techniques} "
                    f"techniques detected)"
                ),
                "coverage": result.to_dict(),
                "markers_injected": len(injected),
            }
        )

        # Add per-technique findings for uncovered areas
        for tid in result.undetected_techniques:
            info = MITRE_TECHNIQUE_CATALOG.get(tid, {})
            findings.append(
                {
                    "finding_type": "detection_gap",
                    "severity": "medium",
                    "technique_id": tid,
                    "technique_name": info.get("name", "Unknown"),
                    "tactic": info.get("tactic", "Unknown"),
                    "plugin": info.get("plugin", "Unknown"),
                    "detail": (f"No detection alert for {tid} ({info.get('name', 'Unknown')})"),
                }
            )

        elapsed_ms = (time.monotonic() - start) * 1000

        self.capture_evidence(
            context,
            f"{len(findings)} coverage findings".encode(),
            "detection_coverage",
        )
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
            metadata={
                "coverage_percentage": result.coverage_percentage,
                "total_techniques": result.total_techniques,
                "detected_count": len(result.detected_techniques),
                "undetected_count": len(result.undetected_techniques),
                "markers_generated": len(markers),
                "seed": seed,
                "elapsed_ms": round(elapsed_ms, 2),
                "simulation_depth": 2,
            },
        )
