"""RedCheck246 — Alert Latency Tester.

Measures the time between injecting a detection marker and receiving
the corresponding alert from the SIEM / EDR pipeline.  Computes
``latency_ms`` and evaluates whether the response time falls within
the engagement's SLA threshold.

Workflow:
1. Record ``t0`` — inject a timestamped marker to the alert endpoint.
2. Poll the alert query endpoint until the marker is acknowledged
   or a bounded TTL expires.
3. Compute ``latency_ms = t_alert - t0``.
4. Compare against ``expected_latency_ms`` → ``within_sla: bool``.

Hard rules:
- Timeout is capped at ``5 × expected_latency_ms`` (never unbounded).
- Poll interval is adaptive: ``max(0.1, expected_latency_ms / 20000)``.
- No evasion — markers are benign and intentionally detectable.
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
# Constants
# ---------------------------------------------------------------------------

_LATENCY_MARKER_PREFIX = "REDCHECK-LAT-"

# Hard cap on how long we wait for an alert (seconds)
LATENCY_POLL_TIMEOUT_CAP: int = 300

# Default expected latency (ms) if not provided by context
DEFAULT_EXPECTED_LATENCY_MS: float = 1000.0

# Multiplier: timeout = expected × this factor
TIMEOUT_MULTIPLIER: int = 5

# Minimum poll interval (seconds)
MIN_POLL_INTERVAL: float = 0.1

# Maximum poll interval (seconds)
MAX_POLL_INTERVAL: float = 5.0


# ---------------------------------------------------------------------------
# Marker generation
# ---------------------------------------------------------------------------


def generate_latency_marker(*, nonce: str = "default") -> str:
    """Create a unique, timestamped marker for latency measurement.

    The marker embeds the nonce so multiple probes can run concurrently
    without colliding.
    """
    data = f"{_LATENCY_MARKER_PREFIX}{nonce}:{time.time_ns()}".encode()
    digest = hashlib.sha256(data).hexdigest()[:24]
    return f"{_LATENCY_MARKER_PREFIX}{digest}"


# ---------------------------------------------------------------------------
# Latency result
# ---------------------------------------------------------------------------


class LatencyResult:
    """Holds a single latency measurement."""

    __slots__ = (
        "marker",
        "latency_ms",
        "expected_ms",
        "within_sla",
        "timed_out",
    )

    def __init__(
        self,
        marker: str,
        latency_ms: float,
        expected_ms: float,
        *,
        timed_out: bool = False,
    ) -> None:
        self.marker = marker
        self.latency_ms = round(latency_ms, 2)
        self.expected_ms = expected_ms
        self.within_sla = latency_ms <= expected_ms and not timed_out
        self.timed_out = timed_out

    def to_dict(self) -> dict[str, Any]:
        return {
            "marker": self.marker,
            "latency_ms": self.latency_ms,
            "expected_ms": self.expected_ms,
            "within_sla": self.within_sla,
            "timed_out": self.timed_out,
        }


def compute_latency_stats(results: list[LatencyResult]) -> dict[str, Any]:
    """Aggregate statistics across multiple latency probes."""
    if not results:
        return {
            "probe_count": 0,
            "avg_latency_ms": 0.0,
            "min_latency_ms": 0.0,
            "max_latency_ms": 0.0,
            "p95_latency_ms": 0.0,
            "sla_pass_rate": 0.0,  # nosec B105 — not a password
            "timeout_count": 0,
        }
    latencies = [r.latency_ms for r in results]
    latencies_sorted = sorted(latencies)
    p95_idx = max(0, int(len(latencies_sorted) * 0.95) - 1)
    sla_pass = sum(1 for r in results if r.within_sla)
    return {
        "probe_count": len(results),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 2),
        "min_latency_ms": latencies_sorted[0],
        "max_latency_ms": latencies_sorted[-1],
        "p95_latency_ms": latencies_sorted[p95_idx],
        "sla_pass_rate": round(sla_pass / len(results) * 100, 2),
        "timeout_count": sum(1 for r in results if r.timed_out),
    }


# ---------------------------------------------------------------------------
# Alert Latency Tester Plugin
# ---------------------------------------------------------------------------


@plugin_dependencies(
    required=[],
    optional=["network-scanner"],
    provides=["latency_metrics"],
)
class AlertLatencyTester(BasePlugin):
    """Measure SIEM / EDR alert latency for detection markers.

    Injects timestamped markers, polls for the corresponding alert,
    and measures the round-trip detection latency against the SLA.
    """

    name = "alert-latency"
    version = "0.1.0"
    description = "Alert pipeline latency measurement"
    requires_authorization = True
    category = "detection"
    capability = PluginCapability.ACTIVE

    required_controls: list[str] = ["allow_auth_testing"]
    timeout_seconds = 180
    rate_limit_rps = 5
    mitre_techniques = ["T1562.006"]
    requires_isolation = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return asyncio.run(self.aexecute(context))

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        # Configuration
        alert_endpoint: str | None = context.get("alert_endpoint")
        alert_query_endpoint: str | None = context.get("alert_query_endpoint")
        sim_latencies_ctx: list[float] = context.get("simulated_latencies_ms", [])
        expected_ms: float = context.get("expected_latency_ms", DEFAULT_EXPECTED_LATENCY_MS)
        probe_count: int = context.get("latency_probe_count", 3)
        probe_count = max(1, min(probe_count, 20))  # cap 1–20

        # No detection infrastructure and no simulated data → PARTIAL
        if not alert_endpoint and not alert_query_endpoint and not sim_latencies_ctx:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                findings=[],
                errors=[
                    "No alert_endpoint, alert_query_endpoint, or simulated_latencies_ms in context"
                ],
                metadata={"mode": "no-input", "contract_status": "PARTIAL"},
            )

        # Timeout = 5 × expected, hard capped
        timeout_s = min(
            expected_ms * TIMEOUT_MULTIPLIER / 1000.0,
            LATENCY_POLL_TIMEOUT_CAP,
        )

        # Adaptive poll interval
        poll_interval = max(
            MIN_POLL_INTERVAL,
            min(expected_ms / 20_000.0, MAX_POLL_INTERVAL),
        )

        results: list[LatencyResult] = []

        for i in range(probe_count):
            nonce = f"probe-{i}"
            marker = generate_latency_marker(nonce=nonce)

            # Inject
            t0 = time.monotonic()
            if alert_endpoint:
                try:
                    async with httpx.AsyncClient(
                        verify=scanning_ssl_context(), timeout=30.0
                    ) as client:
                        await client.post(
                            alert_endpoint,
                            json={
                                "marker": marker,
                                "source": "redcheck-alert-latency",
                                "probe_index": i,
                            },
                        )
                except Exception as exc:
                    errors.append(f"inject probe {i}: {exc}")
                    continue

            # Poll for alert
            detected = False
            if alert_query_endpoint:
                deadline = t0 + timeout_s
                while time.monotonic() < deadline:
                    try:
                        async with httpx.AsyncClient(
                            verify=scanning_ssl_context(), timeout=10.0
                        ) as client:
                            resp = await client.get(
                                alert_query_endpoint,
                                params={"marker": marker},
                            )
                            if resp.status_code == 200:
                                body = resp.json()
                                # Accept if the API returns truthy
                                if isinstance(body, dict) and body.get("found"):
                                    detected = True
                                    break
                                if isinstance(body, list) and body:
                                    detected = True
                                    break
                    except Exception:
                        log.debug("latency_poll_error", probe=i)
                    await asyncio.sleep(poll_interval)
            else:
                # Offline mode — use simulated latencies from context
                sim_latencies: list[float] = sim_latencies_ctx
                if i < len(sim_latencies):
                    sim_ms = sim_latencies[i]
                    await asyncio.sleep(min(sim_ms / 1000.0, 0.01))
                    detected = True
                    latency_ms = sim_ms
                    result = LatencyResult(marker, latency_ms, expected_ms, timed_out=False)
                    results.append(result)
                    continue

            latency_ms = (time.monotonic() - t0) * 1000.0
            result = LatencyResult(
                marker,
                latency_ms,
                expected_ms,
                timed_out=not detected,
            )
            results.append(result)

        # Compute statistics
        stats = compute_latency_stats(results)

        # Overall SLA verdict
        sla_met = stats["sla_pass_rate"] >= 80.0 if results else False

        findings.append(
            {
                "finding_type": "alert_latency",
                "severity": "high" if not sla_met else "info",
                "detail": (
                    f"Alert latency: avg={stats['avg_latency_ms']}ms, "
                    f"p95={stats['p95_latency_ms']}ms, "
                    f"SLA pass rate={stats['sla_pass_rate']}% "
                    f"(expected ≤{expected_ms}ms)"
                ),
                "within_sla": sla_met,
                "stats": stats,
                "probes": [r.to_dict() for r in results],
            }
        )

        elapsed_ms = (time.monotonic() - start) * 1000

        self.capture_evidence(
            context,
            f"{len(findings)} latency findings".encode(),
            "alert_latency",
        )
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
            metadata={
                "expected_latency_ms": expected_ms,
                "probe_count": len(results),
                "avg_latency_ms": stats["avg_latency_ms"],
                "p95_latency_ms": stats["p95_latency_ms"],
                "sla_pass_rate": stats["sla_pass_rate"],
                "sla_met": sla_met,
                "timeout_count": stats["timeout_count"],
                "elapsed_ms": round(elapsed_ms, 2),
                "simulation_depth": 2,
            },
        )
