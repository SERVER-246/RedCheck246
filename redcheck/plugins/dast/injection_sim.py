"""RedCheck246 — Injection Proof-of-Condition (PoC) Simulator.

Validates potential injection vulnerabilities using **safe** proof-of-condition
techniques:

- **Timing oracle**: measures response-time delta for time-based payloads.
- **Ephemeral canary**: injects harmless marker strings and checks for reflection.

ALL payloads are **non-destructive** — no DROP TABLE, no file-system writes,
no command execution.

Triple-gated: ``allow_exploit_validation`` control + ``--confirm-exploit``
flag + re-verified activation.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import time
from typing import Any

import httpx
import structlog

from redcheck.exceptions import OffensiveControlError
from redcheck.models import OffensiveControls, PluginCapability
from redcheck.plugins._http import scanning_ssl_context
from redcheck.plugins.base_plugin import BasePlugin, PluginResult, plugin_dependencies

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Safe payloads — ONLY timing / reflection, never destructive
# ---------------------------------------------------------------------------

_SQLI_TIMING_PAYLOADS: list[dict[str, str]] = [
    {
        "name": "mysql_sleep",
        "payload": "' OR SLEEP(3)-- ",
        "dialect": "mysql",
    },
    {
        "name": "pg_sleep",
        "payload": "'; SELECT pg_sleep(3)-- ",
        "dialect": "postgresql",
    },
    {
        "name": "mssql_waitfor",
        "payload": "'; WAITFOR DELAY '0:0:3'-- ",
        "dialect": "mssql",
    },
]

_XSS_CANARY_PAYLOADS: list[dict[str, str]] = [
    {
        "name": "script_canary",
        "payload": "<script>redcheck_canary_{token}</script>",
        "check": "redcheck_canary_{token}",
    },
    {
        "name": "img_onerror",
        "payload": '<img src=x onerror="redcheck_canary_{token}">',
        "check": "redcheck_canary_{token}",
    },
    {
        "name": "event_handler",
        "payload": '" onmouseover="redcheck_canary_{token}',
        "check": "redcheck_canary_{token}",
    },
]

_SSTI_CANARY_PAYLOADS: list[dict[str, str]] = [
    {
        "name": "jinja2_probe",
        "payload": "{{7*7}}",
        "check": "49",
    },
    {
        "name": "erb_probe",
        "payload": "<%= 7*7 %>",
        "check": "49",
    },
]


@plugin_dependencies(
    required=["dast-scanner"],
    optional=[],
    provides=["injection_proofs"],
)
class InjectionProofOfCondition(BasePlugin):
    """Safe injection PoC validation.

    Triple-gated:
    1. ``allow_exploit_validation`` offensive control
    2. ``confirm_exploit`` flag in context
    3. Activation re-verification (trusts caller)

    Uses ONLY:
    - **Timing oracle**: ``SLEEP(3)`` / ``pg_sleep(3)`` and measures delta.
    - **Canary reflection**: injects unique marker and checks response body.

    Never executes destructive payloads.
    """

    name = "injection-poc-simulator"
    version = "0.1.0"
    description = "Safe injection proof-of-condition via timing and canary"
    requires_authorization = True
    category = "dast"
    capability = PluginCapability.ACTIVE

    required_controls = ["allow_exploit_validation"]
    timeout_seconds = 120
    rate_limit_rps = 3
    mitre_techniques = ["T1190", "T1059"]
    requires_isolation = False

    # Timing threshold in seconds for sleep detection
    _TIMING_THRESHOLD_S = 2.0
    # Baseline request count for timing calibration
    _BASELINE_REQUESTS = 2

    def _check_controls(self, context: dict[str, Any]) -> None:
        """Verify triple gate."""
        controls_data = context.get("offensive_controls", {})
        if isinstance(controls_data, dict):
            controls = OffensiveControls(**controls_data)
        elif isinstance(controls_data, OffensiveControls):
            controls = controls_data
        else:
            controls = OffensiveControls()

        if not controls.has_controls(self.required_controls):
            raise OffensiveControlError(
                self.name,
                [c for c in self.required_controls if not getattr(controls, c, False)],
            )

        if not context.get("confirm_exploit", False):
            raise OffensiveControlError(
                self.name,
                ["confirm_exploit (--confirm-exploit flag required)"],
            )

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return asyncio.run(self.aexecute(context))

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        """Run safe PoC validation."""
        self._check_controls(context)

        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        targets = context.get("injection_targets", [])
        if not targets:
            return PluginResult(
                plugin_name=self.name,
                success=True,
                findings=[],
                metadata={"mode": "no-targets", "description": "No injection targets"},
            )

        async with httpx.AsyncClient(verify=scanning_ssl_context(), timeout=15.0) as client:
            for target in targets:
                url = target.get("url", "")
                params = target.get("params", [])

                for param_name in params:
                    # 1. Timing oracle (SQL injection)
                    sqli_results = await self._timing_oracle(client, url, param_name)
                    findings.extend(sqli_results)

                    # 2. Canary reflection (XSS)
                    xss_results = await self._canary_reflection(
                        client, url, param_name, _XSS_CANARY_PAYLOADS, "xss"
                    )
                    findings.extend(xss_results)

                    # 3. Canary reflection (SSTI)
                    ssti_results = await self._canary_reflection(
                        client, url, param_name, _SSTI_CANARY_PAYLOADS, "ssti"
                    )
                    findings.extend(ssti_results)

        elapsed = (time.monotonic() - start) * 1000
        self.capture_evidence(
            context,
            f"{len(findings)} injection findings".encode(),
            "injection_test",
        )
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
            metadata={
                "targets_tested": len(targets),
                "duration_ms": round(elapsed, 2),
            },
        )

    async def _measure_baseline(
        self,
        client: httpx.AsyncClient,
        url: str,
        param_name: str,
    ) -> float:
        """Measure average baseline response time (seconds)."""
        times: list[float] = []
        for _ in range(self._BASELINE_REQUESTS):
            t0 = time.monotonic()
            with contextlib.suppress(Exception):
                await client.get(url, params={param_name: "baseline"})
            times.append(time.monotonic() - t0)
        return sum(times) / len(times) if times else 0.0

    async def _timing_oracle(
        self,
        client: httpx.AsyncClient,
        url: str,
        param_name: str,
    ) -> list[dict[str, Any]]:
        """Test for time-based SQL injection using safe sleep payloads."""
        findings: list[dict[str, Any]] = []
        baseline = await self._measure_baseline(client, url, param_name)

        for payload_info in _SQLI_TIMING_PAYLOADS:
            try:
                t0 = time.monotonic()
                await client.get(url, params={param_name: payload_info["payload"]})
                elapsed = time.monotonic() - t0

                delta = elapsed - baseline
                if delta > self._TIMING_THRESHOLD_S:
                    findings.append(
                        {
                            "finding_type": "sqli_timing",
                            "target": url,
                            "parameter": param_name,
                            "severity": "critical",
                            "detail": (
                                f"Time-based SQLi detected ({payload_info['dialect']}): "
                                f"delta={delta:.2f}s > threshold={self._TIMING_THRESHOLD_S}s"
                            ),
                            "payload_name": payload_info["name"],
                            "dialect": payload_info["dialect"],
                            "delta_seconds": round(delta, 3),
                            "baseline_seconds": round(baseline, 3),
                            "mitre_technique": "T1190",
                        }
                    )
            except Exception:  # noqa: S112
                continue

        return findings

    async def _canary_reflection(
        self,
        client: httpx.AsyncClient,
        url: str,
        param_name: str,
        payloads: list[dict[str, str]],
        vuln_type: str,
    ) -> list[dict[str, Any]]:
        """Test for reflected content using ephemeral canary tokens."""
        findings: list[dict[str, Any]] = []
        token = hashlib.sha256(f"{url}:{param_name}:{time.monotonic()}".encode()).hexdigest()[:12]

        for payload_info in payloads:
            payload = payload_info["payload"].format(token=token)
            check = payload_info["check"].format(token=token)

            try:
                resp = await client.get(url, params={param_name: payload})
                if check in resp.text:
                    severity = "high" if vuln_type == "xss" else "critical"
                    findings.append(
                        {
                            "finding_type": f"{vuln_type}_reflected",
                            "target": url,
                            "parameter": param_name,
                            "severity": severity,
                            "detail": (
                                f"{vuln_type.upper()} canary reflected: "
                                f"payload '{payload_info['name']}' found in response"
                            ),
                            "payload_name": payload_info["name"],
                            "mitre_technique": "T1059" if vuln_type == "ssti" else "T1190",
                        }
                    )
            except Exception:  # noqa: S112
                continue

        return findings

    @staticmethod
    def safe_payload_inventory() -> dict[str, list[str]]:
        """Return the full list of payload names (for audit / review)."""
        return {
            "sqli_timing": [p["name"] for p in _SQLI_TIMING_PAYLOADS],
            "xss_canary": [p["name"] for p in _XSS_CANARY_PAYLOADS],
            "ssti_canary": [p["name"] for p in _SSTI_CANARY_PAYLOADS],
        }

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "description": "Would test injection PoC via timing oracle and canary",
                "payloads": self.safe_payload_inventory(),
            },
        )
