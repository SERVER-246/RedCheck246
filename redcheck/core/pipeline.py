"""RedCheck246 — Pipeline Executor.

Ordered plugin execution with cross-plugin data flow (chain mode).
Wraps the Orchestrator — never bypasses the 11-step enforcement.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from redcheck.exceptions import ChainModeError, PipelineError  # noqa: F401
from redcheck.plugins.base_plugin import PluginResult

if TYPE_CHECKING:
    from redcheck.core.orchestrator import Orchestrator
    from redcheck.models import EngagementContext

log = structlog.get_logger(__name__)

DEFAULT_CHAIN_ORDER: list[str] = [
    # Phase 1: Reconnaissance (generates target data)
    "passive-recon",
    "network-scanner",
    # Phase 2: Static Analysis (generates vulnerability data)
    "sast-scanner",
    "supply-chain-audit",
    # Phase 3: Dynamic Analysis (uses target + vulnerability data)
    "dast-scanner",
    "protocol-fuzzer",
    # Phase 4: OSINT Enrichment
    "breach-lookup",
    "ct-log-monitor",
    "typosquat-detector",
    # Phase 5: Correlation & Mapping (consumes all upstream data)
    "cve-mapper",
    # Phase 6: Validation
    "auth-session-tester",
    "idor-validator",
    "injection-poc-simulator",
    "exploit-verifier",
    # Phase 7: Detection Assessment
    "detection-coverage",
    "alert-latency",
    # Phase 8: Crypto Analysis
    "hash-strength-analyzer",
    "password-entropy-scorer",
]


def _extract_services(results: dict[str, PluginResult]) -> list[dict[str, Any]]:
    """Extract discovered service info from upstream plugin results."""
    services: list[dict[str, Any]] = []
    for result in results.values():
        for finding in result.findings:
            fd = finding.model_dump() if hasattr(finding, "model_dump") else {}
            finding_type = fd.get("finding_type", "")
            meta = fd.get("metadata") or {}

            # Primary path: structured open_port findings from network-scanner
            if finding_type == "open_port":
                svc = meta.get("service_name", "")
                ver = meta.get("service_version", "")
                port = meta.get("port", "")
                if svc:
                    services.append({"service": svc, "version": ver, "port": str(port)})
                continue

            # Fallback: keyword match for other service-related findings
            detail = fd.get("detail", "")
            if "service" in finding_type.lower() or "service" in detail.lower():
                services.append(fd)
    return services


class PipelineExecutor:
    """Ordered plugin execution with cross-plugin data flow."""

    def __init__(self, orchestrator: Orchestrator) -> None:
        self._orch = orchestrator
        self._results: dict[str, PluginResult] = {}

    @property
    def results(self) -> dict[str, PluginResult]:
        """Read-only access to accumulated results."""
        return dict(self._results)

    async def execute_pipeline(
        self,
        engagement: EngagementContext,
        plugin_order: list[str],
        *,
        dry_run: bool = False,
        chain: bool = False,
    ) -> dict[str, PluginResult]:
        """Execute plugins in order, optionally chaining findings.

        Args:
            engagement: The active EngagementContext.
            plugin_order: Ordered list of plugin names to execute.
            dry_run: If True, plugins produce simulated results.
            chain: If True, upstream findings are injected into subsequent plugins.

        Returns:
            Mapping of plugin name → PluginResult for all executed plugins.

        Raises:
            ChainModeError: If chain=True but offensive_controls.chain_mode is False.
            PipelineError: On unrecoverable pipeline-level errors.
        """
        if chain and not engagement.offensive_controls.chain_mode:
            raise ChainModeError(
                plugin_name="pipeline",
                reason="chain_mode offensive control not enabled",
                engagement_id=engagement.engagement_id,
            )

        if not plugin_order:
            return {}

        self._results.clear()

        log.info(
            "pipeline_start",
            plugins=len(plugin_order),
            chain=chain,
            dry_run=dry_run,
            engagement_id=engagement.engagement_id,
        )

        for plugin_name in plugin_order:
            extra_context: dict[str, Any] = {}

            if chain and self._results:
                extra_context["upstream_findings"] = [
                    f for r in self._results.values() for f in r.findings
                ]
                extra_context["upstream_plugins"] = list(self._results.keys())
                extra_context["discovered_services"] = _extract_services(self._results)

            try:
                result = await self._orch.arun_plugin(
                    plugin_name,
                    engagement,
                    dry_run=dry_run,
                    extra_context=extra_context or None,
                )
            except Exception as exc:
                log.error(
                    "pipeline_plugin_failed",
                    plugin_name=plugin_name,
                    error=str(exc),
                    engagement_id=engagement.engagement_id,
                )
                self._results[plugin_name] = PluginResult(
                    plugin_name=plugin_name,
                    success=False,
                    findings=[],
                    errors=[f"Execution failed: {exc}"],
                    metadata={"error_type": type(exc).__name__, "isolated": True},
                )
                continue

            self._results[plugin_name] = result
            log.info(
                "pipeline_plugin_complete",
                plugin_name=plugin_name,
                success=result.success,
                findings=len(result.findings),
            )

        log.info(
            "pipeline_complete",
            plugins_executed=len(self._results),
            total_findings=sum(len(r.findings) for r in self._results.values()),
            engagement_id=engagement.engagement_id,
        )

        return dict(self._results)
