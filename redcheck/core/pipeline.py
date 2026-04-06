"""RedCheck246 — Pipeline Executor.

Ordered plugin execution with cross-plugin data flow (chain mode).
Wraps the Orchestrator — never bypasses the 11-step enforcement.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from redcheck.exceptions import ChainModeError, PipelineError  # noqa: F401
from redcheck.plugins.base_plugin import PluginRegistry, PluginResult

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


def _extract_credentials(results: dict[str, PluginResult]) -> dict[str, list[str]]:
    """Extract passwords and hashes from upstream SAST findings."""
    passwords: list[str] = []
    hashes: list[str] = []
    for result in results.values():
        for finding in result.findings:
            ft = getattr(finding, "finding_type", "")
            meta = finding.metadata if hasattr(finding, "metadata") else {}
            detail = getattr(finding, "detail", "")

            if ft in ("hardcoded_secret", "hardcoded_password", "hardcoded_credential"):
                val = meta.get("secret_value") or meta.get("password", "")
                if val:
                    passwords.append(val)
            elif ft in ("hardcoded_hash", "weak_hash"):
                val = meta.get("hash_value", "")
                if val:
                    hashes.append(val)
            elif "password" in ft.lower() and meta.get("value"):
                passwords.append(meta["value"])
            elif "hash" in detail.lower() and meta.get("value"):
                hashes.append(meta["value"])
    return {"passwords": passwords, "hashes": hashes}


def _extract_endpoints(results: dict[str, PluginResult]) -> list[str]:
    """Extract discovered web endpoints from DAST/recon results."""
    endpoints: list[str] = []
    for result in results.values():
        for finding in result.findings:
            meta = finding.metadata if hasattr(finding, "metadata") else {}
            url = meta.get("url") or meta.get("endpoint", "")
            if url and url not in endpoints:
                endpoints.append(url)
    return endpoints


def _extract_packages(results: dict[str, PluginResult]) -> list[str]:
    """Extract package names from supply-chain-audit results."""
    packages: list[str] = []
    for result in results.values():
        for finding in result.findings:
            meta = finding.metadata if hasattr(finding, "metadata") else {}
            pkg = meta.get("package") or meta.get("package_name", "")
            if pkg and pkg not in packages:
                packages.append(pkg)
    return packages


# ------------------------------------------------------------------
# Dependency Resolution
# ------------------------------------------------------------------


def resolve_execution_order(plugin_names: list[str] | None = None) -> list[list[str]]:
    """Resolve plugin execution order via topological sort.

    Returns a list of tiers, where each tier is a list of plugin names
    that can execute in parallel.  Cross-tier execution is sequential.

    If *plugin_names* is ``None``, all registered plugins are used.
    Plugins not found in the registry are silently skipped.
    """
    names = list(plugin_names) if plugin_names is not None else PluginRegistry.list_names()

    # Build adjacency from declared required + optional dependencies
    # Only include edges whose source is also in the requested set
    name_set = set(names)
    deps: dict[str, set[str]] = {}
    for name in names:
        plugin_cls = PluginRegistry.get(name)
        if plugin_cls is None:
            continue
        required = set(getattr(plugin_cls, "_dep_required", []))
        optional = set(getattr(plugin_cls, "_dep_optional", []))
        # Only keep dependencies that are in the requested set
        deps[name] = (required | optional) & name_set

    # Kahn's algorithm for topological sort into tiers
    # in_degree[node] = count of deps that are also in the set
    in_degree: dict[str, int] = {}
    for node in deps:
        in_degree[node] = sum(1 for d in deps[node] if d in deps)

    tiers: list[list[str]] = []
    remaining = set(deps.keys())

    while remaining:
        # Current tier: all nodes with in_degree 0
        tier = sorted(n for n in remaining if in_degree[n] == 0)
        if not tier:
            # Cycle detected — break by adding all remaining
            log.warning("dependency_cycle_detected", plugins=sorted(remaining))
            tiers.append(sorted(remaining))
            break
        tiers.append(tier)
        remaining -= set(tier)
        # Reduce in-degree for nodes that depended on this tier
        for node in remaining:
            in_degree[node] = sum(1 for d in deps[node] if d in remaining)

    return tiers


def check_dependencies(
    plugin_name: str,
    completed: dict[str, PluginResult],
) -> tuple[bool, str | None, bool]:
    """Check whether a plugin's dependencies are satisfied.

    Returns:
        (can_execute, skip_reason, degraded)
        - can_execute: True if the plugin should execute
        - skip_reason: If can_execute is False, the reason string
        - degraded: True if a required dependency failed (execute in degraded mode)
    """
    plugin_cls = PluginRegistry.get(plugin_name)
    if plugin_cls is None:
        # Plugin not in registry — no dependency metadata, allow execution
        return True, None, False

    required = getattr(plugin_cls, "_dep_required", [])
    degraded = False

    for dep in required:
        if dep not in completed:
            return False, f"Required dependency '{dep}' did not execute", False
        dep_result = completed[dep]
        if not dep_result.success and dep_result.findings == []:
            degraded = True

    return True, None, degraded


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
        auto_order: bool = False,
    ) -> dict[str, PluginResult]:
        """Execute plugins in order, optionally chaining findings.

        Args:
            engagement: The active EngagementContext.
            plugin_order: Ordered list of plugin names to execute.
            dry_run: If True, plugins produce simulated results.
            chain: If True, upstream findings are injected into subsequent plugins.
            auto_order: If True, reorder plugins using dependency graph
                        (topological sort). *plugin_order* is treated as the
                        set of plugins to run; execution order is determined
                        by declared dependencies.

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

        # Optionally reorder by dependency graph
        if auto_order:
            tiers = resolve_execution_order(plugin_order)
            ordered: list[str] = []
            for tier in tiers:
                ordered.extend(tier)
            plugin_order = ordered
            log.info(
                "pipeline_auto_ordered",
                tiers=[list(t) for t in tiers],
                engagement_id=engagement.engagement_id,
            )

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

            # Dependency check
            can_exec, skip_reason, degraded = check_dependencies(plugin_name, self._results)
            if not can_exec:
                log.warning(
                    "pipeline_dependency_skip",
                    plugin_name=plugin_name,
                    reason=skip_reason,
                    engagement_id=engagement.engagement_id,
                )
                self._results[plugin_name] = PluginResult(
                    plugin_name=plugin_name,
                    success=False,
                    findings=[],
                    errors=[f"Skipped: {skip_reason}"],
                    metadata={
                        "error_type": "dependency_missing",
                        "skip_reason": skip_reason,
                    },
                )
                continue

            if degraded:
                extra_context["_degraded"] = True
                extra_context["_degraded_reason"] = "One or more required dependencies failed"

            if chain and self._results:
                extra_context["upstream_findings"] = [
                    f for r in self._results.values() for f in r.findings
                ]
                extra_context["upstream_plugins"] = list(self._results.keys())
                extra_context["discovered_services"] = _extract_services(self._results)

                # Auto-populate context keys for downstream plugins
                creds = _extract_credentials(self._results)
                if creds["passwords"]:
                    extra_context.setdefault("breach_passwords", creds["passwords"])
                    extra_context.setdefault("passwords", creds["passwords"])
                if creds["hashes"]:
                    extra_context.setdefault("hashes", creds["hashes"])

                endpoints = _extract_endpoints(self._results)
                if endpoints:
                    extra_context.setdefault("idor_endpoints", endpoints)

                packages = _extract_packages(self._results)
                if packages:
                    extra_context.setdefault("typosquat_domains", packages)

                # Provide ct_domains / typosquat_domains from engagement targets
                targets = engagement.targets or []
                if targets:
                    extra_context.setdefault("ct_domains", list(targets))
                    extra_context.setdefault(
                        "typosquat_domains",
                        extra_context.get("typosquat_domains", list(targets)),
                    )

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
