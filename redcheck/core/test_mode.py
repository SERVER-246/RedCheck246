"""RedCheck246 — Test Mode Controller.

Orchestrates Test Mode operations with OTP gating for DESTRUCTIVE plugins.
Wraps the existing Orchestrator — never bypasses it.
Supports pipeline chaining via PipelineExecutor.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import structlog
from pydantic import BaseModel, Field

from redcheck.core.audit import get_audit_logger
from redcheck.core.pipeline import PipelineExecutor
from redcheck.exceptions import (
    ChainModeError,
    ConfigurationError,
    OTPCancelledError,
    OTPExpiredError,
    OTPVerificationError,
    PipelineError,
)
from redcheck.models import (
    EngagementContext,
    PluginCapability,
    PluginResult,
    RuntimeMode,
)
from redcheck.plugins.base_plugin import PluginRegistry

if TYPE_CHECKING:
    from collections.abc import Callable

    from redcheck.core.orchestrator import Orchestrator
    from redcheck.core.otp_engine import OTPEngine

log = structlog.get_logger(__name__)


class TestModeReport(BaseModel):
    """Aggregated Test Mode execution report."""

    __test__ = False  # not a pytest test class

    engagement_id: str
    runtime_mode: str = "test"
    plugins_executed: list[str] = Field(default_factory=list)
    plugins_skipped: list[str] = Field(default_factory=list)
    plugin_results: dict[str, PluginResult] = Field(default_factory=dict)
    attack_paths: list[dict[str, Any]] = Field(default_factory=list)
    total_findings: int = 0
    total_evidence: int = 0
    otp_challenges: int = 0
    otp_verified: int = 0
    otp_cancelled: int = 0
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    chain_mode: bool = False

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()


class TestModeController:
    """Orchestrates Test Mode operations with OTP gating."""

    __test__ = False  # not a pytest test class

    def __init__(
        self,
        orchestrator: Orchestrator,
        otp_engine: OTPEngine,
        *,
        prompt_callback: Callable[[str], str] | None = None,
    ) -> None:
        self._orch = orchestrator
        self._otp = otp_engine
        self._prompt = prompt_callback or input
        self._pipeline_results: dict[str, PluginResult] = {}
        self._audit = get_audit_logger()

    async def run_test_mode(
        self,
        engagement: EngagementContext,
        plugins: list[str],
        *,
        dry_run: bool = False,
        chain: bool = False,
    ) -> TestModeReport:
        """Execute plugins in Test Mode with OTP gating for DESTRUCTIVE plugins.

        Args:
            engagement: The active EngagementContext (must be RuntimeMode.TEST).
            plugins: Ordered list of plugin names to execute.
            dry_run: If True, plugins produce simulated results.
            chain: If True, upstream findings are injected into subsequent plugins
                   via PipelineExecutor.

        Returns:
            TestModeReport with aggregated results.
        """
        # Step 1 — Validate runtime mode
        if engagement.runtime_mode != RuntimeMode.TEST:
            raise ConfigurationError(
                "Test mode requires RuntimeMode.TEST in the engagement context",
                engagement_id=engagement.engagement_id,
            )

        start_time = datetime.now(timezone.utc)
        plugins_executed: list[str] = []
        plugins_skipped: list[str] = []
        otp_challenges = 0
        otp_verified = 0
        otp_cancelled = 0
        self._pipeline_results.clear()

        self._audit.log(
            action="TEST_MODE_START",
            details=f"Test mode starting with {len(plugins)} plugin(s)",
            engagement_id=engagement.engagement_id,
        )

        # Step 1b — Chain mode validation
        if chain and not engagement.offensive_controls.chain_mode:
            raise ChainModeError(
                plugin_name="test-mode",
                reason="chain_mode offensive control not enabled",
                engagement_id=engagement.engagement_id,
            )

        # Phase 1: OTP pre-gate — collect which DESTRUCTIVE plugins need OTP
        otp_passed: set[str] = set()
        for plugin_name in plugins:
            plugin = PluginRegistry.get_instance(plugin_name)
            if plugin is None:
                log.warning("plugin_not_found", plugin_name=plugin_name)
                plugins_skipped.append(plugin_name)
                continue

            capability = getattr(plugin, "capability", PluginCapability.PASSIVE)

            if capability == PluginCapability.DESTRUCTIVE:
                otp_challenges += 1

                if not engagement.otp_email:
                    log.warning(
                        "otp_email_missing",
                        plugin_name=plugin_name,
                    )
                    plugins_skipped.append(plugin_name)
                    continue

                challenge, code = self._otp.generate_otp(
                    engagement_id=engagement.engagement_id,
                    plugin_name=plugin_name,
                )
                self._otp.send_otp(challenge, engagement.otp_email, code)

                try:
                    user_input = self._prompt(
                        f"Enter OTP for DESTRUCTIVE plugin '{plugin_name}' (or 'cancel'): "
                    )
                except (EOFError, KeyboardInterrupt):
                    user_input = "cancel"

                if user_input.strip().lower() == "cancel":
                    otp_cancelled += 1
                    log.info("otp_user_cancelled", plugin_name=plugin_name)
                    self._audit.log(
                        action="OTP_USER_CANCEL",
                        details=f"User cancelled OTP for '{plugin_name}'",
                        engagement_id=engagement.engagement_id,
                    )
                    plugins_skipped.append(plugin_name)
                    continue

                try:
                    self._otp.verify_otp(challenge, user_input)
                    otp_verified += 1
                    otp_passed.add(plugin_name)
                except (OTPExpiredError, OTPVerificationError):
                    log.warning("otp_gate_failed", plugin_name=plugin_name)
                    plugins_skipped.append(plugin_name)
                    continue
                except OTPCancelledError:
                    otp_cancelled += 1
                    plugins_skipped.append(plugin_name)
                    continue
            else:
                otp_passed.add(plugin_name)

        # Phase 2: Determine executable plugins (OTP-gated list)
        executable_plugins = [p for p in plugins if p in otp_passed]

        # Phase 3: Execute — delegate to PipelineExecutor if chaining
        if chain and executable_plugins:
            pipeline = PipelineExecutor(self._orch)
            try:
                self._pipeline_results = await pipeline.execute_pipeline(
                    engagement,
                    executable_plugins,
                    dry_run=dry_run,
                    chain=True,
                )
                plugins_executed = list(self._pipeline_results.keys())
            except PipelineError as exc:
                log.error(
                    "pipeline_failed",
                    error=str(exc),
                    engagement_id=engagement.engagement_id,
                )
                self._pipeline_results = pipeline.results
                plugins_executed = list(self._pipeline_results.keys())
                if exc.failed_plugin:
                    plugins_skipped.append(exc.failed_plugin)
        else:
            # Non-chain execution: run each plugin individually
            for plugin_name in executable_plugins:
                try:
                    result = await self._orch.arun_plugin(
                        plugin_name,
                        engagement,
                        dry_run=dry_run,
                    )
                except Exception as exc:
                    log.error(
                        "plugin_execution_failed",
                        plugin_name=plugin_name,
                        error=str(exc),
                    )
                    self._audit.log(
                        action="PLUGIN_EXEC_FAILED",
                        details=f"Plugin '{plugin_name}' failed: {exc}",
                        engagement_id=engagement.engagement_id,
                        level="ERROR",
                    )
                    plugins_skipped.append(plugin_name)
                    continue

                self._pipeline_results[plugin_name] = result
                plugins_executed.append(plugin_name)

        # Step 7 — Build report
        end_time = datetime.now(timezone.utc)

        total_findings = sum(r.finding_count for r in self._pipeline_results.values())
        total_evidence = sum(len(r.evidence) for r in self._pipeline_results.values())

        report = TestModeReport(
            engagement_id=engagement.engagement_id,
            plugins_executed=plugins_executed,
            plugins_skipped=plugins_skipped,
            plugin_results=dict(self._pipeline_results),
            total_findings=total_findings,
            total_evidence=total_evidence,
            otp_challenges=otp_challenges,
            otp_verified=otp_verified,
            otp_cancelled=otp_cancelled,
            start_time=start_time,
            end_time=end_time,
            chain_mode=chain,
        )

        self._audit.log(
            action="TEST_MODE_COMPLETE",
            details=(
                f"executed={len(plugins_executed)} "
                f"skipped={len(plugins_skipped)} "
                f"findings={total_findings}"
            ),
            engagement_id=engagement.engagement_id,
        )

        return report
