"""
RedCheck246 Orchestrator

Central execution coordinator. Manages engagement lifecycle, plugin dispatch,
and ensures all policy gates are enforced.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from redcheck.core.audit import get_audit_logger
from redcheck.core.policy_engine import PolicyDeniedException, get_policy_engine
from redcheck.plugins.base_plugin import BasePlugin, PluginRegistry, PluginResult


@dataclass
class EngagementContext:
    """Full engagement context passed to plugins."""

    engagement_id: str = ""
    authorizer: str = ""
    authorized_targets: list[dict] = field(default_factory=list)
    allowed_tests: list[str] = field(default_factory=list)
    start_time_utc: str = ""
    end_time_utc: str = ""
    roe_path: str = ""
    roe_validated: bool = False
    activation_verified: bool = False
    safety_mode: str = "dry-run"
    sensitivity: str = "high"
    contact: dict = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "authorizer": self.authorizer,
            "authorized_targets": self.authorized_targets,
            "allowed_tests": self.allowed_tests,
            "start_time_utc": self.start_time_utc,
            "end_time_utc": self.end_time_utc,
            "roe_path": self.roe_path,
            "roe_validated": self.roe_validated,
            "activation_verified": self.activation_verified,
            "safety_mode": self.safety_mode,
            "sensitivity": self.sensitivity,
            "contact": self.contact,
            "metadata": self.metadata,
        }

    @classmethod
    def from_yaml(cls, path: str | Path) -> "EngagementContext":
        """Load engagement context from a YAML file."""
        path = Path(path)
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_roe(cls, roe_data: dict) -> "EngagementContext":
        """Create engagement context from validated RoE data."""
        return cls(
            engagement_id=str(roe_data.get("engagement_id", "")),
            authorizer=str(roe_data.get("authorizer", "")),
            authorized_targets=roe_data.get("authorized_targets", []),
            allowed_tests=roe_data.get("allowed_tests", []),
            start_time_utc=str(roe_data.get("start_time_utc", "")),
            end_time_utc=str(roe_data.get("end_time_utc", "")),
            contact=roe_data.get("contact", {}),
            sensitivity=str(roe_data.get("sensitivity", "high")),
        )


class Orchestrator:
    """Central orchestrator for RedCheck engagements."""

    def __init__(self):
        self.policy = get_policy_engine()
        self.audit = get_audit_logger()
        self._current_engagement: EngagementContext | None = None

    @property
    def current_engagement(self) -> EngagementContext | None:
        return self._current_engagement

    def load_engagement(self, roe_path: str | Path) -> EngagementContext:
        """Load and validate an engagement from its RoE file.

        Returns: EngagementContext if validation passes.
        Raises: PolicyDeniedException if RoE is invalid.
        """
        valid, message, roe_data = self.policy.validate_roe(roe_path)

        if not valid:
            self.audit.log(
                action="ENGAGEMENT_LOAD_FAILED",
                details=message,
                level="ERROR",
            )
            raise PolicyDeniedException("orchestrator", message)

        ctx = EngagementContext.from_roe(roe_data)
        ctx.roe_path = str(roe_path)
        ctx.roe_validated = True
        self._current_engagement = ctx

        self.audit.log_engagement_action(
            action="ENGAGEMENT_LOADED",
            engagement_id=ctx.engagement_id,
            details=f"RoE validated, authorizer: {ctx.authorizer}",
        )

        return ctx

    def activate(self, code: str) -> bool:
        """Activate the current engagement with the given activation code."""
        if not self._current_engagement:
            self.audit.log(
                action="ACTIVATION_FAILED",
                details="No engagement loaded",
                level="WARN",
            )
            return False

        valid = self.policy.validate_activation_code(code)
        if valid:
            self._current_engagement.activation_verified = True
            self._current_engagement.safety_mode = "authorized-active"
            self.audit.log_engagement_action(
                action="ENGAGEMENT_ACTIVATED",
                engagement_id=self._current_engagement.engagement_id,
            )
        return valid

    def run_plugin(
        self,
        plugin_name: str,
        dry_run: bool = False,
        extra_context: dict | None = None,
    ) -> PluginResult:
        """Execute a plugin within the current engagement context.

        Args:
            plugin_name: Name of the registered plugin to run.
            dry_run: If True, use dry_run mode regardless of engagement state.
            extra_context: Additional context to merge.

        Returns: PluginResult
        """
        plugin = PluginRegistry.get_instance(plugin_name)
        if plugin is None:
            return PluginResult(
                plugin_name=plugin_name,
                success=False,
                errors=[f"Plugin '{plugin_name}' not found in registry"],
            )

        # Build context dict
        if self._current_engagement:
            context = self._current_engagement.to_dict()
        else:
            context = {}
        if extra_context:
            context.update(extra_context)

        # Dry run bypasses policy for authorized plugins
        if dry_run:
            self.audit.log(
                action="PLUGIN_DRY_RUN",
                details=f"Dry run: {plugin_name}",
                plugin=plugin_name,
                engagement_id=context.get("engagement_id", ""),
            )
            return plugin.dry_run(context)

        # Policy gate — this MUST pass for active execution
        if plugin.requires_authorization:
            self.policy.authorize(
                plugin_name=plugin_name,
                engagement=context,
                requires_authorization=True,
            )

        # Validate context
        valid, reason = plugin.validate_context(context)
        if not valid:
            return PluginResult(
                plugin_name=plugin_name,
                success=False,
                errors=[f"Context validation failed: {reason}"],
            )

        # Execute
        self.audit.log(
            action="PLUGIN_EXECUTE",
            details=f"Executing: {plugin_name}",
            plugin=plugin_name,
            engagement_id=context.get("engagement_id", ""),
        )

        try:
            result = plugin.execute(context)
        except Exception as e:
            result = PluginResult(
                plugin_name=plugin_name,
                success=False,
                errors=[f"Plugin execution error: {e}"],
            )

        self.audit.log(
            action="PLUGIN_COMPLETE",
            details=f"Plugin {plugin_name}: success={result.success}, findings={len(result.findings)}",
            plugin=plugin_name,
            engagement_id=context.get("engagement_id", ""),
        )

        return result

    def shutdown(self) -> None:
        """Clean shutdown of the orchestrator."""
        if self._current_engagement:
            self.audit.log_engagement_action(
                action="ENGAGEMENT_SHUTDOWN",
                engagement_id=self._current_engagement.engagement_id,
            )
        self._current_engagement = None
