"""
RedCheck246 Policy Engine

Validates RoE signatures, activation codes, and gates all plugin execution.
No active module may execute without passing through this engine.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from redcheck.core.audit import get_audit_logger

if TYPE_CHECKING:
    from redcheck.core.orchestrator import EngagementContext


class PolicyDeniedException(Exception):
    """Raised when the policy engine denies an action."""

    def __init__(self, plugin: str, reason: str):
        self.plugin = plugin
        self.reason = reason
        super().__init__(f"Policy denied for '{plugin}': {reason}")


class PolicyEngine:
    """Central policy gating engine.

    ALL active plugins must call PolicyEngine.authorize() before execution.
    If authorization fails → PolicyDeniedException is raised, logged, execution terminates.
    """

    def __init__(self):
        self.audit = get_audit_logger()

    def validate_roe(self, roe_path: str | Path) -> tuple[bool, str, dict]:
        """Validate a Rules of Engagement YAML file.

        Checks:
        - File exists and is readable
        - Valid YAML structure
        - Required fields present (engagement_id, authorizer, authorized_targets,
          allowed_tests, start_time_utc, end_time_utc)
        - Time window is valid (not expired, not future)
        - Signed field present

        Returns: (valid, message, parsed_roe)
        """
        roe_path = Path(roe_path)

        if not roe_path.exists():
            return False, f"RoE file not found: {roe_path}", {}

        try:
            with open(roe_path, encoding="utf-8") as f:
                roe = yaml.safe_load(f)
        except yaml.YAMLError as e:
            return False, f"Invalid YAML in RoE: {e}", {}

        if not isinstance(roe, dict):
            return False, "RoE must be a YAML dictionary", {}

        # Required fields
        required = [
            "engagement_id",
            "authorizer",
            "authorized_targets",
            "allowed_tests",
            "start_time_utc",
            "end_time_utc",
        ]
        missing = [f for f in required if f not in roe]
        if missing:
            return False, f"Missing required RoE fields: {', '.join(missing)}", {}

        # Validate authorizer is a single entity
        if not isinstance(roe["authorizer"], str) or not roe["authorizer"].strip():
            return False, "Authorizer must be a non-empty string (sole authorizer)", {}

        # Validate targets
        if not isinstance(roe["authorized_targets"], list) or not roe["authorized_targets"]:
            return False, "authorized_targets must be a non-empty list", {}

        # Validate time window
        # Replace trailing 'Z' with '+00:00' for Python 3.10 compat
        # (fromisoformat only learned the 'Z' suffix in 3.11)
        try:
            raw_start = str(roe["start_time_utc"])
            raw_end = str(roe["end_time_utc"])
            if raw_start.endswith("Z"):
                raw_start = raw_start[:-1] + "+00:00"
            if raw_end.endswith("Z"):
                raw_end = raw_end[:-1] + "+00:00"
            start = datetime.fromisoformat(raw_start)
            end = datetime.fromisoformat(raw_end)
        except (ValueError, TypeError) as e:
            return False, f"Invalid time format in RoE: {e}", {}

        now = datetime.now(timezone.utc)
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)

        if now > end:
            return False, f"RoE has expired (end_time: {end.isoformat()})", roe

        # Validate signature field exists
        if "signature" not in roe:
            return False, "RoE must contain a 'signature' field", roe

        self.audit.log(
            action="ROE_VALIDATED",
            details=f"RoE {roe.get('engagement_id')} validated successfully",
            engagement_id=str(roe.get("engagement_id", "")),
        )

        return True, "RoE is valid", roe

    def validate_activation_code(self, code: str) -> bool:
        """Validate activation code via the ActivationEngine.

        Returns True if the code matches the stored activation hash.
        """
        from redcheck.core.activation_engine import get_activation_engine

        engine = get_activation_engine()
        valid = engine.verify_code(code)

        self.audit.log_activation_attempt(success=valid)

        return valid

    def is_action_allowed(
        self,
        plugin_name: str,
        engagement: "EngagementContext | dict | None" = None,
        requires_authorization: bool = True,
    ) -> tuple[bool, str]:
        """Check if a plugin action is allowed under current policy.

        Args:
            plugin_name: Name of the plugin requesting execution.
            engagement: Engagement context (dict or EngagementContext).
            requires_authorization: Whether the plugin requires RoE + activation.

        Returns: (allowed, reason)
        """
        # Plugins that don't require authorization can always run
        if not requires_authorization:
            return True, "Plugin does not require authorization"

        if engagement is None:
            return False, "No engagement context provided"

        # Extract engagement data
        if isinstance(engagement, dict):
            eng_data = engagement
        else:
            eng_data = getattr(engagement, "to_dict", lambda: {})()

        # Check RoE is validated
        if not eng_data.get("roe_validated", False):
            return False, "RoE has not been validated for this engagement"

        # Check activation
        if not eng_data.get("activation_verified", False):
            return False, "Activation code has not been verified"

        # Check allowed tests
        allowed_tests = eng_data.get("allowed_tests", [])
        plugin_category = plugin_name.split(".")[0] if "." in plugin_name else plugin_name
        if allowed_tests and plugin_category not in allowed_tests:
            return (
                False,
                f"Plugin category '{plugin_category}' not in allowed tests: {allowed_tests}",
            )

        # Check time window
        start_str = eng_data.get("start_time_utc")
        end_str = eng_data.get("end_time_utc")
        if start_str and end_str:
            try:
                start = datetime.fromisoformat(str(start_str))
                end = datetime.fromisoformat(str(end_str))
                if start.tzinfo is None:
                    start = start.replace(tzinfo=timezone.utc)
                if end.tzinfo is None:
                    end = end.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                if now < start or now > end:
                    return False, f"Current time outside engagement window ({start} - {end})"
            except (ValueError, TypeError):
                return False, "Invalid time format in engagement context"

        return True, "Action authorized"

    def authorize(
        self,
        plugin_name: str,
        engagement: "EngagementContext | dict | None" = None,
        requires_authorization: bool = True,
    ) -> None:
        """Authorize a plugin action or raise PolicyDeniedException.

        This is the primary gate. Every active plugin MUST call this.
        """
        allowed, reason = self.is_action_allowed(plugin_name, engagement, requires_authorization)

        if not allowed:
            self.audit.log_policy_denial(
                plugin=plugin_name,
                reason=reason,
                engagement_id=str(
                    (engagement or {}).get("engagement_id", "")
                    if isinstance(engagement, dict)
                    else ""
                ),
            )
            raise PolicyDeniedException(plugin_name, reason)

        self.audit.log(
            action="POLICY_AUTHORIZED",
            details=f"Plugin '{plugin_name}' authorized",
            plugin=plugin_name,
            engagement_id=str(
                (engagement or {}).get("engagement_id", "") if isinstance(engagement, dict) else ""
            ),
        )


_policy_engine: PolicyEngine | None = None


def get_policy_engine() -> PolicyEngine:
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
    return _policy_engine
