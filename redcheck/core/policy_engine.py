"""RedCheck246 — Policy Engine.

Validates RoE signatures, activation codes, and gates all plugin execution.
No active module may execute without passing through this engine.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
import yaml

from redcheck.core.audit import get_audit_logger
from redcheck.exceptions import PolicyDeniedException

log = structlog.get_logger(__name__)


class PolicyEngine:
    """Central policy gating engine.

    ALL active plugins must call ``authorize()`` before execution.
    If authorization fails → ``PolicyDeniedException`` is raised.
    """

    def __init__(self) -> None:
        self.audit = get_audit_logger()

    # ------------------------------------------------------------------
    # RoE validation
    # ------------------------------------------------------------------

    def validate_roe(
        self,
        roe_path: str | Path,
        verifier: Any | None = None,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Validate a Rules of Engagement YAML file.

        Parameters
        ----------
        roe_path:
            Path to the RoE YAML file.
        verifier:
            Optional ``SignatureVerifier`` instance.  When provided **and**
            configured, the RoE signature is cryptographically verified.
            When *None* (default), only presence of the ``signature``
            field is checked (backward-compatible behaviour).

        Returns ``(valid, message, parsed_roe)``.
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

        if not isinstance(roe["authorizer"], str) or not roe["authorizer"].strip():
            return False, "Authorizer must be a non-empty string", {}

        if not isinstance(roe["authorized_targets"], list) or not roe["authorized_targets"]:
            return False, "authorized_targets must be a non-empty list", {}

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

        if "signature" not in roe:
            return False, "RoE must contain a 'signature' field", roe

        # Opt-in cryptographic signature verification (S3-3).
        # When a configured verifier is supplied, actually verify the
        # signature instead of only checking that the field exists.
        if verifier is not None and hasattr(verifier, "is_configured") and verifier.is_configured:
            sig_valid, sig_msg = verifier.verify_roe(roe_path)
            if not sig_valid:
                log.warning(
                    "roe_signature_invalid",
                    engagement_id=roe.get("engagement_id"),
                    reason=sig_msg,
                )
                return False, f"RoE signature verification failed: {sig_msg}", roe
            log.info(
                "roe_signature_verified",
                engagement_id=roe.get("engagement_id"),
                mode=getattr(verifier, "mode", "unknown"),
            )

        log.info("roe_validated", engagement_id=roe.get("engagement_id"))
        self.audit.log(
            action="ROE_VALIDATED",
            details=f"RoE {roe.get('engagement_id')} validated successfully",
            engagement_id=str(roe.get("engagement_id", "")),
        )
        return True, "RoE is valid", roe

    # ------------------------------------------------------------------
    # Activation
    # ------------------------------------------------------------------

    def validate_activation_code(self, code: str) -> bool:
        """Validate activation code via the ActivationEngine."""
        from redcheck.core.activation_engine import get_activation_engine

        engine = get_activation_engine()
        valid = engine.verify_code(code)
        self.audit.log_activation_attempt(success=valid)
        return valid

    # ------------------------------------------------------------------
    # Authorization gate
    # ------------------------------------------------------------------

    def authorize(
        self,
        plugin_name: str,
        engagement: dict[str, Any] | None = None,
        requires_authorization: bool = True,
    ) -> None:
        """Gate plugin execution — raises ``PolicyDeniedException`` on denial."""
        allowed, reason = self.is_action_allowed(plugin_name, engagement, requires_authorization)
        if not allowed:
            log.warning("policy_denied", plugin=plugin_name, reason=reason)
            self.audit.log(
                action="POLICY_DENIED",
                details=f"{plugin_name}: {reason}",
                level="WARN",
            )
            raise PolicyDeniedException(plugin_name, reason)

    def is_action_allowed(
        self,
        plugin_name: str,
        engagement: dict[str, Any] | None = None,
        requires_authorization: bool = True,
    ) -> tuple[bool, str]:
        """Check if a plugin action is allowed under current policy."""
        if not requires_authorization:
            return True, "Plugin does not require authorization"

        if engagement is None:
            return False, "No engagement context provided"

        eng_data = engagement

        if not eng_data.get("roe_validated", False):
            return False, "RoE has not been validated"

        if not eng_data.get("activation_verified", False):
            return False, "Activation code has not been verified"

        allowed_tests = eng_data.get("allowed_tests", [])
        if allowed_tests:
            # Check plugin name, category, or name prefix against allowed list
            plugin_category = eng_data.get("plugin_category", "")
            name_prefix = plugin_name.split(".")[0] if "." in plugin_name else ""
            if (
                plugin_name not in allowed_tests
                and plugin_category not in allowed_tests
                and name_prefix not in allowed_tests
            ):
                return (
                    False,
                    f"Plugin '{plugin_name}' not in allowed tests: {allowed_tests}",
                )

        start_str = eng_data.get("start_time_utc")
        end_str = eng_data.get("end_time_utc")
        if start_str and end_str:
            try:
                raw_s = str(start_str)
                raw_e = str(end_str)
                if raw_s.endswith("Z"):
                    raw_s = raw_s[:-1] + "+00:00"
                if raw_e.endswith("Z"):
                    raw_e = raw_e[:-1] + "+00:00"
                start = datetime.fromisoformat(raw_s)
                end = datetime.fromisoformat(raw_e)
                if start.tzinfo is None:
                    start = start.replace(tzinfo=timezone.utc)
                if end.tzinfo is None:
                    end = end.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                if now < start or now > end:
                    return False, f"Current time outside engagement window ({start} — {end})"
            except (ValueError, TypeError):
                return False, "Invalid time format in engagement context"

        return True, "Action authorized"

    # ------------------------------------------------------------------
    # Test isolation
    # ------------------------------------------------------------------

    @classmethod
    def reset(cls) -> None:
        """Reset the module-level singleton for test isolation."""
        global _policy_engine  # noqa: PLW0603
        _policy_engine = None


_policy_engine: PolicyEngine | None = None


def get_policy_engine() -> PolicyEngine:
    """Return the module-level ``PolicyEngine`` singleton."""
    global _policy_engine  # noqa: PLW0603
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
    return _policy_engine
