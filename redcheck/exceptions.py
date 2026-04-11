"""RedCheck246 exception hierarchy.

All framework-specific exceptions inherit from RedCheckError.
Each exception carries structured fields for logging integration.
"""

from __future__ import annotations


class RedCheckError(Exception):
    """Base exception for all RedCheck246 errors."""

    def __init__(self, message: str, *, engagement_id: str | None = None) -> None:
        self.engagement_id = engagement_id
        super().__init__(message)

    def to_dict(self) -> dict[str, object]:
        """Serialize exception to dict for structured logging."""
        return {
            "error_type": type(self).__name__,
            "message": str(self),
            "engagement_id": self.engagement_id,
        }


# ---------------------------------------------------------------------------
# Policy & Authorization
# ---------------------------------------------------------------------------


class PolicyDeniedException(RedCheckError):  # noqa: N818
    """Raised when a plugin execution is denied by the policy engine."""

    def __init__(
        self,
        plugin_name: str,
        reason: str,
        *,
        engagement_id: str | None = None,
    ) -> None:
        self.plugin_name = plugin_name
        self.reason = reason
        super().__init__(
            f"Policy denied for plugin '{plugin_name}': {reason}",
            engagement_id=engagement_id,
        )

    def to_dict(self) -> dict[str, object]:
        d = super().to_dict()
        d.update(plugin_name=self.plugin_name, reason=self.reason)
        return d


class ActivationError(RedCheckError):
    """Raised on activation code failures (set / verify / lockout)."""

    def __init__(
        self,
        message: str,
        *,
        attempts_remaining: int | None = None,
        engagement_id: str | None = None,
    ) -> None:
        self.attempts_remaining = attempts_remaining
        super().__init__(message, engagement_id=engagement_id)


class RoEValidationError(RedCheckError):
    """Raised when an RoE document fails structural or temporal validation."""

    def __init__(
        self,
        message: str,
        *,
        roe_path: str | None = None,
        engagement_id: str | None = None,
    ) -> None:
        self.roe_path = roe_path
        super().__init__(message, engagement_id=engagement_id)

    def to_dict(self) -> dict[str, object]:
        d = super().to_dict()
        d["roe_path"] = self.roe_path
        return d


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class ConfigurationError(RedCheckError):
    """Raised on config loading / validation failures."""


class ConfigTamperError(ConfigurationError):
    """Raised when a config file fails integrity verification (Phase O)."""


# ---------------------------------------------------------------------------
# Cryptography
# ---------------------------------------------------------------------------


class CryptoError(RedCheckError):
    """Raised on encryption / decryption / key-derivation failures."""


# ---------------------------------------------------------------------------
# Plugin System
# ---------------------------------------------------------------------------


class PluginError(RedCheckError):
    """Raised on plugin execution failures."""

    def __init__(
        self,
        plugin_name: str,
        message: str,
        *,
        engagement_id: str | None = None,
    ) -> None:
        self.plugin_name = plugin_name
        super().__init__(
            f"Plugin '{plugin_name}' error: {message}",
            engagement_id=engagement_id,
        )

    def to_dict(self) -> dict[str, object]:
        d = super().to_dict()
        d["plugin_name"] = self.plugin_name
        return d


class PluginNotFoundError(PluginError):
    """Raised when a requested plugin is not in the registry."""

    def __init__(self, plugin_name: str, *, engagement_id: str | None = None) -> None:
        super().__init__(
            plugin_name,
            f"Plugin '{plugin_name}' not found in registry",
            engagement_id=engagement_id,
        )


class ContextValidationError(PluginError):
    """Raised when plugin context fails validation."""

    def __init__(
        self,
        plugin_name: str,
        reason: str,
        *,
        engagement_id: str | None = None,
    ) -> None:
        self.reason = reason
        super().__init__(
            plugin_name,
            f"Context validation failed: {reason}",
            engagement_id=engagement_id,
        )


# ---------------------------------------------------------------------------
# Network / Scanning
# ---------------------------------------------------------------------------


class NetworkError(RedCheckError):
    """Raised on HTTP / DNS / network failures during scanning."""

    def __init__(
        self,
        message: str,
        *,
        target: str | None = None,
        engagement_id: str | None = None,
    ) -> None:
        self.target = target
        super().__init__(message, engagement_id=engagement_id)

    def to_dict(self) -> dict[str, object]:
        d = super().to_dict()
        d["target"] = self.target
        return d


class ScanTimeoutError(NetworkError):
    """Raised when a scan exceeds its configured timeout."""

    def __init__(
        self,
        plugin_name: str,
        timeout_seconds: float,
        *,
        target: str | None = None,
        engagement_id: str | None = None,
    ) -> None:
        self.plugin_name = plugin_name
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"Plugin '{plugin_name}' timed out after {timeout_seconds}s",
            target=target,
            engagement_id=engagement_id,
        )


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


class ScopeViolationError(PolicyDeniedException):
    """Raised when a scan attempts to access out-of-scope targets."""

    def __init__(
        self,
        plugin_name: str,
        target: str,
        *,
        engagement_id: str | None = None,
    ) -> None:
        self.target = target
        super().__init__(
            plugin_name,
            f"Target '{target}' is outside the authorized scope",
            engagement_id=engagement_id,
        )


# ---------------------------------------------------------------------------
# Offensive Controls & Isolation
# ---------------------------------------------------------------------------


class OffensiveControlError(PolicyDeniedException):
    """Raised when required offensive control flags are not enabled."""

    def __init__(
        self,
        plugin_name: str,
        missing_controls: list[str],
        *,
        engagement_id: str | None = None,
    ) -> None:
        self.missing_controls = missing_controls
        super().__init__(
            plugin_name,
            f"Missing offensive controls: {', '.join(missing_controls)}",
            engagement_id=engagement_id,
        )

    def to_dict(self) -> dict[str, object]:
        d = super().to_dict()
        d["missing_controls"] = self.missing_controls
        return d


class ChainModeError(PolicyDeniedException):
    """Raised when attack path chaining is attempted without chain_mode=True."""

    def __init__(
        self,
        plugin_name: str,
        *,
        reason: str = "Attack path chaining requires chain_mode=True in OffensiveControls",
        engagement_id: str | None = None,
    ) -> None:
        super().__init__(
            plugin_name,
            reason,
            engagement_id=engagement_id,
        )


class IsolationError(RedCheckError):
    """Raised when a DESTRUCTIVE plugin runs without Docker sandbox."""

    def __init__(
        self,
        plugin_name: str,
        *,
        engagement_id: str | None = None,
    ) -> None:
        self.plugin_name = plugin_name
        super().__init__(
            f"Plugin '{plugin_name}' requires Docker isolation for DESTRUCTIVE capability",
            engagement_id=engagement_id,
        )

    def to_dict(self) -> dict[str, object]:
        d = super().to_dict()
        d["plugin_name"] = self.plugin_name
        return d


class RateLimitExceededError(RedCheckError):
    """Raised when a plugin exceeds its rate limit allocation."""

    def __init__(
        self,
        plugin_name: str,
        rate_limit_rps: float,
        *,
        engagement_id: str | None = None,
    ) -> None:
        self.plugin_name = plugin_name
        self.rate_limit_rps = rate_limit_rps
        super().__init__(
            f"Plugin '{plugin_name}' exceeded rate limit of {rate_limit_rps} req/s",
            engagement_id=engagement_id,
        )

    def to_dict(self) -> dict[str, object]:
        d = super().to_dict()
        d.update(plugin_name=self.plugin_name, rate_limit_rps=self.rate_limit_rps)
        return d


class TenantIsolationError(RedCheckError):
    """Raised on cross-tenant access attempts."""

    def __init__(
        self,
        requested_tenant: str,
        current_tenant: str,
        *,
        engagement_id: str | None = None,
    ) -> None:
        self.requested_tenant = requested_tenant
        self.current_tenant = current_tenant
        super().__init__(
            f"Cross-tenant access denied: requested '{requested_tenant}' "
            f"from tenant '{current_tenant}'",
            engagement_id=engagement_id,
        )

    def to_dict(self) -> dict[str, object]:
        d = super().to_dict()
        d.update(
            requested_tenant=self.requested_tenant,
            current_tenant=self.current_tenant,
        )
        return d


# ---------------------------------------------------------------------------
# OTP
# ---------------------------------------------------------------------------


class OTPError(RedCheckError):
    """Base for OTP-related errors."""

    def __init__(
        self,
        message: str,
        *,
        challenge_id: str | None = None,
        engagement_id: str | None = None,
    ) -> None:
        self.challenge_id = challenge_id
        super().__init__(message, engagement_id=engagement_id)


class OTPExpiredError(OTPError):
    """OTP challenge has expired."""


class OTPVerificationError(OTPError):
    """OTP verification failed (wrong code)."""

    def __init__(
        self,
        *,
        attempts_remaining: int,
        challenge_id: str | None = None,
        engagement_id: str | None = None,
    ) -> None:
        self.attempts_remaining = attempts_remaining
        super().__init__(
            f"OTP verification failed, {attempts_remaining} attempts remaining",
            challenge_id=challenge_id,
            engagement_id=engagement_id,
        )


class OTPCancelledError(OTPError):
    """User cancelled the OTP challenge."""


class PipelineError(RedCheckError):
    """Pipeline execution error."""

    def __init__(
        self,
        message: str,
        *,
        failed_plugin: str | None = None,
        engagement_id: str | None = None,
    ) -> None:
        self.failed_plugin = failed_plugin
        super().__init__(message, engagement_id=engagement_id)


# ---------------------------------------------------------------------------
# Target Identity Validation
# ---------------------------------------------------------------------------


class TargetIdentityError(RedCheckError):
    """Raised when target identity validation fails in strict mode."""

    def __init__(
        self,
        target: str,
        confidence: float,
        *,
        engagement_id: str | None = None,
    ) -> None:
        self.target = target
        self.confidence = confidence
        super().__init__(
            f"Target identity validation failed for '{target}' (confidence: {confidence:.2f})",
            engagement_id=engagement_id,
        )

    def to_dict(self) -> dict[str, object]:
        d = super().to_dict()
        d.update(target=self.target, confidence=self.confidence)
        return d
