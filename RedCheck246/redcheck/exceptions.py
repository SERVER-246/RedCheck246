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
