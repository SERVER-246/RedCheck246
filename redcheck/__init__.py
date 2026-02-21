"""RedCheck246 — Plugin-based, policy-gated security assessment framework.

Public API surface exported here for convenience.
"""

from __future__ import annotations

__version__ = "0.2.5"

__all__ = [
    "__version__",
    # Exceptions
    "RedCheckError",
    "PolicyDeniedException",
    "ActivationError",
    "ConfigurationError",
    "CryptoError",
    "RoEValidationError",
    "PluginError",
    "PluginNotFoundError",
    "ContextValidationError",
    "NetworkError",
    "ScanTimeoutError",
    "ScopeViolationError",
    "OffensiveControlError",
    "ChainModeError",
    "IsolationError",
    "RateLimitExceededError",
    "TenantIsolationError",
]

from redcheck.exceptions import (
    ActivationError,
    ChainModeError,
    ConfigurationError,
    ContextValidationError,
    CryptoError,
    IsolationError,
    NetworkError,
    OffensiveControlError,
    PluginError,
    PluginNotFoundError,
    PolicyDeniedException,
    RateLimitExceededError,
    RedCheckError,
    RoEValidationError,
    ScanTimeoutError,
    ScopeViolationError,
    TenantIsolationError,
)
