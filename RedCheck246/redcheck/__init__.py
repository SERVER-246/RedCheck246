"""RedCheck246 — Plugin-based, policy-gated security assessment framework.

Public API surface exported here for convenience.
"""

from __future__ import annotations

__version__ = "0.2.0"

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
]

from redcheck.exceptions import (
    ActivationError,
    ConfigurationError,
    ContextValidationError,
    CryptoError,
    NetworkError,
    PluginError,
    PluginNotFoundError,
    PolicyDeniedException,
    RedCheckError,
    RoEValidationError,
    ScanTimeoutError,
    ScopeViolationError,
)
