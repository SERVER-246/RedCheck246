"""RedCheck246 — Plugin-based, policy-gated security assessment framework.

Public API surface exported here for convenience.
"""

from __future__ import annotations

__version__ = "0.3.2"

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
    "OTPError",
    "OTPExpiredError",
    "OTPVerificationError",
    "OTPCancelledError",
    "PipelineError",
    # Config
    "RedCheckConfig",
    # Models
    "RuntimeMode",
    "PluginCapability",
    "OperatorRole",
    # Phase 5 — Multi-Tenant & RBAC
    "RBACAction",
]

from redcheck.config import RedCheckConfig
from redcheck.core.rbac import RBACAction
from redcheck.exceptions import (
    ActivationError,
    ChainModeError,
    ConfigurationError,
    ContextValidationError,
    CryptoError,
    IsolationError,
    NetworkError,
    OffensiveControlError,
    OTPCancelledError,
    OTPError,
    OTPExpiredError,
    OTPVerificationError,
    PipelineError,
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
from redcheck.models import OperatorRole, PluginCapability, RuntimeMode
