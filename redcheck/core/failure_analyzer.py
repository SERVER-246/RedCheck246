"""RedCheck246 — Failure Intelligence Layer.

Classifies plugin exceptions into structured diagnostics
(error_type, failure_stage, etc.) so every failure is explainable.
"""

from __future__ import annotations

import traceback
from typing import Any

import structlog

from redcheck.exceptions import (
    ActivationError,
    ConfigurationError,
    ContextValidationError,
    IsolationError,
    NetworkError,
    OffensiveControlError,
    PluginNotFoundError,
    PolicyDeniedException,
    RoEValidationError,
    ScanTimeoutError,
)
from redcheck.plugins.base_plugin import PluginResult

log = structlog.get_logger(__name__)

# Maps exception types → (error_type, failure_stage)
_EXCEPTION_MAP: dict[type, tuple[str, str]] = {
    PluginNotFoundError: ("plugin_not_found", "init"),
    ContextValidationError: ("config_missing", "init"),
    ConfigurationError: ("config_missing", "init"),
    RoEValidationError: ("roe_validation_error", "pre_execution"),
    ActivationError: ("config_missing", "init"),
    PolicyDeniedException: ("policy_denied", "pre_execution"),
    OffensiveControlError: ("policy_denied", "pre_execution"),
    IsolationError: ("isolation_required", "init"),
    ScanTimeoutError: ("timeout", "execution"),
    NetworkError: ("network_error", "execution"),
}


def classify_exception(exc: BaseException) -> tuple[str, str]:
    """Return (error_type, failure_stage) for an exception.

    Walks the MRO to find the most specific match in the exception map.
    Falls back to ``("execution_error", "execution")`` for unknown types.
    """
    for cls in type(exc).__mro__:
        if cls in _EXCEPTION_MAP:
            return _EXCEPTION_MAP[cls]
    return ("execution_error", "execution")


def analyze_failure(
    plugin_name: str,
    exc: BaseException,
    *,
    context: dict[str, Any] | None = None,
) -> PluginResult:
    """Produce a fully-structured PluginResult from a failed plugin execution.

    This is the single entry-point called by the orchestrator's exception
    handler.  It replaces the old bare-string error pattern.
    """
    error_type, failure_stage = classify_exception(exc)
    error_message = f"Plugin execution error: {exc}"
    tb_lines = traceback.format_exception(type(exc), exc, exc.__traceback__)

    # Build possible_causes heuristic
    possible_causes: list[str] = []
    if error_type == "dependency_missing":
        possible_causes.append("Plugin not installed or not registered in PluginRegistry")
    elif error_type == "config_missing":
        possible_causes.append("Missing or invalid configuration / engagement context")
    elif error_type == "timeout":
        possible_causes.append("Plugin exceeded timeout_seconds threshold")
        possible_causes.append("Target may be unresponsive or rate-limited")
    elif error_type == "network_error":
        possible_causes.append("Target unreachable or DNS resolution failed")
    elif error_type == "policy_denied":
        possible_causes.append("Plugin not in allowed_tests or capability not allowed")
    else:
        possible_causes.append("Unhandled exception during plugin execution")

    # Build next_steps
    next_steps: list[str] = []
    if error_type in ("dependency_missing", "config_missing"):
        next_steps.append("Check engagement configuration and plugin registry")
    elif error_type == "timeout":
        next_steps.append("Increase timeout_seconds or investigate target responsiveness")
    elif error_type == "network_error":
        next_steps.append("Verify target reachability and DNS resolution")
    else:
        next_steps.append("Review stack trace and plugin source for bugs")

    meta: dict[str, Any] = {
        "error_type": error_type,
        "failure_stage": failure_stage,
        "possible_causes": possible_causes,
        "next_steps": next_steps,
        "exception_class": type(exc).__name__,
        "traceback_summary": tb_lines[-1].strip() if tb_lines else "",
    }
    if context:
        meta.update(context)

    result = PluginResult(
        plugin_name=plugin_name,
        success=False,
        error_type=error_type,
        error_message=error_message,
        failure_stage=failure_stage,
        errors=[error_message],
        metadata=meta,
    )

    log.warning(
        "failure_analyzed",
        plugin=plugin_name,
        error_type=error_type,
        failure_stage=failure_stage,
        exception_class=type(exc).__name__,
    )

    return result
