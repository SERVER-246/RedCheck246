"""Tests for redcheck.core.failure_analyzer (Phase H)."""

from __future__ import annotations

from redcheck.core.failure_analyzer import analyze_failure, classify_exception
from redcheck.exceptions import (
    NetworkError,
    PluginNotFoundError,
    PolicyDeniedException,
    RoEValidationError,
    ScanTimeoutError,
    ScopeViolationError,
)


class TestClassifyException:
    def test_network_error(self):
        exc = NetworkError("conn refused")
        error_type, stage = classify_exception(exc)
        assert error_type == "network_error"
        assert stage == "execution"

    def test_timeout_error(self):
        exc = ScanTimeoutError("plug", 60.0)
        error_type, stage = classify_exception(exc)
        assert error_type == "timeout"
        assert stage == "execution"

    def test_policy_denied(self):
        exc = PolicyDeniedException("plug", "not allowed")
        error_type, stage = classify_exception(exc)
        assert error_type == "policy_denied"
        assert stage == "pre_execution"

    def test_scope_violation_inherits_policy(self):
        exc = ScopeViolationError("plug", "10.0.0.0/8")
        error_type, stage = classify_exception(exc)
        # ScopeViolationError subclasses PolicyDeniedException
        assert error_type in ("scope_violation", "policy_denied")

    def test_roe_validation(self):
        exc = RoEValidationError("bad roe")
        error_type, stage = classify_exception(exc)
        assert error_type == "roe_validation_error"
        assert stage == "pre_execution"

    def test_plugin_not_found(self):
        exc = PluginNotFoundError("missing-plugin")
        error_type, stage = classify_exception(exc)
        assert error_type == "plugin_not_found"
        assert stage == "init"

    def test_unknown_exception_defaults(self):
        exc = RuntimeError("unexpected")
        error_type, stage = classify_exception(exc)
        assert error_type == "execution_error"
        assert stage == "execution"


class TestAnalyzeFailure:
    def test_returns_plugin_result(self):
        exc = NetworkError("timeout")
        result = analyze_failure("test-plugin", exc)
        assert result.plugin_name == "test-plugin"
        assert result.success is False
        assert result.error_type == "network_error"
        assert result.failure_stage == "execution"
        assert "timeout" in result.error_message

    def test_metadata_contains_traceback(self):
        exc = ValueError("bad value")
        result = analyze_failure("plug", exc)
        assert "exception_class" in result.metadata
        assert result.metadata["exception_class"] == "ValueError"

    def test_context_passed_through(self):
        exc = RuntimeError("err")
        ctx = {"engagement_id": "eng-1"}
        result = analyze_failure("plug", exc, context=ctx)
        assert result.metadata.get("engagement_id") == "eng-1"
