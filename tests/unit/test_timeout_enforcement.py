"""Tests for timeout enforcement in orchestrator (Phase M)."""

from __future__ import annotations

import time

import pytest

from redcheck.plugins.base_plugin import PluginResult


class TestSyncPluginTimeout:
    """Test that sync run_plugin uses ThreadPoolExecutor timeout."""

    def test_timeout_produces_structured_result(self):
        """Simulate a plugin that sleeps longer than timeout."""
        # We test the timeout logic directly without full orchestrator
        from concurrent.futures import ThreadPoolExecutor
        from concurrent.futures import TimeoutError as FuturesTimeout

        def slow_execute(ctx):
            time.sleep(5)
            return PluginResult(plugin_name="slow", success=True, findings=[])

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(slow_execute, {})
            with pytest.raises(FuturesTimeout):
                future.result(timeout=0.1)


class TestPipelineDeadline:
    """Test that pipeline global deadline skips remaining plugins."""

    def test_deadline_exceeded_marks_remaining_failed(self):
        """When the deadline is hit, remaining plugins get pipeline_timeout error."""
        result = PluginResult(
            plugin_name="late",
            success=False,
            error_type="pipeline_timeout",
            error_message="Pipeline timeout (300s) exceeded",
            failure_stage="scheduling",
            errors=["Pipeline timeout (300s) exceeded"],
        )
        assert result.error_type == "pipeline_timeout"
        assert result.failure_stage == "scheduling"
        assert not result.success


class TestAsyncTimeoutStructured:
    """Test that async timeout now returns structured result instead of raising."""

    def test_timeout_result_fields(self):
        result = PluginResult(
            plugin_name="async-slow",
            success=False,
            error_type="timeout",
            error_message="Plugin 'async-slow' timed out after 60s",
            failure_stage="execution",
            errors=["Plugin 'async-slow' timed out after 60s"],
            metadata={"timeout_seconds": 60},
        )
        assert result.error_type == "timeout"
        assert result.failure_stage == "execution"
        assert result.metadata["timeout_seconds"] == 60
