"""Tests for redcheck.core.sandbox_executor (Phase M)."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="resource module is POSIX-only")

from redcheck.core.sandbox_executor import _serialisable_context, run_sandboxed
from redcheck.models import PluginCapability, PluginMetadata


@pytest.fixture
def metadata() -> PluginMetadata:
    return PluginMetadata(
        name="test-sandbox",
        capability=PluginCapability.PASSIVE,
        timeout_seconds=5,
        memory_limit_mb=256,
        requires_isolation=True,
    )


class TestSerialisableContext:
    def test_strips_private_keys(self):
        ctx = {"_runtime": {}, "target": "example.com"}
        safe = _serialisable_context(ctx)
        assert "_runtime" not in safe
        assert safe["target"] == "example.com"

    def test_converts_non_serialisable(self):
        ctx = {"obj": object()}
        safe = _serialisable_context(ctx)
        assert isinstance(safe["obj"], str)


class TestRunSandboxed:
    def test_timeout_returns_error(self, metadata: PluginMetadata):
        """Simulate subprocess timeout."""
        import subprocess

        with patch(
            "redcheck.core.sandbox_executor.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="python", timeout=5),
        ):
            result = run_sandboxed("test-sandbox", {}, metadata)
            assert result.success is False
            assert result.error_type == "sandbox_timeout"

    def test_crash_returns_error(self, metadata: PluginMetadata):
        """Simulate subprocess crash."""
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stderr = "Segfault"
        mock_proc.stdout = ""
        with patch(
            "redcheck.core.sandbox_executor.subprocess.run",
            return_value=mock_proc,
        ):
            result = run_sandboxed("test-sandbox", {}, metadata)
            assert result.success is False
            assert result.error_type == "sandbox_crash"

    def test_success_returns_result(self, metadata: PluginMetadata):
        """Simulate successful subprocess output."""
        output = json.dumps(
            {
                "plugin_name": "test-sandbox",
                "success": True,
                "findings": [],
            }
        )
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = output
        mock_proc.stderr = ""
        with patch(
            "redcheck.core.sandbox_executor.subprocess.run",
            return_value=mock_proc,
        ):
            result = run_sandboxed("test-sandbox", {}, metadata)
            assert result.success is True
            assert result.plugin_name == "test-sandbox"

    def test_bad_json_returns_parse_error(self, metadata: PluginMetadata):
        """Simulate garbled subprocess output."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "not json at all"
        mock_proc.stderr = ""
        with patch(
            "redcheck.core.sandbox_executor.subprocess.run",
            return_value=mock_proc,
        ):
            result = run_sandboxed("test-sandbox", {}, metadata)
            assert result.success is False
            assert result.error_type == "sandbox_parse_error"

    def test_os_error_returns_sandbox_error(self, metadata: PluginMetadata):
        """Simulate failed subprocess launch."""
        with patch(
            "redcheck.core.sandbox_executor.subprocess.run",
            side_effect=OSError("No such file"),
        ):
            result = run_sandboxed("test-sandbox", {}, metadata)
            assert result.success is False
            assert result.error_type == "sandbox_error"
