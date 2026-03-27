"""Tests for redcheck.plugins.base_plugin — cover capture_evidence, validate_context, suggest."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from redcheck.models import PluginResult
from redcheck.plugins.base_plugin import BasePlugin, PluginRegistry


class _TestPlugin(BasePlugin):
    name = "test-base-coverage"
    version = "0.1.0"
    requires_authorization = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(plugin_name=self.name, success=True)


class TestCaptureEvidence:
    def test_no_store_returns_none(self):
        plugin = _TestPlugin()
        result = plugin.capture_evidence({}, b"data", "test_type")
        assert result is None

    def test_with_store(self):
        plugin = _TestPlugin()
        store = MagicMock()
        store.store.return_value = "evidence-id"
        result = plugin.capture_evidence(
            {"evidence_store": store},
            b"data",
            "test_type",
            finding_ref="f-1",
        )
        assert result == "evidence-id"
        store.store.assert_called_once_with(
            b"data",
            "test_type",
            finding_ref="f-1",
            plugin_name="test-base-coverage",
        )


class TestValidateContext:
    def test_empty_context(self):
        plugin = _TestPlugin()
        ok, msg = plugin.validate_context({})
        assert ok is False
        assert "Empty" in msg

    def test_valid_context(self):
        plugin = _TestPlugin()
        ok, msg = plugin.validate_context({"targets": ["example.com"]})
        assert ok is True


class TestDryRun:
    def test_dry_run(self):
        plugin = _TestPlugin()
        result = plugin.dry_run({"targets": ["t"]})
        assert result.success is True
        assert result.metadata.get("mode") == "dry-run"


class TestHealthCheck:
    def test_default_healthy(self):
        plugin = _TestPlugin()
        healthy, msg = plugin.health_check()
        assert healthy is True
        assert msg == "ok"


class TestRepr:
    def test_repr_no_auth(self):
        plugin = _TestPlugin()
        r = repr(plugin)
        assert "test-base-coverage" in r
        assert "NO-AUTH" in r

    def test_repr_auth_required(self):
        class _AuthPlugin(BasePlugin):
            name = "test-auth-repr"
            version = "0.1.0"
            requires_authorization = True

            def execute(self, context: dict[str, Any]) -> PluginResult:
                return PluginResult(plugin_name=self.name, success=True)

        plugin = _AuthPlugin()
        r = repr(plugin)
        assert "AUTH-REQUIRED" in r


class TestPluginRegistrySuggest:
    def test_suggest_close_match(self):
        # "test-base-coverage" is registered via __init_subclass__
        suggestions = PluginRegistry.suggest("test-base-coverag")
        assert "test-base-coverage" in suggestions

    def test_suggest_no_match(self):
        suggestions = PluginRegistry.suggest("zzzzzzzzzzzzz")
        assert suggestions == []
