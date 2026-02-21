"""Tests for PluginRegistry and BasePlugin system."""

import pytest

from redcheck.plugins.base_plugin import BasePlugin, PluginRegistry, PluginResult


@pytest.fixture(autouse=True)
def clean_registry():
    """Clean registry before and after each test."""
    PluginRegistry.clear()
    yield
    PluginRegistry.clear()


class TestPluginRegistry:
    """Plugin registration and lookup tests."""

    def test_plugin_auto_registers(self):
        class TestPlugin(BasePlugin):
            name = "test-auto-register"
            version = "1.0.0"

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        assert PluginRegistry.get("test-auto-register") is TestPlugin

    def test_list_plugins(self):
        class Alpha(BasePlugin):
            name = "alpha"
            version = "1.0.0"
            description = "Alpha plugin"
            category = "recon"

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        class Beta(BasePlugin):
            name = "beta"
            version = "2.0.0"
            description = "Beta plugin"
            category = "sast"

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        plugins = PluginRegistry.list_plugins()
        assert len(plugins) == 2
        names = [p["name"] for p in plugins]
        assert "alpha" in names
        assert "beta" in names

    def test_get_instance(self):
        class Gamma(BasePlugin):
            name = "gamma"
            version = "0.5.0"

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        instance = PluginRegistry.get_instance("gamma")
        assert instance is not None
        assert isinstance(instance, Gamma)

    def test_unknown_plugin_returns_none(self):
        assert PluginRegistry.get("nonexistent") is None
        assert PluginRegistry.get_instance("nonexistent") is None

    def test_dry_run_default(self):
        class DryTest(BasePlugin):
            name = "dry-test"
            version = "1.0.0"

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        plugin = DryTest()
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata.get("mode") == "dry-run"

    def test_plugin_result_to_dict(self):
        result = PluginResult(
            plugin_name="test",
            success=True,
            findings=[{"type": "info", "detail": "test"}],
        )
        d = result.to_dict()
        assert d["plugin_name"] == "test"
        assert d["success"] is True
        assert len(d["findings"]) == 1
