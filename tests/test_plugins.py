"""Tests for PluginRegistry and BasePlugin system."""

import asyncio

import pytest

from redcheck.models import PluginCapability
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


# ---------------------------------------------------------------------------
# Phase 1: BasePlugin extensions
# ---------------------------------------------------------------------------


class TestBasePluginExtensions:
    """Phase 1 new class attributes and aexecute()."""

    def test_default_required_controls_empty(self):
        class DefaultPlugin(BasePlugin):
            name = "default-ctrl"
            version = "1.0.0"

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        p = DefaultPlugin()
        assert p.required_controls == []

    def test_default_timeout(self):
        class TimeoutPlugin(BasePlugin):
            name = "timeout-plug"
            version = "1.0.0"

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        p = TimeoutPlugin()
        assert p.timeout_seconds == 300

    def test_default_rate_limit(self):
        class RatePlugin(BasePlugin):
            name = "rate-plug"
            version = "1.0.0"

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        p = RatePlugin()
        assert p.rate_limit_rps == 10

    def test_default_mitre_techniques(self):
        class MitrePlugin(BasePlugin):
            name = "mitre-plug"
            version = "1.0.0"

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        p = MitrePlugin()
        assert p.mitre_techniques == []

    def test_default_requires_isolation(self):
        class IsoPlugin(BasePlugin):
            name = "iso-plug"
            version = "1.0.0"

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        p = IsoPlugin()
        assert p.requires_isolation is False

    def test_custom_extensions(self):
        class CustomPlugin(BasePlugin):
            name = "custom-ext"
            version = "1.0.0"
            capability = PluginCapability.ACTIVE
            required_controls = ["allow_auth_testing"]
            timeout_seconds = 120
            rate_limit_rps = 20
            mitre_techniques = ["T1046"]
            requires_isolation = True

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        p = CustomPlugin()
        assert p.required_controls == ["allow_auth_testing"]
        assert p.timeout_seconds == 120
        assert p.rate_limit_rps == 20
        assert p.mitre_techniques == ["T1046"]
        assert p.requires_isolation is True

    @pytest.mark.asyncio
    async def test_aexecute_default_delegates_to_sync(self):
        class SyncPlugin(BasePlugin):
            name = "sync-only"
            version = "1.0.0"

            def execute(self, context):
                return PluginResult(
                    plugin_name=self.name,
                    success=True,
                    metadata={"from": "sync"},
                )

        p = SyncPlugin()
        result = await p.aexecute({"test": True})
        assert result.success is True
        assert result.metadata["from"] == "sync"

    @pytest.mark.asyncio
    async def test_aexecute_override(self):
        class AsyncPlugin(BasePlugin):
            name = "async-override"
            version = "1.0.0"

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True, metadata={"from": "sync"})

            async def aexecute(self, context):
                await asyncio.sleep(0.001)
                return PluginResult(
                    plugin_name=self.name,
                    success=True,
                    metadata={"from": "async"},
                )

        p = AsyncPlugin()
        result = await p.aexecute({})
        assert result.metadata["from"] == "async"

    def test_list_plugins_includes_new_fields(self):
        class FullPlugin(BasePlugin):
            name = "full-info"
            version = "2.0.0"
            capability = PluginCapability.ACTIVE

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        plugins = PluginRegistry.list_plugins()
        p = next(info for info in plugins if info["name"] == "full-info")
        assert p["capability"] == "active"
