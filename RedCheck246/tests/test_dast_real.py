"""Tests for DAST plugin — mocked HTTP responses."""

import pytest

from redcheck.plugins.base_plugin import PluginRegistry


@pytest.fixture(autouse=True)
def register_dast():
    from redcheck.plugins.dast.dast_scanner import DASTPlugin  # noqa: F401

    return


def _ctx(hosts=None):
    return {
        "authorized_targets": [
            {"host": h, "ports": [443], "protocols": ["tcp"]} for h in (hosts or ["target.local"])
        ],
    }


class TestDASTPlugin:
    """DAST scanner tests."""

    def test_plugin_registered(self):
        assert PluginRegistry.get("dast-scanner") is not None

    def test_dry_run(self):
        plugin = PluginRegistry.get_instance("dast-scanner")
        result = plugin.dry_run(_ctx())
        assert result.success is True
        assert result.metadata["mode"] == "dry-run"

    def test_execute_returns_result(self):
        """Execute with no real server — should still return a result."""
        plugin = PluginRegistry.get_instance("dast-scanner")
        result = plugin.execute(_ctx())
        assert result.plugin_name == "dast-scanner"

    def test_plugin_requires_authorization(self):
        cls = PluginRegistry.get("dast-scanner")
        assert cls.requires_authorization is True

    def test_plugin_category(self):
        cls = PluginRegistry.get("dast-scanner")
        assert cls.category == "dast"

    def test_empty_targets(self):
        plugin = PluginRegistry.get_instance("dast-scanner")
        result = plugin.execute({"authorized_targets": []})
        assert result.success is True

    def test_validate_context_empty(self):
        plugin = PluginRegistry.get_instance("dast-scanner")
        valid, msg = plugin.validate_context({})
        assert valid is False

    def test_multiple_targets(self):
        plugin = PluginRegistry.get_instance("dast-scanner")
        result = plugin.execute(_ctx(["host1.local", "host2.local"]))
        assert result.success is True

    def test_security_headers_async_function(self):
        """Verify the async check_security_headers function exists."""
        import asyncio

        from redcheck.plugins.dast.dast_scanner import check_security_headers

        assert asyncio.iscoroutinefunction(check_security_headers)

    def test_health_check(self):
        plugin = PluginRegistry.get_instance("dast-scanner")
        healthy, msg = plugin.health_check()
        assert healthy is True
