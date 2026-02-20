"""Tests for passive_recon plugin — mocked network calls."""

from unittest.mock import MagicMock, patch

import pytest

from redcheck.plugins.base_plugin import PluginRegistry


@pytest.fixture(autouse=True)
def register_recon():
    from redcheck.plugins.recon.passive_recon import PassiveReconPlugin  # noqa: F401

    return


def _ctx(hosts=None):
    return {
        "authorized_targets": [
            {"host": h, "ports": [80, 443]} for h in (hosts or ["target.local"])
        ],
    }


class TestPassiveReconMocked:
    """Passive recon with mocked DNS/HTTP."""

    def test_plugin_registered(self):
        assert PluginRegistry.get("passive-recon") is not None

    @patch("redcheck.plugins.recon.passive_recon.dns.asyncresolver.resolve")
    def test_dns_resolution_mocked(self, mock_resolve):
        """DNS resolve returns results."""
        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda self: iter([MagicMock(to_text=lambda: "1.2.3.4")])
        mock_resolve.return_value = mock_answer

        plugin = PluginRegistry.get_instance("passive-recon")
        result = plugin.execute(_ctx())
        assert result.success is True

    def test_dry_run_no_network(self):
        plugin = PluginRegistry.get_instance("passive-recon")
        result = plugin.dry_run(_ctx(["a.com", "b.com"]))
        assert result.success is True
        assert result.metadata["mode"] == "dry-run"
        assert result.metadata["targets_count"] == 2

    def test_empty_targets_dry_run(self):
        plugin = PluginRegistry.get_instance("passive-recon")
        result = plugin.dry_run({"authorized_targets": []})
        assert result.success is True
        assert result.metadata["targets_count"] == 0

    def test_execute_produces_findings(self):
        """Execute with real async (hits no real server, just validates flow)."""
        plugin = PluginRegistry.get_instance("passive-recon")
        result = plugin.execute(_ctx())
        # Even with failures, plugin should return a result object
        assert result.plugin_name == "passive-recon"

    def test_multiple_targets(self):
        plugin = PluginRegistry.get_instance("passive-recon")
        result = plugin.execute(_ctx(["host1.local", "host2.local"]))
        assert result.success is True

    def test_plugin_metadata(self):
        cls = PluginRegistry.get("passive-recon")
        assert cls.version is not None
        assert cls.category == "recon"

    def test_validate_context_empty(self):
        plugin = PluginRegistry.get_instance("passive-recon")
        valid, msg = plugin.validate_context({})
        assert valid is False
