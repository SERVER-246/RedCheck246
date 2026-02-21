"""Tests for passive recon plugin dry-run mode."""

import pytest

from redcheck.plugins.base_plugin import PluginRegistry


@pytest.fixture(autouse=True)
def register_plugins():
    """Import plugins to trigger registration."""
    from redcheck.plugins.recon.passive_recon import PassiveReconPlugin  # noqa: F401

    return


class TestPassiveReconDryRun:
    def test_dry_run_returns_success(self):
        plugin = PluginRegistry.get_instance("passive-recon")
        assert plugin is not None

        context = {
            "authorized_targets": [
                {"host": "test.example.com", "ports": [80, 443]},
                {"host": "api.example.com", "ports": [443]},
            ]
        }
        result = plugin.dry_run(context)
        assert result.success is True
        assert result.metadata["mode"] == "dry-run"
        assert result.metadata["targets_count"] == 2

    def test_execute_queues_findings(self):
        plugin = PluginRegistry.get_instance("passive-recon")
        context = {
            "authorized_targets": [
                {"host": "target.local"},
            ]
        }
        result = plugin.execute(context)
        assert result.success is True
        assert len(result.findings) >= 2  # DNS + WHOIS at minimum

    def test_empty_targets(self):
        plugin = PluginRegistry.get_instance("passive-recon")
        result = plugin.dry_run({"authorized_targets": []})
        assert result.success is True
        assert result.metadata["targets_count"] == 0
