"""Tests for plugin allowlist enforcement (Phase O)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from redcheck.plugins import enforce_plugin_allowlist
from redcheck.plugins.base_plugin import PluginRegistry


class TestEnforcePluginAllowlist:
    def test_none_allowlist_does_nothing(self):
        """When allowlist is None, no plugins are removed."""
        cfg = MagicMock()
        cfg.plugin_allowlist = None
        with patch("redcheck.config.get_config", return_value=cfg):
            # Should not raise or modify anything
            enforce_plugin_allowlist()

    def test_allowlist_removes_unlisted(self):
        """Plugins not on the allowlist are unregistered."""
        cfg = MagicMock()
        cfg.plugin_allowlist = ["allowed-plugin"]

        # Create a fake registry state
        fake_plugins = {"allowed-plugin": MagicMock(), "blocked-plugin": MagicMock()}

        with (
            patch("redcheck.config.get_config", return_value=cfg),
            patch.object(PluginRegistry, "all_plugins", return_value=fake_plugins),
            patch.object(PluginRegistry, "unregister") as mock_unreg,
        ):
            enforce_plugin_allowlist()
            mock_unreg.assert_called_once_with("blocked-plugin")

    def test_empty_allowlist_removes_all(self):
        """An empty list blocks everything."""
        cfg = MagicMock()
        cfg.plugin_allowlist = []

        fake_plugins = {"a": MagicMock(), "b": MagicMock()}

        with (
            patch("redcheck.config.get_config", return_value=cfg),
            patch.object(PluginRegistry, "all_plugins", return_value=fake_plugins),
            patch.object(PluginRegistry, "unregister") as mock_unreg,
        ):
            enforce_plugin_allowlist()
            assert mock_unreg.call_count == 2
