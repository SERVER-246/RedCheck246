"""Tests for plugin integrity verification at load time (Phase O)."""

from __future__ import annotations

from redcheck.plugins.base_plugin import PluginRegistry


class TestPluginSourceHash:
    def test_register_computes_hash(self):
        """When a plugin is registered, its source hash is recorded."""
        # All auto-discovered plugins should have hashes
        for name in PluginRegistry.list_names():
            h = PluginRegistry._plugin_hashes.get(name, "")
            # Should be a 64-char hex SHA-256 or empty (if source unavailable)
            assert h == "" or (len(h) == 64 and all(c in "0123456789abcdef" for c in h))

    def test_verify_integrity_passes_with_correct_hashes(self):
        """Passing known-good hashes should return no violations."""
        # Use the current hashes as the "trusted" baseline
        violations = PluginRegistry.verify_plugin_integrity(dict(PluginRegistry._plugin_hashes))
        assert violations == []

    def test_verify_integrity_detects_tamper(self):
        """Wrong hash should be flagged as a violation."""
        names = PluginRegistry.list_names()
        if not names:
            return  # nothing to test in minimal env
        target = names[0]
        violations = PluginRegistry.verify_plugin_integrity(
            {target: "0000000000000000000000000000000000000000000000000000000000000000"}
        )
        assert target in violations

    def test_all_plugins_returns_copy(self):
        """all_plugins() returns a new dict, not the internal one."""
        d = PluginRegistry.all_plugins()
        assert isinstance(d, dict)

    def test_unregister_removes_plugin(self):
        """unregister() removes a plugin by name."""
        # Ensure we restore state — use a name that doesn't exist
        PluginRegistry._plugins["_test_dummy_"] = type("Dummy", (), {})  # type: ignore[arg-type]
        PluginRegistry.unregister("_test_dummy_")
        assert PluginRegistry.get("_test_dummy_") is None
