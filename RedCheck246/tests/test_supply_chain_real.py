"""Tests for supply chain plugin — parsing, OSV queries, typosquatting."""

from pathlib import Path

import pytest

from redcheck.plugins.base_plugin import PluginRegistry


@pytest.fixture(autouse=True)
def register_supply_chain():
    from redcheck.plugins.supply_chain.supply_chain_audit import SupplyChainPlugin  # noqa: F401

    return


def _ctx():
    return {
        "authorized_targets": [{"host": "local"}],
    }


class TestParsers:
    """Dependency file parser tests."""

    def test_parse_requirements_txt(self, tmp_path):
        from redcheck.plugins.supply_chain.parsers import parse_requirements_txt

        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\nflask>=2.0,<3.0\nnumpy\n# comment\n")
        deps = parse_requirements_txt(req)
        assert len(deps) >= 3
        names = [d["name"] for d in deps]
        assert "requests" in names
        assert "flask" in names
        assert "numpy" in names

    def test_parse_requirements_pinned_version(self, tmp_path):
        from redcheck.plugins.supply_chain.parsers import parse_requirements_txt

        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\n")
        deps = parse_requirements_txt(req)
        assert deps[0]["version"] == "2.28.0"

    def test_parse_requirements_empty(self, tmp_path):
        from redcheck.plugins.supply_chain.parsers import parse_requirements_txt

        req = tmp_path / "requirements.txt"
        req.write_text("")
        deps = parse_requirements_txt(req)
        assert len(deps) == 0

    def test_parse_nonexistent_file(self):
        from redcheck.plugins.supply_chain.parsers import parse_requirements_txt

        deps = parse_requirements_txt(Path("/nonexistent/requirements.txt"))
        assert len(deps) == 0

    def test_parse_package_json(self, tmp_path):
        from redcheck.plugins.supply_chain.parsers import parse_package_json

        pkg = tmp_path / "package.json"
        pkg.write_text(
            '{"dependencies":{"express":"^4.18.0"},"devDependencies":{"jest":"^29.0.0"}}'
        )
        deps = parse_package_json(pkg)
        assert len(deps) >= 2
        names = [d["name"] for d in deps]
        assert "express" in names


class TestSupplyChainPlugin:
    """Supply chain audit plugin tests."""

    def test_plugin_registered(self):
        assert PluginRegistry.get("supply-chain-audit") is not None

    def test_dry_run(self):
        plugin = PluginRegistry.get_instance("supply-chain-audit")
        result = plugin.dry_run(_ctx())
        assert result.success is True
        assert result.metadata["mode"] == "dry-run"

    def test_plugin_category(self):
        cls = PluginRegistry.get("supply-chain-audit")
        assert cls.category == "supply_chain"

    def test_execute_returns_result(self):
        """Execute with no real deps — still returns a result."""
        plugin = PluginRegistry.get_instance("supply-chain-audit")
        result = plugin.execute(_ctx())
        assert result.plugin_name == "supply-chain-audit"

    def test_health_check(self):
        plugin = PluginRegistry.get_instance("supply-chain-audit")
        healthy, msg = plugin.health_check()
        assert healthy is True

    def test_validate_context_empty(self):
        plugin = PluginRegistry.get_instance("supply-chain-audit")
        valid, msg = plugin.validate_context({})
        assert valid is False
