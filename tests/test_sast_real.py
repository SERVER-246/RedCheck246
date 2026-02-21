"""Tests for SAST plugin — pattern scanning, bandit integration."""

import pytest

from redcheck.plugins.base_plugin import PluginRegistry


@pytest.fixture(autouse=True)
def register_sast():
    from redcheck.plugins.sast.sast_scanner import SASTPlugin  # noqa: F401

    return


def _ctx(scan_path=None):
    return {
        "authorized_targets": [{"host": "local", "ports": []}],
        "scan_path": str(scan_path) if scan_path else ".",
    }


class TestSASTPlugin:
    """SAST scanner tests."""

    def test_plugin_registered(self):
        assert PluginRegistry.get("sast-scanner") is not None

    def test_dry_run(self):
        plugin = PluginRegistry.get_instance("sast-scanner")
        result = plugin.dry_run(_ctx())
        assert result.success is True
        assert result.metadata["mode"] == "dry-run"

    def test_hardcoded_password_detection(self, tmp_path):
        """Custom pattern should detect hardcoded passwords."""
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text('password = "SuperSecret123"\n')

        from redcheck.plugins.sast.sast_scanner import _scan_file_patterns

        findings = _scan_file_patterns(vuln_file)
        assert len(findings) >= 1
        types = [f["type"] for f in findings]
        assert any("password" in t for t in types)

    def test_private_key_detection(self, tmp_path):
        vuln_file = tmp_path / "key.py"
        vuln_file.write_text('key = """-----BEGIN RSA PRIVATE KEY-----\nMIIE..."""\n')

        from redcheck.plugins.sast.sast_scanner import _scan_file_patterns

        findings = _scan_file_patterns(vuln_file)
        assert any("private_key" in f["type"] for f in findings)

    def test_clean_file_no_findings(self, tmp_path):
        clean = tmp_path / "clean.py"
        clean.write_text("import os\nprint(os.getcwd())\n")

        from redcheck.plugins.sast.sast_scanner import _scan_file_patterns

        findings = _scan_file_patterns(clean)
        assert len(findings) == 0

    def test_dependency_unpinned_detection(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests\nflask\nnumpy==1.24.0\n")

        from redcheck.plugins.sast.sast_scanner import _scan_dependency_files

        findings = _scan_dependency_files([req])
        # Should flag unpinned deps
        assert len(findings) >= 1

    def test_plugin_category(self):
        cls = PluginRegistry.get("sast-scanner")
        assert cls.category == "sast"

    def test_validate_context_empty(self):
        plugin = PluginRegistry.get_instance("sast-scanner")
        valid, msg = plugin.validate_context({})
        assert valid is False
