"""Tests for the CLI (Typer app) — init, list-plugins, verify-roe, status, version."""

import yaml
from typer.testing import CliRunner

from redcheck.cli import app

runner = CliRunner()


class TestInit:
    """CLI init command tests."""

    def test_init_creates_directory_structure(self, tmp_path):
        result = runner.invoke(app, ["init", "ENG-001", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        eng = tmp_path / "ENG-001"
        assert eng.is_dir()
        for sub in ("evidence", "reports", "logs", "scans"):
            assert (eng / sub).is_dir()
        assert (eng / "roe.yaml").exists()
        assert (eng / "engagement.yaml").exists()

    def test_init_existing_directory_fails(self, tmp_path):
        (tmp_path / "EXISTING").mkdir()
        result = runner.invoke(app, ["init", "EXISTING", "--dir", str(tmp_path)])
        assert result.exit_code != 0

    def test_init_roe_template_valid_yaml(self, tmp_path):
        runner.invoke(app, ["init", "TMPL", "--dir", str(tmp_path)])
        roe = yaml.safe_load((tmp_path / "TMPL" / "roe.yaml").read_text())
        assert roe["engagement_id"] == "TMPL"
        assert "authorized_targets" in roe


class TestListPlugins:
    """CLI list-plugins command tests."""

    def test_list_plugins_shows_all(self):
        result = runner.invoke(app, ["list-plugins"])
        assert result.exit_code == 0
        # Check for plugin names (may be truncated in Rich table)
        for name in ("passive-recon", "sast-scanner", "dast-scanner"):
            assert name in result.output

    def test_list_plugins_json_format(self):
        result = runner.invoke(app, ["--format", "json", "list-plugins"])
        assert result.exit_code == 0
        import json

        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 5


class TestVerifyRoE:
    """CLI verify-roe command tests."""

    def test_verify_valid_roe(self, valid_roe_file):
        result = runner.invoke(app, ["verify-roe", str(valid_roe_file)])
        assert result.exit_code == 0
        assert "TEST-001" in result.output

    def test_verify_invalid_file(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("engagement_id: INCOMPLETE")
        result = runner.invoke(app, ["verify-roe", str(p)])
        assert result.exit_code != 0

    def test_verify_nonexistent_file(self):
        result = runner.invoke(app, ["verify-roe", "/no/such/file.yaml"])
        assert result.exit_code != 0

    def test_verify_roe_json_format(self, valid_roe_file):
        result = runner.invoke(app, ["--format", "json", "verify-roe", str(valid_roe_file)])
        assert result.exit_code == 0
        # Output may contain Rich formatting; find the JSON object
        import json

        output = result.output.strip()
        # Find first { to start of JSON
        idx = output.find("{")
        assert idx >= 0, f"No JSON in output: {output}"
        data = json.loads(output[idx:])
        assert data["valid"] is True


class TestStatus:
    """CLI status command tests."""

    def test_status_shows_info(self):
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        # Should show version, activation state, plugins
        output_lower = result.output.lower()
        assert "policy-gated" in output_lower or "version" in output_lower or "v0." in result.output


class TestVersion:
    """CLI version flag tests."""

    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "RedCheck246" in result.output

    def test_help_flag(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "policy-gated" in result.output.lower() or "redcheck" in result.output.lower()
