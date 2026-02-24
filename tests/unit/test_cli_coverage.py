"""Comprehensive CLI tests — covering all commands for coverage improvement."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import typer.testing
import yaml

from redcheck.cli import app

runner = typer.testing.CliRunner()


class TestVersion:
    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "RedCheck246" in result.output

    def test_short_version_flag(self) -> None:
        result = runner.invoke(app, ["-V"])
        assert result.exit_code == 0


class TestInit:
    def test_init_creates_directories(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["init", "test-eng", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "initialized" in result.output.lower() or "✓" in result.output
        base = tmp_path / "test-eng"
        assert base.exists()
        assert (base / "evidence").is_dir()
        assert (base / "reports").is_dir()
        assert (base / "logs").is_dir()
        assert (base / "scans").is_dir()
        assert (base / "roe.yaml").exists()
        assert (base / "engagement.yaml").exists()

    def test_init_already_exists(self, tmp_path: Path) -> None:
        (tmp_path / "exists").mkdir()
        result = runner.invoke(app, ["init", "exists", "--dir", str(tmp_path)])
        assert result.exit_code != 0


class TestListPlugins:
    def test_list_plugins_text(self) -> None:
        result = runner.invoke(app, ["list-plugins"])
        assert result.exit_code == 0

    def test_list_plugins_json(self) -> None:
        result = runner.invoke(app, ["--format", "json", "list-plugins"])
        assert result.exit_code == 0

    @patch("redcheck.cli.PluginRegistry.list_plugins", return_value=[])
    def test_list_plugins_empty(self, mock_list: MagicMock) -> None:
        result = runner.invoke(app, ["list-plugins"])
        assert result.exit_code != 0


class TestVerifyRoe:
    def test_verify_roe_valid(self, tmp_path: Path) -> None:
        roe = {
            "engagement_id": "E1",
            "authorizer": "admin",
            "authorized_targets": [{"host": "example.com"}],
            "allowed_tests": ["passive-recon"],
            "start_time_utc": "2020-01-01T00:00:00Z",
            "end_time_utc": "2099-12-31T23:59:59Z",
            "signature": "dummy",
        }
        roe_path = tmp_path / "roe.yaml"
        roe_path.write_text(yaml.dump(roe), encoding="utf-8")
        result = runner.invoke(app, ["verify-roe", str(roe_path)])
        # Valid RoE → exit 0 with ✓
        assert result.exit_code == 0

    def test_verify_roe_invalid(self, tmp_path: Path) -> None:
        roe_path = tmp_path / "roe.yaml"
        roe_path.write_text("not: valid\n", encoding="utf-8")
        result = runner.invoke(app, ["verify-roe", str(roe_path)])
        assert result.exit_code != 0

    def test_verify_roe_json_format(self, tmp_path: Path) -> None:
        roe = {
            "engagement_id": "E1",
            "authorizer": "admin",
            "authorized_targets": [{"host": "example.com"}],
            "allowed_tests": ["passive-recon"],
            "start_time_utc": "2020-01-01T00:00:00Z",
            "end_time_utc": "2099-12-31T23:59:59Z",
            "signature": "dummy",
        }
        roe_path = tmp_path / "roe.yaml"
        roe_path.write_text(yaml.dump(roe), encoding="utf-8")
        result = runner.invoke(app, ["--format", "json", "verify-roe", str(roe_path)])
        assert result.exit_code == 0

    def test_verify_roe_missing_file(self) -> None:
        result = runner.invoke(app, ["verify-roe", "/nonexistent/roe.yaml"])
        assert result.exit_code != 0


class TestActivate:
    def test_activate_show_status(self) -> None:
        result = runner.invoke(app, ["activate"])
        assert result.exit_code == 0

    def test_activate_set_mismatch(self) -> None:
        result = runner.invoke(
            app, ["activate", "--set"], input="code1\ncode2\n"
        )
        assert result.exit_code != 0

    def test_activate_set_success(self) -> None:
        with patch("redcheck.cli.ActivationEngine") as mock_cls:
            engine = MagicMock()
            engine.set_code.return_value = (True, "Code set successfully")
            mock_cls.return_value = engine
            result = runner.invoke(
                app, ["activate", "--set"], input="secret\nsecret\n"
            )
            assert result.exit_code == 0

    def test_activate_verify_success(self) -> None:
        with patch("redcheck.cli.ActivationEngine") as mock_cls:
            engine = MagicMock()
            engine.verify_code.return_value = True
            mock_cls.return_value = engine
            result = runner.invoke(
                app, ["activate", "--verify"], input="secret\n"
            )
            assert result.exit_code == 0

    def test_activate_verify_failure(self) -> None:
        with patch("redcheck.cli.ActivationEngine") as mock_cls:
            engine = MagicMock()
            engine.verify_code.return_value = False
            mock_cls.return_value = engine
            result = runner.invoke(
                app, ["activate", "--verify"], input="wrong\n"
            )
            assert result.exit_code != 0


class TestStatus:
    def test_status_text(self) -> None:
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0

    def test_status_json(self) -> None:
        result = runner.invoke(app, ["--format", "json", "status"])
        assert result.exit_code == 0


class TestRecon:
    def test_recon_dry_run(self, tmp_path: Path) -> None:
        roe = {
            "engagement_id": "E1",
            "authorizer": "admin",
            "authorized_targets": [{"host": "example.com"}],
            "allowed_tests": ["passive-recon"],
            "start_time_utc": "2020-01-01T00:00:00Z",
            "end_time_utc": "2099-12-31T23:59:59Z",
            "signature": "dummy",
        }
        roe_path = tmp_path / "roe.yaml"
        roe_path.write_text(yaml.dump(roe), encoding="utf-8")
        result = runner.invoke(
            app, ["recon", "--roe", str(roe_path), "--dry-run"]
        )
        # Should succeed in dry-run mode
        assert result.exit_code == 0

    def test_recon_policy_denied(self, tmp_path: Path) -> None:
        roe_path = tmp_path / "roe.yaml"
        roe_path.write_text("bad: data\n", encoding="utf-8")
        result = runner.invoke(
            app, ["recon", "--roe", str(roe_path), "--dry-run"]
        )
        assert result.exit_code != 0


class TestRunCmd:
    def test_run_dry_run(self, tmp_path: Path) -> None:
        roe = {
            "engagement_id": "E1",
            "authorizer": "admin",
            "authorized_targets": [{"host": "example.com"}],
            "allowed_tests": ["passive-recon", "sast-scanner"],
            "start_time_utc": "2020-01-01T00:00:00Z",
            "end_time_utc": "2099-12-31T23:59:59Z",
            "signature": "dummy",
        }
        roe_path = tmp_path / "roe.yaml"
        roe_path.write_text(yaml.dump(roe), encoding="utf-8")
        result = runner.invoke(
            app, ["run", "sast-scanner", "--roe", str(roe_path), "--dry-run"]
        )
        assert result.exit_code == 0

    def test_run_no_activation(self, tmp_path: Path) -> None:
        roe = {
            "engagement_id": "E1",
            "authorizer": "admin",
            "authorized_targets": [{"host": "example.com"}],
            "allowed_tests": ["passive-recon"],
            "start_time_utc": "2020-01-01T00:00:00Z",
            "end_time_utc": "2099-12-31T23:59:59Z",
            "signature": "dummy",
        }
        roe_path = tmp_path / "roe.yaml"
        roe_path.write_text(yaml.dump(roe), encoding="utf-8")
        with patch("redcheck.cli.ActivationEngine") as mock_cls:
            engine = MagicMock()
            engine.is_configured = False
            mock_cls.return_value = engine
            result = runner.invoke(
                app, ["run", "passive-recon", "--roe", str(roe_path)]
            )
        assert result.exit_code != 0


class TestReport:
    def test_report_valid_dir(self, tmp_path: Path) -> None:
        reports = tmp_path / "reports"
        reports.mkdir()
        (reports / "scan1.json").write_text("{}", encoding="utf-8")
        result = runner.invoke(app, ["report", str(tmp_path)])
        assert result.exit_code == 0
        assert "scan1.json" in result.output

    def test_report_json_format(self, tmp_path: Path) -> None:
        reports = tmp_path / "reports"
        reports.mkdir()
        result = runner.invoke(
            app, ["report", str(tmp_path), "--output", "json"]
        )
        assert result.exit_code == 0

    def test_report_missing_dir(self) -> None:
        result = runner.invoke(app, ["report", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_report_no_reports_dir(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["report", str(tmp_path)])
        assert result.exit_code != 0


class TestTenant:
    def test_tenant_show_text(self) -> None:
        result = runner.invoke(app, ["tenant", "--show"])
        assert result.exit_code == 0

    def test_tenant_show_json(self) -> None:
        result = runner.invoke(app, ["--format", "json", "tenant", "--show"])
        assert result.exit_code == 0


class TestResearch:
    def test_research_dry_run(self, tmp_path: Path) -> None:
        roe = {
            "engagement_id": "E1",
            "authorizer": "admin",
            "authorized_targets": [{"host": "example.com"}],
            "allowed_tests": ["passive-recon"],
            "start_time_utc": "2020-01-01T00:00:00Z",
            "end_time_utc": "2099-12-31T23:59:59Z",
            "signature": "dummy",
        }
        roe_path = tmp_path / "roe.yaml"
        roe_path.write_text(yaml.dump(roe), encoding="utf-8")
        result = runner.invoke(
            app,
            ["research", "--roe", str(roe_path), "--plugin", "passive-recon"],
        )
        assert result.exit_code == 0

    def test_research_json_format(self, tmp_path: Path) -> None:
        roe = {
            "engagement_id": "E1",
            "authorizer": "admin",
            "authorized_targets": [{"host": "example.com"}],
            "allowed_tests": ["passive-recon"],
            "start_time_utc": "2020-01-01T00:00:00Z",
            "end_time_utc": "2099-12-31T23:59:59Z",
            "signature": "dummy",
        }
        roe_path = tmp_path / "roe.yaml"
        roe_path.write_text(yaml.dump(roe), encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "--format", "json",
                "research",
                "--roe", str(roe_path),
                "--plugin", "passive-recon",
            ],
        )
        assert result.exit_code == 0


class TestGlobalOptions:
    def test_verbose_flag(self) -> None:
        result = runner.invoke(app, ["--verbose", "status"])
        assert result.exit_code == 0

    def test_no_args(self) -> None:
        result = runner.invoke(app, [])
        # no_args_is_help=True shows help and exits
        assert result.exit_code in (0, 2)
