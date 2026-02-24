"""Tests for SAST scanner — pattern scan, bandit integration, dependency scan."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from redcheck.plugins.sast.sast_scanner import (
    SASTPlugin,
    _scan_dependency_files,
    _scan_file_patterns,
)


class TestScanFilePatterns:
    def test_detects_hardcoded_api_key(self, tmp_path: Path) -> None:
        f = tmp_path / "code.py"
        f.write_text('API_KEY = "ABCDEFGHIJKLMNOP1234"\n', encoding="utf-8")
        findings = _scan_file_patterns(f)
        assert any("api_key" in f.get("type", "") for f in findings)

    def test_detects_private_key(self, tmp_path: Path) -> None:
        f = tmp_path / "key.py"
        f.write_text("-----BEGIN RSA PRIVATE KEY-----\nfakedata\n", encoding="utf-8")
        findings = _scan_file_patterns(f)
        assert any("private_key" in f.get("type", "") for f in findings)

    def test_detects_eval(self, tmp_path: Path) -> None:
        f = tmp_path / "code.py"
        f.write_text("result = eval(user_input)\n", encoding="utf-8")
        findings = _scan_file_patterns(f)
        assert any("eval_exec" in f.get("type", "") for f in findings)

    def test_detects_insecure_http(self, tmp_path: Path) -> None:
        f = tmp_path / "code.py"
        f.write_text('url = "http://evil.example.com/api"\n', encoding="utf-8")
        findings = _scan_file_patterns(f)
        assert any("insecure_http" in f.get("type", "") for f in findings)

    def test_no_findings_clean_file(self, tmp_path: Path) -> None:
        f = tmp_path / "clean.py"
        f.write_text("x = 42\n", encoding="utf-8")
        findings = _scan_file_patterns(f)
        assert len(findings) == 0

    def test_unreadable_file(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            findings = _scan_file_patterns(f)
        assert findings == []


class TestScanDependencyFiles:
    def test_detects_unpinned_deps(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests\nflask\n", encoding="utf-8")
        findings = _scan_dependency_files([tmp_path])
        assert any("unpinned" in f.get("type", "") for f in findings)

    def test_skips_comments_and_flags(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("# comment\n-e .\nrequests==2.28\n", encoding="utf-8")
        findings = _scan_dependency_files([tmp_path])
        unpinned = [f for f in findings if "unpinned" in f.get("type", "")]
        assert len(unpinned) == 0

    def test_detects_insecure_index_url(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("-i http://pypi.example.com/simple\nrequests==2.28\n", encoding="utf-8")
        findings = _scan_dependency_files([tmp_path])
        assert any("insecure_url" in f.get("type", "") for f in findings)

    def test_file_read_error(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("content", encoding="utf-8")
        with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            _scan_dependency_files([req.parent])
        # Should not crash, just skip

    def test_direct_file_path(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("flask\n", encoding="utf-8")
        findings = _scan_dependency_files([req])
        assert any("unpinned" in f.get("type", "") for f in findings)

    def test_no_dep_files(self, tmp_path: Path) -> None:
        findings = _scan_dependency_files([tmp_path])
        assert findings == []


class TestSASTPluginExecute:
    def test_execute_with_patterns(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text('secret_key = "super_secret_value_1234567890"\n', encoding="utf-8")
        plugin = SASTPlugin()
        result = plugin.execute({"target_paths": [str(tmp_path)]})
        assert result.success
        assert len(result.findings) > 0

    def test_execute_directory_scan(self, tmp_path: Path) -> None:
        sub = tmp_path / "src"
        sub.mkdir()
        (sub / "app.py").write_text("x = 1\n", encoding="utf-8")
        plugin = SASTPlugin()
        result = plugin.execute({"paths": [str(tmp_path)]})
        assert result.success

    def test_execute_bandit_not_installed(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text("x = 1\n", encoding="utf-8")
        plugin = SASTPlugin()
        with patch(
            "redcheck.plugins.sast.sast_scanner._scan_bandit",
            return_value=[
                {"type": "sast_bandit", "target": "N/A", "detail": "bandit not installed",
                 "data": {"error": "missing_dependency"}}
            ],
        ):
            result = plugin.execute({"target_paths": [str(f)]})
        assert result.success

    def test_execute_bandit_exception(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text("x = 1\n", encoding="utf-8")
        plugin = SASTPlugin()
        with patch(
            "redcheck.plugins.sast.sast_scanner._scan_bandit",
            side_effect=RuntimeError("bandit crashed"),
        ):
            result = plugin.execute({"target_paths": [str(f)]})
        assert result.success
        assert any("Bandit" in e for e in result.errors)

    def test_dry_run(self) -> None:
        plugin = SASTPlugin()
        result = plugin.dry_run({"target_paths": ["."]})
        assert result.success
        assert result.metadata["mode"] == "dry-run"

    def test_dry_run_string_path(self) -> None:
        plugin = SASTPlugin()
        result = plugin.dry_run({"target_paths": "single_path"})
        assert result.success

    def test_deduplication(self, tmp_path: Path) -> None:
        f = tmp_path / "dupe.py"
        f.write_text('api_key = "AAAABBBBCCCCDDDDEEEE"\n', encoding="utf-8")
        plugin = SASTPlugin()
        result = plugin.execute({"target_paths": [str(f)]})
        # Findings should be deduplicated
        keys = [(f["type"], f["target"], f.get("data", {}).get("line", 0)) for f in result.findings]
        assert len(keys) == len(set(keys))
