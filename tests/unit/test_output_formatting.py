"""Tests for CLI output formatting — Rich tables, panels, scan results."""

from __future__ import annotations

from io import StringIO
from typing import Any
from unittest.mock import patch

from rich.console import Console
from rich.table import Table

from redcheck.output import (
    format_findings_table,
    format_plugin_list,
    format_scan_result,
    format_status,
    print_banner,
)


class TestFormatFindingsTable:
    def test_empty_findings(self) -> None:
        table = format_findings_table([])
        assert isinstance(table, Table)

    def test_findings_with_severities(self) -> None:
        findings: list[dict[str, Any]] = [
            {"severity": "critical", "finding_type": "vuln", "target": "host", "detail": "bad"},
            {"severity": "high", "finding_type": "issue", "target": "h2", "detail": "warn"},
            {"severity": "medium", "finding_type": "x", "target": "h3", "detail": "ok"},
            {"severity": "low", "finding_type": "y", "target": "h4", "detail": "fine"},
            {"severity": "info", "finding_type": "z", "target": "h5", "detail": "note"},
            {"severity": "unknown", "type": "other", "detail": "fallback"},
        ]
        table = format_findings_table(findings)
        assert isinstance(table, Table)
        assert table.row_count == 6

    def test_missing_fields_use_defaults(self) -> None:
        table = format_findings_table([{}])
        assert table.row_count == 1


class TestFormatPluginList:
    def test_plugin_table(self) -> None:
        plugins = [
            {
                "name": "scanner",
                "version": "1.0",
                "category": "recon",
                "capability": "passive",
                "requires_authorization": True,
                "description": "A scanner",
            },
            {
                "name": "fuzzer",
                "version": "2.0",
                "category": "fuzzing",
                "capability": "active",
                "requires_authorization": False,
                "description": "A fuzzer",
            },
            {
                "name": "exploit",
                "version": "0.1",
                "category": "exploit",
                "capability": "destructive",
                "requires_authorization": True,
                "description": "Exploit verifier",
            },
        ]
        table = format_plugin_list(plugins)
        assert isinstance(table, Table)
        assert table.row_count == 3


class TestFormatScanResult:
    def test_json_output(self) -> None:
        result = {"plugin_name": "test", "success": True, "findings": []}
        # Should not raise
        format_scan_result(result, fmt="json")

    def test_text_output_with_findings(self) -> None:
        result = {
            "plugin_name": "test",
            "success": True,
            "mode": "live",
            "duration_ms": 42.0,
            "findings": [
                {"severity": "high", "finding_type": "vuln", "target": "h", "detail": "d"},
            ],
            "errors": ["some error"],
        }
        format_scan_result(result, fmt="text")

    def test_text_output_no_findings(self) -> None:
        result = {"plugin_name": "test", "success": False, "findings": [], "errors": []}
        format_scan_result(result, fmt="text")

    def test_text_no_duration(self) -> None:
        result = {"plugin_name": "test", "success": True, "findings": []}
        format_scan_result(result, fmt="text")


class TestFormatStatus:
    def test_json_output(self) -> None:
        status = {"activation": "active", "plugins": 5}
        format_status(status, fmt="json")

    def test_text_output(self) -> None:
        status = {"activation": "active", "plugins": 5, "policy": "enabled"}
        format_status(status, fmt="text")


class TestPrintBanner:
    def test_print_banner(self) -> None:
        print_banner("0.3.0")
