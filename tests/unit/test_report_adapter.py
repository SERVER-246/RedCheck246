"""Tests for redcheck.core.report_adapter — 0% → ~100% coverage."""

from __future__ import annotations

from redcheck.core.report_adapter import _dict_to_finding, plugin_result_to_scan_report
from redcheck.models import Finding, FindingSeverity


class TestDictToFinding:
    """Cover _dict_to_finding with various dict shapes."""

    def test_minimal_dict(self):
        f = _dict_to_finding({}, "test-plugin")
        assert f.finding_type == "unknown"
        assert f.target == "unknown"
        assert f.severity == FindingSeverity.INFO
        assert f.plugin == "test-plugin"

    def test_severity_from_data_nested(self):
        raw = {"data": {"severity": "HIGH"}, "type": "xss", "target": "t"}
        f = _dict_to_finding(raw, "p")
        assert f.severity == FindingSeverity.HIGH
        assert f.finding_type == "xss"

    def test_severity_from_top_level(self):
        raw = {"severity": "critical", "type": "sqli"}
        f = _dict_to_finding(raw, "p")
        assert f.severity == FindingSeverity.CRITICAL

    def test_severity_unknown_defaults_info(self):
        raw = {"severity": "banana"}
        f = _dict_to_finding(raw, "p")
        assert f.severity == FindingSeverity.INFO

    def test_data_fields_extracted(self):
        raw = {
            "type": "vuln",
            "target": "host",
            "detail": "d",
            "data": {
                "cwe_id": "CWE-79",
                "cvss_score": 6.1,
                "remediation": "fix it",
                "mitre_technique": "T1059",
            },
        }
        f = _dict_to_finding(raw, "scanner")
        assert f.cwe_id == "CWE-79"
        assert f.cvss_score == 6.1
        assert f.remediation == "fix it"
        assert f.mitre_technique == "T1059"

    def test_severity_medium_low(self):
        for sev, expected in [("MEDIUM", FindingSeverity.MEDIUM), ("LOW", FindingSeverity.LOW)]:
            raw = {"data": {"severity": sev}}
            f = _dict_to_finding(raw, "p")
            assert f.severity == expected


class TestPluginResultToScanReport:
    """Cover plugin_result_to_scan_report."""

    def test_empty_findings(self):
        report = plugin_result_to_scan_report(
            plugin_name="test",
            findings=[],
            metadata={"key": "val"},
            engagement_id="eng-001",
        )
        assert report.engagement_id == "eng-001"
        assert report.scanner == "test"
        assert len(report.findings) == 0
        assert report.summary["total_findings"] == 0
        assert report.metadata == {"key": "val"}

    def test_finding_objects_passed_through(self):
        f = Finding(
            finding_type="xss",
            target="t",
            severity=FindingSeverity.HIGH,
            detail="d",
        )
        report = plugin_result_to_scan_report(
            plugin_name="p",
            findings=[f],
            metadata={},
            engagement_id="e1",
            duration_ms=100,
        )
        assert len(report.findings) == 1
        assert report.findings[0] is f
        assert report.summary["duration_ms"] == 100

    def test_dict_findings_converted(self):
        raw = {"type": "sqli", "target": "host", "data": {"severity": "high"}}
        report = plugin_result_to_scan_report(
            plugin_name="scanner",
            findings=[raw],
            metadata={},
            engagement_id="e2",
        )
        assert len(report.findings) == 1
        assert report.findings[0].finding_type == "sqli"
        assert report.findings[0].severity == FindingSeverity.HIGH

    def test_mixed_findings(self):
        f = Finding(finding_type="a", target="t", severity=FindingSeverity.LOW, detail="d")
        raw = {"type": "b", "target": "t2", "data": {"severity": "critical"}}
        report = plugin_result_to_scan_report(
            plugin_name="p",
            findings=[f, raw],
            metadata={},
            engagement_id="e3",
        )
        assert len(report.findings) == 2

    def test_bad_dict_skipped(self):
        # A dict that would cause conversion failure (cvss_score out of range)
        bad = {"type": "x", "data": {"cvss_score": 999.0}}
        report = plugin_result_to_scan_report(
            plugin_name="p",
            findings=[bad],
            metadata={},
            engagement_id="e4",
        )
        # Conversion fails, finding is skipped
        assert len(report.findings) == 0
