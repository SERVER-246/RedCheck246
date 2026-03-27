"""Tests for redcheck.core.enrichment — cover lines 220-255."""

from __future__ import annotations

from unittest.mock import MagicMock

from redcheck.core.enrichment import enrich_finding, enrich_plugin_result


class TestEnrichFinding:
    """Cover enrich_finding with known/unknown finding types."""

    def test_known_type_enriches_all_fields(self):
        finding = MagicMock()
        finding.finding_type = "sql_injection"
        finding.metadata = {}
        assert enrich_finding(finding) is True
        assert finding.metadata["cwe_id"] == "CWE-89"
        assert finding.metadata["cvss_score"] == 9.8
        assert "parameterized" in finding.metadata["remediation"]
        assert finding.metadata["mitre_technique"] == "T1190"

    def test_unknown_type_returns_false(self):
        finding = MagicMock()
        finding.finding_type = "nonexistent_type_xyz"
        finding.metadata = {}
        assert enrich_finding(finding) is False
        assert finding.metadata == {}

    def test_empty_finding_type_returns_false(self):
        finding = MagicMock()
        finding.finding_type = ""
        finding.metadata = {}
        assert enrich_finding(finding) is False

    def test_none_finding_type_returns_false(self):
        finding = MagicMock()
        finding.finding_type = None
        finding.metadata = {}
        assert enrich_finding(finding) is False

    def test_already_enriched_fields_not_overwritten(self):
        finding = MagicMock()
        finding.finding_type = "xss"
        finding.metadata = {
            "cwe_id": "CWE-CUSTOM",
            "cvss_score": 1.0,
            "remediation": "already set",
            "mitre_technique": "T0000",
        }
        assert enrich_finding(finding) is False

    def test_partial_enrichment(self):
        finding = MagicMock()
        finding.finding_type = "open_port"
        finding.metadata = {"cwe_id": "CWE-EXISTING"}  # already has cwe
        assert enrich_finding(finding) is True
        # cwe_id should NOT be overwritten
        assert finding.metadata["cwe_id"] == "CWE-EXISTING"
        # others should be enriched
        assert finding.metadata["cvss_score"] == 3.1

    def test_missing_header_type(self):
        finding = MagicMock()
        finding.finding_type = "missing_header"
        finding.metadata = {}
        assert enrich_finding(finding) is True
        assert finding.metadata["cwe_id"] == "CWE-693"

    def test_finding_without_metadata_attr(self):
        finding = MagicMock(spec=[])
        finding.finding_type = "xss"
        # no metadata attribute
        result = enrich_finding(finding)
        # should still work using empty dict fallback
        assert isinstance(result, bool)

    def test_multiple_enrichment_db_types(self):
        """Spot-check several enrichment DB entries."""
        for ftype in [
            "hardcoded_secret",
            "weak_tls",
            "breached_credential",
            "vulnerable_dependency",
        ]:
            finding = MagicMock()
            finding.finding_type = ftype
            finding.metadata = {}
            assert enrich_finding(finding) is True
            assert "cwe_id" in finding.metadata


class TestEnrichPluginResult:
    """Cover enrich_plugin_result."""

    def test_enriches_multiple_findings(self):
        f1 = MagicMock()
        f1.finding_type = "sql_injection"
        f1.metadata = {}

        f2 = MagicMock()
        f2.finding_type = "xss"
        f2.metadata = {}

        result = MagicMock()
        result.findings = [f1, f2]
        result.plugin_name = "test-plugin"

        count = enrich_plugin_result(result)
        assert count == 2

    def test_no_enrichable_findings(self):
        f1 = MagicMock()
        f1.finding_type = "unknown_nonsense"
        f1.metadata = {}

        result = MagicMock()
        result.findings = [f1]
        result.plugin_name = "p"

        count = enrich_plugin_result(result)
        assert count == 0

    def test_empty_findings(self):
        result = MagicMock()
        result.findings = []
        result.plugin_name = "p"
        assert enrich_plugin_result(result) == 0

    def test_mixed_findings(self):
        enrichable = MagicMock()
        enrichable.finding_type = "open_port"
        enrichable.metadata = {}

        not_enrichable = MagicMock()
        not_enrichable.finding_type = "some_weird_type"
        not_enrichable.metadata = {}

        result = MagicMock()
        result.findings = [enrichable, not_enrichable]
        result.plugin_name = "scanner"

        count = enrich_plugin_result(result)
        assert count == 1
