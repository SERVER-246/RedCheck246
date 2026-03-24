"""Tests for redcheck.plugins.exploit.cve_mapper — CVEMapper.

Coverage: version range matching, CVE lookup, plugin execution, dry run.
"""

from __future__ import annotations

from redcheck.models import PluginCapability
from redcheck.plugins.exploit.cve_mapper import (
    _CVE_DATABASE,
    CVEMapper,
    _version_in_range,
    lookup_cves,
)

# ---------------------------------------------------------------------------
# Version range matching
# ---------------------------------------------------------------------------


class TestVersionInRange:
    def test_in_range(self):
        assert _version_in_range("2.10.0", "2.0.0", "2.14.1")

    def test_at_min(self):
        assert _version_in_range("2.0.0", "2.0.0", "2.14.1")

    def test_at_max(self):
        assert _version_in_range("2.14.1", "2.0.0", "2.14.1")

    def test_below_min(self):
        assert not _version_in_range("1.9.0", "2.0.0", "2.14.1")

    def test_above_max(self):
        assert not _version_in_range("2.15.0", "2.0.0", "2.14.1")

    def test_simple_version(self):
        assert _version_in_range("5.6.0", "5.6.0", "5.6.1")

    def test_with_patch_suffix(self):
        assert _version_in_range("9.3p1", "0.0.0", "9.3p1")

    def test_single_digit(self):
        assert _version_in_range("5", "1", "10")


# ---------------------------------------------------------------------------
# CVE lookup
# ---------------------------------------------------------------------------


class TestLookupCVEs:
    def test_log4j_match(self):
        matches = lookup_cves("log4j", "2.10.0")
        assert len(matches) == 1
        assert matches[0]["cve_id"] == "CVE-2021-44228"

    def test_log4j_patched_no_match(self):
        matches = lookup_cves("log4j", "2.17.0")
        assert len(matches) == 0

    def test_xz_match(self):
        matches = lookup_cves("xz", "5.6.0")
        assert any(m["cve_id"] == "CVE-2024-3094" for m in matches)

    def test_unknown_service(self):
        matches = lookup_cves("unknown-service", "1.0.0")
        assert len(matches) == 0

    def test_case_insensitive(self):
        matches = lookup_cves("Log4j", "2.10.0")
        assert len(matches) == 1

    def test_custom_database(self):
        custom = [
            {
                "cve_id": "CVE-CUSTOM-001",
                "service": "myapp",
                "version_min": "1.0",
                "version_max": "2.0",
                "severity": "high",
                "cvss": 8.0,
                "description": "Custom vuln",
                "mitre": "T1234",
            }
        ]
        matches = lookup_cves("myapp", "1.5", database=custom)
        assert len(matches) == 1
        assert matches[0]["cve_id"] == "CVE-CUSTOM-001"

    def test_openssh_match(self):
        matches = lookup_cves("openssh", "9.2")
        assert any(m["cve_id"] == "CVE-2023-38408" for m in matches)


# ---------------------------------------------------------------------------
# CVEMapper plugin
# ---------------------------------------------------------------------------


class TestCVEMapperPlugin:
    def test_no_services(self):
        plugin = CVEMapper()
        result = plugin.execute({"discovered_services": []})
        assert result.success is False
        assert result.metadata.get("contract_status") == "PARTIAL"

    def test_no_services_key(self):
        plugin = CVEMapper()
        result = plugin.execute({})
        assert result.success is False
        assert result.metadata.get("contract_status") == "PARTIAL"

    def test_finds_cves(self):
        plugin = CVEMapper()
        result = plugin.execute(
            {
                "discovered_services": [
                    {"service": "log4j", "version": "2.10.0"},
                    {"service": "openssh", "version": "9.2"},
                ]
            }
        )
        assert result.success
        assert len(result.findings) >= 2
        cve_ids = [f["cve_id"] for f in result.findings]
        assert "CVE-2021-44228" in cve_ids

    def test_safe_version_no_findings(self):
        plugin = CVEMapper()
        result = plugin.execute(
            {
                "discovered_services": [
                    {"service": "log4j", "version": "2.17.0"},
                ]
            }
        )
        assert result.success
        assert len(result.findings) == 0

    def test_skips_empty_service_or_version(self):
        plugin = CVEMapper()
        result = plugin.execute(
            {
                "discovered_services": [
                    {"service": "", "version": "1.0"},
                    {"service": "test", "version": ""},
                ]
            }
        )
        assert result.success
        assert len(result.findings) == 0

    def test_metadata_counts(self):
        plugin = CVEMapper()
        result = plugin.execute(
            {
                "discovered_services": [
                    {"service": "log4j", "version": "2.10.0"},
                ]
            }
        )
        assert result.metadata["services_checked"] == 1
        assert result.metadata["cves_matched"] >= 1

    def test_dry_run(self):
        plugin = CVEMapper()
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata["mode"] == "dry-run"
        assert result.metadata["database_size"] == len(_CVE_DATABASE)

    def test_plugin_name(self):
        assert CVEMapper.name == "cve-mapper"

    def test_passive_capability(self):
        assert CVEMapper.capability == PluginCapability.PASSIVE
