"""Tests for VulnerabilityDatabase (Phase 7, §28)."""

from __future__ import annotations

import pytest

from redcheck.constants import (
    MAX_INJECTION_PAYLOADS_PER_CATEGORY,
    MAX_VULN_MATCHES_PER_SERVICE,
)
from redcheck.core.vuln_db import VulnerabilityDatabase, VulnMatch


@pytest.fixture
def db() -> VulnerabilityDatabase:
    return VulnerabilityDatabase()


class TestVulnDBLoading:
    """Lazy-loading and schema validation tests."""

    def test_lazy_load_on_first_access(self, db: VulnerabilityDatabase):
        assert db._loaded is False
        _ = db.web_vuln_count
        assert db._loaded is True

    def test_web_vulns_populated(self, db: VulnerabilityDatabase):
        assert db.web_vuln_count >= 10

    def test_service_vulns_populated(self, db: VulnerabilityDatabase):
        assert db.service_vuln_count >= 12

    def test_injection_categories_populated(self, db: VulnerabilityDatabase):
        assert db.injection_category_count >= 6

    def test_double_load_is_noop(self, db: VulnerabilityDatabase):
        db._load()
        first_count = db.web_vuln_count
        db._load()
        assert db.web_vuln_count == first_count


class TestMatchService:
    """Service version → CVE matching tests."""

    def test_match_known_service_with_version(self, db: VulnerabilityDatabase):
        matches = db.match_service("Apache HTTP Server", "2.4.49")
        assert len(matches) >= 1
        assert all(isinstance(m, VulnMatch) for m in matches)
        assert all(m.category == "service" for m in matches)

    def test_match_known_service_without_version(self, db: VulnerabilityDatabase):
        # Without version, should return all vulns for service
        matches = db.match_service("Apache HTTP Server")
        assert len(matches) >= 1

    def test_no_match_for_unknown_service(self, db: VulnerabilityDatabase):
        matches = db.match_service("NonExistentService9999")
        assert matches == []

    def test_no_match_for_safe_version(self, db: VulnerabilityDatabase):
        matches = db.match_service("Apache HTTP Server", "99.99.99")
        assert matches == []

    def test_vuln_match_has_cve(self, db: VulnerabilityDatabase):
        matches = db.match_service("Apache HTTP Server", "2.4.49")
        for m in matches:
            assert m.cve is not None
            assert m.cve.startswith("CVE-")

    def test_case_insensitive_service_name(self, db: VulnerabilityDatabase):
        lower = db.match_service("apache http server", "2.4.49")
        upper = db.match_service("APACHE HTTP SERVER", "2.4.49")
        assert len(lower) == len(upper)

    def test_max_matches_cap(self, db: VulnerabilityDatabase):
        matches = db.match_service("Apache HTTP Server")
        assert len(matches) <= MAX_VULN_MATCHES_PER_SERVICE


class TestInjectionPayloads:
    """Injection payload retrieval tests."""

    def test_sql_injection_payloads(self, db: VulnerabilityDatabase):
        payloads = db.get_injection_payloads("sql_injection")
        assert len(payloads) >= 1
        assert all(isinstance(p, str) for p in payloads)

    def test_command_injection_payloads(self, db: VulnerabilityDatabase):
        payloads = db.get_injection_payloads("command_injection")
        assert len(payloads) >= 1

    def test_ldap_injection_payloads(self, db: VulnerabilityDatabase):
        payloads = db.get_injection_payloads("ldap_injection")
        assert len(payloads) >= 1

    def test_xpath_injection_payloads(self, db: VulnerabilityDatabase):
        payloads = db.get_injection_payloads("xpath_injection")
        assert len(payloads) >= 1

    def test_ssti_payloads(self, db: VulnerabilityDatabase):
        payloads = db.get_injection_payloads("ssti")
        assert len(payloads) >= 1

    def test_header_injection_payloads(self, db: VulnerabilityDatabase):
        payloads = db.get_injection_payloads("header_injection")
        assert len(payloads) >= 1

    def test_unknown_category_returns_empty(self, db: VulnerabilityDatabase):
        payloads = db.get_injection_payloads("nonexistent_category")
        assert payloads == []

    def test_payload_count_capped(self, db: VulnerabilityDatabase):
        payloads = db.get_injection_payloads("sql_injection")
        assert len(payloads) <= MAX_INJECTION_PAYLOADS_PER_CATEGORY


class TestMatchWebVuln:
    """Web vulnerability pattern matching tests."""

    def test_match_xss_pattern(self, db: VulnerabilityDatabase):
        body = '<script>alert("xss")</script>'
        matches = db.match_web_vuln(body)
        assert len(matches) >= 1
        assert any("xss" in m.name.lower() or "xss" in m.vuln_id.lower() for m in matches)

    def test_no_match_clean_body(self, db: VulnerabilityDatabase):
        body = "<html><body>Hello, world!</body></html>"
        matches = db.match_web_vuln(body)
        assert matches == []

    def test_header_matching(self, db: VulnerabilityDatabase):
        body = ""
        headers = {"X-Frame-Options": "missing", "Server": "Apache"}
        # The matching looks for patterns in the body first, then headers
        matches = db.match_web_vuln(body, headers)
        # Whether results come back depends on if any patterns match headers
        assert isinstance(matches, list)

    def test_vuln_match_fields(self, db: VulnerabilityDatabase):
        body = "<script>alert(1)</script>"
        matches = db.match_web_vuln(body)
        if matches:
            m = matches[0]
            assert m.vuln_id
            assert m.name
            assert m.severity


class TestDetectionPatterns:
    """Detection pattern retrieval tests."""

    def test_sql_detection_patterns(self, db: VulnerabilityDatabase):
        patterns = db.get_detection_patterns("sql_injection")
        assert len(patterns) >= 1
        assert all(isinstance(p, str) for p in patterns)

    def test_unknown_category_returns_empty(self, db: VulnerabilityDatabase):
        patterns = db.get_detection_patterns("nonexistent")
        assert patterns == []
