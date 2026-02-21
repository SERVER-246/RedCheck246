"""Tests for ScopeValidator — scope enforcement, CIDR expansion, wildcards."""

from __future__ import annotations

import pytest

from redcheck.core.scope_validator import ScopeValidator


class TestValidateTargets:
    """Scope validation against authorized targets."""

    def test_empty_requested_is_valid(self):
        ok, violations = ScopeValidator.validate_targets([], ["10.0.0.1"])
        assert ok is True
        assert violations == []

    def test_exact_hostname_match(self):
        ok, violations = ScopeValidator.validate_targets(["example.com"], ["example.com"])
        assert ok is True
        assert violations == []

    def test_case_insensitive_match(self):
        ok, violations = ScopeValidator.validate_targets(["Example.COM"], ["example.com"])
        assert ok is True

    def test_exact_ip_match(self):
        ok, violations = ScopeValidator.validate_targets(["10.0.0.1"], ["10.0.0.1"])
        assert ok is True

    def test_ip_in_cidr(self):
        ok, violations = ScopeValidator.validate_targets(["10.0.0.5"], ["10.0.0.0/24"])
        assert ok is True

    def test_ip_outside_cidr(self):
        ok, violations = ScopeValidator.validate_targets(["10.0.1.1"], ["10.0.0.0/24"])
        assert ok is False
        assert "10.0.1.1" in violations

    def test_wildcard_match(self):
        ok, violations = ScopeValidator.validate_targets(["sub.example.com"], ["*.example.com"])
        assert ok is True

    def test_wildcard_no_match(self):
        ok, violations = ScopeValidator.validate_targets(["other.com"], ["*.example.com"])
        assert ok is False

    def test_wildcard_deep_subdomain(self):
        ok, violations = ScopeValidator.validate_targets(
            ["deep.sub.example.com"], ["*.example.com"]
        )
        assert ok is True

    def test_multiple_oob_targets(self):
        ok, violations = ScopeValidator.validate_targets(
            ["bad1.com", "bad2.com", "bad3.com", "good.com"],
            ["good.com"],
        )
        assert ok is False
        assert len(violations) == 3

    def test_mixed_authorized(self):
        ok, violations = ScopeValidator.validate_targets(
            ["10.0.0.1", "app.example.com"],
            ["10.0.0.0/24", "*.example.com"],
        )
        assert ok is True

    def test_all_targets_oob(self):
        ok, violations = ScopeValidator.validate_targets(
            [
                "evil1.com",
                "evil2.com",
                "evil3.com",
                "evil4.com",
                "evil5.com",
                "evil6.com",
                "evil7.com",
                "evil8.com",
                "evil9.com",
                "evil10.com",
            ],
            ["good.com"],
        )
        assert ok is False
        assert len(violations) == 10

    def test_target_with_port(self):
        ok, violations = ScopeValidator.validate_targets(["example.com:443"], ["example.com"])
        assert ok is True


class TestExpandCidr:
    """CIDR expansion with hard cap."""

    def test_expand_24(self):
        hosts = ScopeValidator.expand_cidr("10.0.0.0/24")
        assert len(hosts) == 254  # /24 has 254 hosts (excl network+broadcast)

    def test_expand_16_capped(self):
        hosts = ScopeValidator.expand_cidr("10.0.0.0/16")
        assert len(hosts) == 256  # Hard capped at 256

    def test_expand_custom_cap(self):
        hosts = ScopeValidator.expand_cidr("10.0.0.0/24", max_hosts=10)
        assert len(hosts) == 10

    def test_expand_single_host(self):
        hosts = ScopeValidator.expand_cidr("10.0.0.1/32")
        assert len(hosts) == 1
        assert hosts[0] == "10.0.0.1"

    def test_invalid_cidr(self):
        with pytest.raises(ValueError, match="Invalid CIDR"):
            ScopeValidator.expand_cidr("not-a-cidr")

    def test_deterministic_output(self):
        hosts1 = ScopeValidator.expand_cidr("192.168.1.0/28")
        hosts2 = ScopeValidator.expand_cidr("192.168.1.0/28")
        assert hosts1 == hosts2


class TestValidatePort:
    """Port number validation."""

    def test_valid_ports(self):
        assert ScopeValidator.validate_port(1) is True
        assert ScopeValidator.validate_port(80) is True
        assert ScopeValidator.validate_port(443) is True
        assert ScopeValidator.validate_port(65535) is True

    def test_port_zero_invalid(self):
        assert ScopeValidator.validate_port(0) is False

    def test_port_65536_invalid(self):
        assert ScopeValidator.validate_port(65536) is False

    def test_negative_port_invalid(self):
        assert ScopeValidator.validate_port(-1) is False
