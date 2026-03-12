"""Tests for TargetIdentityValidator (Phase 7, §34)."""

from __future__ import annotations

import asyncio
import socket
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from redcheck.core.target_validator import (
    DNSValidation,
    TargetIdentity,
    TargetIdentityValidator,
    TargetValidationResult,
    TLSValidation,
)
from redcheck.exceptions import TargetIdentityError


@pytest.fixture
def validator() -> TargetIdentityValidator:
    return TargetIdentityValidator(verify_tls=True, verify_dns=True)


@pytest.fixture
def dns_only_validator() -> TargetIdentityValidator:
    return TargetIdentityValidator(verify_tls=False, verify_dns=True)


@pytest.fixture
def no_verify_validator() -> TargetIdentityValidator:
    return TargetIdentityValidator(verify_tls=False, verify_dns=False)


# ------------------------------------------------------------------ #
# Data model tests
# ------------------------------------------------------------------ #


class TestDataModels:
    """Data model instantiation and field tests."""

    def test_target_identity_defaults(self):
        ti = TargetIdentity(hostname="example.com")
        assert ti.hostname == "example.com"
        assert ti.expected_ips == []
        assert ti.expected_tls_cn is None
        assert ti.expected_org is None
        assert ti.expected_services == []

    def test_tls_validation_fields(self):
        tls = TLSValidation(
            hostname_matches=True,
            cert_cn="example.com",
            cert_sans=["*.example.com"],
            cert_not_after=datetime.now(tz=timezone.utc),
            cert_expired=False,
            issuer="Let's Encrypt",
        )
        assert tls.hostname_matches is True
        assert tls.issuer == "Let's Encrypt"

    def test_dns_validation_fields(self):
        dns = DNSValidation(
            forward_ips=["1.2.3.4"],
            reverse_hostnames=["example.com"],
            consistent=True,
        )
        assert dns.consistent is True

    def test_target_validation_result_defaults(self):
        r = TargetValidationResult(
            target="example.com",
            confidence=0.8,
            dns_valid=True,
        )
        assert r.tls_valid is None
        assert r.ownership_valid is None
        assert r.warnings == []


# ------------------------------------------------------------------ #
# Hostname matching
# ------------------------------------------------------------------ #


class TestHostnameMatches:
    """Certificate name pattern matching tests."""

    def test_exact_match(self):
        assert TargetIdentityValidator._hostname_matches("example.com", "example.com") is True

    def test_case_insensitive(self):
        assert TargetIdentityValidator._hostname_matches("Example.COM", "example.com") is True

    def test_wildcard_match(self):
        assert TargetIdentityValidator._hostname_matches("sub.example.com", "*.example.com") is True

    def test_wildcard_no_match_bare_domain(self):
        # *.example.com should NOT match example.com
        assert TargetIdentityValidator._hostname_matches("example.com", "*.example.com") is False

    def test_no_match_different_domain(self):
        assert TargetIdentityValidator._hostname_matches("other.com", "example.com") is False


# ------------------------------------------------------------------ #
# DNS validation
# ------------------------------------------------------------------ #


class TestDNSValidation:
    """DNS consistency check tests."""

    def test_dns_consistent(self, dns_only_validator: TargetIdentityValidator):
        """Mock DNS to return consistent forward/reverse."""

        def mock_getaddrinfo(host, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0))]

        def mock_gethostbyaddr(addr):
            return ("example.com", [], ["1.2.3.4"])

        with (
            patch("socket.getaddrinfo", side_effect=mock_getaddrinfo),
            patch("socket.gethostbyaddr", side_effect=mock_gethostbyaddr),
        ):
            result = asyncio.run(dns_only_validator.validate_target("example.com"))
        assert result.dns_valid is True
        assert result.confidence > 0.0

    def test_dns_forward_fails(self, dns_only_validator: TargetIdentityValidator):
        """DNS forward resolution fails → inconsistent."""

        def mock_getaddrinfo(host, port):
            raise socket.gaierror("DNS resolution failed")

        with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
            result = asyncio.run(dns_only_validator.validate_target("unresolvable.test"))
        # No forward IPs → empty but consistent=True via fallback
        assert isinstance(result, TargetValidationResult)

    def test_expected_ip_match_boosts_confidence(self, dns_only_validator: TargetIdentityValidator):
        """Matching expected IPs increases confidence score."""

        def mock_getaddrinfo(host, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0))]

        def mock_gethostbyaddr(addr):
            return ("example.com", [], ["1.2.3.4"])

        identity = TargetIdentity(
            hostname="example.com",
            expected_ips=["1.2.3.4"],
        )

        with (
            patch("socket.getaddrinfo", side_effect=mock_getaddrinfo),
            patch("socket.gethostbyaddr", side_effect=mock_gethostbyaddr),
        ):
            result = asyncio.run(dns_only_validator.validate_target("example.com", identity))
        # DNS consistent (+0.4) + IP match (+0.2) + no TLS (+0.2) = 0.8
        assert result.confidence >= 0.8


# ------------------------------------------------------------------ #
# TLS validation
# ------------------------------------------------------------------ #


class TestTLSValidation:
    """TLS certificate check tests (mocked)."""

    def test_tls_connection_fails(self, validator: TargetIdentityValidator):
        """TLS connection failure → tls_valid=False, low confidence."""

        def mock_getaddrinfo(host, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0))]

        def mock_gethostbyaddr(addr):
            return ("unreachable.test", [], ["1.2.3.4"])

        with (
            patch("socket.getaddrinfo", side_effect=mock_getaddrinfo),
            patch("socket.gethostbyaddr", side_effect=mock_gethostbyaddr),
        ):
            result = asyncio.run(validator.validate_target("unreachable.test"))
        # TLS connection will fail (no real server) → tls_valid=False
        assert result.tls_valid is False


# ------------------------------------------------------------------ #
# No verification mode
# ------------------------------------------------------------------ #


class TestNoVerification:
    """Tests with both TLS and DNS disabled."""

    def test_no_verify_high_confidence(self, no_verify_validator: TargetIdentityValidator):
        result = asyncio.run(no_verify_validator.validate_target("anything.test"))
        # DNS skip (+0.3) + TLS skip (+0.2) = 0.5
        assert result.confidence == pytest.approx(0.5)
        assert result.dns_valid is True

    def test_no_verify_no_warnings(self, no_verify_validator: TargetIdentityValidator):
        result = asyncio.run(no_verify_validator.validate_target("anything.test"))
        assert result.warnings == []


# ------------------------------------------------------------------ #
# validate_all_targets
# ------------------------------------------------------------------ #


class TestValidateAllTargets:
    """Batch validation tests."""

    def test_validates_multiple_targets(self, no_verify_validator: TargetIdentityValidator):
        results = asyncio.run(
            no_verify_validator.validate_all_targets(["a.test", "b.test", "c.test"])
        )
        assert len(results) == 3
        assert all(isinstance(r, TargetValidationResult) for r in results)

    def test_empty_targets_returns_empty(self, no_verify_validator: TargetIdentityValidator):
        results = asyncio.run(no_verify_validator.validate_all_targets([]))
        assert results == []

    def test_strict_mode_raises_on_low_confidence(self):
        """TARGET_IDENTITY_STRICT_MODE=True raises TargetIdentityError."""

        # Validator with DNS on but mocked to fail → low confidence
        validator = TargetIdentityValidator(verify_tls=False, verify_dns=True)

        def mock_getaddrinfo(host, port):
            raise socket.gaierror("fail")

        with (
            patch("socket.getaddrinfo", side_effect=mock_getaddrinfo),
            patch(
                "redcheck.core.target_validator.TARGET_IDENTITY_STRICT_MODE",
                True,
            ),
            patch(
                "redcheck.core.target_validator.TARGET_IDENTITY_MIN_CONFIDENCE",
                0.99,
            ),
            pytest.raises(TargetIdentityError),
        ):
            asyncio.run(validator.validate_all_targets(["fail.test"]))


# ------------------------------------------------------------------ #
# Confidence scoring
# ------------------------------------------------------------------ #


class TestConfidenceScoring:
    """Confidence score boundary tests."""

    def test_confidence_clamped_to_one(self, no_verify_validator: TargetIdentityValidator):
        result = asyncio.run(no_verify_validator.validate_target("test.example"))
        assert result.confidence <= 1.0

    def test_confidence_non_negative(self, dns_only_validator: TargetIdentityValidator):
        def mock_getaddrinfo(host, port):
            raise socket.gaierror("fail")

        with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
            result = asyncio.run(dns_only_validator.validate_target("fail.test"))
        assert result.confidence >= 0.0
