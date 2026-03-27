"""Tests for redcheck.core.target_validator — cover _hostname_matches, validation paths."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from redcheck.core.target_validator import (
    DNSValidation,
    TargetIdentity,
    TargetIdentityValidator,
    TargetValidationResult,
    TLSValidation,
)


class TestHostnameMatches:
    def test_exact_match(self):
        assert TargetIdentityValidator._hostname_matches("example.com", "example.com") is True

    def test_case_insensitive(self):
        assert TargetIdentityValidator._hostname_matches("Example.COM", "example.com") is True

    def test_wildcard_match(self):
        assert TargetIdentityValidator._hostname_matches("sub.example.com", "*.example.com") is True

    def test_wildcard_no_match_bare(self):
        assert TargetIdentityValidator._hostname_matches("example.com", "*.example.com") is False

    def test_wildcard_no_match_different(self):
        assert TargetIdentityValidator._hostname_matches("sub.other.com", "*.example.com") is False

    def test_no_match(self):
        assert TargetIdentityValidator._hostname_matches("other.com", "example.com") is False


class TestDataclasses:
    def test_target_identity(self):
        ti = TargetIdentity(hostname="example.com", expected_ips=["1.2.3.4"])
        assert ti.hostname == "example.com"

    def test_tls_validation(self):
        tv = TLSValidation(
            hostname_matches=True,
            cert_cn="example.com",
            cert_sans=["*.example.com"],
            cert_not_after=datetime.now(tz=timezone.utc),
            cert_expired=False,
            issuer="Let's Encrypt",
        )
        assert tv.hostname_matches is True

    def test_dns_validation(self):
        dv = DNSValidation(
            forward_ips=["1.2.3.4"],
            reverse_hostnames=["example.com"],
            consistent=True,
        )
        assert dv.consistent is True

    def test_target_validation_result(self):
        tvr = TargetValidationResult(
            target="example.com",
            confidence=0.8,
            dns_valid=True,
            tls_valid=True,
        )
        assert tvr.confidence == 0.8


class TestValidateTarget:
    @pytest.mark.asyncio
    async def test_dns_and_tls_disabled(self):
        v = TargetIdentityValidator(verify_tls=False, verify_dns=False)
        result = await v.validate_target("example.com")
        assert result.dns_valid is True
        # confidence = 0.3 (dns off) + 0.2 (tls off) = 0.5
        assert result.confidence == pytest.approx(0.5)

    @pytest.mark.asyncio
    async def test_dns_consistent(self):
        v = TargetIdentityValidator(verify_tls=False, verify_dns=True)
        dns = DNSValidation(
            forward_ips=["1.2.3.4"],
            reverse_hostnames=["example.com"],
            consistent=True,
        )
        with patch.object(v, "_verify_dns_consistency", new_callable=AsyncMock) as mock_dns:
            mock_dns.return_value = dns
            result = await v.validate_target("example.com")
            assert result.dns_valid is True
            assert result.confidence >= 0.6  # 0.4 (dns) + 0.2 (tls off)

    @pytest.mark.asyncio
    async def test_dns_inconsistent(self):
        v = TargetIdentityValidator(verify_tls=False, verify_dns=True)
        dns = DNSValidation(
            forward_ips=["1.2.3.4"],
            reverse_hostnames=["other.com"],
            consistent=False,
        )
        with patch.object(v, "_verify_dns_consistency", new_callable=AsyncMock) as mock_dns:
            mock_dns.return_value = dns
            result = await v.validate_target("example.com")
            assert result.dns_valid is False
            assert len(result.warnings) >= 1

    @pytest.mark.asyncio
    async def test_dns_with_expected_ips_match(self):
        v = TargetIdentityValidator(verify_tls=False, verify_dns=True)
        dns = DNSValidation(
            forward_ips=["1.2.3.4"],
            reverse_hostnames=["example.com"],
            consistent=True,
        )
        identity = TargetIdentity(hostname="example.com", expected_ips=["1.2.3.4"])
        with patch.object(v, "_verify_dns_consistency", new_callable=AsyncMock) as mock_dns:
            mock_dns.return_value = dns
            result = await v.validate_target("example.com", identity)
            # 0.4 (dns) + 0.2 (ip match) + 0.2 (tls off) = 0.8
            assert result.confidence >= 0.8

    @pytest.mark.asyncio
    async def test_dns_with_expected_ips_no_match(self):
        v = TargetIdentityValidator(verify_tls=False, verify_dns=True)
        dns = DNSValidation(forward_ips=["5.6.7.8"], reverse_hostnames=[], consistent=True)
        identity = TargetIdentity(hostname="example.com", expected_ips=["1.2.3.4"])
        with patch.object(v, "_verify_dns_consistency", new_callable=AsyncMock) as mock_dns:
            mock_dns.return_value = dns
            result = await v.validate_target("example.com", identity)
            assert any("don't match" in w for w in result.warnings)

    @pytest.mark.asyncio
    async def test_tls_valid(self):
        v = TargetIdentityValidator(verify_tls=True, verify_dns=False)
        tls = TLSValidation(
            hostname_matches=True,
            cert_cn="example.com",
            cert_sans=[],
            cert_not_after=datetime(2030, 1, 1, tzinfo=timezone.utc),
            cert_expired=False,
            issuer="CA",
        )
        with patch.object(v, "_verify_tls_identity", new_callable=AsyncMock) as mock_tls:
            mock_tls.return_value = tls
            result = await v.validate_target("example.com")
            assert result.tls_valid is True
            # 0.3 (dns off) + 0.4 (tls valid) = 0.7
            assert result.confidence >= 0.7

    @pytest.mark.asyncio
    async def test_tls_expired(self):
        v = TargetIdentityValidator(verify_tls=True, verify_dns=False)
        tls = TLSValidation(
            hostname_matches=True,
            cert_cn="example.com",
            cert_sans=[],
            cert_not_after=datetime(2020, 1, 1, tzinfo=timezone.utc),
            cert_expired=True,
            issuer="CA",
        )
        with patch.object(v, "_verify_tls_identity", new_callable=AsyncMock) as mock_tls:
            mock_tls.return_value = tls
            result = await v.validate_target("example.com")
            assert result.tls_valid is False
            assert any("expired" in w for w in result.warnings)

    @pytest.mark.asyncio
    async def test_tls_cn_mismatch(self):
        v = TargetIdentityValidator(verify_tls=True, verify_dns=False)
        tls = TLSValidation(
            hostname_matches=False,
            cert_cn="other.com",
            cert_sans=[],
            cert_not_after=datetime(2030, 1, 1, tzinfo=timezone.utc),
            cert_expired=False,
            issuer="CA",
        )
        with patch.object(v, "_verify_tls_identity", new_callable=AsyncMock) as mock_tls:
            mock_tls.return_value = tls
            result = await v.validate_target("example.com")
            assert result.tls_valid is False
            assert any("mismatch" in w for w in result.warnings)

    @pytest.mark.asyncio
    async def test_tls_cn_mismatch_but_expected_cn_matches(self):
        v = TargetIdentityValidator(verify_tls=True, verify_dns=False)
        tls = TLSValidation(
            hostname_matches=False,
            cert_cn="other.com",
            cert_sans=[],
            cert_not_after=datetime(2030, 1, 1, tzinfo=timezone.utc),
            cert_expired=False,
            issuer="CA",
        )
        identity = TargetIdentity(hostname="example.com", expected_tls_cn="other.com")
        with patch.object(v, "_verify_tls_identity", new_callable=AsyncMock) as mock_tls:
            mock_tls.return_value = tls
            result = await v.validate_target("example.com", identity)
            # 0.3 (dns off) + 0.1 (expected CN match) = 0.4
            assert result.confidence >= 0.4


class TestValidateAllTargets:
    @pytest.mark.asyncio
    async def test_multiple_targets(self):
        v = TargetIdentityValidator(verify_tls=False, verify_dns=False)
        results = await v.validate_all_targets(["a.com", "b.com"])
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_low_confidence_warning(self):
        v = TargetIdentityValidator(verify_tls=False, verify_dns=False)
        # confidence will be 0.5, which should be above default min
        results = await v.validate_all_targets(["a.com"])
        assert len(results) == 1
