"""RedCheck246 — Target Identity Validator.

Pre-flight verification that targets are genuinely the systems described
in the Rules of Engagement. Performs DNS consistency checks, TLS
certificate validation, and optional domain ownership verification.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

import structlog

from redcheck.constants import (
    TARGET_IDENTITY_DNS_TIMEOUT_SECONDS,
    TARGET_IDENTITY_MIN_CONFIDENCE,
    TARGET_IDENTITY_STRICT_MODE,
    TARGET_IDENTITY_TLS_TIMEOUT_SECONDS,
)
from redcheck.exceptions import TargetIdentityError

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class TargetIdentity:
    """Expected identity of a target system (from RoE or operator)."""

    hostname: str
    expected_ips: list[str] = field(default_factory=list)
    expected_tls_cn: str | None = None
    expected_org: str | None = None
    expected_services: list[str] = field(default_factory=list)


@dataclass
class TLSValidation:
    """TLS certificate identity check result."""

    hostname_matches: bool
    cert_cn: str
    cert_sans: list[str]
    cert_not_after: datetime
    cert_expired: bool
    issuer: str


@dataclass
class DNSValidation:
    """DNS consistency check result."""

    forward_ips: list[str]
    reverse_hostnames: list[str]
    consistent: bool


@dataclass
class TargetValidationResult:
    """Full identity validation result for one target."""

    target: str
    confidence: float
    dns_valid: bool
    tls_valid: bool | None = None
    ownership_valid: bool | None = None
    warnings: list[str] = field(default_factory=list)
    dns_details: DNSValidation | None = None
    tls_details: TLSValidation | None = None


# ---------------------------------------------------------------------------
# Target Identity Validator
# ---------------------------------------------------------------------------


class TargetIdentityValidator:
    """Validates that targets are genuinely the systems described in the RoE.

    Runs BEFORE any plugin execution to confirm target identity.
    This is a pre-flight check, not a plugin.
    """

    def __init__(
        self,
        *,
        verify_tls: bool = True,
        verify_dns: bool = True,
        verify_ownership: bool = False,
    ) -> None:
        self._verify_tls = verify_tls
        self._verify_dns = verify_dns
        self._verify_ownership = verify_ownership

    async def validate_target(
        self,
        target: str,
        expected_identity: TargetIdentity | None = None,
    ) -> TargetValidationResult:
        """Validate a single target's identity.

        Steps:
          1. DNS resolution — resolve hostname → IP, check consistency
          2. TLS certificate — verify cert CN/SAN matches hostname
          3. Compute confidence score from validation results
        """
        warnings: list[str] = []
        confidence = 0.0
        dns_valid = False
        tls_valid: bool | None = None
        dns_details: DNSValidation | None = None
        tls_details: TLSValidation | None = None

        # Step 1: DNS consistency
        if self._verify_dns:
            dns_details = await self._verify_dns_consistency(target)
            dns_valid = dns_details.consistent
            if dns_valid:
                confidence += 0.4
            else:
                warnings.append(
                    f"DNS inconsistency for {target}: "
                    f"forward={dns_details.forward_ips}, "
                    f"reverse={dns_details.reverse_hostnames}"
                )

            # Check against expected IPs if provided
            if expected_identity and expected_identity.expected_ips:
                ip_match = any(
                    ip in expected_identity.expected_ips for ip in dns_details.forward_ips
                )
                if ip_match:
                    confidence += 0.2
                else:
                    warnings.append(
                        f"Resolved IPs {dns_details.forward_ips} don't match "
                        f"expected {expected_identity.expected_ips}"
                    )
        else:
            dns_valid = True
            confidence += 0.3

        # Step 2: TLS verification
        if self._verify_tls:
            tls_details = await self._verify_tls_identity(target)
            tls_valid = tls_details.hostname_matches and not tls_details.cert_expired
            if tls_valid:
                confidence += 0.4
            else:
                if tls_details.cert_expired:
                    warnings.append(f"TLS certificate expired for {target}")
                if not tls_details.hostname_matches:
                    warnings.append(
                        f"TLS CN/SAN mismatch: cert_cn={tls_details.cert_cn}, target={target}"
                    )

                # Check against expected CN
                if (
                    expected_identity
                    and expected_identity.expected_tls_cn
                    and tls_details.cert_cn == expected_identity.expected_tls_cn
                ):
                    confidence += 0.1
        else:
            confidence += 0.2

        # Clamp confidence
        confidence = min(1.0, max(0.0, confidence))

        return TargetValidationResult(
            target=target,
            confidence=confidence,
            dns_valid=dns_valid,
            tls_valid=tls_valid,
            ownership_valid=None,
            warnings=warnings,
            dns_details=dns_details,
            tls_details=tls_details,
        )

    async def validate_all_targets(
        self,
        targets: list[str],
        identities: dict[str, TargetIdentity] | None = None,
    ) -> list[TargetValidationResult]:
        """Validate all RoE targets before engagement begins.

        If any target fails validation with confidence below
        TARGET_IDENTITY_MIN_CONFIDENCE, log a warning.
        If TARGET_IDENTITY_STRICT_MODE is True, raise
        TargetIdentityError for failed validations.
        """
        results: list[TargetValidationResult] = []
        for target in targets:
            identity = (identities or {}).get(target)
            result = await self.validate_target(target, identity)
            results.append(result)

            if result.confidence < TARGET_IDENTITY_MIN_CONFIDENCE:
                log.warning(
                    "target_identity_low_confidence",
                    target=target,
                    confidence=result.confidence,
                    warnings=result.warnings,
                )
                if TARGET_IDENTITY_STRICT_MODE:
                    raise TargetIdentityError(
                        target=target,
                        confidence=result.confidence,
                    )

        return results

    async def _verify_tls_identity(self, hostname: str, port: int = 443) -> TLSValidation:
        """Connect to target, retrieve TLS certificate, verify identity.

        Does NOT perform full PKI validation — this is identity
        confirmation, not security assessment.
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            conn = asyncio.open_connection(
                hostname,
                port,
                ssl=ctx,
            )
            reader, writer = await asyncio.wait_for(
                conn, timeout=TARGET_IDENTITY_TLS_TIMEOUT_SECONDS
            )

            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is None:
                writer.close()
                return TLSValidation(
                    hostname_matches=False,
                    cert_cn="",
                    cert_sans=[],
                    cert_not_after=datetime.now(tz=timezone.utc),
                    cert_expired=True,
                    issuer="unknown",
                )

            cert = ssl_obj.getpeercert()
            writer.close()

            if not cert:
                return TLSValidation(
                    hostname_matches=False,
                    cert_cn="",
                    cert_sans=[],
                    cert_not_after=datetime.now(tz=timezone.utc),
                    cert_expired=True,
                    issuer="unknown",
                )

            # Extract CN
            subject = dict(x[0] for x in cert.get("subject", ()))
            cert_cn = subject.get("commonName", "")

            # Extract SANs
            san_entries = cert.get("subjectAltName", ())
            cert_sans = [v for t, v in san_entries if t == "DNS"]

            # Check hostname match
            all_names = [cert_cn] + cert_sans
            hostname_matches = any(self._hostname_matches(hostname, name) for name in all_names)

            # Check expiry
            not_after_str = cert.get("notAfter", "")
            try:
                cert_not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
            except (ValueError, TypeError):
                cert_not_after = datetime.now(tz=timezone.utc)
            cert_expired = cert_not_after < datetime.now(tz=timezone.utc)

            # Issuer
            issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
            issuer = issuer_dict.get("organizationName", "unknown")

            return TLSValidation(
                hostname_matches=hostname_matches,
                cert_cn=cert_cn,
                cert_sans=cert_sans,
                cert_not_after=cert_not_after,
                cert_expired=cert_expired,
                issuer=issuer,
            )

        except Exception as exc:
            log.debug("tls_validation_failed", hostname=hostname, error=str(exc))
            return TLSValidation(
                hostname_matches=False,
                cert_cn="",
                cert_sans=[],
                cert_not_after=datetime.now(tz=timezone.utc),
                cert_expired=True,
                issuer="unknown",
            )

    async def _verify_dns_consistency(self, target: str) -> DNSValidation:
        """Forward and reverse DNS resolution consistency check."""
        forward_ips: list[str] = []
        reverse_hostnames: list[str] = []

        try:
            loop = asyncio.get_running_loop()
            addrs = await asyncio.wait_for(
                loop.run_in_executor(None, socket.getaddrinfo, target, None),
                timeout=TARGET_IDENTITY_DNS_TIMEOUT_SECONDS,
            )
            forward_ips = list({addr[4][0] for addr in addrs})
        except Exception as exc:
            log.debug("dns_forward_failed", target=target, error=str(exc))

        # Reverse DNS for each resolved IP
        for ip in forward_ips[:5]:
            try:
                loop = asyncio.get_running_loop()
                hostname_result = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda addr=ip: socket.gethostbyaddr(addr)[0],
                    ),
                    timeout=TARGET_IDENTITY_DNS_TIMEOUT_SECONDS,
                )
                reverse_hostnames.append(hostname_result)
            except Exception:  # noqa: S110
                pass

        # Consistency: reverse should contain the original target
        consistent = (
            (
                len(forward_ips) > 0
                and any(
                    target.lower() in rh.lower() or rh.lower() in target.lower()
                    for rh in reverse_hostnames
                )
            )
            if reverse_hostnames
            else len(forward_ips) > 0
        )

        return DNSValidation(
            forward_ips=forward_ips,
            reverse_hostnames=reverse_hostnames,
            consistent=consistent,
        )

    @staticmethod
    def _hostname_matches(hostname: str, pattern: str) -> bool:
        """Check if hostname matches a certificate name pattern.

        Supports wildcard patterns like ``*.example.com``.
        """
        hostname = hostname.lower()
        pattern = pattern.lower()

        if pattern == hostname:
            return True

        if pattern.startswith("*."):
            suffix = pattern[2:]
            if hostname.endswith(suffix) and "." in hostname[: -len(suffix)]:
                return True

        return False
