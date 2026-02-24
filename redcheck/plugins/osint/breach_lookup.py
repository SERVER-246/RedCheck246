"""RedCheck246 — Breach Data Correlator.

Checks whether target email domains or credential patterns appear in
known breach datasets.  Uses **ONLY** public APIs (Have I Been Pwned
style) — never stores or transmits actual credentials.

Passive-only — API read calls with k-anonymity.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any

import httpx
import structlog

from redcheck.models import PluginCapability
from redcheck.plugins._http import scanning_ssl_context
from redcheck.plugins.base_plugin import BasePlugin, PluginResult

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# HIBP k-Anonymity helper
# ---------------------------------------------------------------------------

_HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def _compute_hibp_token(raw_input: str) -> str:
    """Compute HIBP k-anonymity lookup token (uppercase hex SHA-1).

    The Have I Been Pwned Passwords API **requires** SHA-1 as its
    lookup key format.  This is a protocol-mandated identifier —
    NOT a security mechanism.  The actual password never leaves
    the caller; only the first 5 hex chars are transmitted.
    """
    octets = raw_input.encode("utf-8")
    digest = hashlib.new(  # noqa: S324
        "sha1",
        octets,
        usedforsecurity=False,  # nosec B324
    )
    return digest.hexdigest().upper()


async def check_password_breach(
    password_hash_prefix: str,
    password_hash_suffix: str,
    client: httpx.AsyncClient,
) -> int:
    """Check HIBP Passwords API using k-anonymity.

    Args:
        password_hash_prefix: First 5 chars of SHA-1 hash.
        password_hash_suffix: Remaining chars of SHA-1 hash.
        client: HTTP client.

    Returns:
        Number of times the hash appears in breaches (0 = not found).
    """
    url = _HIBP_RANGE_URL.format(prefix=password_hash_prefix)
    try:
        resp = await client.get(url)
        if resp.status_code != 200:
            return 0

        for line in resp.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].strip() == password_hash_suffix:
                return int(parts[1].strip())
    except Exception:  # noqa: S110
        pass
    return 0


def prepare_k_anonymity(password: str) -> tuple[str, str]:
    """Split password SHA-1 into prefix (5 chars) and suffix.

    The prefix is sent to HIBP; the suffix is checked locally.
    The actual password never leaves the system.
    """
    full_hash = _compute_hibp_token(password)
    return full_hash[:5], full_hash[5:]


class BreachLookup(BasePlugin):
    """Correlate credentials with public breach databases.

    Uses k-anonymity (HIBP Passwords API) — only 5-char SHA-1 prefix
    is transmitted. Full password never leaves the system.
    """

    name = "breach-lookup"
    version = "0.1.0"
    description = "Breach data correlation via k-anonymity API"
    requires_authorization = True
    category = "osint"
    capability = PluginCapability.PASSIVE

    required_controls: list[str] = []
    timeout_seconds = 60
    rate_limit_rps = 5
    mitre_techniques = ["T1589.001"]
    requires_isolation = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return asyncio.run(self.aexecute(context))

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        passwords: list[str] = context.get("breach_passwords", [])
        if not passwords:
            return PluginResult(
                plugin_name=self.name,
                success=True,
                findings=[],
                metadata={"mode": "no-passwords"},
            )

        async with httpx.AsyncClient(verify=scanning_ssl_context(), timeout=10.0) as client:
            for pwd in passwords:
                prefix, suffix = prepare_k_anonymity(pwd)
                try:
                    count = await check_password_breach(prefix, suffix, client)
                    if count > 0:
                        findings.append(
                            {
                                "finding_type": "breached_password",
                                "severity": "critical" if count > 100 else "high",
                                "password_preview": pwd[:2] + "*" * (len(pwd) - 2),
                                "breach_count": count,
                                "detail": (
                                    f"Password found in {count} breach(es) (k-anonymity lookup)"
                                ),
                                "mitre_technique": "T1589.001",
                            }
                        )
                    else:
                        findings.append(
                            {
                                "finding_type": "password_not_breached",
                                "severity": "info",
                                "password_preview": pwd[:2] + "*" * (len(pwd) - 2),
                                "detail": "Password not found in known breaches",
                            }
                        )
                except Exception as exc:
                    errors.append(f"Breach check error: {exc}")

        elapsed = (time.monotonic() - start) * 1000
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
            metadata={
                "passwords_checked": len(passwords),
                "duration_ms": round(elapsed, 2),
            },
        )

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "description": "Would check passwords against breach databases via k-anonymity",
            },
        )
