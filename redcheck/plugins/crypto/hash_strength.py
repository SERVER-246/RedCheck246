"""RedCheck246 — Offline Hash Strength Analyzer.

Evaluates the resilience of password hashes found in configuration files,
databases, or leaked datasets — **entirely offline** with no network access.

Classifies hash algorithms, estimates crack difficulty, and flags weak
schemes (MD5, SHA-1, unsalted SHA-256) against current GPU benchmarks.
"""

from __future__ import annotations

import re
import time
from typing import Any

import structlog

from redcheck.models import PluginCapability
from redcheck.plugins.base_plugin import BasePlugin, PluginResult, plugin_dependencies

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Hash algorithm signatures
# ---------------------------------------------------------------------------

_HASH_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "MD5",
        "regex": re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),
        "bits": 128,
        "crackable_per_second_gpu": 64_000_000_000,  # ~64 GH/s modern GPU
        "rating": "critical",
    },
    {
        "name": "SHA-1",
        "regex": re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE),
        "bits": 160,
        "crackable_per_second_gpu": 25_000_000_000,  # ~25 GH/s
        "rating": "critical",
    },
    {
        "name": "SHA-256",
        "regex": re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE),
        "bits": 256,
        "crackable_per_second_gpu": 8_000_000_000,  # ~8 GH/s (unsalted)
        "rating": "high",
    },
    {
        "name": "SHA-512",
        "regex": re.compile(r"^[a-f0-9]{128}$", re.IGNORECASE),
        "bits": 512,
        "crackable_per_second_gpu": 3_000_000_000,
        "rating": "high",
    },
    {
        "name": "bcrypt",
        "regex": re.compile(r"^\$2[aby]?\$\d{2}\$.{53}$"),
        "bits": 184,
        "crackable_per_second_gpu": 105_000,  # ~105 kH/s cost=12
        "rating": "low",
    },
    {
        "name": "scrypt",
        "regex": re.compile(r"^\$scrypt\$"),
        "bits": 256,
        "crackable_per_second_gpu": 1_000,
        "rating": "low",
    },
    {
        "name": "argon2",
        "regex": re.compile(r"^\$argon2(id?|d)\$"),
        "bits": 256,
        "crackable_per_second_gpu": 500,
        "rating": "low",
    },
    {
        "name": "PBKDF2",
        "regex": re.compile(r"^pbkdf2[:_]", re.IGNORECASE),
        "bits": 256,
        "crackable_per_second_gpu": 2_500_000,  # depends on iterations
        "rating": "medium",
    },
    {
        "name": "NTLM",
        "regex": re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),
        "bits": 128,
        "crackable_per_second_gpu": 100_000_000_000,  # ~100 GH/s
        "rating": "critical",
        "context_hint": "ntlm",
    },
]


def identify_hash(hash_str: str, context_hint: str = "") -> dict[str, Any] | None:
    """Identify hash algorithm from a hash string.

    Returns dict with name, bits, rating, crackable_per_second_gpu or None.
    """
    hash_str = hash_str.strip()
    if not hash_str:
        return None

    # Check context-specific hints first
    for pattern in _HASH_PATTERNS:
        if (
            pattern.get("context_hint")
            and pattern["context_hint"] in context_hint.lower()
            and pattern["regex"].match(hash_str)
        ):
            return {
                "name": pattern["name"],
                "bits": pattern["bits"],
                "rating": pattern["rating"],
                "crackable_per_second_gpu": pattern["crackable_per_second_gpu"],
            }

    for pattern in _HASH_PATTERNS:
        if "context_hint" in pattern:
            continue
        if pattern["regex"].match(hash_str):
            return {
                "name": pattern["name"],
                "bits": pattern["bits"],
                "rating": pattern["rating"],
                "crackable_per_second_gpu": pattern["crackable_per_second_gpu"],
            }
    return None


def estimate_crack_time(
    hash_info: dict[str, Any],
    charset_size: int = 95,
    password_length: int = 8,
) -> dict[str, Any]:
    """Estimate brute-force crack time for a given hash algorithm.

    Args:
        hash_info: Output from ``identify_hash``.
        charset_size: Size of the character set (95 = printable ASCII).
        password_length: Assumed password length.

    Returns:
        Dict with estimated seconds, human-readable time, feasibility.
    """
    keyspace = charset_size**password_length
    rate = hash_info["crackable_per_second_gpu"]
    seconds = keyspace / rate if rate > 0 else float("inf")

    if seconds < 1:
        human = "instant"
        feasibility = "trivial"
    elif seconds < 3600:
        human = f"{seconds / 60:.0f} minutes"
        feasibility = "trivial"
    elif seconds < 86400:
        human = f"{seconds / 3600:.1f} hours"
        feasibility = "easy"
    elif seconds < 86400 * 365:
        human = f"{seconds / 86400:.0f} days"
        feasibility = "moderate"
    elif seconds < 86400 * 365 * 100:
        human = f"{seconds / (86400 * 365):.1f} years"
        feasibility = "hard"
    else:
        human = "centuries+"
        feasibility = "infeasible"

    return {
        "keyspace": keyspace,
        "rate_per_second": rate,
        "estimated_seconds": seconds,
        "human_readable": human,
        "feasibility": feasibility,
    }


@plugin_dependencies(
    required=[],
    optional=["sast-scanner", "auth-session-tester"],
    provides=["hash_analysis"],
)
class OfflineHashStrengthAnalyzer(BasePlugin):
    """Offline password hash strength analyzer.

    Analyzes password hashes entirely offline:
    1. Identifies hash algorithm from structure.
    2. Estimates GPU crack time.
    3. Flags weak algorithms.
    """

    name = "hash-strength-analyzer"
    version = "0.1.0"
    description = "Offline password hash strength analysis"
    requires_authorization = True
    category = "crypto"
    capability = PluginCapability.PASSIVE

    required_controls: list[str] = []
    rate_limit_rps = 10
    mitre_techniques = ["T1110.002"]
    requires_isolation = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        """Analyze hashes from context."""
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        hashes: list[str | dict[str, str]] = context.get("hashes", [])
        if not hashes:
            return PluginResult(
                plugin_name=self.name,
                success=True,
                findings=[],
                errors=[],
                metadata={
                    "mode": "no-input",
                    "note": (
                        "No hashes available for analysis — "
                        "upstream SAST findings provide input via chain mode"
                    ),
                },
            )

        for entry in hashes:
            if isinstance(entry, str):
                hash_str = entry
                context_hint = ""
            elif isinstance(entry, dict):
                hash_str = entry.get("hash", "")
                context_hint = entry.get("context", "")
            else:
                continue

            info = identify_hash(hash_str, context_hint)
            if info is None:
                errors.append(f"Unrecognized hash format: {hash_str[:16]}...")
                continue

            crack = estimate_crack_time(info)
            severity = info["rating"]

            findings.append(
                {
                    "finding_type": (
                        "weak_hash" if severity in ("critical", "high") else "hash_analysis"
                    ),
                    "hash_preview": (
                        hash_str[:8] + "..." + hash_str[-4:] if len(hash_str) > 12 else hash_str
                    ),
                    "algorithm": info["name"],
                    "bits": info["bits"],
                    "severity": severity,
                    "crack_estimate": crack["human_readable"],
                    "feasibility": crack["feasibility"],
                    "detail": (
                        f"{info['name']} hash — crack estimate: {crack['human_readable']} "
                        f"(feasibility: {crack['feasibility']})"
                    ),
                }
            )

        elapsed = (time.monotonic() - start) * 1000
        self.capture_evidence(
            context,
            f"{len(findings)} hash findings".encode(),
            "hash_analysis",
        )
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
            metadata={
                "hashes_analyzed": len(hashes),
                "duration_ms": round(elapsed, 2),
            },
        )

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        """Async wrapper — analysis is CPU-bound so just delegates."""
        return self.execute(context)

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "description": "Would analyze hash strength offline",
                "supported_algorithms": [
                    p["name"] for p in _HASH_PATTERNS if "context_hint" not in p
                ],
            },
        )
