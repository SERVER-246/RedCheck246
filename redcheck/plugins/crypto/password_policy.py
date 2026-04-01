"""RedCheck246 — Password Entropy Scorer.

Evaluates password policy strength and individual password entropy.
Entirely offline — never transmits passwords.
"""

from __future__ import annotations

import math
import re
import time
from typing import Any

import structlog

from redcheck.models import PluginCapability
from redcheck.plugins.base_plugin import BasePlugin, PluginResult

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Entropy calculation
# ---------------------------------------------------------------------------

_CHAR_CLASSES: list[tuple[str, int, re.Pattern[str]]] = [
    ("lowercase", 26, re.compile(r"[a-z]")),
    ("uppercase", 26, re.compile(r"[A-Z]")),
    ("digits", 10, re.compile(r"[0-9]")),
    ("symbols", 33, re.compile(r"[^a-zA-Z0-9]")),
]

# Common weak patterns
_WEAK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sequential_digits", re.compile(r"(012|123|234|345|456|567|678|789)")),
    ("repeated_chars", re.compile(r"(.)\1{2,}")),
    ("keyboard_walk", re.compile(r"(qwerty|asdfgh|zxcvbn)", re.IGNORECASE)),
    ("common_word", re.compile(r"(password|admin|letmein|welcome|monkey|dragon)", re.IGNORECASE)),
]


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy in bits for a password.

    Uses character class analysis to estimate the effective keyspace.
    """
    if not password:
        return 0.0

    charset_size = 0
    for _, size, pattern in _CHAR_CLASSES:
        if pattern.search(password):
            charset_size += size

    if charset_size == 0:
        charset_size = 1

    return len(password) * math.log2(charset_size)


def evaluate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a password policy for strength.

    Args:
        policy: Dict with keys like ``min_length``, ``require_uppercase``,
                ``require_digits``, ``require_symbols``, ``max_age_days``.

    Returns:
        Dict with ``score`` (0–100), ``rating``, and ``issues``.
    """
    score = 0
    issues: list[str] = []

    min_length = policy.get("min_length", 0)
    if min_length >= 12:
        score += 30
    elif min_length >= 8:
        score += 15
    else:
        issues.append(f"Minimum length {min_length} is too short (recommend ≥12)")

    if policy.get("require_uppercase", False):
        score += 10
    else:
        issues.append("No uppercase requirement")

    if policy.get("require_digits", False):
        score += 10
    else:
        issues.append("No digit requirement")

    if policy.get("require_symbols", False):
        score += 15
    else:
        issues.append("No symbol requirement")

    max_age = policy.get("max_age_days", 0)
    if max_age and max_age <= 90:
        score += 10
    elif max_age and max_age <= 365:
        score += 5
    else:
        issues.append("No password rotation or rotation period too long")

    if policy.get("mfa_required", False):
        score += 25
    else:
        issues.append("MFA not required")

    # Rating
    if score >= 80:
        rating = "strong"
    elif score >= 50:
        rating = "moderate"
    elif score >= 25:
        rating = "weak"
    else:
        rating = "critical"

    return {"score": score, "rating": rating, "issues": issues}


def check_weak_patterns(password: str) -> list[str]:
    """Check password against known weak patterns.

    Returns list of detected pattern names.
    """
    found: list[str] = []
    for name, pattern in _WEAK_PATTERNS:
        if pattern.search(password):
            found.append(name)
    return found


class PasswordEntropyScorer(BasePlugin):
    """Evaluate password and policy entropy.

    Operates entirely offline:
    1. Calculates password entropy (bit strength).
    2. Detects weak patterns (sequential, repeated, keyboard walks).
    3. Evaluates password policies against best practices.
    """

    name = "password-entropy-scorer"
    version = "0.1.0"
    description = "Password entropy and policy strength evaluation"
    requires_authorization = True
    category = "crypto"
    capability = PluginCapability.PASSIVE

    required_controls: list[str] = []
    timeout_seconds = 30
    rate_limit_rps = 10
    mitre_techniques = ["T1110", "T1078"]
    requires_isolation = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []

        # Analyze individual passwords (masked in output)
        passwords: list[str] = context.get("passwords", [])
        policies: list[dict[str, Any]] = context.get("password_policies", [])

        if not passwords and not policies:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                findings=[],
                errors=["No passwords or password_policies in context"],
                metadata={
                    "mode": "no-input",
                    "contract_status": "PARTIAL",
                    "duration_ms": (time.monotonic() - start) * 1000,
                },
            )

        for pwd in passwords:
            entropy = calculate_entropy(pwd)
            patterns = check_weak_patterns(pwd)

            if entropy < 28:
                severity = "critical"
            elif entropy < 36:
                severity = "high"
            elif entropy < 50:
                severity = "medium"
            else:
                severity = "low"

            findings.append(
                {
                    "finding_type": "password_entropy",
                    "password_preview": pwd[:2] + "*" * (len(pwd) - 2) if len(pwd) > 2 else "**",
                    "entropy_bits": round(entropy, 2),
                    "severity": severity,
                    "weak_patterns": patterns,
                    "detail": f"Entropy: {entropy:.1f} bits ({severity})",
                }
            )

        # Evaluate password policies
        for i, policy in enumerate(policies):
            eval_result = evaluate_policy(policy)
            severity = eval_result["rating"]
            if severity == "strong":
                severity = "info"

            findings.append(
                {
                    "finding_type": "password_policy",
                    "policy_index": i,
                    "score": eval_result["score"],
                    "rating": eval_result["rating"],
                    "severity": severity,
                    "issues": eval_result["issues"],
                    "detail": f"Policy score: {eval_result['score']}/100 ({eval_result['rating']})",
                }
            )

        elapsed = (time.monotonic() - start) * 1000
        self.capture_evidence(
            context,
            f"{len(findings)} password findings".encode(),
            "password_analysis",
        )
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
            metadata={
                "passwords_analyzed": len(passwords),
                "policies_analyzed": len(policies),
                "duration_ms": round(elapsed, 2),
            },
        )

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        return self.execute(context)

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "description": "Would analyze password entropy and policies",
            },
        )
