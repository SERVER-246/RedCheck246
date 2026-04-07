"""RedCheck246 — Typosquatting Domain Detector.

Generates typosquat permutations for target domains and checks
DNS resolution to identify potentially malicious look-alikes.

Entirely passive — DNS lookups only, no active probing.
"""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Any

import structlog

from redcheck.models import PluginCapability
from redcheck.plugins.base_plugin import BasePlugin, PluginResult, plugin_dependencies

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Permutation generators
# ---------------------------------------------------------------------------


def _remove_char(domain: str) -> list[str]:
    """Omission: remove one character at a time."""
    return [domain[:i] + domain[i + 1 :] for i in range(len(domain))]


def _swap_adjacent(domain: str) -> list[str]:
    """Transposition: swap adjacent characters."""
    results = []
    for i in range(len(domain) - 1):
        if domain[i] != domain[i + 1]:
            s = list(domain)
            s[i], s[i + 1] = s[i + 1], s[i]
            results.append("".join(s))
    return results


def _replace_char(domain: str) -> list[str]:
    """Substitution: replace with nearby keyboard characters."""
    keyboard_neighbors: dict[str, str] = {
        "a": "sqz",
        "b": "vgn",
        "c": "xdv",
        "d": "sfce",
        "e": "rdw",
        "f": "dgcr",
        "g": "fhtb",
        "h": "gjyn",
        "i": "ujko",
        "j": "hkum",
        "k": "jlio",
        "l": "kop",
        "m": "nk",
        "n": "bmhj",
        "o": "iplk",
        "p": "ol",
        "q": "wa",
        "r": "eft",
        "s": "adwx",
        "t": "rgy",
        "u": "yij",
        "v": "cfb",
        "w": "qse",
        "x": "zsc",
        "y": "tuh",
        "z": "xa",
    }
    results = []
    for i, ch in enumerate(domain):
        for neighbor in keyboard_neighbors.get(ch.lower(), ""):
            results.append(domain[:i] + neighbor + domain[i + 1 :])
    return results


def _double_char(domain: str) -> list[str]:
    """Repetition: double a character."""
    return [domain[:i] + domain[i] + domain[i:] for i in range(len(domain))]


def _homoglyph(domain: str) -> list[str]:
    """Homoglyph: visually similar characters."""
    glyphs: dict[str, list[str]] = {
        "o": ["0"],
        "l": ["1", "i"],
        "i": ["1", "l"],
        "0": ["o"],
        "1": ["l", "i"],
        "a": ["@"],
        "e": ["3"],
        "s": ["5", "$"],
        "g": ["9"],
    }
    results = []
    for i, ch in enumerate(domain):
        for g in glyphs.get(ch.lower(), []):
            results.append(domain[:i] + g + domain[i + 1 :])
    return results


def generate_permutations(domain: str, *, include_tld: bool = False) -> list[str]:
    """Generate typosquat permutations for a domain.

    Args:
        domain: The base domain (e.g. ``example`` or ``example.com``).
        include_tld: If True, keeps TLD; otherwise strips it for permutation.

    Returns:
        Deduplicated list of permuted domain strings.
    """
    # Split domain and TLD
    if "." in domain and not include_tld:
        parts = domain.rsplit(".", 1)
        base = parts[0]
        tld = "." + parts[1]
    else:
        base = domain
        tld = ""

    perms: set[str] = set()
    for gen in (_remove_char, _swap_adjacent, _replace_char, _double_char, _homoglyph):
        for p in gen(base):
            candidate = p + tld
            if candidate != domain and candidate:
                perms.add(candidate)

    return sorted(perms)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[-1]


async def _dns_resolve(domain: str) -> str | None:
    """Resolve domain to IP via DNS. Returns IP or None."""
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, socket.gethostbyname, domain)
        return result
    except (socket.gaierror, OSError):
        return None


@plugin_dependencies(
    required=["supply-chain-audit"],
    optional=[],
    provides=["typosquat_risks"],
)
class TyposquatDetector(BasePlugin):
    """Detect typosquat domains that resolve in DNS.

    Passive-only — DNS lookups, no active connections.
    """

    name = "typosquat-detector"
    version = "0.1.0"
    description = "Typosquatting domain detection via DNS"
    requires_authorization = True
    category = "osint"
    capability = PluginCapability.PASSIVE

    required_controls: list[str] = []
    timeout_seconds = 120
    rate_limit_rps = 10
    mitre_techniques = ["T1583.001"]
    requires_isolation = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return asyncio.run(self.aexecute(context))

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        domains: list[str] = context.get("typosquat_domains", [])
        max_resolve: int = context.get("typosquat_max_resolve", 50)

        if not domains:
            # Standalone fallback: extract domains from targets
            domains = self._derive_domains(context)
        if not domains:
            return PluginResult(
                plugin_name=self.name,
                success=True,
                findings=[],
                errors=[],
                metadata={
                    "mode": "no-input",
                    "note": "No domains available for typosquat analysis",
                },
            )

        for domain in domains:
            permutations = generate_permutations(domain)
            resolved: list[dict[str, str]] = []

            # Limit DNS lookups
            to_check = permutations[:max_resolve]
            for perm in to_check:
                ip = await _dns_resolve(perm)
                if ip:
                    dist = levenshtein_distance(domain.split(".")[0], perm.split(".")[0])
                    resolved.append(
                        {
                            "domain": perm,
                            "ip": ip,
                            "edit_distance": str(dist),
                        }
                    )

            if resolved:
                findings.append(
                    {
                        "finding_type": "typosquat_resolved",
                        "original_domain": domain,
                        "severity": "high",
                        "resolved_count": len(resolved),
                        "total_permutations": len(permutations),
                        "resolved_domains": resolved,
                        "detail": (
                            f"{len(resolved)}/{len(to_check)} typosquat permutations "
                            f"of '{domain}' resolve in DNS"
                        ),
                    }
                )
            else:
                findings.append(
                    {
                        "finding_type": "typosquat_none_resolved",
                        "original_domain": domain,
                        "severity": "info",
                        "total_permutations": len(permutations),
                        "detail": f"No typosquat permutations of '{domain}' resolved",
                    }
                )

        elapsed = (time.monotonic() - start) * 1000
        self.capture_evidence(
            context,
            f"{len(findings)} typosquat findings".encode(),
            "typosquat_detection",
        )
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
            metadata={
                "domains_checked": len(domains),
                "duration_ms": round(elapsed, 2),
            },
        )

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "description": "Would generate and DNS-check typosquat permutations",
            },
        )

    @staticmethod
    def _derive_domains(context: dict[str, Any]) -> list[str]:
        """Extract domain names from engagement targets."""
        import ipaddress

        domains: list[str] = []
        targets = context.get("authorized_targets", context.get("targets", []))
        for t in targets:
            host = t.get("host", t) if isinstance(t, dict) else str(t)
            for pfx in ("https://", "http://"):
                if host.startswith(pfx):
                    host = host[len(pfx) :]
            host = host.split("/")[0].split(":")[0]
            # Skip IPs and CIDR — typosquat only works on domain names
            try:
                ipaddress.ip_network(host, strict=False)
                continue
            except ValueError:
                pass
            if "." in host and host not in domains:
                domains.append(host)
        return domains
