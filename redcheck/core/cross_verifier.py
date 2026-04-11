"""RedCheck246 — Cross-Plugin Verification Engine (Phase N).

Runs post-pipeline to correlate findings across plugins and upgrade
``verification_status`` when multiple independent sources agree.
"""

from __future__ import annotations

import structlog

from redcheck.models import Finding, PluginResult, VerificationStatus

log = structlog.get_logger(__name__)

# Plugin names that provide verification authority
_EXPLOIT_PLUGINS = frozenset({"exploit-verifier", "injection-poc-simulator"})
_SAST_PLUGINS = frozenset({"sast-scanner"})
_DAST_PLUGINS = frozenset({"dast-scanner", "protocol-fuzzer"})


def _finding_key(finding: Finding) -> str:
    """Build a normalised key for cross-plugin matching.

    Matches on (target, finding_type) — two plugins reporting the same
    vuln type on the same target are cross-corroborating.
    """
    return f"{finding.target}::{finding.finding_type}"


def cross_verify(results: dict[str, PluginResult]) -> dict[str, PluginResult]:
    """Analyse all plugin results and upgrade verification status.

    Rules:
      - Exploit verifier validates a vuln → CONFIRMED
      - SAST finding + DAST finding on same target+type → CONFIRMED
      - SAST-only with ``likely_false_positive=True`` → likelihood 0.7
      - Unverified findings get ``false_positive_likelihood`` inferred
        from plugin confidence

    Returns the same results dict (mutated in-place for efficiency).
    """
    # Build index: finding_key → list of (plugin_name, finding)
    index: dict[str, list[tuple[str, Finding]]] = {}
    for plugin_name, result in results.items():
        for finding in result.findings:
            key = _finding_key(finding)
            index.setdefault(key, []).append((plugin_name, finding))

    # Track which findings have been confirmed by exploit plugins
    exploit_confirmed: set[str] = set()
    for plugin_name, result in results.items():
        if plugin_name not in _EXPLOIT_PLUGINS:
            continue
        for finding in result.findings:
            if finding.metadata.get("exploit_success") or finding.metadata.get("verified"):
                key = _finding_key(finding)
                exploit_confirmed.add(key)
                finding.verification_status = VerificationStatus.CONFIRMED

    # Cross-match SAST + DAST
    sast_keys: set[str] = set()
    dast_keys: set[str] = set()
    for plugin_name, result in results.items():
        for finding in result.findings:
            key = _finding_key(finding)
            if plugin_name in _SAST_PLUGINS:
                sast_keys.add(key)
            if plugin_name in _DAST_PLUGINS:
                dast_keys.add(key)

    cross_matched = sast_keys & dast_keys

    # Apply upgrades
    for key, entries in index.items():
        for plugin_name, finding in entries:
            if finding.verification_status == VerificationStatus.CONFIRMED:
                continue  # already confirmed

            if key in exploit_confirmed:
                finding.verification_status = VerificationStatus.CONFIRMED
                log.debug("finding_confirmed_by_exploit", key=key, plugin=plugin_name)
                continue

            if key in cross_matched:
                finding.verification_status = VerificationStatus.CONFIRMED
                log.debug("finding_confirmed_by_cross_match", key=key, plugin=plugin_name)
                continue

            # SAST-only with likely_false_positive flag
            if plugin_name in _SAST_PLUGINS and finding.metadata.get("likely_false_positive"):
                finding.verification_status = VerificationStatus.SUSPECTED
                finding.false_positive_likelihood = 0.7
                continue

            # Infer false_positive_likelihood from confidence
            if finding.false_positive_likelihood is None:
                conf = finding.confidence
                if conf == "high":
                    finding.false_positive_likelihood = 0.1
                elif conf == "medium":
                    finding.false_positive_likelihood = 0.3
                else:
                    finding.false_positive_likelihood = 0.5

    return results
