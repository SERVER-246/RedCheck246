"""RedCheck246 — Finding Enrichment Layer.

Post-processor that enriches findings with CWE, CVSS, remediation,
and MITRE ATT&CK technique mappings based on ``finding_type``.
Applied automatically by the Orchestrator after each plugin returns.
"""

from __future__ import annotations

from typing import Any

import structlog

log = structlog.get_logger(__name__)

# ------------------------------------------------------------------
# Enrichment database — finding_type → enrichment data
# ------------------------------------------------------------------

_ENRICHMENT_DB: dict[str, dict[str, Any]] = {
    # ── DAST / Header findings ──────────────────────────────────
    "missing_header": {
        "cwe_id": "CWE-693",
        "cvss_score": 4.3,
        "mitre_technique": "T1190",
        "remediation": "Add the missing security header to all HTTP responses.",
    },
    "dast_missing_header": {
        "cwe_id": "CWE-693",
        "cvss_score": 4.3,
        "mitre_technique": "T1190",
        "remediation": "Configure web server to include the missing security header.",
    },
    "missing_hsts": {
        "cwe_id": "CWE-319",
        "cvss_score": 4.3,
        "mitre_technique": "T1557",
        "remediation": (
            "Enable HTTP Strict Transport Security (HSTS) with a minimum max-age of 31536000."
        ),
    },
    "missing_csp": {
        "cwe_id": "CWE-693",
        "cvss_score": 5.3,
        "mitre_technique": "T1059.007",
        "remediation": "Implement a restrictive Content-Security-Policy header.",
    },
    "missing_x_frame_options": {
        "cwe_id": "CWE-1021",
        "cvss_score": 4.3,
        "mitre_technique": "T1189",
        "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN.",
    },
    "cors_misconfiguration": {
        "cwe_id": "CWE-942",
        "cvss_score": 6.5,
        "mitre_technique": "T1189",
        "remediation": "Restrict Access-Control-Allow-Origin to trusted domains only.",
    },
    # ── Network / Port findings ─────────────────────────────────
    "open_port": {
        "cwe_id": "CWE-200",
        "cvss_score": 3.1,
        "mitre_technique": "T1046",
        "remediation": "Review exposed services and close unnecessary ports.",
    },
    "outdated_service": {
        "cwe_id": "CWE-1104",
        "cvss_score": 7.5,
        "mitre_technique": "T1190",
        "remediation": "Update the service to the latest stable version.",
    },
    "weak_tls": {
        "cwe_id": "CWE-326",
        "cvss_score": 5.3,
        "mitre_technique": "T1557",
        "remediation": "Disable TLS 1.0/1.1 and weak cipher suites; enforce TLS 1.2+.",
    },
    "expired_certificate": {
        "cwe_id": "CWE-295",
        "cvss_score": 5.9,
        "mitre_technique": "T1557",
        "remediation": "Renew the TLS certificate before expiry.",
    },
    # ── Auth / Session findings ─────────────────────────────────
    "insecure_cookie": {
        "cwe_id": "CWE-614",
        "cvss_score": 4.3,
        "mitre_technique": "T1539",
        "remediation": "Set Secure, HttpOnly, and SameSite flags on all session cookies.",
    },
    "session_fixation": {
        "cwe_id": "CWE-384",
        "cvss_score": 7.5,
        "mitre_technique": "T1539",
        "remediation": "Regenerate session ID after successful authentication.",
    },
    "missing_csrf_protection": {
        "cwe_id": "CWE-352",
        "cvss_score": 6.5,
        "mitre_technique": "T1189",
        "remediation": "Implement anti-CSRF tokens on all state-changing forms.",
    },
    # ── SAST findings ───────────────────────────────────────────
    "hardcoded_secret": {
        "cwe_id": "CWE-798",
        "cvss_score": 7.5,
        "mitre_technique": "T1552.001",
        "remediation": "Move secrets to an environment variable or secrets manager.",
    },
    "hardcoded_ip": {
        "cwe_id": "CWE-547",
        "cvss_score": 3.1,
        "mitre_technique": "T1016",
        "remediation": "Use configuration files or DNS for service discovery.",
    },
    "sql_injection": {
        "cwe_id": "CWE-89",
        "cvss_score": 9.8,
        "mitre_technique": "T1190",
        "remediation": (
            "Use parameterized queries or an ORM; never concatenate user input into SQL."
        ),
    },
    "xss": {
        "cwe_id": "CWE-79",
        "cvss_score": 6.1,
        "mitre_technique": "T1059.007",
        "remediation": "Encode output contextually; use CSP as defense-in-depth.",
    },
    "command_injection": {
        "cwe_id": "CWE-78",
        "cvss_score": 9.8,
        "mitre_technique": "T1059",
        "remediation": "Avoid shell invocations; use safe subprocess APIs with argument lists.",
    },
    "path_traversal": {
        "cwe_id": "CWE-22",
        "cvss_score": 7.5,
        "mitre_technique": "T1083",
        "remediation": "Validate and canonicalize file paths; use allowlists.",
    },
    # ── Supply-chain findings ───────────────────────────────────
    "vulnerable_dependency": {
        "cwe_id": "CWE-1104",
        "cvss_score": 7.5,
        "mitre_technique": "T1195.002",
        "remediation": "Update the dependency to a patched version.",
    },
    "typosquat_package": {
        "cwe_id": "CWE-506",
        "cvss_score": 8.1,
        "mitre_technique": "T1195.002",
        "remediation": "Remove the suspected typosquat package and verify the correct name.",
    },
    # ── OSINT findings ──────────────────────────────────────────
    "exposed_email": {
        "cwe_id": "CWE-200",
        "cvss_score": 3.1,
        "mitre_technique": "T1589.002",
        "remediation": "Remove exposed email addresses from public sources.",
    },
    "breached_credential": {
        "cwe_id": "CWE-521",
        "cvss_score": 7.5,
        "mitre_technique": "T1078",
        "remediation": "Force password reset and enable MFA for affected accounts.",
    },
    "dns_zone_transfer": {
        "cwe_id": "CWE-200",
        "cvss_score": 5.3,
        "mitre_technique": "T1590.002",
        "remediation": "Restrict DNS zone transfers to authorized secondary servers.",
    },
    # ── Crypto findings ─────────────────────────────────────────
    "weak_hash_algorithm": {
        "cwe_id": "CWE-328",
        "cvss_score": 5.3,
        "mitre_technique": "T1110",
        "remediation": (
            "Use bcrypt, scrypt, or Argon2 for password hashing; SHA-256+ for integrity."
        ),
    },
    "weak_password": {
        "cwe_id": "CWE-521",
        "cvss_score": 7.5,
        "mitre_technique": "T1110.001",
        "remediation": "Enforce minimum password length (12+) and complexity requirements.",
    },
    # ── CVE findings ────────────────────────────────────────────
    "known_cve": {
        "cwe_id": "CWE-1104",
        "cvss_score": 7.5,
        "mitre_technique": "T1190",
        "remediation": "Apply vendor patches or upgrade to a non-vulnerable version.",
    },
    # ── Fuzzing findings ────────────────────────────────────────
    "protocol_anomaly": {
        "cwe_id": "CWE-20",
        "cvss_score": 5.3,
        "mitre_technique": "T1190",
        "remediation": "Implement strict input validation on the affected protocol handler.",
    },
    "crash_detected": {
        "cwe_id": "CWE-120",
        "cvss_score": 7.5,
        "mitre_technique": "T1499.004",
        "remediation": "Fix the crash-inducing input handling; add bounds checks.",
    },
}


def enrich_finding(finding: Any) -> bool:
    """Enrich a single Finding in-place from the enrichment database.

    Returns True if any field was enriched, False otherwise.
    """
    finding_type = getattr(finding, "finding_type", "") or ""
    if not finding_type:
        return False

    entry = _ENRICHMENT_DB.get(finding_type)
    if entry is None:
        return False

    enriched = False
    metadata = finding.metadata if hasattr(finding, "metadata") else {}

    if not metadata.get("cwe_id") and entry.get("cwe_id"):
        metadata["cwe_id"] = entry["cwe_id"]
        if hasattr(finding, "cwe_id") and not finding.cwe_id:
            finding.cwe_id = entry["cwe_id"]
        enriched = True

    if not metadata.get("cvss_score") and entry.get("cvss_score"):
        metadata["cvss_score"] = entry["cvss_score"]
        if hasattr(finding, "cvss_score") and finding.cvss_score is None:
            finding.cvss_score = entry["cvss_score"]
        enriched = True

    if not metadata.get("remediation") and entry.get("remediation"):
        metadata["remediation"] = entry["remediation"]
        if hasattr(finding, "remediation") and not finding.remediation:
            finding.remediation = entry["remediation"]
        enriched = True

    if not metadata.get("mitre_technique") and entry.get("mitre_technique"):
        metadata["mitre_technique"] = entry["mitre_technique"]
        if hasattr(finding, "mitre_technique") and not finding.mitre_technique:
            finding.mitre_technique = entry["mitre_technique"]
        enriched = True

    return enriched


def enrich_plugin_result(result: Any) -> int:
    """Enrich all findings in a PluginResult. Returns count of enriched findings."""
    count = 0
    for finding in getattr(result, "findings", []):
        if enrich_finding(finding):
            count += 1
    if count:
        log.debug(
            "findings_enriched",
            plugin=getattr(result, "plugin_name", "unknown"),
            enriched=count,
            total=len(result.findings),
        )
    return count
