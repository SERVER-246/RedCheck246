"""RedCheck246 — Certificate Transparency (CT) Log Monitor.

Queries public CT log APIs to discover certificates issued for target
domains.  Entirely passive — reads public data only.

Discovers:
- Sub-domain certificates (wildcard, SAN entries)
- Certificate issuers and validity periods
- Recently issued certificates (potential phishing / shadow IT)
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import quote

import httpx
import structlog

from redcheck.models import PluginCapability
from redcheck.plugins._http import scanning_ssl_context
from redcheck.plugins.base_plugin import BasePlugin, PluginResult

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# CT Log API endpoints (public, free, no auth)
# ---------------------------------------------------------------------------

_CT_API_URL = "https://crt.sh/?q={domain}&output=json"


def _parse_ct_entry(entry: dict[str, Any], base_domain: str) -> dict[str, Any]:
    """Normalize a crt.sh JSON entry."""
    name_value = entry.get("name_value", "")
    issuer = entry.get("issuer_name", "")
    not_before = entry.get("not_before", "")
    not_after = entry.get("not_after", "")

    # Extract sub-domains from multi-line name_value
    subdomains = set()
    for line in name_value.splitlines():
        line = line.strip().lower()
        if line and base_domain.lower() in line:
            subdomains.add(line)

    return {
        "subdomains": sorted(subdomains),
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "serial": entry.get("serial_number", ""),
    }


class CTLogMonitor(BasePlugin):
    """Discover certificates via public CT log queries.

    Passive-only — reads crt.sh public API.
    """

    name = "ct-log-monitor"
    version = "0.1.0"
    description = "Certificate Transparency log monitoring"
    requires_authorization = True
    category = "osint"
    capability = PluginCapability.PASSIVE

    required_controls: list[str] = []
    timeout_seconds = 60
    rate_limit_rps = 2
    mitre_techniques = ["T1596.003"]
    requires_isolation = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return asyncio.run(self.aexecute(context))

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        domains: list[str] = context.get("ct_domains", [])
        if not domains:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                findings=[],
                errors=["No ct_domains in context — provide domains or enable chain_mode"],
                metadata={"mode": "no-input", "contract_status": "PARTIAL"},
            )

        async with httpx.AsyncClient(verify=scanning_ssl_context(), timeout=30.0) as client:
            for domain in domains:
                try:
                    url = _CT_API_URL.format(domain=quote(domain, safe=""))
                    resp = await client.get(url)

                    if resp.status_code != 200:
                        errors.append(f"crt.sh returned {resp.status_code} for {domain}")
                        continue

                    entries = resp.json()
                    if not isinstance(entries, list):
                        continue

                    all_subdomains: set[str] = set()
                    issuers: set[str] = set()

                    for entry in entries:
                        parsed = _parse_ct_entry(entry, domain)
                        all_subdomains.update(parsed["subdomains"])
                        if parsed["issuer"]:
                            issuers.add(parsed["issuer"])

                    findings.append(
                        {
                            "finding_type": "ct_certificates",
                            "domain": domain,
                            "severity": "info",
                            "subdomains_found": sorted(all_subdomains),
                            "subdomain_count": len(all_subdomains),
                            "unique_issuers": len(issuers),
                            "total_certs": len(entries),
                            "detail": (
                                f"Found {len(all_subdomains)} subdomains, "
                                f"{len(entries)} certificates for {domain}"
                            ),
                        }
                    )

                except Exception as exc:
                    errors.append(f"{domain}: {exc}")

        elapsed = (time.monotonic() - start) * 1000
        self.capture_evidence(
            context,
            f"{len(findings)} ct_log findings".encode(),
            "ct_log_query",
        )
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
            metadata={
                "domains_queried": len(domains),
                "duration_ms": round(elapsed, 2),
            },
        )

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "description": "Would query crt.sh for CT log entries",
            },
        )
