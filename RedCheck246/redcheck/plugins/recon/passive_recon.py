"""RedCheck246 — Recon Plugin: Passive Reconnaissance.

Performs passive-only reconnaissance against authorized targets.
Does NOT send packets to targets (except safe GET for HTTP fingerprinting
and subdomain DNS queries).  All network calls are async.

Capabilities:
  1. DNS Resolution  (A, AAAA, MX, NS, TXT, CNAME, SOA)
  2. Reverse DNS      (PTR for each resolved IP)
  3. WHOIS Lookup     (registrar, dates, name-servers)
  4. Certificate Transparency  (crt.sh — SANs / subdomains)
  5. HTTP Fingerprinting  (Server, X-Powered-By headers)
  6. Subdomain Enumeration  (DNS brute from built-in wordlist)
  7. Email Harvesting  (TXT / SPF / DMARC records)
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any

import dns.asyncresolver
import dns.name
import dns.rdatatype
import dns.reversename
import httpx

from redcheck.plugins.base_plugin import BasePlugin, PluginResult
from redcheck.plugins.recon.wordlists import COMMON_SUBDOMAINS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_RESOLVER_TIMEOUT = 5.0
_HTTP_TIMEOUT = 10.0
_CT_TIMEOUT = 15.0


def _extract_host(target: dict | str) -> str:
    if isinstance(target, str):
        return target.strip()
    return (target.get("host") or "").strip()


async def _safe_resolve(
    qname: str,
    rdtype: str,
    resolver: dns.asyncresolver.Resolver | None = None,
) -> list[str]:
    """Resolve *qname* for *rdtype*, returning strings.  Never raises."""
    try:
        r = resolver or dns.asyncresolver.Resolver()
        r.lifetime = _RESOLVER_TIMEOUT
        answers = await r.resolve(qname, rdtype)
        return [rr.to_text() for rr in answers]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Recon functions — each returns a list[dict] (findings)
# ---------------------------------------------------------------------------


async def dns_resolve(host: str) -> list[dict[str, Any]]:
    """Resolve A, AAAA, MX, NS, TXT, CNAME, SOA for *host*."""
    findings: list[dict[str, Any]] = []
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    tasks = {rt: _safe_resolve(host, rt) for rt in record_types}
    results: dict[str, list[str]] = {}
    for rt, coro in tasks.items():
        results[rt] = await coro

    for rt, records in results.items():
        if records:
            findings.append(
                {
                    "type": "dns_record",
                    "target": host,
                    "detail": f"{rt}: {', '.join(records)}",
                    "data": {"record_type": rt, "values": records},
                }
            )
    return findings


async def reverse_dns(ips: list[str]) -> list[dict[str, Any]]:
    """PTR lookup for each IP address."""
    findings: list[dict[str, Any]] = []
    for ip_str in ips:
        try:
            rev_name = dns.reversename.from_address(ip_str)
            ptrs = await _safe_resolve(str(rev_name), "PTR")
            if ptrs:
                findings.append(
                    {
                        "type": "reverse_dns",
                        "target": ip_str,
                        "detail": f"PTR: {', '.join(ptrs)}",
                        "data": {"ip": ip_str, "ptr_records": ptrs},
                    }
                )
        except Exception:  # noqa: S112
            continue
    return findings


async def whois_lookup(host: str) -> list[dict[str, Any]]:
    """WHOIS lookup via python-whois (synchronous, wrapped in executor)."""
    findings: list[dict[str, Any]] = []
    try:
        import whois as python_whois  # type: ignore[import-untyped]

        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(None, python_whois.whois, host)

        info: dict[str, Any] = {}
        for key in (
            "registrar",
            "creation_date",
            "expiration_date",
            "name_servers",
            "org",
            "country",
        ):
            val = getattr(data, key, None)
            if val is not None:
                # creation_date / expiration_date can be lists
                if isinstance(val, list):  # noqa: SIM108
                    val = [str(v) for v in val]
                else:
                    val = str(val)
                info[key] = val

        if info:
            findings.append(
                {
                    "type": "whois",
                    "target": host,
                    "detail": f"Registrar: {info.get('registrar', '?')}",
                    "data": info,
                }
            )
    except ImportError:
        findings.append(
            {
                "type": "whois",
                "target": host,
                "detail": "python-whois not installed — skipping WHOIS lookup",
                "data": {"error": "missing_dependency"},
            }
        )
    except Exception as exc:
        findings.append(
            {
                "type": "whois",
                "target": host,
                "detail": f"WHOIS query failed: {exc}",
                "data": {"error": str(exc)},
            }
        )
    return findings


async def cert_transparency(host: str) -> list[dict[str, Any]]:
    """Query crt.sh for certificate transparency logs."""
    findings: list[dict[str, Any]] = []
    url = f"https://crt.sh/?q=%.{host}&output=json"
    try:
        async with httpx.AsyncClient(timeout=_CT_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            entries = resp.json()

        # Deduplicate SANs
        sans: set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*"):
                    sans.add(name)

        if sans:
            findings.append(
                {
                    "type": "cert_transparency",
                    "target": host,
                    "detail": f"Found {len(sans)} unique SANs via crt.sh",
                    "data": {"sans": sorted(sans)},
                }
            )
    except Exception as exc:
        findings.append(
            {
                "type": "cert_transparency",
                "target": host,
                "detail": f"crt.sh query failed: {exc}",
                "data": {"error": str(exc)},
            }
        )
    return findings


async def http_fingerprint(host: str) -> list[dict[str, Any]]:
    """GET request to extract Server / X-Powered-By headers."""
    findings: list[dict[str, Any]] = []
    schemes = ["https", "http"]

    for scheme in schemes:
        url = f"{scheme}://{host}/"
        try:
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT,
                follow_redirects=True,
                verify=False,  # noqa: S501 — intentional for fingerprinting
            ) as client:
                resp = await client.get(url)

            headers_of_interest = [
                "Server",
                "X-Powered-By",
                "X-Generator",
                "X-AspNet-Version",
                "X-AspNetMvc-Version",
            ]
            captured: dict[str, str] = {}
            for hdr in headers_of_interest:
                val = resp.headers.get(hdr)
                if val:
                    captured[hdr] = val

            if captured:
                findings.append(
                    {
                        "type": "http_fingerprint",
                        "target": host,
                        "detail": f"({scheme}) "
                        + ", ".join(f"{k}: {v}" for k, v in captured.items()),
                        "data": {
                            "scheme": scheme,
                            "headers": captured,
                            "status_code": resp.status_code,
                        },
                    }
                )
            # Only need one successful scheme
            break
        except Exception:  # noqa: S112
            continue
    return findings


async def subdomain_enum(host: str, wordlist: list[str] | None = None) -> list[dict[str, Any]]:
    """DNS brute-force subdomain enumeration."""
    findings: list[dict[str, Any]] = []
    subs = wordlist or COMMON_SUBDOMAINS
    discovered: list[str] = []

    sem = asyncio.Semaphore(20)  # limit concurrency

    async def _check(sub: str) -> str | None:
        fqdn = f"{sub}.{host}"
        async with sem:
            records = await _safe_resolve(fqdn, "A")
            if records:
                return fqdn
            return None

    tasks = [_check(sub) for sub in subs]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, str):
            discovered.append(r)

    if discovered:
        findings.append(
            {
                "type": "subdomain_enum",
                "target": host,
                "detail": f"Discovered {len(discovered)} subdomains",
                "data": {"subdomains": sorted(discovered)},
            }
        )
    return findings


async def email_harvest(host: str) -> list[dict[str, Any]]:
    """Extract emails from TXT / SPF / DMARC records."""
    findings: list[dict[str, Any]] = []
    emails: set[str] = set()

    # TXT records on the domain itself
    txt_records = await _safe_resolve(host, "TXT")
    for rec in txt_records:
        emails.update(_EMAIL_RE.findall(rec))

    # DMARC record
    dmarc = await _safe_resolve(f"_dmarc.{host}", "TXT")
    for rec in dmarc:
        emails.update(_EMAIL_RE.findall(rec))

    if emails:
        findings.append(
            {
                "type": "email_harvest",
                "target": host,
                "detail": f"Harvested {len(emails)} email(s) from DNS TXT/DMARC records",
                "data": {"emails": sorted(emails)},
            }
        )
    return findings


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------


class PassiveReconPlugin(BasePlugin):
    """Passive OSINT reconnaissance — DNS, WHOIS, cert-transparency & more."""

    name = "passive-recon"
    version = "0.2.0"
    description = "Passive OSINT reconnaissance — DNS, WHOIS, certificate transparency"
    requires_authorization = True
    category = "recon"

    def execute(self, context: dict) -> PluginResult:
        """Run all passive recon modules against authorized targets."""
        targets = context.get("authorized_targets", [])
        all_findings: list[dict[str, Any]] = []
        errors: list[str] = []
        metadata: dict[str, Any] = {"targets_scanned": 0, "modules": []}

        for target in targets:
            host = _extract_host(target)
            if not host:
                continue
            metadata["targets_scanned"] += 1
            try:
                target_findings = asyncio.run(self._scan_target(host))
                all_findings.extend(target_findings)
            except Exception as exc:
                errors.append(f"Error scanning {host}: {exc}")

        metadata["total_findings"] = len(all_findings)
        metadata["modules"] = [
            "dns_resolve",
            "reverse_dns",
            "whois_lookup",
            "cert_transparency",
            "http_fingerprint",
            "subdomain_enum",
            "email_harvest",
        ]

        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=all_findings,
            errors=errors,
            metadata=metadata,
        )

    async def _scan_target(self, host: str) -> list[dict[str, Any]]:
        """Run all recon modules for a single target, aggregate findings."""
        findings: list[dict[str, Any]] = []

        # 1. DNS Resolution
        dns_findings = await dns_resolve(host)
        findings.extend(dns_findings)

        # 2. Reverse DNS for resolved A/AAAA records
        ips: list[str] = []
        for f in dns_findings:
            data = f.get("data", {})
            if data.get("record_type") in ("A", "AAAA"):
                for v in data.get("values", []):
                    try:
                        ipaddress.ip_address(v)
                        ips.append(v)
                    except ValueError:
                        pass
        if ips:
            findings.extend(await reverse_dns(ips))

        # 3-7 can run concurrently
        whois_task = whois_lookup(host)
        ct_task = cert_transparency(host)
        http_task = http_fingerprint(host)
        sub_task = subdomain_enum(host)
        email_task = email_harvest(host)

        results = await asyncio.gather(
            whois_task,
            ct_task,
            http_task,
            sub_task,
            email_task,
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                findings.append(
                    {
                        "type": "error",
                        "target": host,
                        "detail": f"Module error: {result}",
                    }
                )

        return findings

    def dry_run(self, context: dict) -> PluginResult:
        """Simulate execution — report what *would* happen."""
        targets = context.get("authorized_targets", [])
        hosts = [_extract_host(t) for t in targets]
        hosts = [h for h in hosts if h]
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "targets_count": len(hosts),
                "targets": hosts,
                "modules": [
                    "dns_resolve",
                    "reverse_dns",
                    "whois_lookup",
                    "cert_transparency",
                    "http_fingerprint",
                    "subdomain_enum",
                    "email_harvest",
                ],
                "description": (
                    "Would perform passive DNS, reverse-DNS, WHOIS, "
                    "certificate transparency, HTTP fingerprinting, "
                    "subdomain enumeration, and email harvesting"
                ),
            },
        )
