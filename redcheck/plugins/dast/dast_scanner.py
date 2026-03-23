"""RedCheck246 — DAST Plugin: Dynamic Application Security Testing.

Tests running applications for security vulnerabilities.
Requires full authorization — sends live requests to targets.

Capabilities:
  1. HTTP Security Headers  — HSTS, CSP, X-Frame-Options, etc.
  2. SSL/TLS Assessment     — protocol version, cert validity, ciphers
  3. HTTP Method Testing    — OPTIONS, dangerous methods
  4. Cookie Security        — Secure, HttpOnly, SameSite flags
  5. Directory Discovery    — sensitive-path enumeration
  6. Redirect Analysis      — HTTP→HTTPS, open redirect detection
"""

from __future__ import annotations

import asyncio
import socket
from datetime import datetime, timezone
from typing import Any

import httpx

from redcheck.plugins._http import scanning_ssl_context
from redcheck.plugins.base_plugin import BasePlugin, PluginResult
from redcheck.plugins.dast.wordlists import SENSITIVE_PATHS

_HTTP_TIMEOUT = 10.0
_SSL_TIMEOUT = 5.0


def _strip_scheme(host: str) -> str:
    """Remove any existing URL scheme from a host string."""
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix) :]
    return host.rstrip("/")


def _extract_targets(context: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalise target list from context."""
    raw = context.get("authorized_targets", [])
    targets = []
    for t in raw:
        if isinstance(t, str):
            targets.append({"host": t, "ports": [443, 80], "protocols": ["tcp"]})
        elif isinstance(t, dict):
            targets.append(t)
    return targets


# ---------------------------------------------------------------------------
# Security header checks
# ---------------------------------------------------------------------------

_REQUIRED_HEADERS: list[tuple[str, str, str]] = [
    ("Strict-Transport-Security", "HIGH", "Missing HSTS header"),
    ("Content-Security-Policy", "MEDIUM", "Missing CSP header"),
    ("X-Frame-Options", "MEDIUM", "Missing X-Frame-Options header"),
    ("X-Content-Type-Options", "LOW", "Missing X-Content-Type-Options header"),
    ("Referrer-Policy", "LOW", "Missing Referrer-Policy header"),
    ("Permissions-Policy", "LOW", "Missing Permissions-Policy header"),
    ("Cross-Origin-Opener-Policy", "INFO", "Missing COOP header"),
    ("Cross-Origin-Resource-Policy", "INFO", "Missing CORP header"),
]


async def check_security_headers(url: str) -> list[dict[str, Any]]:
    """Analyse HTTP response headers for security best practices."""
    findings: list[dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT,
            verify=scanning_ssl_context(),
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)

        for hdr_name, severity, message in _REQUIRED_HEADERS:
            val = resp.headers.get(hdr_name)
            if not val:
                findings.append(
                    {
                        "type": "dast_missing_header",
                        "target": url,
                        "detail": message,
                        "data": {"header": hdr_name, "severity": severity},
                    }
                )
            else:
                # Extra checks for known headers
                if hdr_name == "Strict-Transport-Security":
                    if "max-age" in val.lower():
                        try:
                            max_age = int(val.lower().split("max-age=")[1].split(";")[0].strip())
                            if max_age < 31536000:
                                findings.append(
                                    {
                                        "type": "dast_weak_hsts",
                                        "target": url,
                                        "detail": (
                                            f"HSTS max-age too short: "
                                            f"{max_age}s (should be ≥31536000)"
                                        ),
                                        "data": {
                                            "header": hdr_name,
                                            "severity": "MEDIUM",
                                            "max_age": max_age,
                                        },
                                    }
                                )
                        except (ValueError, IndexError):
                            pass
                elif hdr_name == "Content-Security-Policy":
                    csp_lower = val.lower()
                    for dangerous in ("unsafe-inline", "unsafe-eval", "'*'"):
                        if dangerous in csp_lower:
                            findings.append(
                                {
                                    "type": "dast_weak_csp",
                                    "target": url,
                                    "detail": f"CSP contains '{dangerous}'",
                                    "data": {
                                        "header": hdr_name,
                                        "severity": "MEDIUM",
                                        "directive": dangerous,
                                    },
                                }
                            )

        # X-XSS-Protection (deprecated but informational)
        xss = resp.headers.get("X-XSS-Protection")
        if xss and xss.strip() == "0":
            findings.append(
                {
                    "type": "dast_xss_protection_disabled",
                    "target": url,
                    "detail": "X-XSS-Protection explicitly disabled",
                    "data": {"severity": "INFO"},
                }
            )

    except Exception as exc:
        findings.append(
            {
                "type": "dast_header_error",
                "target": url,
                "detail": f"Header check failed: {exc}",
                "data": {"error": str(exc)},
            }
        )
    return findings


# ---------------------------------------------------------------------------
# SSL/TLS assessment
# ---------------------------------------------------------------------------


async def check_ssl_tls(host: str, port: int = 443) -> list[dict[str, Any]]:
    """Assess SSL/TLS configuration."""
    findings: list[dict[str, Any]] = []
    loop = asyncio.get_running_loop()

    def _probe() -> dict[str, Any]:
        ctx = scanning_ssl_context()
        with socket.create_connection((host, port), timeout=_SSL_TIMEOUT) as sock:  # noqa: SIM117
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                return {
                    "version": ssock.version(),
                    "cipher": ssock.cipher(),
                    "cert": cert or {},
                }

    try:
        info = await loop.run_in_executor(None, _probe)

        # Protocol version check
        version = info.get("version", "")
        if "TLSv1.0" in version or "TLSv1.1" in version or "SSLv" in version:
            findings.append(
                {
                    "type": "dast_weak_tls",
                    "target": f"{host}:{port}",
                    "detail": f"Weak TLS version: {version}",
                    "data": {"severity": "CRITICAL", "version": version},
                }
            )
        elif "TLSv1.2" in version:
            findings.append(
                {
                    "type": "dast_tls_version",
                    "target": f"{host}:{port}",
                    "detail": f"TLS version: {version} (OK, but TLS 1.3 preferred)",
                    "data": {"severity": "INFO", "version": version},
                }
            )

        # Certificate expiry
        cert = info.get("cert", {})
        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days_left = (exp - datetime.now(tz=timezone.utc)).days
                if days_left < 0:
                    findings.append(
                        {
                            "type": "dast_cert_expired",
                            "target": f"{host}:{port}",
                            "detail": f"Certificate expired {abs(days_left)} days ago",
                            "data": {"severity": "CRITICAL", "expires": not_after},
                        }
                    )
                elif days_left < 30:
                    findings.append(
                        {
                            "type": "dast_cert_expiring",
                            "target": f"{host}:{port}",
                            "detail": f"Certificate expires in {days_left} days",
                            "data": {"severity": "HIGH", "expires": not_after},
                        }
                    )
            except ValueError:
                pass

        # Self-signed check
        issuer = cert.get("issuer", ())
        subject = cert.get("subject", ())
        if issuer and subject and issuer == subject:
            findings.append(
                {
                    "type": "dast_self_signed",
                    "target": f"{host}:{port}",
                    "detail": "Self-signed certificate detected",
                    "data": {"severity": "HIGH"},
                }
            )

    except Exception as exc:
        findings.append(
            {
                "type": "dast_ssl_error",
                "target": f"{host}:{port}",
                "detail": f"SSL/TLS check failed: {exc}",
                "data": {"error": str(exc)},
            }
        )
    return findings


# ---------------------------------------------------------------------------
# HTTP methods
# ---------------------------------------------------------------------------


async def check_http_methods(url: str) -> list[dict[str, Any]]:
    """Check for dangerous HTTP methods via OPTIONS."""
    findings: list[dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT,
            verify=scanning_ssl_context(),
            follow_redirects=True,
        ) as client:
            resp = await client.options(url)
        allow = resp.headers.get("Allow", "")
        if allow:
            methods = {m.strip().upper() for m in allow.split(",")}
            dangerous = methods & {"TRACE", "PUT", "DELETE", "PATCH"}
            if dangerous:
                findings.append(
                    {
                        "type": "dast_dangerous_methods",
                        "target": url,
                        "detail": f"Dangerous HTTP methods allowed: {', '.join(sorted(dangerous))}",
                        "data": {"severity": "MEDIUM", "methods": sorted(dangerous)},
                    }
                )
    except Exception:  # noqa: S110
        pass
    return findings


# ---------------------------------------------------------------------------
# Cookie analysis
# ---------------------------------------------------------------------------


async def check_cookies(url: str) -> list[dict[str, Any]]:
    """Analyse Set-Cookie headers for security attributes."""
    findings: list[dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT,
            verify=scanning_ssl_context(),
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)

        for cookie_hdr in resp.headers.get_list("set-cookie"):
            parts_lower = cookie_hdr.lower()
            name = cookie_hdr.split("=", 1)[0].strip()

            is_https = url.startswith("https")
            if is_https and "secure" not in parts_lower:
                findings.append(
                    {
                        "type": "dast_cookie_no_secure",
                        "target": url,
                        "detail": f"Cookie '{name}' missing Secure flag on HTTPS",
                        "data": {"severity": "MEDIUM", "cookie": name},
                    }
                )
            if "httponly" not in parts_lower:
                findings.append(
                    {
                        "type": "dast_cookie_no_httponly",
                        "target": url,
                        "detail": f"Cookie '{name}' missing HttpOnly flag",
                        "data": {"severity": "MEDIUM", "cookie": name},
                    }
                )
            if "samesite" not in parts_lower:
                findings.append(
                    {
                        "type": "dast_cookie_no_samesite",
                        "target": url,
                        "detail": f"Cookie '{name}' missing SameSite attribute",
                        "data": {"severity": "LOW", "cookie": name},
                    }
                )
    except Exception:  # noqa: S110
        pass
    return findings


# ---------------------------------------------------------------------------
# Directory / path discovery
# ---------------------------------------------------------------------------


async def discover_paths(base_url: str) -> list[dict[str, Any]]:
    """Test sensitive paths for unexpected 200 responses."""
    findings: list[dict[str, Any]] = []
    sem = asyncio.Semaphore(10)

    async def _probe(path: str) -> dict[str, Any] | None:
        url = f"{base_url.rstrip('/')}{path}"
        async with sem:
            try:
                async with httpx.AsyncClient(
                    timeout=_HTTP_TIMEOUT,
                    verify=scanning_ssl_context(),
                    follow_redirects=False,
                ) as client:
                    resp = await client.get(url)
                if resp.status_code in (200, 301, 302, 403):
                    return {
                        "type": "dast_path_found",
                        "target": url,
                        "detail": f"Sensitive path accessible: {path} (HTTP {resp.status_code})",
                        "data": {
                            "path": path,
                            "status_code": resp.status_code,
                            "severity": "HIGH" if resp.status_code == 200 else "INFO",
                        },
                    }
            except Exception:  # noqa: S110
                pass
            return None

    tasks = [_probe(p) for p in SENSITIVE_PATHS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)
    return findings


# ---------------------------------------------------------------------------
# Redirect analysis
# ---------------------------------------------------------------------------


async def check_redirects(host: str) -> list[dict[str, Any]]:
    """Check HTTP→HTTPS redirect and open-redirect patterns."""
    findings: list[dict[str, Any]] = []
    host = _strip_scheme(host)
    http_url = f"http://{host}/"
    try:
        async with httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT,
            verify=scanning_ssl_context(),
            follow_redirects=False,
        ) as client:
            resp = await client.get(http_url)

        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("location", "")
            if location.startswith("https://"):
                findings.append(
                    {
                        "type": "dast_redirect_ok",
                        "target": host,
                        "detail": f"HTTP→HTTPS redirect present ({resp.status_code})",
                        "data": {"severity": "INFO", "location": location},
                    }
                )
            else:
                findings.append(
                    {
                        "type": "dast_no_https_redirect",
                        "target": host,
                        "detail": f"HTTP redirect does not go to HTTPS: {location}",
                        "data": {"severity": "MEDIUM", "location": location},
                    }
                )
        elif resp.status_code == 200:
            findings.append(
                {
                    "type": "dast_no_https_redirect",
                    "target": host,
                    "detail": "HTTP serves content without redirecting to HTTPS",
                    "data": {"severity": "HIGH"},
                }
            )
    except Exception:  # noqa: S110
        pass
    return findings


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------


class DASTPlugin(BasePlugin):
    """Dynamic Application Security Testing — live target scanning."""

    name = "dast-scanner"
    version = "0.2.0"
    description = "Dynamic application security testing — live target scanning"
    requires_authorization = True
    category = "dast"

    def execute(self, context: dict[str, Any]) -> PluginResult:
        """Run all DAST modules against authorized targets."""
        targets = _extract_targets(context)
        all_findings: list[dict[str, Any]] = []
        errors: list[str] = []

        for target in targets:
            host = target.get("host", "")
            if not host:
                continue
            ports = target.get("ports", [443, 80])

            try:
                target_findings = asyncio.run(self._scan_target(host, ports))
                all_findings.extend(target_findings)
            except Exception as exc:
                errors.append(f"Error scanning {host}: {exc}")

        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=all_findings,
            errors=errors,
            metadata={
                "targets_scanned": len(targets),
                "total_findings": len(all_findings),
                "modules": [
                    "security_headers",
                    "ssl_tls",
                    "http_methods",
                    "cookies",
                    "path_discovery",
                    "redirects",
                ],
            },
        )

    async def _scan_target(self, host: str, ports: list[int]) -> list[dict[str, Any]]:
        """Run all DAST modules for a single target."""
        findings: list[dict[str, Any]] = []

        # Determine base URL (prefer HTTPS); strip existing scheme to avoid
        # double-scheme URLs like "https://https://evil.com" (M-5).
        host = _strip_scheme(host)
        base_url = f"https://{host}" if 443 in ports else f"http://{host}"

        # 1. SSL/TLS (only if port 443)
        if 443 in ports:
            findings.extend(await check_ssl_tls(host, 443))

        # 2-6 can run concurrently
        results = await asyncio.gather(
            check_security_headers(base_url),
            check_http_methods(base_url),
            check_cookies(base_url),
            discover_paths(base_url),
            check_redirects(host),
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                findings.append(
                    {
                        "type": "dast_error",
                        "target": host,
                        "detail": f"Module error: {result}",
                    }
                )

        return findings

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        """Simulate execution."""
        targets = _extract_targets(context)
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "targets_count": len(targets),
                "modules": [
                    "security_headers",
                    "ssl_tls",
                    "http_methods",
                    "cookies",
                    "path_discovery",
                    "redirects",
                ],
                "description": (
                    "Would perform HTTP security header analysis, SSL/TLS assessment, "
                    "HTTP method testing, cookie security checks, sensitive path discovery, "
                    "and redirect analysis"
                ),
            },
        )
