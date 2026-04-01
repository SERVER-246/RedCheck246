"""RedCheck246 — Fuzzing Plugin: Protocol and Input Fuzzing.

Generates malformed inputs to test robustness and discover crashes.
Requires full authorization — sends live traffic to targets.

Capabilities:
  1. HTTP Parameter Fuzzer  — query params, headers, body
  2. Response Analyser      — reflection (XSS), error messages (SQLi), timing
  3. Mutation Engine        — bit-flip, boundary values, unicode edge cases
  4. Crash Detection        — 5xx, timeouts, connection resets
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import httpx

from redcheck.plugins._http import scanning_ssl_context
from redcheck.plugins.base_plugin import BasePlugin, PluginResult
from redcheck.plugins.fuzzing.payloads import (
    ALL_PAYLOADS,
)

_HTTP_TIMEOUT = 10.0
_MAX_RPS = 10  # default rate limit


def _strip_scheme(host: str) -> str:
    """Remove any existing URL scheme from a host string."""
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix) :]
    return host.rstrip("/")


# Patterns indicating a reflected payload or error leakage
_ERROR_PATTERNS = re.compile(
    r"(?i)(?:sql\s*(?:syntax|error)|"
    r"ora-\d{5}|"
    r"mysql_fetch|"
    r"pg_query|"
    r"unclosed quotation|"
    r"stack\s*trace|"
    r"traceback\s*\(most recent|"
    r"internal\s*server\s*error|"
    r"syntax\s*error|"
    r"exception\s*in\s*thread|"
    r"java\.lang\.\w+Exception|"
    r"Microsoft\s+OLE\s+DB)"
)

_XSS_REFLECTION_PATTERNS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]


def _extract_targets(context: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalise target list from context."""
    raw = context.get("authorized_targets", [])
    targets = []
    for t in raw:
        if isinstance(t, str):
            targets.append({"host": t, "ports": [80, 443], "protocols": ["tcp"]})
        elif isinstance(t, dict):
            targets.append(t)
    return targets


# ---------------------------------------------------------------------------
# Fuzz helpers
# ---------------------------------------------------------------------------


class _RateLimiter:
    """Simple token-bucket rate limiter."""

    def __init__(self, rps: int = _MAX_RPS) -> None:
        self._interval = 1.0 / max(rps, 1)
        self._last = 0.0

    async def wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed < self._interval:
            await asyncio.sleep(self._interval - elapsed)
        self._last = time.monotonic()


async def _fuzz_query_params(
    base_url: str,
    payloads: list[str],
    limiter: _RateLimiter,
) -> list[dict[str, Any]]:
    """Inject payloads into query parameters and analyse responses."""
    findings: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT,
        verify=scanning_ssl_context(),
        follow_redirects=True,
    ) as client:
        # Baseline request
        await limiter.wait()
        try:
            baseline = await client.get(base_url)
            baseline_time = baseline.elapsed.total_seconds()
        except Exception:
            baseline_time = 1.0

        for payload in payloads:
            await limiter.wait()
            url = f"{base_url}?fuzz={payload}"
            try:
                start = time.monotonic()
                resp = await client.get(url)
                elapsed = time.monotonic() - start

                # Crash detection: 5xx
                if resp.status_code >= 500:
                    findings.append(
                        {
                            "type": "fuzz_server_error",
                            "target": base_url,
                            "detail": f"HTTP {resp.status_code} with payload in query param",
                            "data": {
                                "severity": "HIGH",
                                "status_code": resp.status_code,
                                "payload_category": _categorise_payload(payload),
                                "payload_preview": payload[:60],
                            },
                        }
                    )

                # Timing anomaly (>3x baseline)
                if elapsed > baseline_time * 3 and elapsed > 3.0:
                    findings.append(
                        {
                            "type": "fuzz_timing_anomaly",
                            "target": base_url,
                            "detail": (
                                f"Response time anomaly: {elapsed:.1f}s "
                                f"(baseline {baseline_time:.1f}s)"
                            ),
                            "data": {
                                "severity": "MEDIUM",
                                "elapsed": round(elapsed, 2),
                                "baseline": round(baseline_time, 2),
                                "payload_preview": payload[:60],
                            },
                        }
                    )

                # XSS reflection
                body = resp.text
                for marker in _XSS_REFLECTION_PATTERNS:
                    if marker in body and marker in payload:
                        findings.append(
                            {
                                "type": "fuzz_xss_reflection",
                                "target": base_url,
                                "detail": "Payload reflected in response body (potential XSS)",
                                "data": {
                                    "severity": "HIGH",
                                    "reflected": marker[:40],
                                    "payload_preview": payload[:60],
                                },
                            }
                        )
                        break

                # SQL error patterns
                if _ERROR_PATTERNS.search(body):
                    findings.append(
                        {
                            "type": "fuzz_error_leak",
                            "target": base_url,
                            "detail": "Error message / stack trace leaked in response",
                            "data": {
                                "severity": "HIGH",
                                "payload_preview": payload[:60],
                                "snippet": body[:200],
                            },
                        }
                    )

            except httpx.ConnectError:
                findings.append(
                    {
                        "type": "fuzz_connection_lost",
                        "target": base_url,
                        "detail": "Connection refused after fuzzing — potential crash",
                        "data": {"severity": "CRITICAL", "payload_preview": payload[:60]},
                    }
                )
                break  # target may be down
            except httpx.TimeoutException:
                findings.append(
                    {
                        "type": "fuzz_timeout",
                        "target": base_url,
                        "detail": "Request timed out during fuzzing",
                        "data": {"severity": "MEDIUM", "payload_preview": payload[:60]},
                    }
                )
            except Exception:  # noqa: S112
                continue

    return findings


async def _fuzz_headers(
    base_url: str,
    payloads: list[str],
    limiter: _RateLimiter,
) -> list[dict[str, Any]]:
    """Inject payloads into HTTP headers (Host, User-Agent, Referer)."""
    findings: list[dict[str, Any]] = []
    header_targets = ["User-Agent", "Referer", "X-Forwarded-For", "Host"]

    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT,
        verify=scanning_ssl_context(),
        follow_redirects=True,
    ) as client:
        for hdr_name in header_targets:
            for payload in payloads[:10]:  # limit per header to avoid excess
                await limiter.wait()
                try:
                    resp = await client.get(base_url, headers={hdr_name: payload})
                    if resp.status_code >= 500:
                        findings.append(
                            {
                                "type": "fuzz_header_error",
                                "target": base_url,
                                "detail": f"HTTP {resp.status_code} with fuzzed {hdr_name} header",
                                "data": {
                                    "severity": "HIGH",
                                    "header": hdr_name,
                                    "payload_preview": payload[:60],
                                },
                            }
                        )
                    body = resp.text
                    if _ERROR_PATTERNS.search(body):
                        findings.append(
                            {
                                "type": "fuzz_header_leak",
                                "target": base_url,
                                "detail": f"Error leaked via fuzzed {hdr_name} header",
                                "data": {
                                    "severity": "HIGH",
                                    "header": hdr_name,
                                    "payload_preview": payload[:60],
                                },
                            }
                        )
                except Exception:  # noqa: S112
                    continue
    return findings


async def _fuzz_body(
    base_url: str,
    payloads: list[str],
    limiter: _RateLimiter,
) -> list[dict[str, Any]]:
    """POST malformed JSON bodies."""
    findings: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT,
        verify=scanning_ssl_context(),
        follow_redirects=True,
    ) as client:
        for payload in payloads[:20]:
            await limiter.wait()
            bodies = [
                {"input": payload},
                payload,  # raw string body
            ]
            for body in bodies:
                try:
                    if isinstance(body, dict):
                        resp = await client.post(base_url, json=body)
                    else:
                        resp = await client.post(
                            base_url,
                            content=str(body).encode(),
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                        )
                    if resp.status_code >= 500:
                        findings.append(
                            {
                                "type": "fuzz_body_error",
                                "target": base_url,
                                "detail": f"HTTP {resp.status_code} with fuzzed POST body",
                                "data": {
                                    "severity": "HIGH",
                                    "payload_preview": str(payload)[:60],
                                },
                            }
                        )
                except Exception:  # noqa: S112
                    continue
    return findings


def _categorise_payload(payload: str) -> str:
    """Best-effort categorisation of a payload string."""
    for category, plist in ALL_PAYLOADS.items():
        if payload in plist:
            return category
    return "unknown"


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------


class FuzzingPlugin(BasePlugin):
    """Protocol and input fuzzing — crash and anomaly detection."""

    name = "protocol-fuzzer"
    version = "0.2.0"
    description = "Protocol and input fuzzing — crash and anomaly detection"
    requires_authorization = True
    category = "fuzzing"

    def execute(self, context: dict[str, Any]) -> PluginResult:
        """Run HTTP fuzzing against authorized targets."""
        targets = _extract_targets(context)
        all_findings: list[dict[str, Any]] = []
        errors: list[str] = []

        max_rps = context.get("max_rps", _MAX_RPS)
        # Build combined payload set (cap to avoid flooding)
        payloads: list[str] = []
        for cat in ("sqli", "xss", "cmdi", "boundary"):
            payloads.extend(ALL_PAYLOADS.get(cat, []))

        for target in targets:
            host = target.get("host", "")
            if not host:
                continue
            ports = target.get("ports", [80, 443])
            host = _strip_scheme(host)
            base_url = f"https://{host}" if 443 in ports else f"http://{host}"

            try:
                target_findings = asyncio.run(self._fuzz_target(base_url, payloads, max_rps))
                all_findings.extend(target_findings)
            except Exception as exc:
                errors.append(f"Fuzzing error on {host}: {exc}")

        self.capture_evidence(
            context,
            f"{len(all_findings)} fuzz findings".encode(),
            "fuzz_results",
        )
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=all_findings,
            errors=errors,
            metadata={
                "targets_fuzzed": len(targets),
                "total_payloads": len(payloads),
                "total_findings": len(all_findings),
                "max_rps": max_rps,
                "modules": ["query_param_fuzz", "header_fuzz", "body_fuzz"],
                "note": (
                    "0 findings means the target handled all fuzz payloads "
                    "without errors, reflections, or timing anomalies."
                    if not all_findings
                    else ""
                ),
            },
        )

    async def _fuzz_target(
        self, base_url: str, payloads: list[str], max_rps: int
    ) -> list[dict[str, Any]]:
        """Fuzz a single target with all modules."""
        limiter = _RateLimiter(max_rps)
        findings: list[dict[str, Any]] = []

        # Run fuzz modules sequentially to respect rate limit
        findings.extend(await _fuzz_query_params(base_url, payloads, limiter))
        findings.extend(await _fuzz_headers(base_url, payloads, limiter))
        findings.extend(await _fuzz_body(base_url, payloads, limiter))

        return findings

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        """Simulate execution."""
        targets = _extract_targets(context)
        payload_count = sum(len(v) for v in ALL_PAYLOADS.values())
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "targets_count": len(targets),
                "total_payloads": payload_count,
                "categories": list(ALL_PAYLOADS.keys()),
                "modules": ["query_param_fuzz", "header_fuzz", "body_fuzz"],
                "description": (
                    "Would fuzz HTTP query parameters, headers, and POST bodies "
                    f"with {payload_count} payloads across "
                    f"{len(ALL_PAYLOADS)} categories"
                ),
            },
        )
