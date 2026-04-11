"""RedCheck246 — Environment Awareness Pre-flight Probe (Phase N).

Runs before the pipeline to assess network reachability, DNS resolution,
and external dependency availability.  Results are stored in the report
so that plugin failures can be attributed to environment issues rather
than real scan findings.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Any, Literal

import structlog

log = structlog.get_logger(__name__)

_DNS_TIMEOUT = 5
_CONNECT_TIMEOUT = 5


@dataclass
class EnvironmentStatus:
    """Pre-flight environment assessment for a single engagement."""

    network_status: Literal["stable", "degraded", "unreachable"] = "stable"
    dns_resolution: Literal["ok", "partial", "failed"] = "ok"
    target_reachable: bool = True
    external_dependencies: dict[str, Literal["available", "blocked", "unknown"]] = field(
        default_factory=dict
    )
    latency_ms: float | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "network_status": self.network_status,
            "dns_resolution": self.dns_resolution,
            "target_reachable": self.target_reachable,
            "external_dependencies": dict(self.external_dependencies),
            "latency_ms": self.latency_ms,
            "warnings": list(self.warnings),
        }


def _check_dns(hostname: str) -> tuple[bool, list[str]]:
    """Attempt DNS resolution. Returns (success, resolved_ips)."""
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = sorted({info[4][0] for info in infos})
        return True, ips
    except (socket.gaierror, OSError):
        return False, []


def _check_tcp_connect(host: str, port: int = 443) -> tuple[bool, float | None]:
    """Attempt a TCP connection. Returns (success, latency_ms)."""
    try:
        start = time.monotonic()
        sock = socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT)
        latency = (time.monotonic() - start) * 1000
        sock.close()
        return True, round(latency, 2)
    except (OSError, TimeoutError):
        return False, None


def probe_environment(
    targets: list[str],
    external_deps: list[str] | None = None,
) -> EnvironmentStatus:
    """Run pre-flight environment checks.

    Args:
        targets: Engagement target hostnames.
        external_deps: Optional list of external service hostnames
                       (e.g. NVD API, CVE databases) to check.

    Returns:
        EnvironmentStatus with assessment results.
    """
    warnings: list[str] = []
    dns_ok = 0
    dns_total = 0
    reachable = False
    latency: float | None = None

    for target in targets:
        # Strip protocol/port for DNS
        host = target.split("://")[-1].split(":")[0].split("/")[0]
        if not host:
            continue
        dns_total += 1
        ok, ips = _check_dns(host)
        if ok:
            dns_ok += 1
            tcp_ok, tcp_lat = _check_tcp_connect(host)
            if tcp_ok:
                reachable = True
                if latency is None or (tcp_lat is not None and tcp_lat < latency):
                    latency = tcp_lat
            else:
                warnings.append(f"TCP connect failed for {host}")
        else:
            warnings.append(f"DNS resolution failed for {host}")

    # Determine DNS status
    if dns_total == 0:
        dns_status: Literal["ok", "partial", "failed"] = "ok"
    elif dns_ok == dns_total:
        dns_status = "ok"
    elif dns_ok > 0:
        dns_status = "partial"
    else:
        dns_status = "failed"

    # Determine network status
    if dns_status == "failed" or (dns_total > 0 and not reachable):
        network: Literal["stable", "degraded", "unreachable"] = "unreachable"
    elif dns_status == "partial" or warnings:
        network = "degraded"
    else:
        network = "stable"

    # Check external dependencies
    ext_results: dict[str, Literal["available", "blocked", "unknown"]] = {}
    for dep in external_deps or []:
        dep_host = dep.split("://")[-1].split(":")[0].split("/")[0]
        ok, _ = _check_dns(dep_host)
        if ok:
            tcp_ok, _ = _check_tcp_connect(dep_host)
            ext_results[dep] = "available" if tcp_ok else "blocked"
        else:
            ext_results[dep] = "unknown"

    status = EnvironmentStatus(
        network_status=network,
        dns_resolution=dns_status,
        target_reachable=reachable,
        external_dependencies=ext_results,
        latency_ms=latency,
        warnings=warnings,
    )

    log.info(
        "environment_probe_complete",
        network=status.network_status,
        dns=status.dns_resolution,
        reachable=status.target_reachable,
    )
    return status
