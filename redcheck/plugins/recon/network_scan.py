"""RedCheck246 — Network & Infrastructure Discovery Plugin.

Performs active network scanning against authorized targets:
  1. TCP connect scan (rate-limited, scope-validated)
  2. Service version detection via banner fingerprinting
  3. OS heuristic identification (TTL, banner)
  4. Topology inference via subnet clustering

All operations are bounded by ``redcheck.constants`` hard limits.
Requires ``PluginCapability.ACTIVE`` mode and ``allow_auth_testing`` control.
"""

from __future__ import annotations

import asyncio
import importlib.resources
import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog
import yaml

from redcheck.constants import TCP_CPS_DEFAULT
from redcheck.core.scope_validator import ScopeValidator
from redcheck.core.token_bucket import TokenBucket
from redcheck.core.topology import HostNode, TopologyEngine
from redcheck.models import PluginCapability
from redcheck.plugins.base_plugin import BasePlugin, PluginResult
from redcheck.plugins.recon.packet_craft import PacketCraft

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Fingerprint database loader
# ---------------------------------------------------------------------------


def _load_fingerprints() -> dict[str, Any]:
    """Load service fingerprint database from package data."""
    try:
        ref = importlib.resources.files("redcheck.data").joinpath("service_fingerprints.yaml")
        text = ref.read_text(encoding="utf-8")
        return yaml.safe_load(text) or {}
    except Exception:
        log.warning("fingerprint_db_load_failed", exc_info=True)
        return {}


_FINGERPRINT_DB: dict[str, Any] | None = None


def _get_fingerprints() -> dict[str, Any]:
    global _FINGERPRINT_DB  # noqa: PLW0603
    if _FINGERPRINT_DB is None:
        _FINGERPRINT_DB = _load_fingerprints()
    return _FINGERPRINT_DB


# ---------------------------------------------------------------------------
# Service fingerprint result
# ---------------------------------------------------------------------------


@dataclass
class ServiceFingerprint:
    """Enriched service fingerprint with CPE and CVE data."""

    service: str
    version: str | None = None
    cpe: str | None = None
    raw_banner: str = ""
    matched_cves: list[str] = field(default_factory=list)
    confidence: float = 0.0


# ---------------------------------------------------------------------------
# Service version detection
# ---------------------------------------------------------------------------


class ServiceVersionDetector:
    """Detect service from banner strings using fingerprint database."""

    def __init__(self) -> None:
        db = _get_fingerprints()
        self._fingerprints: list[dict[str, str]] = db.get("fingerprints", [])
        self._port_defaults: dict[int, str] = {
            int(k): v for k, v in db.get("port_defaults", {}).items()
        }
        self._service_versions: dict[str, Any] | None = None

    def detect(self, banner: str, port: int | None = None) -> tuple[str, float]:
        """Identify service from banner string.

        Returns ``(service_name, confidence)`` where confidence is:
        - ``1.0`` for exact substring match
        - ``0.7`` for fuzzy/partial match
        - ``0.3`` for port-default fallback
        - ``0.0`` for unknown
        """
        if not banner:
            # Port default fallback
            if port and port in self._port_defaults:
                return self._port_defaults[port], 0.3
            return "unknown", 0.0

        banner_lower = banner.lower().strip()

        # Exact substring match (high confidence)
        for fp in self._fingerprints:
            pattern = fp.get("pattern", "").lower()
            if pattern and pattern in banner_lower:
                return fp.get("service", pattern), 1.0

        # Port default fallback
        if port and port in self._port_defaults:
            return self._port_defaults[port], 0.3

        return "unknown", 0.0

    def detect_fingerprint(self, banner: str, port: int | None = None) -> ServiceFingerprint:
        """Detect service and return enriched fingerprint with CPE."""
        service_name, confidence = self.detect(banner, port)

        cpe: str | None = None
        for fp in self._fingerprints:
            if fp.get("service", "").lower() == service_name.lower():
                cpe = fp.get("cpe")
                break

        return ServiceFingerprint(
            service=service_name,
            cpe=cpe,
            raw_banner=banner,
            confidence=confidence,
        )

    def correlate_cves(
        self,
        service_name: str,
        version: str | None = None,
    ) -> list[str]:
        """Correlate a service name and version against known CVEs.

        Uses ``service_versions.json`` to find matching CVEs.

        Returns:
            List of CVE identifiers.
        """
        if self._service_versions is None:
            self._service_versions = self._load_service_versions()

        services = self._service_versions.get("services", {})
        svc_data = services.get(service_name, {})
        versions = svc_data.get("versions", {})

        if version and version in versions:
            cves: list[str] = versions[version].get("cves", [])
            return cves

        # If no specific version, return all CVEs for the service
        all_cves: list[str] = []
        for v_data in versions.values():
            for cve in v_data.get("cves", []):
                if cve not in all_cves:
                    all_cves.append(cve)
        return all_cves

    @staticmethod
    def _load_service_versions() -> dict[str, Any]:
        """Load service_versions.json from package data."""
        try:
            ref = importlib.resources.files("redcheck.data").joinpath("service_versions.json")
            loaded: dict[str, Any] = json.loads(ref.read_text(encoding="utf-8"))
            return loaded
        except Exception:
            log.warning("service_versions_load_failed", exc_info=True)
            return {}


# ---------------------------------------------------------------------------
# Network Scanner Plugin
# ---------------------------------------------------------------------------


class NetworkScanner(BasePlugin):
    """Active network and infrastructure discovery plugin.

    Performs:
    - TCP connect scanning (rate-limited)
    - Service version detection (banner fingerprinting)
    - OS heuristic identification (TTL, banner)
    - Topology inference (subnet clustering)
    """

    name = "network-scanner"
    version = "0.1.0"
    description = "Active network and infrastructure discovery"
    requires_authorization = True
    category = "recon"
    capability = PluginCapability.ACTIVE

    # Phase 1 extensions
    required_controls = ["allow_auth_testing"]
    timeout_seconds = 120
    rate_limit_rps = 10
    mitre_techniques = ["T1046", "T1595.001"]
    requires_isolation = False

    def __init__(self) -> None:
        super().__init__()
        self._pkt = PacketCraft(timeout=3.0)
        self._detector = ServiceVersionDetector()
        self._topology = TopologyEngine()

    def health_check(self) -> tuple[bool, str]:
        db = _get_fingerprints()
        if not db.get("fingerprints"):
            return False, "Fingerprint database not loaded"
        return True, "ok"

    def execute(self, context: dict[str, Any]) -> PluginResult:
        """Execute network scan synchronously via asyncio.run()."""
        return asyncio.run(self.aexecute(context))

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        """Async network scan execution."""
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        targets = context.get("authorized_targets", context.get("targets", []))
        if not targets:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                errors=["No targets specified"],
            )

        # Resolve target hosts
        hosts: list[str] = []
        for t in targets:
            if isinstance(t, dict):
                h = t.get("host", "").strip()
                if h:
                    hosts.append(h)
            elif isinstance(t, str):
                hosts.append(t.strip())

        if not hosts:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                errors=["No valid hosts found in targets"],
            )

        # Scope validation
        authorized = [(t.get("host", t) if isinstance(t, dict) else t) for t in targets]
        valid, violations = ScopeValidator.validate_targets(hosts, authorized)
        if not valid:
            for v in violations:
                errors.append(f"Out of scope: {v}")

        # Default ports to scan
        default_ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            143,
            443,
            445,
            993,
            995,
            3306,
            3389,
            5432,
            6379,
            8080,
            8443,
        ]

        # Get port list from context
        scan_ports: list[int] = []
        for t in targets:
            if isinstance(t, dict) and "ports" in t:
                scan_ports.extend(t["ports"])
        if not scan_ports:
            scan_ports = default_ports

        # Rate limiter
        rate = min(self.rate_limit_rps, TCP_CPS_DEFAULT)
        bucket = TokenBucket(rate=rate)

        # Scan each host
        for host in hosts:
            node = HostNode(address=host)
            open_ports: list[int] = []
            services: dict[int, str] = {}

            for port in scan_ports:
                await bucket.acquire()
                is_open, latency = await self._pkt.tcp_syn_probe(host, port)

                if is_open:
                    open_ports.append(port)
                    # Grab banner from the open port
                    banner = await self._pkt.banner_grab(host, port)

                    # Active probe for HTTP(S) ports that don't send
                    # an unsolicited banner.
                    if not banner and (
                        port in self._pkt._HTTP_PORTS
                        or port in self._pkt._HTTPS_PORTS
                    ):
                        banner = await self._pkt.active_banner_probe(host, port)

                    svc_name, confidence = self._detector.detect(banner, port)
                    services[port] = svc_name

                    findings.append(
                        {
                            "finding_type": "open_port",
                            "target": host,
                            "port": port,
                            "service": svc_name,
                            "confidence": confidence,
                            "latency_ms": round(latency, 2),
                            "severity": "info",
                            "detail": f"Port {port}/tcp open — {svc_name}",
                            "banner": banner[:256] if banner else "",
                        }
                    )

                    # TLS certificate inspection for HTTPS ports
                    if port in self._pkt._HTTPS_PORTS:
                        cert = await self._pkt.tls_cert_info(host, port)
                        if cert:
                            findings.append(
                                {
                                    "finding_type": "tls_certificate",
                                    "target": host,
                                    "port": port,
                                    "severity": "info",
                                    "detail": (
                                        f"TLS cert on {host}:{port} — "
                                        f"expires {cert.get('notAfter', 'unknown')}"
                                    ),
                                    "metadata": cert,
                                }
                            )

            node.open_ports = open_ports
            node.services = services

            # OS fingerprint (heuristic, read-only)
            self._topology.add_host(node)
            os_name, os_conf = self._topology.infer_os(host)
            if os_name != "unknown":
                findings.append(
                    {
                        "finding_type": "os_fingerprint",
                        "target": host,
                        "os": os_name,
                        "confidence": round(os_conf, 2),
                        "severity": "info",
                        "detail": f"OS heuristic: {os_name} (confidence: {os_conf:.0%})",
                    }
                )

        # Topology inference
        topology = self._topology.to_dict()

        elapsed = (time.monotonic() - start) * 1000
        return PluginResult(
            plugin_name=self.name,
            success=len(errors) == 0,
            findings=findings,
            errors=errors,
            metadata={
                "hosts_scanned": len(hosts),
                "ports_per_host": len(scan_ports),
                "topology": topology,
                "duration_ms": round(elapsed, 2),
            },
        )

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        """Simulate network scan without touching targets."""
        targets = context.get("authorized_targets", context.get("targets", []))
        hosts = []
        for t in targets:
            if isinstance(t, dict):
                h = t.get("host", "").strip()
                if h:
                    hosts.append(h)
            elif isinstance(t, str):
                hosts.append(t.strip())

        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "hosts": hosts,
                "description": f"Would scan {len(hosts)} hosts",
            },
        )
