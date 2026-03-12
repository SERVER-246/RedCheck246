"""RedCheck246 — Lateral Movement Analyzer.

Analyzes lateral movement potential across discovered hosts by
examining trust relationships, credential reuse risk, and network
segmentation effectiveness.

All analysis is **read-only** — this plugin operates on findings
already collected by upstream plugins (``network-scanner``,
``passive-recon``, ``breach-lookup``, ``auth-session-tester``).
It does NOT make additional network connections.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any

import structlog

from redcheck.models import PluginCapability
from redcheck.plugins.base_plugin import BasePlugin, PluginResult

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Management ports that indicate lateral movement risk
# ---------------------------------------------------------------------------

_MANAGEMENT_PORTS: frozenset[int] = frozenset({22, 3389, 5985, 5986, 23, 445})


class LateralMovementAnalyzer(BasePlugin):
    """Analyze lateral movement potential across discovered hosts.

    Consumes upstream findings to assess:
    1. Trust relationships between hosts (shared services, DNS)
    2. Credential reuse risk (breach data cross-reference)
    3. Network segmentation effectiveness (flat network detection)
    """

    name = "lateral-movement-analyzer"
    version = "0.1.0"
    description = "Analyze lateral movement potential across discovered hosts"
    requires_authorization = True
    category = "recon"
    capability = PluginCapability.ACTIVE

    required_controls: list[str] = ["allow_auth_testing"]
    timeout_seconds = 120
    rate_limit_rps = 10
    mitre_techniques = ["T1021", "T1550", "T1078"]
    requires_isolation = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return asyncio.run(self.aexecute(context))

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        # Extract upstream data
        upstream = context.get("upstream_findings", [])
        targets: list[str] = context.get("targets", [])

        # Build host → port/service map from upstream findings
        host_ports: dict[str, list[int]] = {}
        host_services: dict[str, list[str]] = {}
        breached_hosts: set[str] = set()
        auth_hosts: set[str] = set()

        for f in upstream:
            if isinstance(f, dict):
                ft = f.get("finding_type", "")
                target = f.get("target", "")
                meta = f.get("metadata", {})
            else:
                ft = getattr(f, "finding_type", "")
                target = getattr(f, "target", "")
                meta = getattr(f, "metadata", {})

            if ft == "open_port":
                port = meta.get("port")
                if port is not None:
                    host_ports.setdefault(target, []).append(int(port))
            elif ft in {"dns_record", "subdomain_enum"}:
                host_services.setdefault(target, [])
            elif ft == "breached_password":
                breached_hosts.add(target)
            elif ft == "weak_credentials":
                auth_hosts.add(target)

        # Also add targets that don't have upstream findings yet
        all_hosts = (
            set(host_ports.keys())
            | set(host_services.keys())
            | breached_hosts
            | auth_hosts
            | set(targets)
        )

        if not all_hosts:
            return PluginResult(
                plugin_name=self.name,
                success=True,
                findings=[],
                metadata={"duration_ms": (time.monotonic() - start) * 1000},
            )

        # Module 1: Trust Relationship Analysis
        trust_findings = self._analyze_trust_relationships(host_ports, host_services)
        findings.extend(trust_findings)

        # Module 2: Credential Reuse Risk
        cred_findings = self._assess_credential_reuse(breached_hosts, auth_hosts, all_hosts)
        findings.extend(cred_findings)

        # Module 3: Network Segmentation Assessment
        seg_findings = self._assess_segmentation(host_ports, all_hosts)
        findings.extend(seg_findings)

        duration_ms = (time.monotonic() - start) * 1000
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
            metadata={"duration_ms": round(duration_ms, 2), "hosts_analyzed": len(all_hosts)},
        )

    def _analyze_trust_relationships(
        self,
        host_ports: dict[str, list[int]],
        host_services: dict[str, list[str]],
    ) -> list[dict[str, Any]]:
        """Identify trust relationships between hosts via shared services."""
        findings: list[dict[str, Any]] = []
        hosts = list(host_ports.keys())

        for i, host_a in enumerate(hosts):
            ports_a = set(host_ports.get(host_a, []))
            for host_b in hosts[i + 1 :]:
                ports_b = set(host_ports.get(host_b, []))
                shared = ports_a & ports_b
                if shared:
                    findings.append(
                        {
                            "finding_type": "lateral_trust_relationship",
                            "target": host_a,
                            "severity": "medium",
                            "detail": (
                                f"Hosts {host_a} and {host_b} share "
                                f"{len(shared)} open port(s): {sorted(shared)}"
                            ),
                            "metadata": {
                                "peer_host": host_b,
                                "shared_ports": sorted(shared),
                            },
                        }
                    )

        return findings

    def _assess_credential_reuse(
        self,
        breached_hosts: set[str],
        auth_hosts: set[str],
        all_hosts: set[str],
    ) -> list[dict[str, Any]]:
        """Evaluate credential reuse risk based on breach and auth data."""
        findings: list[dict[str, Any]] = []

        overlap = breached_hosts & auth_hosts
        for host in sorted(overlap):
            findings.append(
                {
                    "finding_type": "lateral_credential_reuse",
                    "target": host,
                    "severity": "high",
                    "detail": (
                        f"Host {host} has both breached credentials and "
                        f"weak authentication — high credential reuse risk"
                    ),
                    "metadata": {"has_breach": True, "has_weak_auth": True},
                }
            )

        # Also flag any breached host with services as potential pivot
        for host in sorted(breached_hosts - overlap):
            if host in all_hosts:
                findings.append(
                    {
                        "finding_type": "lateral_pivot_path",
                        "target": host,
                        "severity": "high",
                        "detail": f"Host {host} has breached credentials — potential pivot point",
                        "metadata": {"has_breach": True, "pivot_risk": True},
                    }
                )

        return findings

    def _assess_segmentation(
        self,
        host_ports: dict[str, list[int]],
        all_hosts: set[str],
    ) -> list[dict[str, Any]]:
        """Evaluate network segmentation effectiveness."""
        findings: list[dict[str, Any]] = []

        # Check management port exposure across hosts
        for host in sorted(host_ports.keys()):
            ports = set(host_ports[host])
            mgmt_exposed = ports & _MANAGEMENT_PORTS
            if mgmt_exposed:
                findings.append(
                    {
                        "finding_type": "lateral_management_exposure",
                        "target": host,
                        "severity": "medium",
                        "detail": (f"Management ports exposed on {host}: {sorted(mgmt_exposed)}"),
                        "metadata": {"management_ports": sorted(mgmt_exposed)},
                    }
                )

        # Flat network detection — if all hosts appear to be in same subnet
        if len(all_hosts) > 1:
            subnets = self._detect_subnets(all_hosts)
            if len(subnets) == 1:
                findings.append(
                    {
                        "finding_type": "lateral_flat_network",
                        "target": next(iter(all_hosts)),
                        "severity": "high",
                        "detail": (
                            f"All {len(all_hosts)} hosts appear to be in the same "
                            f"subnet ({next(iter(subnets))}) — flat network detected"
                        ),
                        "metadata": {
                            "subnet": next(iter(subnets)),
                            "host_count": len(all_hosts),
                        },
                    }
                )

        return findings

    @staticmethod
    def _detect_subnets(hosts: set[str]) -> set[str]:
        """Group hosts into /24 subnets for flat network detection."""
        import ipaddress

        subnets: set[str] = set()
        for host in hosts:
            try:
                ip = ipaddress.ip_address(host)
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                subnets.add(str(net))
            except ValueError:
                # Non-IP hostnames get a hash-based pseudo-subnet
                digest = hashlib.sha256(host.encode()).hexdigest()[:8]
                subnets.add(f"dns:{digest}")
        return subnets
