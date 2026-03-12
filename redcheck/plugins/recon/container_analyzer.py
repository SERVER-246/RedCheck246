"""RedCheck246 — Container Environment Analyzer.

Analyzes container environment configurations for security
misconfigurations including privileged mode, host networking,
Docker socket exposure, missing security profiles, and
excessive Linux capabilities.

Operates on the local Docker daemon only. Does NOT scan remote
container registries or orchestration platforms unless explicitly
configured in the RoE.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import Any

import structlog

from redcheck.models import PluginCapability
from redcheck.plugins.base_plugin import BasePlugin, PluginResult

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Dangerous capabilities and security checks
# ---------------------------------------------------------------------------

_DANGEROUS_CAPS: frozenset[str] = frozenset(
    {
        "CAP_SYS_ADMIN",
        "CAP_NET_RAW",
        "CAP_SYS_PTRACE",
        "CAP_DAC_OVERRIDE",
        "CAP_NET_ADMIN",
    }
)

_CONTAINER_INDICATORS = (
    ("/proc/1/cgroup", "docker"),
    ("/proc/1/cgroup", "containerd"),
    ("/proc/1/cgroup", "lxc"),
)


class ContainerAnalyzer(BasePlugin):
    """Analyze container environment configurations.

    Modules:
    1. Environment detection (cgroup, .dockerenv, env vars)
    2. Configuration analysis (via Docker socket API)
    3. Boundary mapping (network topology)
    4. Misconfiguration detection (privileged, caps, etc.)
    """

    name = "container-analyzer"
    version = "0.1.0"
    description = "Analyze container environment configurations"
    requires_authorization = True
    category = "recon"
    capability = PluginCapability.ACTIVE

    required_controls: list[str] = ["allow_auth_testing"]
    timeout_seconds = 120
    rate_limit_rps = 10
    mitre_techniques = ["T1610", "T1611", "T1613"]
    requires_isolation = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return asyncio.run(self.aexecute(context))

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        target = "localhost"
        if isinstance(context.get("targets"), list) and context["targets"]:
            target = context["targets"][0]

        # Module 1: Environment Detection
        env_info = self._detect_container_env()
        findings.append(
            {
                "finding_type": "container_env_detected",
                "target": target,
                "severity": "info",
                "detail": (
                    f"Container environment: "
                    f"{'containerized' if env_info['is_containerized'] else 'bare-metal/VM'}"
                ),
                "metadata": env_info,
            }
        )

        # Module 2-4: Container analysis (from context or upstream)
        containers = context.get("containers", [])
        if not containers:
            # Try to parse container info from upstream findings
            upstream = context.get("upstream_findings", [])
            containers = self._extract_containers_from_upstream(upstream)

        for container in containers:
            container_findings = self._analyze_container(container, target)
            findings.extend(container_findings)

        # Module 3: Boundary mapping
        if containers:
            boundary = self._map_boundaries(containers)
            findings.append(
                {
                    "finding_type": "container_boundary_map",
                    "target": target,
                    "severity": "info",
                    "detail": (
                        f"Container network boundary: "
                        f"{boundary['network_count']} network(s), "
                        f"{boundary['container_count']} container(s)"
                    ),
                    "metadata": boundary,
                }
            )

        duration_ms = (time.monotonic() - start) * 1000
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
            metadata={
                "duration_ms": round(duration_ms, 2),
                "containers_analyzed": len(containers),
                "is_containerized": env_info["is_containerized"],
            },
        )

    def _detect_container_env(self) -> dict[str, Any]:
        """Detect if running inside a container."""
        indicators: dict[str, bool] = {
            "dockerenv_file": Path("/.dockerenv").exists(),
            "container_env": os.environ.get("CONTAINER") is not None,
            "docker_socket": Path("/var/run/docker.sock").exists(),
        }

        # Check cgroup for container runtime indicators
        cgroup_path = Path("/proc/1/cgroup")
        if cgroup_path.exists():
            try:
                content = cgroup_path.read_text()
                indicators["cgroup_docker"] = "docker" in content
                indicators["cgroup_containerd"] = "containerd" in content
            except (PermissionError, OSError):
                indicators["cgroup_docker"] = False
                indicators["cgroup_containerd"] = False
        else:
            indicators["cgroup_docker"] = False
            indicators["cgroup_containerd"] = False

        return {
            "is_containerized": any(indicators.values()),
            "indicators": indicators,
        }

    @staticmethod
    def _extract_containers_from_upstream(
        upstream: list[Any],
    ) -> list[dict[str, Any]]:
        """Extract container config from upstream findings if available."""
        containers: list[dict[str, Any]] = []
        for f in upstream:
            meta = f.get("metadata", {}) if isinstance(f, dict) else getattr(f, "metadata", {})
            if "container_config" in meta:
                containers.append(meta["container_config"])
        return containers

    def _analyze_container(
        self,
        container: dict[str, Any],
        target: str,
    ) -> list[dict[str, Any]]:
        """Analyze a single container configuration for misconfigurations."""
        findings: list[dict[str, Any]] = []
        name = container.get("name", "unknown")

        # Check: Privileged mode
        if container.get("privileged", False):
            findings.append(
                {
                    "finding_type": "container_privileged",
                    "target": target,
                    "severity": "critical",
                    "detail": f"Container '{name}' runs in privileged mode",
                    "metadata": {"container_name": name, "privileged": True},
                }
            )

        # Check: Host network
        network_mode = container.get("network_mode", "")
        if network_mode == "host":
            findings.append(
                {
                    "finding_type": "container_host_network",
                    "target": target,
                    "severity": "high",
                    "detail": f"Container '{name}' uses host network namespace",
                    "metadata": {"container_name": name, "network_mode": "host"},
                }
            )

        # Check: Docker socket mount
        volumes = container.get("volumes", [])
        for vol in volumes:
            vol_src = vol if isinstance(vol, str) else vol.get("source", "")
            if "/var/run/docker.sock" in vol_src:
                findings.append(
                    {
                        "finding_type": "container_socket_mount",
                        "target": target,
                        "severity": "critical",
                        "detail": f"Container '{name}' has Docker socket mounted",
                        "metadata": {"container_name": name, "volume": vol_src},
                    }
                )

        # Check: Security profile
        security_opt = container.get("security_opt", [])
        if not security_opt:
            findings.append(
                {
                    "finding_type": "container_no_secprofile",
                    "target": target,
                    "severity": "medium",
                    "detail": f"Container '{name}' has no security profile (AppArmor/seccomp)",
                    "metadata": {"container_name": name, "security_opt": []},
                }
            )

        # Check: Writable rootfs
        if not container.get("read_only_rootfs", False):
            findings.append(
                {
                    "finding_type": "container_writable_rootfs",
                    "target": target,
                    "severity": "medium",
                    "detail": f"Container '{name}' has writable root filesystem",
                    "metadata": {"container_name": name, "read_only_rootfs": False},
                }
            )

        # Check: Excessive capabilities
        caps = set(container.get("cap_add", []))
        dangerous = caps & _DANGEROUS_CAPS
        if dangerous:
            findings.append(
                {
                    "finding_type": "container_excessive_caps",
                    "target": target,
                    "severity": "high",
                    "detail": (
                        f"Container '{name}' has dangerous capabilities: {sorted(dangerous)}"
                    ),
                    "metadata": {
                        "container_name": name,
                        "dangerous_capabilities": sorted(dangerous),
                    },
                }
            )

        return findings

    @staticmethod
    def _map_boundaries(containers: list[dict[str, Any]]) -> dict[str, Any]:
        """Map container network boundaries."""
        networks: set[str] = set()
        host_network_containers: list[str] = []

        for c in containers:
            name = c.get("name", "unknown")
            net_mode = c.get("network_mode", "bridge")
            if net_mode == "host":
                host_network_containers.append(name)
            networks.add(net_mode)

            # Check for additional networks
            for net in c.get("networks", []):
                networks.add(net if isinstance(net, str) else net.get("name", ""))

        return {
            "network_count": len(networks),
            "container_count": len(containers),
            "networks": sorted(networks),
            "host_network_containers": host_network_containers,
        }
