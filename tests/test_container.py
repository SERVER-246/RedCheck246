"""Tests for the Container Analyzer plugin.

Covers:
- Container environment detection (mocked)
- Misconfiguration detection (privileged, host_network, socket_mount,
  no_secprofile, writable_rootfs, excessive_caps)
- Boundary mapping
- Upstream container extraction
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from redcheck.plugins.base_plugin import PluginRegistry
from redcheck.plugins.recon.container_analyzer import (
    _DANGEROUS_CAPS,
    ContainerAnalyzer,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    PluginRegistry.clear()
    PluginRegistry.register(ContainerAnalyzer)
    yield
    PluginRegistry.clear()


@pytest.fixture
def plugin() -> ContainerAnalyzer:
    return ContainerAnalyzer()


# ---------------------------------------------------------------------------
# Registration & metadata
# ---------------------------------------------------------------------------


class TestContainerRegistration:
    def test_auto_registers(self) -> None:
        assert PluginRegistry.get("container-analyzer") is ContainerAnalyzer

    def test_name_and_version(self, plugin: ContainerAnalyzer) -> None:
        assert plugin.name == "container-analyzer"
        assert plugin.version == "0.1.0"

    def test_mitre_techniques(self, plugin: ContainerAnalyzer) -> None:
        assert set(plugin.mitre_techniques) == {"T1610", "T1611", "T1613"}

    def test_required_controls(self, plugin: ContainerAnalyzer) -> None:
        assert plugin.required_controls == ["allow_auth_testing"]


# ---------------------------------------------------------------------------
# Environment detection (mocked)
# ---------------------------------------------------------------------------


class TestContainerEnvDetection:
    def test_bare_metal(self, plugin: ContainerAnalyzer) -> None:
        """On a typical dev machine, no container indicators → bare-metal."""
        result = plugin.execute({"targets": ["10.0.0.1"]})
        assert result.success
        env = [f for f in result.findings if f["finding_type"] == "container_env_detected"]
        assert len(env) == 1
        # Actual containerized status depends on host — just check structure
        assert "is_containerized" in env[0]["metadata"]

    @patch("redcheck.plugins.recon.container_analyzer.Path")
    @patch("redcheck.plugins.recon.container_analyzer.os.environ", {"CONTAINER": "docker"})
    def test_containerized_via_env(self, mock_path, plugin: ContainerAnalyzer) -> None:
        """When 'container' env var is set, detect containerized."""
        mock_path.return_value.exists.return_value = False
        env_info = plugin._detect_container_env()
        assert env_info["is_containerized"] is True
        assert env_info["indicators"]["container_env"] is True


# ---------------------------------------------------------------------------
# Misconfiguration detection
# ---------------------------------------------------------------------------


def _container(name: str = "test-app", **overrides) -> dict:
    base = {
        "name": name,
        "privileged": False,
        "network_mode": "bridge",
        "volumes": [],
        "security_opt": ["seccomp=default"],
        "read_only_rootfs": True,
        "cap_add": [],
    }
    base.update(overrides)
    return base


class TestPrivilegedMode:
    def test_privileged_detected(self, plugin: ContainerAnalyzer) -> None:
        ctx = {"targets": ["h1"], "containers": [_container(privileged=True)]}
        result = plugin.execute(ctx)
        priv = [f for f in result.findings if f["finding_type"] == "container_privileged"]
        assert len(priv) == 1
        assert priv[0]["severity"] == "critical"

    def test_not_privileged_no_finding(self, plugin: ContainerAnalyzer) -> None:
        ctx = {"targets": ["h1"], "containers": [_container(privileged=False)]}
        result = plugin.execute(ctx)
        priv = [f for f in result.findings if f["finding_type"] == "container_privileged"]
        assert len(priv) == 0


class TestHostNetwork:
    def test_host_network_detected(self, plugin: ContainerAnalyzer) -> None:
        ctx = {"targets": ["h1"], "containers": [_container(network_mode="host")]}
        result = plugin.execute(ctx)
        hn = [f for f in result.findings if f["finding_type"] == "container_host_network"]
        assert len(hn) == 1
        assert hn[0]["severity"] == "high"

    def test_bridge_network_no_finding(self, plugin: ContainerAnalyzer) -> None:
        ctx = {"targets": ["h1"], "containers": [_container(network_mode="bridge")]}
        result = plugin.execute(ctx)
        hn = [f for f in result.findings if f["finding_type"] == "container_host_network"]
        assert len(hn) == 0


class TestSocketMount:
    def test_docker_socket_detected(self, plugin: ContainerAnalyzer) -> None:
        ctx = {
            "targets": ["h1"],
            "containers": [_container(volumes=["/var/run/docker.sock:/var/run/docker.sock"])],
        }
        result = plugin.execute(ctx)
        sock = [f for f in result.findings if f["finding_type"] == "container_socket_mount"]
        assert len(sock) == 1
        assert sock[0]["severity"] == "critical"

    def test_no_socket_no_finding(self, plugin: ContainerAnalyzer) -> None:
        ctx = {"targets": ["h1"], "containers": [_container(volumes=["/data:/data"])]}
        result = plugin.execute(ctx)
        sock = [f for f in result.findings if f["finding_type"] == "container_socket_mount"]
        assert len(sock) == 0


class TestSecurityProfile:
    def test_no_secprofile_detected(self, plugin: ContainerAnalyzer) -> None:
        ctx = {"targets": ["h1"], "containers": [_container(security_opt=[])]}
        result = plugin.execute(ctx)
        sec = [f for f in result.findings if f["finding_type"] == "container_no_secprofile"]
        assert len(sec) == 1
        assert sec[0]["severity"] == "medium"

    def test_with_secprofile_no_finding(self, plugin: ContainerAnalyzer) -> None:
        c = _container(security_opt=["apparmor=docker-default"])
        ctx = {"targets": ["h1"], "containers": [c]}
        result = plugin.execute(ctx)
        sec = [f for f in result.findings if f["finding_type"] == "container_no_secprofile"]
        assert len(sec) == 0


class TestWritableRootfs:
    def test_writable_rootfs_detected(self, plugin: ContainerAnalyzer) -> None:
        ctx = {"targets": ["h1"], "containers": [_container(read_only_rootfs=False)]}
        result = plugin.execute(ctx)
        rw = [f for f in result.findings if f["finding_type"] == "container_writable_rootfs"]
        assert len(rw) == 1
        assert rw[0]["severity"] == "medium"

    def test_readonly_rootfs_no_finding(self, plugin: ContainerAnalyzer) -> None:
        ctx = {"targets": ["h1"], "containers": [_container(read_only_rootfs=True)]}
        result = plugin.execute(ctx)
        rw = [f for f in result.findings if f["finding_type"] == "container_writable_rootfs"]
        assert len(rw) == 0


class TestExcessiveCaps:
    def test_dangerous_caps_detected(self, plugin: ContainerAnalyzer) -> None:
        ctx = {
            "targets": ["h1"],
            "containers": [_container(cap_add=["CAP_SYS_ADMIN", "CAP_NET_RAW"])],
        }
        result = plugin.execute(ctx)
        caps = [f for f in result.findings if f["finding_type"] == "container_excessive_caps"]
        assert len(caps) == 1
        assert caps[0]["severity"] == "high"
        assert "CAP_SYS_ADMIN" in caps[0]["metadata"]["dangerous_capabilities"]

    def test_safe_caps_no_finding(self, plugin: ContainerAnalyzer) -> None:
        ctx = {"targets": ["h1"], "containers": [_container(cap_add=["CAP_CHOWN"])]}
        result = plugin.execute(ctx)
        caps = [f for f in result.findings if f["finding_type"] == "container_excessive_caps"]
        assert len(caps) == 0

    def test_dangerous_caps_constant(self) -> None:
        assert "CAP_SYS_ADMIN" in _DANGEROUS_CAPS
        assert "CAP_NET_RAW" in _DANGEROUS_CAPS
        assert "CAP_SYS_PTRACE" in _DANGEROUS_CAPS


# ---------------------------------------------------------------------------
# Boundary mapping
# ---------------------------------------------------------------------------


class TestBoundaryMapping:
    def test_boundary_map_generated(self, plugin: ContainerAnalyzer) -> None:
        ctx = {
            "targets": ["h1"],
            "containers": [
                _container("app", network_mode="bridge"),
                _container("db", network_mode="internal"),
            ],
        }
        result = plugin.execute(ctx)
        boundary = [f for f in result.findings if f["finding_type"] == "container_boundary_map"]
        assert len(boundary) == 1
        assert boundary[0]["metadata"]["container_count"] == 2
        assert boundary[0]["metadata"]["network_count"] >= 2

    def test_host_network_containers_listed(self, plugin: ContainerAnalyzer) -> None:
        ctx = {"targets": ["h1"], "containers": [_container("web", network_mode="host")]}
        result = plugin.execute(ctx)
        boundary = [f for f in result.findings if f["finding_type"] == "container_boundary_map"]
        assert "web" in boundary[0]["metadata"]["host_network_containers"]


# ---------------------------------------------------------------------------
# Upstream container extraction
# ---------------------------------------------------------------------------


class TestUpstreamExtraction:
    def test_extract_from_upstream_findings(self, plugin: ContainerAnalyzer) -> None:
        upstream = [
            {
                "finding_type": "service_detected",
                "target": "10.0.0.1",
                "metadata": {
                    "container_config": _container("upstream-app", privileged=True),
                },
            },
        ]
        result = plugin.execute({"targets": ["10.0.0.1"], "upstream_findings": upstream})
        priv = [f for f in result.findings if f["finding_type"] == "container_privileged"]
        assert len(priv) == 1


# ---------------------------------------------------------------------------
# Multiple containers
# ---------------------------------------------------------------------------


class TestMultipleContainers:
    def test_all_misconfigs_across_containers(self, plugin: ContainerAnalyzer) -> None:
        containers = [
            _container("risky", privileged=True, network_mode="host"),
            _container("safe"),
        ]
        ctx = {"targets": ["h1"], "containers": containers}
        result = plugin.execute(ctx)
        priv = [f for f in result.findings if f["finding_type"] == "container_privileged"]
        hn = [f for f in result.findings if f["finding_type"] == "container_host_network"]
        assert len(priv) == 1
        assert len(hn) == 1


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------


class TestContainerDryRun:
    def test_dry_run_succeeds(self, plugin: ContainerAnalyzer) -> None:
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata.get("mode") == "dry-run"
