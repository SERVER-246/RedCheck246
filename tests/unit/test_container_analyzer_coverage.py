"""Tests for redcheck.plugins.recon.container_analyzer — cover _analyze_container etc."""

from __future__ import annotations

from unittest.mock import MagicMock

from redcheck.plugins.recon.container_analyzer import ContainerAnalyzer


class TestAnalyzeContainer:
    """Cover _analyze_container with each misconfiguration type."""

    def setup_method(self):
        self.analyzer = ContainerAnalyzer()
        self.target = "10.0.0.1"

    def test_privileged_container(self):
        container = {"name": "priv", "privileged": True}
        findings = self.analyzer._analyze_container(container, self.target)
        types = [f["finding_type"] for f in findings]
        assert "container_privileged" in types

    def test_host_network(self):
        container = {"name": "hostnet", "network_mode": "host"}
        findings = self.analyzer._analyze_container(container, self.target)
        types = [f["finding_type"] for f in findings]
        assert "container_host_network" in types

    def test_docker_socket_mount(self):
        container = {
            "name": "sock",
            "volumes": ["/var/run/docker.sock"],
        }
        findings = self.analyzer._analyze_container(container, self.target)
        types = [f["finding_type"] for f in findings]
        assert "container_socket_mount" in types

    def test_no_security_profile(self):
        container = {"name": "nosec", "security_opt": []}
        findings = self.analyzer._analyze_container(container, self.target)
        types = [f["finding_type"] for f in findings]
        assert "container_no_secprofile" in types

    def test_writable_rootfs(self):
        container = {"name": "writable", "read_only_rootfs": False}
        findings = self.analyzer._analyze_container(container, self.target)
        types = [f["finding_type"] for f in findings]
        assert "container_writable_rootfs" in types

    def test_dangerous_capabilities(self):
        container = {"name": "caps", "cap_add": ["CAP_SYS_ADMIN", "CAP_NET_RAW"]}
        findings = self.analyzer._analyze_container(container, self.target)
        types = [f["finding_type"] for f in findings]
        assert "container_excessive_caps" in types

    def test_clean_container(self):
        container = {
            "name": "clean",
            "privileged": False,
            "network_mode": "bridge",
            "volumes": [],
            "security_opt": ["apparmor=docker-default"],
            "read_only_rootfs": True,
            "cap_add": [],
        }
        findings = self.analyzer._analyze_container(container, self.target)
        assert findings == []

    def test_all_misconfigs_at_once(self):
        container = {
            "name": "worst",
            "privileged": True,
            "network_mode": "host",
            "volumes": ["/var/run/docker.sock"],
            "security_opt": [],
            "read_only_rootfs": False,
            "cap_add": ["CAP_SYS_ADMIN"],
        }
        findings = self.analyzer._analyze_container(container, self.target)
        types = {f["finding_type"] for f in findings}
        assert "container_privileged" in types
        assert "container_host_network" in types
        assert "container_socket_mount" in types
        assert "container_no_secprofile" in types
        assert "container_writable_rootfs" in types
        assert "container_excessive_caps" in types


class TestExtractContainersFromUpstream:
    def test_dict_findings_with_container_config(self):
        upstream = [
            {"metadata": {"container_config": {"name": "c1", "privileged": True}}},
            {"metadata": {}},
        ]
        containers = ContainerAnalyzer._extract_containers_from_upstream(upstream)
        assert len(containers) == 1
        assert containers[0]["name"] == "c1"

    def test_object_findings(self):
        f = MagicMock()
        f.metadata = {"container_config": {"name": "c2"}}
        containers = ContainerAnalyzer._extract_containers_from_upstream([f])
        assert len(containers) == 1

    def test_empty_upstream(self):
        assert ContainerAnalyzer._extract_containers_from_upstream([]) == []


class TestMapBoundaries:
    def test_basic_mapping(self):
        containers = [
            {"name": "c1", "network_mode": "bridge", "networks": ["frontend"]},
            {"name": "c2", "network_mode": "host", "networks": []},
        ]
        boundary = ContainerAnalyzer._map_boundaries(containers)
        assert boundary["container_count"] == 2
        assert boundary["network_count"] >= 2
        assert "c2" in boundary["host_network_containers"]

    def test_empty_containers(self):
        boundary = ContainerAnalyzer._map_boundaries([])
        assert boundary["container_count"] == 0
        assert boundary["network_count"] == 0

    def test_all_bridge(self):
        containers = [
            {"name": "c1", "network_mode": "bridge", "networks": []},
            {"name": "c2", "network_mode": "bridge", "networks": []},
        ]
        boundary = ContainerAnalyzer._map_boundaries(containers)
        assert boundary["host_network_containers"] == []


class TestDetectContainerEnv:
    def test_returns_dict(self):
        analyzer = ContainerAnalyzer()
        env = analyzer._detect_container_env()
        assert "is_containerized" in env
        assert "indicators" in env
        assert isinstance(env["indicators"], dict)
