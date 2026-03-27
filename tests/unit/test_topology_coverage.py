"""Tests for redcheck.core.topology — cover UnionFind, infer_os, infer_subnets."""

from __future__ import annotations

import pytest

from redcheck.core.topology import HostNode, SubnetCluster, TopologyEngine, _UnionFind


class TestUnionFind:
    def test_single_element(self):
        uf = _UnionFind()
        assert uf.find("a") == "a"

    def test_union_two_elements(self):
        uf = _UnionFind()
        uf.union("a", "b")
        assert uf.find("a") == uf.find("b")

    def test_groups(self):
        uf = _UnionFind()
        uf.union("a", "b")
        uf.union("c", "d")
        groups = uf.groups()
        assert len(groups) == 2
        # a and b in same group
        root_a = uf.find("a")
        assert "a" in groups[root_a]
        assert "b" in groups[root_a]

    def test_transitive_union(self):
        uf = _UnionFind()
        uf.union("a", "b")
        uf.union("b", "c")
        assert uf.find("a") == uf.find("c")

    def test_union_same_element(self):
        uf = _UnionFind()
        uf.find("a")
        uf.union("a", "a")
        assert uf.find("a") == "a"

    def test_rank_balancing(self):
        uf = _UnionFind()
        uf.union("a", "b")
        uf.union("c", "d")
        uf.union("a", "c")
        # All 4 in one group
        roots = {uf.find(x) for x in "abcd"}
        assert len(roots) == 1


class TestHostNode:
    def test_to_dict(self):
        node = HostNode(
            address="192.168.1.1",
            hostname="web1",
            os_guess="Linux",
            os_confidence=0.8,
            open_ports=[22, 80],
            services={22: "ssh", 80: "http"},
            ttl=64,
            banner="OpenSSH",
        )
        d = node.to_dict()
        assert d["address"] == "192.168.1.1"
        assert d["hostname"] == "web1"
        assert d["ttl"] == 64
        assert 22 in d["open_ports"]

    def test_defaults(self):
        node = HostNode(address="10.0.0.1")
        assert node.hostname is None
        assert node.open_ports == []
        assert node.services == {}


class TestSubnetCluster:
    def test_to_dict(self):
        h = HostNode(address="10.0.0.1")
        sc = SubnetCluster(network="10.0.0.0/24", hosts=[h], gateway="10.0.0.1")
        d = sc.to_dict()
        assert d["network"] == "10.0.0.0/24"
        assert d["host_count"] == 1
        assert d["gateway"] == "10.0.0.1"


class TestTopologyEngine:
    def test_add_host_and_count(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="10.0.0.1"))
        assert engine.host_count == 1

    def test_add_hosts(self):
        engine = TopologyEngine()
        engine.add_hosts([HostNode(address="10.0.0.1"), HostNode(address="10.0.0.2")])
        assert engine.host_count == 2

    def test_get_host(self):
        engine = TopologyEngine()
        node = HostNode(address="10.0.0.1", hostname="web")
        engine.add_host(node)
        assert engine.get_host("10.0.0.1") is node
        assert engine.get_host("10.0.0.99") is None

    def test_infer_subnets_same_network(self):
        engine = TopologyEngine()
        engine.add_hosts(
            [
                HostNode(address="192.168.1.1"),
                HostNode(address="192.168.1.2"),
                HostNode(address="192.168.1.3"),
            ]
        )
        subnets = engine.infer_subnets()
        assert len(subnets) == 1
        assert len(subnets[0].hosts) == 3

    def test_infer_subnets_different_networks(self):
        engine = TopologyEngine()
        engine.add_hosts(
            [
                HostNode(address="10.0.1.1"),
                HostNode(address="10.0.2.1"),
            ]
        )
        subnets = engine.infer_subnets()
        assert len(subnets) == 2

    def test_infer_subnets_non_ip_skipped(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="not-an-ip"))
        subnets = engine.infer_subnets()
        assert subnets == []


class TestInferOS:
    def test_unknown_host(self):
        engine = TopologyEngine()
        os_name, conf = engine.infer_os("10.0.0.99")
        assert os_name == "unknown"
        assert conf == 0.0

    def test_linux_ttl(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="10.0.0.1", ttl=64))
        os_name, conf = engine.infer_os("10.0.0.1")
        assert os_name == "Linux/Unix"
        assert conf == 0.4

    def test_windows_ttl(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="10.0.0.1", ttl=128))
        os_name, conf = engine.infer_os("10.0.0.1")
        assert os_name == "Windows"
        assert conf == 0.4

    def test_network_device_ttl(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="10.0.0.1", ttl=255))
        os_name, conf = engine.infer_os("10.0.0.1")
        assert os_name == "Network Device"
        assert conf == 0.3

    def test_ubuntu_banner(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="10.0.0.1", ttl=64, banner="Ubuntu 22.04"))
        os_name, conf = engine.infer_os("10.0.0.1")
        assert os_name == "Linux (Debian/Ubuntu)"
        assert conf == 0.8

    def test_centos_banner(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="10.0.0.1", ttl=64, banner="CentOS 7"))
        os_name, conf = engine.infer_os("10.0.0.1")
        assert os_name == "Linux (RHEL/CentOS)"

    def test_windows_banner(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="10.0.0.1", ttl=128, banner="Microsoft IIS 10"))
        os_name, conf = engine.infer_os("10.0.0.1")
        assert os_name == "Windows Server"

    def test_nginx_banner_with_linux_ttl(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="10.0.0.1", ttl=64, banner="nginx/1.24"))
        os_name, conf = engine.infer_os("10.0.0.1")
        assert os_name == "Linux/Unix"
        assert conf == pytest.approx(0.6)  # 0.4 (ttl) + 0.2 (nginx)

    def test_nginx_banner_no_ttl(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="10.0.0.1", banner="nginx/1.24"))
        os_name, conf = engine.infer_os("10.0.0.1")
        assert os_name == "Linux/Unix"
        assert conf == 0.2

    def test_no_ttl_no_banner(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="10.0.0.1"))
        os_name, conf = engine.infer_os("10.0.0.1")
        assert os_name == "unknown"
        assert conf == 0.0

    def test_debian_banner(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="10.0.0.1", banner="Debian GNU/Linux"))
        os_name, conf = engine.infer_os("10.0.0.1")
        assert os_name == "Linux (Debian/Ubuntu)"

    def test_red_hat_banner(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="10.0.0.1", banner="Red Hat Enterprise"))
        os_name, conf = engine.infer_os("10.0.0.1")
        assert os_name == "Linux (RHEL/CentOS)"

    def test_apache_banner(self):
        engine = TopologyEngine()
        engine.add_host(HostNode(address="10.0.0.1", ttl=64, banner="Apache/2.4"))
        os_name, conf = engine.infer_os("10.0.0.1")
        assert os_name == "Linux/Unix"
        assert conf == pytest.approx(0.6)


class TestTopologyEngineToDict:
    def test_to_dict(self):
        engine = TopologyEngine()
        engine.add_hosts(
            [
                HostNode(address="192.168.1.1", ttl=64),
                HostNode(address="192.168.1.2", ttl=128),
            ]
        )
        d = engine.to_dict()
        assert d["total_hosts"] == 2
        assert "subnets" in d
        assert "hosts" in d
        assert "192.168.1.1" in d["hosts"]
