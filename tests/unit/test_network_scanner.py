"""Tests for Module 2.1 — Network & Infrastructure Discovery.

Covers: NetworkScanner, PacketCraft, TopologyEngine, ServiceVersionDetector.
Target: ≥ 35 tests.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from redcheck.constants import (
    PACKET_MAX_PAYLOAD_BYTES,
    PACKET_MAX_REPEAT,
)
from redcheck.core.topology import HostNode, SubnetCluster, TopologyEngine, _UnionFind
from redcheck.models import PluginCapability
from redcheck.plugins.recon.network_scan import (
    NetworkScanner,
    ServiceVersionDetector,
    _load_fingerprints,
)
from redcheck.plugins.recon.packet_craft import PacketCraft

# ═══════════════════════════════════════════════════════════════════
# PacketCraft
# ═══════════════════════════════════════════════════════════════════


class TestPacketCraftValidation:
    """Test PacketCraft hard-limit enforcement."""

    def test_payload_within_limit(self) -> None:
        pkt = PacketCraft()
        pkt.validate_payload(b"A" * 100)  # should not raise

    def test_payload_at_exact_limit(self) -> None:
        pkt = PacketCraft()
        pkt.validate_payload(b"A" * PACKET_MAX_PAYLOAD_BYTES)

    def test_payload_exceeds_limit(self) -> None:
        pkt = PacketCraft()
        with pytest.raises(ValueError, match="exceeds hard limit"):
            pkt.validate_payload(b"A" * (PACKET_MAX_PAYLOAD_BYTES + 1))

    def test_repeat_valid(self) -> None:
        PacketCraft.validate_repeat(1)
        PacketCraft.validate_repeat(PACKET_MAX_REPEAT)

    def test_repeat_zero(self) -> None:
        with pytest.raises(ValueError, match="must be >= 1"):
            PacketCraft.validate_repeat(0)

    def test_repeat_exceeds_limit(self) -> None:
        with pytest.raises(ValueError, match="exceeds hard limit"):
            PacketCraft.validate_repeat(PACKET_MAX_REPEAT + 1)

    def test_repeat_negative(self) -> None:
        with pytest.raises(ValueError, match="must be >= 1"):
            PacketCraft.validate_repeat(-1)


class TestPacketCraftSend:
    """Test PacketCraft send operations (mocked network)."""

    @pytest.mark.asyncio
    async def test_tcp_syn_probe_open(self) -> None:
        pkt = PacketCraft(timeout=1.0)
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (AsyncMock(), mock_writer)
            is_open, latency = await pkt.tcp_syn_probe("127.0.0.1", 80)
            assert is_open is True
            assert latency >= 0

    @pytest.mark.asyncio
    async def test_tcp_syn_probe_closed(self) -> None:
        pkt = PacketCraft(timeout=0.1)
        with patch(
            "asyncio.open_connection",
            new_callable=AsyncMock,
            side_effect=OSError("Connection refused"),
        ):
            is_open, latency = await pkt.tcp_syn_probe("127.0.0.1", 9999)
            assert is_open is False
            assert latency >= 0

    @pytest.mark.asyncio
    async def test_tcp_syn_probe_timeout(self) -> None:
        pkt = PacketCraft(timeout=0.01)
        with patch(
            "asyncio.open_connection",
            new_callable=AsyncMock,
            side_effect=asyncio.TimeoutError(),
        ):
            is_open, latency = await pkt.tcp_syn_probe("192.0.2.1", 80)
            assert is_open is False

    @pytest.mark.asyncio
    async def test_bound_send_tcp_success(self) -> None:
        pkt = PacketCraft(timeout=1.0)
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n")
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (mock_reader, mock_writer)
            result = await pkt.bound_send("127.0.0.1", 80, b"GET / HTTP/1.0\r\n\r\n")
            assert result.success is True
            assert len(result.responses) == 1

    @pytest.mark.asyncio
    async def test_bound_send_unsupported_protocol(self) -> None:
        pkt = PacketCraft()
        result = await pkt.bound_send("127.0.0.1", 80, b"data", protocol="sctp")
        assert result.success is False
        assert any("Unsupported" in e for e in result.errors)

    @pytest.mark.asyncio
    async def test_bound_send_payload_too_large(self) -> None:
        pkt = PacketCraft()
        with pytest.raises(ValueError, match="exceeds hard limit"):
            await pkt.bound_send("127.0.0.1", 80, b"A" * (PACKET_MAX_PAYLOAD_BYTES + 1))

    @pytest.mark.asyncio
    async def test_bound_send_repeat_too_high(self) -> None:
        pkt = PacketCraft()
        with pytest.raises(ValueError, match="exceeds hard limit"):
            await pkt.bound_send("127.0.0.1", 80, b"test", repeat=PACKET_MAX_REPEAT + 1)


# ═══════════════════════════════════════════════════════════════════
# ServiceVersionDetector
# ═══════════════════════════════════════════════════════════════════


class TestServiceVersionDetector:
    """Test service fingerprint detection."""

    def test_detect_apache(self) -> None:
        det = ServiceVersionDetector()
        svc, conf = det.detect("Apache/2.4.54 (Ubuntu)")
        assert svc == "Apache HTTP Server"
        assert conf == 1.0

    def test_detect_nginx(self) -> None:
        det = ServiceVersionDetector()
        svc, conf = det.detect("nginx/1.24.0")
        assert svc == "Nginx"
        assert conf == 1.0

    def test_detect_openssh(self) -> None:
        det = ServiceVersionDetector()
        svc, conf = det.detect("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        assert svc == "OpenSSH"
        assert conf == 1.0

    def test_detect_empty_banner_port_default(self) -> None:
        det = ServiceVersionDetector()
        svc, conf = det.detect("", port=22)
        assert svc == "SSH"
        assert conf == 0.3

    def test_detect_empty_banner_no_port(self) -> None:
        det = ServiceVersionDetector()
        svc, conf = det.detect("")
        assert svc == "unknown"
        assert conf == 0.0

    def test_detect_unknown_banner(self) -> None:
        det = ServiceVersionDetector()
        svc, conf = det.detect("CustomServer/1.0")
        # May fall through to port default or unknown
        assert isinstance(svc, str)
        assert 0.0 <= conf <= 1.0

    def test_detect_mysql_banner(self) -> None:
        det = ServiceVersionDetector()
        svc, conf = det.detect("5.7.42-0ubuntu0.18.04.1 MySQL Community Server")
        assert svc == "MySQL"
        assert conf == 1.0

    def test_detect_redis_banner(self) -> None:
        det = ServiceVersionDetector()
        svc, conf = det.detect("$-1\r\nRedis")
        assert conf >= 0.3  # at least port default or banner match

    def test_detect_port_default_http(self) -> None:
        det = ServiceVersionDetector()
        svc, conf = det.detect("", port=80)
        assert svc == "HTTP"
        assert conf == 0.3

    def test_detect_port_default_https(self) -> None:
        det = ServiceVersionDetector()
        svc, conf = det.detect("", port=443)
        assert svc == "HTTPS"
        assert conf == 0.3


# ═══════════════════════════════════════════════════════════════════
# TopologyEngine
# ═══════════════════════════════════════════════════════════════════


class TestUnionFind:
    """Test the internal union-find data structure."""

    def test_single_element(self) -> None:
        uf = _UnionFind()
        assert uf.find("a") == "a"

    def test_union_two(self) -> None:
        uf = _UnionFind()
        uf.union("a", "b")
        assert uf.find("a") == uf.find("b")

    def test_groups(self) -> None:
        uf = _UnionFind()
        uf.union("a", "b")
        uf.union("b", "c")
        uf.union("d", "e")
        groups = uf.groups()
        assert len(groups) == 2
        # a,b,c in one group; d,e in another
        sizes = sorted(len(v) for v in groups.values())
        assert sizes == [2, 3]


class TestTopologyEngine:
    """Test topology inference and OS fingerprinting."""

    def test_add_host(self) -> None:
        topo = TopologyEngine()
        topo.add_host(HostNode(address="10.0.0.1"))
        assert topo.host_count == 1

    def test_add_multiple_hosts(self) -> None:
        topo = TopologyEngine()
        hosts = [HostNode(address=f"10.0.0.{i}") for i in range(1, 6)]
        topo.add_hosts(hosts)
        assert topo.host_count == 5

    def test_get_host(self) -> None:
        topo = TopologyEngine()
        node = HostNode(address="10.0.0.1", hostname="web-01")
        topo.add_host(node)
        result = topo.get_host("10.0.0.1")
        assert result is not None
        assert result.hostname == "web-01"

    def test_get_host_missing(self) -> None:
        topo = TopologyEngine()
        assert topo.get_host("10.0.0.1") is None

    def test_infer_subnets_same_network(self) -> None:
        topo = TopologyEngine()
        for i in range(1, 6):
            topo.add_host(HostNode(address=f"10.0.1.{i}"))
        subnets = topo.infer_subnets(prefix_len=24)
        # All hosts in 10.0.1.0/24 → 1 cluster
        assert len(subnets) == 1
        assert len(subnets[0].hosts) == 5

    def test_infer_subnets_different_networks(self) -> None:
        topo = TopologyEngine()
        for i in range(1, 4):
            topo.add_host(HostNode(address=f"10.0.1.{i}"))
        for i in range(1, 4):
            topo.add_host(HostNode(address=f"10.0.2.{i}"))
        for i in range(1, 4):
            topo.add_host(HostNode(address=f"10.0.3.{i}"))
        subnets = topo.infer_subnets(prefix_len=24)
        # 3 distinct /24 subnets → 3 clusters
        assert len(subnets) == 3

    def test_os_fingerprint_linux_ttl(self) -> None:
        topo = TopologyEngine()
        topo.add_host(HostNode(address="10.0.0.1", ttl=64))
        os_name, conf = topo.infer_os("10.0.0.1")
        assert "linux" in os_name.lower() or "unix" in os_name.lower()
        assert conf > 0

    def test_os_fingerprint_windows_ttl(self) -> None:
        topo = TopologyEngine()
        topo.add_host(HostNode(address="10.0.0.2", ttl=128))
        os_name, conf = topo.infer_os("10.0.0.2")
        assert "windows" in os_name.lower()
        assert conf > 0

    def test_os_fingerprint_banner_boost(self) -> None:
        topo = TopologyEngine()
        topo.add_host(HostNode(address="10.0.0.3", ttl=64, banner="Ubuntu 22.04"))
        os_name, conf = topo.infer_os("10.0.0.3")
        assert "ubuntu" in os_name.lower() or "debian" in os_name.lower()
        assert conf >= 0.8  # TTL (0.4) + banner (0.4)

    def test_os_fingerprint_unknown(self) -> None:
        topo = TopologyEngine()
        topo.add_host(HostNode(address="10.0.0.4"))
        os_name, conf = topo.infer_os("10.0.0.4")
        assert os_name == "unknown"
        assert conf == 0.0

    def test_os_fingerprint_missing_host(self) -> None:
        topo = TopologyEngine()
        os_name, conf = topo.infer_os("10.0.0.99")
        assert os_name == "unknown"
        assert conf == 0.0

    def test_to_dict(self) -> None:
        topo = TopologyEngine()
        topo.add_host(HostNode(address="10.0.0.1", open_ports=[80, 443]))
        result = topo.to_dict()
        assert result["total_hosts"] == 1
        assert "subnets" in result
        assert "hosts" in result


class TestHostNode:
    """Test HostNode serialization."""

    def test_to_dict(self) -> None:
        node = HostNode(
            address="10.0.0.1",
            hostname="web-01",
            open_ports=[80, 443],
            services={80: "HTTP", 443: "HTTPS"},
            ttl=64,
        )
        d = node.to_dict()
        assert d["address"] == "10.0.0.1"
        assert d["hostname"] == "web-01"
        assert d["open_ports"] == [80, 443]
        assert d["ttl"] == 64


class TestSubnetCluster:
    """Test SubnetCluster serialization."""

    def test_to_dict(self) -> None:
        cl = SubnetCluster(
            network="10.0.0.0/24",
            hosts=[HostNode(address="10.0.0.1"), HostNode(address="10.0.0.2")],
        )
        d = cl.to_dict()
        assert d["network"] == "10.0.0.0/24"
        assert d["host_count"] == 2


# ═══════════════════════════════════════════════════════════════════
# NetworkScanner Plugin
# ═══════════════════════════════════════════════════════════════════


class TestNetworkScannerPlugin:
    """Test the NetworkScanner plugin registration and execution."""

    def test_plugin_registered(self) -> None:
        from redcheck.plugins.base_plugin import PluginRegistry

        plugin_cls = PluginRegistry.get("network-scanner")
        assert plugin_cls is not None
        assert plugin_cls.name == "network-scanner"

    def test_plugin_metadata(self) -> None:
        scanner = NetworkScanner()
        assert scanner.capability == PluginCapability.ACTIVE
        assert "allow_auth_testing" in scanner.required_controls
        assert scanner.timeout_seconds == 120
        assert scanner.rate_limit_rps == 10
        assert "T1046" in scanner.mitre_techniques

    def test_health_check(self) -> None:
        scanner = NetworkScanner()
        healthy, msg = scanner.health_check()
        assert healthy is True
        assert msg == "ok"

    def test_dry_run(self) -> None:
        scanner = NetworkScanner()
        ctx = {"authorized_targets": [{"host": "10.0.0.1", "ports": [80]}]}
        result = scanner.dry_run(ctx)
        assert result.success is True
        assert result.metadata["mode"] == "dry-run"

    def test_dry_run_no_targets(self) -> None:
        scanner = NetworkScanner()
        result = scanner.dry_run({})
        assert result.success is True
        assert result.metadata["hosts"] == []

    def test_execute_no_targets(self) -> None:
        scanner = NetworkScanner()
        result = scanner.execute({})
        assert result.success is False
        assert "No targets" in result.errors[0]

    def test_validate_context_empty(self) -> None:
        scanner = NetworkScanner()
        valid, msg = scanner.validate_context({})
        assert valid is False

    def test_repr(self) -> None:
        scanner = NetworkScanner()
        r = repr(scanner)
        assert "network-scanner" in r
        assert "AUTH-REQUIRED" in r


class TestFingerprints:
    """Test fingerprint database loading."""

    def test_load_fingerprints(self) -> None:
        db = _load_fingerprints()
        assert "fingerprints" in db
        assert "port_defaults" in db
        assert len(db["fingerprints"]) > 10
        assert len(db["port_defaults"]) > 10
