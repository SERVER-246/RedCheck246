"""Tests for InternalNetworkDiscoveryEngine (Phase 7, §25)."""

from __future__ import annotations

import asyncio

import pytest

from redcheck.constants import MAX_DISCOVERY_HOSTS, UDP_DEFAULT_PORTS
from redcheck.plugins.recon.network_discovery import InternalNetworkDiscoveryEngine


@pytest.fixture
def engine() -> InternalNetworkDiscoveryEngine:
    return InternalNetworkDiscoveryEngine()


class TestNetworkDiscoveryBasic:
    """Basic discovery engine tests."""

    def test_plugin_metadata(self, engine: InternalNetworkDiscoveryEngine):
        assert engine.name == "network-discovery"
        assert engine.version == "0.1.0"
        assert engine.requires_authorization is True

    def test_health_check(self, engine: InternalNetworkDiscoveryEngine):
        ok, msg = engine.health_check()
        assert ok is True
        assert msg == "ok"

    def test_dry_run_no_targets(self, engine: InternalNetworkDiscoveryEngine):
        result = engine.dry_run({"targets": []})
        assert result.success is True
        assert result.metadata.get("mode") == "dry-run"

    def test_dry_run_with_targets(self, engine: InternalNetworkDiscoveryEngine):
        result = engine.dry_run({"targets": ["10.0.0.1", "10.0.0.2"]})
        assert result.success is True
        assert len(result.metadata.get("hosts", [])) == 2

    def test_execute_no_targets(self, engine: InternalNetworkDiscoveryEngine):
        result = engine.execute({"targets": []})
        assert result.success is False
        assert "No targets specified" in result.errors

    def test_execute_with_hosts(self, engine: InternalNetworkDiscoveryEngine):
        result = engine.execute(
            {
                "authorized_targets": ["10.0.0.1"],
                "targets": ["10.0.0.1"],
            }
        )
        assert result.success is True
        assert result.metadata.get("hosts_discovered") == 1


class TestAarpScan:
    """ARP scan simulation tests."""

    def test_arp_scan_valid_cidr(self, engine: InternalNetworkDiscoveryEngine):
        hosts = asyncio.run(engine._arp_scan("10.0.0.0/30"))
        # /30 has 2 usable hosts
        assert len(hosts) == 2
        assert "10.0.0.1" in hosts
        assert "10.0.0.2" in hosts

    def test_arp_scan_invalid_cidr(self, engine: InternalNetworkDiscoveryEngine):
        hosts = asyncio.run(engine._arp_scan("not-a-cidr"))
        assert hosts == []

    def test_arp_scan_respects_max_hosts(self, engine: InternalNetworkDiscoveryEngine):
        hosts = asyncio.run(engine._arp_scan("10.0.0.0/16"))
        assert len(hosts) <= MAX_DISCOVERY_HOSTS

    def test_arp_scan_small_subnet(self, engine: InternalNetworkDiscoveryEngine):
        hosts = asyncio.run(engine._arp_scan("10.0.0.0/29"))
        # /29 has 6 usable hosts
        assert len(hosts) == 6


class TestUdpProbe:
    """UDP probe tests."""

    def test_udp_probe_returns_services(self, engine: InternalNetworkDiscoveryEngine):
        results = asyncio.run(engine._udp_probe("10.0.0.1", UDP_DEFAULT_PORTS))
        assert isinstance(results, dict)
        # Port 53 should map to DNS via port_defaults
        assert 53 in results
        assert results[53] == "DNS"

    def test_udp_probe_empty_ports(self, engine: InternalNetworkDiscoveryEngine):
        results = asyncio.run(engine._udp_probe("10.0.0.1", []))
        assert results == {}

    def test_udp_probe_unknown_port(self, engine: InternalNetworkDiscoveryEngine):
        results = asyncio.run(engine._udp_probe("10.0.0.1", [99999]))
        # Port 99999 has no default mapping
        assert 99999 not in results


class TestOsFingerprint:
    """OS fingerprinting tests."""

    def test_os_fingerprint_unknown_host(self, engine: InternalNetworkDiscoveryEngine):
        os_name, confidence = asyncio.run(engine._os_fingerprint("10.0.0.99"))
        assert os_name == "unknown"
        assert confidence == 0.0


class TestExecuteWithCidr:
    """Integration tests with CIDR ranges."""

    def test_execute_with_cidr(self, engine: InternalNetworkDiscoveryEngine):
        result = engine.execute(
            {
                "authorized_targets": ["10.0.0.0/30"],
                "targets": ["10.0.0.0/30"],
            }
        )
        assert result.success is True
        assert result.metadata.get("hosts_discovered", 0) > 0

    def test_execute_scope_enforcement(self, engine: InternalNetworkDiscoveryEngine):
        """Hosts discovered outside authorized scope are excluded."""
        result = engine.execute(
            {
                "authorized_targets": ["10.0.0.0/30"],
                "targets": ["10.0.0.0/30"],
            }
        )
        assert result.success is True
        # All findings should be for in-scope hosts
        for finding in result.findings:
            target = finding.get("target", "")
            assert target.startswith("10.0.0.")

    def test_execute_with_dict_targets(self, engine: InternalNetworkDiscoveryEngine):
        result = engine.execute(
            {
                "authorized_targets": [{"host": "10.0.0.1"}],
                "targets": [{"host": "10.0.0.1"}],
            }
        )
        assert result.success is True

    def test_topology_in_metadata(self, engine: InternalNetworkDiscoveryEngine):
        result = engine.execute(
            {
                "authorized_targets": ["10.0.0.1"],
                "targets": ["10.0.0.1"],
            }
        )
        assert "topology" in result.metadata
        assert "duration_ms" in result.metadata

    def test_udp_findings_generated(self, engine: InternalNetworkDiscoveryEngine):
        result = engine.execute(
            {
                "authorized_targets": ["10.0.0.1"],
                "targets": ["10.0.0.1"],
            }
        )
        udp_findings = [
            f for f in result.findings if f.get("finding_type") == "udp_service_discovered"
        ]
        assert len(udp_findings) > 0
        assert udp_findings[0].get("protocol") == "udp"
