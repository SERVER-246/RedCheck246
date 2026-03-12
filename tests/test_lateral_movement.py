"""Tests for the Lateral Movement Analyzer plugin.

Covers:
- Trust relationship analysis (shared ports between hosts)
- Credential reuse risk assessment (breach + auth cross-reference)
- Network segmentation assessment (management ports, flat network)
- Empty / edge-case inputs
"""

from __future__ import annotations

import pytest

from redcheck.plugins.base_plugin import PluginRegistry, PluginResult

# Import triggers auto-registration via __init_subclass__
from redcheck.plugins.recon.lateral_movement import (
    _MANAGEMENT_PORTS,
    LateralMovementAnalyzer,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    PluginRegistry.clear()
    PluginRegistry.register(LateralMovementAnalyzer)
    yield
    PluginRegistry.clear()


@pytest.fixture
def plugin() -> LateralMovementAnalyzer:
    return LateralMovementAnalyzer()


# ---------------------------------------------------------------------------
# Registration & metadata
# ---------------------------------------------------------------------------


class TestLateralMovementRegistration:
    def test_auto_registers(self) -> None:
        assert PluginRegistry.get("lateral-movement-analyzer") is LateralMovementAnalyzer

    def test_name_and_version(self, plugin: LateralMovementAnalyzer) -> None:
        assert plugin.name == "lateral-movement-analyzer"
        assert plugin.version == "0.1.0"

    def test_mitre_techniques(self, plugin: LateralMovementAnalyzer) -> None:
        assert set(plugin.mitre_techniques) == {"T1021", "T1550", "T1078"}

    def test_required_controls(self, plugin: LateralMovementAnalyzer) -> None:
        assert plugin.required_controls == ["allow_auth_testing"]


# ---------------------------------------------------------------------------
# Execute — empty / minimal inputs
# ---------------------------------------------------------------------------


class TestLateralMovementEmpty:
    def test_no_upstream_no_targets(self, plugin: LateralMovementAnalyzer) -> None:
        result = plugin.execute({})
        assert isinstance(result, PluginResult)
        assert result.success
        assert result.findings == []

    def test_targets_only(self, plugin: LateralMovementAnalyzer) -> None:
        result = plugin.execute({"targets": ["10.0.0.1"]})
        assert result.success
        # Only segmentation module can fire (but single host → no flat network)
        assert result.metadata["hosts_analyzed"] == 1


# ---------------------------------------------------------------------------
# Module 1: Trust Relationship Analysis
# ---------------------------------------------------------------------------


class TestTrustRelationships:
    def test_shared_ports_create_trust_finding(self, plugin: LateralMovementAnalyzer) -> None:
        upstream = [
            {"finding_type": "open_port", "target": "10.0.0.1", "metadata": {"port": 80}},
            {"finding_type": "open_port", "target": "10.0.0.1", "metadata": {"port": 443}},
            {"finding_type": "open_port", "target": "10.0.0.2", "metadata": {"port": 80}},
            {"finding_type": "open_port", "target": "10.0.0.2", "metadata": {"port": 22}},
        ]
        result = plugin.execute({"upstream_findings": upstream})
        trust = [f for f in result.findings if f["finding_type"] == "lateral_trust_relationship"]
        assert len(trust) == 1
        assert 80 in trust[0]["metadata"]["shared_ports"]

    def test_no_shared_ports_no_trust(self, plugin: LateralMovementAnalyzer) -> None:
        upstream = [
            {"finding_type": "open_port", "target": "10.0.0.1", "metadata": {"port": 80}},
            {"finding_type": "open_port", "target": "10.0.0.2", "metadata": {"port": 22}},
        ]
        result = plugin.execute({"upstream_findings": upstream})
        trust = [f for f in result.findings if f["finding_type"] == "lateral_trust_relationship"]
        assert len(trust) == 0

    def test_multiple_hosts_with_shared_ports(self, plugin: LateralMovementAnalyzer) -> None:
        upstream = [
            {"finding_type": "open_port", "target": "10.0.0.1", "metadata": {"port": 80}},
            {"finding_type": "open_port", "target": "10.0.0.2", "metadata": {"port": 80}},
            {"finding_type": "open_port", "target": "10.0.0.3", "metadata": {"port": 80}},
        ]
        result = plugin.execute({"upstream_findings": upstream})
        trust = [f for f in result.findings if f["finding_type"] == "lateral_trust_relationship"]
        # 3 hosts with shared port 80 → 3 pairs: (1,2), (1,3), (2,3)
        assert len(trust) == 3


# ---------------------------------------------------------------------------
# Module 2: Credential Reuse Risk
# ---------------------------------------------------------------------------


class TestCredentialReuse:
    def test_breach_and_weak_auth_overlap(self, plugin: LateralMovementAnalyzer) -> None:
        upstream = [
            {"finding_type": "breached_password", "target": "host-a", "metadata": {}},  # nosec B105
            {"finding_type": "weak_credentials", "target": "host-a", "metadata": {}},
        ]
        result = plugin.execute({"upstream_findings": upstream})
        cred = [f for f in result.findings if f["finding_type"] == "lateral_credential_reuse"]
        assert len(cred) == 1
        assert cred[0]["severity"] == "high"
        assert cred[0]["target"] == "host-a"

    def test_breach_only_generates_pivot(self, plugin: LateralMovementAnalyzer) -> None:
        upstream = [
            {"finding_type": "breached_password", "target": "host-b", "metadata": {}},  # nosec B105
        ]
        result = plugin.execute({"upstream_findings": upstream, "targets": ["host-b"]})
        pivot = [f for f in result.findings if f["finding_type"] == "lateral_pivot_path"]
        assert len(pivot) == 1
        assert pivot[0]["metadata"]["pivot_risk"] is True

    def test_no_breach_no_credential_findings(self, plugin: LateralMovementAnalyzer) -> None:
        upstream = [
            {"finding_type": "open_port", "target": "10.0.0.1", "metadata": {"port": 80}},
        ]
        result = plugin.execute({"upstream_findings": upstream})
        cred = [
            f
            for f in result.findings
            if f["finding_type"] in {"lateral_credential_reuse", "lateral_pivot_path"}
        ]
        assert len(cred) == 0


# ---------------------------------------------------------------------------
# Module 3: Network Segmentation
# ---------------------------------------------------------------------------


class TestSegmentation:
    def test_management_ports_detected(self, plugin: LateralMovementAnalyzer) -> None:
        upstream = [
            {"finding_type": "open_port", "target": "10.0.0.1", "metadata": {"port": 22}},
            {"finding_type": "open_port", "target": "10.0.0.1", "metadata": {"port": 3389}},
        ]
        result = plugin.execute({"upstream_findings": upstream})
        mgmt = [f for f in result.findings if f["finding_type"] == "lateral_management_exposure"]
        assert len(mgmt) == 1
        assert 22 in mgmt[0]["metadata"]["management_ports"]
        assert 3389 in mgmt[0]["metadata"]["management_ports"]

    def test_non_management_ports_ignored(self, plugin: LateralMovementAnalyzer) -> None:
        upstream = [
            {"finding_type": "open_port", "target": "10.0.0.1", "metadata": {"port": 80}},
            {"finding_type": "open_port", "target": "10.0.0.1", "metadata": {"port": 443}},
        ]
        result = plugin.execute({"upstream_findings": upstream})
        mgmt = [f for f in result.findings if f["finding_type"] == "lateral_management_exposure"]
        assert len(mgmt) == 0

    def test_flat_network_detected_same_subnet(self, plugin: LateralMovementAnalyzer) -> None:
        upstream = [
            {"finding_type": "open_port", "target": "10.0.0.1", "metadata": {"port": 80}},
            {"finding_type": "open_port", "target": "10.0.0.2", "metadata": {"port": 80}},
        ]
        result = plugin.execute({"upstream_findings": upstream})
        flat = [f for f in result.findings if f["finding_type"] == "lateral_flat_network"]
        assert len(flat) == 1
        assert flat[0]["severity"] == "high"

    def test_different_subnets_no_flat_network(self, plugin: LateralMovementAnalyzer) -> None:
        upstream = [
            {"finding_type": "open_port", "target": "10.0.0.1", "metadata": {"port": 80}},
            {"finding_type": "open_port", "target": "10.1.0.1", "metadata": {"port": 80}},
        ]
        result = plugin.execute({"upstream_findings": upstream})
        flat = [f for f in result.findings if f["finding_type"] == "lateral_flat_network"]
        assert len(flat) == 0

    def test_management_ports_constant(self) -> None:
        assert 22 in _MANAGEMENT_PORTS
        assert 3389 in _MANAGEMENT_PORTS
        assert 5985 in _MANAGEMENT_PORTS
        assert 445 in _MANAGEMENT_PORTS

    def test_detect_subnets_with_hostnames(self) -> None:
        subnets = LateralMovementAnalyzer._detect_subnets({"web.example.com", "db.example.com"})
        # Hostnames get hash-based pseudo-subnets — each is different
        assert all(s.startswith("dns:") for s in subnets)


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------


class TestLateralMovementDryRun:
    def test_dry_run_succeeds(self, plugin: LateralMovementAnalyzer) -> None:
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata.get("mode") == "dry-run"
