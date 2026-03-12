"""Tests for the Attack Path Correlator (redcheck.core.attack_path_correlator)."""

from __future__ import annotations

import pytest

from redcheck.core.attack_path_correlator import (
    _ASSET_FINDING_TYPES,
    _EDGE_TYPE_MAP,
    _SEVERITY_PROBABILITY,
    AttackPathCorrelator,
)
from redcheck.models import (
    AttackerClass,
    Finding,  # noqa: TC001
    FindingSeverity,
    PluginResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    finding_type: str,
    target: str = "10.0.0.1",
    severity: FindingSeverity = FindingSeverity.HIGH,
    detail: str = "test detail",
    mitre_technique: str | None = None,
    metadata: dict | None = None,
) -> Finding:
    return Finding(
        finding_type=finding_type,
        target=target,
        severity=severity,
        detail=detail,
        mitre_technique=mitre_technique,
        metadata=metadata or {},
    )


def _result(
    plugin_name: str,
    findings: list[Finding] | None = None,
) -> PluginResult:
    return PluginResult(
        plugin_name=plugin_name,
        success=True,
        findings=findings or [],
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestAttackPathCorrelatorInit:
    """Verify correlator construction with various attacker classes."""

    def test_default_init(self) -> None:
        c = AttackPathCorrelator()
        assert c.graph.attacker_class == AttackerClass.AC1

    @pytest.mark.parametrize("ac", list(AttackerClass))
    def test_all_attacker_classes(self, ac: AttackerClass) -> None:
        c = AttackPathCorrelator(attacker_class=ac)
        assert c.graph.attacker_class == ac

    def test_chain_mode_passthrough(self) -> None:
        c = AttackPathCorrelator(chain_mode=True, allow_exploit_validation=True)
        assert c.graph.can_execute_chain()

    def test_no_chain_mode_by_default(self) -> None:
        c = AttackPathCorrelator()
        assert not c.graph.can_execute_chain()


# ---------------------------------------------------------------------------
# Asset ingestion
# ---------------------------------------------------------------------------


class TestAssetIngestion:
    """Verify that asset-type findings create graph nodes."""

    def test_open_port_creates_asset(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "network-scanner": _result(
                "network-scanner",
                [_finding("open_port", "10.0.0.1", metadata={"port": "443"})],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.node_count == 1

    def test_open_port_without_port_metadata(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "network-scanner": _result(
                "network-scanner",
                [_finding("open_port", "10.0.0.1")],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.node_count == 1

    def test_dns_record_creates_asset(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "passive-recon": _result(
                "passive-recon",
                [_finding("dns_record", "example.com")],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.node_count == 1

    def test_subdomain_enum_creates_asset(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "passive-recon": _result(
                "passive-recon",
                [_finding("subdomain_enum", "sub.example.com")],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.node_count == 1

    def test_os_fingerprint_creates_new_asset(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "network-scanner": _result(
                "network-scanner",
                [_finding("os_fingerprint", "10.0.0.1", detail="Linux 5.x")],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.node_count == 1

    def test_os_fingerprint_enriches_existing_asset(self) -> None:
        c = AttackPathCorrelator()
        # First add the host, then enrich
        results1 = {
            "network-scanner": _result(
                "network-scanner",
                [_finding("dns_record", "10.0.0.1")],
            ),
        }
        c.ingest_findings(results1)
        assert c.graph.node_count == 1

        results2 = {
            "network-scanner": _result(
                "network-scanner",
                [_finding("os_fingerprint", "10.0.0.1", detail="Linux 5.x")],
            ),
        }
        c.ingest_findings(results2)
        # Should NOT add a new node — enriches existing
        assert c.graph.node_count == 1

    def test_multiple_hosts(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "network-scanner": _result(
                "network-scanner",
                [
                    _finding("open_port", "10.0.0.1", metadata={"port": "80"}),
                    _finding("open_port", "10.0.0.2", metadata={"port": "443"}),
                ],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.node_count == 2

    def test_duplicate_asset_idempotent(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "passive-recon": _result(
                "passive-recon",
                [
                    _finding("dns_record", "example.com"),
                    _finding("dns_record", "example.com"),
                ],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.node_count == 1


# ---------------------------------------------------------------------------
# Edge ingestion
# ---------------------------------------------------------------------------


class TestEdgeIngestion:
    """Verify that vulnerability findings create graph edges."""

    def test_supply_chain_vuln_creates_edge(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "supply-chain-audit": _result(
                "supply-chain-audit",
                [
                    _finding(
                        "supply_chain_vulnerability",
                        "10.0.0.1",
                        severity=FindingSeverity.CRITICAL,
                    )
                ],
            ),
        }
        c.ingest_findings(results)
        # Creates source asset + target asset + edge
        assert c.graph.node_count == 2
        assert c.graph.edge_count == 1

    def test_dast_sensitive_path_edge(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "dast-scanner": _result(
                "dast-scanner",
                [_finding("dast_sensitive_path", "10.0.0.1")],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.edge_count == 1

    def test_dast_weak_tls_edge(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "dast-scanner": _result(
                "dast-scanner",
                [_finding("dast_weak_tls", "10.0.0.1")],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.edge_count == 1

    def test_sqli_timing_edge(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "injection-poc-simulator": _result(
                "injection-poc-simulator",
                [_finding("sqli_timing", "10.0.0.1", mitre_technique="T1190")],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.edge_count == 1

    def test_xss_reflected_edge(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "injection-poc-simulator": _result(
                "injection-poc-simulator",
                [_finding("xss_reflected", "10.0.0.1", mitre_technique="T1059")],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.edge_count == 1

    def test_weak_credentials_edge_ac4(self) -> None:
        # authz_bypass requires AC2+ or AC4
        c = AttackPathCorrelator(attacker_class=AttackerClass.AC4)
        results = {
            "auth-session-tester": _result(
                "auth-session-tester",
                [_finding("weak_credentials", "10.0.0.1")],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.edge_count == 1

    def test_idor_accessible_edge_ac4(self) -> None:
        c = AttackPathCorrelator(attacker_class=AttackerClass.AC4)
        results = {
            "idor-validator": _result(
                "idor-validator",
                [_finding("idor_accessible", "10.0.0.1")],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.edge_count == 1

    def test_breached_password_edge_ac4(self) -> None:
        c = AttackPathCorrelator(attacker_class=AttackerClass.AC4)
        results = {
            "breach-lookup": _result(
                "breach-lookup",
                [_finding("breached_password", "10.0.0.1")],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.edge_count == 1

    def test_edge_rejected_by_attacker_class(self) -> None:
        """AC1 only allows exploit_public + misconfig — authz_bypass is rejected."""
        c = AttackPathCorrelator(attacker_class=AttackerClass.AC1)
        results = {
            "auth-session-tester": _result(
                "auth-session-tester",
                [_finding("weak_credentials", "10.0.0.1")],
            ),
        }
        c.ingest_findings(results)
        # Assets created but edge rejected by AC1
        assert c.graph.node_count == 2
        assert c.graph.edge_count == 0

    def test_source_asset_auto_created(self) -> None:
        """Edge ingestion should auto-create source asset if missing."""
        c = AttackPathCorrelator()
        results = {
            "dast-scanner": _result(
                "dast-scanner",
                [_finding("dast_sensitive_path", "newhost.com")],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.node_count == 2  # source + vulnerability target


# ---------------------------------------------------------------------------
# Severity → probability mapping
# ---------------------------------------------------------------------------


class TestSeverityProbability:
    """Verify that severity maps to correct probability values."""

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            (FindingSeverity.CRITICAL, 0.9),
            (FindingSeverity.HIGH, 0.7),
            (FindingSeverity.MEDIUM, 0.4),
            (FindingSeverity.LOW, 0.2),
            (FindingSeverity.INFO, 0.05),
        ],
    )
    def test_severity_probability_mapping(self, severity: FindingSeverity, expected: float) -> None:
        assert _SEVERITY_PROBABILITY[severity] == expected

    def test_all_severities_covered(self) -> None:
        for sev in FindingSeverity:
            assert sev in _SEVERITY_PROBABILITY


# ---------------------------------------------------------------------------
# Correlate
# ---------------------------------------------------------------------------


class TestCorrelate:
    """Verify the correlate() output structure."""

    def test_empty_graph_returns_structure(self) -> None:
        c = AttackPathCorrelator()
        result = c.correlate()
        assert "ranked_paths" in result
        assert "mitre_techniques" in result
        assert "graph" in result
        assert result["ranked_paths"] == []
        assert result["mitre_techniques"] == []

    def test_correlate_with_assets_only(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "passive-recon": _result(
                "passive-recon",
                [
                    _finding("dns_record", "10.0.0.1"),
                    _finding("dns_record", "10.0.0.2"),
                ],
            ),
        }
        c.ingest_findings(results)
        result = c.correlate()
        assert result["graph"]["node_count"] == 2
        # No edges → no paths
        assert result["ranked_paths"] == []

    def test_correlate_with_edges(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "passive-recon": _result(
                "passive-recon",
                [_finding("dns_record", "10.0.0.1")],
            ),
            "dast-scanner": _result(
                "dast-scanner",
                [_finding("dast_sensitive_path", "10.0.0.1")],
            ),
        }
        c.ingest_findings(results)
        result = c.correlate()
        assert result["graph"]["node_count"] >= 2
        assert result["graph"]["edge_count"] >= 1

    def test_correlate_mitre_techniques(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "injection-poc-simulator": _result(
                "injection-poc-simulator",
                [
                    _finding("sqli_timing", "10.0.0.1", mitre_technique="T1190"),
                    _finding("xss_reflected", "10.0.0.1", mitre_technique="T1059"),
                ],
            ),
        }
        c.ingest_findings(results)
        result = c.correlate()
        assert "T1190" in result["mitre_techniques"]
        assert "T1059" in result["mitre_techniques"]

    def test_correlate_graph_serialization(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "passive-recon": _result(
                "passive-recon",
                [_finding("dns_record", "10.0.0.1")],
            ),
        }
        c.ingest_findings(results)
        result = c.correlate()
        graph = result["graph"]
        assert "attacker_class" in graph
        assert "nodes" in graph
        assert "edges" in graph
        assert graph["attacker_class"] == "ac1"


# ---------------------------------------------------------------------------
# Ranked paths
# ---------------------------------------------------------------------------


class TestRankedPaths:
    """Verify path ranking through the correlator."""

    def test_ranked_path_with_chain(self) -> None:
        """Build a graph where a ranked path is possible."""
        c = AttackPathCorrelator()
        # Create host asset, then a vulnerability edge on the same host
        results = {
            "passive-recon": _result(
                "passive-recon",
                [_finding("dns_record", "target.com")],
            ),
            "supply-chain-audit": _result(
                "supply-chain-audit",
                [
                    _finding(
                        "supply_chain_vulnerability",
                        "target.com",
                        severity=FindingSeverity.CRITICAL,
                        mitre_technique="T1195",
                    ),
                ],
            ),
        }
        c.ingest_findings(results)
        result = c.correlate()
        # The dns_record asset is first, supply_chain adds source + vuln target
        # Path: asset:target.com → asset:target.com:vuln:supply_chain_vulnerability
        assert len(result["ranked_paths"]) >= 1
        path = result["ranked_paths"][0]
        assert path["rank"] == 1
        assert path["aggregate_probability"] == pytest.approx(0.9, abs=0.01)


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------


class TestModuleConstants:
    """Verify the module-level mappings are correct."""

    def test_asset_finding_types(self) -> None:
        assert "open_port" in _ASSET_FINDING_TYPES
        assert "os_fingerprint" in _ASSET_FINDING_TYPES
        assert "dns_record" in _ASSET_FINDING_TYPES
        assert "subdomain_enum" in _ASSET_FINDING_TYPES
        assert len(_ASSET_FINDING_TYPES) == 4

    def test_edge_type_map_keys(self) -> None:
        expected_keys = {
            "supply_chain_vulnerability",
            "dast_sensitive_path",
            "dast_weak_tls",
            "weak_credentials",
            "idor_accessible",
            "sqli_timing",
            "xss_reflected",
            "breached_password",
        }
        assert set(_EDGE_TYPE_MAP.keys()) == expected_keys

    def test_edge_type_map_values(self) -> None:
        expected_types = {"exploit_public", "misconfig", "authz_bypass", "idor", "token_reuse"}
        assert set(_EDGE_TYPE_MAP.values()) == expected_types


# ---------------------------------------------------------------------------
# Unknown finding types
# ---------------------------------------------------------------------------


class TestUnknownFindings:
    """Verify that unknown finding types are silently skipped."""

    def test_unknown_type_ignored(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "custom-plugin": _result(
                "custom-plugin",
                [_finding("unknown_finding", "10.0.0.1")],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.node_count == 0
        assert c.graph.edge_count == 0

    def test_mixed_known_unknown(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "mixed-plugin": _result(
                "mixed-plugin",
                [
                    _finding("dns_record", "10.0.0.1"),
                    _finding("totally_custom", "10.0.0.1"),
                ],
            ),
        }
        c.ingest_findings(results)
        assert c.graph.node_count == 1  # only dns_record
        assert c.graph.edge_count == 0


# ---------------------------------------------------------------------------
# Multi-plugin ingestion
# ---------------------------------------------------------------------------


class TestMultiPluginIngestion:
    """Verify correlator handles findings from multiple plugins."""

    def test_full_pipeline_ingestion(self) -> None:
        """Simulate a mini pipeline: recon → dast → supply chain."""
        c = AttackPathCorrelator()
        results = {
            "network-scanner": _result(
                "network-scanner",
                [
                    _finding("open_port", "10.0.0.1", metadata={"port": "80"}),
                    _finding("open_port", "10.0.0.1", metadata={"port": "443"}),
                    _finding("os_fingerprint", "10.0.0.1", detail="Ubuntu 22.04"),
                ],
            ),
            "passive-recon": _result(
                "passive-recon",
                [
                    _finding("dns_record", "10.0.0.2"),
                    _finding("subdomain_enum", "api.10.0.0.2"),
                ],
            ),
            "dast-scanner": _result(
                "dast-scanner",
                [
                    _finding("dast_sensitive_path", "10.0.0.1", severity=FindingSeverity.MEDIUM),
                    _finding("dast_weak_tls", "10.0.0.2", severity=FindingSeverity.LOW),
                ],
            ),
            "supply-chain-audit": _result(
                "supply-chain-audit",
                [
                    _finding(
                        "supply_chain_vulnerability",
                        "10.0.0.1",
                        severity=FindingSeverity.CRITICAL,
                        mitre_technique="T1195",
                    ),
                ],
            ),
        }
        c.ingest_findings(results)
        # 2 port assets + dns_record + subdomain + edge auto-assets
        assert c.graph.node_count >= 4
        # dast_sensitive_path + dast_weak_tls + supply_chain = 3 edges
        assert c.graph.edge_count >= 3
        result = c.correlate()
        assert "T1195" in result["mitre_techniques"]

    def test_empty_results(self) -> None:
        c = AttackPathCorrelator()
        c.ingest_findings({})
        result = c.correlate()
        assert result["graph"]["node_count"] == 0

    def test_plugin_with_no_findings(self) -> None:
        c = AttackPathCorrelator()
        results = {
            "empty-scanner": _result("empty-scanner", []),
        }
        c.ingest_findings(results)
        assert c.graph.node_count == 0
