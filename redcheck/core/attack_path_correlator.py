"""RedCheck246 — Attack Path Correlator.

Builds an ``AttackPathGraph`` from pipeline findings by mapping
``finding_type`` values to graph nodes (``Asset``) and edges
(``ExploitEdge``), then exposes ranked paths, MITRE technique
lists, and serialised graph output.

Uses the existing ``AttackPathGraph`` engine as-is — no changes
to ``attack_graph.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from redcheck.models import AttackerClass, FindingSeverity
from redcheck.plugins.exploit.attack_graph import (
    Asset,
    AttackPathGraph,
    ExploitEdge,
)

if TYPE_CHECKING:
    from redcheck.models import PluginResult

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Severity → probability mapping (§8.4)
# ---------------------------------------------------------------------------

_SEVERITY_PROBABILITY: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 0.9,
    FindingSeverity.HIGH: 0.7,
    FindingSeverity.MEDIUM: 0.4,
    FindingSeverity.LOW: 0.2,
    FindingSeverity.INFO: 0.05,
}

# ---------------------------------------------------------------------------
# Finding types that create Asset nodes
# ---------------------------------------------------------------------------

_ASSET_FINDING_TYPES: frozenset[str] = frozenset(
    {
        "open_port",
        "os_fingerprint",
        "dns_record",
        "subdomain_enum",
    }
)

# ---------------------------------------------------------------------------
# Finding type → edge_type mapping (§8.3)
# ---------------------------------------------------------------------------

_EDGE_TYPE_MAP: dict[str, str] = {
    "supply_chain_vulnerability": "exploit_public",
    "dast_sensitive_path": "misconfig",
    "dast_weak_tls": "misconfig",
    "weak_credentials": "authz_bypass",
    "idor_accessible": "idor",
    "sqli_timing": "exploit_public",
    "xss_reflected": "exploit_public",
    "breached_password": "token_reuse",  # noqa: S105  # nosec B105
}


class AttackPathCorrelator:
    """Builds ``AttackPathGraph`` from pipeline findings."""

    def __init__(
        self,
        attacker_class: AttackerClass = AttackerClass.AC1,
        chain_mode: bool = False,
        allow_exploit_validation: bool = False,
    ) -> None:
        self._ac = attacker_class
        self._graph = AttackPathGraph(
            attacker_class=attacker_class,
            chain_mode=chain_mode,
            allow_exploit_validation=allow_exploit_validation,
        )
        # Track assets for edge construction
        self._asset_ids: list[str] = []

    # -- public API -------------------------------------------------------

    @property
    def graph(self) -> AttackPathGraph:
        """Return the underlying ``AttackPathGraph``."""
        return self._graph

    def ingest_findings(
        self,
        results: dict[str, PluginResult],
    ) -> None:
        """Convert pipeline findings into graph nodes and edges.

        Iterates over every ``Finding`` in each ``PluginResult``,
        maps ``finding_type`` to either an ``Asset`` node or an
        ``ExploitEdge``, and adds them to the internal graph.
        """
        for plugin_name, plugin_result in results.items():
            for finding in plugin_result.findings:
                ft = finding.finding_type

                if ft in _ASSET_FINDING_TYPES:
                    self._ingest_asset(finding, ft)
                elif ft in _EDGE_TYPE_MAP:
                    self._ingest_edge(finding, ft, plugin_name)
                else:
                    log.debug(
                        "correlator_unknown_finding_type",
                        finding_type=ft,
                        plugin=plugin_name,
                    )

    def correlate(self) -> dict[str, Any]:
        """Run path analysis and return structured output.

        Returns a dict with:
        - ``ranked_paths``: list of ranked attack paths (up to 10)
        - ``mitre_techniques``: deduplicated MITRE technique list
        - ``graph``: serialised graph dict
        """
        ranked_paths: list[dict[str, Any]] = []

        # Attempt to rank paths between first and last discovered assets
        if len(self._asset_ids) >= 2:
            source = self._asset_ids[0]
            target = self._asset_ids[-1]
            paths = self._graph.rank_paths(source, target, max_paths=10)
            ranked_paths = [p.to_dict() for p in paths]

        return {
            "ranked_paths": ranked_paths,
            "mitre_techniques": self._graph.mitre_techniques(),
            "graph": self._graph.to_dict(),
        }

    # -- private helpers --------------------------------------------------

    def _ingest_asset(self, finding: Any, finding_type: str) -> None:
        """Create or enrich an Asset node from a finding."""
        host = finding.target
        metadata: dict[str, Any] = dict(finding.metadata) if finding.metadata else {}

        if finding_type == "os_fingerprint":
            # Enrich existing asset with OS guess
            asset_id = f"asset:{host}"
            metadata["os_guess"] = finding.detail
            if asset_id in set(self._asset_ids):
                # Asset already exists — we can't mutate frozen dataclass,
                # but the graph node metadata is mutable via networkx
                if self._graph._graph.has_node(asset_id):  # noqa: SLF001
                    self._graph._graph.nodes[asset_id]["metadata"].update(  # noqa: SLF001
                        metadata
                    )
                return
            role = "server"
        elif finding_type == "open_port":
            port = metadata.get("port", "")
            asset_id = f"asset:{host}:{port}" if port else f"asset:{host}"
            role = "service"
        elif finding_type == "dns_record":
            asset_id = f"asset:{host}"
            role = "discovered_host"
        else:  # subdomain_enum
            asset_id = f"asset:{host}"
            role = "subdomain"

        asset = Asset(
            id=asset_id,
            host=host,
            role=role,
            metadata=metadata,
        )
        added = self._graph.add_asset(asset)
        if added and asset_id not in self._asset_ids:
            self._asset_ids.append(asset_id)
            log.debug(
                "correlator_asset_added",
                asset_id=asset_id,
                finding_type=finding_type,
            )

    def _ingest_edge(
        self,
        finding: Any,
        finding_type: str,
        plugin_name: str,
    ) -> None:
        """Create an ExploitEdge from a finding."""
        edge_type = _EDGE_TYPE_MAP[finding_type]
        probability = _SEVERITY_PROBABILITY.get(finding.severity, 0.2)
        mitre = finding.mitre_technique or ""

        # Edge needs source and target assets — derive from finding.target
        host = finding.target
        source_id = f"asset:{host}"
        target_id = f"asset:{host}:vuln:{finding_type}"

        # Ensure both endpoints exist
        if source_id not in self._asset_ids:
            source_asset = Asset(id=source_id, host=host, role="host")
            if self._graph.add_asset(source_asset):
                self._asset_ids.append(source_id)

        target_asset = Asset(
            id=target_id,
            host=host,
            role="vulnerability",
            metadata={
                "finding_type": finding_type,
                "plugin": plugin_name,
                "detail": finding.detail,
            },
        )
        if self._graph.add_asset(target_asset) and target_id not in self._asset_ids:
            self._asset_ids.append(target_id)

        edge = ExploitEdge(
            source_id=source_id,
            target_id=target_id,
            probability=probability,
            mitre_technique=mitre,
            edge_type=edge_type,
            description=f"{finding_type} on {host} ({plugin_name})",
        )
        added = self._graph.add_edge(edge)
        if added:
            log.debug(
                "correlator_edge_added",
                source=source_id,
                target=target_id,
                edge_type=edge_type,
                probability=probability,
            )
