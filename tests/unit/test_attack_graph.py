"""Tests for redcheck.plugins.exploit.attack_graph — AttackPathGraph.

Coverage targets (from Phase 3 DoD):
- Graph construction speed (50 assets + 100 edges in < 1 s)
- Dijkstra correctness (hand-calculated paths on 3 fixed graphs)
- Deterministic output (same input + seed → identical ranking × 5 runs)
- Node cap enforcement (1001 nodes → truncates to 1000 + warning)
- Edge cap enforcement (5001 edges → truncates to 5000)
- Chain mode gate (chain_mode=False → no multi-hop execution)
- Chain requires both flags (chain_mode=True + allow_exploit=False → ChainModeError)
- MITRE annotations (each edge has technique ID)
- JSON export (to_dict() round-trips with ranked paths)
- Attacker class scoping (edge-type filtering, depth limits, node caps)
"""

from __future__ import annotations

import time
import warnings
from typing import Any

import pytest

from redcheck import constants
from redcheck.exceptions import ChainModeError
from redcheck.models import AttackerClass
from redcheck.plugins.exploit.attack_graph import (
    Asset,
    AttackPathGraph,
    ExploitEdge,
    _max_depth_for,
    _max_nodes_for,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _linear_graph(
    n: int = 5,
    prob: float = 0.8,
    ac: AttackerClass = AttackerClass.AC4,
    edge_type: str = "lateral",
    mitre: str = "T1021",
    **kwargs: Any,
) -> AttackPathGraph:
    """Build a simple A→B→C→… linear chain of *n* nodes."""
    g = AttackPathGraph(attacker_class=ac, **kwargs)
    for i in range(n):
        g.add_asset(Asset(id=f"n{i}", host=f"10.0.0.{i}", role="server"))
    for i in range(n - 1):
        g.add_edge(
            ExploitEdge(
                source_id=f"n{i}",
                target_id=f"n{i + 1}",
                probability=prob,
                mitre_technique=mitre,
                edge_type=edge_type,
            )
        )
    return g


def _diamond_graph(
    ac: AttackerClass = AttackerClass.AC4,
    **kwargs: Any,
) -> AttackPathGraph:
    """Diamond: A→B (0.9), A→C (0.5), B→D (0.8), C→D (0.95).

    Path A→B→D agg=0.72, Path A→C→D agg=0.475
    Best path = A→B→D.
    """
    g = AttackPathGraph(attacker_class=ac, **kwargs)
    for nid, host, role in [
        ("A", "10.0.0.1", "entry"),
        ("B", "10.0.0.2", "server"),
        ("C", "10.0.0.3", "server"),
        ("D", "10.0.0.4", "target"),
    ]:
        g.add_asset(Asset(id=nid, host=host, role=role))
    g.add_edge(
        ExploitEdge(
            source_id="A",
            target_id="B",
            probability=0.9,
            mitre_technique="T1190",
            edge_type="exploit_public",
        )
    )
    g.add_edge(
        ExploitEdge(
            source_id="A",
            target_id="C",
            probability=0.5,
            mitre_technique="T1078",
            edge_type="lateral",
        )
    )
    g.add_edge(
        ExploitEdge(
            source_id="B",
            target_id="D",
            probability=0.8,
            mitre_technique="T1068",
            edge_type="privesc",
        )
    )
    g.add_edge(
        ExploitEdge(
            source_id="C",
            target_id="D",
            probability=0.95,
            mitre_technique="T1021",
            edge_type="lateral",
        )
    )
    return g


def _triangle_graph(
    ac: AttackerClass = AttackerClass.AC4,
    **kwargs: Any,
) -> AttackPathGraph:
    """Triangle: A→B (0.7), B→C (0.6), A→C (0.3).

    Path A→B→C agg=0.42, Path A→C agg=0.30
    Best path = A→B→C.
    """
    g = AttackPathGraph(attacker_class=ac, **kwargs)
    for nid in ("A", "B", "C"):
        g.add_asset(Asset(id=nid, host=f"10.0.0.{ord(nid) - 64}", role="server"))
    g.add_edge(
        ExploitEdge(
            source_id="A",
            target_id="B",
            probability=0.7,
            mitre_technique="T1190",
            edge_type="exploit_public",
        )
    )
    g.add_edge(
        ExploitEdge(
            source_id="B",
            target_id="C",
            probability=0.6,
            mitre_technique="T1068",
            edge_type="privesc",
        )
    )
    g.add_edge(
        ExploitEdge(
            source_id="A",
            target_id="C",
            probability=0.3,
            mitre_technique="T1078",
            edge_type="lateral",
        )
    )
    return g


# ===========================================================================
# Graph Construction
# ===========================================================================


class TestGraphConstruction:
    """Basic construction, add_asset / add_edge, idempotency."""

    def test_empty_graph(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC1)
        assert g.node_count == 0
        assert g.edge_count == 0
        assert not g.is_truncated

    def test_add_asset(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC1)
        ok = g.add_asset(Asset(id="host1", host="10.0.0.1", role="web"))
        assert ok
        assert g.node_count == 1

    def test_add_asset_idempotent(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC1)
        a = Asset(id="host1", host="10.0.0.1")
        g.add_asset(a)
        g.add_asset(a)
        assert g.node_count == 1

    def test_add_edge_between_known_nodes(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC1)
        g.add_asset(Asset(id="a", host="10.0.0.1"))
        g.add_asset(Asset(id="b", host="10.0.0.2"))
        ok = g.add_edge(
            ExploitEdge(
                source_id="a",
                target_id="b",
                probability=0.5,
                edge_type="exploit_public",
                mitre_technique="T1190",
            )
        )
        assert ok
        assert g.edge_count == 1

    def test_add_edge_missing_source_rejected(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC1)
        g.add_asset(Asset(id="b", host="10.0.0.2"))
        ok = g.add_edge(
            ExploitEdge(
                source_id="a",
                target_id="b",
                probability=0.5,
                edge_type="exploit_public",
            )
        )
        assert not ok

    def test_add_edge_missing_target_rejected(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC1)
        g.add_asset(Asset(id="a", host="10.0.0.1"))
        ok = g.add_edge(
            ExploitEdge(
                source_id="a",
                target_id="b",
                probability=0.5,
                edge_type="exploit_public",
            )
        )
        assert not ok

    def test_probability_validation_zero(self) -> None:
        with pytest.raises(ValueError, match="probability"):
            ExploitEdge(source_id="a", target_id="b", probability=0.0)

    def test_probability_validation_negative(self) -> None:
        with pytest.raises(ValueError, match="probability"):
            ExploitEdge(source_id="a", target_id="b", probability=-0.5)

    def test_probability_validation_above_one(self) -> None:
        with pytest.raises(ValueError, match="probability"):
            ExploitEdge(source_id="a", target_id="b", probability=1.5)

    def test_probability_one_is_valid(self) -> None:
        e = ExploitEdge(source_id="a", target_id="b", probability=1.0)
        assert e.probability == 1.0


# ===========================================================================
# Construction Speed
# ===========================================================================


class TestConstructionSpeed:
    """DoD: 50 assets + 100 edges in < 1 s."""

    def test_50_assets_100_edges_under_1s(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC4)
        start = time.monotonic()

        for i in range(50):
            g.add_asset(Asset(id=f"h{i}", host=f"10.0.0.{i}", role="server"))

        edge_count = 0
        for i in range(50):
            for j in range(i + 1, 50):
                if edge_count >= 100:
                    break
                g.add_edge(
                    ExploitEdge(
                        source_id=f"h{i}",
                        target_id=f"h{j}",
                        probability=0.5,
                        mitre_technique="T1021",
                        edge_type="lateral",
                    )
                )
                edge_count += 1
            if edge_count >= 100:
                break

        elapsed = time.monotonic() - start
        assert g.node_count == 50
        assert g.edge_count == 100
        assert elapsed < 1.0, f"Construction took {elapsed:.3f}s (> 1s)"


# ===========================================================================
# Dijkstra Correctness (3 fixed graphs)
# ===========================================================================


class TestDijkstraCorrectness:
    """DoD: Matches hand-calculated path on 3 fixed graphs."""

    def test_diamond_best_path(self) -> None:
        """Diamond: A→B→D (agg=0.72) beats A→C→D (agg=0.475)."""
        g = _diamond_graph()
        paths = g.rank_paths("A", "D")
        assert len(paths) >= 2
        best = paths[0]
        assert best.nodes == ["A", "B", "D"]
        assert abs(best.aggregate_probability - 0.72) < 1e-9

    def test_diamond_second_path(self) -> None:
        g = _diamond_graph()
        paths = g.rank_paths("A", "D")
        second = paths[1]
        assert second.nodes == ["A", "C", "D"]
        assert abs(second.aggregate_probability - 0.475) < 1e-9

    def test_triangle_best_path(self) -> None:
        """Triangle: A→B→C (agg=0.42) beats A→C (agg=0.30)."""
        g = _triangle_graph()
        paths = g.rank_paths("A", "C")
        assert len(paths) >= 2
        best = paths[0]
        assert best.nodes == ["A", "B", "C"]
        assert abs(best.aggregate_probability - 0.42) < 1e-9

    def test_linear_chain_single_path(self) -> None:
        """Linear 4-node: A→B→C→D, agg = 0.8^3 = 0.512."""
        g = _linear_graph(n=4, prob=0.8)
        paths = g.rank_paths("n0", "n3")
        assert len(paths) == 1
        assert abs(paths[0].aggregate_probability - 0.8**3) < 1e-9

    def test_no_path_returns_empty(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC4)
        g.add_asset(Asset(id="a", host="10.0.0.1"))
        g.add_asset(Asset(id="b", host="10.0.0.2"))
        assert g.rank_paths("a", "b") == []

    def test_unknown_source_returns_empty(self) -> None:
        g = _linear_graph(n=3)
        assert g.rank_paths("unknown", "n2") == []

    def test_unknown_target_returns_empty(self) -> None:
        g = _linear_graph(n=3)
        assert g.rank_paths("n0", "unknown") == []

    def test_shortest_path_helper(self) -> None:
        g = _diamond_graph()
        best = g.shortest_path("A", "D")
        assert best is not None
        assert best.rank == 1
        assert best.nodes == ["A", "B", "D"]

    def test_shortest_path_none_when_no_path(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC4)
        g.add_asset(Asset(id="a", host="10.0.0.1"))
        g.add_asset(Asset(id="b", host="10.0.0.2"))
        assert g.shortest_path("a", "b") is None


# ===========================================================================
# Deterministic Output
# ===========================================================================


class TestDeterministicOutput:
    """DoD: Same input + seed → identical ranking on 5 runs."""

    def test_five_runs_identical(self) -> None:
        results: list[list[dict[str, Any]]] = []
        for _ in range(5):
            g = _diamond_graph(seed=42)
            paths = g.rank_paths("A", "D")
            results.append([p.to_dict() for p in paths])

        for run in results[1:]:
            assert run == results[0]


# ===========================================================================
# Node / Edge Cap Enforcement
# ===========================================================================


class TestCapEnforcement:
    """DoD: 1001 nodes → truncates + warning; 5001 edges → truncates."""

    def test_node_cap_truncation_with_warning(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC4)
        # AC4 max = 1000 (equals global max)
        for i in range(constants.ATTACK_GRAPH_MAX_NODES):
            g.add_asset(Asset(id=f"n{i}", host=f"10.{i // 256}.{i % 256}.1"))
        assert g.node_count == constants.ATTACK_GRAPH_MAX_NODES

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            ok = g.add_asset(Asset(id="overflow", host="10.255.255.1"))
            assert not ok
            assert g.node_count == constants.ATTACK_GRAPH_MAX_NODES
            assert len(w) == 1
            assert "Node cap" in str(w[0].message)

    def test_per_class_node_cap_ac1(self) -> None:
        """AC1 cap = 50 nodes."""
        g = AttackPathGraph(attacker_class=AttackerClass.AC1)
        for i in range(constants.ATTACK_GRAPH_AC1_MAX_NODES):
            g.add_asset(Asset(id=f"n{i}", host=f"10.0.0.{i}"))
        assert g.node_count == constants.ATTACK_GRAPH_AC1_MAX_NODES

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            ok = g.add_asset(Asset(id="overflow", host="10.0.0.250"))
            assert not ok
            assert len(w) == 1

    def test_edge_cap_truncation(self) -> None:
        """5001 edges → truncates to 5000."""
        g = AttackPathGraph(attacker_class=AttackerClass.AC4)
        # Need enough nodes to hold 5001 edges
        n_nodes = 200
        for i in range(n_nodes):
            g.add_asset(Asset(id=f"n{i}", host=f"10.{i // 256}.{i % 256}.1"))

        added = 0
        for i in range(n_nodes):
            for j in range(n_nodes):
                if i == j:
                    continue
                if added >= constants.ATTACK_GRAPH_MAX_EDGES + 1:
                    break
                g.add_edge(
                    ExploitEdge(
                        source_id=f"n{i}",
                        target_id=f"n{j}",
                        probability=0.5,
                        edge_type="lateral",
                        mitre_technique="T1021",
                    )
                )
                added += 1
            if added >= constants.ATTACK_GRAPH_MAX_EDGES + 1:
                break

        assert g.edge_count == constants.ATTACK_GRAPH_MAX_EDGES
        assert g.is_truncated

    def test_subsequent_nodes_after_cap_silently_dropped(self) -> None:
        """After the first warning, subsequent overflows don't warn again."""
        g = AttackPathGraph(attacker_class=AttackerClass.AC1)
        for i in range(constants.ATTACK_GRAPH_AC1_MAX_NODES):
            g.add_asset(Asset(id=f"n{i}", host=f"10.0.0.{i}"))

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            g.add_asset(Asset(id="over1", host="10.0.0.250"))
            g.add_asset(Asset(id="over2", host="10.0.0.251"))
            # Only one warning for the first overflow
            assert len(w) == 1


# ===========================================================================
# Chain Mode Gate
# ===========================================================================


class TestChainModeGate:
    """DoD: chain_mode=False → no execution; requires both flags."""

    def test_chain_mode_false_raises(self) -> None:
        g = _diamond_graph(chain_mode=False, allow_exploit_validation=True)
        path = g.rank_paths("A", "D")[0]
        with pytest.raises(ChainModeError):
            g.execute_chain(path)

    def test_allow_exploit_false_raises(self) -> None:
        g = _diamond_graph(chain_mode=True, allow_exploit_validation=False)
        path = g.rank_paths("A", "D")[0]
        with pytest.raises(ChainModeError):
            g.execute_chain(path)

    def test_both_false_raises(self) -> None:
        g = _diamond_graph(chain_mode=False, allow_exploit_validation=False)
        path = g.rank_paths("A", "D")[0]
        with pytest.raises(ChainModeError):
            g.execute_chain(path)

    def test_both_true_succeeds(self) -> None:
        g = _diamond_graph(chain_mode=True, allow_exploit_validation=True)
        path = g.rank_paths("A", "D")[0]
        result = g.execute_chain(path)
        assert result["chain_mode"] is True
        assert result["total_hops"] == 2
        assert len(result["hops"]) == 2

    def test_can_execute_chain_property(self) -> None:
        g1 = AttackPathGraph(
            attacker_class=AttackerClass.AC4,
            chain_mode=True,
            allow_exploit_validation=True,
        )
        assert g1.can_execute_chain() is True

        g2 = AttackPathGraph(
            attacker_class=AttackerClass.AC4,
            chain_mode=False,
            allow_exploit_validation=True,
        )
        assert g2.can_execute_chain() is False

    def test_execute_chain_returns_planned_status(self) -> None:
        g = _diamond_graph(chain_mode=True, allow_exploit_validation=True)
        path = g.rank_paths("A", "D")[0]
        result = g.execute_chain(path)
        for hop in result["hops"]:
            assert hop["status"] == "planned"


# ===========================================================================
# Attacker Class Scoping
# ===========================================================================


class TestAttackerClassScoping:
    """DoD: edge-type filtering, depth limits, node caps per class."""

    def test_ac1_rejects_lateral_edge_type(self) -> None:
        """AC1 only allows exploit_public, misconfig."""
        g = AttackPathGraph(attacker_class=AttackerClass.AC1)
        g.add_asset(Asset(id="a", host="10.0.0.1"))
        g.add_asset(Asset(id="b", host="10.0.0.2"))
        ok = g.add_edge(
            ExploitEdge(
                source_id="a",
                target_id="b",
                probability=0.5,
                edge_type="lateral",
                mitre_technique="T1021",
            )
        )
        assert not ok
        assert g.edge_count == 0

    def test_ac1_accepts_exploit_public(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC1)
        g.add_asset(Asset(id="a", host="10.0.0.1"))
        g.add_asset(Asset(id="b", host="10.0.0.2"))
        ok = g.add_edge(
            ExploitEdge(
                source_id="a",
                target_id="b",
                probability=0.5,
                edge_type="exploit_public",
                mitre_technique="T1190",
            )
        )
        assert ok

    def test_ac2_accepts_privesc(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC2)
        g.add_asset(Asset(id="a", host="10.0.0.1"))
        g.add_asset(Asset(id="b", host="10.0.0.2"))
        ok = g.add_edge(
            ExploitEdge(
                source_id="a",
                target_id="b",
                probability=0.5,
                edge_type="privesc",
                mitre_technique="T1068",
            )
        )
        assert ok

    def test_ac3_accepts_api_chain(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC3)
        g.add_asset(Asset(id="a", host="10.0.0.1"))
        g.add_asset(Asset(id="b", host="10.0.0.2"))
        ok = g.add_edge(
            ExploitEdge(
                source_id="a",
                target_id="b",
                probability=0.5,
                edge_type="api_chain",
                mitre_technique="T1106",
            )
        )
        assert ok

    def test_ac4_accepts_all_edge_types(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC4)
        edge_types = ["lateral", "privesc", "exploit_public", "exfil_indicator"]
        # Create separate target nodes so DiGraph doesn't overwrite edges
        g.add_asset(Asset(id="a", host="10.0.0.1"))
        for i, etype in enumerate(edge_types):
            target_id = f"t{i}"
            g.add_asset(Asset(id=target_id, host=f"10.0.0.{i + 2}"))
            g.add_edge(
                ExploitEdge(
                    source_id="a",
                    target_id=target_id,
                    probability=0.5,
                    edge_type=etype,
                    mitre_technique="T1021",
                )
            )
        assert g.edge_count == 4

    def test_ac1_depth_limit_filters_deep_paths(self) -> None:
        """AC1 max depth = 1 → paths > 1 hop are filtered."""
        g = AttackPathGraph(attacker_class=AttackerClass.AC1)
        for nid in ("A", "B", "C"):
            g.add_asset(Asset(id=nid, host=f"10.0.0.{ord(nid) - 64}"))
        g.add_edge(
            ExploitEdge(
                source_id="A",
                target_id="B",
                probability=0.8,
                edge_type="exploit_public",
                mitre_technique="T1190",
            )
        )
        g.add_edge(
            ExploitEdge(
                source_id="B",
                target_id="C",
                probability=0.8,
                edge_type="exploit_public",
                mitre_technique="T1190",
            )
        )
        # Path A→B→C has depth 2, exceeds AC1 max_depth=1
        paths = g.rank_paths("A", "C")
        assert len(paths) == 0

    def test_ac1_single_hop_allowed(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC1)
        g.add_asset(Asset(id="A", host="10.0.0.1"))
        g.add_asset(Asset(id="B", host="10.0.0.2"))
        g.add_edge(
            ExploitEdge(
                source_id="A",
                target_id="B",
                probability=0.9,
                edge_type="exploit_public",
                mitre_technique="T1190",
            )
        )
        paths = g.rank_paths("A", "B")
        assert len(paths) == 1
        assert paths[0].depth == 1

    def test_max_depth_property(self) -> None:
        for ac, expected in [
            (AttackerClass.AC1, constants.ATTACK_GRAPH_AC1_MAX_DEPTH),
            (AttackerClass.AC2, constants.ATTACK_GRAPH_AC2_MAX_DEPTH),
            (AttackerClass.AC3, constants.ATTACK_GRAPH_AC3_MAX_DEPTH),
            (AttackerClass.AC4, constants.ATTACK_GRAPH_AC4_MAX_DEPTH),
        ]:
            g = AttackPathGraph(attacker_class=ac)
            assert g.max_depth == expected

    def test_max_nodes_property(self) -> None:
        for ac, expected in [
            (AttackerClass.AC1, constants.ATTACK_GRAPH_AC1_MAX_NODES),
            (AttackerClass.AC2, constants.ATTACK_GRAPH_AC2_MAX_NODES),
            (AttackerClass.AC3, constants.ATTACK_GRAPH_AC3_MAX_NODES),
            (AttackerClass.AC4, constants.ATTACK_GRAPH_AC4_MAX_NODES),
        ]:
            g = AttackPathGraph(attacker_class=ac)
            assert g.max_nodes == expected

    def test_allowed_edge_types_property(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC2)
        assert g.allowed_edge_types == frozenset({"privesc", "idor", "authz_bypass"})


# ===========================================================================
# MITRE Annotations
# ===========================================================================


class TestMITREAnnotations:
    """DoD: Each edge has MITRE technique ID."""

    def test_mitre_techniques_listed(self) -> None:
        g = _diamond_graph()
        techniques = g.mitre_techniques()
        assert "T1190" in techniques
        assert "T1078" in techniques
        assert "T1068" in techniques
        assert "T1021" in techniques

    def test_edges_carry_mitre_in_ranked_paths(self) -> None:
        g = _diamond_graph()
        paths = g.rank_paths("A", "D")
        for path in paths:
            for edge in path.edges:
                assert edge.mitre_technique != ""

    def test_empty_graph_no_techniques(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC1)
        assert g.mitre_techniques() == []


# ===========================================================================
# JSON Export / Round-Trip
# ===========================================================================


class TestJSONRoundTrip:
    """DoD: to_dict() round-trips with ranked paths."""

    def test_to_dict_structure(self) -> None:
        g = _diamond_graph()
        d = g.to_dict()
        assert d["attacker_class"] == "ac4"
        assert d["node_count"] == 4
        assert d["edge_count"] == 4
        assert len(d["nodes"]) == 4
        assert len(d["edges"]) == 4

    def test_round_trip_preserves_nodes(self) -> None:
        g = _diamond_graph()
        d = g.to_dict()
        g2 = AttackPathGraph.from_dict(d)
        assert g2.node_count == g.node_count
        assert g2.edge_count == g.edge_count

    def test_round_trip_preserves_paths(self) -> None:
        g = _diamond_graph()
        paths_orig = g.rank_paths("A", "D")
        d = g.to_dict()
        g2 = AttackPathGraph.from_dict(d)
        paths_restored = g2.rank_paths("A", "D")

        assert len(paths_restored) == len(paths_orig)
        for orig, restored in zip(paths_orig, paths_restored, strict=True):
            assert orig.nodes == restored.nodes
            assert abs(orig.aggregate_probability - restored.aggregate_probability) < 1e-9

    def test_round_trip_preserves_mitre(self) -> None:
        g = _diamond_graph()
        techniques_orig = g.mitre_techniques()
        d = g.to_dict()
        g2 = AttackPathGraph.from_dict(d)
        assert g2.mitre_techniques() == techniques_orig

    def test_ranked_path_to_dict(self) -> None:
        g = _diamond_graph()
        paths = g.rank_paths("A", "D")
        d = paths[0].to_dict()
        assert "rank" in d
        assert "nodes" in d
        assert "edges" in d
        assert "aggregate_probability" in d
        assert "depth" in d

    def test_from_dict_respects_attacker_class(self) -> None:
        g = AttackPathGraph(attacker_class=AttackerClass.AC2)
        g.add_asset(Asset(id="a", host="10.0.0.1"))
        g.add_asset(Asset(id="b", host="10.0.0.2"))
        g.add_edge(
            ExploitEdge(
                source_id="a",
                target_id="b",
                probability=0.5,
                edge_type="privesc",
                mitre_technique="T1068",
            )
        )
        d = g.to_dict()
        g2 = AttackPathGraph.from_dict(d)
        assert g2.attacker_class == AttackerClass.AC2


# ===========================================================================
# Repr
# ===========================================================================


class TestRepr:
    def test_repr_format(self) -> None:
        g = _diamond_graph()
        r = repr(g)
        assert "ac4" in r
        assert "nodes=4" in r
        assert "edges=4" in r


# ===========================================================================
# Helper Functions
# ===========================================================================


class TestHelpers:
    def test_max_depth_for_all_classes(self) -> None:
        assert _max_depth_for(AttackerClass.AC1) == 1
        assert _max_depth_for(AttackerClass.AC2) == 3
        assert _max_depth_for(AttackerClass.AC3) == 4
        assert _max_depth_for(AttackerClass.AC4) == 6

    def test_max_nodes_for_all_classes(self) -> None:
        assert _max_nodes_for(AttackerClass.AC1) == 50
        assert _max_nodes_for(AttackerClass.AC2) == 200
        assert _max_nodes_for(AttackerClass.AC3) == 500
        assert _max_nodes_for(AttackerClass.AC4) == 1000
