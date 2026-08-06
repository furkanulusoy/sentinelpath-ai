"""
tests.test_networkx_attack_path_engine
=========================================

networkx bu ortamda kurulu oldugu icin canli calistirilabiliyor.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sentinelpath.attack_path_engine.infrastructure.networkx_engine import (
    NetworkXAttackPathEngine,
)
from sentinelpath.core.models import AttackGraphSnapshot, GraphEdge, RelationType

NOW = datetime.now(timezone.utc)


def _snapshot(edges: list[GraphEdge], nodes: tuple[str, ...] | None = None) -> AttackGraphSnapshot:
    node_set = set(nodes or ())
    for e in edges:
        node_set.add(e.source_node)
        node_set.add(e.target_node)
    return AttackGraphSnapshot(nodes=tuple(sorted(node_set)), edges=tuple(edges), generated_at=NOW)


def test_no_path_from_isolated_start_node_returns_empty_list() -> None:
    engine = NetworkXAttackPathEngine()
    snapshot = _snapshot([], nodes=("host-a",))

    assert engine.find_candidate_paths(snapshot, "host-a") == []


def test_unknown_start_node_returns_empty_list() -> None:
    engine = NetworkXAttackPathEngine()
    snapshot = _snapshot([])

    assert engine.find_candidate_paths(snapshot, "does-not-exist") == []


def test_single_hop_path_is_found() -> None:
    engine = NetworkXAttackPathEngine()
    edge = GraphEdge(
        source_node="host-a", target_node="host-b",
        relation=RelationType.OBSERVED_LATERAL_MOVEMENT, weight=3.0,
        mitre_technique_ids=("T1021.001",),
    )
    snapshot = _snapshot([edge])

    candidates = engine.find_candidate_paths(snapshot, "host-a")

    assert len(candidates) == 1
    c = candidates[0]
    assert c.path_nodes == ("host-a", "host-b")
    assert c.hop_relations == (RelationType.OBSERVED_LATERAL_MOVEMENT,)
    assert c.hop_weights == (3.0,)
    assert c.plausible_techniques == ("T1021.001",)


def test_multi_hop_chain_is_found() -> None:
    engine = NetworkXAttackPathEngine()
    edges = [
        GraphEdge(source_node="a", target_node="b", relation=RelationType.OBSERVED_LATERAL_MOVEMENT, weight=1.0, mitre_technique_ids=("T1021.001",)),
        GraphEdge(source_node="b", target_node="c", relation=RelationType.OBSERVED_LATERAL_MOVEMENT, weight=1.0, mitre_technique_ids=("T1021.002",)),
    ]
    snapshot = _snapshot(edges)

    candidates = engine.find_candidate_paths(snapshot, "a", max_hops=4)
    path_node_tuples = {c.path_nodes for c in candidates}

    assert ("a", "b") in path_node_tuples
    assert ("a", "b", "c") in path_node_tuples


def test_max_hops_limits_path_depth() -> None:
    engine = NetworkXAttackPathEngine()
    edges = [
        GraphEdge(source_node="a", target_node="b", relation=RelationType.NETWORK_REACHABLE),
        GraphEdge(source_node="b", target_node="c", relation=RelationType.NETWORK_REACHABLE),
        GraphEdge(source_node="c", target_node="d", relation=RelationType.NETWORK_REACHABLE),
    ]
    snapshot = _snapshot(edges)

    candidates = engine.find_candidate_paths(snapshot, "a", max_hops=1)
    path_node_tuples = {c.path_nodes for c in candidates}

    assert ("a", "b") in path_node_tuples
    assert ("a", "b", "c") not in path_node_tuples  # 2 hop -- max_hops=1'i asiyor


def test_dominant_edge_prefers_lateral_movement_over_network_reachable() -> None:
    """Ayni host cifti arasinda HEM lateral movement HEM genel baglanti
    varsa, hop_relations lateral movement'i secmeli (bkz. RELATION_PRIORITY)."""

    engine = NetworkXAttackPathEngine()
    edges = [
        GraphEdge(source_node="a", target_node="b", relation=RelationType.NETWORK_REACHABLE, weight=10.0),
        GraphEdge(source_node="a", target_node="b", relation=RelationType.OBSERVED_LATERAL_MOVEMENT, weight=1.0, mitre_technique_ids=("T1021.001",)),
    ]
    snapshot = _snapshot(edges)

    candidates = engine.find_candidate_paths(snapshot, "a")
    direct = next(c for c in candidates if c.path_nodes == ("a", "b"))

    assert direct.hop_relations == (RelationType.OBSERVED_LATERAL_MOVEMENT,)
    assert direct.plausible_techniques == ("T1021.001",)


def test_is_reachable_true_for_connected_nodes() -> None:
    engine = NetworkXAttackPathEngine()
    edges = [
        GraphEdge(source_node="a", target_node="b", relation=RelationType.NETWORK_REACHABLE),
        GraphEdge(source_node="b", target_node="c", relation=RelationType.NETWORK_REACHABLE),
    ]
    snapshot = _snapshot(edges)

    assert engine.is_reachable(snapshot, "a", "c") is True


def test_is_reachable_false_for_disconnected_nodes() -> None:
    engine = NetworkXAttackPathEngine()
    edges = [GraphEdge(source_node="a", target_node="b", relation=RelationType.NETWORK_REACHABLE)]
    snapshot = _snapshot(edges, nodes=("c",))

    assert engine.is_reachable(snapshot, "a", "c") is False


def test_is_reachable_false_for_unknown_nodes() -> None:
    engine = NetworkXAttackPathEngine()
    snapshot = _snapshot([])

    assert engine.is_reachable(snapshot, "ghost-1", "ghost-2") is False


def test_no_cycles_in_candidate_paths() -> None:
    """all_simple_paths dogasi geregi cevrimleri (cycle) tekrar
    ziyaret ETMEZ -- bu, sonsuz dongu riskini onler."""

    engine = NetworkXAttackPathEngine()
    edges = [
        GraphEdge(source_node="a", target_node="b", relation=RelationType.NETWORK_REACHABLE),
        GraphEdge(source_node="b", target_node="a", relation=RelationType.NETWORK_REACHABLE),  # dongu
    ]
    snapshot = _snapshot(edges)

    candidates = engine.find_candidate_paths(snapshot, "a", max_hops=4)
    for c in candidates:
        assert len(c.path_nodes) == len(set(c.path_nodes))  # tekrar node yok
