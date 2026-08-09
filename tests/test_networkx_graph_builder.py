"""
tests.test_networkx_graph_builder
====================================

Bu testler networkx'in bu ortamda GERCEKTEN kurulu olmasi sayesinde
(Faz 2/3'ten farkli olarak) canli calistirilabiliyor -- manuel dogrulama
yerine gercek modul davranisi test ediliyor.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelpath.core.models import (
    EventSource,
    GraphEdge,
    HostFeatureVector,
    NormalizedEvent,
    RelationType,
)
from sentinelpath.graph_builder.infrastructure.networkx_adapter import NetworkXGraphBuilder

NOW = datetime.now(UTC)


def _event(**overrides) -> NormalizedEvent:
    defaults = dict(
        event_id="e",
        timestamp=NOW,
        source=EventSource.NETWORK,
        source_host="host-a",
        target_host="host-b",
        user=None,
        raw_action="tcp_connect:port_8080",
        mitre_technique_id=None,
        metadata={},
    )
    defaults.update(overrides)
    return NormalizedEvent(**defaults)


def _feature_vector(host_id: str) -> HostFeatureVector:
    return HostFeatureVector(
        host_id=host_id,
        window_start=NOW,
        window_end=NOW,
        distinct_users_count=0,
        distinct_target_hosts_count=0,
        failed_auth_ratio=0.0,
        off_hours_activity_ratio=0.0,
    )


def test_isolated_host_appears_as_node_without_edges() -> None:
    """Hic disa baglantisi olmayan bir host bile graf'ta node olarak
    durmali -- Attack Path Engine'in 'bu host'a ulasilabilir mi'
    sorusunu sorabilmesi icin (bkz. ADR 0005 gerekcesi).
    """

    builder = NetworkXGraphBuilder()
    snapshot = builder.build(events=[], feature_vectors=[_feature_vector("host-isolated")])

    assert snapshot.nodes == ("host-isolated",)
    assert snapshot.edges == ()


def test_successful_auth_event_creates_authenticates_to_edge() -> None:
    builder = NetworkXGraphBuilder()
    event = _event(source=EventSource.AUTH, metadata={"outcome": "success"})

    snapshot = builder.build(events=[event], feature_vectors=[])

    assert len(snapshot.edges) == 1
    edge = snapshot.edges[0]
    assert edge.relation is RelationType.AUTHENTICATES_TO
    assert edge.source_node == "host-a"
    assert edge.target_node == "host-b"


def test_failed_auth_event_does_not_create_authenticates_to_edge() -> None:
    builder = NetworkXGraphBuilder()
    event = _event(source=EventSource.AUTH, metadata={"outcome": "failure"})

    snapshot = builder.build(events=[event], feature_vectors=[])

    assert len(snapshot.edges) == 1
    assert snapshot.edges[0].relation is RelationType.NETWORK_REACHABLE


def test_t1021_technique_creates_lateral_movement_edge() -> None:
    builder = NetworkXGraphBuilder()
    event = _event(mitre_technique_id="T1021.001")

    snapshot = builder.build(events=[event], feature_vectors=[])

    assert snapshot.edges[0].relation is RelationType.OBSERVED_LATERAL_MOVEMENT


def test_edge_carries_specific_mitre_technique_ids() -> None:
    """Faz 6 / ADR 0007: relation kaba bir kategoridir, ama edge ayrica
    SPESIFIK teknik ID'lerini de tasimalidir (Attack Path Engine bunu
    kullanacak)."""

    builder = NetworkXGraphBuilder()
    event = _event(mitre_technique_id="T1021.001")

    snapshot = builder.build(events=[event], feature_vectors=[])

    assert snapshot.edges[0].mitre_technique_ids == ("T1021.001",)


def test_edge_accumulates_multiple_distinct_techniques() -> None:
    """Ayni host cifti arasinda FARKLI zamanlarda farkli teknikler
    gozlemlenmisse (orn. bir gun RDP, baska gun baska bir T1021
    alt-teknigi), edge'in mitre_technique_ids'i HEPSINI icermelidir."""

    builder = NetworkXGraphBuilder()
    events = [
        _event(mitre_technique_id="T1021.001"),
        _event(mitre_technique_id="T1021.002"),
    ]

    snapshot = builder.build(events=events, feature_vectors=[])

    assert len(snapshot.edges) == 1  # ayni relation kategorisi -> tek edge
    assert snapshot.edges[0].mitre_technique_ids == ("T1021.001", "T1021.002")
    assert snapshot.edges[0].weight == 2.0


def test_edge_without_technique_has_empty_technique_ids() -> None:
    builder = NetworkXGraphBuilder()
    event = _event(mitre_technique_id=None)

    snapshot = builder.build(events=[event], feature_vectors=[])

    assert snapshot.edges[0].mitre_technique_ids == ()


def test_unclassified_traffic_creates_network_reachable_edge() -> None:
    builder = NetworkXGraphBuilder()
    event = _event(mitre_technique_id=None)

    snapshot = builder.build(events=[event], feature_vectors=[])

    assert snapshot.edges[0].relation is RelationType.NETWORK_REACHABLE


def test_repeated_identical_events_increase_edge_weight_not_edge_count() -> None:
    builder = NetworkXGraphBuilder()
    events = [_event(mitre_technique_id="T1021.001") for _ in range(5)]

    snapshot = builder.build(events=events, feature_vectors=[])

    assert len(snapshot.edges) == 1  # tek edge
    assert snapshot.edges[0].weight == 5.0  # ama weight 5 gozlemi yansitiyor


def test_same_host_pair_can_have_multiple_relation_types_in_parallel() -> None:
    """MultiDiGraph seciminin somut kaniti: ayni host cifti arasinda
    HEM authenticates_to HEM network_reachable edge'i AYNI ANDA var
    olabilmeli (bkz. modul docstring'i, DiGraph yerine MultiDiGraph
    secme gerekcesi).
    """

    builder = NetworkXGraphBuilder()
    events = [
        _event(source=EventSource.AUTH, metadata={"outcome": "success"}),
        _event(
            source=EventSource.NETWORK, mitre_technique_id=None, raw_action="tcp_connect:port_9999"
        ),
    ]

    snapshot = builder.build(events=events, feature_vectors=[])

    relations = {e.relation for e in snapshot.edges}
    assert relations == {RelationType.AUTHENTICATES_TO, RelationType.NETWORK_REACHABLE}
    assert len(snapshot.edges) == 2


def test_events_without_target_host_are_ignored() -> None:
    builder = NetworkXGraphBuilder()
    event = _event(target_host=None)

    snapshot = builder.build(events=[event], feature_vectors=[])

    assert snapshot.edges == ()


def test_self_loop_events_are_ignored() -> None:
    builder = NetworkXGraphBuilder()
    event = _event(source_host="host-a", target_host="host-a")

    snapshot = builder.build(events=[event], feature_vectors=[])

    assert snapshot.edges == ()


def test_hosts_seen_only_in_events_are_still_added_as_nodes() -> None:
    """feature_vectors bos olsa bile, event'lerde gorulen host'lar
    graf'a node olarak eklenmeli (defensive completeness)."""

    builder = NetworkXGraphBuilder()
    event = _event(source_host="host-x", target_host="host-y")

    snapshot = builder.build(events=[event], feature_vectors=[])

    assert set(snapshot.nodes) == {"host-x", "host-y"}


def test_merge_static_topology_adds_new_edge() -> None:
    builder = NetworkXGraphBuilder()
    base_snapshot = builder.build(
        events=[], feature_vectors=[_feature_vector("host-a"), _feature_vector("host-b")]
    )

    merged = builder.merge_static_topology(base_snapshot, topology_edges=[("host-a", "host-b")])

    assert len(merged.edges) == 1
    assert merged.edges[0].relation is RelationType.NETWORK_REACHABLE
    assert merged.edges[0].source_node == "host-a"


def test_merge_static_topology_is_idempotent() -> None:
    """Ayni statik topolojiyi iki kez merge etmek mukerrer edge
    URETMEMELIDIR (orn. topology.json dosyasi periyodik olarak yeniden
    okunup merge edilirse)."""

    builder = NetworkXGraphBuilder()
    base_snapshot = builder.build(events=[], feature_vectors=[])

    once = builder.merge_static_topology(base_snapshot, topology_edges=[("host-a", "host-b")])
    twice = builder.merge_static_topology(once, topology_edges=[("host-a", "host-b")])

    assert len(twice.edges) == 1


def test_merge_static_topology_preserves_existing_behavioral_edges() -> None:
    builder = NetworkXGraphBuilder()
    behavioral_event = _event(source=EventSource.AUTH, metadata={"outcome": "success"})
    base_snapshot = builder.build(events=[behavioral_event], feature_vectors=[])

    merged = builder.merge_static_topology(base_snapshot, topology_edges=[("host-c", "host-d")])

    relations = {e.relation for e in merged.edges}
    assert RelationType.AUTHENTICATES_TO in relations  # eski davranissal edge kaybolmamis
    assert len(merged.edges) == 2  # eski + yeni statik edge

def test_merge_detected_edges_preserves_relation_weight_and_technique() -> None:
    builder = NetworkXGraphBuilder()
    snapshot = builder.build(events=[], feature_vectors=[])

    detected = [
        GraphEdge(
            source_node="attacker",
            target_node="host1",
            relation=RelationType.OBSERVED_SCANNING,
            weight=2.0,
            mitre_technique_ids=("T1046",),
        )
    ]
    merged = builder.merge_detected_edges(snapshot, detected)

    assert len(merged.edges) == 1
    edge = merged.edges[0]
    assert edge.relation == RelationType.OBSERVED_SCANNING
    assert edge.weight == 2.0
    assert edge.mitre_technique_ids == ("T1046",)


def test_merge_detected_edges_is_idempotent() -> None:
    builder = NetworkXGraphBuilder()
    snapshot = builder.build(events=[], feature_vectors=[])
    detected = [
        GraphEdge(
            source_node="a", target_node="b",
            relation=RelationType.OBSERVED_SCANNING, weight=3.0,
            mitre_technique_ids=("T1046",),
        )
    ]
    once = builder.merge_detected_edges(snapshot, detected)
    twice = builder.merge_detected_edges(once, detected)
    assert len(twice.edges) == len(once.edges) == 1
