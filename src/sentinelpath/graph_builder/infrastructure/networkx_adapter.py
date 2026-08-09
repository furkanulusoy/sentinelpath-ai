"""
graph_builder.infrastructure.networkx_adapter
================================================

GraphBuilderPort'un NetworkX implementasyonu (bkz. ADR 0001, neden
NetworkX secildi). Bu, projede NetworkX'in fiilen kullanildigi ilk
dosyadir.

MultiDiGraph secimi
--------------------
DiGraph degil MultiDiGraph kullaniyoruz: ayni (source, target) host
cifti arasinda BIRDEN FAZLA farkli iliski tipi olabilir (orn. hem
basarili bir authenticate hem de ayrica genel bir ag baglantisi
gozlemlenmis olabilir). DiGraph bu ikinci edge'i birincinin uzerine
yazardi -- bilgi kaybi. MultiDiGraph'ta her (source, target, key) ucluesu
ayri bir parallel edge'dir; key olarak RelationType.value kullaniyoruz,
boylece ayni cift arasinda relation basina EN FAZLA bir edge olur
(tekrarlanan ayni-tip event'ler, edge SAYISI degil edge WEIGHT'i artirir).

Stateless tasarim
-------------------
Bu sinif hicbir ic durum (instance state) tutmaz. Her `build()` cagrisi
sifirdan bir graf kurar; `merge_static_topology()` mevcut bir snapshot'i
girdi olarak alir ve YENI bir snapshot doner (mutasyon yok). Bu,
AttackGraphSnapshot'in immutable deger nesnesi felsefesiyle tutarlidir
(bkz. core/models.py).
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

import networkx as nx

from sentinelpath.core.models import (
    AttackGraphSnapshot,
    EventSource,
    GraphEdge,
    HostFeatureVector,
    NormalizedEvent,
    RelationType,
)

# MITRE ATT&CK T1021 (Remote Services) alt-teknikleri -- bir bu prefix ile
# baslayan bir teknik gozlemlendiyse, bu baglanti lateral movement
# gostergesi olarak etiketlenir (bkz. Faz 2'deki PORT_TO_TECHNIQUE tablosu
# ile ayni MITRE kategorisi).
LATERAL_MOVEMENT_TECHNIQUE_PREFIX = "T1021"


def _classify_relation(event: NormalizedEvent) -> RelationType:
    """Tek bir event'in graf uzerinde HANGI iliski tipini temsil ettigine
    karar verir. Bu siniflandirma sirasi ONEMLIDIR: daha spesifik/guclu
    sinyaller (basarili authenticate, bilinen lateral movement teknigi)
    genel 'sadece baglanti var' sinyalinden ONCE kontrol edilir.
    """

    if event.source is EventSource.AUTH and event.metadata.get("outcome") == "success":
        return RelationType.AUTHENTICATES_TO

    if event.mitre_technique_id is not None and event.mitre_technique_id.startswith(
        LATERAL_MOVEMENT_TECHNIQUE_PREFIX
    ):
        return RelationType.OBSERVED_LATERAL_MOVEMENT

    return RelationType.NETWORK_REACHABLE


def graph_to_snapshot(graph: nx.MultiDiGraph) -> AttackGraphSnapshot:
    edges = tuple(
        GraphEdge(
            source_node=source,
            target_node=target,
            relation=data["relation"],
            weight=data["weight"],
            mitre_technique_ids=data.get("mitre_technique_ids", ()),
        )
        for source, target, data in graph.edges(data=True)
    )
    return AttackGraphSnapshot(
        nodes=tuple(sorted(graph.nodes)),
        edges=edges,
        generated_at=datetime.now(UTC),
    )


def snapshot_to_graph(snapshot: AttackGraphSnapshot) -> nx.MultiDiGraph:
    """AttackGraphSnapshot'i tekrar bir nx.MultiDiGraph'a cevirir.

    Bu fonksiyon, `merge_static_topology`'nin var olan bir snapshot
    uzerine ekleme yapabilmesi icin gereklidir; ayrica Faz 6'da Attack
    Path Engine'in de NetworkX algoritmalarini (shortest_path vb.)
    calistirmak icin ayni fonksiyonu kullanmasi beklenir -- bu yuzden
    module-level, disari acik (public) bir fonksiyon olarak tutuluyor.
    """

    graph: nx.MultiDiGraph = nx.MultiDiGraph()
    graph.add_nodes_from(snapshot.nodes)
    for edge in snapshot.edges:
        graph.add_edge(
            edge.source_node,
            edge.target_node,
            key=edge.relation.value,
            relation=edge.relation,
            weight=edge.weight,
            mitre_technique_ids=edge.mitre_technique_ids,
        )
    return graph


class NetworkXGraphBuilder:
    """GraphBuilderPort'u NetworkX MultiDiGraph ile karsilayan adapter.
    `domain.ports.GraphBuilderPort`'tan miras ALMAZ (Protocol, yapisal
    tiplemedir).
    """

    def build(
        self, events: list[NormalizedEvent], feature_vectors: list[HostFeatureVector]
    ) -> AttackGraphSnapshot:
        graph: nx.MultiDiGraph = nx.MultiDiGraph()
        graph.add_nodes_from(v.host_id for v in feature_vectors)

        edge_counts: Counter[tuple[str, str, RelationType]] = Counter()
        # Faz 6'da eklendi (ADR 0007): her (source, target, relation)
        # uclusu icin gozlemlenen SPESIFIK MITRE teknik ID'lerini de
        # ayrica takip ediyoruz -- relation kategorisi kaba, bu kume
        # spesifik.
        edge_techniques: dict[tuple[str, str, RelationType], set[str]] = {}

        for event in events:
            if event.target_host is None:
                continue
            if event.source_host == event.target_host:
                continue  # self-loop: sinyal degeri yok (bkz. Faz 2'deki ayni karar)

            relation = _classify_relation(event)
            key = (event.source_host, event.target_host, relation)
            edge_counts[key] += 1
            if event.mitre_technique_id is not None:
                edge_techniques.setdefault(key, set()).add(event.mitre_technique_id)

        for (source, target, relation), count in edge_counts.items():
            graph.add_node(source)
            graph.add_node(target)
            techniques = tuple(sorted(edge_techniques.get((source, target, relation), set())))
            graph.add_edge(
                source,
                target,
                key=relation.value,
                relation=relation,
                weight=float(count),
                mitre_technique_ids=techniques,
            )

        return graph_to_snapshot(graph)

    def merge_static_topology(
        self, snapshot: AttackGraphSnapshot, topology_edges: list[tuple[str, str]]
    ) -> AttackGraphSnapshot:
        graph = snapshot_to_graph(snapshot)

        for source, target in topology_edges:
            graph.add_node(source)
            graph.add_node(target)
            # Idempotency: ayni statik edge iki kez merge edilirse
            # (orn. topology dosyasi yeniden okunursa) mukerrer edge
            # OLUSMAMALIDIR -- has_edge kontrolu bunu saglar.
            if not graph.has_edge(source, target, key=RelationType.NETWORK_REACHABLE.value):
                graph.add_edge(
                    source,
                    target,
                    key=RelationType.NETWORK_REACHABLE.value,
                    relation=RelationType.NETWORK_REACHABLE,
                    weight=1.0,
                )

        return graph_to_snapshot(graph)

    def merge_detected_edges(
        self, snapshot: AttackGraphSnapshot, detected_edges: list[GraphEdge]
    ) -> AttackGraphSnapshot:
        """Faz B / ADR 0015: dis bir dedektorun (orn.
        discovery_detection.scan_detector) urettigi ZENGIN kenarlari
        (relation, weight, mitre_technique_ids dahil) mevcut bir grafa
        birlestirir.

        merge_static_topology()'den FARKI: o fonksiyon basit (source,
        target) ciftlerini HER ZAMAN NETWORK_REACHABLE/weight=1.0 olarak
        ekler. Bu fonksiyon ise cagiran tarafin ONCEDEN hesapladigi TAM
        GraphEdge nesnelerini OLDUGU GIBI ekler.
        """
        graph = snapshot_to_graph(snapshot)

        for edge in detected_edges:
            graph.add_node(edge.source_node)
            graph.add_node(edge.target_node)
            key = edge.relation.value
            if not graph.has_edge(edge.source_node, edge.target_node, key=key):
                graph.add_edge(
                    edge.source_node,
                    edge.target_node,
                    key=key,
                    relation=edge.relation,
                    weight=edge.weight,
                    mitre_technique_ids=edge.mitre_technique_ids,
                )

        return graph_to_snapshot(graph)
