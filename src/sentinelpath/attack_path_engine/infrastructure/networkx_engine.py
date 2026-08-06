"""
attack_path_engine.infrastructure.networkx_engine
=====================================================

AttackPathEnginePort'un NetworkX implementasyonu. DETERMINISTIK --
hicbir olasilik hesaplamaz (bkz. ADR 0002, domain/ports.py uyarisi).

RELATION_PRIORITY: MultiDiGraph'ta ayni (source, target) cifti arasinda
BIRDEN FAZLA paralel edge olabilir (Faz 4, farkli iliski tipleri icin).
Bir CandidatePath'in her hop'u icin TEK bir "baskin" edge secmemiz
gerekiyor (bkz. ADR 0008) -- bu siralama, hangisinin secilecegini
belirler: saldiri-iliskili olan (lateral movement) her zaman genel
baglantidan (network_reachable) ONCE gelir.
"""

from __future__ import annotations

import networkx as nx

from sentinelpath.core.models import AttackGraphSnapshot, CandidatePath, RelationType
from sentinelpath.graph_builder.infrastructure.networkx_adapter import snapshot_to_graph

RELATION_PRIORITY: dict[RelationType, int] = {
    RelationType.OBSERVED_LATERAL_MOVEMENT: 3,
    RelationType.AUTHENTICATES_TO: 2,
    RelationType.TRUSTS: 1,
    RelationType.NETWORK_REACHABLE: 0,
}


def _dominant_edge_data(graph: nx.MultiDiGraph, source: str, target: str) -> dict:
    """source->target arasindaki (varsa birden fazla) paralel edge'den
    RELATION_PRIORITY'ye gore en 'saldiri-iliskili' olanini secer."""

    parallel_edges = graph.get_edge_data(source, target)
    best_key = max(
        parallel_edges, key=lambda key: RELATION_PRIORITY[parallel_edges[key]["relation"]]
    )
    return parallel_edges[best_key]


class NetworkXAttackPathEngine:
    """AttackPathEnginePort'u NetworkX ile karsilayan adapter.
    `domain.ports.AttackPathEnginePort`'tan miras ALMAZ (Protocol,
    yapisal tiplemedir).
    """

    def find_candidate_paths(
        self, graph: AttackGraphSnapshot, start_node: str, max_hops: int = 4
    ) -> list[CandidatePath]:
        multi_graph = snapshot_to_graph(graph)
        if start_node not in multi_graph:
            return []

        # Yol SAYIMI icin (hangi node siralarinin mumkun oldugu), paralel
        # edge'leri onemsemeyen basit bir DiGraph yeterli -- bir "yol"un
        # kimligi node sirasidir, hangi iliski tipiyle degil. Her hop'un
        # DETAYINI (agirlik, teknik) asagida _dominant_edge_data ile
        # orijinal MultiDiGraph'tan ayrica cekiyoruz.
        simple_graph = nx.DiGraph(multi_graph)

        # NOT: nx.all_simple_paths bu surumde `target` parametresini
        # ZORUNLU kiliyor (eski surumlerde omitting = "tum ulasilabilir
        # node'lar" anlamina gelirdi). Ayni davranisi elde etmek icin
        # start_node disindaki TUM node'lari hedef olarak veriyoruz --
        # boylece "start_node'dan max_hops icinde ulasilabilecek HER
        # yol" bulunmus olur.
        candidates: list[CandidatePath] = []
        possible_targets = set(simple_graph.nodes) - {start_node}
        if not possible_targets:
            return []

        for path in nx.all_simple_paths(
            simple_graph, source=start_node, target=possible_targets, cutoff=max_hops
        ):
            if len(path) < 2:
                continue  # trivial: hic hop yok

            hop_relations: list[RelationType] = []
            hop_weights: list[float] = []
            hop_technique_ids: list[tuple[str, ...]] = []
            techniques: set[str] = set()
            reason_parts: list[str] = []

            for hop_source, hop_target in zip(path, path[1:], strict=True):
                dominant = _dominant_edge_data(multi_graph, hop_source, hop_target)
                hop_relations.append(dominant["relation"])
                hop_weights.append(dominant["weight"])
                hop_techniques = dominant.get("mitre_technique_ids", ())
                hop_technique_ids.append(hop_techniques)
                techniques.update(hop_techniques)
                reason_parts.append(dominant["relation"].value)

            candidates.append(
                CandidatePath(
                    path_nodes=tuple(path),
                    plausible_techniques=tuple(sorted(techniques)),
                    structural_reason=" -> ".join(reason_parts),
                    hop_relations=tuple(hop_relations),
                    hop_weights=tuple(hop_weights),
                    hop_technique_ids=tuple(hop_technique_ids),
                )
            )

        return candidates

    def is_reachable(self, graph: AttackGraphSnapshot, source_node: str, target_node: str) -> bool:
        multi_graph = snapshot_to_graph(graph)
        if source_node not in multi_graph or target_node not in multi_graph:
            return False
        return bool(nx.has_path(multi_graph, source_node, target_node))
