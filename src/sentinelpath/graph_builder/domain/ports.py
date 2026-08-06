"""
graph_builder.domain.ports
===========================

Bu port bilerek NetworkX'e (veya baska bir graf kutuphanesine) HICBIR
ATIF YAPMAZ. Sozlesme yalnizca core.models.AttackGraphSnapshot uzerinden
konusur. Somut NetworkX implementasyonu infrastructure/networkx_adapter.py
icinde (Faz 4) yer alacak.

Bu ayrimin somut faydasi: ARCHITECTURE.md'de tartisilan "NetworkX vs Neo4j"
kararini ileride degistirmek istersek (orn. node sayisi 100k'yi asarsa),
SADECE infrastructure/ klasorundeki adapter'i degistiririz -- graph_builder'i
kullanan Attack Path Engine, Baseline Behavior gibi katmanlar hicbir
degisiklige ugramaz.

FAZ 4 REVIZYONU (bkz. docs/adr/0005-graph-builder-events-parameter.md)
--------------------------------------------------------------------------
`build()` imzasina `events: list[NormalizedEvent]` parametresi eklendi.
Faz 1'de yalnizca `feature_vectors` vardi; implementasyonu yazarken
HostFeatureVector'in (bilincli olarak) aggregate edilmis bir ozet
oldugu, edge kurmak icin gereken cift-yonlu (source_host, target_host)
kimlik bilgisini ICERMEDIGI ortaya cikti.
"""

from __future__ import annotations

from typing import Protocol

from sentinelpath.core.models import AttackGraphSnapshot, HostFeatureVector, NormalizedEvent


class GraphBuilderPort(Protocol):
    """Ham event'lerden ve host feature vektorlerinden bir
    AttackGraphSnapshot ureten adapter sozlesmesi.
    """

    def build(
        self, events: list[NormalizedEvent], feature_vectors: list[HostFeatureVector]
    ) -> AttackGraphSnapshot:
        """Verilen event'lere (edge kimligi icin) ve feature vektorlerine
        (node envanteri icin) dayanarak guncel attack graph anlik
        goruntusunu (snapshot) uretir."""
        ...

    def merge_static_topology(
        self, snapshot: AttackGraphSnapshot, topology_edges: list[tuple[str, str]]
    ) -> AttackGraphSnapshot:
        """Statik ag topolojisi bilgisini (orn. subnet erisim kurallari,
        firewall ACL'lerinden turetilmis komsuluk) davranissal graf ile
        birlestirir.

        Bu iki bilgiyi ayri metodlarda tutmamizin nedeni: davranissal graf
        siklikla (her yeni event batch'inde) guncellenirken, statik topoloji
        cok daha seyrek degisir (agda yeni bir subnet acildiginda). Bunlari
        tek bir 'build' metoduna sikistirmak, gereksiz yere sik yeniden
        hesaplamaya yol acardi.
        """
        ...
