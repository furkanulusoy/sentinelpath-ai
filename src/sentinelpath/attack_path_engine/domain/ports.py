"""
attack_path_engine.domain.ports
=================================

DIKKAT: Bu port'un implementasyonlari (Faz 6) HICBIR ML/istatistik
kutuphanesi kullanmamalidir (scikit-learn, torch, vb. import ETMEMELIDIR).

Bu bilerek konulmus bir kisitlamadir. Attack Path Engine'in gorevi SAF
GRAF TEORISIDIR: reachability, shortest path, cycle detection gibi
deterministik algoritmalar. "Hangi yol daha olasi?" sorusu burada
CEVAPLANMAZ -- o soru prediction/ katmaninin sorumlulugudur.

Bu ayrimi ihlal eden bir implementasyon (orn. burada bir olasilik skoru
hesaplamaya baslamak), ARCHITECTURE.md'de anlatilan acikanabilirlik
(explainability) faydasini yok eder.
"""
from __future__ import annotations

from typing import Protocol

from sentinelpath.core.models import AttackGraphSnapshot, CandidatePath


class AttackPathEnginePort(Protocol):
    def find_candidate_paths(
        self,
        graph: AttackGraphSnapshot,
        start_node: str,
        max_hops: int = 4,
    ) -> list[CandidatePath]:
        """Baslangic node'undan itibaren, graf yapisina gore YAPISAL OLARAK
        MUMKUN olan aday yollari bulur.

        `max_hops` sinirinin var olmasinin nedeni: sinirsiz derinlikte graf
        gezinme (traversal), buyuk ortamlarda kombinatoryal patlamaya
        (combinatorial explosion) yol acar. MITRE ATT&CK kill chain'i
        pratikte nadiren 4-5 adimdan uzun surer, bu yuzden bu varsayilan
        deger hem performans hem gercekci saldiri senaryolariyla uyumludur.
        """
        ...

    def is_reachable(
        self, graph: AttackGraphSnapshot, source_node: str, target_node: str
    ) -> bool:
        """Iki node arasinda herhangi bir yapisal yol olup olmadigini
        hizlica kontrol eder (tam yol listesi gerekmedigi durumlar icin,
        orn. bir onceki tahminin hala gecerli olup olmadigini dogrulama).
        """
        ...
