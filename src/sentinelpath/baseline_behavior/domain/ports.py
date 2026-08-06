"""
baseline_behavior.domain.ports
================================

Bu katman, mimarideki EN KRITIK zamanlama karariyla iliskilidir: baseline
hesaplama SENKRON (istek-anlik) degil, ASENKRON (periyodik/batch) olmalidir.

Neden? Bir "normal davranis" tanimi, birkac gunluk/haftalik veriye dayanir.
Bunu her tahmin isteginde yeniden hesaplamak hem gereksiz hesaplama
maliyeti (compute cost) hem de gecikme (latency) demektir. Bunun yerine
`recompute()` bir zamanlayici (scheduler) tarafindan periyodik cagrilir,
`get_profile()` ise API istegi geldiginde onceden hesaplanmis sonucu
hizlica dondurur.

Bu Protocol'u kullanan use-case (application/ katmani, Faz 5) bu iki
metodu birbirinden BAGIMSIZ tetikleyecek sekilde tasarlanacaktir.

FAZ 5 REVIZYONU (bkz. docs/adr/0006-baseline-events-and-window.md)
-----------------------------------------------------------------------
`recompute()` imzasi `AttackGraphSnapshot` yerine ham
`NormalizedEvent` listesi + acik pencere aliyor. Gerekce: "tipik saatler"
ve "tipik peer'lar" kavramlari saat-duzeyinde zaman damgasina VE
gun-sinirlarini koruyan bir veri kaynagina ihtiyac duyar -- bunlarin
hicbiri tek bir AttackGraphSnapshot'ta mevcut degildir (bkz. ADR 0004,
0005 ile ayni desen).
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from sentinelpath.core.models import BaselineProfile, NormalizedEvent


class BaselineBehaviorPort(Protocol):
    def recompute(
        self, events: list[NormalizedEvent], window_start: datetime, window_end: datetime
    ) -> list[BaselineProfile]:
        """Verilen zaman penceresindeki TUM event'lere gore, gorulen her
        node icin baseline profillerini yeniden hesaplar ve ic durumu
        gunceller. Maliyetli bir islemdir; periyodik/arka plan gorevi
        (background job) olarak calistirilmasi beklenir.
        """
        ...

    def get_profile(self, node_id: str) -> BaselineProfile | None:
        """Onceden hesaplanmis, tek bir node'a ait baseline profilini
        hizlica dondurur (senkron istek yolunda kullanilir). Henuz hicbir
        baseline hesaplanmamissa None doner -- cagiran taraf (Attack Path
        Engine) bunu 'yetersiz veri, dusuk guven' olarak yorumlamalidir.
        """
        ...
