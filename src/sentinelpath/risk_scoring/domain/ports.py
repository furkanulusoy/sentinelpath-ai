"""
risk_scoring.domain.ports
============================

Bu katman bilerek Prediction Model'den AYRI tutulmustur. Risk skorlama
formulu (probability x asset_criticality x technique_severity) kurum-
spesifik degerlendirmeler icerir -- "bu host ne kadar kritik?" sorusunun
cevabi bir bankada ile bir e-ticaret sirketinde farklidir.

Bu ayrimin faydasi: bir kurum kendi kritiklik agirliklarini degistirmek
istediginde (orn. "bizde credential access, domain admin host'ta lateral
movement'tan daha kritik"), SADECE bu katmanin infrastructure adapter'ini
degistirir -- Prediction Model'i yeniden egitmeye gerek kalmaz.

FAZ 7 REVIZYONU (bkz. docs/adr/0010-risk-score-baseline-confidence.md)
---------------------------------------------------------------------------
`score()` imzasina opsiyonel `baseline_profiles` parametresi eklendi --
RiskScore artik (ana formule DAHIL OLMADAN, ayri bir baglam alani
olarak) baseline confidence'i da tasiyabiliyor.
"""

from __future__ import annotations

from typing import Protocol

from sentinelpath.core.models import BaselineProfile, PredictionResult, RiskScore


class RiskScoringPort(Protocol):
    def score(
        self,
        prediction: PredictionResult,
        baseline_profiles: list[BaselineProfile] | None = None,
    ) -> list[RiskScore]:
        """Bir tahmin sonucundaki her teknik icin risk skoru hesaplar.

        `baseline_profiles` saglanirsa, ilgili node'un confidence degeri
        RiskScore.baseline_confidence alanina (BAGLAM olarak, formule
        dahil edilmeden) eklenir.
        """
        ...

    def asset_criticality(self, node_id: str) -> float:
        """Belirli bir node'un kurumsal kritiklik degerini (0.0-1.0)
        dondurur. MVP'de statik bir konfigurasyon dosyasindan (config/)
        okunur; ileride CMDB/varlik envanteri entegrasyonuna genisletilebilir.
        """
        ...
