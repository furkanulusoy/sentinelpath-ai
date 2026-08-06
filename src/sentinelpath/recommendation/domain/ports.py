"""
recommendation.domain.ports
=============================

MVP kapsaminda bu katman KURAL TABANLIDIR (rule-based): MITRE ATT&CK
teknik ID'sinden resmi MITRE mitigation ID'sine statik bir mapping.
Bilerek ML kullanilmiyor -- oneri/mitigasyon metni ureten bir dil modeli
(LLM) buraya eklenebilir (v2+), ancak MVP'de "hangi teknige karsi hangi
onlem onerilir" sorusunun cevabi zaten MITRE'nin kendi ATT&CK veri
tabaninda mevcut ve deterministik olmalidir -- bunu olasiliksal hale
getirmenin (LLM ile) MVP'de katma degeri yoktur, sadece belirsizlik ekler.
"""

from __future__ import annotations

from typing import Protocol

from sentinelpath.core.models import Recommendation, RiskScore


class RecommendationEnginePort(Protocol):
    def recommend(self, risk_scores: list[RiskScore]) -> list[Recommendation]:
        """Risk skoru verilmis her teknik icin somut mitigasyon onerisi
        uretir (MITRE ATT&CK mitigation kataloguna dayanarak)."""
        ...
