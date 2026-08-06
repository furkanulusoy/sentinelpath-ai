"""
reporting.domain.ports
========================

Pipeline'in son katmani. Ayni SentinelPathReport nesnesinin BIRDEN FAZLA
formatta disari verilebilmesi gerekiyor (ham JSON, MITRE ATT&CK Navigator
layer JSON, ileride belki PDF/HTML). Bu yuzden tek bir 'render' metodu
yerine, her format icin ayri bir port metodu tanimliyoruz -- boylece yeni
bir format eklemek (orn. Sigma kurali export'u) mevcut kodu bozmadan
yapilabilir (Open/Closed Principle).
"""

from __future__ import annotations

from typing import Protocol

from sentinelpath.core.models import SentinelPathReport


class ReportingPort(Protocol):
    def to_json(self, report: SentinelPathReport) -> str:
        """Raporu genel amacli, makine-okunur JSON formatinda dondurur."""
        ...

    def to_attack_navigator_layer(self, report: SentinelPathReport) -> dict:
        """Raporu MITRE ATT&CK Navigator'in 'layer' JSON semasina uygun
        sekilde dondurur -- boylece kullanici ciktiyi dogrudan
        https://mitre-attack.github.io/attack-navigator/ arayuzune
        yukleyip gorsellestirebilir. Bu, projenin gercek guvenlik
        standartlariyla uyumlu olma hedefinin somut bir uygulamasidir.
        """
        ...
