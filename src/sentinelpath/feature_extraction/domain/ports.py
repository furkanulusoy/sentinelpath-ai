"""
feature_extraction.domain.ports
================================

Bu katmanin sorumlulugu: "Bu ham NormalizedEvent listesi, host/kullanici
davranisi acisindan NE ANLAMA GELIYOR?" sorusuna cevap vermek.

Collector'dan farkli oldugu nokta: Collector formatla ilgilenir (Sysmon mi,
pcap mi), Feature Extraction ise DOMAIN MANTIGIYLA ilgilenir (orn. "gece
saatinde basarisiz login orani" gibi bir sinyal, guvenlik acisindan anlamli
midir?). Bu ayrim ARCHITECTURE.md'de detayli gerekcelendirilmistir.

FAZ 3 REVIZYONU (bkz. docs/adr/0004-explicit-feature-window.md)
------------------------------------------------------------------
`extract()` imzasina `window_start`/`window_end` parametreleri eklendi.
Faz 1'de bu parametreler yoktu; pencerenin event zaman damgalarindan
turetilebilecegi varsayilmisti. Gercek implementasyonu yazarken bu
varsayimin kirildigi ortaya cikti: bir host'un HIC event'i olmayabilir
(orn. yeni provizyonlanmis, henuz gozlemlenmemis bir host) ve bu durumda
turetilecek bir zaman damgasi yoktur -- oysa "bu host'ta bu pencerede
hicbir aktivite gozlenmedi" basli basina anlamli bir ozellik vektorudur.
Bu yuzden pencere, cagiran taraf (kim/ne zaman sorusunu bilen use-case
katmani) tarafindan ACIKCA belirtilir; event listesi sadece o pencere
icinde NE gozlemlendigini soyler.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from sentinelpath.core.models import HostFeatureVector, NormalizedEvent


class FeatureExtractorPort(Protocol):
    """NormalizedEvent listesinden HostFeatureVector ureten adapter sozlesmesi.

    Tasarim notu: `extract()` bir host_id ile sinirlandirilmis calisir --
    tum ortam icin tek seferde degil. Bu, Faz 3'te feature hesaplamasini
    host bazinda paralellestirebilmemizi saglar (buyuk ortamlarda onemli
    bir performans kaygisi).
    """

    def extract(
        self,
        host_id: str,
        events: list[NormalizedEvent],
        window_start: datetime,
        window_end: datetime,
    ) -> HostFeatureVector:
        """Belirli bir host'a, belirli bir zaman penceresine ait
        event'lerden davranissal ozellik vektorunu hesaplar.

        `events` listesi onceden bu host'a/pencereye filtrelenmis
        olabilir ya da olmayabilir -- implementasyon kendi ic filtrelemesini
        yapmalidir (bkz. RuleBasedFeatureExtractor).
        """
        ...

    def feature_names(self) -> tuple[str, ...]:
        """Bu extractor'in urettigi ozelliklerin isim listesini dondurur.

        Bu metod onemli: Prediction Model (Faz 6) hangi ozelliklerin
        modele girdi oldugunu bilmeli, aksi halde model egitimi ile
        inference arasinda 'feature drift' (ozellik uyusmazligi) hatasi
        sessizce olusabilir -- production ML sistemlerinde en sik gorulen
        hatalardan biridir.
        """
        ...
