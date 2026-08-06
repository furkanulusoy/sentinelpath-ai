"""
feature_extraction.infrastructure.rule_based_extractor
==========================================================

MVP icin FeatureExtractorPort'un saf Python (stdlib) implementasyonu.
Pandas/numpy KULLANILMAZ -- gerekce ARCHITECTURE.md'de ve bu fazin
sohbet gecmisindeki analizde detaylandirilmistir: port imzasi tek-host
calisir (`extract(host_id, events, ...)`), pandas'in asil gucu olan
toplu (batch) vektorlestirmeyi bu arayuzde kullanamayiz; bu olcekte
(host basina yuzlerce event) saf Python dongusu hem yeterince hizli
hem tip-guvenlidir (mypy ile).

Eger ileride tum hostlar icin TOPLU ozellik cikarimi ihtiyaci dogarsa
(performans darbogazi kanitlanirsa), ayni port'u karsilayan bir
PandasFeatureExtractorAdapter yazilabilir -- use-case katmani hicbir
degisikligie ugramaz.
"""

from __future__ import annotations

from datetime import datetime

from sentinelpath.core.models import EventSource, HostFeatureVector, NormalizedEvent

FEATURE_NAMES: tuple[str, ...] = (
    "distinct_users_count",
    "distinct_target_hosts_count",
    "failed_auth_ratio",
    "off_hours_activity_ratio",
    "observed_techniques",
)


class RuleBasedFeatureExtractor:
    """FeatureExtractorPort'u kural-tabanli (istatistiksel olmayan)
    hesaplamalarla karsilayan adapter. `domain.ports.FeatureExtractorPort`'tan
    miras ALMAZ (Protocol yapisal tiplemedir) -- imzayi karsiladigi icin
    otomatik olarak o tipten sayilir.
    """

    def __init__(
        self, business_hours_start: int | None = None, business_hours_end: int | None = None
    ) -> None:
        # Not: get_settings() SADECE gerektiginde (bir parametre eksikse)
        # cagirilir. Boylece bu sinif, testlerde acik parametrelerle
        # kullanildiginda pydantic-settings'in kurulu olmasini GEREKTIRMEZ
        # -- Faz 2'deki "lazy import" prensibiyle ayni mantik.
        if business_hours_start is None or business_hours_end is None:
            # Lazy import: config.settings, pydantic-settings'e bagimlidir.
            # Bu importu fonksiyon icine almak, business_hours degerleri
            # ACIKCA verildiginde bu sinifin pydantic-settings kurulu
            # olmadan da kullanilabilmesini saglar (bkz. Faz 2, ADR 0003
            # ile ayni "lazy import" prensibi).
            from sentinelpath.config.settings import get_settings

            settings = get_settings()
            business_hours_start = (
                business_hours_start
                if business_hours_start is not None
                else settings.business_hours_start
            )
            business_hours_end = (
                business_hours_end
                if business_hours_end is not None
                else settings.business_hours_end
            )

        self._business_hours_start = business_hours_start
        self._business_hours_end = business_hours_end

    def feature_names(self) -> tuple[str, ...]:
        return FEATURE_NAMES

    def extract(
        self,
        host_id: str,
        events: list[NormalizedEvent],
        window_start: datetime,
        window_end: datetime,
    ) -> HostFeatureVector:
        host_events = [
            e
            for e in events
            if e.source_host == host_id and window_start <= e.timestamp < window_end
        ]

        return HostFeatureVector(
            host_id=host_id,
            window_start=window_start,
            window_end=window_end,
            distinct_users_count=self._distinct_users_count(host_events),
            distinct_target_hosts_count=self._distinct_target_hosts_count(host_events),
            failed_auth_ratio=self._failed_auth_ratio(host_events),
            off_hours_activity_ratio=self._off_hours_activity_ratio(host_events),
            observed_techniques=self._observed_techniques(host_events),
        )

    # --- Ozel hesaplama metodlari (her biri tek bir ozelligin sorumlusu) ---

    @staticmethod
    def _distinct_users_count(host_events: list[NormalizedEvent]) -> int:
        users = {e.user for e in host_events if e.user is not None}
        return len(users)

    @staticmethod
    def _distinct_target_hosts_count(host_events: list[NormalizedEvent]) -> int:
        targets = {e.target_host for e in host_events if e.target_host is not None}
        return len(targets)

    @staticmethod
    def _failed_auth_ratio(host_events: list[NormalizedEvent]) -> float:
        """AUTH kaynakli, metadata['outcome'] alani DOLU olan event'ler
        uzerinden hesaplanir. 'outcome' bilgisi olmayan event'ler ne
        basari ne basarisizlik sayilir -- yanlis varsayimda bulunmamak
        icin paydaya dahil edilmezler.

        NOT (dikkat edilmesi gereken sinirlama): Eger hicbir AUTH
        event'inde 'outcome' bilgisi yoksa, bu metod 0.0 doner. Bu 0.0,
        "hep basarili" anlamina GELMEZ -- "yeterli sinyal yok" anlamina
        gelir. Bu ayrimin kaybolmasi, Faz 5/6'da yanlis guvenle
        yorumlanan bir baseline'a yol acabilir; bu yuzden burada acikca
        not ediyoruz (ileride ayri bir 'confidence' alani eklenmesi
        degerlendirilebilir).
        """

        auth_events = [
            e for e in host_events if e.source is EventSource.AUTH and "outcome" in e.metadata
        ]
        if not auth_events:
            return 0.0

        failed = sum(1 for e in auth_events if e.metadata.get("outcome") == "failure")
        return failed / len(auth_events)

    def _off_hours_activity_ratio(self, host_events: list[NormalizedEvent]) -> float:
        if not host_events:
            return 0.0

        off_hours_count = sum(
            1 for e in host_events if not self._is_business_hour(e.timestamp.hour)
        )
        return off_hours_count / len(host_events)

    def _is_business_hour(self, hour: int) -> bool:
        return self._business_hours_start <= hour < self._business_hours_end

    @staticmethod
    def _observed_techniques(host_events: list[NormalizedEvent]) -> tuple[str, ...]:
        techniques = {e.mitre_technique_id for e in host_events if e.mitre_technique_id is not None}
        return tuple(sorted(techniques))
