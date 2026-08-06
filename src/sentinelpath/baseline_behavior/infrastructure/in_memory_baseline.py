"""
baseline_behavior.infrastructure.in_memory_baseline
=======================================================

BaselineBehaviorPort'un stateful implementasyonu. DIKKAT: Bu, projede
STATEFUL olan ilk adapter'dir -- Graph Builder (Faz 4) bilerek stateless
tasarlanmisti, ama Baseline Behavior'in kendi doga geregi (recompute()
[yavas/batch] ile get_profile() [hizli/senkron] arasindaki ayrim, bkz.
Faz 1 ports.py aciklamasi) ic durum tutmayi GEREKTIRIR.

"InMemory" onekinin anlami: profiller sadece bellekte tutulur, kalici
degildir (process yeniden baslarsa kaybolur). MVP icin yeterlidir --
gercek bir dagitik/production dagitimda bu SQLite/PostgreSQL'e
(pyproject.toml'daki mevcut bagimlilik) yazan bir adapter ile
degistirilebilir, port sozlesmesine dokunmadan.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

from sentinelpath.core.models import BaselineProfile, NormalizedEvent


class InMemoryBaselineBehavior:
    """BaselineBehaviorPort'u bellek-ici bir sozluk ile karsilayan
    adapter. `domain.ports.BaselineBehaviorPort`'tan miras ALMAZ
    (Protocol, yapisal tiplemedir).
    """

    def __init__(
        self,
        hour_frequency_threshold: float | None = None,
        peer_day_fraction_threshold: float | None = None,
    ) -> None:
        if hour_frequency_threshold is None or peer_day_fraction_threshold is None:
            # Lazy import: RuleBasedFeatureExtractor'daki (Faz 3) ayni
            # prensip -- acik parametrelerle kullanildiginda
            # pydantic-settings kurulu olmayan ortamlarda da calisabilsin.
            from sentinelpath.config.settings import get_settings

            settings = get_settings()
            hour_frequency_threshold = (
                hour_frequency_threshold
                if hour_frequency_threshold is not None
                else settings.baseline_hour_frequency_threshold
            )
            peer_day_fraction_threshold = (
                peer_day_fraction_threshold
                if peer_day_fraction_threshold is not None
                else settings.baseline_peer_day_fraction_threshold
            )

        self._hour_frequency_threshold = hour_frequency_threshold
        self._peer_day_fraction_threshold = peer_day_fraction_threshold
        self._profiles: dict[str, BaselineProfile] = {}

    def get_profile(self, node_id: str) -> BaselineProfile | None:
        return self._profiles.get(node_id)

    def recompute(
        self, events: list[NormalizedEvent], window_start: datetime, window_end: datetime
    ) -> list[BaselineProfile]:
        windowed = [e for e in events if window_start <= e.timestamp < window_end]
        requested_days = max(1, (window_end - window_start).days)

        events_by_host: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in windowed:
            events_by_host[event.source_host].append(event)

        profiles: list[BaselineProfile] = []
        for host, host_events in events_by_host.items():
            profiles.append(
                self._build_profile(host, host_events, requested_days)
            )

        # Tam degistirme (full replace): her recompute() cagrisi, bir
        # onceki durumu SIFIRLAR. Kismi/artimli guncelleme YAPILMAZ --
        # bu, "recompute() her zaman verilen event kumesinden TAM bir
        # baseline uretir" garantisini basitlestirir (bkz. modul
        # docstring'i, Faz 4'teki stateless felsefeyle karsilastirma).
        self._profiles = {p.node_id: p for p in profiles}
        return profiles

    def _build_profile(
        self, host: str, host_events: list[NormalizedEvent], requested_days: int
    ) -> BaselineProfile:
        observed_days = {e.timestamp.date() for e in host_events}

        hour_counts = Counter(e.timestamp.hour for e in host_events)
        total_events = len(host_events)
        typical_hours = tuple(
            sorted(
                hour
                for hour, count in hour_counts.items()
                if count / total_events >= self._hour_frequency_threshold
            )
        )

        peer_days: dict[str, set] = defaultdict(set)
        for event in host_events:
            if event.target_host is not None:
                peer_days[event.target_host].add(event.timestamp.date())

        typical_peers = tuple(
            sorted(
                peer
                for peer, days in peer_days.items()
                if len(days) / len(observed_days) >= self._peer_day_fraction_threshold
            )
        )

        confidence = min(1.0, len(observed_days) / requested_days)

        return BaselineProfile(
            node_id=host,
            baseline_window_days=requested_days,
            typical_active_hours=typical_hours,
            typical_peer_nodes=typical_peers,
            confidence=confidence,
        )
