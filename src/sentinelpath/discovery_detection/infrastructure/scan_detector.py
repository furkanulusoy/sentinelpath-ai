"""
discovery_detection.infrastructure.scan_detector
====================================================

MITRE ATT&CK Discovery taktigindeki T1046 (Network Service Discovery)
icin istatistiksel esik-tabanli tespit. Bagimsiz bir modul (bkz.
ADR 0015) -- Graph Builder'a (Faz 4) veya baska hicbir mevcut modulun
koduna DOKUNMAZ. Urettigi GraphEdge listesi, mevcut
merge_static_topology() mekanizmasiyla disaridan graf'a eklenir.

Kasitli olarak REDTEAM.TXT'e (veya baska bir ground truth'a) HICBIR
sekilde bakmaz -- ne esik secimi (bkz. InMemoryBaselineBehavior,
Tukey IQR) ne bu dosyadaki agirlik formulu ground truth'a gore
ayarlanmistir (bkz. ADR 0015, "sizinti onleme" bolumu).

Iki bagimsiz sinyal birlikte kullanilir:
  1. Fan-out: host'un kendi baseline'ina gore ANORMAL sayida farkli
     hedefe baglanmasi (bkz. BaselineProfile.typical_max_targets_per_window).
  2. Dusuk hacim (VARSA): flows-tabanli veri kaynaklarinda (orn. LANL
     flows.txt), meta['byte_count'] mevcutsa, gercek veri transferi
     DEGIL, sadece "yoklama" niteliginde dusuk hacimli baglantilar
     aranir -- bu, yuksek-fan-out ama yuksek-hacimli MESRU trafigi
     (orn. bir yedekleme sunucusu) elemek icindir. Bu meta alani
     mevcut degilse (orn. pcap-tabanli Collector), sadece fan-out
     sinyaline guvenilir -- bu, ACIKCA belgelenen bir sinirlamadir.
"""

from __future__ import annotations

from collections import Counter
from datetime import timedelta

from sentinelpath.core.models import (
    BaselineProfile,
    GraphEdge,
    NormalizedEvent,
    RelationType,
)

TECHNIQUE_ID = "T1046"

# Bir baglantinin "yoklama" (dusuk hacim) sayilmasi icin ust sinir.
# Tipik bir SYN+RST/ACK denemesi bunun cok altindadir; gercek bir veri
# transferi (dosya erisimi, RDP oturumu) genelde bunu asar.
LOW_VOLUME_BYTE_THRESHOLD = 1024


def detect_scanning(
    events: list[NormalizedEvent],
    baseline_profiles: dict[str, BaselineProfile],
    window_minutes: int = 5,
) -> list[GraphEdge]:
    """Her host icin, kendi baseline esigini asan fan-out donemlerini
    ("tarama bolumu") tespit edip T1046 iliskili GraphEdge'ler uretir.

    Baseline profili olmayan (veya typical_max_targets_per_window'u
    None olan) host'lar icin HICBIR tespit yapilmaz (bkz. ADR 0006,
    0010, 0015 ile ayni "yetersiz veriyle iddiada bulunma" ilkesi).
    """
    edges: list[GraphEdge] = []
    window = timedelta(minutes=window_minutes)

    events_by_host: dict[str, list[NormalizedEvent]] = {}
    for event in events:
        if event.target_host is None:
            continue
        events_by_host.setdefault(event.source_host, []).append(event)

    for host, host_events in events_by_host.items():
        profile = baseline_profiles.get(host)
        if profile is None or profile.typical_max_targets_per_window is None:
            continue
        edges.extend(
            _detect_for_host(
                host, host_events, profile.typical_max_targets_per_window, window
            )
        )

    return edges


def _detect_for_host(
    host: str,
    host_events: list[NormalizedEvent],
    threshold: float,
    window: timedelta,
) -> list[GraphEdge]:
    sorted_events = sorted(host_events, key=lambda e: e.timestamp)
    left = 0
    seen_targets: Counter[str] = Counter()
    window_events: list[NormalizedEvent] = []

    edges: list[GraphEdge] = []
    in_episode = False
    episode_targets: set[str] = set()
    episode_max_ratio = 0.0

    for event in sorted_events:
        seen_targets[event.target_host] += 1
        window_events.append(event)
        while sorted_events[left].timestamp <= event.timestamp - window:
            leaving = sorted_events[left]
            seen_targets[leaving.target_host] -= 1
            if seen_targets[leaving.target_host] == 0:
                del seen_targets[leaving.target_host]
            window_events.pop(0)
            left += 1

        fanout = len(seen_targets)
        qualifies = fanout > threshold and _passes_volume_check(window_events)

        if qualifies:
            in_episode = True
            episode_targets.update(seen_targets.keys())
            episode_max_ratio = max(episode_max_ratio, fanout / threshold)
        elif in_episode:
            edges.extend(_emit_episode_edges(host, episode_targets, episode_max_ratio))
            in_episode = False
            episode_targets = set()
            episode_max_ratio = 0.0

    if in_episode:
        edges.extend(_emit_episode_edges(host, episode_targets, episode_max_ratio))

    return edges


def _passes_volume_check(window_events: list[NormalizedEvent]) -> bool:
    volumes = [
        int(e.metadata["byte_count"])
        for e in window_events
        if "byte_count" in e.metadata
    ]
    if not volumes:
        # Bu veri kaynagi hacim bilgisi tasimiyor (orn. pcap Collector)
        # -- sadece fan-out sinyaline guveniliyor (bkz. modul docstring'i).
        return True
    average = sum(volumes) / len(volumes)
    return average < LOW_VOLUME_BYTE_THRESHOLD


def _emit_episode_edges(
    host: str, targets: set[str], ratio: float
) -> list[GraphEdge]:
    return [
        GraphEdge(
            source_node=host,
            target_node=target,
            relation=RelationType.OBSERVED_SCANNING,
            weight=ratio,
            mitre_technique_ids=(TECHNIQUE_ID,),
        )
        for target in sorted(targets)
    ]