"""Discovery Detection (T1046) icin testler -- bkz. ADR 0015."""

from datetime import UTC, datetime, timedelta

from sentinelpath.core.models import (
    BaselineProfile,
    EventSource,
    NormalizedEvent,
    RelationType,
)
from sentinelpath.discovery_detection.infrastructure.scan_detector import (
    detect_scanning,
)

BASE = datetime(2026, 1, 1, tzinfo=UTC)


def _event(seconds_offset: int, target: str, byte_count: int | None = None) -> NormalizedEvent:
    metadata = {}
    if byte_count is not None:
        metadata["byte_count"] = str(byte_count)
    return NormalizedEvent(
        event_id=f"e{seconds_offset}-{target}",
        timestamp=BASE + timedelta(seconds=seconds_offset),
        source=EventSource.NETWORK,
        source_host="ATTACKER",
        target_host=target,
        user=None,
        raw_action="tcp_connect",
        metadata=metadata,
    )


def _profile(threshold: float | None) -> BaselineProfile:
    return BaselineProfile(
        node_id="ATTACKER",
        baseline_window_days=15,
        typical_active_hours=(),
        typical_peer_nodes=(),
        confidence=1.0,
        typical_max_targets_per_window=threshold,
    )


def test_no_profile_no_detection() -> None:
    events = [_event(i, f"host{i}") for i in range(10)]
    edges = detect_scanning(events, baseline_profiles={})
    assert edges == []


def test_threshold_none_no_detection() -> None:
    events = [_event(i, f"host{i}") for i in range(10)]
    profiles = {"ATTACKER": _profile(None)}
    edges = detect_scanning(events, baseline_profiles=profiles)
    assert edges == []


def test_below_threshold_no_detection() -> None:
    events = [_event(i, f"host{i}") for i in range(3)]
    profiles = {"ATTACKER": _profile(5.0)}
    edges = detect_scanning(events, baseline_profiles=profiles)
    assert edges == []


def test_above_threshold_detects_with_correct_technique() -> None:
    events = [_event(i, f"host{i}") for i in range(10)]
    profiles = {"ATTACKER": _profile(5.0)}
    edges = detect_scanning(events, baseline_profiles=profiles, window_minutes=5)
    assert len(edges) > 0
    assert all("T1046" in e.mitre_technique_ids for e in edges)
    assert all(e.relation == RelationType.OBSERVED_SCANNING for e in edges)


def test_high_volume_traffic_is_filtered_out() -> None:
    """Yuksek hacimli baglantilar (orn. bir yedekleme sunucusu) tarama
    olarak isaretlenmemeli -- sadece dusuk hacimli 'yoklama' baglantilari."""
    events = [_event(i, f"host{i}", byte_count=50_000) for i in range(10)]
    profiles = {"ATTACKER": _profile(5.0)}
    edges = detect_scanning(events, baseline_profiles=profiles, window_minutes=5)
    assert edges == []


def test_low_volume_traffic_is_detected() -> None:
    events = [_event(i, f"host{i}", byte_count=100) for i in range(10)]
    profiles = {"ATTACKER": _profile(5.0)}
    edges = detect_scanning(events, baseline_profiles=profiles, window_minutes=5)
    assert len(edges) > 0


def test_episode_based_emission_avoids_duplicate_explosion() -> None:
    """Uzun bir 'tarama bolumu' boyunca, ayni hedefe BIRDEN FAZLA kez
    kenar uretilmemeli -- bkz. modul docstring'i, 'episode' mantigi."""
    events = [_event(i, f"host{i % 10}") for i in range(30)]
    profiles = {"ATTACKER": _profile(5.0)}
    edges = detect_scanning(events, baseline_profiles=profiles, window_minutes=5)
    targets_in_edges = [e.target_node for e in edges]
    assert len(targets_in_edges) == len(set(targets_in_edges))


def test_events_without_target_host_are_ignored() -> None:
    events = [
        NormalizedEvent(
            event_id=f"nt{i}",
            timestamp=BASE + timedelta(seconds=i),
            source=EventSource.NETWORK,
            source_host="ATTACKER",
            target_host=None,
            user=None,
            raw_action="broadcast",
        )
        for i in range(20)
    ]
    profiles = {"ATTACKER": _profile(5.0)}
    edges = detect_scanning(events, baseline_profiles=profiles)
    assert edges == []