"""
tests.test_in_memory_baseline
================================

Tamamen stdlib'e dayanir (acik esik parametreleriyle pydantic-settings
bagimliligindan kacinilir -- bkz. Faz 3'teki ayni desen).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sentinelpath.baseline_behavior.infrastructure.in_memory_baseline import (
    InMemoryBaselineBehavior,
)
from sentinelpath.core.models import EventSource, NormalizedEvent

WINDOW_START = datetime(2026, 1, 1, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 1, 15, tzinfo=timezone.utc)  # 14 gunluk pencere


def _event(day_offset: int, hour: int, target: str | None = "host-b", **overrides) -> NormalizedEvent:
    timestamp = WINDOW_START + timedelta(days=day_offset, hours=hour)
    defaults = dict(
        event_id=f"e-{day_offset}-{hour}",
        timestamp=timestamp,
        source=EventSource.NETWORK,
        source_host="host-a",
        target_host=target,
        user=None,
        raw_action="tcp_connect:port_1234",
        mitre_technique_id=None,
        metadata={},
    )
    defaults.update(overrides)
    return NormalizedEvent(**defaults)


def _extractor() -> InMemoryBaselineBehavior:
    return InMemoryBaselineBehavior(hour_frequency_threshold=0.15, peer_day_fraction_threshold=0.2)


def test_no_events_produces_no_profiles() -> None:
    baseline = _extractor()
    profiles = baseline.recompute([], WINDOW_START, WINDOW_END)
    assert profiles == []
    assert baseline.get_profile("host-a") is None


def test_events_outside_window_are_excluded() -> None:
    baseline = _extractor()
    outside_event = _event(day_offset=-5, hour=10)  # pencereden 5 gun once

    profiles = baseline.recompute([outside_event], WINDOW_START, WINDOW_END)
    assert profiles == []


def test_typical_active_hours_requires_frequency_above_threshold() -> None:
    """host-a, 10 farkli gunde saat 10'da aktif (baskin patern);
    ayrica 1 gunde (11. gun) saat 3'te tek seferlik bir aktivite var
    (dusuk frekans -- typical SAYILMAMALI)."""

    baseline = _extractor()  # esik: 0.15
    events = [_event(day_offset=d, hour=10) for d in range(10)]
    events.append(_event(day_offset=10, hour=3, target="host-c"))

    profiles = baseline.recompute(events, WINDOW_START, WINDOW_END)
    profile = next(p for p in profiles if p.node_id == "host-a")

    assert 10 in profile.typical_active_hours       # 10/11 = %91 -> tipik
    assert 3 not in profile.typical_active_hours     # 1/11  = %9  -> esigin altinda


def test_typical_peer_nodes_requires_recurrence_across_days() -> None:
    """host-b her gun gorulen bir peer (tipik); host-c sadece 1 gun
    gorulen bir peer (tipik DEGIL)."""

    baseline = _extractor()  # esik: 0.2
    events = [_event(day_offset=d, hour=10, target="host-b") for d in range(10)]
    events.append(_event(day_offset=10, hour=3, target="host-c"))

    profiles = baseline.recompute(events, WINDOW_START, WINDOW_END)
    profile = next(p for p in profiles if p.node_id == "host-a")

    assert "host-b" in profile.typical_peer_nodes
    assert "host-c" not in profile.typical_peer_nodes


def test_confidence_scales_with_observed_days_vs_requested_window() -> None:
    baseline = _extractor()
    # 14 gunluk pencerede sadece 7 farkli gunde aktivite var
    events = [_event(day_offset=d, hour=10) for d in range(7)]

    profiles = baseline.recompute(events, WINDOW_START, WINDOW_END)
    profile = next(p for p in profiles if p.node_id == "host-a")

    assert abs(profile.confidence - 0.5) < 1e-9  # 7/14


def test_single_day_of_data_yields_low_confidence() -> None:
    baseline = _extractor()
    events = [_event(day_offset=0, hour=10)]  # tek gun

    profiles = baseline.recompute(events, WINDOW_START, WINDOW_END)
    profile = next(p for p in profiles if p.node_id == "host-a")

    assert profile.confidence < 0.1  # 1/14 gun -> cok dusuk guven


def test_get_profile_returns_none_before_recompute() -> None:
    baseline = _extractor()
    assert baseline.get_profile("host-a") is None


def test_get_profile_returns_stored_profile_after_recompute() -> None:
    baseline = _extractor()
    events = [_event(day_offset=d, hour=10) for d in range(10)]

    baseline.recompute(events, WINDOW_START, WINDOW_END)
    profile = baseline.get_profile("host-a")

    assert profile is not None
    assert profile.node_id == "host-a"


def test_recompute_fully_replaces_previous_profiles() -> None:
    """Ikinci bir recompute() cagrisi, host-a icin eski veriyi degil
    SADECE yeni verilen event'leri yansitmalidir (tam degistirme)."""

    baseline = _extractor()
    first_events = [_event(day_offset=d, hour=10, source_host="host-a") for d in range(10)]
    baseline.recompute(first_events, WINDOW_START, WINDOW_END)
    assert baseline.get_profile("host-a") is not None

    second_events = [_event(day_offset=d, hour=10, source_host="host-x") for d in range(5)]
    baseline.recompute(second_events, WINDOW_START, WINDOW_END)

    assert baseline.get_profile("host-a") is None  # artik yok -- tam degistirildi
    assert baseline.get_profile("host-x") is not None


def test_host_with_no_target_host_events_has_empty_typical_peers() -> None:
    baseline = _extractor()
    events = [_event(day_offset=d, hour=10, target=None) for d in range(10)]

    profiles = baseline.recompute(events, WINDOW_START, WINDOW_END)
    profile = next(p for p in profiles if p.node_id == "host-a")

    assert profile.typical_peer_nodes == ()
