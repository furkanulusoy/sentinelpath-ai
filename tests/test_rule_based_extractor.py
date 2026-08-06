"""
tests.test_rule_based_extractor
==================================

Bu testler tamamen stdlib'e dayanir (RuleBasedFeatureExtractor'a acik
business_hours parametreleri vererek pydantic-settings bagimliligindan
kacinilir -- bkz. sinifin __init__ metodundaki lazy-import yorumu).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelpath.core.models import EventSource, NormalizedEvent
from sentinelpath.feature_extraction.infrastructure.rule_based_extractor import (
    RuleBasedFeatureExtractor,
)

WINDOW_START = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
WINDOW_END = datetime(2026, 1, 2, 0, 0, tzinfo=UTC)


def _event(**overrides) -> NormalizedEvent:
    defaults = dict(
        event_id="e",
        timestamp=datetime(2026, 1, 1, 10, 0, tzinfo=UTC),  # business hours icinde
        source=EventSource.ENDPOINT,
        source_host="host-a",
        target_host="host-b",
        user="alice",
        raw_action="process_create",
        mitre_technique_id=None,
        metadata={},
    )
    defaults.update(overrides)
    return NormalizedEvent(**defaults)


def _extractor() -> RuleBasedFeatureExtractor:
    # business_hours = 08:00-18:00 (acik parametre, pydantic-settings gerekmez)
    return RuleBasedFeatureExtractor(business_hours_start=8, business_hours_end=18)


def test_empty_event_list_produces_zeroed_vector() -> None:
    extractor = _extractor()
    vector = extractor.extract("host-a", [], WINDOW_START, WINDOW_END)

    assert vector.host_id == "host-a"
    assert vector.distinct_users_count == 0
    assert vector.distinct_target_hosts_count == 0
    assert vector.failed_auth_ratio == 0.0
    assert vector.off_hours_activity_ratio == 0.0
    assert vector.observed_techniques == ()


def test_events_outside_window_are_excluded() -> None:
    extractor = _extractor()
    outside_event = _event(timestamp=datetime(2025, 12, 1, 10, 0, tzinfo=UTC))

    vector = extractor.extract("host-a", [outside_event], WINDOW_START, WINDOW_END)
    assert vector.distinct_users_count == 0  # pencere disinda oldugu icin sayilmamali


def test_events_for_other_hosts_are_excluded() -> None:
    extractor = _extractor()
    other_host_event = _event(source_host="host-z")

    vector = extractor.extract("host-a", [other_host_event], WINDOW_START, WINDOW_END)
    assert vector.distinct_users_count == 0


def test_distinct_users_and_targets_are_counted_correctly() -> None:
    extractor = _extractor()
    events = [
        _event(user="alice", target_host="host-b"),
        _event(user="bob", target_host="host-c"),
        _event(user="alice", target_host="host-b"),  # tekrar -- tekil sayilmali
        _event(user=None, target_host=None),  # eksik alanlar sayilmamali
    ]

    vector = extractor.extract("host-a", events, WINDOW_START, WINDOW_END)
    assert vector.distinct_users_count == 2
    assert vector.distinct_target_hosts_count == 2


def test_failed_auth_ratio_only_counts_auth_events_with_known_outcome() -> None:
    extractor = _extractor()
    events = [
        _event(source=EventSource.AUTH, metadata={"outcome": "failure"}),
        _event(source=EventSource.AUTH, metadata={"outcome": "failure"}),
        _event(source=EventSource.AUTH, metadata={"outcome": "success"}),
        _event(source=EventSource.AUTH, metadata={}),  # outcome yok -> sayilmaz
        _event(
            source=EventSource.ENDPOINT, metadata={"outcome": "failure"}
        ),  # AUTH degil -> sayilmaz
    ]

    vector = extractor.extract("host-a", events, WINDOW_START, WINDOW_END)
    # Paydaya sadece outcome bilgisi olan 3 AUTH event'i girer, 2'si failure -> 2/3
    assert abs(vector.failed_auth_ratio - (2 / 3)) < 1e-9


def test_failed_auth_ratio_is_zero_not_error_when_no_signal() -> None:
    """'Sinyal yok' durumunun 0.0 donmesi -- ama bunun 'hep basarili'
    anlamina GELMEDIGI, extractor'in docstring'inde acikca belirtilmistir.
    Bu test sadece CRASH ETMEDIGINI ve 0.0 dondugunu dogrular.
    """

    extractor = _extractor()
    events = [_event(source=EventSource.ENDPOINT)]  # hic AUTH event'i yok

    vector = extractor.extract("host-a", events, WINDOW_START, WINDOW_END)
    assert vector.failed_auth_ratio == 0.0


def test_off_hours_activity_ratio() -> None:
    extractor = _extractor()  # business hours: 08-18
    events = [
        _event(timestamp=datetime(2026, 1, 1, 10, 0, tzinfo=UTC)),  # 10:00 -> is saati
        _event(timestamp=datetime(2026, 1, 1, 3, 0, tzinfo=UTC)),  # 03:00 -> off-hours
        _event(timestamp=datetime(2026, 1, 1, 22, 0, tzinfo=UTC)),  # 22:00 -> off-hours
        _event(timestamp=datetime(2026, 1, 1, 14, 0, tzinfo=UTC)),  # 14:00 -> is saati
    ]

    vector = extractor.extract("host-a", events, WINDOW_START, WINDOW_END)
    assert abs(vector.off_hours_activity_ratio - 0.5) < 1e-9  # 2/4


def test_observed_techniques_are_unique_and_sorted() -> None:
    extractor = _extractor()
    events = [
        _event(mitre_technique_id="T1021.001"),
        _event(mitre_technique_id="T1078"),
        _event(mitre_technique_id="T1021.001"),  # tekrar
        _event(mitre_technique_id=None),  # bilinmiyor -> disarida
    ]

    vector = extractor.extract("host-a", events, WINDOW_START, WINDOW_END)
    assert vector.observed_techniques == ("T1021.001", "T1078")


def test_feature_names_matches_documented_contract() -> None:
    extractor = _extractor()
    names = extractor.feature_names()
    assert "distinct_users_count" in names
    assert "failed_auth_ratio" in names
    assert "observed_techniques" in names


def test_window_end_is_exclusive() -> None:
    extractor = _extractor()
    boundary_event = _event(timestamp=WINDOW_END)  # tam pencere sonu -> haric tutulmali

    vector = extractor.extract("host-a", [boundary_event], WINDOW_START, WINDOW_END)
    assert vector.distinct_users_count == 0
