"""LANLFlowsCollector ve yardimci fonksiyonlari icin testler -- bkz. ADR 0014."""

import gzip
from datetime import datetime, timedelta
from pathlib import Path

from sentinelpath.collector.infrastructure.lanl_flows_adapter import (
    LANL_VIRTUAL_EPOCH,
    LANLFlowsCollector,
    build_flow_technique_index,
    lanl_seconds_to_datetime,
    lookup_flow_technique,
)
from sentinelpath.core.models import NormalizedEvent


def _write_flows_gz(path: Path, lines: list[str]) -> None:
    with gzip.open(path, "wt") as f:
        f.write("\n".join(lines) + "\n")


def test_known_port_maps_to_technique(tmp_path: Path) -> None:
    flows_path = tmp_path / "flows.txt.gz"
    _write_flows_gz(flows_path, ["1,0,C1,100,C2,445,6,10,200"])

    events = LANLFlowsCollector(str(flows_path)).collect()

    assert len(events) == 1
    assert events[0].mitre_technique_id == "T1021.002"
    assert events[0].raw_action == "tcp_connect:smb_admin_shares"


def test_unknown_port_produces_event_without_technique(tmp_path: Path) -> None:
    flows_path = tmp_path / "flows.txt.gz"
    _write_flows_gz(flows_path, ["1,0,C1,100,C2,8080,6,10,200"])

    events = LANLFlowsCollector(str(flows_path)).collect()

    assert events[0].mitre_technique_id is None


def test_named_port_code_does_not_crash(tmp_path: Path) -> None:
    """LANL bazen dst_port alaninda 'N####' gibi isimlendirilmis kodlar
    kullanir -- int() basarisiz olsa bile crash etmemeli."""
    flows_path = tmp_path / "flows.txt.gz"
    _write_flows_gz(flows_path, ["1,0,C1,100,C2,N10451,6,10,200"])

    events = LANLFlowsCollector(str(flows_path)).collect()

    assert len(events) == 1
    assert events[0].mitre_technique_id is None


def test_time_conversion_uses_virtual_epoch() -> None:
    result = lanl_seconds_to_datetime(3600)
    assert result == LANL_VIRTUAL_EPOCH + timedelta(hours=1)


def test_since_filter_excludes_older_events(tmp_path: Path) -> None:
    flows_path = tmp_path / "flows.txt.gz"
    _write_flows_gz(
        flows_path,
        ["1,0,C1,100,C2,445,6,10,200", "1000000,0,C1,100,C3,445,6,10,200"],
    )

    all_events = LANLFlowsCollector(str(flows_path)).collect()
    assert len(all_events) == 2

    cutoff = LANL_VIRTUAL_EPOCH + timedelta(seconds=500000)
    recent_events = LANLFlowsCollector(str(flows_path)).collect(since=cutoff)
    assert len(recent_events) == 1
    assert recent_events[0].target_host == "C3"


def test_malformed_line_is_skipped(tmp_path: Path) -> None:
    flows_path = tmp_path / "flows.txt.gz"
    _write_flows_gz(flows_path, ["eksik,kolon,sayisi", "1,0,C1,100,C2,445,6,10,200"])

    events = LANLFlowsCollector(str(flows_path)).collect()

    assert len(events) == 1


def test_source_name_reports_path(tmp_path: Path) -> None:
    flows_path = tmp_path / "flows.txt.gz"
    _write_flows_gz(flows_path, ["1,0,C1,100,C2,445,6,10,200"])

    collector = LANLFlowsCollector(str(flows_path))

    assert str(flows_path) in collector.source_name()


def _flow_event(
    source: str, target: str, timestamp: datetime, technique: str | None
) -> NormalizedEvent:
    from sentinelpath.core.models import EventSource

    return NormalizedEvent(
        event_id="x",
        timestamp=timestamp,
        source=EventSource.NETWORK,
        source_host=source,
        target_host=target,
        user=None,
        raw_action="tcp_connect:x",
        mitre_technique_id=technique,
    )


def test_index_only_includes_events_with_technique() -> None:
    ts = LANL_VIRTUAL_EPOCH
    events = [
        _flow_event("a", "b", ts, "T1021.002"),
        _flow_event("a", "c", ts, None),
    ]
    index = build_flow_technique_index(events)

    assert ("a", "b") in index
    assert ("a", "c") not in index


def test_lookup_finds_match_within_tolerance() -> None:
    ts = LANL_VIRTUAL_EPOCH
    index = build_flow_technique_index([_flow_event("a", "b", ts, "T1021.002")])

    result = lookup_flow_technique(index, "a", "b", ts + timedelta(seconds=30))

    assert result == "T1021.002"


def test_lookup_returns_none_outside_tolerance() -> None:
    ts = LANL_VIRTUAL_EPOCH
    index = build_flow_technique_index([_flow_event("a", "b", ts, "T1021.002")])

    result = lookup_flow_technique(index, "a", "b", ts + timedelta(seconds=120))

    assert result is None


def test_lookup_returns_none_for_unknown_pair() -> None:
    ts = LANL_VIRTUAL_EPOCH
    index = build_flow_technique_index([_flow_event("a", "b", ts, "T1021.002")])

    result = lookup_flow_technique(index, "x", "y", ts)

    assert result is None