"""
tests.test_packet_translation
================================

Bu test dosyasi BILEREK scapy'ye bagimli DEGILDIR -- packet_translation.py
ile ayni "saf mantik" sinirini paylasir. PacketRecord'lari elle kurup
dogrudan translate_packet()/translate_packets() cagirir.

Bu, Faz 2'nin mimari kararinin (Scapy I/O ile domain mantiginin ayrilmasi)
somut faydasidir: bu testler Scapy kurulu olmasa bile calisir.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sentinelpath.collector.infrastructure.packet_record import (
    PacketRecord,
    TransportProtocol,
)
from sentinelpath.collector.infrastructure.packet_translation import (
    translate_packet,
    translate_packets,
)
from sentinelpath.core.models import EventSource

NOW = datetime.now(timezone.utc)


def _record(**overrides) -> PacketRecord:
    defaults = dict(
        timestamp=NOW,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.10",
        dst_port=3389,
        protocol=TransportProtocol.TCP,
        payload_size=128,
    )
    defaults.update(overrides)
    return PacketRecord(**defaults)


def test_known_service_port_maps_to_mitre_technique() -> None:
    event = translate_packet(_record(dst_port=3389))
    assert event is not None
    assert event.mitre_technique_id == "T1021.001"
    assert event.raw_action == "tcp_connect:rdp"
    assert event.source is EventSource.NETWORK


def test_smb_port_maps_to_correct_subtechnique() -> None:
    event = translate_packet(_record(dst_port=445))
    assert event is not None
    assert event.mitre_technique_id == "T1021.002"


def test_unknown_port_still_produces_event_without_technique() -> None:
    event = translate_packet(_record(dst_port=8080))
    assert event is not None
    assert event.mitre_technique_id is None
    assert event.raw_action == "tcp_connect:port_8080"


def test_udp_protocol_is_labelled_correctly() -> None:
    event = translate_packet(_record(dst_port=53, protocol=TransportProtocol.UDP))
    assert event is not None
    assert event.raw_action == "udp_connect:port_53"


def test_non_tcp_udp_protocol_is_filtered_out() -> None:
    event = translate_packet(_record(protocol=TransportProtocol.OTHER))
    assert event is None


def test_self_traffic_is_filtered_out() -> None:
    event = translate_packet(_record(src_ip="10.0.0.5", dst_ip="10.0.0.5"))
    assert event is None


def test_event_id_is_deterministic_for_identical_records() -> None:
    record = _record()
    event_a = translate_packet(record)
    event_b = translate_packet(record)
    assert event_a is not None and event_b is not None
    assert event_a.event_id == event_b.event_id


def test_event_id_differs_for_different_records() -> None:
    event_a = translate_packet(_record(dst_port=3389))
    event_b = translate_packet(_record(dst_port=445))
    assert event_a is not None and event_b is not None
    assert event_a.event_id != event_b.event_id


def test_translate_packets_filters_none_results() -> None:
    records = [
        _record(dst_port=3389),               # gecerli -> event
        _record(src_ip="10.0.0.5", dst_ip="10.0.0.5"),  # self-trafik -> None
        _record(protocol=TransportProtocol.OTHER),      # ICMP vb. -> None
    ]
    events = translate_packets(records)
    assert len(events) == 1
    assert events[0].mitre_technique_id == "T1021.001"


def test_metadata_contains_port_and_protocol() -> None:
    event = translate_packet(_record(dst_port=22, protocol=TransportProtocol.TCP))
    assert event is not None
    assert event.metadata["dst_port"] == "22"
    assert event.metadata["protocol"] == "tcp"
