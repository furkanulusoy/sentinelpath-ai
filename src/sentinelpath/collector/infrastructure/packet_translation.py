"""
collector.infrastructure.packet_translation
==============================================

Bu dosya BILEREK scapy import ETMEZ. Sozlesme: bu modul yalnizca stdlib
ve sentinelpath.core.models'e bagimli olabilir. Bu kural bozulursa, bu
dosyanin var olma amaci (Scapy'siz test edilebilirlik) ortadan kalkar.

Port -> MITRE ATT&CK teknigi eslemesi, MITRE'nin kendi kamuya acik ATT&CK
veri tabanindaki T1021 (Remote Services) alt-tekniklerine dayanir. Bu bir
saldiri rehberi degildir -- tam tersine, savunma amacli bir attack graph
aracinin, gozlemlenen bir aga-baglanti turunu HANGI bilinen tekniğe
karsilik geldigini etiketlemesidir (network defenders'in zaten bildigi,
"port 3389 = RDP" seviyesinde genel bilgi).
"""

from __future__ import annotations

import hashlib

from sentinelpath.collector.infrastructure.packet_record import (
    PacketRecord,
    TransportProtocol,
)
from sentinelpath.core.models import EventSource, NormalizedEvent

# service_name, MITRE T1021 alt-teknik ID'si
PORT_TO_TECHNIQUE: dict[int, tuple[str, str]] = {
    22: ("ssh", "T1021.004"),
    135: ("dcom", "T1021.003"),
    445: ("smb_admin_shares", "T1021.002"),
    3389: ("rdp", "T1021.001"),
    5900: ("vnc", "T1021.005"),
    5985: ("winrm_http", "T1021.006"),
    5986: ("winrm_https", "T1021.006"),
}


def _deterministic_event_id(record: PacketRecord) -> str:
    """Ayni pcap dosyasi birden fazla kez okunsa bile ayni event_id'lerin
    uretilmesini saglar (idempotency). Bu, Faz 5'te baseline hesaplamasi
    ayni veriyi iki kez saymasin diye onemlidir.
    """

    raw = (
        f"{record.timestamp.isoformat()}|{record.src_ip}|{record.dst_ip}|"
        f"{record.dst_port}|{record.protocol.value}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def translate_packet(record: PacketRecord) -> NormalizedEvent | None:
    """Tek bir PacketRecord'u NormalizedEvent'e cevirir.

    Asagidaki durumlarda None doner (event uretilmez):
      - Protokol TCP/UDP disinda ise (Faz 2 kapsami baglanti-yonelimli
        trafikle sinirli; ICMP vb. gelecekte ele alinabilir).
      - Kaynak ve hedef IP ayniysa (loopback/self-trafik, sinyal degeri yok).
    """

    if record.protocol not in (TransportProtocol.TCP, TransportProtocol.UDP):
        return None
    if record.src_ip == record.dst_ip:
        return None

    known_service = PORT_TO_TECHNIQUE.get(record.dst_port)
    if known_service is not None:
        service_name, technique_id = known_service
        raw_action = f"{record.protocol.value}_connect:{service_name}"
    else:
        service_name, technique_id = None, None
        raw_action = f"{record.protocol.value}_connect:port_{record.dst_port}"

    return NormalizedEvent(
        event_id=_deterministic_event_id(record),
        timestamp=record.timestamp,
        source=EventSource.NETWORK,
        source_host=record.src_ip,
        target_host=record.dst_ip,
        user=None,  # ham ag trafiginde kullanici bilgisi yoktur (bkz. AUTH kaynagi, ileride)
        raw_action=raw_action,
        mitre_technique_id=technique_id,
        metadata={
            "dst_port": str(record.dst_port),
            "protocol": record.protocol.value,
            "payload_size": str(record.payload_size),
        },
    )


def translate_packets(records: list[PacketRecord]) -> list[NormalizedEvent]:
    """Bir PacketRecord listesini NormalizedEvent listesine cevirir,
    None donenleri (ilgisiz paketleri) filtreler.
    """

    events: list[NormalizedEvent] = []
    for record in records:
        event = translate_packet(record)
        if event is not None:
            events.append(event)
    return events
