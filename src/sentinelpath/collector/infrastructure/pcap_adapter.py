"""
collector.infrastructure.pcap_adapter
========================================

Bu dosya, projede scapy'ye bagimli TEK dosyadir (bu katman icin). Butun
sorumlulugu: bir .pcap dosyasini okumak, her paketi framework-bagimsiz
PacketRecord'a cevirmek, ve gercek "ne anlama geliyor" mantigini
packet_translation.translate_packets()'e devretmek.

NOT (durustluk icin): Bu dosya, gelistirme ortaminda (bu sandbox'ta)
scapy kurulu olmadigi ve internet erisimi kapali oldugu icin calistirilarak
DOGRULANAMADI. Import'lar fonksiyon ICINE (lazy import) alinmistir, ki
`pip install -e ".[network]"` yapilmadan bu modulun geri kalanini
(ornegin sadece tip kontrolu icin) import etmek scapy'nin kurulu olmasini
GEREKTIRMESIN. Sozdizimi `python -m py_compile` ile dogrulanmistir; asil
calisma zamani davranisi kullanicinin kendi ortaminda `pytest` ile
teyit edilmelidir (bkz. tests/test_pcap_adapter.py).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelpath.collector.infrastructure.packet_record import (
    PacketRecord,
    TransportProtocol,
)
from sentinelpath.collector.infrastructure.packet_translation import translate_packets
from sentinelpath.core.models import NormalizedEvent
from sentinelpath.logging_setup import get_logger

logger = get_logger(__name__)


class PcapFileCollector:
    """CollectorPort sozlesmesini bir .pcap dosyasi okuyarak karsilayan
    adapter. `domain.ports.CollectorPort`'tan miras ALMAZ (Protocol,
    structural subtyping kullanir -- bkz. collector/domain/ports.py
    dosyasindaki 'Neden Protocol' aciklamasi); imzalari karsiladigi icin
    tip sisteminde otomatik olarak CollectorPort sayilir.
    """

    def __init__(self, pcap_path: str) -> None:
        self._pcap_path = pcap_path

    def source_name(self) -> str:
        return f"pcap_file:{self._pcap_path}"

    def collect(self, since: datetime | None = None) -> list[NormalizedEvent]:
        records = self._read_packet_records()
        if since is not None:
            records = [r for r in records if r.timestamp > since]

        events = translate_packets(records)
        logger.info(
            "pcap_collected",
            source=self.source_name(),
            packet_count=len(records),
            event_count=len(events),
        )
        return events

    def _read_packet_records(self) -> list[PacketRecord]:
        """Scapy'ye bagimli TEK metod. Lazy import: scapy yalnizca bu
        metod cagrildiginda import edilir, boylece modulun geri kalani
        scapy kurulu olmadan da import edilebilir/tip kontrolunden
        gecebilir.
        """

        try:
            from scapy.all import IP, TCP, UDP, rdpcap  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - ortam kurulumu hatasi
            raise RuntimeError(
                "scapy kurulu degil. Kurulum icin: pip install -e '.[network]'"
            ) from exc

        packets = rdpcap(self._pcap_path)
        records: list[PacketRecord] = []

        for packet in packets:
            if IP not in packet:
                continue  # Faz 2 kapsami IPv4 ile sinirli

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            pkt_timestamp = datetime.fromtimestamp(float(packet.time), tz=UTC)
            payload_size = len(bytes(packet))

            if TCP in packet:
                protocol = TransportProtocol.TCP
                dst_port = int(packet[TCP].dport)
            elif UDP in packet:
                protocol = TransportProtocol.UDP
                dst_port = int(packet[UDP].dport)
            else:
                continue  # Faz 2 kapsami TCP/UDP ile sinirli (bkz. ARCHITECTURE.md gerekcesi)

            records.append(
                PacketRecord(
                    timestamp=pkt_timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    payload_size=payload_size,
                )
            )

        return records
