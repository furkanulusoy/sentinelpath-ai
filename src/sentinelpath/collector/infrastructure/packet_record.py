"""
collector.infrastructure.packet_record
========================================

PacketRecord, Scapy'den (veya baska bir paket yakalama kutuphanesinden)
TAMAMEN bagimsiz, saf bir veri tipidir.

MIMARI GEREKCE
--------------
Bu tipin var olma nedeni, packet_translation.py'nin scapy'ye bagimli
olmamasini saglamaktir. pcap_adapter.py (Scapy'ye bagimli TEK dosya),
her Scapy paketini bu tipe cevirir; geri kalan tum mantik (port -> MITRE
teknigi eslemesi gibi) bu saf tip uzerinden calisir ve bu sayede Scapy
kurulu olmadan bile test edilebilir.

Bu, Faz 1'de core.models icin uyguladigimiz "framework'ten bagimsiz ic
temsil" prensibinin, tek bir modul icinde bir kademe daha derine
uygulanmis halidir.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class TransportProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    OTHER = "other"


@dataclass(frozen=True)
class PacketRecord:
    """Tek bir ag paketinin/akisinin, framework-bagimsiz temsili.

    Not: Bu bir NormalizedEvent DEGILDIR (core.models'e ait degildir).
    Bu tip, yalnizca Collector'in ic cevrim surecine (Scapy -> ortak
    format -> NormalizedEvent) ait bir ara adimdir; pipeline'in geri
    kalan katmanlari bu tipten haberdar degildir ve olmamalidir.
    """

    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: TransportProtocol
    payload_size: int = 0
