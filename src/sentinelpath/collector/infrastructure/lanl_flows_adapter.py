"""
collector.infrastructure.lanl_flows_adapter
===============================================

LANL Comprehensive Multi-Source Cyber-Security Events veri setinin
flows.txt dosyasini NormalizedEvent listesine cevirir (bkz. ADR 0014,
0015). Format (LANL resmi dokumantasyonu + gercek veriden dogrulandi):

    time,duration,src_computer,src_port,dst_computer,dst_port,protocol,
    packet_count,byte_count

`packet_translation.py`'deki AYNI PORT_TO_TECHNIQUE tablosunu yeniden
kullanir -- port-teknik eslemesi TEK bir yerde tanimli kalir (bkz.
ADR 0011/0015, "modul = tespit yontemi" prensibi; T1021 ailesi zaten
port-tabanli TEK bir mantiktan geliyor, pcap ve LANL flows icin ayri
ayri tanimlanmaz).
"""


from __future__ import annotations

import gzip
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinelpath.collector.infrastructure.packet_translation import PORT_TO_TECHNIQUE
from sentinelpath.core.models import EventSource, NormalizedEvent
from sentinelpath.logging_setup import get_logger

logger = get_logger(__name__)

# LANL veri seti zaman damgalari, veri toplama basindan itibaren gecen
# SANIYE SAYISIdir (gercek takvim tarihi degil). TUM LANL-tabanli
# adapter'ler (flows, auth) AYNI sanal baslangic tarihini kullanmalidir
# -- aksi halde zaman-tabanli capraz dogrulama (bkz. ADR 0014) bozulur.
LANL_VIRTUAL_EPOCH = datetime(2024, 1, 1, tzinfo=UTC)


def lanl_seconds_to_datetime(seconds: int) -> datetime:
    return LANL_VIRTUAL_EPOCH + timedelta(seconds=seconds)


class LANLFlowsCollector:
    """CollectorPort implementasyonu: LANL flows.txt -> NormalizedEvent."""

    def __init__(self, flows_path: str) -> None:
        self._flows_path = Path(flows_path)

    def source_name(self) -> str:
        return f"lanl_flows:{self._flows_path}"

    def collect(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        progress_every_lines: int = 0,
    ) -> list[NormalizedEvent]:
        """`until` verilirse, LANL verisinin ZAMANA GORE SIRALI oldugu
        varsayimiyla, o zamani gecen ilk satirda okuma DURDURULUR.

        `progress_every_lines` > 0 verilirse, her N satirda bir
        (yaklasik) ilerleme yuzdesi loglanir -- sikistirilmis dosyanin
        ne kadarinin okundugu, gercek bayt konumuna gore hesaplanir.
        Buyuk dosyalarda (orn. LANL auth.txt, ~7.4GB) tek seferlik bir
        ilerleme gostergesi ihtiyacindan dogdu, varsayilan 0 = kapali.
        """
        total_size = self._flows_path.stat().st_size
        events: list[NormalizedEvent] = []
        line_num = 0

        raw_file = open(self._flows_path, "rb")
        try:
            with gzip.open(raw_file, "rt") as f:
                for line_num, line in enumerate(f, start=1):
                    if progress_every_lines and line_num % progress_every_lines == 0:
                        percent = raw_file.tell() / total_size * 100
                        logger.info(
                            "lanl_flows_progress",
                            lines_read=line_num,
                            events_collected=len(events),
                            compressed_bytes_percent=round(percent, 1),
                        )

                    parsed = self._parse_line(line, line_num)
                    if parsed is None:
                        continue
                    if until is not None and parsed.timestamp > until:
                        break
                    if since is not None and parsed.timestamp < since:
                        continue
                    events.append(parsed)
        finally:
            raw_file.close()

        logger.info(
            "lanl_flows_collected",
            source=self.source_name(),
            lines_read=line_num,
            event_count=len(events),
        )
        return events

    def _parse_line(self, line: str, line_num: int) -> NormalizedEvent | None:
        parts = line.strip().split(",")
        if len(parts) != 9:
            return None
        (
            time_s, duration, src, _src_port, dst, dst_port,
            protocol, _packet_count, byte_count,
        ) = parts

        try:
            dst_port_int: int | None = int(dst_port)
        except ValueError:
            dst_port_int = None  # LANL bazen "N####" gibi isimlendirilmis port kodu kullanir

        known = PORT_TO_TECHNIQUE.get(dst_port_int) if dst_port_int is not None else None
        if known is not None:
            service_name, technique_id = known
        else:
            service_name, technique_id = f"port_{dst_port}", None

        return NormalizedEvent(
            event_id=f"lanl-flow-{line_num}",
            timestamp=lanl_seconds_to_datetime(int(time_s)),
            source=EventSource.NETWORK,
            source_host=src,
            target_host=dst,
            user=None,
            raw_action=f"tcp_connect:{service_name}",
            mitre_technique_id=technique_id,
            metadata={
                "byte_count": byte_count,
                "duration": duration,
                "dst_port": dst_port,
                "protocol": protocol,
            },
        )


def build_flow_technique_index(
    flow_events: list[NormalizedEvent],
) -> dict[tuple[str, str], list[tuple[datetime, str]]]:
    """(kaynak, hedef) -> [(zaman, teknik_id), ...] sozlugu -- ADR 0014
    Karar 2'deki auth.txt/flows.txt capraz dogrulamasi icin kullanilir.

    Basit, dogrusal (linear-scan) arama kullanir -- LANL olcegindeki
    tam performans optimizasyonu bilerek YAPILMADI (YAGNI); gerektiginde
    eklenebilir.
    """
    index: dict[tuple[str, str], list[tuple[datetime, str]]] = {}
    for event in flow_events:
        if event.mitre_technique_id is None:
            continue
        key = (event.source_host, event.target_host)
        index.setdefault(key, []).append((event.timestamp, event.mitre_technique_id))
    return index


def lookup_flow_technique(
    index: dict[tuple[str, str], list[tuple[datetime, str]]],
    source: str,
    target: str,
    at_time: datetime,
    time_tolerance_seconds: int = 60,
) -> str | None:
    candidates = index.get((source, target))
    if not candidates:
        return None
    tolerance = timedelta(seconds=time_tolerance_seconds)
    for ts, technique_id in candidates:
        if abs(ts - at_time) <= tolerance:
            return technique_id
    return None