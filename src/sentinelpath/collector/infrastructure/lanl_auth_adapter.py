"""
collector.infrastructure.lanl_auth_adapter
==============================================

LANL auth.txt dosyasini NormalizedEvent listesine cevirir, ADR 0014'teki
UC KATMANLI MITRE teknik siniflandirmasini uygular. Format (gercek
veriden dogrulandi):

    time,src_user@domain,dst_user@domain,src_computer,dst_computer,
    auth_type,logon_type,orientation,outcome

REDTEAM.TXT'E HICBIR SEKILDE BAKMAZ (bkz. ADR 0014/0015, "sizinti
onleme"). Teknik atamasi SADECE bu dosyanin kendi semasina ve (varsa)
flows.txt capraz dogrulamasina dayanir.

ONEMLI NORMALIZASYON NOTU: LANL'in ham 'outcome' degerleri ("Success",
"Fail") pipeline'in geri kalaniyla UYUMSUZDUR --
graph_builder/infrastructure/networkx_adapter.py 'outcome' == "success"
(kucuk harf) bekler, feature_extraction/infrastructure/rule_based_extractor.py
ise "failure" (tam kelime) bekler. Bu adapter bu iki degeri DOGRU
formata cevirir -- aksi halde LANL verisinden hicbir AUTHENTICATES_TO
kenari uretilmez VE failed_auth_ratio sessizce hep 0.0 doner (gercek
calistirmada bulunup duzeltilmis bir hata).
"""

from __future__ import annotations

import gzip
from datetime import datetime
from pathlib import Path

from sentinelpath.collector.infrastructure.lanl_flows_adapter import (
    lanl_seconds_to_datetime,
    lookup_flow_technique,
)
from sentinelpath.core.models import EventSource, NormalizedEvent
from sentinelpath.logging_setup import get_logger

logger = get_logger(__name__)

IGNORED_LOGON_TYPES = frozenset(
    {"Interactive", "CachedInteractive", "Unlock", "Service", "Batch"}
)

NETWORK_LOGON_TYPES = frozenset({"Network", "NetworkCleartext"})
REMOTE_INTERACTIVE = "RemoteInteractive"  # Windows logon type 10 -- SADECE RDP

_OUTCOME_NORMALIZATION = {"success": "success", "fail": "failure"}


class LANLAuthCollector:
    """CollectorPort implementasyonu: LANL auth.txt -> NormalizedEvent.

    flow_index verilmezse (None), Katman 2 (flows.txt capraz dogrulama)
    hic denenmez -- tum "Network" tipi olaylar dogrudan Katman 3'e
    (genel T1021, dusuk guven) duser.
    """

    def __init__(
        self,
        auth_path: str,
        flow_index: dict[tuple[str, str], list[tuple[datetime, str]]] | None = None,
    ) -> None:
        self._auth_path = Path(auth_path)
        self._flow_index = flow_index or {}

    def source_name(self) -> str:
        return f"lanl_auth:{self._auth_path}"

    def collect(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        progress_every_lines: int = 0,
    ) -> list[NormalizedEvent]:
        total_size = self._auth_path.stat().st_size
        events: list[NormalizedEvent] = []
        line_num = 0

        raw_file = open(self._auth_path, "rb")
        try:
            with gzip.open(raw_file, "rt") as f:
                for line_num, line in enumerate(f, start=1):
                    if progress_every_lines and line_num % progress_every_lines == 0:
                        percent = raw_file.tell() / total_size * 100
                        logger.info(
                            "lanl_auth_progress",
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
            "lanl_auth_collected",
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
            time_s, src_user, _dst_user, src_computer, dst_computer,
            auth_type, logon_type, orientation, outcome,
        ) = parts

        if orientation != "LogOn":
            return None

        if src_user.split("@")[0].endswith("$"):
            return None

        if logon_type in IGNORED_LOGON_TYPES:
            return None

        timestamp = lanl_seconds_to_datetime(int(time_s))
        normalized_outcome = _OUTCOME_NORMALIZATION.get(outcome.lower(), outcome.lower())
        metadata = {
            "outcome": normalized_outcome,
            "auth_type": auth_type,
            "logon_type": logon_type,
        }

        technique_id: str | None
        raw_action: str
        target_host: str | None = dst_computer if dst_computer != src_computer else None

        if logon_type == REMOTE_INTERACTIVE:
            technique_id = "T1021.001"
            raw_action = "remote_interactive_logon:rdp"
        elif logon_type in NETWORK_LOGON_TYPES:
            if target_host is None:
                return None
            cross_ref = lookup_flow_technique(
                self._flow_index, src_computer, dst_computer, timestamp
            )
            if cross_ref is not None:
                technique_id = cross_ref
                raw_action = f"network_logon:cross_referenced:{cross_ref}"
            else:
                technique_id = "T1021"
                raw_action = "network_logon:unclassified"
        else:
            technique_id = None
            raw_action = f"logon:{logon_type}"

        return NormalizedEvent(
            event_id=f"lanl-auth-{line_num}",
            timestamp=timestamp,
            source=EventSource.AUTH,
            source_host=src_computer,
            target_host=target_host,
            user=src_user,
            raw_action=raw_action,
            mitre_technique_id=technique_id,
            metadata=metadata,
        )