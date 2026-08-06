"""
tests.test_pcap_adapter
==========================

DURUSTLUK NOTU
--------------
Bu test dosyasi `scapy` paketine bagimlidir (`pip install -e ".[network]"`).
Bu testler, bu projeyi hazirladigim sandbox ortaminda (internet erisimi
kapali, scapy kurulamiyor) CALISTIRILARAK DOGRULANAMADI. Sozdizimi
`python -m py_compile` ile kontrol edilmistir ve kod, packet_translation.py
ile ayni (zaten 10/10 testle dogrulanmis) mantigi kullanir -- ama
PcapFileCollector._read_packet_records() metodunun Scapy API'siyle
dogru etkilesime girdigi bu ortamda TEYIT EDILEMEMISTIR.

Kendi ortaminizda calistirmak icin:
    pip install -e ".[network,dev]"
    pytest tests/test_pcap_adapter.py -v

Eger bir hata cikarsa (orn. Scapy surum farkindan kaynakli bir API
degisikligi), en olasi hata noktasi pcap_adapter.py'deki
`_read_packet_records()` metodudur -- translate_packets() ayrica
dogrulanmis oldugu icin sorun byte parse etme, katman kodlariyla ilgili
degildir.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

scapy = pytest.importorskip("scapy.all", reason="scapy kurulu degil (pip install -e '.[network]')")


@pytest.fixture()
def sample_pcap_path(tmp_path: Path) -> str:
    """Scapy'nin kendi paket olusturma API'siyle (agdan bagimsiz, sadece
    bellekte bayt insasi) kucuk bir ornek pcap dosyasi uretir: bir RDP
    baglantisi (3389) ve bir bilinmeyen port baglantisi (9999) icerir.
    """

    from scapy.all import IP, TCP, wrpcap

    rdp_packet = IP(src="10.0.0.5", dst="10.0.0.10") / TCP(dport=3389, sport=51000)
    unknown_packet = IP(src="10.0.0.5", dst="10.0.0.11") / TCP(dport=9999, sport=51001)

    pcap_file = tmp_path / "sample.pcap"
    wrpcap(str(pcap_file), [rdp_packet, unknown_packet])
    return str(pcap_file)


def test_collect_produces_normalized_events(sample_pcap_path: str) -> None:
    from sentinelpath.collector.infrastructure.pcap_adapter import PcapFileCollector

    collector = PcapFileCollector(pcap_path=sample_pcap_path)
    events = collector.collect()

    assert len(events) == 2
    technique_ids = {e.mitre_technique_id for e in events}
    assert "T1021.001" in technique_ids  # RDP paketi taninmali
    assert None in technique_ids  # bilinmeyen port da bir event uretmeli


def test_source_name_reports_pcap_path(sample_pcap_path: str) -> None:
    from sentinelpath.collector.infrastructure.pcap_adapter import PcapFileCollector

    collector = PcapFileCollector(pcap_path=sample_pcap_path)
    assert sample_pcap_path in collector.source_name()


def test_since_filter_excludes_older_events(sample_pcap_path: str) -> None:
    from sentinelpath.collector.infrastructure.pcap_adapter import PcapFileCollector

    collector = PcapFileCollector(pcap_path=sample_pcap_path)
    future_cutoff = datetime.now(UTC).replace(year=2099)
    events = collector.collect(since=future_cutoff)
    assert events == []  # 2099'dan sonrasi istendigi icin hicbir event kalmamali


def test_missing_scapy_raises_clear_runtime_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scapy kurulu degilse, kullaniciya ne kurmasi gerektigini soyleyen
    acik bir hata verilmelidir -- sessiz bir ImportError yerine.
    """

    from sentinelpath.collector.infrastructure import pcap_adapter

    collector = pcap_adapter.PcapFileCollector(pcap_path="does-not-matter.pcap")

    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "scapy.all":
            raise ImportError("simulated missing scapy")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(RuntimeError, match="scapy kurulu degil"):
        collector.collect()
