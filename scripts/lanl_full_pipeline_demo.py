"""
scripts/lanl_full_pipeline_demo.py
=====================================

Faz B: C17693 (redteam.txt'ten dogrulanmis GERCEK saldirgan) icin,
TAM pipeline'i (PipelineOrchestrator uzerinden -- Faz 9'da zaten test
edilmis, dashboard'un da kullandigi AYNI yol) gercek LANL verisiyle
calistirir.
"""

import json
from datetime import timedelta

from sentinelpath.collector.infrastructure.lanl_auth_adapter import LANLAuthCollector
from sentinelpath.collector.infrastructure.lanl_flows_adapter import (
    LANL_VIRTUAL_EPOCH,
    LANLFlowsCollector,
    build_flow_technique_index,
)
from sentinelpath.orchestration.pipeline_orchestrator import (
    PipelineConfig,
    PipelineOrchestrator,
)
from sentinelpath.reporting.infrastructure.json_reporting import JSONReporting

import time
_start = time.time()

def checkpoint(label):
    elapsed = time.time() - _start
    print(f"[{elapsed/60:.1f} dk] {label}")

WINDOW_START = LANL_VIRTUAL_EPOCH + timedelta(days=1)
WINDOW_END = LANL_VIRTUAL_EPOCH + timedelta(days=2)
START_NODE = "C17693"  # bkz. ADR 0015 -- redteam.txt'ten dogrulanmis gercek saldirgan

print("flows.txt okunuyor...")
flows_collector = LANLFlowsCollector("scripts/lanl_data/flows.txt.gz")
flow_events = flows_collector.collect(
    since=WINDOW_START, until=WINDOW_END, progress_every_lines=2_000_000
)
print(f"  {len(flow_events)} flow event")
checkpoint(f"flows.txt bitti ({len(flow_events)} event)")

flow_index = build_flow_technique_index(flow_events)

print("\nauth.txt okunuyor...")
auth_collector = LANLAuthCollector("scripts/lanl_data/auth.txt.gz", flow_index=flow_index)
auth_events = auth_collector.collect(
    since=WINDOW_START, until=WINDOW_END, progress_every_lines=2_000_000
)
print(f"  {len(auth_events)} auth event")
checkpoint(f"auth.txt bitti ({len(auth_events)} event)")

all_events = flow_events + auth_events
print(f"\nToplam {len(all_events)} event, pipeline'a veriliyor...")

known_hosts = sorted(
    {e.source_host for e in all_events}
    | {e.target_host for e in all_events if e.target_host}
)
print(f"  {len(known_hosts)} farkli host taniniyor")

if START_NODE not in known_hosts:
    raise SystemExit(f"HATA: {START_NODE}, bu pencerede hic event uretmemis.")

print("\nPipelineOrchestrator calistiriliyor (bu adim biraz surebilir, Gorev Yoneticisi'ni izleyin)...")
orchestrator = PipelineOrchestrator(
    PipelineConfig(
        default_asset_criticality=0.5,
        default_technique_severity=0.5,
        max_hops=2,  # gercek, yogun graf'ta 4 komb. patlamaya yol acti -- once 2'yi deneyelim
    )
)

report = orchestrator.run(
    events=all_events,
    known_hosts=known_hosts,
    start_node=START_NODE,
    feature_window_start=WINDOW_START,
    feature_window_end=WINDOW_END,
    baseline_window_start=WINDOW_START,
    baseline_window_end=WINDOW_END,
)

print("\n=== SONUC ===")
print(f"Baslangic node: {report.target_node}")
print(f"\nRisk skorlari ({len(report.risk_scores)} adet):")
checkpoint(f"pipeline bitti ({len(report.risk_scores)} risk skoru)")

for rs in report.risk_scores:
    print(
        f"  hedef={rs.target_node:15s} teknik={rs.technique_id:12s} "
        f"olasilik={rs.probability:.2f} skor={rs.score:5.1f} "
        f"baseline_guven={rs.baseline_confidence}"
    )

print(f"\nOneriler ({len(report.recommendations)} adet):")
for rec in report.recommendations:
    print(f"  [{rec.mitigation_id}] {rec.action}")

reporter = JSONReporting()
report_json = reporter.to_json(report)
with open("scripts/lanl_data/lanl_real_report.json", "w") as f:
    f.write(report_json)
print("\nRapor kaydedildi: scripts/lanl_data/lanl_real_report.json")

print("\nDashboard icin kucultulmus event seti hazirlaniyor...")

# Sadece GERCEKTEN kesfedilen (rapor'da yer alan) host'lari ilgilendiren
# event'leri filtrele -- ayni grafi/sonucu uretir ama tarayiciya
# gonderilebilecek kuclukte olur.
relevant_hosts = {report.target_node} | {rs.target_node for rs in report.risk_scores}
print(f"  {len(relevant_hosts)} host ilgili bulundu")

dashboard_events = [
    e for e in all_events
    if e.source_host in relevant_hosts and (e.target_host is None or e.target_host in relevant_hosts)
]
print(f"  {len(dashboard_events)} event kucultulmus sete dahil edildi (orijinal: {len(all_events)})")

# API'nin bekledigi JSON semasina cevir (app.js'teki buildDemoEvents ile ayni format)
events_json = [
    {
        "event_id": e.event_id,
        "timestamp": e.timestamp.isoformat().replace("+00:00", "Z"),
        "source": e.source.value,
        "source_host": e.source_host,
        "target_host": e.target_host,
        "user": e.user,
        "raw_action": e.raw_action,
        "mitre_technique_id": e.mitre_technique_id,
        "metadata": e.metadata,
    }
    for e in dashboard_events
]

dashboard_payload = {
    "events": events_json,
    "known_hosts": sorted(relevant_hosts),
    "start_node": report.target_node,
    "feature_window_start": WINDOW_START.isoformat().replace("+00:00", "Z"),
    "feature_window_end": WINDOW_END.isoformat().replace("+00:00", "Z"),
    "baseline_window_start": WINDOW_START.isoformat().replace("+00:00", "Z"),
    "baseline_window_end": WINDOW_END.isoformat().replace("+00:00", "Z"),
    "asset_criticality_map": {},
}

with open("src/sentinelpath/static/dashboard/lanl_demo_payload.json", "w") as f:
    json.dump(dashboard_payload, f)
print("  Kaydedildi: src/sentinelpath/static/dashboard/lanl_demo_payload.json")