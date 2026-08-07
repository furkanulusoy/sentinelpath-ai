from pathlib import Path
from datetime import timedelta

from sentinelpath.collector.infrastructure.pcap_adapter import PcapFileCollector
from sentinelpath.orchestration.pipeline_orchestrator import PipelineConfig, PipelineOrchestrator

# --- KENDI IP'LERINIZLE DEGISTIRIN ---
ATTACKER = "192.168.56.1"
WIN10 = "192.168.56.101"
WINSERVER22 = "192.168.56.102"   # gercek IP'yi yazin

project_root = Path(__file__).resolve().parent.parent

collector1 = PcapFileCollector(pcap_path=str(project_root / "scripts" / "hop1_host_to_win10_v2.pcap"))
collector2 = PcapFileCollector(pcap_path=str(project_root / "scripts" / "hop2_win10_to_winserver22.pcap"))

events = collector1.collect() + collector2.collect()

print(f"Toplam {len(events)} event bulundu.\n")
for e in events:
    print(f"  {e.source_host} -> {e.target_host}  {e.raw_action}  teknik={e.mitre_technique_id}")

if not events:
    raise SystemExit("Hic event bulunamadi -- pcap dosya yollarini/IP'leri kontrol edin.")

window_start = min(e.timestamp for e in events) - timedelta(minutes=5)
window_end = max(e.timestamp for e in events) + timedelta(minutes=5)
baseline_start = window_end - timedelta(days=15)

orchestrator = PipelineOrchestrator(
    PipelineConfig(
        asset_criticality_map={WIN10: 0.7, WINSERVER22: 0.95},
        default_asset_criticality=0.5,
        default_technique_severity=0.5,
    )
)

report = orchestrator.run(
    events=events,
    known_hosts=[ATTACKER, WIN10, WINSERVER22],
    start_node=ATTACKER,
    feature_window_start=window_start,
    feature_window_end=window_end,
    baseline_window_start=baseline_start,
    baseline_window_end=window_end,
)

print("\n--- TAHMIN SONUCU (GERCEK VERIYLE) ---")
if not report.risk_scores:
    print("  Hic tahmin uretilmedi -- muhtemelen ATTACKER'dan baslayan bir yol bulunamadi.")
for rs in report.risk_scores:
    print(f"  skor={rs.score:5.1f}  hedef={rs.target_node:15s}  teknik={rs.technique_id:12s}  olasilik={rs.probability:.2f}  baseline_guveni={rs.baseline_confidence}")

print("\n--- ONERILER ---")
for rec in report.recommendations:
    print(f"  [{rec.mitigation_id}] {rec.action}")