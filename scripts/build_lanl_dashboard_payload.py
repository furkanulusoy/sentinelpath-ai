import json
import pickle

print("Onbellekten event'ler yukleniyor...")
with open("scripts/lanl_data/lanl_events_cache.pkl", "rb") as f:
    all_events = pickle.load(f)
print(f"  {len(all_events)} event yuklendi")

print("\nMevcut rapordan (lanl_real_report.json) ilgili host'lar okunuyor...")
with open("scripts/lanl_data/lanl_real_report.json") as f:
    report_data = json.load(f)

start_node = report_data["target_node"]
relevant_hosts = {start_node} | {rs["target_node"] for rs in report_data["risk_scores"]}
print(f"  start_node={start_node}, {len(relevant_hosts)} ilgili host")

dashboard_events = [
    e for e in all_events
    if e.source_host in relevant_hosts and (e.target_host is None or e.target_host in relevant_hosts)
]
print(f"  {len(dashboard_events)} event kucultulmus sete dahil edildi")

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

W_START, W_END = "2024-01-02T00:00:00Z", "2024-01-03T00:00:00Z"
dashboard_payload = {
    "events": events_json,
    "known_hosts": sorted(relevant_hosts),
    "start_node": start_node,
    "feature_window_start": W_START,
    "feature_window_end": W_END,
    "baseline_window_start": W_START,
    "baseline_window_end": W_END,
    "asset_criticality_map": {},
}

with open("src/sentinelpath/static/dashboard/lanl_demo_payload.json", "w") as f:
    json.dump(dashboard_payload, f)
print("Kaydedildi: src/sentinelpath/static/dashboard/lanl_demo_payload.json")