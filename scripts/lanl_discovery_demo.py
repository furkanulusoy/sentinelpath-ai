"""
scripts/lanl_discovery_demo.py
================================

Faz B / video demo hazirligi: LANL flows.txt verisinin gun 1-2
penceresinde (saat 24-48), discovery_detection (T1046) modulunu
GERCEKTEN calistirip, en guclu tarama sinyalini ureten host'u bulur.

ONEMLI: Bu secim REDTEAM.TXT'E HIC BAKMADAN yapilir -- sadece
discovery_detection'in kendi istatistiksel esigine gore. redteam.txt
kontrolu, secimden SONRA, ayri ve BILGI AMACLI bir adim olarak yapilir.
"""

import gzip
from collections import defaultdict
from datetime import timedelta

from sentinelpath.baseline_behavior.infrastructure.in_memory_baseline import (
    InMemoryBaselineBehavior,
)
from sentinelpath.collector.infrastructure.lanl_flows_adapter import (
    LANL_VIRTUAL_EPOCH,
    LANLFlowsCollector,
)
from sentinelpath.discovery_detection.infrastructure.scan_detector import (
    detect_scanning,
)

WINDOW_START = LANL_VIRTUAL_EPOCH + timedelta(days=1)
WINDOW_END = LANL_VIRTUAL_EPOCH + timedelta(days=2)

print("flows.txt okunuyor (gun 1-2, saat 24-48)...")
flows_collector = LANLFlowsCollector("scripts/lanl_data/flows.txt.gz")
flow_events = flows_collector.collect(
    since=WINDOW_START, until=WINDOW_END, progress_every_lines=2_000_000
)
print(f"  {len(flow_events)} flow event okundu")

print("\nBaseline hesaplaniyor (Tukey IQR, ayni pencereden -- bkz. ADR 0015)...")
baseline = InMemoryBaselineBehavior()
baseline.recompute(flow_events, window_start=WINDOW_START, window_end=WINDOW_END)

all_hosts = {e.source_host for e in flow_events}
baseline_profiles = {}
for host in all_hosts:
    profile = baseline.get_profile(host)
    if profile is not None and profile.typical_max_targets_per_window is not None:
        baseline_profiles[host] = profile

print(f"  {len(baseline_profiles)} host icin gecerli baseline profili var")

print("\ndiscovery_detection (T1046) calistiriliyor...")
scanning_edges = detect_scanning(flow_events, baseline_profiles, window_minutes=5)
print(f"  {len(scanning_edges)} OBSERVED_SCANNING kenari uretildi")

if not scanning_edges:
    print("\nHic tarama sinyali bulunamadi -- yedek plan: en yuksek fan-out.")
    targets_per_host = defaultdict(set)
    for e in flow_events:
        if e.target_host:
            targets_per_host[e.source_host].add(e.target_host)
    best_host = max(targets_per_host, key=lambda h: len(targets_per_host[h]))
    print(f"  Yedek secim: {best_host} ({len(targets_per_host[best_host])} farkli hedef)")
else:
    best_per_host = {}
    for edge in scanning_edges:
        if edge.source_node not in best_per_host or edge.weight > best_per_host[edge.source_node]:
            best_per_host[edge.source_node] = edge.weight

    ranked = sorted(best_per_host.items(), key=lambda kv: kv[1], reverse=True)
    print("\nEn guclu tarama sinyaline sahip ilk 10 host:")
    for host, ratio in ranked[:10]:
        print(f"  {host}: oran={ratio:.2f}")

    best_host = ranked[0][0]
    print(f"\nSECILEN start_node (redteam.txt'e HIC bakilmadan): {best_host}")

# --- redteam.txt kontrolu -- SECIMDEN SONRA, secimi ETKILEMEDEN ---
print("\n--- redteam.txt kontrolu (SADECE bilgi amacli) ---")
redteam_hits = []
with gzip.open("scripts/lanl_data/redteam.txt.gz", "rt") as f:
    for line in f:
        t, user, src, dst = line.strip().split(",")
        event_time = LANL_VIRTUAL_EPOCH + timedelta(seconds=int(t))
        if WINDOW_START <= event_time <= WINDOW_END and src == best_host:
            redteam_hits.append((event_time, user, src, dst))

if redteam_hits:
    print(f"  ESLESME: {best_host}, bu pencerede {len(redteam_hits)} bilinen saldiri olayinin KAYNAGI.")
    for t, user, src, dst in redteam_hits:
        print(f"    {t.isoformat()}  {user}  {src} -> {dst}")
else:
    print(f"  {best_host}, bu pencerede redteam.txt'te bir saldiri kaynagi olarak gorunmuyor.")

#----------------------------------------------------------------------
# Onceki script'in SONUNA ekleyin (redteam kontrolu blogundan sonra)

print("\n--- GENISLETILMIS KONTROL: tum redteam kaynaklari nasil siralandi? ---")
redteam_sources_in_window = set()
with gzip.open("scripts/lanl_data/redteam.txt.gz", "rt") as f:
    for line in f:
        t, user, src, dst = line.strip().split(",")
        event_time = LANL_VIRTUAL_EPOCH + timedelta(seconds=int(t))
        if WINDOW_START <= event_time <= WINDOW_END:
            redteam_sources_in_window.add(src)

print(f"Bu pencerede {len(redteam_sources_in_window)} farkli redteam kaynak host'u var.")

full_ranking = sorted(best_per_host.items(), key=lambda kv: kv[1], reverse=True)
host_to_rank = {host: i + 1 for i, (host, _) in enumerate(full_ranking)}

matches = [(h, host_to_rank.get(h)) for h in redteam_sources_in_window if h in host_to_rank]
print(f"\nBunlardan {len(matches)} tanesi bizim discovery_detection siralamamizda da cikti:")
for host, rank in sorted(matches, key=lambda x: x[1]):
    print(f"  {host}: siralamada #{rank} (toplam {len(full_ranking)} host arasinda)")

#------------------------------------------------------------------------------------

print("\n--- TESHIS: saldirgan host'un kendi verisi ne durumda? ---")
attacker_host = list(redteam_sources_in_window)[0]
attacker_events = [e for e in flow_events if e.source_host == attacker_host]
print(f"Host: {attacker_host}")
print(f"  Bu pencerede kac flow event'i var: {len(attacker_events)}")

attacker_profile = baseline.get_profile(attacker_host)
if attacker_profile is None:
    print("  Baseline profili: HIC OLUSMADI")
elif attacker_profile.typical_max_targets_per_window is None:
    print("  Baseline profili var ama typical_max_targets_per_window: None (yetersiz varyasyon/veri)")
else:
    print(f"  typical_max_targets_per_window: {attacker_profile.typical_max_targets_per_window:.2f}")
    attacker_targets = {e.target_host for e in attacker_events if e.target_host}
    print(f"  Bu pencerede gozlemlenen FARKLI hedef sayisi: {len(attacker_targets)}")