import os
import pickle
from collections import Counter
from datetime import timedelta

from sentinelpath.collector.infrastructure.lanl_auth_adapter import LANLAuthCollector
from sentinelpath.collector.infrastructure.lanl_flows_adapter import (
    LANL_VIRTUAL_EPOCH,
    LANLFlowsCollector,
    build_flow_technique_index,
)

# --- Kucuk olcekte once dogrulama -- bkz. ADR 0015, "olcek sinirlamasi" notu ---
CUTOFF = LANL_VIRTUAL_EPOCH + timedelta(hours=6)

# Cache dosyasi adina CUTOFF'u dahil ediyoruz -- boylece ileride CUTOFF'u
# degistirdiginizde (orn. 1 gune cikardiginizda), eski/kucuk bir pencereden
# kalma index YANLISLIKLA kullanilmaz.
CACHE_PATH = f"scripts/lanl_data/flow_index_{CUTOFF.isoformat().replace(':', '-')}.pkl"

if os.path.exists(CACHE_PATH):
    print(f"Onceden hesaplanmis flow_index diskten yukleniyor ({CACHE_PATH})...")
    with open(CACHE_PATH, "rb") as f:
        flow_index = pickle.load(f)
    print(f"  {len(flow_index)} farkli (kaynak,hedef) cifti yuklendi")
else:
    print("flows.txt okunuyor (ilk kez, biraz surecek)...")
    flows_collector = LANLFlowsCollector("scripts/lanl_data/flows.txt.gz")
    flow_events = flows_collector.collect(until=CUTOFF, progress_every_lines=2_000_000)
    print(f"  {len(flow_events)} flow event okundu")

    flow_index = build_flow_technique_index(flow_events)
    print(f"  {len(flow_index)} farkli (kaynak,hedef) cifti icin teknik indexlendi")

    print(f"  Sonuc diske kaydediliyor ({CACHE_PATH}) -- bir sonraki calistirmada tekrar okunmayacak...")
    with open(CACHE_PATH, "wb") as f:
        pickle.dump(flow_index, f)

print("\nauth.txt okunuyor...")
auth_collector = LANLAuthCollector("scripts/lanl_data/auth.txt.gz", flow_index=flow_index)
auth_events = auth_collector.collect(until=CUTOFF, progress_every_lines=2_000_000)
print(f"  {len(auth_events)} auth event okundu")

action_counts = Counter(
    e.raw_action.split(":")[0] + ":" + e.raw_action.split(":")[1]
    if ":" in e.raw_action
    else e.raw_action
    for e in auth_events
)
print("\nAuth event turlerine gore dagilim:")
for action, count in action_counts.most_common(10):
    print(f"  {action}: {count}")

technique_counts = Counter(e.mitre_technique_id for e in auth_events if e.mitre_technique_id)
print("\nTeknik dagilimi:")
for tech, count in technique_counts.most_common():
    print(f"  {tech}: {count}")