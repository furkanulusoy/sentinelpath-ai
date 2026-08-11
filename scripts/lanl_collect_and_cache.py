import pickle
from datetime import timedelta

from sentinelpath.collector.infrastructure.lanl_auth_adapter import LANLAuthCollector
from sentinelpath.collector.infrastructure.lanl_flows_adapter import (
    LANL_VIRTUAL_EPOCH,
    LANLFlowsCollector,
    build_flow_technique_index,
)

WINDOW_START = LANL_VIRTUAL_EPOCH + timedelta(days=1)
WINDOW_END = LANL_VIRTUAL_EPOCH + timedelta(days=2)
CACHE_PATH = "scripts/lanl_data/lanl_events_cache.pkl"

print("flows.txt okunuyor...")
flows_collector = LANLFlowsCollector("scripts/lanl_data/flows.txt.gz")
flow_events = flows_collector.collect(
    since=WINDOW_START, until=WINDOW_END, progress_every_lines=2_000_000
)
print(f"  {len(flow_events)} flow event")

flow_index = build_flow_technique_index(flow_events)

print("\nauth.txt okunuyor...")
auth_collector = LANLAuthCollector("scripts/lanl_data/auth.txt.gz", flow_index=flow_index)
auth_events = auth_collector.collect(
    since=WINDOW_START, until=WINDOW_END, progress_every_lines=2_000_000
)
print(f"  {len(auth_events)} auth event")

all_events = flow_events + auth_events
print(f"\n{len(all_events)} event onbelleklendi -> {CACHE_PATH}")
with open(CACHE_PATH, "wb") as f:
    pickle.dump(all_events, f)

print("BITTI -- bundan sonra HICBIR script flows.txt/auth.txt'i tekrar okumayacak.")