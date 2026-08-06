from sentinelpath.collector.infrastructure.pcap_adapter import PcapFileCollector

# Dosya adi Wireshark'ta ne kaydettiyseniz onu yazin
collector = PcapFileCollector(pcap_path="hadi.pcap")
events = collector.collect()

print(f"{len(events)} event bulundu:\n")
for e in events:
    print(f"{e.source_host} -> {e.target_host}  {e.raw_action}  teknik={e.mitre_technique_id}")
    print(f"   metadata: {e.metadata}")


# -----------------------------------------------------------------------------------------------

from sentinelpath.feature_extraction.infrastructure.rule_based_extractor import RuleBasedFeatureExtractor
from sentinelpath.graph_builder.infrastructure.networkx_adapter import NetworkXGraphBuilder
from datetime import datetime, timezone

# --- Faz 4: ham event'leri graf'a indirge (asil "ozet" burasi) ---
known_hosts = sorted({e.source_host for e in events} | {e.target_host for e in events if e.target_host})

extractor = RuleBasedFeatureExtractor(business_hours_start=8, business_hours_end=18)
window_start = min(e.timestamp for e in events)
window_end = max(e.timestamp for e in events) + __import__("datetime").timedelta(seconds=1)
feature_vectors = [extractor.extract(h, events, window_start, window_end) for h in known_hosts]

builder = NetworkXGraphBuilder()
snapshot = builder.build(events=events, feature_vectors=feature_vectors)

print(f"\n--- OZET (Graf) --- {len(snapshot.nodes)} host, {len(snapshot.edges)} iliski\n")
for edge in snapshot.edges:
    print(f"{edge.source_node} -> {edge.target_node}  [{edge.relation.value}]  "
          f"gozlem={edge.weight:.0f}  teknik={edge.mitre_technique_ids or '-'}")