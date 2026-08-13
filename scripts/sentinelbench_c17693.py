"""
scripts/sentinelbench_c17693.py
==================================

SentinelBench'in ilk gercek "leaderboard" calistirmasi: gercek C17693
senaryosunda, 3 modeli (WeightedMarkovPredictionModel + 2 baseline)
AYNI aday yollara karsi calistirip, redteam.txt'teki GERCEK sonraki
hedef(ler)e karsi karsilastirir.

Sizinti-onleme (bkz. LEAKAGE_PREVENTION.md): redteam.txt SADECE en
sonda, DEGERLENDIRME icin okunur -- hicbir modelin/candidate_paths
uretiminin hicbir asamasinda kullanilmaz.
"""

from datetime import timedelta

from sentinelpath.attack_path_engine.infrastructure.networkx_engine import (
    NetworkXAttackPathEngine,
)
from sentinelpath.benchmark.domain.metrics import evaluate_scenario, predicted_host
from sentinelpath.benchmark.infrastructure.baseline_models import (
    MostConnectedBaselineModel,
    RandomBaselineModel,
)
from sentinelpath.collector.infrastructure.lanl_auth_adapter import LANLAuthCollector
from sentinelpath.collector.infrastructure.lanl_flows_adapter import (
    LANL_VIRTUAL_EPOCH,
    LANLFlowsCollector,
    build_flow_technique_index,
)
from sentinelpath.graph_builder.infrastructure.networkx_adapter import NetworkXGraphBuilder
from sentinelpath.prediction.infrastructure.weighted_markov_model import (
    WeightedMarkovPredictionModel,
)

WINDOW_START = LANL_VIRTUAL_EPOCH + timedelta(days=1)
WINDOW_END = LANL_VIRTUAL_EPOCH + timedelta(days=2)
START_NODE = "C17693"

# --- 1. Veri toplama (ADR 0014'teki AYNI yontem) ---
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

# --- 2. Graf kurulumu + aday yollar (Prediction Model'den ONCE) ---
print("\nGraf kuruluyor...")
graph_builder = NetworkXGraphBuilder()
snapshot = graph_builder.build(events=all_events, feature_vectors=[])

print("Aday yollar bulunuyor (max_hops=2)...")
engine = NetworkXAttackPathEngine()
candidate_paths = engine.find_candidate_paths(snapshot, start_node=START_NODE, max_hops=2)
print(f"  {len(candidate_paths)} aday yol bulundu")

if not candidate_paths:
    raise SystemExit(f"HATA: {START_NODE} icin hic aday yol bulunamadi.")

# --- 3. Uc modeli AYNI aday yollara karsi calistir ---
models = [
    WeightedMarkovPredictionModel(),
    RandomBaselineModel(seed=42),
    MostConnectedBaselineModel(),
]
results = {model.model_name(): model.predict(candidate_paths) for model in models}

# --- 4. Ground truth -- SADECE SIMDI, degerlendirme icin okunuyor ---
print("\nredteam.txt'ten gercek sonraki hedef(ler) okunuyor (degerlendirme icin)...")
import gzip

ground_truth_hosts = []
with gzip.open("scripts/lanl_data/redteam.txt.gz", "rt") as f:
    for line in f:
        t, user, src, dst = line.strip().split(",")
        event_time = LANL_VIRTUAL_EPOCH + timedelta(seconds=int(t))
        if src == START_NODE and WINDOW_START <= event_time <= WINDOW_END:
            ground_truth_hosts.append(dst)

print(f"  {len(ground_truth_hosts)} gercek sonraki hedef bulundu: {ground_truth_hosts}")

if not ground_truth_hosts:
    raise SystemExit("HATA: bu pencerede hic ground truth olayi yok, karsilastirma yapilamaz.")

# --- 5. Her model icin, TUM ground truth hedeflere karsi ortalama metrik ---
print("\n" + "=" * 70)
print("SENTINELBENCH LEADERBOARD -- C17693, gun 1-2 penceresi")
print("=" * 70)

leaderboard = []
for model_name, result in results.items():
    per_scenario = [evaluate_scenario(result, gt, k_values=(1, 3, 5)) for gt in ground_truth_hosts]
    avg = {
        key: sum(s[key] for s in per_scenario) / len(per_scenario)
        for key in per_scenario[0]
    }
    leaderboard.append((model_name, avg))

leaderboard.sort(key=lambda x: x[1]["reciprocal_rank"], reverse=True)

print(f"\n{'Model':<28} {'Top-1':>8} {'Top-3':>8} {'Top-5':>8} {'MRR':>8}")
print("-" * 70)
for model_name, avg in leaderboard:
    print(
        f"{model_name:<28} {avg['top_1']:>8.2f} {avg['top_3']:>8.2f} "
        f"{avg['top_5']:>8.2f} {avg['reciprocal_rank']:>8.3f}"
    )

print(f"\n(N={len(ground_truth_hosts)} gercek ground-truth olayi uzerinden ortalama)")

# --- TESHIS: gercek hedefler, aday listesinde HIC var mi? ---
print("\n--- TESHIS: kapsama kontrolu ---")
candidate_targets = {p.path_nodes[-1] for p in candidate_paths}
print(f"Aday yollardaki FARKLI hedef sayisi: {len(candidate_targets)}")

covered = [gt for gt in ground_truth_hosts if gt in candidate_targets]
not_covered = [gt for gt in ground_truth_hosts if gt not in candidate_targets]

print(f"\nGercek hedeflerden ADAY LISTESINDE OLANLAR ({len(covered)}/{len(ground_truth_hosts)}): {covered}")
print(f"Gercek hedeflerden HIC ADAY OLMAYANLAR ({len(not_covered)}/{len(ground_truth_hosts)}): {not_covered}")

# --- DERINLEMESINE TESHIS: gercek hedefler NEREDE sıralandı, HANGI kanıtla? ---
print("\n--- DERINLEMESINE TESHIS: siralama + kanit ---")

markov_result = results["weighted_markov_v1"]
rank_by_host = {predicted_host(p): i for i, p in enumerate(markov_result.predictions, start=1)}

print(f"\n{'Gercek Hedef':<14} {'Markov Sirasi':<16} {'/113':<6} {'Iliski Tipi':<26} {'Agirlik':<10}")
print("-" * 80)
for gt in ground_truth_hosts:
    rank = rank_by_host.get(gt, "YOK")
    matching_paths = [p for p in candidate_paths if p.path_nodes[-1] == gt]
    if matching_paths:
        p = matching_paths[0]
        relation = p.hop_relations[-1].value if p.hop_relations else "?"
        weight = p.hop_weights[-1] if p.hop_weights else "?"
    else:
        relation, weight = "?", "?"
    print(f"{gt:<14} {rank!s:<16} {'/113':<6} {relation:<26} {weight!s:<10}")

# Karsilastirma icin: en YUKSEK siralanan 5 aday neye dayaniyor?
print("\nEn yuksek siralanan 5 aday (karsilastirma icin):")
for p in markov_result.predictions[:5]:
    host = predicted_host(p)
    matching = [c for c in candidate_paths if c.path_nodes[-1] == host]
    relation = matching[0].hop_relations[-1].value if matching and matching[0].hop_relations else "?"
    weight = matching[0].hop_weights[-1] if matching and matching[0].hop_weights else "?"
    print(f"  {host:<14} olasilik={p.probability:.4f}  iliski={relation}  agirlik={weight}")

    # --- TESHIS 3: gercek hedeflerin USTUNDEKI 246 adayin iliski dagilimi ---
    print("\n--- TESHIS 3: ust siralardaki adaylarin iliski tipi dagilimi ---")
    from collections import Counter

    top_predictions = markov_result.predictions[:246]  # gercek hedeflerin USTUNDE kalan tum adaylar
    relation_dist = Counter()
    for p in top_predictions:
        matching = [c for c in candidate_paths if c.path_nodes[-1] == predicted_host(p)]
        if matching and matching[0].hop_relations:
            relation_dist[matching[0].hop_relations[-1].value] += 1

    for relation, count in relation_dist.most_common():
        print(f"  {relation}: {count} aday ({count / len(top_predictions) * 100:.1f}%)")