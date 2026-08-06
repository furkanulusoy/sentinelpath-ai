"""
scripts/demo_end_to_end.py
=============================

Faz 1-4'un BIRLIKTE calistigi, gercek girdi/ciktilarla uctan uca bir
gosterim. Resmi bir faz degildir -- su ana kadar insa edilenlerin
gercekten birbirine baglanabildigini kanitlamak icin yazilmistir.

Zincir:
    PacketRecord (Scapy'nin uretecegi format, burada elle simule edildi)
        -> packet_translation.translate_packets()      [Faz 2]
    + elle olusturulmus AUTH NormalizedEvent'ler
        -> RuleBasedFeatureExtractor.extract()            [Faz 3]
        -> NetworkXGraphBuilder.build()                    [Faz 4]

NOT 1: Scapy bu gelistirme ortaminda kurulu olmadigi icin PcapFileCollector
degil, onun kullandigi ayni ceviri fonksiyonu (translate_packets)
kullanildi -- ADR 0003'un tam olarak ongordugu senaryo: Scapy I/O
katmani olmadan da domain mantigi calisiyor.

NOT 2: AUTH kaynakli event'ler icin henuz bir Collector adaptoru
yazilmadi (auth log parser, gelecekteki bir genisletme). Bu event'ler
burada elle olusturuldu -- amac, coklu-kaynak (network + auth) event
birlestirmenin pipeline'da nasil calisacagini simdiden gostermek.

Senaryo: Kucuk bir ortamda bir saldirganin (10.0.0.50) once RDP ile
bir veritabani sunucusuna (10.0.0.10), oradan da SMB ile bir dosya
sunucusuna (10.0.0.20) sicradigi klasik T1021-tabanli lateral movement.
Ayni ortamda, alice adli kullanicinin normal/gunduz calismasi (benign
trafik) da var -- boylece "supheli" ve "normal" davranis ayni graf
icinde yan yana gorulebiliyor.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sentinelpath.collector.infrastructure.packet_record import (
    PacketRecord,
    TransportProtocol,
)
from sentinelpath.collector.infrastructure.packet_translation import translate_packets
from sentinelpath.core.models import EventSource, NormalizedEvent, SentinelPathReport
from sentinelpath.feature_extraction.infrastructure.rule_based_extractor import (
    RuleBasedFeatureExtractor,
)
from sentinelpath.graph_builder.infrastructure.networkx_adapter import NetworkXGraphBuilder
from sentinelpath.baseline_behavior.infrastructure.in_memory_baseline import (
    InMemoryBaselineBehavior,
)
from sentinelpath.attack_path_engine.infrastructure.networkx_engine import (
    NetworkXAttackPathEngine,
)
from sentinelpath.prediction.infrastructure.weighted_markov_model import (
    WeightedMarkovPredictionModel,
)
from sentinelpath.risk_scoring.infrastructure.config_based_risk_scoring import (
    ConfigBasedRiskScoring,
)
from sentinelpath.recommendation.infrastructure.rule_based_recommender import (
    RuleBasedRecommendationEngine,
)
from sentinelpath.reporting.infrastructure.json_reporting import JSONReporting

# --- Senaryo sabitleri -------------------------------------------------

ATTACKER = "10.0.0.50"
DB_SERVER = "10.0.0.10"
FILE_SERVER = "10.0.0.20"
WEB_PROXY = "10.0.0.30"
ALICE_WORKSTATION = "10.0.0.40"

ALL_HOSTS = [ATTACKER, DB_SERVER, FILE_SERVER, WEB_PROXY, ALICE_WORKSTATION]

ATTACK_TIME = datetime(2026, 8, 5, 2, 15, tzinfo=timezone.utc)   # gece yarisi -- off-hours
NORMAL_TIME = datetime(2026, 8, 5, 10, 0, tzinfo=timezone.utc)  # is saati

WINDOW_START = datetime(2026, 8, 5, 0, 0, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 8, 6, 0, 0, tzinfo=timezone.utc)

# Baseline icin daha genis bir "gecmis" penceresi (14 gun) taniyoruz --
# ama demo verimiz sadece 1 gunu kapsiyor. Bu KASITLI: dusuk confidence
# degerinin dogru sekilde ortaya cikmasini gostermek icin (bkz. Faz 5,
# "az veriyle yuksek guven iddia etmemek" ilkesi).
BASELINE_WINDOW_START = WINDOW_END - timedelta(days=14)
BASELINE_WINDOW_END = WINDOW_END


def _minutes(base: datetime, delta_minutes: int) -> datetime:
    return base + timedelta(minutes=delta_minutes)


def build_network_events() -> list[NormalizedEvent]:
    """Faz 2: PacketRecord'lari (Scapy'nin uretecegi format) simule edip
    gercek translate_packets() fonksiyonundan gecirir."""

    records = [
        # Saldiri: ATTACKER -> DB_SERVER (RDP -> T1021.001)
        PacketRecord(
            timestamp=ATTACK_TIME, src_ip=ATTACKER, dst_ip=DB_SERVER,
            dst_port=3389, protocol=TransportProtocol.TCP, payload_size=512,
        ),
        # Saldiri devami: DB_SERVER -> FILE_SERVER (SMB -> T1021.002)
        PacketRecord(
            timestamp=_minutes(ATTACK_TIME, 5), src_ip=DB_SERVER, dst_ip=FILE_SERVER,
            dst_port=445, protocol=TransportProtocol.TCP, payload_size=2048,
        ),
        # Benign: alice -> web-proxy (gunduz, bilinmeyen port)
        PacketRecord(
            timestamp=NORMAL_TIME, src_ip=ALICE_WORKSTATION, dst_ip=WEB_PROXY,
            dst_port=8080, protocol=TransportProtocol.TCP, payload_size=256,
        ),
        # Benign: alice -> db-server (gunduz, postgres -- taninmayan port)
        PacketRecord(
            timestamp=NORMAL_TIME, src_ip=ALICE_WORKSTATION, dst_ip=DB_SERVER,
            dst_port=5432, protocol=TransportProtocol.TCP, payload_size=128,
        ),
    ]
    return translate_packets(records)


def build_auth_events() -> list[NormalizedEvent]:
    """Henuz bir Collector adaptoru olmadigi icin elle olusturulmus AUTH
    event'leri -- NormalizedEvent semasinin coklu-kaynak destegini
    gosterir (bkz. core/models.py EventSource.AUTH)."""

    return [
        # Saldirgan, RDP baglantisindan hemen sonra basariyla authenticate oluyor
        NormalizedEvent(
            event_id="auth-1", timestamp=_minutes(ATTACK_TIME, 1),
            source=EventSource.AUTH, source_host=ATTACKER, target_host=DB_SERVER,
            user="svc_admin", raw_action="auth_attempt", mitre_technique_id="T1078",
            metadata={"outcome": "success"},
        ),
        # Saldirgan, file-server'a dogrudan erismeye calisiyor ama basarisiz oluyor
        NormalizedEvent(
            event_id="auth-2", timestamp=_minutes(ATTACK_TIME, 2),
            source=EventSource.AUTH, source_host=ATTACKER, target_host=FILE_SERVER,
            user="svc_admin", raw_action="auth_attempt", mitre_technique_id=None,
            metadata={"outcome": "failure"},
        ),
        # Saldiri zinciri devam ediyor: db-server -> file-server basarili authenticate
        NormalizedEvent(
            event_id="auth-3", timestamp=_minutes(ATTACK_TIME, 6),
            source=EventSource.AUTH, source_host=DB_SERVER, target_host=FILE_SERVER,
            user="svc_admin", raw_action="auth_attempt", mitre_technique_id="T1078",
            metadata={"outcome": "success"},
        ),
        # Benign: alice, is saatinde kendi ise db-server'a normal sekilde giriyor
        NormalizedEvent(
            event_id="auth-4", timestamp=NORMAL_TIME,
            source=EventSource.AUTH, source_host=ALICE_WORKSTATION, target_host=DB_SERVER,
            user="alice", raw_action="auth_attempt", mitre_technique_id="T1078",
            metadata={"outcome": "success"},
        ),
    ]


def main() -> None:
    network_events = build_network_events()
    auth_events = build_auth_events()
    all_events = network_events + auth_events

    print("=" * 70)
    print("FAZ 2 CIKTISI -- NormalizedEvent listesi")
    print("=" * 70)
    for e in all_events:
        print(
            f"  [{e.source.value:8s}] {e.source_host:12s} -> "
            f"{(e.target_host or '-'):12s} {e.raw_action:24s} "
            f"technique={e.mitre_technique_id}"
        )

    print()
    print("=" * 70)
    print("FAZ 3 CIKTISI -- HostFeatureVector (her host icin)")
    print("=" * 70)
    extractor = RuleBasedFeatureExtractor(business_hours_start=8, business_hours_end=18)
    feature_vectors = [
        extractor.extract(host, all_events, WINDOW_START, WINDOW_END) for host in ALL_HOSTS
    ]
    for v in feature_vectors:
        print(
            f"  {v.host_id:12s} users={v.distinct_users_count} "
            f"targets={v.distinct_target_hosts_count} "
            f"failed_auth_ratio={v.failed_auth_ratio:.2f} "
            f"off_hours_ratio={v.off_hours_activity_ratio:.2f} "
            f"techniques={v.observed_techniques}"
        )

    print()
    print("=" * 70)
    print("FAZ 4 CIKTISI -- AttackGraphSnapshot")
    print("=" * 70)
    builder = NetworkXGraphBuilder()
    snapshot = builder.build(events=all_events, feature_vectors=feature_vectors)

    print(f"  Node sayisi: {len(snapshot.nodes)} -> {snapshot.nodes}")
    print(f"  Edge sayisi: {len(snapshot.edges)}")
    for edge in snapshot.edges:
        print(
            f"    {edge.source_node:12s} --[{edge.relation.value}]--> "
            f"{edge.target_node:12s} (weight={edge.weight})"
        )

    print()
    print("=" * 70)
    print("FAZ 5 CIKTISI -- BaselineProfile (14 gunluk pencere istendi)")
    print("=" * 70)
    baseline = InMemoryBaselineBehavior(
        hour_frequency_threshold=0.15, peer_day_fraction_threshold=0.2
    )
    baseline_profiles = baseline.recompute(all_events, BASELINE_WINDOW_START, BASELINE_WINDOW_END)
    for p in baseline_profiles:
        print(
            f"  {p.node_id:12s} confidence={p.confidence:.2f} "
            f"typical_hours={p.typical_active_hours} "
            f"typical_peers={p.typical_peer_nodes}"
        )

    print()
    print("=" * 70)
    print("FAZ 6 CIKTISI -- Attack Path Prediction (ATTACKER'in sonraki adimi)")
    print("=" * 70)
    engine = NetworkXAttackPathEngine()
    candidate_paths = engine.find_candidate_paths(snapshot, start_node=ATTACKER, max_hops=3)
    print(f"  {len(candidate_paths)} aday yol bulundu (start_node={ATTACKER}):")
    for c in candidate_paths:
        print(f"    {' -> '.join(c.path_nodes)}  [{c.structural_reason}]")

    predictor = WeightedMarkovPredictionModel()
    prediction = predictor.predict(candidate_paths)
    print()
    print(f"  Model: {prediction.model_name}")
    print(f"  Tahminler ({ATTACKER} icin, azalan olasilikla):")
    for tp in prediction.predictions:
        path_str = " -> ".join(tp.contributing_path.path_nodes)
        print(
            f"    %{tp.probability*100:5.1f}  {tp.technique_id:12s} {tp.technique_name:45s} "
            f"yol: {path_str}"
        )

    print()
    print("=" * 70)
    print("FAZ 7 CIKTISI -- Risk Scoring")
    print("=" * 70)
    # Ornek kurum varlik envanteri: DB_SERVER ve FILE_SERVER kritik
    # (muhasebe/musteri verisi), WEB_PROXY ve ALICE_WORKSTATION daha
    # dusuk kritiklikte.
    asset_criticality_map = {
        DB_SERVER: 0.9,
        FILE_SERVER: 0.95,
        WEB_PROXY: 0.3,
        ALICE_WORKSTATION: 0.2,
    }
    risk_scorer = ConfigBasedRiskScoring(
        asset_criticality_map=asset_criticality_map,
        default_asset_criticality=0.5,
        default_technique_severity=0.5,
    )
    risk_scores = risk_scorer.score(prediction, baseline_profiles=baseline_profiles)

    for rs in risk_scores:
        confidence_str = f"{rs.baseline_confidence:.2f}" if rs.baseline_confidence is not None else "N/A"
        print(
            f"  skor={rs.score:5.1f}  {rs.target_node:12s} {rs.technique_id:12s} "
            f"(olasilik={rs.probability:.2f} x kritiklik={rs.asset_criticality:.2f} x "
            f"siddet={rs.technique_severity:.2f})  baseline_confidence={confidence_str}"
        )

    print()
    print("=" * 70)
    print("FAZ 8 CIKTISI -- Reporting (Recommendation Engine + JSON/Navigator)")
    print("=" * 70)
    recommender = RuleBasedRecommendationEngine()
    recommendations = recommender.recommend(risk_scores)
    print("  Oneriler:")
    for rec in recommendations:
        print(f"    {rec.technique_id:12s} [{rec.mitigation_id}] {rec.action}")

    report = SentinelPathReport(
        target_node=ATTACKER,
        risk_scores=tuple(risk_scores),
        recommendations=tuple(recommendations),
        generated_at=datetime.now(timezone.utc),
        pipeline_version="0.1.0",
    )

    reporter = JSONReporting()
    json_output = reporter.to_json(report)
    navigator_layer = reporter.to_attack_navigator_layer(report)

    print()
    print(f"  JSON rapor uzunlugu: {len(json_output)} karakter")
    print(f"  ATT&CK Navigator layer'i {len(navigator_layer['techniques'])} teknik iceriyor:")
    for t in navigator_layer["techniques"]:
        print(f"    {t['techniqueID']}  skor={t['score']}  {t['comment']}")

    print()
    print("=" * 70)
    print(
        "OZET: MVP PIPELINE TAMAMLANDI --\n"
        ".pcap -> NormalizedEvent -> HostFeatureVector -> AttackGraphSnapshot\n"
        "-> BaselineProfile -> CandidatePath -> PredictionResult -> RiskScore\n"
        "-> Recommendation -> SentinelPathReport (JSON + ATT&CK Navigator).\n\n"
        "Uretilen Navigator layer'i https://mitre-attack.github.io/attack-navigator/\n"
        "adresine 'Open Existing Layer -> Upload from local' ile yuklenip\n"
        "gorsellestirilebilir.\n\n"
        "Bu, sistem promptunda tanimlanan 10 fazlik yol haritasinin ilk 8\n"
        "fazini tamamliyor (Faz 9-10, Dashboard/Deployment, gelecek plani\n"
        "kapsaminda kaldi -- bkz. README)."
    )


if __name__ == "__main__":
    main()
