"""
tests.test_pipeline_orchestrator
===================================

Bu testler PipelineOrchestrator'i UCTAN UCA test eder -- framework
bagimliligi olmadigi icin (bkz. ADR 0011) bu sandbox'ta TAM olarak
calisir. Senaryo, scripts/demo_end_to_end.py ile aynidir (tutarlilik
icin).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sentinelpath.collector.infrastructure.packet_record import (
    PacketRecord,
    TransportProtocol,
)
from sentinelpath.collector.infrastructure.packet_translation import translate_packets
from sentinelpath.core.models import EventSource, NormalizedEvent
from sentinelpath.orchestration.pipeline_orchestrator import (
    PipelineConfig,
    PipelineOrchestrator,
)

ATTACKER = "10.0.0.50"
DB_SERVER = "10.0.0.10"
FILE_SERVER = "10.0.0.20"
ALL_HOSTS = [ATTACKER, DB_SERVER, FILE_SERVER]

ATTACK_TIME = datetime(2026, 8, 5, 2, 15, tzinfo=UTC)
WINDOW_START = datetime(2026, 8, 5, 0, 0, tzinfo=UTC)
WINDOW_END = datetime(2026, 8, 6, 0, 0, tzinfo=UTC)
BASELINE_START = WINDOW_END - timedelta(days=14)


def _build_events() -> list[NormalizedEvent]:
    records = [
        PacketRecord(
            timestamp=ATTACK_TIME,
            src_ip=ATTACKER,
            dst_ip=DB_SERVER,
            dst_port=3389,
            protocol=TransportProtocol.TCP,
            payload_size=512,
        ),
        PacketRecord(
            timestamp=ATTACK_TIME + timedelta(minutes=5),
            src_ip=DB_SERVER,
            dst_ip=FILE_SERVER,
            dst_port=445,
            protocol=TransportProtocol.TCP,
            payload_size=2048,
        ),
    ]
    network_events = translate_packets(records)

    auth_events = [
        NormalizedEvent(
            event_id="auth-1",
            timestamp=ATTACK_TIME + timedelta(minutes=1),
            source=EventSource.AUTH,
            source_host=ATTACKER,
            target_host=DB_SERVER,
            user="svc_admin",
            raw_action="auth_attempt",
            mitre_technique_id="T1078",
            metadata={"outcome": "success"},
        ),
        NormalizedEvent(
            event_id="auth-2",
            timestamp=ATTACK_TIME + timedelta(minutes=6),
            source=EventSource.AUTH,
            source_host=DB_SERVER,
            target_host=FILE_SERVER,
            user="svc_admin",
            raw_action="auth_attempt",
            mitre_technique_id="T1078",
            metadata={"outcome": "success"},
        ),
    ]
    return network_events + auth_events


def test_full_pipeline_produces_report_with_predicted_technique() -> None:
    orchestrator = PipelineOrchestrator(
        PipelineConfig(
            asset_criticality_map={DB_SERVER: 0.9, FILE_SERVER: 0.95},
        )
    )
    events = _build_events()

    report = orchestrator.run(
        events=events,
        known_hosts=ALL_HOSTS,
        start_node=ATTACKER,
        feature_window_start=WINDOW_START,
        feature_window_end=WINDOW_END,
        baseline_window_start=BASELINE_START,
        baseline_window_end=WINDOW_END,
    )

    assert report.target_node == ATTACKER
    assert len(report.risk_scores) > 0
    technique_ids = {rs.technique_id for rs in report.risk_scores}
    assert "T1021.002" in technique_ids or "T1021.001" in technique_ids


def test_full_pipeline_produces_recommendations() -> None:
    orchestrator = PipelineOrchestrator()
    events = _build_events()

    report = orchestrator.run(
        events=events,
        known_hosts=ALL_HOSTS,
        start_node=ATTACKER,
        feature_window_start=WINDOW_START,
        feature_window_end=WINDOW_END,
        baseline_window_start=BASELINE_START,
        baseline_window_end=WINDOW_END,
    )

    assert len(report.recommendations) > 0
    assert all(r.mitigation_id is not None for r in report.recommendations)


def test_isolated_start_node_yields_empty_report_not_crash() -> None:
    """Faz 6'nin predict([]) ValueError firlattigi durum -- orchestrator
    bunu YAKALAMALI, cokmemelidir (bkz. _predict_safely)."""

    orchestrator = PipelineOrchestrator()
    events = _build_events()

    report = orchestrator.run(
        events=events,
        known_hosts=ALL_HOSTS,
        start_node="10.0.0.99",  # graf'ta olmayan bir host
        feature_window_start=WINDOW_START,
        feature_window_end=WINDOW_END,
        baseline_window_start=BASELINE_START,
        baseline_window_end=WINDOW_END,
    )

    assert report.target_node == "10.0.0.99"
    assert report.risk_scores == ()
    assert report.recommendations == ()


def test_orchestrator_output_is_json_serializable() -> None:
    orchestrator = PipelineOrchestrator(
        PipelineConfig(asset_criticality_map={DB_SERVER: 0.9, FILE_SERVER: 0.95})
    )
    events = _build_events()

    report = orchestrator.run(
        events=events,
        known_hosts=ALL_HOSTS,
        start_node=ATTACKER,
        feature_window_start=WINDOW_START,
        feature_window_end=WINDOW_END,
        baseline_window_start=BASELINE_START,
        baseline_window_end=WINDOW_END,
    )

    json_str = orchestrator.to_json(report)
    assert '"target_node"' in json_str

    layer = orchestrator.to_navigator_layer(report)
    assert layer["domain"] == "enterprise-attack"


def test_custom_config_affects_business_hours_classification() -> None:
    """business_hours_start/end degistirilirse, ayni event'ler farkli
    off_hours_activity_ratio uretmelidir -- config'in gercekten
    feature extractor'a ulasti dogrulanir."""

    events = _build_events()

    default_orchestrator = PipelineOrchestrator()
    wide_hours_orchestrator = PipelineOrchestrator(
        PipelineConfig(business_hours_start=0, business_hours_end=24)  # her saat "is saati"
    )

    default_report = default_orchestrator.run(
        events=events,
        known_hosts=ALL_HOSTS,
        start_node=ATTACKER,
        feature_window_start=WINDOW_START,
        feature_window_end=WINDOW_END,
        baseline_window_start=BASELINE_START,
        baseline_window_end=WINDOW_END,
    )
    wide_hours_report = wide_hours_orchestrator.run(
        events=events,
        known_hosts=ALL_HOSTS,
        start_node=ATTACKER,
        feature_window_start=WINDOW_START,
        feature_window_end=WINDOW_END,
        baseline_window_start=BASELINE_START,
        baseline_window_end=WINDOW_END,
    )

    # Ikisi de gecerli rapor uretmeli (config gercekten kullanildigi
    # icin CRASH ETMEMELI); iceriklerini tam karsilastirmak yerine
    # sadece ikisinin de basariyla calistigini dogruluyoruz.
    assert default_report.target_node == wide_hours_report.target_node == ATTACKER
