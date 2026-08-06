"""
tests.test_core_models
=======================

FAZ 1 KAPSAMI ICIN TEST FELSEFESI
-----------------------------------
Bu fazda henuz is mantigi (business logic) yok -- sadece mimari iskelet.
Bu yuzden bu testler "bir algoritma dogru mu calisiyor" sorusunu degil,
"mimarinin temel sozlesmesi (core.models) gecerli ve tutarli mi" sorusunu
sinar. Bu, sonraki her fazin uzerine insa edecegi zemini dogrular.

Ozellikle iki seyi dogrulanir:
  1. Her domain tipi, tanimlandigi haliyle gercekten ornoklenebilir mi
     (import hatalari, tip hatalari yok mu)?
  2. Immutability (frozen=True) gercekten zorlaniyor mu? Bu, "core/models.py"
     dosyasinin ust kisminda anlatilan mimari garantinin (bir nesnenin
     pipeline asamalari arasinda yanlislikla degistirilememesi) kod
     seviyesinde dogru calistigini kanitlar.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from sentinelpath.core.models import (
    AttackGraphSnapshot,
    BaselineProfile,
    CandidatePath,
    EventSource,
    GraphEdge,
    HostFeatureVector,
    NormalizedEvent,
    PredictionResult,
    Recommendation,
    RelationType,
    RiskScore,
    SentinelPathReport,
    TechniquePrediction,
)

NOW = datetime.now(UTC)


def test_normalized_event_can_be_constructed() -> None:
    event = NormalizedEvent(
        event_id="e1",
        timestamp=NOW,
        source=EventSource.ENDPOINT,
        source_host="host-a",
        target_host="host-b",
        user="alice",
        raw_action="rdp_login",
        mitre_technique_id="T1021.001",
    )
    assert event.source is EventSource.ENDPOINT
    assert event.metadata == {}  # default_factory dogru calisiyor mu


def test_normalized_event_is_immutable() -> None:
    event = NormalizedEvent(
        event_id="e1",
        timestamp=NOW,
        source=EventSource.NETWORK,
        source_host="host-a",
        target_host=None,
        user=None,
        raw_action="port_scan",
    )
    with pytest.raises(FrozenInstanceError):
        event.user = "someone-else"  # type: ignore[misc]


def test_attack_graph_snapshot_holds_typed_edges() -> None:
    edge = GraphEdge(
        source_node="host-a",
        target_node="host-b",
        relation=RelationType.NETWORK_REACHABLE,
    )
    snapshot = AttackGraphSnapshot(nodes=("host-a", "host-b"), edges=(edge,), generated_at=NOW)

    assert len(snapshot.edges) == 1
    assert snapshot.edges[0].relation is RelationType.NETWORK_REACHABLE


def test_candidate_path_has_no_probability_field() -> None:
    """Mimari garanti testi: CandidatePath'in olasilik alani OLMAMALIDIR
    (bkz. docs/adr/0002). Bu test, ileride birisi yanlislikla bu alani
    eklerse kirilarak mimari sinirin ihlal edildigini erken haber verir.
    """

    path = CandidatePath(
        path_nodes=("host-a", "host-b"),
        plausible_techniques=("T1021.001",),
        structural_reason="network_reachable",
    )
    assert not hasattr(path, "probability")


def test_prediction_result_wraps_technique_predictions() -> None:
    path = CandidatePath(
        path_nodes=("host-a", "host-b"),
        plausible_techniques=("T1078",),
        structural_reason="valid_credentials_observed",
    )
    prediction = TechniquePrediction(
        technique_id="T1078",
        technique_name="Valid Accounts",
        probability=0.62,
        contributing_path=path,
    )
    result = PredictionResult(
        target_node="host-b",
        predictions=(prediction,),
        model_name="stub_model_v0",
        generated_at=NOW,
    )
    assert result.predictions[0].probability == pytest.approx(0.62)


def test_risk_score_and_recommendation_and_report_are_constructible() -> None:
    risk = RiskScore(
        target_node="host-b",
        technique_id="T1078",
        probability=0.62,
        asset_criticality=0.9,
        technique_severity=0.7,
        score=39.06,
    )
    rec = Recommendation(
        technique_id="T1078",
        mitigation_id="M1032",
        action="Enforce MFA on privileged accounts",
        rationale="T1078 (Valid Accounts) mitigated by multi-factor authentication",
    )
    report = SentinelPathReport(
        target_node="host-b",
        risk_scores=(risk,),
        recommendations=(rec,),
        generated_at=NOW,
        pipeline_version="0.1.0",
    )
    assert report.risk_scores[0].score == pytest.approx(39.06)
    assert report.recommendations[0].mitigation_id == "M1032"


def test_host_feature_vector_and_baseline_profile_defaults() -> None:
    vector = HostFeatureVector(
        host_id="host-a",
        window_start=NOW,
        window_end=NOW,
        distinct_users_count=3,
        distinct_target_hosts_count=5,
        failed_auth_ratio=0.1,
        off_hours_activity_ratio=0.05,
    )
    assert vector.observed_techniques == ()  # default_factory=tuple dogru mu

    profile = BaselineProfile(
        node_id="host-a",
        baseline_window_days=14,
        typical_active_hours=tuple(range(8, 19)),
        typical_peer_nodes=("host-b", "host-c"),
        confidence=0.8,
    )
    assert profile.baseline_window_days == 14
