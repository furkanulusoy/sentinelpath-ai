"""
tests.test_config_based_risk_scoring
=======================================

Tamamen stdlib'e dayanir (acik parametrelerle pydantic-settings
bagimliligindan kacinilir -- bkz. Faz 3/5/7'deki ayni desen).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelpath.core.models import (
    BaselineProfile,
    CandidatePath,
    PredictionResult,
    TechniquePrediction,
)
from sentinelpath.risk_scoring.infrastructure.config_based_risk_scoring import (
    ConfigBasedRiskScoring,
)

NOW = datetime.now(UTC)


def _path(nodes) -> CandidatePath:
    return CandidatePath(path_nodes=tuple(nodes), plausible_techniques=(), structural_reason="x")


def _prediction(
    entries: list[tuple[str, float, list[str]]], target_node: str = "host-a"
) -> PredictionResult:
    """entries: (technique_id, probability, path_nodes) uclulerinden PredictionResult kurar."""

    predictions = tuple(
        TechniquePrediction(
            technique_id=tid,
            technique_name=tid,
            probability=prob,
            contributing_path=_path(nodes),
        )
        for tid, prob, nodes in entries
    )
    return PredictionResult(
        target_node=target_node,
        predictions=predictions,
        model_name="test_model",
        generated_at=NOW,
    )


def _scorer(**overrides) -> ConfigBasedRiskScoring:
    defaults = dict(default_asset_criticality=0.5, default_technique_severity=0.5)
    defaults.update(overrides)
    return ConfigBasedRiskScoring(**defaults)


def test_unknown_host_gets_default_criticality() -> None:
    scorer = _scorer(default_asset_criticality=0.42)
    assert scorer.asset_criticality("unknown-host") == 0.42


def test_known_host_gets_configured_criticality() -> None:
    scorer = _scorer(asset_criticality_map={"db-server": 0.9})
    assert scorer.asset_criticality("db-server") == 0.9
    assert scorer.asset_criticality("other-host") == 0.5  # varsayilan


def test_score_uses_path_destination_not_prediction_target_node() -> None:
    """Risk skoru, YOLUN SON node'unu (hedef asset) kullanmalidir --
    prediction.target_node (zaten ele gecirilmis kaynak) DEGIL."""

    scorer = _scorer(asset_criticality_map={"host-b": 0.9, "host-c": 0.1})
    prediction = _prediction([("T1078", 1.0, ["host-a", "host-b"])], target_node="host-a")

    scores = scorer.score(prediction)

    assert scores[0].target_node == "host-b"  # yolun SON node'u
    assert scores[0].asset_criticality == 0.9


def test_score_formula_is_probability_times_criticality_times_severity() -> None:
    scorer = _scorer(
        asset_criticality_map={"host-b": 0.8},
        technique_severity_map={"T1078": 0.5},
    )
    prediction = _prediction([("T1078", 0.6, ["host-a", "host-b"])])

    scores = scorer.score(prediction)

    expected = 0.6 * 0.8 * 0.5 * 100.0
    assert abs(scores[0].score - expected) < 1e-9


def test_unknown_technique_uses_default_severity() -> None:
    scorer = _scorer(default_technique_severity=0.33)
    prediction = _prediction([("T9999.999", 1.0, ["host-a", "host-b"])])

    scores = scorer.score(prediction)

    assert scores[0].technique_severity == 0.33


def test_scores_sorted_descending() -> None:
    scorer = _scorer(asset_criticality_map={"host-b": 0.9, "host-c": 0.1})
    prediction = _prediction(
        [
            ("T1078", 0.5, ["host-a", "host-c"]),  # dusuk kritiklik
            ("T1078", 0.5, ["host-a", "host-b"]),  # yuksek kritiklik
        ]
    )

    scores = scorer.score(prediction)

    assert scores[0].target_node == "host-b"  # daha yuksek skor once gelmeli
    assert scores[0].score > scores[1].score


def test_baseline_confidence_is_attached_when_profiles_provided() -> None:
    scorer = _scorer()
    prediction = _prediction([("T1078", 1.0, ["host-a", "host-b"])])
    profiles = [
        BaselineProfile(
            node_id="host-b",
            baseline_window_days=14,
            typical_active_hours=(),
            typical_peer_nodes=(),
            confidence=0.85,
        )
    ]

    scores = scorer.score(prediction, baseline_profiles=profiles)

    assert scores[0].baseline_confidence == 0.85


def test_baseline_confidence_is_none_when_profiles_not_provided() -> None:
    scorer = _scorer()
    prediction = _prediction([("T1078", 1.0, ["host-a", "host-b"])])

    scores = scorer.score(prediction)

    assert scores[0].baseline_confidence is None


def test_baseline_confidence_is_none_for_node_without_profile() -> None:
    scorer = _scorer()
    prediction = _prediction([("T1078", 1.0, ["host-a", "host-b"])])
    profiles = [
        BaselineProfile(
            node_id="some-other-host",
            baseline_window_days=14,
            typical_active_hours=(),
            typical_peer_nodes=(),
            confidence=0.9,
        )
    ]

    scores = scorer.score(prediction, baseline_profiles=profiles)

    assert scores[0].baseline_confidence is None


def test_score_does_not_mutate_main_formula_regardless_of_confidence() -> None:
    """ADR 0010: confidence ANA FORMULE DAHIL DEGILDIR. Ayni tahmin,
    farkli confidence degerleriyle bile AYNI score degerini uretmelidir."""

    scorer = _scorer(asset_criticality_map={"host-b": 0.8}, technique_severity_map={"T1078": 0.5})
    prediction = _prediction([("T1078", 0.6, ["host-a", "host-b"])])

    low_confidence_profile = [
        BaselineProfile(
            node_id="host-b",
            baseline_window_days=14,
            typical_active_hours=(),
            typical_peer_nodes=(),
            confidence=0.01,
        )
    ]
    high_confidence_profile = [
        BaselineProfile(
            node_id="host-b",
            baseline_window_days=14,
            typical_active_hours=(),
            typical_peer_nodes=(),
            confidence=0.99,
        )
    ]

    score_low = scorer.score(prediction, baseline_profiles=low_confidence_profile)[0].score
    score_high = scorer.score(prediction, baseline_profiles=high_confidence_profile)[0].score

    assert abs(score_low - score_high) < 1e-9


def test_empty_predictions_yields_empty_risk_scores() -> None:
    scorer = _scorer()
    prediction = _prediction([])

    assert scorer.score(prediction) == []
