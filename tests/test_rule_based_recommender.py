"""
tests.test_rule_based_recommender
====================================
"""

from __future__ import annotations

from sentinelpath.core.models import RiskScore
from sentinelpath.recommendation.infrastructure.rule_based_recommender import (
    RuleBasedRecommendationEngine,
)


def _risk_score(technique_id: str, score: float, target_node: str = "host-b") -> RiskScore:
    return RiskScore(
        target_node=target_node,
        technique_id=technique_id,
        probability=0.5,
        asset_criticality=0.5,
        technique_severity=0.5,
        score=score,
    )


def test_known_technique_gets_correct_mitigation() -> None:
    engine = RuleBasedRecommendationEngine()
    recs = engine.recommend([_risk_score("T1078", 50.0)])

    assert len(recs) == 1
    assert recs[0].technique_id == "T1078"
    assert recs[0].mitigation_id == "M1032"
    assert "MFA" in recs[0].action


def test_unknown_technique_gets_fallback_recommendation() -> None:
    engine = RuleBasedRecommendationEngine()
    recs = engine.recommend([_risk_score("T9999.999", 50.0)])

    assert len(recs) == 1
    assert recs[0].mitigation_id is None
    assert "manuel inceleme" in recs[0].action


def test_duplicate_technique_across_multiple_targets_yields_single_recommendation() -> None:
    """Ayni teknik farkli hedef node'lar icin birden fazla RiskScore'da
    gorunse bile, TEKIL bir oneri uretilmelidir."""

    engine = RuleBasedRecommendationEngine()
    recs = engine.recommend(
        [
            _risk_score("T1078", 80.0, target_node="host-b"),
            _risk_score("T1078", 40.0, target_node="host-c"),
        ]
    )

    assert len(recs) == 1


def test_recommendations_ordered_by_descending_risk_score() -> None:
    engine = RuleBasedRecommendationEngine()
    recs = engine.recommend(
        [
            _risk_score("T1021.001", 20.0),
            _risk_score("T1078", 90.0),
            _risk_score("T1021.002", 55.0),
        ]
    )

    technique_order = [r.technique_id for r in recs]
    assert technique_order == ["T1078", "T1021.002", "T1021.001"]


def test_empty_risk_scores_yields_empty_recommendations() -> None:
    engine = RuleBasedRecommendationEngine()
    assert engine.recommend([]) == []


def test_all_t1021_subtechniques_have_mappings() -> None:
    """Faz 2'den beri tanidigimiz tum T1021 alt-tekniklerinin bir
    mitigasyon haritalamasi olmali (bilgi kaybi olmasin)."""

    engine = RuleBasedRecommendationEngine()
    subtechniques = [
        "T1021.001",
        "T1021.002",
        "T1021.003",
        "T1021.004",
        "T1021.005",
        "T1021.006",
    ]
    recs = engine.recommend([_risk_score(t, 10.0) for t in subtechniques])

    assert all(r.mitigation_id is not None for r in recs)
