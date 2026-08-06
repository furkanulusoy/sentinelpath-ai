"""
tests.test_weighted_markov_model
===================================
"""

from __future__ import annotations

import pytest

from sentinelpath.core.models import CandidatePath, RelationType
from sentinelpath.prediction.infrastructure.weighted_markov_model import (
    WeightedMarkovPredictionModel,
)


def _path(nodes, relations, weights, technique_ids_per_hop) -> CandidatePath:
    all_techniques = sorted({t for hop in technique_ids_per_hop for t in hop})
    return CandidatePath(
        path_nodes=tuple(nodes),
        plausible_techniques=tuple(all_techniques),
        structural_reason=" -> ".join(r.value for r in relations),
        hop_relations=tuple(relations),
        hop_weights=tuple(weights),
        hop_technique_ids=tuple(technique_ids_per_hop),
    )


def test_predict_raises_on_empty_candidate_list() -> None:
    model = WeightedMarkovPredictionModel()
    with pytest.raises(ValueError):
        model.predict([])


def test_predict_raises_when_candidates_have_different_origins() -> None:
    model = WeightedMarkovPredictionModel()
    paths = [
        _path(("a", "b"), [RelationType.NETWORK_REACHABLE], [1.0], [()]),
        _path(("x", "y"), [RelationType.NETWORK_REACHABLE], [1.0], [()]),
    ]
    with pytest.raises(ValueError):
        model.predict(paths)


def test_single_candidate_with_technique_gets_probability_one() -> None:
    model = WeightedMarkovPredictionModel()
    paths = [
        _path(("a", "b"), [RelationType.OBSERVED_LATERAL_MOVEMENT], [1.0], [("T1021.001",)]),
    ]

    result = model.predict(paths)

    assert result.target_node == "a"
    assert len(result.predictions) == 1
    assert result.predictions[0].technique_id == "T1021.001"
    assert abs(result.predictions[0].probability - 1.0) < 1e-9


def test_candidates_without_last_hop_technique_are_excluded() -> None:
    model = WeightedMarkovPredictionModel()
    paths = [
        _path(("a", "b"), [RelationType.OBSERVED_LATERAL_MOVEMENT], [1.0], [("T1021.001",)]),
        _path(("a", "c"), [RelationType.NETWORK_REACHABLE], [5.0], [()]),  # teknik yok -> elenir
    ]

    result = model.predict(paths)

    assert len(result.predictions) == 1
    assert result.predictions[0].technique_id == "T1021.001"


def test_all_candidates_without_technique_yields_empty_predictions() -> None:
    model = WeightedMarkovPredictionModel()
    paths = [_path(("a", "b"), [RelationType.NETWORK_REACHABLE], [1.0], [()])]

    result = model.predict(paths)

    assert result.predictions == ()
    assert result.target_node == "a"  # target_node yine de cikarilabilmeli


def test_higher_weight_path_gets_higher_probability() -> None:
    model = WeightedMarkovPredictionModel()
    paths = [
        _path(("a", "b"), [RelationType.OBSERVED_LATERAL_MOVEMENT], [9.0], [("T1021.001",)]),
        _path(("a", "c"), [RelationType.OBSERVED_LATERAL_MOVEMENT], [1.0], [("T1021.002",)]),
    ]

    result = model.predict(paths)

    prob_by_technique = {p.technique_id: p.probability for p in result.predictions}
    assert prob_by_technique["T1021.001"] > prob_by_technique["T1021.002"]
    assert abs(sum(prob_by_technique.values()) - 1.0) < 1e-9  # normalize edilmis


def test_relation_prior_boosts_lateral_movement_over_equal_weight_reachable() -> None:
    """Ayni agirlikta (1.0) iki yol olsa bile, OBSERVED_LATERAL_MOVEMENT
    iliskisi NETWORK_REACHABLE'dan daha yuksek onceklige (prior) sahip
    olmali (bkz. DEFAULT_RELATION_PRIORS)."""

    model = WeightedMarkovPredictionModel()
    paths = [
        _path(("a", "b"), [RelationType.OBSERVED_LATERAL_MOVEMENT], [1.0], [("T1021.001",)]),
        _path(("a", "c"), [RelationType.NETWORK_REACHABLE], [1.0], [("T1078",)]),
    ]

    result = model.predict(paths)
    prob_by_technique = {p.technique_id: p.probability for p in result.predictions}

    assert prob_by_technique["T1021.001"] > prob_by_technique["T1078"]


def test_weak_additional_hop_reduces_relative_score() -> None:
    """Zayif (dusuk agirlikli) bir ek hop, zinciri gerceten ZAYIFLATIR --
    ama bu 'her uzun zincir dogal olarak dusuk skorludur' anlamina
    GELMEZ (bkz. modul docstring'indeki durustluk notu). Bu test sadece
    ZAYIF bir ek hop eklendiginde skorun dustugunu dogrular."""

    model = WeightedMarkovPredictionModel()
    paths = [
        _path(("a", "b"), [RelationType.OBSERVED_LATERAL_MOVEMENT], [5.0], [("T1021.001",)]),
        _path(
            ("a", "x", "c"),
            [RelationType.OBSERVED_LATERAL_MOVEMENT, RelationType.NETWORK_REACHABLE],
            [5.0, 0.1],  # ikinci hop COK zayif gozlemlenmis
            [(), ("T1078",)],
        ),
    ]

    result = model.predict(paths)
    prob_by_technique = {p.technique_id: p.probability for p in result.predictions}

    assert prob_by_technique["T1021.001"] > prob_by_technique["T1078"]


def test_strong_multi_hop_chain_can_outscore_weak_single_hop() -> None:
    """DURUSTLUK TESTI: iki hop'ta da GUCLU kanit varsa, bu zincir tek
    hop'luk ZAYIF bir alternatiften DAHA YUKSEK skor alabilir. Bu,
    'kisa yol her zaman kazanir' gibi yanlis bir varsayimin koda
    sizmadigini dogrular (bkz. modul docstring'i, 'IKINCI DURUSTLUK
    NOTU')."""

    model = WeightedMarkovPredictionModel()
    paths = [
        _path(("a", "b"), [RelationType.NETWORK_REACHABLE], [1.0], [("T1078",)]),  # zayif, tek hop
        _path(
            ("a", "x", "c"),
            [RelationType.OBSERVED_LATERAL_MOVEMENT, RelationType.OBSERVED_LATERAL_MOVEMENT],
            [10.0, 10.0],  # iki hop'ta da COK guclu kanit
            [(), ("T1021.001",)],
        ),
    ]

    result = model.predict(paths)
    prob_by_technique = {p.technique_id: p.probability for p in result.predictions}

    assert prob_by_technique["T1021.001"] > prob_by_technique["T1078"]


def test_only_last_hop_technique_is_used_not_earlier_hops() -> None:
    """Coklu-hop'lu bir yolda, ILK hop'un teknigi 'sonraki adim' olarak
    ONERILMEMELIDIR -- sadece SON hop'un teknigi kullanilmalidir."""

    model = WeightedMarkovPredictionModel()
    paths = [
        _path(
            ("a", "b", "c"),
            [RelationType.OBSERVED_LATERAL_MOVEMENT, RelationType.AUTHENTICATES_TO],
            [1.0, 1.0],
            [("T1021.001",), ("T1078",)],  # ilk hop: T1021.001, son hop: T1078
        ),
    ]

    result = model.predict(paths)
    technique_ids = {p.technique_id for p in result.predictions}

    assert technique_ids == {"T1078"}  # SADECE son hop'un teknigi
    assert "T1021.001" not in technique_ids


def test_predictions_are_sorted_descending_by_probability() -> None:
    model = WeightedMarkovPredictionModel()
    paths = [
        _path(("a", "b"), [RelationType.NETWORK_REACHABLE], [1.0], [("T1078",)]),
        _path(("a", "c"), [RelationType.OBSERVED_LATERAL_MOVEMENT], [10.0], [("T1021.001",)]),
    ]

    result = model.predict(paths)

    probabilities = [p.probability for p in result.predictions]
    assert probabilities == sorted(probabilities, reverse=True)


def test_model_name_is_stable_identifier() -> None:
    model = WeightedMarkovPredictionModel()
    assert model.model_name() == "weighted_markov_v1"


def test_technique_name_lookup_for_known_technique() -> None:
    model = WeightedMarkovPredictionModel()
    paths = [_path(("a", "b"), [RelationType.OBSERVED_LATERAL_MOVEMENT], [1.0], [("T1021.001",)])]

    result = model.predict(paths)

    assert "Remote Desktop" in result.predictions[0].technique_name


def test_unknown_technique_id_falls_back_to_id_as_name() -> None:
    model = WeightedMarkovPredictionModel()
    paths = [_path(("a", "b"), [RelationType.NETWORK_REACHABLE], [1.0], [("T9999.999",)])]

    result = model.predict(paths)

    assert result.predictions[0].technique_name == "T9999.999"
