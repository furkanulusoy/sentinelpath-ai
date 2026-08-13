"""benchmark.domain.metrics icin testler."""

from datetime import UTC, datetime

from sentinelpath.benchmark.domain.metrics import (
    evaluate_scenario,
    predicted_host,
    reciprocal_rank,
    top_k_hit,
)
from sentinelpath.core.models import CandidatePath, PredictionResult, TechniquePrediction


def _path(nodes: list[str], technique: str) -> CandidatePath:
    return CandidatePath(
        path_nodes=tuple(nodes),
        plausible_techniques=(technique,),
        structural_reason="test",
        hop_technique_ids=((technique,),),
    )


def _result() -> PredictionResult:
    paths = [
        _path(["A", "B"], "T1021.001"),
        _path(["A", "C"], "T1021.002"),
        _path(["A", "D"], "T1021"),
    ]
    preds = tuple(
        sorted(
            [
                TechniquePrediction("T1021.001", "RDP", 0.5, paths[0]),
                TechniquePrediction("T1021.002", "SMB", 0.3, paths[1]),
                TechniquePrediction("T1021", "Generic", 0.2, paths[2]),
            ],
            key=lambda p: p.probability,
            reverse=True,
        )
    )
    return PredictionResult("A", preds, "test_model", datetime.now(UTC))


def test_predicted_host_returns_last_path_node() -> None:
    result = _result()
    assert predicted_host(result.predictions[0]) == "B"


def test_top_k_hit_true_when_within_k() -> None:
    result = _result()
    assert top_k_hit(result, "C", k=2) is True


def test_top_k_hit_false_when_outside_k() -> None:
    result = _result()
    assert top_k_hit(result, "D", k=1) is False


def test_reciprocal_rank_first_place() -> None:
    result = _result()
    assert reciprocal_rank(result, "B") == 1.0


def test_reciprocal_rank_third_place() -> None:
    result = _result()
    assert abs(reciprocal_rank(result, "D") - (1 / 3)) < 1e-9


def test_reciprocal_rank_not_found_returns_zero() -> None:
    result = _result()
    assert reciprocal_rank(result, "Z") == 0.0


def test_evaluate_scenario_returns_all_metrics() -> None:
    result = _result()
    metrics = evaluate_scenario(result, "C", k_values=(1, 3))
    assert metrics["top_1"] == 0.0
    assert metrics["top_3"] == 1.0
    assert metrics["reciprocal_rank"] == 0.5