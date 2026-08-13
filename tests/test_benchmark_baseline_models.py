"""benchmark.infrastructure.baseline_models icin testler."""

from sentinelpath.benchmark.domain.metrics import predicted_host
from sentinelpath.benchmark.infrastructure.baseline_models import (
    MostConnectedBaselineModel,
    RandomBaselineModel,
)
from sentinelpath.core.models import CandidatePath


def _path(nodes: list[str], technique: str) -> CandidatePath:
    return CandidatePath(
        path_nodes=tuple(nodes),
        plausible_techniques=(technique,),
        structural_reason="test",
        hop_technique_ids=((technique,),),
    )


def test_random_baseline_empty_input() -> None:
    result = RandomBaselineModel(seed=1).predict([])
    assert result.predictions == ()


def test_random_baseline_probabilities_sum_to_one() -> None:
    paths = [_path(["A", "B"], "T1021"), _path(["A", "C"], "T1021.002")]
    result = RandomBaselineModel(seed=42).predict(paths)
    total = sum(p.probability for p in result.predictions)
    assert abs(total - 1.0) < 1e-9


def test_random_baseline_is_reproducible_with_seed() -> None:
    paths = [_path(["A", "B"], "T1021"), _path(["A", "C"], "T1021.002")]
    r1 = RandomBaselineModel(seed=7).predict(paths)
    r2 = RandomBaselineModel(seed=7).predict(paths)
    assert [p.probability for p in r1.predictions] == [p.probability for p in r2.predictions]


def test_random_baseline_model_name() -> None:
    assert RandomBaselineModel().model_name() == "random_baseline_v1"


def test_most_connected_prefers_target_with_more_paths() -> None:
    paths = [
        _path(["A", "B"], "T1021.001"),
        _path(["A", "B"], "T1021.002"),
        _path(["A", "C"], "T1021"),
    ]
    result = MostConnectedBaselineModel().predict(paths)
    assert predicted_host(result.predictions[0]) == "B"
    assert abs(result.predictions[0].probability - (2 / 3)) < 1e-9


def test_most_connected_empty_input() -> None:
    result = MostConnectedBaselineModel().predict([])
    assert result.predictions == ()


def test_most_connected_model_name() -> None:
    assert MostConnectedBaselineModel().model_name() == "most_connected_baseline_v1"


def test_no_leakage_baselines_use_only_candidate_paths_structure() -> None:
    """Sizinti-onleme kontrolu (bkz. LEAKAGE_PREVENTION.md, Kategori 1):
    her iki baseline'in predict() imzasi SADECE candidate_paths alir --
    ground truth/redteam bilgisi icin hicbir parametre YOKTUR."""
    import inspect

    for cls in (RandomBaselineModel, MostConnectedBaselineModel):
        sig = inspect.signature(cls.predict)
        params = list(sig.parameters.keys())
        assert params == ["self", "candidate_paths"]