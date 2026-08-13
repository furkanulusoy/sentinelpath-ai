"""
benchmark.infrastructure.baseline_models
============================================

SentinelBench icin, PredictionModelPort'a uyan, KASITLI OLARAK basit
kiyaslama modelleri. Bunlarin amaci "iyi" olmak degil -- ana modelimizin
(WeightedMarkovModel, ADR 0009) bu basit alternatiflerden GERCEKTEN daha
iyi performans gosterip gostermedigini olcmek. Bir model, rastgele
tahminden daha iyi degilse, o modelin degeri supheli demektir.

Ikisi de ground truth'a (redteam.txt) HICBIR SEKILDE bakmaz -- sadece
kendilerine verilen candidate_paths listesinin YAPISINA bakarlar (bkz.
LEAKAGE_PREVENTION.md, Kategori 1).
"""

from __future__ import annotations

import random
from collections import Counter
from datetime import UTC, datetime

from sentinelpath.core.models import CandidatePath, PredictionResult, TechniquePrediction


def _technique_for(path: CandidatePath) -> str:
    if path.hop_technique_ids and path.hop_technique_ids[-1]:
        return path.hop_technique_ids[-1][0]
    return "UNKNOWN"


class RandomBaselineModel:
    """Her aday yola RASTGELE (ama normalize edilmis) bir olasilik
    atar. Herhangi bir gercek modelin GECMESI gereken en dusuk cita --
    bunu gecemeyen bir model, hicbir gercek sinyal yakalamiyor demektir.
    """

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)

    def predict(self, candidate_paths: list[CandidatePath]) -> PredictionResult:
        if not candidate_paths:
            return PredictionResult("", (), self.model_name(), datetime.now(UTC))

        raw_weights = [self._rng.random() for _ in candidate_paths]
        total = sum(raw_weights)
        predictions = tuple(
            TechniquePrediction(
                technique_id=_technique_for(path),
                technique_name=_technique_for(path),
                probability=w / total,
                contributing_path=path,
            )
            for path, w in zip(candidate_paths, raw_weights, strict=True)
        )
        predictions = tuple(sorted(predictions, key=lambda p: p.probability, reverse=True))
        return PredictionResult(
            target_node=candidate_paths[0].path_nodes[0],
            predictions=predictions,
            model_name=self.model_name(),
            generated_at=datetime.now(UTC),
        )

    def model_name(self) -> str:
        return "random_baseline_v1"


class MostConnectedBaselineModel:
    """Bir hedefe ULASAN aday yol SAYISINA gore siralar (agirliklara
    DEGIL, sadece cok-yollu-baglanabilirlige bakar). Ana Weighted Markov
    modelinden (ADR 0009) kasitli olarak daha basit -- gercek kenar
    agirliklarini (gozlemlenen davranis siklig/turu) hic kullanmaz,
    sadece graf TOPOLOJISININ kendisine bakar.
    """

    def predict(self, candidate_paths: list[CandidatePath]) -> PredictionResult:
        if not candidate_paths:
            return PredictionResult("", (), self.model_name(), datetime.now(UTC))

        target_counts = Counter(p.path_nodes[-1] for p in candidate_paths)
        total = sum(target_counts.values())

        predictions = tuple(
            TechniquePrediction(
                technique_id=_technique_for(path),
                technique_name=_technique_for(path),
                probability=target_counts[path.path_nodes[-1]] / total,
                contributing_path=path,
            )
            for path in candidate_paths
        )
        predictions = tuple(sorted(predictions, key=lambda p: p.probability, reverse=True))
        return PredictionResult(
            target_node=candidate_paths[0].path_nodes[0],
            predictions=predictions,
            model_name=self.model_name(),
            generated_at=datetime.now(UTC),
        )

    def model_name(self) -> str:
        return "most_connected_baseline_v1"