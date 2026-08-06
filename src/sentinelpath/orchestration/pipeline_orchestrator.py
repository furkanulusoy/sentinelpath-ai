"""
orchestration.pipeline_orchestrator
======================================

Faz 2-8'de yazilan TUM pipeline asamalarini zincirleyen tek bir
kullanim-durumu (use-case) sinifi. Bu, `scripts/demo_end_to_end.py`'de
prosedurel olarak yapilan isin, gercek bir uygulamadan (Faz 9'daki
FastAPI katmani) cagrilabilecek, resmi bir siniftir.

BILEREK HICBIR WEB FRAMEWORK'UNE (FastAPI, Flask, vb.) BAGIMLI DEGILDIR
-- bkz. ADR 0011. Bu, bu sinifin:
  1. Bu sandbox'ta (fastapi/pydantic kurulu olmadan) TAM olarak test
     edilebilmesini,
  2. Ileride FastAPI disinda baska bir arayuzden (CLI, Slack bot, baska
     bir web framework) de kullanilabilmesini saglar.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from sentinelpath.attack_path_engine.infrastructure.networkx_engine import (
    NetworkXAttackPathEngine,
)
from sentinelpath.baseline_behavior.infrastructure.in_memory_baseline import (
    InMemoryBaselineBehavior,
)
from sentinelpath.core.models import NormalizedEvent, PredictionResult, SentinelPathReport
from sentinelpath.feature_extraction.infrastructure.rule_based_extractor import (
    RuleBasedFeatureExtractor,
)
from sentinelpath.graph_builder.infrastructure.networkx_adapter import NetworkXGraphBuilder
from sentinelpath.prediction.infrastructure.weighted_markov_model import (
    WeightedMarkovPredictionModel,
)
from sentinelpath.recommendation.infrastructure.rule_based_recommender import (
    RuleBasedRecommendationEngine,
)
from sentinelpath.reporting.infrastructure.json_reporting import JSONReporting
from sentinelpath.risk_scoring.infrastructure.config_based_risk_scoring import (
    ConfigBasedRiskScoring,
)


@dataclass(frozen=True)
class PipelineConfig:
    """Orchestrator'in tum alt-bilesenlerine iletilen tek bir
    konfigurasyon nesnesi. Her alanin varsayilani, ilgili fazda
    belirlenen varsayilanla AYNIDIR (bkz. config/settings.py) -- burada
    tekrarlanmasinin nedeni, bu sinifin pydantic-settings'e bagimli
    OLMAMASIDIR (bkz. ADR 0011, framework-bagimsizlik gerekcesi).
    """

    business_hours_start: int = 8
    business_hours_end: int = 18
    baseline_hour_frequency_threshold: float = 0.05
    baseline_peer_day_fraction_threshold: float = 0.2
    max_hops: int = 4
    asset_criticality_map: dict[str, float] = field(default_factory=dict)
    default_asset_criticality: float = 0.5
    default_technique_severity: float = 0.5
    pipeline_version: str = "0.1.0"


class PipelineOrchestrator:
    """Faz 3-8 arasindaki tum adapter'lari kurar ve zincirler.

    Constructor'da TUM adapter'lara ACIK parametreler verilir (Faz 3/5/7
    dosyalarindaki "lazy settings" prensibiyle ayni) -- boylece bu sinif
    pydantic-settings kurulu olmadan da ornoklenebilir ve test edilebilir.
    """

    def __init__(self, config: PipelineConfig | None = None) -> None:
        self._config = config or PipelineConfig()

        self._feature_extractor = RuleBasedFeatureExtractor(
            business_hours_start=self._config.business_hours_start,
            business_hours_end=self._config.business_hours_end,
        )
        self._graph_builder = NetworkXGraphBuilder()
        self._baseline = InMemoryBaselineBehavior(
            hour_frequency_threshold=self._config.baseline_hour_frequency_threshold,
            peer_day_fraction_threshold=self._config.baseline_peer_day_fraction_threshold,
        )
        self._attack_path_engine = NetworkXAttackPathEngine()
        self._prediction_model = WeightedMarkovPredictionModel()
        self._risk_scorer = ConfigBasedRiskScoring(
            asset_criticality_map=dict(self._config.asset_criticality_map),
            default_asset_criticality=self._config.default_asset_criticality,
            default_technique_severity=self._config.default_technique_severity,
        )
        self._recommender = RuleBasedRecommendationEngine()
        self._reporter = JSONReporting()

    def run(
        self,
        events: list[NormalizedEvent],
        known_hosts: list[str],
        start_node: str,
        feature_window_start: datetime,
        feature_window_end: datetime,
        baseline_window_start: datetime,
        baseline_window_end: datetime,
    ) -> SentinelPathReport:
        """Faz 3'ten Faz 8'e kadar tum pipeline'i calistirir.

        `known_hosts`, feature vektoru cikarilacak host kimliklerinin
        listesidir (bkz. ADR 0005 -- Graph Builder'in node envanteri
        icin bu listeye ihtiyaci vardir, hic disa baglantisi olmayan
        host'lar bile graf'ta yer almalidir).
        """

        feature_vectors = [
            self._feature_extractor.extract(host, events, feature_window_start, feature_window_end)
            for host in known_hosts
        ]

        snapshot = self._graph_builder.build(events=events, feature_vectors=feature_vectors)

        baseline_profiles = self._baseline.recompute(
            events, baseline_window_start, baseline_window_end
        )

        candidate_paths = self._attack_path_engine.find_candidate_paths(
            snapshot, start_node=start_node, max_hops=self._config.max_hops
        )

        prediction = self._predict_safely(candidate_paths, start_node)

        risk_scores = self._risk_scorer.score(prediction, baseline_profiles=baseline_profiles)
        recommendations = self._recommender.recommend(risk_scores)

        return SentinelPathReport(
            target_node=start_node,
            risk_scores=tuple(risk_scores),
            recommendations=tuple(recommendations),
            generated_at=datetime.now(UTC),
            pipeline_version=self._config.pipeline_version,
        )

    def _predict_safely(self, candidate_paths: list, start_node: str) -> PredictionResult:
        """WeightedMarkovPredictionModel.predict() BOS bir liste ile
        cagrilirsa ValueError firlatir (bkz. Faz 6) -- bu, saldirganin
        yapisal olarak HICBIR sonraki adiminin olmadigi (izole bir host,
        veya graf'ta hic cikis edge'i olmayan bir node) gecerli ve
        gerceklesebilir bir durumdur. Bu metod bu durumu YAKALAR ve
        bos (ama gecerli) bir PredictionResult doner -- hata firlatmaz.
        """

        if not candidate_paths:
            return PredictionResult(
                target_node=start_node,
                predictions=(),
                model_name=self._prediction_model.model_name(),
                generated_at=datetime.now(UTC),
            )
        return self._prediction_model.predict(candidate_paths)

    def to_json(self, report: SentinelPathReport) -> str:
        return self._reporter.to_json(report)

    def to_navigator_layer(self, report: SentinelPathReport) -> dict:
        return self._reporter.to_attack_navigator_layer(report)
