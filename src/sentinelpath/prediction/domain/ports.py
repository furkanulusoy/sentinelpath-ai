"""
prediction.domain.ports
=========================

Bu proje boyunca en cok DEGISECEK katman burasidir -- sistem prompt'ta
belirtildigi gibi Faz 6'da Isolation Forest, Random Forest, XGBoost, GNN,
Temporal Graph Network gibi birden fazla yaklasim karsilastirilacak.

Bu port'un var olma nedeni tam olarak budur: `application/predict_next_step.py`
(Faz 6'da yazilacak use-case) SADECE bu Protocol'u bilecek. Hangi somut model
calisiyor olursa olsun (RandomForestAdapter, MarkovChainAdapter,
GNNAdapter, ...), use-case kodu TEK SATIR bile degismeyecek. Model
degisikligi, sadece dependency-injection / config seviyesinde bir karardir.

Bu, "Attack Path Engine vs Prediction Model" ayriminin kod seviyesindeki
somut yansimasidir (bkz. ARCHITECTURE.md).
"""

from __future__ import annotations

from typing import Protocol

from sentinelpath.core.models import CandidatePath, PredictionResult


class PredictionModelPort(Protocol):
    def predict(
        self, candidate_paths: list[CandidatePath]
    ) -> PredictionResult:
        """Attack Path Engine'in urettigi yapisal olarak mumkun adaylar
        icinden, her biri icin bir olasilik degeri hesaplar.

        Onemli: Bu metod candidate_paths listesinin DISINDA yeni bir teknik
        'uyduramaz' -- yalnizca verilen adaylari siralar/agirliklandirir.
        Bu kisitlama acikanabilirligi korur: bir tahminin her zaman graf
        yapisinda karsiligi olan bir dayanagi vardir.
        """
        ...

    def model_name(self) -> str:
        """Raporlama ve loglama icin model kimligi (orn. 'random_forest_v1',
        'markov_chain_v1'). RiskScore ve Report ciktilarinda hangi modelin
        tahmin urettigini izlenebilir kilmak icin kullanilir.
        """
        ...
