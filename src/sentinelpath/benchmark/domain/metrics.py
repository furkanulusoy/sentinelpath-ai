"""
benchmark.domain.metrics
===========================

SentinelBench: herhangi bir PredictionModelPort implementasyonunu,
ayni sizinti-onleme disipliniyle (bkz. LEAKAGE_PREVENTION.md)
degerlendirmek icin kullanilan saf metrik fonksiyonlari.

Bu fonksiyonlar KASITLI OLARAK saf (pure) -- hicbir I/O, hicbir dosya
okuma yapmazlar, sadece PredictionResult + gercek (ground truth) hedef
host alip bir sayi donerler. Bu, test edilebilirligi kolaylastirir ve
metrik mantigini veri kaynagindan (LANL, baska bir veri seti, sentetik
test) tamamen ayirir.
"""

from __future__ import annotations

from sentinelpath.core.models import PredictionResult, TechniquePrediction


def predicted_host(prediction: TechniquePrediction) -> str:
    """Bir TechniquePrediction'in 'tahmin ettigi' hedef host'u -- aday
    yolun SON node'u (bkz. ADR 0008, hop_technique_ids'in SADECE son
    hop'u temsil etmesiyle ayni mantik)."""
    return prediction.contributing_path.path_nodes[-1]


def top_k_hit(result: PredictionResult, ground_truth_host: str, k: int) -> bool:
    """Gercek hedef, modelin ilk k tahmininin ARASINDA mi?"""
    return any(predicted_host(p) == ground_truth_host for p in result.predictions[:k])


def reciprocal_rank(result: PredictionResult, ground_truth_host: str) -> float:
    """Mean Reciprocal Rank (MRR) hesaplamasinin tekil-ornek katkisi.
    Gercek hedef modelin N'inci tahmininde cikarsa 1/N doner; hic
    cikmazsa 0.0 doner (uydurma bir kismi kredi VERILMEZ)."""
    for i, p in enumerate(result.predictions, start=1):
        if predicted_host(p) == ground_truth_host:
            return 1.0 / i
    return 0.0


def evaluate_scenario(
    result: PredictionResult, ground_truth_host: str, k_values: tuple[int, ...] = (1, 3, 5)
) -> dict[str, float]:
    """Tek bir senaryo (bir baslangic node'u + bir gercek sonraki hedef)
    icin tum metrikleri tek seferde hesaplar."""
    metrics: dict[str, float] = {
        f"top_{k}": float(top_k_hit(result, ground_truth_host, k)) for k in k_values
    }
    metrics["reciprocal_rank"] = reciprocal_rank(result, ground_truth_host)
    return metrics