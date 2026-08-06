"""
risk_scoring.infrastructure.config_based_risk_scoring
==========================================================

RiskScoringPort'un MVP implementasyonu. Iki veri kaynagi kullanir:

1. `asset_criticality_map`: host_id -> kritiklik (0.0-1.0). Kurumun
   KENDI varlik envanterinden gelmesi beklenir (MVP'de constructor'a
   dogrudan dict olarak verilir; JSON dosyasindan yuklemek icin
   `load_asset_criticality_from_json()` yardimci fonksiyonu kullanilabilir).

2. `TECHNIQUE_SEVERITY`: MITRE teknik ID -> siddet (0.0-1.0).

DURUSTLUK NOTU: TECHNIQUE_SEVERITY degerleri resmi bir CVSS skoru
DEGILDIR -- CVSS, CVE'lere (spesifik yazilim zafiyetlerine) atanir,
MITRE ATT&CK tekniklerine degil (teknikler zafiyetten bagimsiz taktiksel
davranislardir, orn. "Valid Accounts" bir CVE degildir). Bu degerler,
alan bilgisine dayanan MAKUL varsayimlardir (Faz 6'daki RELATION_PRIORITY
ile ayni ruhta) -- gercek CVSS entegrasyonu (spesifik exploit edilen
zafiyetler biliniyorsa) gelecekteki bir genisletmedir.
"""

from __future__ import annotations

import json

from sentinelpath.core.models import BaselineProfile, PredictionResult, RiskScore

# MITRE teknik ID -> siddet (0.0-1.0). Degerler, teknigin tipik olarak
# ne kadar genis/kalici erisim sagladigina dayanir (orn. Valid Accounts,
# tespit edilmesi en zor tekniklerden biri oldugu icin yuksek).
TECHNIQUE_SEVERITY: dict[str, float] = {
    "T1021.001": 0.70,  # RDP
    "T1021.002": 0.75,  # SMB/Windows Admin Shares
    "T1021.003": 0.65,  # DCOM
    "T1021.004": 0.70,  # SSH
    "T1021.005": 0.60,  # VNC
    "T1021.006": 0.70,  # WinRM
    "T1078": 0.80,  # Valid Accounts -- tespiti en zor, en genis erisim
}


def load_asset_criticality_from_json(path: str) -> dict[str, float]:
    """Basit bir JSON dosyasindan {host_id: criticality} eslemesini yukler.
    Format: {"10.0.0.10": 0.9, "10.0.0.20": 0.7}
    """

    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    return {str(host): float(value) for host, value in raw.items()}


class ConfigBasedRiskScoring:
    """RiskScoringPort'u statik konfigurasyon tabanli kritiklik/siddet
    eslemeleriyle karsilayan adapter. `domain.ports.RiskScoringPort`'tan
    miras ALMAZ (Protocol, yapisal tiplemedir).
    """

    def __init__(
        self,
        asset_criticality_map: dict[str, float] | None = None,
        default_asset_criticality: float | None = None,
        technique_severity_map: dict[str, float] | None = None,
        default_technique_severity: float | None = None,
    ) -> None:
        if default_asset_criticality is None or default_technique_severity is None:
            # Lazy import: RuleBasedFeatureExtractor'daki (Faz 3) ayni
            # prensip -- acik parametrelerle testte pydantic-settings
            # kurulu olmasi gerekmesin.
            from sentinelpath.config.settings import get_settings

            settings = get_settings()
            default_asset_criticality = (
                default_asset_criticality
                if default_asset_criticality is not None
                else settings.default_asset_criticality
            )
            default_technique_severity = (
                default_technique_severity
                if default_technique_severity is not None
                else settings.default_technique_severity
            )

        self._asset_criticality_map = asset_criticality_map or {}
        self._default_asset_criticality = default_asset_criticality
        self._technique_severity_map = technique_severity_map or TECHNIQUE_SEVERITY
        self._default_technique_severity = default_technique_severity

    def asset_criticality(self, node_id: str) -> float:
        return self._asset_criticality_map.get(node_id, self._default_asset_criticality)

    def _technique_severity(self, technique_id: str) -> float:
        return self._technique_severity_map.get(technique_id, self._default_technique_severity)

    def score(
        self,
        prediction: PredictionResult,
        baseline_profiles: list[BaselineProfile] | None = None,
    ) -> list[RiskScore]:
        confidence_by_node: dict[str, float] = {}
        if baseline_profiles:
            confidence_by_node = {p.node_id: p.confidence for p in baseline_profiles}

        risk_scores: list[RiskScore] = []
        for tp in prediction.predictions:
            # Risk skoru, SALDIRGANIN ULASACAGI hedefin ("bu asset ne
            # kadar kritik") kritikligini yansitmalidir -- bu yuzden
            # prediction.target_node (zaten ele gecirilmis kaynak host)
            # DEGIL, yolun SON node'u (henuz ele gecirilmemis hedef)
            # kullanilir.
            destination = tp.contributing_path.path_nodes[-1]

            criticality = self.asset_criticality(destination)
            severity = self._technique_severity(tp.technique_id)
            raw_score = tp.probability * criticality * severity

            risk_scores.append(
                RiskScore(
                    target_node=destination,
                    technique_id=tp.technique_id,
                    probability=tp.probability,
                    asset_criticality=criticality,
                    technique_severity=severity,
                    score=raw_score * 100.0,
                    baseline_confidence=confidence_by_node.get(destination),
                )
            )

        return sorted(risk_scores, key=lambda r: r.score, reverse=True)
