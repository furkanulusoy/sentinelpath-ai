"""
api.schemas
=============

FastAPI icin Pydantic istek/yanit semalari. Bu dosya BILEREK
`core.models`'daki domain dataclass'larini DOGRUDAN API'ye maruz
BIRAKMAZ -- ayri Pydantic modelleri tanimlar. Gerekce: domain modelleri
(core.models) pipeline'in IC temsilidir ve HTTP/JSON sozlesmesinden
bagimsiz kalmalidir (bkz. core/models.py'nin kendi ust-duzey gerekcesi,
"domain katmani framework'ten haberdar olmamali"). API semasi
degisirse (orn. bir alan yeniden adlandirilirsa), core.models'a
DOKUNULMAZ.

NOT: Bu dosya `pydantic` bagimliligi gerektirir (bkz. pyproject.toml
`api` ekstra grubu). Bu sandbox'ta pydantic kurulu olmadigi icin
CALISTIRILARAK DOGRULANAMADI -- sadece sozdizimi kontrol edildi
(bkz. ADR 0011).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class NormalizedEventRequest(BaseModel):
    """core.models.NormalizedEvent'in HTTP sozlesmesi karsiligi."""

    event_id: str
    timestamp: datetime
    source: str = Field(description="network | endpoint | auth | historical")
    source_host: str
    target_host: str | None = None
    user: str | None = None
    raw_action: str
    mitre_technique_id: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class PredictRequest(BaseModel):
    """POST /api/v1/predict icin istek govdesi."""

    events: list[NormalizedEventRequest]
    known_hosts: list[str] = Field(
        description="Feature vektoru cikarilacak ve graf'ta node olarak "
        "yer alacak TUM host kimlikleri (bkz. ADR 0005)."
    )
    start_node: str = Field(description="Analiz edilecek, zaten ele gecirilmis host.")
    feature_window_start: datetime
    feature_window_end: datetime
    baseline_window_start: datetime
    baseline_window_end: datetime
    asset_criticality_map: dict[str, float] = Field(default_factory=dict)
    max_hops: int = Field(default=4, ge=1, le=10)


class RiskScoreResponse(BaseModel):
    target_node: str
    technique_id: str
    probability: float
    asset_criticality: float
    technique_severity: float
    score: float
    baseline_confidence: float | None = None


class RecommendationResponse(BaseModel):
    technique_id: str
    mitigation_id: str | None
    action: str
    rationale: str


class ReportResponse(BaseModel):
    """SentinelPathReport'un HTTP yanit sozlesmesi karsiligi."""

    target_node: str
    risk_scores: list[RiskScoreResponse]
    recommendations: list[RecommendationResponse]
    generated_at: datetime
    pipeline_version: str


class HealthResponse(BaseModel):
    status: str = "ok"
