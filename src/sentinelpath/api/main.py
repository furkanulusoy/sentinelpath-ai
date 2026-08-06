"""
api.main
==========

FastAPI uygulamasi -- BILEREK ince bir katmandir. Tum is mantigi
`orchestration.pipeline_orchestrator.PipelineOrchestrator`'da yasar
(bkz. ADR 0011). Bu dosyanin tek sorumlulugu: HTTP istek/yanit <-> domain
tipi donusumu.

CALISTIRMA:
    pip install -e ".[api]"
    uvicorn sentinelpath.api.main:app --reload

Sonra:
    http://localhost:8000/docs        -> otomatik OpenAPI dokumantasyonu
    http://localhost:8000/dashboard/  -> statik dashboard sayfasi

NOT (durustluk): Bu dosya, pydantic/fastapi bu gelistirme ortaminda
kurulu olmadigi ve internet erisimi kapali oldugu icin CALISTIRILARAK
DOGRULANAMADI. Sozdizimi `python -m py_compile` ile kontrol edildi.
Is mantigi (PipelineOrchestrator) ayrica ve TAM olarak test edildi --
bkz. tests/test_pipeline_orchestrator.py.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

from sentinelpath.api.schemas import (
    HealthResponse,
    PredictRequest,
    RecommendationResponse,
    ReportResponse,
    RiskScoreResponse,
)
from sentinelpath.core.models import EventSource, NormalizedEvent
from sentinelpath.orchestration.pipeline_orchestrator import PipelineConfig, PipelineOrchestrator

app = FastAPI(
    title="SentinelPath AI",
    description="Predict the attack before it happens.",
    version="0.1.0",
)

# static/dashboard, `src/sentinelpath/` PAKETININ ICINDE tutulur (repo
# kokunde DEGIL). Gerekce: `pip install -e ".[api]"` (gelistirme) ile
# `pip install ".[api]"` (production, editable OLMAYAN) arasinda dosya
# yollari FARKLI davranir -- bir paket ICINDEKI dosyalar her iki
# senaryoda da `__file__`'a GORECELI olarak bulunabilirken, repo
# KOKUNE goreli bir yol (orn. 4 seviye yukari) sadece kaynak agacindan
# calisirken (editable/gelistirme) dogru sonuc verir, gercek bir
# `site-packages` kurulumunda YANLIS yere isaret eder. Bu hata Faz 10'da
# Docker imaji tasarlanirken bulundu (bkz. ADR 0012).
#
# EK GUVENCE: `SENTINELPATH_STATIC_DIR` ortam degiskeni VARSA, paket-
# goreli hesaplamanin YERINE gecer. Bu, Docker imajinin, wheel'in
# statik dosyalari fiilen icerip icermedigine dair BELIRSIZLIGE hic
# bagimli kalmadan (bu sandbox'ta hatchling kurulu olmadigi icin bu
# davranis test EDILEMEDI), statik dosyalarin konumunu ACIKCA kontrol
# edebilmesini saglar -- bkz. Dockerfile.
_static_dir_override = os.environ.get("SENTINELPATH_STATIC_DIR")
_STATIC_DASHBOARD_DIR = (
    Path(_static_dir_override)
    if _static_dir_override
    else Path(__file__).resolve().parent.parent / "static" / "dashboard"
)
if _STATIC_DASHBOARD_DIR.exists():
    app.mount(
        "/dashboard", StaticFiles(directory=str(_STATIC_DASHBOARD_DIR), html=True), name="dashboard"
    )


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/api/v1/predict", response_model=ReportResponse)
def predict(request: PredictRequest) -> ReportResponse:
    """Faz 3-8 pipeline'inin tamamini calistirir ve bir SentinelPathReport
    dondurur. Is mantigi tamamen PipelineOrchestrator'da yasar -- bu
    fonksiyon sadece Pydantic <-> domain donusumu yapar.
    """

    try:
        events = [_to_domain_event(e) for e in request.events]
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    orchestrator = PipelineOrchestrator(
        PipelineConfig(
            asset_criticality_map=request.asset_criticality_map,
            max_hops=request.max_hops,
        )
    )

    report = orchestrator.run(
        events=events,
        known_hosts=request.known_hosts,
        start_node=request.start_node,
        feature_window_start=request.feature_window_start,
        feature_window_end=request.feature_window_end,
        baseline_window_start=request.baseline_window_start,
        baseline_window_end=request.baseline_window_end,
    )

    return ReportResponse(
        target_node=report.target_node,
        risk_scores=[
            RiskScoreResponse(
                target_node=rs.target_node,
                technique_id=rs.technique_id,
                probability=rs.probability,
                asset_criticality=rs.asset_criticality,
                technique_severity=rs.technique_severity,
                score=rs.score,
                baseline_confidence=rs.baseline_confidence,
            )
            for rs in report.risk_scores
        ],
        recommendations=[
            RecommendationResponse(
                technique_id=r.technique_id,
                mitigation_id=r.mitigation_id,
                action=r.action,
                rationale=r.rationale,
            )
            for r in report.recommendations
        ],
        generated_at=report.generated_at,
        pipeline_version=report.pipeline_version,
    )


def _to_domain_event(event_request) -> NormalizedEvent:  # type: ignore[no-untyped-def]
    """NormalizedEventRequest (Pydantic) -> NormalizedEvent (domain dataclass).

    `source` alani bir string olarak gelir (HTTP JSON'da enum yoktur);
    burada core.models.EventSource'a cevrilir. Bilinmeyen bir deger
    gelirse ACIKCA 422 hatasi verilir (sessizce yanlis bir varsayilana
    dusmek yerine).
    """

    try:
        source = EventSource(event_request.source)
    except ValueError as exc:
        raise ValueError(
            f"Gecersiz source degeri: {event_request.source!r}. "
            f"Gecerli degerler: {[e.value for e in EventSource]}"
        ) from exc

    return NormalizedEvent(
        event_id=event_request.event_id,
        timestamp=event_request.timestamp,
        source=source,
        source_host=event_request.source_host,
        target_host=event_request.target_host,
        user=event_request.user,
        raw_action=event_request.raw_action,
        mitre_technique_id=event_request.mitre_technique_id,
        metadata=event_request.metadata,
    )
