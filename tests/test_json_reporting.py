"""
tests.test_json_reporting
============================
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from sentinelpath.core.models import Recommendation, RiskScore, SentinelPathReport
from sentinelpath.reporting.infrastructure.json_reporting import JSONReporting

NOW = datetime.now(UTC)


def _report(risk_scores=None, recommendations=None) -> SentinelPathReport:
    return SentinelPathReport(
        target_node="host-a",
        risk_scores=tuple(risk_scores or []),
        recommendations=tuple(recommendations or []),
        generated_at=NOW,
        pipeline_version="0.1.0",
    )


def test_to_json_produces_valid_parseable_json() -> None:
    reporter = JSONReporting()
    risk_score = RiskScore(
        target_node="host-b",
        technique_id="T1078",
        probability=0.6,
        asset_criticality=0.8,
        technique_severity=0.5,
        score=24.0,
        baseline_confidence=0.07,
    )
    recommendation = Recommendation(
        technique_id="T1078",
        mitigation_id="M1032",
        action="Enforce MFA",
        rationale="...",
    )
    report = _report(risk_scores=[risk_score], recommendations=[recommendation])

    json_str = reporter.to_json(report)
    parsed = json.loads(json_str)  # crash etmemeli

    assert parsed["target_node"] == "host-a"
    assert parsed["risk_scores"][0]["technique_id"] == "T1078"
    assert parsed["risk_scores"][0]["baseline_confidence"] == 0.07
    assert parsed["recommendations"][0]["mitigation_id"] == "M1032"
    assert "generated_at" in parsed  # datetime basariyla serialize edilmis


def test_to_json_handles_none_baseline_confidence() -> None:
    reporter = JSONReporting()
    risk_score = RiskScore(
        target_node="host-b",
        technique_id="T1078",
        probability=0.6,
        asset_criticality=0.8,
        technique_severity=0.5,
        score=24.0,
    )  # baseline_confidence varsayilan olarak None
    report = _report(risk_scores=[risk_score])

    parsed = json.loads(reporter.to_json(report))

    assert parsed["risk_scores"][0]["baseline_confidence"] is None


def test_navigator_layer_has_required_fields_per_spec() -> None:
    """bkz. https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md"""

    reporter = JSONReporting()
    risk_score = RiskScore(
        target_node="host-b",
        technique_id="T1078",
        probability=0.6,
        asset_criticality=0.8,
        technique_severity=0.5,
        score=24.0,
    )
    report = _report(risk_scores=[risk_score])

    layer = reporter.to_attack_navigator_layer(report)

    assert layer["domain"] == "enterprise-attack"  # zorunlu alan
    assert "name" in layer  # zorunlu alan
    assert layer["versions"]["layer"] == "4.5"  # spesifikasyonun zorunlu kildigi deger
    assert layer["versions"]["navigator"] >= "4.9.0"  # spesifikasyonun asgari surumu
    assert "attack" not in layer["versions"]  # bilerek atlandi (bkz. modul docstring'i)


def test_navigator_layer_technique_score_matches_risk_score() -> None:
    reporter = JSONReporting()
    risk_score = RiskScore(
        target_node="host-b",
        technique_id="T1078",
        probability=0.6,
        asset_criticality=0.8,
        technique_severity=0.5,
        score=24.0,
    )
    report = _report(risk_scores=[risk_score])

    layer = reporter.to_attack_navigator_layer(report)
    technique = layer["techniques"][0]

    assert technique["techniqueID"] == "T1078"
    assert technique["score"] == 24.0


def test_navigator_layer_uses_max_score_for_duplicate_technique() -> None:
    """Ayni teknik farkli hedefler icin farkli skorlarla gorunuyorsa,
    Navigator TEK bir skor destekledigi icin EN YUKSEK skor kullanilmalidir."""

    reporter = JSONReporting()
    risk_scores = [
        RiskScore(
            target_node="host-b",
            technique_id="T1078",
            probability=0.3,
            asset_criticality=0.5,
            technique_severity=0.5,
            score=15.0,
        ),
        RiskScore(
            target_node="host-c",
            technique_id="T1078",
            probability=0.9,
            asset_criticality=0.9,
            technique_severity=0.5,
            score=80.0,
        ),
    ]
    report = _report(risk_scores=risk_scores)

    layer = reporter.to_attack_navigator_layer(report)

    assert len(layer["techniques"]) == 1  # tek teknik, dedupe edilmis
    assert layer["techniques"][0]["score"] == 80.0
    assert layer["techniques"][0]["comment"].find("host-c") != -1  # en yuksek skorun hedefi


def test_navigator_layer_gradient_maps_high_score_to_red() -> None:
    """Risk baglaminda YUKSEK skor = KOTU = kirmizi olmali (MITRE'nin
    kendi ornek layer'inin tersi bir semantik -- bkz. modul docstring'i)."""

    reporter = JSONReporting()
    report = _report()

    layer = reporter.to_attack_navigator_layer(report)

    assert layer["gradient"]["colors"][-1] == "#ff6666"  # kirmizi, en yuksek uc
    assert layer["gradient"]["colors"][0] == "#8ec843"  # yesil, en dusuk uc


def test_navigator_layer_with_no_risk_scores_has_empty_techniques() -> None:
    reporter = JSONReporting()
    report = _report()

    layer = reporter.to_attack_navigator_layer(report)

    assert layer["techniques"] == []


def test_navigator_layer_technique_metadata_includes_baseline_confidence_when_present() -> None:
    reporter = JSONReporting()
    risk_score = RiskScore(
        target_node="host-b",
        technique_id="T1078",
        probability=0.6,
        asset_criticality=0.8,
        technique_severity=0.5,
        score=24.0,
        baseline_confidence=0.42,
    )
    report = _report(risk_scores=[risk_score])

    layer = reporter.to_attack_navigator_layer(report)
    metadata_names = {m["name"] for m in layer["techniques"][0]["metadata"]}

    assert "baseline_guveni" in metadata_names
