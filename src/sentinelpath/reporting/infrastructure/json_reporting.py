"""
reporting.infrastructure.json_reporting
==========================================

ReportingPort'un iki cikti formatini karsilayan implementasyonu:
1. Genel amacli JSON (to_json)
2. MITRE ATT&CK Navigator layer formati v4.5 (to_attack_navigator_layer)

NAVIGATOR LAYER FORMATI HAKKINDA
----------------------------------
Sema, MITRE'nin resmi spesifikasyonuna gore dogrulanmistir:
https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md

Onemli kisitlamalar:
- `versions.navigator` en az "4.9.0" olmalidir, `versions.layer` "4.5"
  olmalidir (spesifikasyonun kendi zorunlulugu).
- `versions.attack` OPSIYONELDIR ve BILEREK atlanmistir -- hangi ATT&CK
  veri surumune karsilik geldigini iddia etmek, bu kodun yazildigi
  tarihten sonra ATT&CK veri seti guncellenirse yanlis olabilir. Bir
  kurum kendi ATT&CK surumunu biliyorsa, donen dict'e sonradan
  `versions["attack"] = "..."` ekleyebilir.
- Ayni teknik ID'si BIRDEN FAZLA farkli hedef node icin farkli skorlarla
  gorunebilir (orn. T1078 hem host-b hem host-c icin tahmin edilmis
  olabilir). Navigator, teknik basina TEK bir skoru destekler -- bu
  yuzden EN YUKSEK skor alinir (en kotu senaryoyu one cikarmak,
  guvenlik baglaminda daha temkinli bir secimdir) ve diger hedefler
  teknigin metadata'sinda listelenir.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime

from sentinelpath.core.models import SentinelPathReport

# Risk skoru (0-100) icin renk gradyani: DUSUK skor = yesil (guvenli),
# YUKSEK skor = kirmizi (tehlikeli). MITRE'nin kendi ornek layer'i
# (bkz. spec) bunun tersini kullanir (onlarin baglaminda skor "tespit
# kapsami" gibi baska bir anlam tasiyabilir) -- bizim baglamimizda
# YUKSEK risk = KOTU oldugu icin kirmizi ile eslestirilmelidir.
RISK_GRADIENT_COLORS = ["#8ec843", "#ffe766", "#ff6666"]  # yesil -> sari -> kirmizi


def _json_default(obj: object) -> str:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"{type(obj)} JSON'a cevrilemez")


class JSONReporting:
    """ReportingPort'u JSON ve ATT&CK Navigator layer formatlariyla
    karsilayan adapter. `domain.ports.ReportingPort`'tan miras ALMAZ
    (Protocol, yapisal tiplemedir).
    """

    def to_json(self, report: SentinelPathReport) -> str:
        report_dict = asdict(report)
        return json.dumps(report_dict, default=_json_default, indent=2, ensure_ascii=False)

    def to_attack_navigator_layer(self, report: SentinelPathReport) -> dict:
        # Ayni teknik birden fazla hedef icin gorunuyorsa, EN YUKSEK
        # skoru ve o skora ait detaylari sakla (bkz. modul docstring'i).
        best_by_technique: dict[str, dict] = {}
        for rs in report.risk_scores:
            existing = best_by_technique.get(rs.technique_id)
            if existing is None or rs.score > existing["score"]:
                best_by_technique[rs.technique_id] = {
                    "score": rs.score,
                    "target_node": rs.target_node,
                    "probability": rs.probability,
                    "asset_criticality": rs.asset_criticality,
                    "technique_severity": rs.technique_severity,
                    "baseline_confidence": rs.baseline_confidence,
                }

        techniques = []
        for technique_id, info in best_by_technique.items():
            metadata = [
                {"name": "hedef_host", "value": info["target_node"]},
                {"name": "olasilik", "value": f"{info['probability']:.2f}"},
                {"name": "varlik_kritikligi", "value": f"{info['asset_criticality']:.2f}"},
                {"name": "teknik_siddeti", "value": f"{info['technique_severity']:.2f}"},
            ]
            if info["baseline_confidence"] is not None:
                metadata.append(
                    {"name": "baseline_guveni", "value": f"{info['baseline_confidence']:.2f}"}
                )

            techniques.append(
                {
                    "techniqueID": technique_id,
                    "score": round(info["score"], 1),
                    "color": "",
                    "comment": (
                        f"SentinelPath AI tahmini -- hedef: {info['target_node']}, "
                        f"kaynak: {report.target_node}"
                    ),
                    "enabled": True,
                    "showSubtechniques": True,
                    "metadata": metadata,
                }
            )

        return {
            "name": f"SentinelPath AI - {report.target_node}",
            "versions": {
                "navigator": "4.9.1",
                "layer": "4.5",
                # NOT: "attack" alani BILEREK atlandi (bkz. modul docstring'i)
            },
            "domain": "enterprise-attack",
            "description": (
                f"SentinelPath AI tarafindan {report.generated_at.isoformat()} tarihinde, "
                f"{report.target_node} icin uretilen attack path tahmini "
                f"(pipeline v{report.pipeline_version})."
            ),
            "sorting": 3,  # azalan skora gore sirala
            "layout": {
                "layout": "side",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
                "aggregateFunction": "max",
            },
            "techniques": techniques,
            "gradient": {
                "colors": RISK_GRADIENT_COLORS,
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Dusuk risk", "color": RISK_GRADIENT_COLORS[0]},
                {"label": "Orta risk", "color": RISK_GRADIENT_COLORS[1]},
                {"label": "Yuksek risk", "color": RISK_GRADIENT_COLORS[2]},
            ],
            "showTacticRowBackground": False,
        }
