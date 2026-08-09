"""
recommendation.infrastructure.rule_based_recommender
========================================================

RecommendationEnginePort'un MVP implementasyonu. Faz 1'de bu katman icin
zaten "kural tabanli olacak, LLM/ML KULLANILMAYACAK" karari verilmisti
(bkz. domain/ports.py docstring'i): MITRE ATT&CK teknik ID -> resmi
mitigation ID + eylem + gerekce eslemesi.

NOT: Bu faz orijinal 10 fazlik yol haritasinda AYRI bir faz olarak
listelenmemisti, ama Faz 1'in pipeline diyaminda Risk Scoring ile
Reporting arasinda yer aliyordu -- Reporting'in SentinelPathReport'u
kurabilmesi icin `recommendations` alaninin dolu olmasi gerekiyor. Bu
yuzden Faz 8 kapsamina (Reporting ile birlikte) alindi.
"""

from __future__ import annotations

from sentinelpath.core.models import Recommendation, RiskScore

# MITRE teknik ID -> (mitigation_id, eylem, gerekce). Mitigation ID'ler
# MITRE ATT&CK'in resmi kamuya acik mitigasyon kataloguna karsilik gelir
# (attack.mitre.org/mitigations/). Bu eslemeler MITRE'nin T1021/T1078
# sayfalarindaki resmi onerilen mitigasyonlarin bir alt kumesidir --
# tam liste degil, MVP icin en dogrudan ilgili olanlar secilmistir.
TECHNIQUE_MITIGATIONS: dict[str, tuple[str, str, str]] = {
    "T1021.001": (
        "M1032",
        "RDP erisimini MFA ile koruyun; RDP'yi dogrudan internete acmayin, "
        "sadece jump host/bastion uzerinden erisime izin verin.",
        "T1021.001 (RDP), calinti veya zayif kimlik bilgileriyle kotuye "
        "kullanilabilir. MFA bu riski onemli olcude azaltir.",
    ),
    "T1021.002": (
        "M1030",
        "SMB/Windows Admin Shares erisimini ag segmentasyonuyla sinirlayin; "
        "yonetici paylasimlarina erisimi sadece gerekli yonetici "
        "hesaplariyla kisitlayin.",
        "T1021.002, genis yetkili 'admin shares' erisimini kotuye kullanir. "
        "Ag segmentasyonu, ele gecirilmis bir host'un yatay hareketini sinirlar.",
    ),
    "T1021.003": (
        "M1042",
        "Gerekli olmayan sistemlerde DCOM'u devre disi birakin veya kisitlayin.",
        "T1021.003 (DCOM), varsayilan olarak acik oldugu icin genis bir saldiri yuzeyi sunar.",
    ),
    "T1021.004": (
        "M1032",
        "SSH erisiminde MFA/anahtar-tabanli kimlik dogrulama zorunlu kilin; "
        "parola ile SSH girisini devre disi birakin.",
        "T1021.004 (SSH), zayif parola tabanli kimlik dogrulamada en cok "
        "kotuye kullanilan servislerden biridir.",
    ),
    "T1021.005": (
        "M1032",
        "VNC erisiminde MFA zorunlu kilin; VNC'yi mumkunse devre disi "
        "birakip daha guvenli uzak erisim araclariyla degistirin.",
        "T1021.005 (VNC), genellikle zayif/varsayilan kimlik dogrulama kullanir.",
    ),
    "T1021.006": (
        "M1032",
        "WinRM erisiminde MFA zorunlu kilin; WinRM'i sadece yonetim aglarindan erisilebilir yapin.",
        "T1021.006 (WinRM), yonetimsel uzak erisim sagladigi icin yuksek "
        "etkili bir lateral movement vektorudur.",
    ),
    "T1078": (
        "M1032",
        "Tum ayricalikli hesaplarda MFA zorunlu kilin; parola politikalarini "
        "sikilastirin ve kullanilmayan/eski hesaplari duzenli olarak "
        "denetleyip kaldirin.",
        "T1078 (Valid Accounts), gecerli kimlik bilgilerini kullandigi "
        "icin tespiti EN ZOR tekniklerden biridir -- MFA ve hesap "
        "hijyeni en etkili savunmadir.",
    ),
    "T1046": (
        "M1030",
        "Ag segmentasyonuyla, bir host'un erisebildigi hedef sayisini "
        "sinirlayin; gereksiz servis/port erisimini kapatin.",
        "T1046 (Network Service Discovery), saldirganin sonraki lateral "
        "movement hedefini secmesini saglar. MITRE'nin resmi onerisi de "
        "M1030 (Network Segmentation) -- ayni mitigasyon, T1021.002 icin "
        "zaten kullanilan mitigasyonla tutarli.",
    ),
}

DEFAULT_ACTION = (
    "Bu teknik icin onceden tanimlanmis bir azaltma haritalamasi yok. "
    "MITRE ATT&CK'in resmi mitigasyon kataloguna (attack.mitre.org) "
    "bakarak manuel inceleme yapin."
)


class RuleBasedRecommendationEngine:
    """RecommendationEnginePort'u statik bir MITRE mitigation
    haritalamasiyla karsilayan adapter. `domain.ports.RecommendationEnginePort`'tan
    miras ALMAZ (Protocol, yapisal tiplemedir).
    """

    def recommend(self, risk_scores: list[RiskScore]) -> list[Recommendation]:
        # Ayni teknik birden fazla RiskScore'da (farkli hedef node'lar
        # icin) tekrar edebilir -- mitigasyon onerisi teknige ozgudur,
        # hedefe degil, bu yuzden TEKIL teknik basina bir oneri uretilir.
        # Sira, en yuksek risk skoruna sahip teknikten baslar (analistin
        # en once neye bakmasi gerektigini yansitir).
        seen_techniques: set[str] = set()
        recommendations: list[Recommendation] = []

        for risk_score in sorted(risk_scores, key=lambda r: r.score, reverse=True):
            if risk_score.technique_id in seen_techniques:
                continue
            seen_techniques.add(risk_score.technique_id)

            mapping = TECHNIQUE_MITIGATIONS.get(risk_score.technique_id)
            if mapping is not None:
                mitigation_id, action, rationale = mapping
            else:
                mitigation_id, action, rationale = (
                    None,
                    DEFAULT_ACTION,
                    f"{risk_score.technique_id} icin bilinen bir mitigasyon haritalamasi yok.",
                )

            recommendations.append(
                Recommendation(
                    technique_id=risk_score.technique_id,
                    mitigation_id=mitigation_id,
                    action=action,
                    rationale=rationale,
                )
            )

        return recommendations
