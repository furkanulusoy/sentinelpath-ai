"""
core.models
===========

Bu modul, SentinelPath AI pipeline'indaki TUM katmanlarin ortak konustugu
veri sozlesmelerini (data contracts) tanimlar.

MIMARI GEREKCE
--------------
Hexagonal / Ports & Adapters mimarisinde her katman (Collector, Graph
Builder, Prediction Model, ...) birbirine DOGRUDAN bagimli olmamalidir.
Bunun yerine ortak, somut framework'ten bagimsiz veri tipleri uzerinden
konusurlar. Bu dosya o "ortak dil"dir.

Neden dataclass, neden Pydantic BaseModel degil?
    Bu tipler pipeline'in ICINDE, katmanlar arasinda tasinan ic temsillerdir
    (internal representations) -- disari acilan bir API sozlesmesi degildir.
    FastAPI katmaninda (Reporting/API adapter'i) bunlar Pydantic modellerine
    cevrilecektir. Ic domain modelini Pydantic'e baglamak, domain katmanini
    web framework'une bagimli hale getirir ki bu Hexagonal Architecture'in
    tam olarak onlemeye calistigi seydir ("domain katmani framework'ten
    haberdar olmamali").

Neden her sey immutable (frozen=True)?
    Bir AttackGraph ya da Prediction nesnesi pipeline'in bir asamasindan
    digerine gecerken yanlislikla mutasyona ugramamali. Bir feature'in
    Prediction Model asamasinda "duzeltilmesi", hata ayiklamayi (debugging)
    imkansiza yakin hale getirir -- "bu deger nerede degisti?" sorusuna
    cevap bulamazsiniz. Immutability bunu yapisal olarak engeller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

# ---------------------------------------------------------------------------
# 1. Collector asamasi ciktisi
# ---------------------------------------------------------------------------


class EventSource(StrEnum):
    """Bir NormalizedEvent'in hangi ham veri kaynagindan geldigini belirtir.

    Bunu Enum yapmamizin nedeni: Feature Extraction katmani, kaynaga gore
    farkli guven (confidence) agirligi uygulayabilir -- ornegin bir NETWORK
    event'i (paket yakalama) genelde ENDPOINT event'inden (ajan raporu) daha
    az sahte-pozitif (false positive) uretir cunku endpoint ajanlari bazen
    yanlis siniflandirma yapar.
    """

    NETWORK = "network"
    ENDPOINT = "endpoint"
    AUTH = "auth"
    HISTORICAL = "historical"


@dataclass(frozen=True)
class NormalizedEvent:
    """Collector katmaninin urettigi, kaynagi ne olursa olsun standart formata
    cevrilmis tekil olay.

    Ham veri (Sysmon XML, pcap, auth.log satiri) burada bitmelidir. Bu
    noktadan sonra hicbir katman ham format bilmemelidir -- bu, Collector'in
    "tek sorumlulugudur" (SOLID - Single Responsibility Principle).
    """

    event_id: str
    timestamp: datetime
    source: EventSource
    source_host: str
    target_host: str | None
    user: str | None
    raw_action: str  # orn. "rdp_login", "process_create", "registry_read"
    mitre_technique_id: str | None = None  # orn. "T1078" -- taniniyorsa
    metadata: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 2. Feature Extraction asamasi ciktisi
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HostFeatureVector:
    """Belirli bir host icin cikarilan davranissal ozellikler.

    Neden ham event listesi degil de bir "vector"? Prediction Model asamasi
    (Faz 6) istatistiksel/ML modeller kullanacak; bu modeller ozellik
    vektorleri uzerinde calisir, ham olay listesi uzerinde degil. Bu tipi
    simdiden tanimlamak, Faz 3'te (Feature Extraction) neyi uretmemiz
    gerektigini netlestirir.
    """

    host_id: str
    window_start: datetime
    window_end: datetime
    distinct_users_count: int
    distinct_target_hosts_count: int
    failed_auth_ratio: float
    off_hours_activity_ratio: float
    observed_techniques: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# 3. Graph Builder asamasi ciktisi
# ---------------------------------------------------------------------------


class RelationType(StrEnum):
    """Attack graph icindeki edge (kenar) tipleri.

    MITRE ATT&CK tactic kategorileriyle kasitli olarak hizalanmistir --
    boylece Attack Path Engine'de "bu edge tipinden hangi tekniklere
    gecilebilir?" sorusu dogrudan cevaplanabilir.
    """

    NETWORK_REACHABLE = "network_reachable"  # topolojik komsuluk
    AUTHENTICATES_TO = "authenticates_to"  # kullanici -> host
    TRUSTS = "trusts"  # host -> host (domain trust vb.)
    OBSERVED_LATERAL_MOVEMENT = "observed_lateral_movement"
    # Faz B (LANL degerlendirmesi) icin eklendi -- bkz. ADR 0015.
    # Discovery taktigi (TA0007), Lateral Movement'tan ONCE ve ondan daha
    # ZAYIF bir kanittir -- bu yuzden RELATION_PRIORS tablosunda mevcut
    # olceğin (1.0-3.0) BIR BASAMAK ALTINA yerlestirilir, ayri bir
    # kategori olarak degil.
    OBSERVED_SCANNING = "observed_scanning"


@dataclass(frozen=True)
class GraphEdge:
    source_node: str
    target_node: str
    relation: RelationType
    weight: float = 1.0  # graf algoritmalari icin (orn. en kisa yol maliyeti)
    # Faz 6'da eklendi (bkz. docs/adr/0007-graph-edge-technique-ids.md):
    # relation kaba bir KATEGORIdir (orn. "lateral movement"), bu alan
    # ise SPESIFIK MITRE teknik ID'lerini tasir (orn. "T1021.001").
    # Attack Path Engine'in CandidatePath.plausible_techniques alanini
    # doldurabilmesi icin bu ayrim gereklidir.
    mitre_technique_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class AttackGraphSnapshot:
    """Graph Builder'in urettigi, belirli bir zaman noktasindaki graf durumu.

    NetworkX'in kendi DiGraph nesnesini pipeline'da tasimak yerine bu
    "snapshot" tipini kullaniyoruz. Gerekce: NetworkX DiGraph mutable ve
    framework-spesifiktir; onu diger katmanlara sizdirmak, ileride
    NetworkX'i baska bir graf kutuphanesiyle (orn. Neo4j) degistirmek
    istedigimizde tum pipeline'i etkiler. Bu snapshot, o degisikligi
    yalnizca Graph Builder'in infrastructure katmaniyla sinirli tutar.
    """

    nodes: tuple[str, ...]
    edges: tuple[GraphEdge, ...]
    generated_at: datetime


# ---------------------------------------------------------------------------
# 4. Baseline Behavior asamasi ciktisi
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BaselineProfile:
    """Bir node (host/user) icin 'normal' davranisin istatistiksel ozeti.

    Attack Path Engine ve Prediction Model, gozlemlenen bir davranisin bu
    baseline'dan ne kadar saptigini kullanarak anomalili sinyalleri
    agirliklandirabilir.
    """

    node_id: str
    baseline_window_days: int
    typical_active_hours: tuple[int, ...]  # orn. (8,9,...,18)
    typical_peer_nodes: tuple[str, ...]
    confidence: float  # 0.0-1.0, baseline'in kac gunluk veriye dayandigina bagli
    # Faz B (LANL degerlendirmesi) icin eklendi -- bkz. ADR 0015.
    # Tukey IQR yontemiyle turetilen, bu host icin "normal" sayilan
    # bir zaman penceresindeki (varsayilan 5 dk) MAKSIMUM farkli hedef
    # sayisi. Yeterli veri yoksa None -- typical_peer_nodes gibi, uydurma
    # bir sayi uretilmez.
    typical_max_targets_per_window: float | None = None


# ---------------------------------------------------------------------------
# 5. Attack Path Engine asamasi ciktisi (DETERMINISTIK)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CandidatePath:
    """Attack Path Engine'in graf yapisina bakarak urettigi, YAPISAL OLARAK
    MUMKUN aday saldiri yolu. Burada HENUZ olasilik yoktur -- bu bilgi
    Prediction Model asamasinda eklenir.

    Bu tipin 'probability' alani OLMAMASI kasitlidir: Attack Path Engine'in
    deterministik/olasiliksal ayrimini kod seviyesinde de zorlamak icin.
    """

    path_nodes: tuple[str, ...]  # sirali node zinciri
    plausible_techniques: tuple[str, ...]  # her adim icin mumkun MITRE teknikleri
    structural_reason: str  # orn. "network_reachable + valid_credentials_observed"
    # Faz 6'da eklendi (bkz. docs/adr/0008-candidate-path-hop-data.md):
    # Prediction Model'in olasilik hesaplayabilmesi icin YAPILANDIRILMIS
    # per-hop veriye ihtiyaci var -- structural_reason (serbest metin)
    # bu amaca uygun degil. Uzunluk: len(path_nodes) - 1 (hop sayisi).
    hop_relations: tuple[RelationType, ...] = field(default_factory=tuple)
    hop_weights: tuple[float, ...] = field(default_factory=tuple)
    # Faz 6 implementasyonu sirasinda eklendi (ADR 0008 guncellemesi):
    # her hop icin AYRI teknik ID kumesi. plausible_techniques (yukarida)
    # TUM hop'larin birlesimidir; Prediction Model'in "sonraki adim"
    # tahmini icin ise SADECE SON hop'un tekniklerine ihtiyaci vardir --
    # bu ayrim olmadan ilk hop'un teknigi yanlislikla "sonraki adim"
    # olarak sunulabilirdi.
    hop_technique_ids: tuple[tuple[str, ...], ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# 6. Prediction Model asamasi ciktisi (OLASILIKSAL)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TechniquePrediction:
    """Belirli bir MITRE ATT&CK teknigi icin modelin urettigi olasilik."""

    technique_id: str  # orn. "T1078"
    technique_name: str  # orn. "Valid Accounts"
    probability: float  # 0.0-1.0
    contributing_path: CandidatePath


@dataclass(frozen=True)
class PredictionResult:
    target_node: str
    predictions: tuple[TechniquePrediction, ...]  # olasiliga gore azalan sirada
    model_name: str  # hangi adapter uretti (orn. "random_forest_v1")
    generated_at: datetime


# ---------------------------------------------------------------------------
# 7. Risk Scoring asamasi ciktisi
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskScore:
    """probability x asset_criticality x technique_severity formulunun ciktisi.

    Formulun kendisi (agirliklar) bilerek burada DEGIL, risk_scoring
    modulunun infrastructure/adapter katmaninda tutulacak -- boylece bir
    musteri/kurum kendi kritiklik agirliklarini modeli yeniden egitmeden
    degistirebilir (bkz. ARCHITECTURE.md, 'Risk Scoring vs Prediction Model').
    """

    target_node: str
    technique_id: str
    probability: float
    asset_criticality: float
    technique_severity: float
    score: float  # 0-100 arasi normalize edilmis nihai skor
    # Faz 7'de eklendi (bkz. docs/adr/0010-risk-score-baseline-confidence.md):
    # ANA FORMULE DAHIL DEGILDIR (carpan degildir) -- ayri bir baglam
    # alanidir. None = bu node icin baseline degerlendirmesi yapilmadi.
    baseline_confidence: float | None = field(default=None)


# ---------------------------------------------------------------------------
# 8. Recommendation Engine asamasi ciktisi
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Recommendation:
    technique_id: str
    mitigation_id: str | None  # MITRE ATT&CK mitigation ID varsa, orn. "M1032"
    action: str
    rationale: str


# ---------------------------------------------------------------------------
# 9. Reporting asamasi ciktisi
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SentinelPathReport:
    """Pipeline'in nihai, disari verilen ciktisi. FastAPI katmani bunu JSON'a
    ve/veya ATT&CK Navigator layer formatina serialize eder.
    """

    target_node: str
    risk_scores: tuple[RiskScore, ...]
    recommendations: tuple[Recommendation, ...]
    generated_at: datetime
    pipeline_version: str
