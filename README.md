# SentinelPath AI

**Predict the attack before it happens.**

SentinelPath AI, ag topolojisi, host iliskileri, kullanici davranislari ve
gecmis saldiri verilerini analiz ederek, olasi bir saldirganin bir sonraki
adimini **MITRE ATT&CK** teknikleriyle iliskilendirilmis olasilik degerleri
ile tahmin eden bir attack path prediction motorudur.

> Bu bir anomali/alarm sistemi degildir. Amac "ne oldu"yu tespit etmek
> degil, gozlemlenen kismi saldiri zincirinden **"sirada ne var?"**
> sorusuna, izlenebilir ve acikanabilir bir sekilde cevap vermektir.

## Neden SentinelPath AI?

Bugunku IDS/IPS/EDR/NDR cozumleri buyuk olcude reaktiftir — saldiri
gerceklestikten sonra alarm uretirler. Attack graph literaturu (MulVAL,
TVA) genelde statik zafiyet grafigine dayanir; endustriyel EDR/NDR
urunleri ise davranissaldir ama grafiksel degildir. SentinelPath AI bu
ikisinin kesisimini hedefler: **surekli guncellenen bir davranissal
attack graph uzerinde, olasiliksal, MITRE ATT&CK'e baglanmis tahmin.**

Detayli problem analizi, alternatif cozumlerin karsilastirmasi ve hedef
kullanici kitlesi icin proje kok dizinindeki tasarim notlarina bakiniz.

## Mimari

Sistem, **Hexagonal Architecture (Ports & Adapters)** ile **pipeline veri
akisini** birlestiren bir mimariyle tasarlanmistir. Detayli diyagram,
katman gerekceleri ve Architecture Decision Record'lar icin bkz.
**[ARCHITECTURE.md](ARCHITECTURE.md)**.

Ozet akis:

```
Data Sources → Collector → Feature Extraction → Graph Builder
→ Baseline Behavior ⇄ Attack Path Engine → Prediction Model
→ Risk Scoring → Recommendation Engine → Reporting
```

## Kurulum

> Sistem promptunda tanımlanan 10 fazlık yol haritasının tamamı
> tamamlanmıştır (bkz. Faz Haritası). Aşağıdaki kurulum adımları güncel
> ve çalışan pipeline için geçerlidir.

```bash
# Sanal ortam olustur
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Cekirdek bagimliliklari kur
pip install -e .

# Gelistirme bagimliliklarini da eklemek icin
pip install -e ".[dev]"

# Ozellik gruplarina gore (ihtiyaca gore):
pip install -e ".[api]"      # FastAPI + uvicorn
pip install -e ".[network]"  # Scapy (pasif ag kesfi icin)
pip install -e ".[ml]"       # scikit-learn, xgboost
pip install -e ".[gnn]"      # torch (Graph Neural Network, Faz 6+)
```

Ortam degiskenleri icin `.env` dosyasi olusturun (bkz.
`src/sentinelpath/config/settings.py` icin desteklenen alanlar,
`SENTINELPATH_` on ekiyle):

```env
SENTINELPATH_ENVIRONMENT=development
SENTINELPATH_LOG_LEVEL=INFO
SENTINELPATH_LOG_FORMAT=console
```

## Kullanim

### Testleri calistirma

```bash
pip install -e ".[dev]"
pytest                                        # tum Python testleri

node tests/dashboard/test_app_pure_functions.js  # dashboard JS testleri (Node.js gerektirir)
```

### Network Parser (Collector) — Faz 2

`.pcap` dosyasini `NormalizedEvent` listesine ceviren ilk somut Collector
adaptoru kullanima hazir. Scapy'ye ihtiyac duyar:

```bash
pip install -e ".[network]"
```

```python
from sentinelpath.collector.infrastructure.pcap_adapter import PcapFileCollector

collector = PcapFileCollector(pcap_path="capture.pcap")
events = collector.collect()

for event in events:
    print(event.source_host, "->", event.target_host, event.raw_action, event.mitre_technique_id)
```

Ornek cikti (RDP ve SMB trafigi iceren bir capture icin):

```
10.0.0.5 -> 10.0.0.10 tcp_connect:rdp T1021.001
10.0.0.5 -> 10.0.0.11 tcp_connect:smb_admin_shares T1021.002
10.0.0.7 -> 10.0.0.10 tcp_connect:port_8080 None
```

**Mimari not:** Bu adaptorun ic tasarimi (Scapy'ye bagimli I/O'nun
domain cevirme mantigindan ayrilmasi) icin bkz.
[ADR 0003](docs/adr/0003-pure-translation-vs-framework-io-split.md).
Ceviri mantigi (`packet_translation.py`), Scapy KURULU OLMASA BILE
`tests/test_packet_translation.py` ile test edilebilir.

### Feature Extraction — Faz 3

`NormalizedEvent` listesinden `HostFeatureVector` üreten kural-tabanlı
(pandas gerektirmeyen) extractor:

```python
from datetime import datetime, timezone
from sentinelpath.feature_extraction.infrastructure.rule_based_extractor import (
    RuleBasedFeatureExtractor,
)

extractor = RuleBasedFeatureExtractor()  # settings'ten is-saati varsayilanlarini okur
vector = extractor.extract(
    host_id="10.0.0.5",
    events=events,  # Faz 2'nin PcapFileCollector'indan gelen NormalizedEvent listesi
    window_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
    window_end=datetime(2026, 1, 2, tzinfo=timezone.utc),
)

print(vector.distinct_users_count, vector.failed_auth_ratio, vector.observed_techniques)
```

Ornek cikti:

```
distinct_users_count=2 failed_auth_ratio=0.33 observed_techniques=('T1021.001', 'T1021.002')
```

**Mimari not:** `FeatureExtractorPort` imzasina Faz 3'te açık bir zaman
penceresi eklendi — gerekçesi için bkz.
[ADR 0004](docs/adr/0004-explicit-feature-window.md). Pandas'a karşı
saf-Python seçiminin gerekçesi için ARCHITECTURE.md, Faz 3 notlarına
bakınız.

### Graph Builder — Faz 4

`NormalizedEvent` listesinden ve host envanterinden bir `AttackGraphSnapshot`
üreten NetworkX tabanlı adaptör:

```python
from sentinelpath.graph_builder.infrastructure.networkx_adapter import NetworkXGraphBuilder

builder = NetworkXGraphBuilder()
snapshot = builder.build(events=events, feature_vectors=feature_vectors)

for edge in snapshot.edges:
    print(edge.source_node, "->", edge.target_node, edge.relation.value, f"(weight={edge.weight})")

# Statik topoloji bilgisini (orn. firewall/subnet erişim kuralları) birleştirmek icin:
snapshot = builder.merge_static_topology(snapshot, topology_edges=[("host-a", "host-c")])
```

Örnek çıktı:

```
10.0.0.5 -> 10.0.0.10 authenticates_to (weight=1.0)
10.0.0.5 -> 10.0.0.11 observed_lateral_movement (weight=3.0)
```

**Mimari not:** `GraphBuilderPort.build()` imzasına Faz 4'te açık
`events` parametresi eklendi — gerekçesi için bkz.
[ADR 0005](docs/adr/0005-graph-builder-events-parameter.md). `DiGraph`
yerine `MultiDiGraph` seçiminin gerekçesi (aynı host çifti arasında
birden fazla ilişki tipinin aynı anda var olabilmesi) için
`networkx_adapter.py` modül docstring'ine bakınız.

### Uçtan uca demo (Faz 1-4 birlikte)

`scripts/demo_end_to_end.py`, şu ana kadar inşa edilen dört fazı gerçek
girdi/çıktılarla zincirler — bir lateral movement senaryosunu (RDP →
SMB) ve aynı ortamdaki normal/gündüz trafiğini aynı grafta gösterir:

```bash
PYTHONPATH=src python3 scripts/demo_end_to_end.py
```

Bu, `.pcap`/Scapy adımı hariç (bu ortamda Scapy kurulu değil — bkz. ADR
0003), pipeline'ın geri kalanının uçtan uca gerçekten çalıştığının
kanıtıdır.

### Baseline Behaviour — Faz 5

Ham `NormalizedEvent` geçmişinden (birden fazla günü kapsayan geniş bir
pencere) her host için "normal" davranış profili çıkarır:

```python
from sentinelpath.baseline_behavior.infrastructure.in_memory_baseline import (
    InMemoryBaselineBehavior,
)

baseline = InMemoryBaselineBehavior()
baseline.recompute(events, window_start=..., window_end=...)  # periyodik/batch cagri

profile = baseline.get_profile("10.0.0.10")  # hizli, senkron okuma
print(profile.confidence, profile.typical_active_hours, profile.typical_peer_nodes)
```

**Önemli:** `confidence` alanı, istenen pencereye göre GERÇEKTEN kaç gün
veri gözlemlendiğini yansıtır. Az veriyle "bu davranış anormal" iddia
etmemek için Faz 6'daki Prediction Model bu değeri mutlaka hesaba
katmalıdır — `scripts/demo_end_to_end.py`'nin çıktısı bunu somut olarak
gösteriyor (tek günlük demo verisiyle confidence ≈ 0.07).

**Mimari not:** `BaselineBehaviorPort.recompute()` imzası Faz 5'te
`AttackGraphSnapshot` yerine ham event + açık pencere alacak şekilde
değiştirildi — gerekçesi için bkz.
[ADR 0006](docs/adr/0006-baseline-events-and-window.md). Bu sınıf,
projedeki ilk **stateful** adaptördür (Graph Builder'ın aksine) —
gerekçesi için `in_memory_baseline.py` modül docstring'ine bakınız.

### Attack Path Prediction — Faz 6

Bu, projenin asıl değer önerisi. İki ayrı motor birlikte çalışır (bkz.
ADR 0002): **Attack Path Engine** (deterministik, sadece graf teorisi)
ve **Prediction Model** (olasılıksal sıralama).

```python
from sentinelpath.attack_path_engine.infrastructure.networkx_engine import (
    NetworkXAttackPathEngine,
)
from sentinelpath.prediction.infrastructure.weighted_markov_model import (
    WeightedMarkovPredictionModel,
)

engine = NetworkXAttackPathEngine()
candidate_paths = engine.find_candidate_paths(snapshot, start_node="10.0.0.50", max_hops=3)

predictor = WeightedMarkovPredictionModel()
result = predictor.predict(candidate_paths)

for tp in result.predictions:  # azalan olasılıkla sıralı
    print(f"%{tp.probability*100:.1f}  {tp.technique_id}  {tp.technique_name}")
```

**Model seçimi:** Isolation Forest, Random Forest, XGBoost, GNN, Temporal
GNN, LSTM ve Transformer değerlendirildi ve MVP için reddedildi — hepsi
etiketli eğitim verisi gerektiriyor, bu projede henüz hiç yok. Bunun
yerine, gözlemlenen graf ağırlıklarından (zaten ampirik gözlem sıklığı)
doğrudan olasılık üreten, eğitim gerektirmeyen bir **ağırlıklı Markov
geçiş modeli** seçildi. Tam karşılaştırma tablosu ve gerekçe için bkz.
[ADR 0009](docs/adr/0009-prediction-model-selection.md).

**Mimari not:** Bu fazda implementasyon sırasında **iki gerçek veri kaybı**
bulundu ve düzeltildi:
- `GraphEdge`, spesifik MITRE teknik ID'lerini taşımıyordu (sadece kaba
  ilişki kategorisini) — bkz. [ADR 0007](docs/adr/0007-graph-edge-technique-ids.md)
- `CandidatePath`, Prediction Model'in olasılık hesaplayabilmesi için
  gereken hop-bazlı yapılandırılmış veriyi taşımıyordu — bkz.
  [ADR 0008](docs/adr/0008-candidate-path-hop-data.md)

Ayrıca `networkx`'in bu sürümünde `all_simple_paths()`'ın `target`
parametresini artık zorunlu kıldığı canlı testler sırasında ortaya
çıktı ve düzeltildi.

### Risk Scoring — Faz 7

`PredictionResult`'i alıp her tahmin için `probability × asset_criticality
× technique_severity` formülüyle bir risk skoru (0-100) üretir:

```python
from sentinelpath.risk_scoring.infrastructure.config_based_risk_scoring import (
    ConfigBasedRiskScoring,
)

risk_scorer = ConfigBasedRiskScoring(
    asset_criticality_map={"10.0.0.20": 0.95, "10.0.0.10": 0.9},  # kurumun kendi varlık envanteri
)
risk_scores = risk_scorer.score(prediction, baseline_profiles=baseline_profiles)

for rs in risk_scores:  # azalan skora göre sıralı
    print(rs.target_node, rs.score, rs.baseline_confidence)
```

**Mimari not:** `RiskScore`'a Faz 7'de `baseline_confidence` alanı
eklendi — ama **ana formüle karıştırılmadı**, ayrı bir bağlam alanı
olarak taşınıyor. Gerekçesi için bkz.
[ADR 0010](docs/adr/0010-risk-score-baseline-confidence.md). Bu,
Faz 6'nın "düşük güvenin skoru artırması mı azaltması mı gerektiği
belirsiz" tespitine dürüst bir cevaptır: nihai yorumu insana bırakır.

`TECHNIQUE_SEVERITY` tablosundaki değerler resmi CVSS skorları
**değildir** — CVSS'nin CVE'lere (zafiyetlere) atandığını, MITRE
ATT&CK tekniklerine değil, unutmamak gerekir. Bunlar alan bilgisine
dayanan makul varsayımlardır (Faz 6'daki `RELATION_PRIORITY` ile aynı
ruhta).

### Recommendation Engine + Reporting — Faz 8 (MVP'nin son fazı)

**Not:** Recommendation Engine, orijinal 10 fazlık yol haritasında ayrı
bir faz olarak listelenmemişti, ama Faz 1'in kendi pipeline diyagramında
(Risk Scoring → Recommendation Engine → Reporting) vardı — Reporting'in
`SentinelPathReport`'u kurabilmesi için `recommendations` alanının dolu
olması gerektiğinden, bu ikisi birlikte tamamlandı.

```python
from sentinelpath.recommendation.infrastructure.rule_based_recommender import (
    RuleBasedRecommendationEngine,
)
from sentinelpath.reporting.infrastructure.json_reporting import JSONReporting
from sentinelpath.core.models import SentinelPathReport
from datetime import datetime, timezone

recommendations = RuleBasedRecommendationEngine().recommend(risk_scores)

report = SentinelPathReport(
    target_node="10.0.0.50", risk_scores=tuple(risk_scores),
    recommendations=tuple(recommendations),
    generated_at=datetime.now(timezone.utc), pipeline_version="0.1.0",
)

reporter = JSONReporting()
json_output = reporter.to_json(report)
navigator_layer = reporter.to_attack_navigator_layer(report)
```

Gerçek pipeline çıktısından üretilmiş örnek dosyalar `examples/`
klasöründe bulunur:
- `examples/sample_report.json` — genel amaçlı JSON rapor
- `examples/sample_navigator_layer.json` — bu dosya doğrudan
  [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)'a
  "Open Existing Layer → Upload from local" ile yüklenip
  görselleştirilebilir.

**Mimari not:** Navigator layer şeması, implementasyon öncesi resmi
MITRE spesifikasyonuna (`layerformat.md`, v4.5) karşı doğrulandı.
`versions.attack` alanı bilerek atlandı — hangi ATT&CK veri sürümüne
karşılık geldiğini iddia etmek, veri seti güncellenince yanlış olabilir
(alan opsiyonel). Risk skoru gradyanı MITRE'nin kendi örnek layer'inin
tersi yönde tasarlandı (bizim bağlamımızda yüksek skor = kötü = kırmızı).

## MVP Tamamlandı

Sistem promptunda tanımlanan 10 fazlık yol haritasının **ilk 8 fazı**
(MVP kapsamı) tamamlanmıştır. Uçtan uca çalışan pipeline
`scripts/demo_end_to_end.py` ile gösterilmektedir. Faz 9 (Dashboard) ve
Faz 10 (Deployment), README'nin "Gelecek Planı" bölümünde ele
alınmaktadır.

### Dashboard — Faz 9

Faz 2-8'de yazılan tüm bileşenleri zincirleyen bir **PipelineOrchestrator**
(saf Python, hiçbir web framework'üne bağımlı değil), bunu HTTP üzerinden
sunan bir **FastAPI uygulaması**, ve bunu görselleştiren **statik bir
HTML/vanilla JS dashboard** eklendi.

```bash
pip install -e ".[api]"
uvicorn sentinelpath.api.main:app --reload
```

Sonra tarayıcıda `http://localhost:8000/dashboard/` açılıp "Demo
senaryosunu çalıştır" butonuna basılabilir — risk skoru tablosu,
öneriler ve `vis-network` ile çizilmiş bir saldırı grafiği görüntülenir.
API dokümantasyonu otomatik olarak `http://localhost:8000/docs`
adresinde oluşturulur (FastAPI'nin OpenAPI desteği sayesinde).

**Mimari not:** Bu fazda da (Faz 2'deki Scapy kısıtıyla aynı ruhta)
dürüst bir sınır var — bu sandbox'ta `pydantic`/`fastapi` kurulu değil,
internet kapalı. Bu yüzden mimari, ADR 0003'ün aynısını bir web
framework'üne uyguladı (bkz.
[ADR 0011](docs/adr/0011-dashboard-tech-stack.md)):
`PipelineOrchestrator` tamamen framework-bağımsız yazıldı ve **bu
sandbox'ta gerçekten test edildi** (5/5 test); FastAPI katmanı (`api/main.py`,
`api/schemas.py`) sadece ince bir HTTP dönüşüm katmanı ve sadece
sözdizimi doğrulanabildi. Dashboard'ın JavaScript'i de aynı prensiple
ikiye bölündü: DOM'a bağımlı olmayan saf fonksiyonlar (`buildGraphData`,
`riskColor`, vb.) Node.js altında **gerçekten test edildi** (20/20 test,
bkz. `tests/dashboard/test_app_pure_functions.js`); DOM/fetch kodu
sadece tarayıcıda çalışır ve bu ortamda görsel olarak doğrulanamadı.

### Deployment — Faz 10 (yol haritasının son fazı)

```bash
# Docker Compose ile:
docker compose up --build
# http://localhost:8000/dashboard/

# Veya doğrudan Docker ile:
docker build -t sentinelpath-ai .
docker run -p 8000:8000 sentinelpath-ai
```

CI/CD, GitHub Actions ile sağlanır (`.github/workflows/ci.yml`):
Python 3.11/3.12 matrisi, `ruff` lint, `mypy` tip kontrolü, tam `pytest`
paketi (tüm opsiyonel bağımlılıklarla — `api`, `network`, `ml`), Node.js
dashboard testleri, ve bir Docker build doğrulaması.

**Mimari not — projenin dürüstlük teması burada kapanıyor:** Bu
sandbox'ta internet erişimi kapalı olduğu için `scapy`, `pydantic`,
`fastapi` gibi bağımlılıklar hiç kurulamadı ve buna bağlı testler
(`test_pcap_adapter.py`, `test_weighted_markov_model.py`'nin `pytest`
kısmı, API katmanı) sadece sözdizimi seviyesinde doğrulanabildi. GitHub
Actions runner'larının **gerçek internet erişimi** vardır — CI, bu
projenin geliştirilmesi boyunca "bu ortamda test edemedim" diye
işaretlenen **her şeyi** nihayet gerçekten çalıştıracaktır. Detaylar
için bkz. [ADR 0012](docs/adr/0012-deployment-tech-stack.md).

Docker imajı çok-aşamalı (multi-stage) build kullanır — derleme araçları
(gcc vb.) yalnızca `builder` aşamasında kalır, final `runtime` imajı
bunları içermez (saldırı yüzeyini küçültmek, bir güvenlik aracı için
tematik olarak da tutarlı). Konteyner root olmayan bir kullanıcıyla
çalışır ve `GET /health` üzerinden bir `HEALTHCHECK` tanımlıdır.

**Dürüst sınır:** Bu sandbox'ta Docker daemon kurulu değil —
`docker build`/`docker compose up` bu ortamda çalıştırılarak
doğrulanamadı. Dockerfile ve docker-compose.yml sözdizimi/mantık olarak
gözden geçirildi (docker-compose.yml gerçek bir YAML parser ile
doğrulandı), ama gerçek bir build denemesi CI'da (veya kendi
ortamınızda) yapılmalıdır.

## Proje Yapisi

```
sentinelpath-ai/
├── ARCHITECTURE.md          ← mimari kararlar ve gerekceleri
├── docs/adr/                ← Architecture Decision Records
├── examples/                ← gercek pipeline ciktisindan uretilmis ornek raporlar
├── Dockerfile, docker-compose.yml, .dockerignore  ← Faz 10: konteynerlestirme
├── .github/workflows/ci.yml  ← Faz 10: GitHub Actions CI
├── src/sentinelpath/
│   ├── core/models.py       ← paylasilan domain veri sozlesmeleri
│   ├── config/settings.py   ← tip-guvenli konfigurasyon
│   ├── logging_setup.py     ← yapilandirilmis (JSON) loglama
│   ├── orchestration/        ← Faz 9: PipelineOrchestrator (framework-bagimsiz)
│   ├── api/                  ← Faz 9: FastAPI katmani (ince, orchestrator'i sarar)
│   ├── static/dashboard/      ← Faz 9: statik HTML/CSS/JS dashboard (PAKET ICINDE, bkz. ADR 0012)
│   └── <module>/
│       ├── domain/ports.py         ← soyut arayuz (Protocol)
│       ├── application/            ← use-case'ler
│       └── infrastructure/         ← somut implementasyonlar
└── tests/
    └── dashboard/            ← Faz 9: dashboard JS'in saf fonksiyonlari icin Node.js testleri
```

Her pipeline asamasi (`collector`, `feature_extraction`, `graph_builder`,
`baseline_behavior`, `attack_path_engine`, `prediction`, `risk_scoring`,
`recommendation`, `reporting`) ayni `domain/application/infrastructure`
desenini takip eder. Gerekce icin bkz. ARCHITECTURE.md, bolum 4.

## Faz Haritasi

| Faz | Icerik | Durum |
|---|---|---|
| 1 | Repository, Architecture, Documentation | ✅ Tamamlandi |
| 2 | Network Parser (Collector implementasyonu — pcap → NormalizedEvent) | ✅ Tamamlandi |
| 3 | Feature Extraction (NormalizedEvent → HostFeatureVector) | ✅ Tamamlandi |
| 4 | Graph Builder (NetworkX MultiDiGraph adapter) | ✅ Tamamlandi |
| 5 | Baseline Behaviour (NormalizedEvent gecmisi → BaselineProfile) | ✅ Tamamlandi |
| 6 | Attack Path Prediction (Attack Path Engine + Weighted Markov Model) | ✅ Tamamlandi |
| 7 | Risk Scoring (probability × criticality × severity + baseline context) | ✅ Tamamlandi |
| 8 | Reporting (Recommendation Engine + JSON/ATT&CK Navigator export) | ✅ Tamamlandi (MVP) |
| 9 | Dashboard (PipelineOrchestrator + FastAPI + statik HTML/JS) | ✅ Tamamlandi |
| 10 | Deployment (Docker + docker-compose + GitHub Actions CI) | ✅ Tamamlandi |

**Sistem promptunda tanımlanan 10 fazlık yol haritası tamamlanmıştır.**

Her faz sonunda bagimsiz calisabilen bir urun ortaya cikacak sekilde
ilerlenmektedir; bir sonraki faza gecmeden once bu README ve
ARCHITECTURE.md guncellenir.

## Ornek Cikti

> Faz 6-8 tamamlandiginda, ornek bir `PredictionResult` → `SentinelPathReport`
> ciktisi buraya eklenecektir.

## Gelecek Plani

- MITRE ATT&CK Navigator ile tam uyumlu layer export'u
- Sigma kural onerisi (tahmin edilen teknige karsi proaktif tespit kurali)
- Sysmon / Zeek gercek veri format destegi
- Statik model baseline'dan Graph Neural Network / Temporal Graph Network'e
  gecis (karsilastirmali degerlendirme ile, bkz. Faz 6)
- Topluluk katkili "attack path dataset" formati

## Katkida Bulunma

Bu proje acik kaynak bir arastirma platformu olarak tasarlanmistir.
Mimari kararlar hakkinda soru sormadan once ARCHITECTURE.md ve
`docs/adr/` klasorune bakmaniz onerilir — birçok "neden boyle?" sorusunun
cevabi zaten orada gerekceli olarak yazilidir.

## Lisans

MIT — bkz. [LICENSE](LICENSE).
