# SentinelPath AI — Mimari Dokumantasyonu

> Bu dosya her fazin sonunda guncellenir. Amac, projeye sonradan katilan
> birinin (veya gelecekteki sizin) "neden boyle yapilmis?" sorusuna kod
> okumadan cevap bulabilmesidir.

## 1. Tasarim Felsefesi

SentinelPath AI, **Hexagonal Architecture (Ports & Adapters)** ile
**pipeline veri akisini** birlestiren bir hibrit mimari kullanir:

- Disaridan bakildiginda sistem bir **pipeline** gibi calisir: veri
  Collector'dan Reporting'e dogru sirali asamalardan gecer.
- Icerden bakildiginda her asama, somut implementasyonuna degil, soyut bir
  **port** (Python `typing.Protocol`) arayuzune bagimlidir.

### Neden bu hibrit, neden saf pipeline degil?

Sıradan bir script dizisi (`collector.py` → `graph.py` → `predict.py`,
hepsi birbirine sıkı bagimli) hizli bir MVP verir ama iki yerde tikanir:

1. Faz 6'da Random Forest'tan GNN'e gecerken tum pipeline'i bozarsiniz.
2. Unit test yazmak neredeyse imkansiz hale gelir, cunku her modul bir
   oncekinin somut ciktisina bagimlidir.

Ports & Adapters bu iki sorunu da yapisal olarak cozer: bir katmanin
implementasyonu degistiginde, onu KULLANAN katmanlar hicbir degisiklige
ugramaz (sadece port sozlesmesi karsilaniyor olmali).

## 2. Ust Seviye Veri Akisi

```
┌──────────────┐
│ Data Sources │  (topology.json, sysmon-like events, auth logs, historical paths)
└──────┬───────┘
       │
       ▼
┌──────────────┐     Sorumluluk: I/O + normalizasyon
│  Collector   │     "Ham veriyi standart ic formata cevir"
└──────┬───────┘
       │  NormalizedEvent[]
       ▼
┌────────────────────┐  Sorumluluk: domain sinyali cikarma
│ Feature Extractor   │  "Bu event'ler neyi ifade ediyor?"
└──────┬───────────────┘  (frekans, MITRE tag, off-hours orani...)
       │  HostFeatureVector
       ▼
┌──────────────┐     Sorumluluk: yapisal iliski modeli
│ Graph Builder │     Host/User node'lari + tipli edge'ler (NetworkX DiGraph)
└──────┬────────┘
       │  AttackGraphSnapshot
       │◄──────────────────────────────┐
       ▼                               │ (periyodik, async guncelleme)
┌────────────────────────┐             │
│ Baseline Behavior Eng.  │─────────────┘
└──────┬───────────────────┘  "Normal ne demek?" → node/edge confidence
       │  BaselineProfile
       ▼
┌─────────────────────┐  Sorumluluk: DETERMINISTIK graf akil yurutme
│ Attack Path Engine   │  "Graf yapisina gore yapisal olarak mumkun
└──────┬────────────────┘   sonraki adimlar hangileri?" (ML DEGIL)
       │  CandidatePath[]
       ▼
┌───────────────────┐   Sorumluluk: OLASILIKSAL tahmin
│ Prediction Model   │   "Bu adaylardan hangisi ne olasilikla gerceklesir?"
└──────┬───────────────┘  (Faz 6 — model secimi ADR'de gerekcelendirilecek)
       │  PredictionResult
       ▼
┌───────────────┐
│ Risk Scoring  │  probability × asset_criticality × technique_severity
└──────┬─────────┘
       │  RiskScore[]
       ▼
┌───────────────────────┐
│ Recommendation Engine │  technique → MITRE mitigation mapping (rule-based, MVP)
└──────┬──────────────────┘
       │  Recommendation[]
       ▼
┌──────────────┐
│  Reporting   │  JSON / ATT&CK Navigator layer / FastAPI response
└──────────────┘
```

### Iki farkli zaman dongusu

`Graph Builder ↔ Baseline Behavior Engine` arasindaki cift yonlu ok
kasitlidir. Sistemde iki ayri zaman dongusu vardir:

- **Senkron/istek-bagli:** Bir tahmin istendiginde Collector'dan
  Reporting'e kadar tek seferlik akis.
- **Asenkron/batch:** Baseline, yeni event'ler biriktikce periyodik olarak
  yeniden hesaplanmalidir — aksi halde "normal" tanimi donar ve zamanla
  anlamsizlasir (concept drift).

Bu ikisini ayni modulde karistirmak, "tahmin istegi neden 40 saniye
suruyor" gibi performans hatalarina yol acar. Bu ayrim Faz 5'te
(Baseline Behaviour) somutlasacaktir.

## 3. Katman Gerekceleri

### Collector vs Feature Extraction — neden ayri?

Ikisinin **degisme nedeni farklidir**: Collector, veri formati
degistiginde degisir (Sysmon yerine Zeek log okumaya gecince). Feature
Extraction, domain mantigi degistiginde degisir (yeni bir davranissal
sinyal eklendiginde). Single Responsibility Principle'in pratik testi:
"Bu dosyayi hangi sebeple degistiririm?" sorusuna birden fazla cevap
varsa, o dosya ikiye bolunmelidir.

### Graph Builder: NetworkX secimi

Bkz. [`docs/adr/0001-networkx-over-neo4j.md`](docs/adr/0001-networkx-over-neo4j.md).

### Attack Path Engine vs Prediction Model — projenin en onemli ayrimi

Bkz. [`docs/adr/0002-deterministic-vs-probabilistic-split.md`](docs/adr/0002-deterministic-vs-probabilistic-split.md).

### Risk Scoring vs Prediction Model — neden ayri?

Prediction Model'in ciktisi objektif bir istatistiktir (olasilik). Risk
Scoring ise **kurum-spesifik bir deger yargisi** icerir (bu host ne kadar
kritik?). Ayrilmazsa, modeli yeniden egitmeden risk formulunu
degistiremezsiniz.

## 4. Ic Mimari: Her Modulun Klasor Yapisi

```
<module_name>/
├── domain/
│   └── ports.py          ← soyut arayuz (Protocol)
├── application/
│   └── <use_case>.py     ← is akisi, SADECE port'u bilir
└── infrastructure/
    └── <adapter>.py      ← somut implementasyon(lar)
```

**Neden bu kadar katman?** Model/adapter secimi bir kere yapilip
bitmeyecek (orn. Prediction Model'de Faz 6'da coklu model
karsilastirmasi var). `application/` katmanindaki use-case kodu SADECE
`domain/ports.py`'deki Protocol'u bilir; hangi somut adapter'in calistigi
bir config/dependency-injection meselesidir. Bu ayni zamanda unit
testlerde sahte (fake/mock) adapter kullanmayi kolaylastirir.

## 5. Paylasilan Domain Modelleri

Tum katmanlar arasindaki veri sozlesmeleri `src/sentinelpath/core/models.py`
icinde tanimlidir. Bu dosya, pipeline'daki her asamanin girdi/ciktisini
tek bir yerden gorebilmenizi saglar — kod okumaya buradan baslamak
onerilir.

## 6. Teknoloji Secimleri Ozeti

| Katman | Teknoloji | Gerekce |
|---|---|---|
| Graph | NetworkX | ADR 0001 |
| Config | pydantic-settings | Tip-guvenli, "fail fast" |
| Logging | structlog (JSON) | SIEM entegrasyonuna hazir, izlenebilir |
| API (Faz 2+) | FastAPI | Async destegi, otomatik OpenAPI semasi |
| Test | pytest | Protocol tabanli mimariyle dogal uyum (fake adapter'lar kolay) |

## 7. Faz Haritasi

Bkz. [README.md](README.md#faz-haritasi).

## 8. Architecture Decision Records (ADR)

- [ADR 0001 — NetworkX vs Neo4j](docs/adr/0001-networkx-over-neo4j.md)
- [ADR 0002 — Deterministik/Olasiliksal Ayrim](docs/adr/0002-deterministic-vs-probabilistic-split.md)
- [ADR 0003 — Saf ceviri mantigi vs framework I/O ayrimi](docs/adr/0003-pure-translation-vs-framework-io-split.md)
- [ADR 0004 — FeatureExtractorPort'a acik zaman penceresi eklenmesi](docs/adr/0004-explicit-feature-window.md)
- [ADR 0005 — GraphBuilderPort.build()'a events parametresi eklenmesi](docs/adr/0005-graph-builder-events-parameter.md)
- [ADR 0006 — BaselineBehaviorPort.recompute()'un ham event+pencere almasi](docs/adr/0006-baseline-events-and-window.md)
- [ADR 0007 — GraphEdge'e mitre_technique_ids eklenmesi](docs/adr/0007-graph-edge-technique-ids.md)
- [ADR 0008 — CandidatePath'e hop-bazli yapilandirilmis veri eklenmesi](docs/adr/0008-candidate-path-hop-data.md)
- [ADR 0009 — MVP Prediction Model secimi (Agirlikli Markov)](docs/adr/0009-prediction-model-selection.md)
- [ADR 0010 — RiskScore'a baseline_confidence eklenmesi (ayri baglam olarak)](docs/adr/0010-risk-score-baseline-confidence.md)
- [ADR 0011 — Dashboard teknoloji secimi (FastAPI + statik HTML/JS)](docs/adr/0011-dashboard-tech-stack.md)
- [ADR 0012 — Deployment yigin secimleri (Docker, docker-compose, CI)](docs/adr/0012-deployment-tech-stack.md)

Yeni bir mimari karar alindiginda, bu listeye yeni bir ADR eklenmelidir.

## 9. Faz 2 Notu: Collector Implementasyon Deseni

`PcapFileCollector` ile baslayan desen, bundan sonraki her framework-bagimli
Collector adaptoru (orn. gelecekteki bir Sysmon/Zeek parser) icin referans
alinmalidir:

```
<adapter>.py          ← dis kutuphaneyi import eden TEK dosya (ince I/O)
<format>_record.py    ← framework-bagimsiz ara veri tipi
<format>_translation.py  ← saf fonksiyon: ara tip -> NormalizedEvent (test edilebilir)
```

Gerekce ve bu deseni ne zaman uygulayip ne zaman uygulamamak gerektigi
icin bkz. [ADR 0003](docs/adr/0003-pure-translation-vs-framework-io-split.md).
