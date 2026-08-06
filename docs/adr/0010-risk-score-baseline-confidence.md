# ADR 0010: RiskScore'a baseline_confidence eklenmesi (ana formule DEGIL, ayri baglam olarak)

**Durum:** Kabul edildi
**Tarih:** Faz 7
**Baglam:** `core/models.py` RiskScore (Faz 1), `risk_scoring/domain/ports.py` (Faz 1)

## Karar

```python
@dataclass(frozen=True)
class RiskScore:
    target_node: str
    technique_id: str
    probability: float
    asset_criticality: float
    technique_severity: float
    score: float
    baseline_confidence: float | None = field(default=None)  # YENI
```

```python
# Faz 1 (eski):
def score(self, prediction: PredictionResult) -> list[RiskScore]: ...

# Faz 7 (yeni):
def score(
    self, prediction: PredictionResult, baseline_profiles: list[BaselineProfile] | None = None
) -> list[RiskScore]: ...
```

## Gerekce

Faz 6'nin demo ciktisinda acikca soylenmis bir taahhut vardi: "risk
skoru = olasilik x guven x kritiklik". Ama Faz 1'in RiskScore modelinde
guven (confidence) icin hic alan yoktu.

**Neden ana formule CARPAN olarak eklenmedi:** Faz 6'da BaselineProfile
ile ilgili benzer bir tartisma yapilmisti (bkz. Faz 6 implementasyon
notlari) -- dusuk confidence'in skoru YUKSELTMESI mi (cunku ne
olacagini bilmiyoruz, temkinli olmali) yoksa DUSURMESI mi (cunku
iddiamizin kendisi guvenilir degil) gerektigi, TEK bir "doğru" cevabi
olmayan bir tasarim sorusudur -- gercek etiketli geri bildirim
olmadan bu isareti secmek keyfi olurdu.

Bu yuzden confidence'i formulun DISINDA, ayri bir baglam alani olarak
tasiyoruz. Faz 8 (Reporting), bir SOC analistine "skor %75, AMA bu
host icin baseline verimiz sadece 1 gunluk (guven %7)" gibi ikisini
YAN YANA gosterebilir -- nihai yorumu insana birakmak, yanlis bir
carpan secmekten daha guvenli bir MVP karari.

## Sonuclar

- **Olumlu:** Risk skorunun HESAPLANMASI degismedi (geriye donuk
  uyumlu formul); confidence EK bilgi olarak sunuluyor.
- **Olumsuz:** `score()` artik opsiyonel bir `baseline_profiles`
  parametresi aliyor -- cagiran taraf bunu saglamazsa
  `baseline_confidence` alani `None` kalir (bilgi eksikligi acikca
  isaretlenir, sessizce 0.0 gibi yanlis-yorumlanabilir bir deger
  verilmez).
