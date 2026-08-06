# ADR 0007: GraphEdge'e mitre_technique_ids alani eklenmesi

**Durum:** Kabul edildi
**Tarih:** Faz 6
**Baglam:** `core/models.py` GraphEdge (Faz 1'de tanimlanmisti, Faz 4'te dolduruluyordu)

## Karar

```python
@dataclass(frozen=True)
class GraphEdge:
    source_node: str
    target_node: str
    relation: RelationType
    weight: float = 1.0
    mitre_technique_ids: tuple[str, ...] = field(default_factory=tuple)  # YENI
```

## Gerekce

Faz 4'te `_classify_relation()`, bir event'in `mitre_technique_id` alanina
BAKARAK `RelationType.OBSERVED_LATERAL_MOVEMENT` gibi bir KATEGORI
secıyordu -- ama bu kategoriye karar verdikten sonra, event'in tasidigi
SPESIFIK teknik ID'sini (orn. "T1021.001") edge'e YAZMIYORDU. Sonuc:
`AttackGraphSnapshot`'a bakarak "bu iki host arasinda lateral movement
var" diyebiliyorduk ama "hangi teknikle" diyemiyorduk.

Faz 6'da Attack Path Engine, `CandidatePath.plausible_techniques`
alanini doldurmak zorunda (bu alan Faz 1'de zaten tanimliydi). Bu bilgi
olmadan bu alan hep bos kalirdi -- ki bu, MITRE ATT&CK'e dogrudan
baglanma hedefini (projenin ana degeri) bosa cikarirdi.

## Sonuclar

- **Olumlu:** Artik bir edge'e bakarak "bu baglanti hangi spesifik
  MITRE teknikleriyle gozlemlendi" sorusu cevaplanabiliyor. Birden
  fazla farkli teknik ayni host cifti icin gozlemlenmisse (orn. bir
  gun RDP, baska gun SSH), HEPSI korunur (tuple).
- **Olumsuz:** `NetworkXGraphBuilder.build()` artik edge sayaclarina EK
  olarak teknik ID kumelerini de takip etmek zorunda (Counter yaninda
  bir de dict[key, set[str]]).
- **Geriye uyumluluk:** `mitre_technique_ids` varsayilan degeri bos
  tuple'dir -- Faz 4'te yazilmis mevcut testler/kod, bu alani hic
  bilmeden calismaya devam eder (yeni alan opsiyonel).
