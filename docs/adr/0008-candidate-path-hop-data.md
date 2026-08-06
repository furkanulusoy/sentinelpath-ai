# ADR 0008: CandidatePath'e hop_relations ve hop_weights alanlari eklenmesi

**Durum:** Kabul edildi
**Tarih:** Faz 6
**Baglam:** `core/models.py` CandidatePath (Faz 1'de tanimlanmisti)

## Karar

```python
@dataclass(frozen=True)
class CandidatePath:
    path_nodes: tuple[str, ...]
    plausible_techniques: tuple[str, ...]
    structural_reason: str
    hop_relations: tuple[RelationType, ...] = field(default_factory=tuple)  # YENI
    hop_weights: tuple[float, ...] = field(default_factory=tuple)            # YENI
```

Bir N-node'luk yol icin bu iki tuple N-1 uzunlugundadir -- her hop
(node[i] -> node[i+1]) icin bir deger.

## Guncelleme (implementasyon sirasinda, ayni ADR icinde)

Implementasyon sirasinda UCUNCU bir alana ihtiyac oldugu ortaya cikti:
`hop_technique_ids: tuple[tuple[str, ...], ...]` -- her hop icin ayri
ayri gozlemlenen teknik ID kumesi. Gerekce: `plausible_techniques`
TUM hop'lardaki tekniklerin BIRLESIMIDIR (path-genelinde "hangi
teknikler bu yolda gorulmus" sorusuna cevap verir), ama Prediction
Model'in (ADR 0009) "SONRAKI adim hangi teknikle olur" sorusunu
cevaplayabilmesi icin SADECE SON HOP'un tekniklerine ihtiyaci var.
Bu ayrim olmadan, coklu-hop'lu bir yolda ILK hop'un teknigi yanlislikla
"sonraki adim tahmini" olarak sunulabilirdi.

```python
@dataclass(frozen=True)
class CandidatePath:
    path_nodes: tuple[str, ...]
    plausible_techniques: tuple[str, ...]
    structural_reason: str
    hop_relations: tuple[RelationType, ...] = field(default_factory=tuple)
    hop_weights: tuple[float, ...] = field(default_factory=tuple)
    hop_technique_ids: tuple[tuple[str, ...], ...] = field(default_factory=tuple)  # YENI
```

## Gerekce

ADR 0002'de Attack Path Engine (deterministik) ile Prediction Model
(olasiliksal) BILINCLI olarak ayrildi: Prediction Model, Attack Path
Engine'in urettigi adaylari SIRALAR ama YENI bir yol UYDURAMAZ.

Ancak "siralamak" icin bile SAYISAL veriye ihtiyac var. Faz 1'deki
`CandidatePath.structural_reason: str` yalnizca insan-okunur bir metin
("network_reachable" gibi) -- Prediction Model bunun uzerinde GUVENILIR
sekilde hesap YAPAMAZ (string parse etmek kirilgan olurdu, ADR 0003'teki
"framework/format ayrimi" prensibiyle de celisirdi).

Prediction Model'in agirlikli Markov hesaplamasi (bkz. ADR 0009) icin
her hop'un GERCEK edge agirligina (weight) ve iliski tipine (relation)
YAPILANDIRILMIS erisimi olmasi gerekiyor.

## Neden GraphSnapshot'i tekrar predict()'e vermek yerine bu yol secildi?

Alternatif: `PredictionModelPort.predict()` imzasina `graph:
AttackGraphSnapshot` parametresi de eklemek, Prediction Model kendi
edge'leri kendi arasin.

Bunu REDDETTIM: Bu, Prediction Model'e TUM grafa erisim verir --
ADR 0002'nin "Prediction Model sadece verilen adaylari degerlendirir"
sinirini bulaniklastirir (teorik olarak grafi kullanip candidate_paths
disinda yeni bir yol "kesfedebilir", ki bu tam olarak onlemeye
calistigimiz seydir). CandidatePath'i zenginlestirmek, bu sinirin KOD
SEVIYESINDE korunmasini saglar -- Prediction Model'e SADECE ihtiyaci
olan veri (bu path'in hop'lari) verilir, grafin tamamina degil.

## Sonuclar

- **Olumlu:** Prediction Model, `candidate_paths` disinda hicbir ek
  veri kaynagina ihtiyac duymadan olasilik hesaplayabiliyor. ADR
  0002'nin sinir kontrolu kod seviyesinde korunuyor.
- **Olumsuz:** Attack Path Engine, coklu paralel edge (MultiDiGraph)
  arasindan HANGI birini "baskin" (dominant) sayacagina karar vermek
  zorunda (bkz. RELATION_PRIORITY siralamasi, networkx_engine.py) --
  bu, Faz 4'teki "her iliski tipini ayri edge olarak tut" kararindan
  (ADR icermeyen ama Faz 4 modul docstring'inde gerekcelendirilen karar)
  bir adim geri gibi gorunebilir, ama kayip degil: hala TUM iliski
  tipleri `snapshot.edges` uzerinden erisilebilir durumda, sadece
  CandidatePath'in kendisi TEK bir "en saldiri-iliskili" secimi tasiyor.
