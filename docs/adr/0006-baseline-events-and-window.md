# ADR 0006: BaselineBehaviorPort.recompute() imzasinin AttackGraphSnapshot yerine ham event+pencere almasi

**Durum:** Kabul edildi
**Tarih:** Faz 5
**Baglam:** `baseline_behavior/domain/ports.py` (Faz 1'de tanimlanmisti)

## Karar

```python
# Faz 1 (eski):
def recompute(self, graph: AttackGraphSnapshot) -> list[BaselineProfile]: ...

# Faz 5 (yeni):
def recompute(
    self, events: list[NormalizedEvent], window_start: datetime, window_end: datetime
) -> list[BaselineProfile]: ...
```

## Gerekce

Bu, projede UCUNCU kez karsimiza cikan ayni desen (bkz. ADR 0004, ADR
0005): Faz 1'de spekulatif tasarlanan bir port, implementasyonla
sinandiginda eksik cikiyor.

Bu sefer sorun IKI KATMANLI:

1. **`typical_active_hours` icin saat-duzeyinde veri gerekir.**
   `AttackGraphSnapshot`'taki `GraphEdge` HICBIR zaman damgasi tasimaz --
   sadece (source, target, relation, weight). Bir host'un "genelde
   08:00-18:00 arasi aktif oldugu" bilgisini turetmek icin, o host'a
   ait TUM event'lerin saat bilgisine erismek gerekir.

2. **"Tipik" (typical) kelimesi COKLU GUN boyunca tekrar anlamina gelir.**
   Tek bir `AttackGraphSnapshot`, TEK bir agregasyon penceresini temsil
   eder (bkz. Faz 4). Bir host'un bir peer'e "her gun" mu yoksa "sadece
   bir kez" mi baglandigini ayirt etmek icin, GUN SINIRLARINI koruyan
   bir veri kaynagina ihtiyac var -- bu da yalnizca ham
   `NormalizedEvent.timestamp` uzerinden mumkun.

Ayni zamanda, Faz 3'teki ADR 0004 ile TUTARLILIK icin (window_days gibi
bir tam sayi yerine) acik `window_start`/`window_end` kullanildi --
guven (confidence) hesaplamasi icin "istenen pencere ne kadar gundu"
sorusunun cevabi, event listesinden turetilmek yerine acikca verilir.

## Sonuclar

- **Olumlu:** Baseline Behavior artik Feature Extraction ile AYNI ham
  veri kaynagina (NormalizedEvent + acik pencere) erisiyor -- pipeline
  genelinde tutarli bir "ham veri erisimi" deseni olustu.
- **Olumsuz:** `recompute()` artik potansiyel olarak COK BUYUK bir event
  listesi alabilir (14 gunluk tum ham event'ler, tek bir gunluk
  penceresi degil). Bu, ADR 0001'de bahsedilen "veri hacmi buyudukce"
  senaryosunun ilk somut ornegidir -- Faz 5 implementasyonu bunu
  stdlib ile (Counter, set) cozuyor, ama bu, ileride buyuk ortamlarda
  performans acisindan yeniden degerlendirilebilecek bir noktadir.

## Deseni Genelleme

Uc ADR'de (0004, 0005, 0006) tekrarlanan ayni ders: **agregatlanmis
tipler (HostFeatureVector, AttackGraphSnapshot), bir sonraki asamanin
ihtiyaci olan GRANULERLIGI kaybeder.** Bundan sonraki her yeni port
tasarlanirken, "bu port'un ihtiyaci olan bilgi, girdi tipinde gercekten
MEVCUT MU, yoksa bir onceki asamanin agregasyonunda mi kayboldu?"
sorusu ACIKCA sorulmalidir.
