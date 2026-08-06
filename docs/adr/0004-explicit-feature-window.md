# ADR 0004: FeatureExtractorPort.extract() imzasina acik zaman penceresi eklenmesi

**Durum:** Kabul edildi
**Tarih:** Faz 3
**Baglam:** `feature_extraction/domain/ports.py` (Faz 1'de tanimlanmisti)

## Karar

`FeatureExtractorPort.extract()` imzasi:

```python
# Faz 1 (eski):
def extract(self, host_id: str, events: list[NormalizedEvent]) -> HostFeatureVector: ...

# Faz 3 (yeni):
def extract(
    self, host_id: str, events: list[NormalizedEvent],
    window_start: datetime, window_end: datetime,
) -> HostFeatureVector: ...
```

## Gerekce

Faz 1'de bu port spekulatif olarak tasarlanmisti -- henuz gercek bir
implementasyona karsi sinanmamisti. Faz 3'te implementasyonu yazarken
somut bir sorun ortaya cikti: `HostFeatureVector.window_start/window_end`
alanlari zorunlu (Optional degil), ama bu deger event zaman
damgalarindan turetilirse, **hic event'i olmayan bir host icin pencere
tanimsiz kalir.**

Bu onemsiz bir edge-case degildir: "bu host'ta bu pencerede hicbir
aktivite gozlenmedi" tam olarak Baseline Behavior Engine'in (Faz 5)
ilgilenecegi turden bir sinyaldir (orn. bir host beklenenden AZ aktif
ise bu da anomali olabilir -- "dormant sonra aniden aktif olma" klasik
bir saldiri paterni).

Pencereyi disaridan (cagiran use-case katmanindan) acikca almak, bu
belirsizligi ortadan kaldirir: "hangi zaman araligini soruyorsun?"
sorusunun cevabi artik event verisine bagli degildir.

## Sonuclar

- **Olumlu:** Sifir-event durumu artik dogal olarak ele alinir (bkz.
  `RuleBasedFeatureExtractor`, bos event listesi icin sifir/notr degerler
  doner, hata firlatmaz).
- **Olumsuz:** Port'u kullanan her cagrida (use-case katmani, Faz 5+)
  pencereyi ACIKCA belirtmek gerekir -- bu, cagiran kodun "hangi
  pencereyi soruyorum?" kararini bilerek vermesini zorunlu kilar (bu
  aslinda istenen bir zorlama, "gizli varsayimlarla calismayin" ilkesi).

## Ogrenilen Ders

Bu, Ports & Adapters mimarisinin dogal bir parcasidir: port'lar ilk
tasarimda MUKEMMEL olmak zorunda degildir; gercek implementasyonla
sinandiginda kucuk revizyonlar gerekebilir. Onemli olan, bu revizyonun
GEREKCELI ve KAYITLI (bu ADR) yapilmasidir -- sessizce degistirilmesi
degil.
