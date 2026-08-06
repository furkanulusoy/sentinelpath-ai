# ADR 0005: GraphBuilderPort.build() imzasina `events` parametresi eklenmesi

**Durum:** Kabul edildi
**Tarih:** Faz 4
**Baglam:** `graph_builder/domain/ports.py` (Faz 1'de tanimlanmisti)

## Karar

```python
# Faz 1 (eski):
def build(self, feature_vectors: list[HostFeatureVector]) -> AttackGraphSnapshot: ...

# Faz 4 (yeni):
def build(
    self, events: list[NormalizedEvent], feature_vectors: list[HostFeatureVector]
) -> AttackGraphSnapshot: ...
```

## Gerekce

`HostFeatureVector`, bir host'un davranisinin **aggregate edilmis** ozetidir
(Faz 3'un bilincli tasarim karari). `distinct_target_hosts_count: int` alani
KAC farkli hosta baglanildigini soyler ama HANGI hostlara baglandigini
SOYLEMEZ -- bu bilgi, Faz 3'te feature cikarimi sirasinda ozetlenirken
kaybedilir (ki bu, o fazda dogru bir karardi: bir feature vektoru zaten
"ozet" olmasi gerektigi icin).

Bir graf edge'i (`GraphEdge(source_node, target_node, ...)`) kurmak icin
CIFT-YONLU KIMLIK bilgisi gerekir -- bu bilgi yalnizca ham
`NormalizedEvent.source_host`/`target_host` ciftinde vardir. Bu yuzden
Graph Builder'in feature_vectors'a EK olarak ham event listesine de
erisimi olmalidir.

## Sonuclar

- **Olumlu:** Edge'ler artik gercek gozlemlenmis baglantilardan
  kuruluyor; node'lar ise feature_vectors'tan geliyor (hic disa
  baglantisi olmayan bir host bile graf'ta bir node olarak durur --
  bu, Attack Path Engine'in "bu host'a ulasilabilir mi" sorusunu
  sorabilmesi icin gereklidir).
- **Olumsuz:** Graph Builder artik iki farkli veri kaynagina bagimli;
  cagiran use-case katmani (Faz 5+) ikisini de dogru zamanlamayla
  saglamalidir (ayni pencereye ait event'ler ve feature vektorleri).

## Ogrenilen Ders (Faz 3 ADR 0004 ile ayni desen)

Bu, projede ikinci kez karsimiza cikan bir durum: Faz 1'de spekulatif
tasarlanan bir port, gercek implementasyonla sinandiginda eksik cikiyor.
Bu BEKLENEN bir durumdur (bkz. ADR 0004, "Ogrenilen Ders" bolumu) --
onemli olan degisikligin gerekceli ve kayitli yapilmasidir.
