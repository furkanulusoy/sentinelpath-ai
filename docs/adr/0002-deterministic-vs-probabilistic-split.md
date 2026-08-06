# ADR 0002: Attack Path Engine (deterministik) ile Prediction Model (olasiliksal) kesin ayrimi

**Durum:** Kabul edildi
**Tarih:** Faz 1
**Baglam:** Pipeline mimarisi (bkz. ARCHITECTURE.md, bolum 2)

## Karar

Saldiri yolu tahmini iki ayri, birbirinden bagimsiz katmana bolunecektir:

1. **Attack Path Engine** — Yalnizca graf teorisi (BFS/DFS, shortest path,
   reachability). Girdisi bir `AttackGraphSnapshot`, ciktisi yapisal olarak
   MUMKUN `CandidatePath` listesidir. Bu katman HICBIR olasilik/skor
   uretmez ve HICBIR ML/istatistik kutuphanesi import etmez.
2. **Prediction Model** — Attack Path Engine'in urettigi adaylar icinden
   "hangisi daha olasi?" sorusuna istatistiksel/ML cevabi verir. Bu katman
   YENI bir teknik/yol UYDURAMAZ; yalnizca verilen adaylari
   siralar/agirliklandirir.

## Gerekce

Bircok "AI destekli saldiri tahmini" projesi bu ikisini tek bir kara kutu
modelde birlestirir. Bunun bedeli **acikanabilirligin (explainability)
kaybi**dir: Bir SOC analisti "model neden bunu tahmin etti?" diye
sordugunda, kara kutu bir modelde cevap verilemez.

Bu ayrimla cevap iki parcaya bolunebilir:
  - "Yapisal olarak mumkun olanlar bunlardi" → Attack Path Engine ciktisi,
    tamamen izlenebilir (hangi graf yolu, hangi edge tipi).
  - "Bunlar arasindan model X'i secti, cunku Y" → Prediction Model ciktisi,
    sadece bir olasilik dagilimi, uydurma bir senaryo degil.

MITRE ATT&CK tabanli bir sistemde bu izlenebilirlik, projenin akademik ve
pratik degerinin buyuk kismini olusturur (bkz. proje on-analizi, madde 3:
"yenilikci taraf").

## Sonuclar

- **Olumlu:** Her tahminin denetlenebilir bir graf-temelli dayanagi vardir;
  Faz 6'da model degistirmek (Random Forest → GNN) Attack Path Engine'e
  DOKUNMAZ; unit testler iki katmani bagimsiz test edebilir (deterministik
  katman icin sabit girdi/cikti testleri, olasiliksal katman icin
  istatistiksel ozellik testleri).
- **Olumsuz:** Bu ayrim, Prediction Model'in "hicten" bir senaryo
  onerememesi anlamina gelir -- eger Attack Path Engine bir yolu graf
  yapisal olarak imkansiz buluyorsa (orn. network erisimi yok), Prediction
  Model o yolu ASLA on plana cikaramaz, boyle bir yol gozlemlenmis olsa
  bile (bu senaryo, graf'in guncel/eksiksiz olmadigi anlamina gelebilir --
  gercek sorun graf veri kalitesidir, model bunu "duzeltmemelidir").

## Kod Seviyesinde Zorlanmasi

`core.models.CandidatePath` tipinde bilerek bir `probability` alani YOKTUR.
Bu, katmanlar arasindaki sinirin sadece dokumantasyonla degil, TIP
SISTEMIYLE de zorlanmasini saglar -- bir gelistirici yanlislikla Attack
Path Engine'de olasilik hesaplamaya kalksa bile, donus tipi buna izin
vermez.
