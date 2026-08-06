# ADR 0009: MVP Prediction Model secimi -- Agirlikli Markov gecis modeli

**Durum:** Kabul edildi
**Tarih:** Faz 6
**Baglam:** `prediction/domain/ports.py` (Faz 1), model karsilastirmasi (bkz. sistem prompt "YAPAY ZEKA" bolumu)

## Karar

MVP Prediction Model implementasyonu olarak, gozlemlenen graf edge
agirliklarini (GraphEdge.weight, ADR 0007 sonrasi + mitre_technique_ids)
ve iliski-tipi onceliklerini kullanan, EGITIM VERISI GEREKTIRMEYEN bir
agirlikli Markov gecis modeli (`WeightedMarkovPredictionModel`) secildi.
Isolation Forest, Random Forest, XGBoost, GNN, Temporal GNN, LSTM ve
Transformer DEGERLENDIRILDI ve MVP icin REDDEDILDI.

## Gerekce (karsilastirma tablosu icin bkz. Faz 6 sohbet gecmisi / README)

Tum reddedilen alternatiflerin ORTAK sorunu: hepsi (Isolation Forest
haric, ki o da amac uyusmazligi nedeniyle elendi) ETIKETLI GECMIS
SALDIRI VERISI gerektirir -- "bu kismi zincirden sonra GERCEKTEN hangi
teknik kullanildi" turunden dogrulanmis ornekler. Bu proje YENI
kuruldugu icin boyle bir veri seti YOK.

Agirlikli Markov modeli bu sorunu asar cunku: GraphEdge.weight zaten
AMPIRIK BIR GOZLEM SIKLIGI TAHMINIDIR (Faz 4'te, her (source, target,
relation) uclusunun kac kez gozlemlendigini sayarak olusturduk). Bunu
bir olasilik tahmini olarak kullanmak, istatistikte standart bir
yontemdir (frequency-based Markov chain) ve HICBIR ek etiketli veri
gerektirmez.

## Neden bu bir "kolay yol" degil, savunulabilir bir muhendislik karari

- **Acikanabilirlik:** Her tahminin dayanagi tek cumlede ozetlenebilir:
  "bu yol X kez gozlemlendi, iliski tipi Y, bu yuzden Z olasilikla
  tahmin edildi." ADR 0002'nin acikanabilirlik hedefiyle birebir uyumlu.
- **Hesaplama maliyeti:** O(aday sayisi) -- ihmal edilebilir. GPU,
  egitim suresi, hyperparameter tuning YOK.
- **Soguk baslangic (cold start) standardi:** Oneri sistemleri
  literaturunde de (collaborative filtering, vb.) yeni sistemlerde
  "yeterli veri birikene kadar frekans-tabanli bir baseline kullan,
  sonra ML modeline gec" standart bir kaliptir. Bu proje de ayni
  kaliba uyuyor.

## Ne zaman yeniden degerlendirilir (Faz 1 vizyonundaki "gelecek plani" ile tutarli)

1. **Etiketli geri bildirim biriktiginde:** Faz 7+ sonrasi bir SOC
   analisti arayuzu ("bu tahmin dogruydu/yanlisti" butonu) eklenip
   yeterli ornek (onerilen: en az birkac yuz dogrulanmis ornek)
   toplandiginda, Random Forest/XGBoost GERCEKCI bir yukseltme olur.
2. **Graf olcegi buyudugunde:** Yuzlerce/binlerce node'a ulasildiginda,
   GNN'in node-embedding gucu anlamli hale gelebilir.
3. **Zaman serisi onemi arttiginda:** Saldiri paternlerinin zamana gore
   nasil evrildigi (orn. "bu teknik son 6 ayda daha sik kullaniliyor")
   onemli hale gelirse, Temporal GNN degerlendirilebilir.

Bu ADR, bu tetikleyicilerden biri gerceklestiginde GUNCELLENMELI, model
degisikligi ayri bir ADR olarak kayit altina alinmalidir -- port
sozlesmesi (`PredictionModelPort`) sayesinde bu degisiklik
`WeightedMarkovPredictionModel`'i baska bir adapterle DEGISTIRMEK
kadar basit olacaktir, use-case katmani etkilenmeyecektir.
