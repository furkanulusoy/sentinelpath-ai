# ADR 0017: Prediction Model'de Ham Ağırlık Baskınlığı — Kısmi Düzeltme, Tam Çözüm Tasarlandı

**Durum:** Kısmen uygulandı (bkz. "Karar" bölümü) — tam çözüm henüz kod
haline getirilmedi, sadece tasarlandı.
**Bağlam:** SentinelBench (bkz. `benchmark/` modülü, `LEAKAGE_PREVENTION.md`)
ile `WeightedMarkovPredictionModel`'i rastgele ve "en bağlantılı hedef"
baseline'larına karşı, gerçek `C17693` senaryosunda (redteam.txt'ten
doğrulanmış saldırgan, 24 saatlik gerçek LANL penceresi) test ederken
bulundu.

## Bulgu — gerçek sayılarla kanıtlanmış bir zayıflık

İlk çalıştırmada, `weighted_markov_v1` modeli **her iki basit
baseline'dan da kötü** çıktı (MRR `0.005`, `random_baseline_v1`'in
`0.029`'unun altında). Kök sebep araştırıldı:

- 10 gerçek redteam hedefinin **tamamı**, modelin sıralamasında
  343 adayın **en altına** (`247`-`257`. sıra) düşmüştü.
- Bu 10 hedefin tamamı `authenticates_to` ilişkisiyle, ağırlık
  neredeyse hep `1.0` (nadir, tek seferlik gerçek kimlik doğrulama
  olayları).
- En üstteki adaylar `observed_lateral_movement` ilişkisiyle, ağırlık
  `496`, `354`, `67` gibi (yüksek hacimli, muhtemelen meşru/rutin
  trafik).
- Kök sebep koddan doğrulandı: `Graph Builder`'da `weight = float(count)`
  (ham gözlemlenen event sayısı), `Prediction Model`'de bu değer
  **doğrudan** çarpana giriyor (`score *= weight * prior`) — hiçbir
  üst sınır yok.

Bu, dıştan gelen bir uzman incelemesinin (bu konuşmada daha önce
paylaşılan, "connection frequency != attack probability" uyarısı)
**gerçek veriyle, somut sayılarla doğrulanmış** hali.

## Karar 1 — Uygulandı: `log1p` ile ağırlık sıkıştırma

`WeightedMarkovPredictionModel.predict()`'te, ham ağırlık kullanılmadan
önce `math.log1p(weight)` ile sıkıştırılır. Bu, sıralamayı KORUR (daha
fazla gözlem hâlâ daha güçlü kanıttır) ama açık uçlu büyümeyi sınırlar.

**Ölçülen etki:** `authenticates_to` (weight=1) ile `observed_lateral_movement`
(weight=496) arasındaki oran, `744` kattan `~13` kata düştü.

**Test sonucu:** Mevcut 159 test hâlâ geçiyor (hiçbiri tam sayı ağırlık
varsayımına dayanmıyormuş).

**DÜRÜST SONUÇ — bu YETERSIZ kaldı:** Aynı gerçek senaryoda tekrar
çalıştırıldığında, 10 gerçek hedefin sıralaması **hiç değişmedi**
(hâlâ `247`-`257`. sırada). Teşhis: üst sıralardaki 246 adayın
**%64.6'sı** `observed_lateral_movement` tipi — sorun tek bir aşırı
değer değil, **sistematik bir kategori üstünlüğü.** `log1p` bunu
çözemez, çünkü orta-düzey `lateral_movement` kanıtları bile (örn.
weight=38), sıkıştırılmış haliyle bile tek bir `authenticates_to`
kanıtını hâlâ ~8 kat geçiyor.

## Bilinçli olarak REDDEDİLEN bir "kolay" çözüm

`RELATION_PRIORS` tablosundaki `AUTHENTICATES_TO`/`OBSERVED_LATERAL_MOVEMENT`
değerlerini, bu **belirli** senaryonun sonucunu iyileştirecek şekilde
elle ayarlamak düşünüldü ve **reddedildi.** Bu, `LEAKAGE_PREVENTION.md`
Kategori 2'nin (parametre-ayarlama sızıntısı) birebir tanımına girerdi
— tek bir gözlemlenen sonuca göre bir sabiti ayarlamak, o sonuca göre
"iyi görünmek" olur, genellenebilir bir düzeltme değil.

## Karar 2 — Tasarlandı, henüz UYGULANMADI: yerel Markov normalizasyonu

Modülün kendi orijinal docstring'i ("İKİNCİ DÜRÜSTLÜK NOTU") bunu zaten
öngörmüştü: doğru bir Markov zinciri, her hop için ham sayı yerine
**yerel geçiş olasılığı** kullanır — kaynak node'un o ilişki tipindeki
**TOPLAM** çıkış ağırlığına bölünerek normalize edilmiş bir oran.

Örnek: `C395`'e giden `496` bağlantıyı `1000`'lik bir `lateral_movement`
toplamına bölüp `%49.6` payına çevirmek; `C1003`'e giden `1` bağlantıyı
`10`'luk bir `authenticates_to` toplamına bölüp `%10` payına çevirmek
— artık ikisi de aynı ölçekte (0-1 oran), adil karşılaştırılabilir.

**Bunun gerektirdiği (henüz yapılmadı):**
- `CandidatePath`'e (bkz. `ADR 0008`), her hop için "kaynak node'un o
  ilişki tipindeki toplam çıkış ağırlığı" alanının eklenmesi.
- `Attack Path Engine`'in bu toplamı hesaplayıp `CandidatePath`'e
  yazması — mevcut, test edilmiş yol üretme mantığına dokunmadan,
  ek bir hesaplama katmanı olarak.
- `WeightedMarkovPredictionModel`'in bu yeni alanı kullanacak şekilde
  güncellenmesi.

## Sonuç

Kod tabanında şu an **kısmi bir iyileştirme** (log1p) var — gerçek,
ölçülmüş, testlerle doğrulanmış, ama **tek başına yetersiz.** Tam
çözüm (yerel normalizasyon) tasarlandı ama kod haline getirilmedi.
Bu ADR, ikisi arasındaki farkı gelecekteki geliştiriciler (ve gelecekteki
biz) için açıkça ayırmak için yazıldı.

## Bilinen Sınırlama

`C395` adayının, `weighted_markov_v1` çıktısında **birebir aynı olasılık
ve ağırlıkla iki kez** göründüğü gözlemlendi (mükerrer kayıt şüphesi).
Bu, ayrı bir soruşturma gerektiriyor, bu ADR kapsamında ele alınmadı.