# ADR 0016: Gercek Olcekte Bulunan Performans Sinirlari

**Durum:** Kabul edildi
**Baglam:** Faz B, LANL verisiyle ilk tam uctan uca (Collector ->
Dashboard) calistirma sirasinda bulundu.

## Bulgu 1 -- Bellek tasmasi (30 gunluk pencere denemesi)

ADR 0015'teki "tek pencere" tasarimi, tam 30 gunluk hedef pencereyle
denendiginde, `auth.txt`'in sadece %1.6'sinda (18 milyon satir) bellek
kullaniminin %98'e ulastigi gozlemlendi.

**Teshis:** `collect()` metodu, TUM event'leri tek bir Python listesinde
biriktiriyor -- bu, milyonlarca nesneye olcekte bellek acisindan
surdurulemez.

**Karar:** Degerlendirme penceresi 24 saate kucultuldu. Akis/generator
tabanli bir mimariye gecis, "Bilinen Sinirlama" olarak asagida kayit
altina alindi.

## Bulgu 2 -- Attack Path Engine, yogun gercek graf'larda kombinatoryal patlama

C17693 icin tam pipeline (24 saatlik pencere, ~10 milyon event)
calistirildiginda, cikti 600MB'a (`2.292.558` risk skoru) ulasti.

**Teshis:** `nx.all_simple_paths(max_hops=4)`, sadece kucuk sentetik
graf'larda (5-10 node) test edilmisti. Gercek, yogun bir graf'ta
(binlerce node, on binlerce kenar) yol sayisi sicramaya gore USTEL
buyudu.

**Karar:** `max_hops=2` ile calistirildi, sonuc `257` risk skoruna
(69KB) dustu -- ayni pipeline'dan, sadece parametre degisikligiyle.
Attack Path Engine'in kendi kodu DEGISTIRILMEDI -- sadece cagiran
taraf, gercek/yogun aglar icin uygun bir konfigurasyon degeri secmelidir.

**Bilinen Sinirlama:** Cok daha yogun aglarda `max_hops=2` bile buyuk
kalabilir. Kalici bir cozum (orn. Attack Path Engine'e "en fazla N
aday yol" limiti eklemek) gelecek planina alindi.

## Bulgu 3 -- Dashboard grafik render'i, fizik-tabanli duzende tikaniyor

257 sonuclu gercek rapor dashboard'da acildiginda, grafigin gozle
gorulur sekilde yavasladigi/tikandigi gozlemlendi.

**Teshis:** `vis-network`'un fizik simulasyonu (`physics: true`)
node ciftlerini karsilastirarak yerlesim hesaplar -- O(n^2)
karmasiklik. 5 node'luk sentetik demoda sorunsuzdu, 257 node'da
tarayiciyi kilitledi.

**Karar:** Duzen, fizik simulasyonundan HIYERARSIK (deterministik,
soldan-saga yonlu) bir duzene cevrildi -- grafimizin zaten sahip
oldugu "merkez + yayilan hedefler" sekline dogal olarak uyuyor, node
sayisindan bagimsiz hizli calisir. Gorsel netlik icin (performans
zorunlulugu DEGIL) en yuksek skorlu ilk 15 sonuc goruntuleniyor --
risk tablosunun kendisi hala TUM sonuclari listeler.

## Ilk basarili uctan uca gercek veri calistirmasi

Yukaridaki uc duzeltmeden sonra, PipelineOrchestrator gercek LANL
verisiyle (C17693 baslangic noktasi) basariyla calistirildi ve
dashboard'da gorsellestirildi. En yuksek risk: C395 hedefi, T1021.002
(SMB) ve T1021.003 (DCOM) teknikleriyle, %25 goreli olasilikla. Dort
farkli MITRE mitigasyonu (M1030, M1042, M1032, ve bir "bilinen
mitigasyon yok" durustlugu) uretildi.

**Onemli not:** `baseline_guven=1.0` degerleri, TEK bir 24 saatlik
pencerenin tamaminin gozlemlenmis olmasindan kaynaklanir -- bu,
endustri-standardi 2-4 haftalik kalibrasyon donemiyle KARISTIRILMAMALI
(bkz. ADR 0015 "Tek Pencere Karari"). Sonuc gercek ve degerlidir, ama
kisa pencereli bir dogrulamadir.

## Bilinen Sinirlama

`collect()`'in bellek mimarisi (Bulgu 1), tam 30 gunluk/749 olaylik
degerlendirme icin akis/generator tabanli bir yeniden tasarim
gerektiriyor -- bu, README'nin Gelecek Plani'na eklenmelidir.