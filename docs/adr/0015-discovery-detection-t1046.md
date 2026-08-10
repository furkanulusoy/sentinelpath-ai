# ADR 0015: T1046 (Network Service Discovery) Tespiti ve Sizinti-Onleme Metodolojisi

**Durum:** Kabul edildi
**Baglam:** Faz B (LANL veri seti ile nicel degerlendirme) sirasinda,
"redteam.txt'e hicbir sekilde sizinti olmayan, hata toleransi dusuk bir
tespit sistemi" hedefiyle tasarlandi.

## Sorun

MITRE ATT&CK'in Discovery taktigindeki T1046'yi (Network Service
Discovery), sadece flows/network verisinden, ground truth'a (redteam.txt)
HICBIR asamada bakmadan tespit etmemiz gerekiyordu -- ne etiketleme
asamasinda, ne parametre secerken.

## Karar 1 -- Modul siniri: "tespit yontemi", "MITRE ID" degil

`packet_translation.py` (port-tabanli, T1021 ailesinin tamami) ve yeni
`discovery_detection/` (istatistiksel esik-tabanli, T1046) BAGIMSIZ
modullerdir. Aralarinda ortak bir `TechniqueDetectorPort` arayuzu
BILEREK henuz tanimlanmadi (YAGNI -- sadece 2 ornekle soyutlama
cikarmak icin erken). Bkz. "Bilinen Sinirlama".

## Karar 2 -- Esik: disaridan sabit sayi degil, verinin kendi dagilimi

Zeek (100 port/60sn), Snort ve SOC pratiklerinden (5dk pencere, ~10 port
hedefli) sabit esikler arastirildi ve REDDEDILDI -- bunlar (a) farkli
bir fenomeni (tek host'a cok PORT) olcuyor, biz "tek host'tan cok HOST'a"
sorusunu soruyoruz; (b) internete acik, gurultulu aglar icin ayarlanmis,
LANL gibi kapali kurumsal bir ag baglaminda gecersiz varsayimlar.

Bunun yerine **Tukey IQR** (`Q3 + 1.5*(Q3-Q1)`) ile, HER HOST ICIN
KENDI gecmis dagilimindan turetilen bir esik kullanilir
(`BaselineProfile.typical_max_targets_per_window`,
`InMemoryBaselineBehavior` icinde 5 dakikalik kayan pencereyle
hesaplanir).

## Karar 3 -- Uc ayri sizinti turu, hepsi ayri ayri engellendi

1. **Etiketleme sizintisi:** auth.txt/flows.txt olaylarina teknik
   atarken redteam.txt'e bakilmaz.
2. **Parametre ayarlama sizintisi:** esik/agirlik formulundeki HICBIR
   sabit (Tukey katsayisi, pencere boyutu, dusuk-hacim esigi) "en iyi
   Top-K sonucunu veren" degere gore SECILMEZ -- sadece dissal,
   ilkeli gerekceyle (istatistik literaturu, mevcut tablo olcegi)
   belirlenir.
3. **Baseline kirlenmesi:** `typical_max_targets_per_window`,
   TUM 58 gunden degil, SADECE erken bir kalibrasyon penceresinden
   (endustri-standardi 2-4 hafta, bkz. UEBA arastirmasi) hesaplanir --
   `ADR 0006`'nin zaten sagladigi `window_start`/`window_end`
   parametreleri kullanilarak, yeni bir mekanizma icat edilmeden.

## Karar 4 -- Iki bagimsiz sinyal: fan-out + (varsa) dusuk hacim

Sadece "farkli hedef sayisi" tek basina yetersizdi -- yuksek hacimli
MESRU trafik (orn. bir yedekleme sunucusu) de dogal olarak coklu
host'a baglanir. `flows.txt` gibi hacim bilgisi (`byte_count`) tasiyan
kaynaklarda, DUSUK hacimli "yoklama" baglantilari aranarak bu ayrim
yapilir. Hacim bilgisi olmayan kaynaklarda (orn. mevcut pcap Collector),
sadece fan-out sinyaline guvenilir -- bu, acikca belgelenmis, daha
yuksek yanlis-pozitif riski tasiyan bir sinirlamadir.

## Karar 5 -- Episode-tabanli kenar uretimi

Kayan pencere her event'te yeniden hesaplandigi icin, esik bir kez
asilinca uzun sure asili kalabilir -- event-basi kenar uretmek,
ayni (host, hedef) cifti icin YUZLERCE tekrarlayan kenar demek olurdu.
Bunun yerine, esigin asili kaldigi surekli "bolum" (episode) tespit
edilip, bolum basina TEK BIR kenar seti (bolum boyunca gozlemlenen
en yuksek oran agirlikla) uretilir.

## Karar 6 -- Agirliklandirma: mevcut tablolarin kendi ic mantigina dayanarak

- `RELATION_PRIORS[OBSERVED_SCANNING] = 0.5`: mevcut olcegin
  (1.0-3.0) bir basamak altina, tablonun KENDI ic orantisina gore
  yerlestirildi -- "MITRE'de Discovery once gelir" gibi disaridan
  ödünc alinmis bir gerekceyle DEGIL.
- `TECHNIQUE_SEVERITY["T1046"] = 0.40`: ayni "Discovery = daha erken,
  daha zayif kanit" mantigi, iki ayri tabloda TUTARLI sekilde
  uygulandi.
- `TECHNIQUE_MITIGATIONS["T1046"] -> M1030`: MITRE'nin resmi
  attack.mitre.org sayfasindan DOGRULANDI (ezberden alinmadi) --
  T1021.002 icin zaten kullanilan mitigasyonla ayni oldugu tesadufi
  degil, MITRE'nin kendi resmi onerisi.

## Degerlendirme metodolojisi hakkinda durust bir not

LANL'daki redteam olaylari, toplam verinin ~%0.00007'si -- bu kadar
dengesiz bir dagilimda, "kac gercek saldiriyi yakaladik" (recall)
olcmek YETERLI DEGILDIR; "ne siklikla masum host'lari isaretledik"
(yaklasik precision) de ayri raporlanmalidir (bkz. Axelsson 2000,
"base-rate fallacy"). ANCAK: LANL sadece SALDIRI olaylarini
etiketliyor, "kesinlikle temiz" diye etiketlenmis bir kume YOK -- bu
yuzden KESIN bir false-positive-rate iddia EDILEMEZ, sadece "uretilen
tespitlerin ne kadari bilinen bir redteam olayina yakin zaman/host'ta
gerceklesti" gibi bir YAKLASIK olcum verilebilir. Bu sinirlama,
nihai degerlendirme raporunda acikca belirtilecektir.

## Bilinen Sinirlama

- `discovery_detection` ile `packet_translation.py` arasinda ortak bir
  Port arayuzu YOK (Karar 1). Ucuncu, gercekten farkli bir tespit
  yontemi (orn. process-tabanli) eklendiginde, bu ikisinin ortak bir
  `TechniqueDetectorPort`'a baglanmasi ONERILIR.
- Fan-out hesaplamasi UDP/TCP ayrimi yapmaz -- `ADR 0013`'teki
  paket-sayimi sorunu, flows.txt'in kendi formatinda zaten cozulmus
  olabilir (flows zaten aggregate edilmis baglanti kayitlaridir), ama
  bu VARSAYIM, LANL flows.txt'in gercek formatinda DOGRULANMADAN
  kesinlestirilmemistir.

## Sonuc

`GraphEdge`'lere yeni bir `OBSERVED_SCANNING` / T1046 kategorisi
eklendi. Bu kenarlar, mevcut `merge_static_topology()` mekanizmasiyla
Graph Builder'in urettigi ana grafa DISARIDAN eklenir -- Graph
Builder'in kendi kodu degismedi.

## Guncelleme -- Tek Pencere Karari (Faz B, gercek LANL calistirmasi)

redteam.txt incelendiginde, 749 saldiri olayinin TAMAMININ veri setinin
ilk ~30 gununde yogunlastigi gorulduu (58 gunluk toplam pencerenin
yarisindan azi). Bu, ilk tasarlanan "once temiz bir kalibrasyon
donemi, sonra saldiri donemi" ayrimini (ayri bir "kirletilmemis"
pencere gerektiriyordu) PRATIK OLARAK imkansiz kildi.

**Karar:** Ayri bir kalibrasyon penceresi ARANMADI. Bunun yerine, Tukey
IQR yonteminin kendi istatistiksel dayanikliligina (breakdown point,
~%25'e kadar aykiri deger toleransi) guvenilerek, AYNI pencere (gun
0-30) hem baseline hesaplamasi HEM degerlendirme icin kullanildi.
Gerekce: 749 olay, cok sayida farkli host'a dagilmis durumda; tek bir
host'un kendi 5-dakikalik pencere dagiliminda saldiri-iliskili
pencerelerin orani, Tukey'in tolerans esiginin cok altinda kalir.

Bu karar, "saldiri gunlerine yakin olaylari elle cikaralim" gibi bir
alternatifi BILEREK REDDETMISTIR -- bu, redteam.txt'e bakarak "normal"i
sekillendirmek olurdu, ADR 0015 Karar 3'teki sizinti-onleme ilkesinin
ihlali olurdu.

`until` parametresi (bkz. LANLFlowsCollector/LANLAuthCollector), sadece
PERFORMANS icin eklendi -- 58 gunluk verinin tamaminin islenmesini
onlemek amaciyla, metodolojiyi etkilemez.

## Guncelleme -- Bellek Kisitlamasi Nedeniyle Kucultulmus Degerlendirme Olcegi (Faz B)

Yukarida tanimlanan "Tek Pencere Karari" (gun 0-30) metodolojik olarak
dogru olsa da, PRATIKTE tam olcekte calistirilamadi. auth.txt'in 30
gunluk kismini (tahminen yuz milyonlarca satir) tek seferde bellege
yuklemeye calisan ilk deneme, tuketici sinifi bir bilgisayarda bellek
tasmasina (memory exhaustion) yol acti -- `collect()` metodunun TUM
event'leri tek bir Python listesinde biriktiren tasarimi, bu olcekte
yapisal olarak yetersiz kaldi.

**Durust sonuc:** Resmi, gercek LANL veri seti elimizde olmasina ragmen,
tam 30 gunluk / tum 749 redteam olayini kapsayan nicel bir Top-K
dogruluk/MRR degerlendirmesi bu asamada URETILEMEDI. Bunun yerine,
cok daha kisa bir pencere (ilk 6 saat) kullanilarak sistemin GERCEK
LANL verisiyle uctan uca DOGRU CALISTIGI basariyla kanitlandi (bkz.
ADR 0014 guncellemesi) -- ama bu, kucuk olcekli bir dogrulamadir,
orijinal Faz B'nin buyuk olcekli nicel hedefi degildir.

## Bilinen Sinirlama -- Bellek Mimarisi (yeni)

`LANLAuthCollector`/`LANLFlowsCollector`'in `collect()` metodu, TUM
event'leri bellekte bir Python listesi olarak biriktirir. Bu, kucuk
pcap dosyalarinda ve kisa LANL pencerelerinde (6 saat) sorunsuz
calisir, ama 30 gunluk LANL penceresinde bellek tasmasina yol actigi
GERCEK CALISTIRMADA dogrulanmistir. Tam olcekli degerlendirme icin
akis/generator tabanli bir isleme mimarisine gecis GEREKLIDIR --
bu, README'nin "Gelecek Planı" bolumune de eklenmelidir.