# ADR 0014: auth.txt Olaylarina MITRE Teknik Atamasi

**Durum:** Kabul edildi
**Baglam:** Faz B (LANL degerlendirmesi) icin `LANLAuthCollector`
tasarlanirken -- pcap Collector'daki gibi port bilgisi olmadan,
`auth.txt`'in kendi semasindan teknik cikarma sorunu.

## Sorun

`auth.txt` dogrudan port bilgisi tasimiyor (pcap Collector'daki gibi
445->SMB, 3389->RDP eslemesi burada yok). Ama "hicbir teknik atamayalim"
demek de yanlis olurdu -- Windows'un kendi logon_type semasinda ve
`flows.txt` ile capraz dogrulamada, redteam.txt'e HIC bakmadan elde
edilebilecek gercek sinyaller var.

## Karar

Uc katmanli, guven seviyesine gore siniflandirma:

1. **`logon_type == "RemoteInteractive"` -> T1021.001 (RDP), YUKSEK
   guven.** Bu, Windows'un kendi resmi logon type tanimi (tip 10) --
   tartismasiz, sadece RDP/Terminal Services oturumlari icin kullanilir.

2. **`logon_type` in `{"Network", "NetworkCleartext"}` + ayni
   zaman/host cifti icin `flows.txt`'te port 445/139 eslesmesi ->
   T1021.002 (SMB), YUKSEK guven.** pcap Collector'da zaten dogrulanmis
   port-teknik tablosunun capraz-kaynak dogrulamasi.

3. **`logon_type` in `{"Network", "NetworkCleartext"}` ama flows.txt'te
   ESLESME YOK -> genel T1021 (alt-teknik belirsiz), DUSUK guven.**
   Durust bir "bilmiyoruz ama uzaktan erisim" kovasi -- uydurma bir
   alt-teknik atanmaz.

## Bilinen kapsam disi birakma -- T1078 (Valid Accounts)

T1078, "bu giris gercek kullanicidan mi calinti kimlik bilgisinden mi
geldi" ayrimina dayanir. `auth.txt`'in kendisi bunu YAPISAL OLARAK
soyleyemez -- basarili bir Kerberos girisi, gercek kullanicidan da
gelse saldargandan da gelse BIREBIR AYNI gorunur. Bunu ayirt etmenin
TEK yolu redteam.txt'e bakmak olurdu -- ki bu, projenin baglica
ilkesi olan "hicbir asamada ground truth'a sizinti yok" kuralinin
ihlali olurdu. Bu yuzden T1078, BILINCLI OLARAK kapsam disi
birakilmistir.

## Gurultu azaltma -- redteam.txt'e bakmadan verilebilen kararlar

Su kategoriler, SADECE auth.txt'in kendi semasina bakilarak (ground
truth'a hic degmeden) elenir:

- `logon_type` in `{"Interactive", "CachedInteractive", "Unlock"}`:
  yerel/fiziksel girisler, lateral movement ile ilgisi yok.
- `logon_type` in `{"Service", "Batch"}`: arka plan servisleri/
  zamanlanmis gorevler, insan-yonlendirmeli saldiri degil.
- Kullanici adi `$` ile bitenler (orn. `C101$@DOM1`): makine/servis
  hesaplari, `ANONYMOUS LOGON` ile ayni mantikla elenir.
- `outcome != "Success"`: graf kenari olarak EKLENMEZ -- ama bu veri
  atilmaz, Faz 3'teki mevcut `failed_auth_ratio` ozelligine (Feature
  Extraction) besleme yapar, tekerlek yeniden icat edilmez.

## Sonuc

`LANLAuthCollector`, bu uc katmanli mantikla `NormalizedEvent` uretir.
Yuksek/dusuk guven ayrimi, ileride raporda ayri ayri gosterilebilir
(orn. "T1021.002 tespitlerinin %X'i flows.txt ile capraz dogrulanmis").

## Guncelleme -- Gercek Veriyle Bulunan Kapsama Farki (Faz B)

6 saatlik gercek bir calistirmada, auth.txt'teki "Network" tipi
olaylarin sadece ~%1.85'i flows.txt ile capraz dogrulanabildi
(Katman 2), geri kalan ~%98'i Katman 3'e (genel T1021, dusuk guven)
dustu.

Arastirma sonrasi bunun bir HATA DEGIL, LANL'in kendi veri toplama
metodolojisinin bir sonucu oldugu dogrulandi: flow verisi "sadece
birkac kilit router konumunda" toplanmis (LANL resmi aciklamasi),
auth.txt ise AG GENELINDE her kimlik dogrulamayi kapsiyor. Ayni
switch/segment icindeki host ciftleri arasindaki trafik, hicbir
router'dan gecmedigi icin flows.txt'te YAPISAL OLARAK hic gorunmez --
zaman toleransini genisletmek bunu COZMEZ, kok sebep zamanlama degil
kapsama farkidir.

Bu, uc katmanli tasarimin (ADR 0014) DOGRULUGUNU teyit ediyor: Katman 3
olmasaydi, bu ~140bin olayin tamami sessizce kaybolurdu.

## Guncelleme -- Outcome Normalizasyon Hatasi (Faz B, kod incelemesinde bulundu)

LANLAuthCollector yazilirken (gercek calistirmadan ONCE), mevcut
Graph Builder ve Feature Extraction kodu incelenirken bir uyumsuzluk
bulundu: Graph Builder `outcome == "success"` (kucuk harf) bekliyor,
Feature Extraction ise `outcome == "failure"` (tam kelime) bekliyor --
ama LANL'in ham verisi `"Success"`/`"Fail"` formatinda geliyor.

Bu duzeltilmeseydi, LANL verisinden HICBIR AUTHENTICATES_TO kenari
uretilmeyecekti VE failed_auth_ratio sessizce her zaman 0.0 donecekti
-- ikisi de fark edilmesi zor, sessiz hatalar olurdu. `_OUTCOME_NORMALIZATION`
sozlugu bu iki degeri dogru formata cevirir (bkz. lanl_auth_adapter.py).

Bu, "gercek koda entegrasyon oncesi dikkatli inceleme"nin de (sadece
"gercek veriyle calistirma"nin degil) gercek hata yakalayabildiginin
bir kanitidir.