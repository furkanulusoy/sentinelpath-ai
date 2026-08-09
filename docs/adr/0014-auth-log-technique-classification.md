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