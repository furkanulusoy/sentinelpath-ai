# ADR 0013: Paket sayimi yerine baglanti (SYN) sayimi

**Durum:** Kabul edildi
**Tarih:** Faz B (gercek lab dogrulamasi)
**Baglam:** Gercek lab verisiyle (Windows 10 -> Windows Server 2022,
SMB + RDP zinciri) test edilirken bulundu.

## Sorun

`packet_translation.py`, her TCP/UDP paketini ayri bir "baglanti"
event'i olarak sayiyordu. Kisa omurlu protokoller (SMB dosya paylasimi
gezinme) ile uzun sureli, surekli veri akisi olan protokoller (RDP
oturumu -- ekran/klavye/fare verisi surekli akar) arasinda adaletsiz
bir karsilastirma olusuyordu.

Ilk gercek lab testinde, tek bir SMB gezinmesi 38 paket/event
uretirken, tek bir RDP oturumu 1042 paket/event uretti -- oysa
gercekte ikisi de "1 baglanti" idi. Bu, WeightedMarkovPredictionModel'in
RDP'yi SMB'den yaklasik 27 kat daha "sik gozlemlenmis" sanmasina yol
acti; ki bu, gercek saldiri sikligini degil, protokolun dogasi geregi
urettigi paket hacmini yansitiyordu.

## Karar

TCP icin sadece SAF SYN paketleri (baglanti baslangici, SYN=1,
ACK=0) sayilir -- SYN-ACK, ACK, veri paketleri degil. Bu,
`PacketRecord.is_new_connection` alaniyla isaretlenir ve
`packet_translation.py`, bu alan `False` olan TCP paketlerini
event'e cevirmeden eler.

## Bilinen Sinirlama: UDP

UDP, baglanti kavrami olmayan (connectionless) bir protokoldur --
"baglanti baslangici" diye bir sey yoktur, bu yuzden bu filtre UDP'ye
UYGULANAMAZ (`is_new_connection` UDP icin her zaman `True` kalir).

Bu, pratikte onemli bir sinirlamadir: RDP'nin goruntu/ses akisi byuk
olcude UDP uzerinden gider, bu yuzden uzun bir RDP oturumu hala
yuzlerce UDP event'i uretebilir. Ikinci lab testinde bu acikca
gorulmustur (SMB: 1 event, RDP: 695 event -- buyuk kismi UDP).

Bu, MVP kapsaminda BILEREK cozulmedi. Olasi gelecek cozumleri:
- UDP icin de bir "akis" (flow) kavrami tanimlamak (orn. ayni
  5-tuple'in [src_ip, dst_ip, src_port, dst_port, protocol] belirli
  bir sure icinde tek bir "baglanti" sayilmasi).
- Payload boyutuna gore agirliklandirma (buyuk veri akisi = tek bir
  "oturum" olarak yorumlanabilir).

## Sonuc

Edge weight'leri artik "gozlemlenen BAGLANTI SAYISI" anlamina geliyor,
"gozlemlenen PAKET SAYISI" degil -- bu, ADR 0009'daki "ampirik gozlem
sikligi" kavramiyla daha tutarlidir. Ancak UDP-agirlikli protokollerde
(RDP gibi) bu duzeltme kismidir; sonuclar hala bir miktar UDP hacim
onyargisi tasiyabilir (bkz. yukaridaki "Bilinen Sinirlama").

## Nasil Bulundu

Bu sorun, sentetik demo verisiyle degil, gercek bir VirtualBox lab
ortaminda (host -> Windows 10 -> Windows Server 2022) gercek SMB ve
RDP trafigi yakalanip pipeline'a verildiginde ortaya cikti. Sentetik
senaryolarda her event elle, "1 baglanti = 1 event" varsayimiyla
uretildigi icin bu sorun hic gorunmuyordu -- bu, projenin B fazinin
(gercek veri dogrulamasi) tam olarak nicin gerekli oldugunun somut
bir kanitidir.