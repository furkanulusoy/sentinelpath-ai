# ADR 0003: Framework-bagimli I/O ile saf ceviri mantiginin ayrilmasi

**Durum:** Kabul edildi
**Tarih:** Faz 2
**Baglam:** Collector implementasyonlari (`PcapFileCollector` ve sonraki adapter'lar)

## Karar

Bir dis kutuphaneye (Scapy, ileride belki bir Sysmon/Zeek parser
kutuphanesi) bagimli her Collector adapter'i, ikiye bolunecektir:

1. **Saf ceviri katmani** (orn. `packet_translation.py`) — yalnizca
   stdlib ve `sentinelpath.core.models`'e bagimlidir, framework'e
   ait HICBIR tipi import etmez. Domain mantigini (bu veri ne anlama
   geliyor?) icerir.
2. **Ince I/O adaptoru** (orn. `pcap_adapter.py`) — dis kutuphaneyi
   import eden TEK dosyadir. Sorumlulugu yalnizca "kutuphanenin
   nesnesini framework-bagimsiz bir ara veri tipine (orn.
   `PacketRecord`) cevirmek" ile sinirlidir; hicbir domain karari
   (port -> teknik eslemesi gibi) burada verilmez.

## Gerekce

Bu karar Faz 2'de, gelistirme sirasinda scapy'nin bu ortamda
kurulamamasi (internet erisimi kapali) nedeniyle somutlasti, ama
sonuc genel gecerlilikte bir prensiptir:

**Framework-bagimli kod ile domain mantigi ayni dosyada oldugunda,
domain mantigini dogrulamak icin her zaman framework'un calisir
durumda olmasi gerekir.** Bu, ozellikle su durumlarda sorun yaratir:
- CI/CD ortaminda agir/opsiyonel bagimliliklarin (Scapy root yetkisi,
  bazi ML kutuphaneleri buyuk indirme boyutu) her testte kurulu olmasi
  gerekir.
- Bir katkida bulunan, sadece domain mantigini degistirmek istediginde
  bile tum framework kurulumunu yapmak zorunda kalir.
- Framework'un kendi API'sindeki bir davranis (orn. Scapy'nin belirli
  bir surumdeki paket ayristirma quirklari) ile domain mantigi
  testlerinin birbirine karismasi, bir testin neden basarisiz oldugunu
  anlamayi zorlastirir.

## Sonuclar

- **Olumlu:** `packet_translation.py` (ve gelecekte ayni deseni
  izleyecek her modul) framework kurulu olmadan test edilebilir.
  Faz 2'de bu, 10/10 testin scapy hic kurulamadan gecmesini sagladi
  (bkz. `tests/test_packet_translation.py`).
- **Olumsuz:** Ekstra bir dosya/soyutlama katmani (`PacketRecord`)
  gerektirir; cok kucuk/basit adapter'lar icin bu fazla muhendislik
  (over-engineering) gibi gorunebilir.
- **Ne zaman uygulanir:** Bu desen, adapter'in cevirdigi domain mantigi
  ONEMLI ve TEST EDILMESI GEREKEN bir mantik icerdiginde uygulanir
  (orn. port->teknik eslemesi). Adapter yalnizca duz veri kopyaliyorsa
  (orn. bir CSV dosyasini oldugu gibi okuyup NormalizedEvent'e cevirme),
  bu ekstra katman gereksizdir -- asiri soyutlamadan kacinilmalidir.

## Gelecek Fazlara Etkisi

Faz 3+ icin ayni desen tekrar kullanilabilir: bir gelecekteki Sysmon/Zeek
parser'i da ayni sekilde "framework/format'a bagimli ince katman + saf
ceviri mantigi" olarak tasarlanmalidir.
