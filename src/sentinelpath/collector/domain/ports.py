"""
collector.domain.ports
=======================

NEDEN Protocol, NEDEN ABC DEGIL?
---------------------------------
Python'da soyut arayuz tanimlamanin iki yolu var: `abc.ABC` (nominal
subtyping -- somut sinif acikca `class X(CollectorPort)` yazip miras almali)
ve `typing.Protocol` (structural subtyping -- bir sinif, imzasi uyuyorsa
otomatik olarak o tipten sayilir, miras almasina gerek yok, "duck typing"in
tip-guvenli hali).

Bu projede Protocol'u tercih ediyoruz cunku:
  1. Test yazarken sahte (mock/fake) adapter'lar gercek porttan miras almak
     ZORUNDA kalmiyor -- sadece ayni metod imzasina sahip olmasi yeterli.
     Bu, unit testlerde bagimliliklari azaltir.
  2. Ileride disaridan (baska bir pip paketinden) gelen bir adapter'i
     projeye entegre etmek istersek, o paketin bizim ABC'mizden haberdar
     olmasina gerek kalmaz -- sadece imzayi karsilamasi yeterlidir.

Bu Faz 1'de yalnizca ARAYUZ (sozlesme) tanimlanir. Somut implementasyon
(infrastructure/ klasoru) Faz 2'de (Network Parser) yazilacaktir.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from sentinelpath.core.models import NormalizedEvent


class CollectorPort(Protocol):
    """Ham veri kaynagini (pcap, Sysmon log, auth.log, sentetik JSON, ...)
    standart NormalizedEvent listesine ceviren her adapter'in uymasi
    gereken sozlesme.

    Tasarim notu: `collect()` metodu bir zaman araligi (`since`) parametresi
    alir, TUM veriyi degil. Bunun nedeni Baseline Behavior Engine'in
    (Faz 5) periyodik/artimli (incremental) calisacak olmasi -- her seferinde
    bastan tum veriyi okumak, veri hacmi buyudukce olceklenmeyen bir
    tasarim hatasi olurdu.
    """

    def collect(self, since: datetime | None = None) -> list[NormalizedEvent]:
        """Belirtilen zamandan itibaren biriken olaylari normallestirilmis
        formatta dondurur. `since=None` ise mevcut tum veriyi okur (ornegin
        ilk calistirma / soguk baslangic (cold start) senaryosu).
        """
        ...

    def source_name(self) -> str:
        """Bu adapter'in hangi veri kaynagini temsil ettigini dondurur
        (loglama ve hata ayiklama icin, orn. 'sysmon_file_adapter')."""
        ...
