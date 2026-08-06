"""
logging_setup
=============

NEDEN structlog + JSON, NEDEN standart logging insan-okunur format degil?
-----------------------------------------------------------------------------
SentinelPath AI, felsefesi geregi bir gun baska bir SIEM/log toplama
sistemine kendi loglarini besleyebilecek bir arac olmalidir (projenin
kendi vizyonuyla tutarli: bir guvenlik araci uretecegi verinin de
makine-tarafindan islenebilir olmasini saglamalidir).

JSON formatinda structured logging'in somut faydalari:
  1. Her log satiri dogrudan bir log toplama sistemine (ELK, Loki, Splunk)
     parse edilmeden beslenebilir.
  2. `structlog.contextvars` ile bir istek boyunca (orn. tek bir
     tahmin cagrisi) `request_id` gibi bir baglam otomatik olarak her log
     satirina eklenebilir -- dagitik/async pipeline'da (Collector'dan
     Reporting'e kadar) hangi log satirinin hangi istege ait oldugunu
     izlemek icin kritik.
  3. Gelistirme ortaminda okunabilirlik icin `log_format=console`
     secenegiyle insan-okunur renkli ciktiya gecilebilir (bkz.
     config/settings.py) -- production'da JSON, gelistirmede konsol.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

try:
    import structlog

    _STRUCTLOG_AVAILABLE = True
except ImportError:  # pragma: no cover - yalniz structlog kurulu olmayan ortamlarda
    _STRUCTLOG_AVAILABLE = False


class _FallbackBoundLogger:
    """structlog kurulu DEGILSE kullanilan, stdlib `logging` uzerine ince
    bir sarmalayici.

    NEDEN BU FALLBACK VAR?
    -----------------------
    structlog, pyproject.toml'da bir CEKIRDEK bagimliliktir (opsiyonel
    degil) -- normal kurulumda her zaman mevcut olmalidir. Ancak bu
    modulu import eden her dosya (orn. pcap_adapter.py) sadece loglama
    icin cagirdigi bir yan-bagimlilik yuzunden CALISMAZ HALE gelmemelidir.
    Bir loglama yardimcisinin eksikligi, asil is mantigini (Scapy pcap
    okuma gibi) engellememelidir -- bu, "yan ozellik ana ozelligi kilitler"
    turunden kirilgan bir tasarim olurdu. Bu fallback, structlog kurulana
    kadar gecici olarak stdlib logging ile ayni cagirma imzasini
    (`logger.info("event_adi", key=value, ...)`) korur.
    """

    def __init__(self, name: str) -> None:
        self._logger = logging.getLogger(name)

    def _log(self, level: int, event: str, **kwargs: Any) -> None:
        if kwargs:
            extra = " ".join(f"{k}={v!r}" for k, v in kwargs.items())
            self._logger.log(level, "%s %s", event, extra)
        else:
            self._logger.log(level, event)

    def debug(self, event: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, event, **kwargs)

    def info(self, event: str, **kwargs: Any) -> None:
        self._log(logging.INFO, event, **kwargs)

    def warning(self, event: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, event, **kwargs)

    def error(self, event: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, event, **kwargs)


def configure_logging() -> None:
    """Uygulama baslangicinda BIR KEZ cagrilmasi gereken logging
    yapilandirmasi. main.py / API entrypoint'inde en tepede cagrilmalidir.

    structlog kurulu degilse bu fonksiyon sessizce hicbir sey yapmaz --
    get_logger() zaten stdlib fallback'ine gececektir.
    """

    if not _STRUCTLOG_AVAILABLE:
        logging.basicConfig(level=logging.INFO, stream=sys.stdout)
        return

    from sentinelpath.config.settings import get_settings  # lazy: pydantic-settings'e bagimli

    settings = get_settings()

    shared_processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if settings.log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping().get(settings.log_level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:
    """Modul bazinda logger almak icin kullanilir, orn.:
        logger = get_logger(__name__)
        logger.info("attack_path_computed", target_node="host-42", hop_count=3)

    Not: `logger.info("mesaj", key=value, ...)` formati structlog'un
    "event + structured fields" idiomudur -- f-string ile mesaj
    formatlamak yerine (orn. f"host {host} icin {n} yol bulundu") her
    zaman ayri alanlar kullanin. Bu, log'lari sonradan filtrelemeyi/arama
    yapmayi (orn. 'tum hop_count > 3 olan loglar') mumkun kilar.

    structlog kurulu degilse, ayni cagirma imzasini destekleyen bir
    stdlib-tabanli fallback dondurulur (bkz. _FallbackBoundLogger).
    """

    if _STRUCTLOG_AVAILABLE:
        return structlog.get_logger(name)
    return _FallbackBoundLogger(name)
