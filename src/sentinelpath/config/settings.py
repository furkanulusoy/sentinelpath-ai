"""
config.settings
================

NEDEN pydantic-settings, NEDEN cipnak os.environ okuma degil?
----------------------------------------------------------------
Ciplak `os.environ.get("SOME_VAR")` kullanimi iki soruna yol acar:

  1. Tip guvenligi yok: `MAX_HOPS` gibi bir deger her zaman string olarak
     gelir; int'e cevirmeyi unutursaniz hata calisma zamaninda (runtime),
     hatta pipeline'in ortasinda cikar -- en kotu zamanlama.
  2. Dogrulama yok: Yanlis/eksik bir config degeri, uygulama BASLADIKTAN
     SONRA, ilgili kod yoluna gelindiginde patlar.

pydantic-settings ile tum config, uygulama baslarken TEK SEFERDE
dogrulanir ve tiplenir. Bu, "fail fast" prensibinin somut uygulamasidir --
bir guvenlik aracinin yanlis konfigurasyonla sessizce yanlis calismasi,
"hic calismamasindan" cok daha tehlikelidir.

Bu dosya Faz 1'de sadece ISKELET olarak commit edilir; her faz kendi
config alanlarini buraya ekleyecektir (orn. Faz 4'te NETWORKX_MAX_NODES,
Faz 6'da PREDICTION_MODEL_NAME gibi).
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Uygulama genelinde kullanilan, ortam degiskenlerinden (.env veya
    sistem env) okunan, tip-guvenli konfigurasyon.
    """

    model_config = SettingsConfigDict(
        env_prefix="SENTINELPATH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Genel ---
    environment: str = Field(
        default="development",
        description="development | staging | production",
    )
    log_level: str = Field(default="INFO")
    log_format: str = Field(
        default="json",
        description=(
            "'json' (structlog, makine-okunur) veya "
            "'console' (insan-okunur, gelistirme icin)"
        ),
    )

    # --- Veritabani (Faz 2+ icin hazirlik) ---
    database_url: str = Field(
        default="sqlite:///./sentinelpath.db",
        description="MVP: SQLite. Ileride PostgreSQL'e gecis icin ayni alan kullanilacak.",
    )

    # --- Attack Path Engine (Faz 6 icin hazirlik) ---
    attack_path_max_hops: int = Field(
        default=4,
        ge=1,
        le=10,
        description="Graf gezinmesinde izin verilen maksimum sicrama sayisi.",
    )

    # --- Feature Extraction (Faz 3) ---
    business_hours_start: int = Field(
        default=8,
        ge=0,
        le=23,
        description=(
            "Mesai saatinin basladigi saat (UTC, 0-23). Bu sinirin disindaki "
            "aktivite 'off-hours' sayilir. NOT: MVP'de tum event zaman "
            "damgalari UTC kabul edilir; host'a ozel yerel saat dilimi "
            "esleme Faz 5+ icin planlanan bir gelisimdir."
        ),
    )
    business_hours_end: int = Field(
        default=18,
        ge=0,
        le=23,
        description="Mesai saatinin bittigi saat (UTC, 0-23, dahil degil).",
    )

    # --- Baseline Behavior (Faz 5) ---
    baseline_hour_frequency_threshold: float = Field(
        default=0.05,
        ge=0.0,
        le=1.0,
        description=(
            "Bir saatin 'tipik aktif saat' sayilmasi icin, o host'un TUM "
            "event'leri icindeki minimum goreli frekans esigi (orn. 0.05 "
            "= event'lerin en az %5'i o saatte gerceklesmis olmali)."
        ),
    )
    baseline_peer_day_fraction_threshold: float = Field(
        default=0.2,
        ge=0.0,
        le=1.0,
        description=(
            "Bir peer node'un 'tipik peer' sayilmasi icin, gozlemlenen "
            "GUNLERIN en az bu oraninda goruluyor olmasi gerekir (orn. 0.2 "
            "= gozlemlenen gunlerin en az %20'sinde bu peer'e baglanti "
            "olmali). Bu esik, 'bir kez gorulen' ile 'surekli gorulen' "
            "baglantiyi ayirt etmek icindir."
        ),
    )

    # --- Risk Scoring (Faz 7) ---
    default_asset_criticality: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description=(
            "Kritiklik konfigurasyonunda listelenmemis bir host icin "
            "kullanilan varsayilan kritiklik degeri. Notr (orta) bir "
            "deger secildi: cok dusuk bir varsayilan gercek riskleri "
            "gizleyebilir, cok yuksek bir varsayilan gereksiz alarm "
            "yorgunluguna yol acabilir. Kurumlar KENDI varlik "
            "envanterlerini saglamaya tesvik edilir; bu sadece bir "
            "'bilmiyoruz' isaretidir, 'dogrulanmis dusuk risk' degildir."
        ),
    )
    default_technique_severity: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description=(
            "TECHNIQUE_SEVERITY tablosunda listelenmemis bir MITRE "
            "teknigi icin kullanilan varsayilan siddet degeri."
        ),
    )


def get_settings() -> Settings:
    """Ayarlari yukler. Ayri bir fonksiyon olmasinin nedeni: FastAPI
    dependency-injection sisteminde (`Depends(get_settings)`) test
    sirasinda ayarlari kolayca override edebilmek (bkz. Faz 2+ testleri).
    """

    return Settings()
