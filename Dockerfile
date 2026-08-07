# syntax=docker/dockerfile:1
#
# Coklu-asamali build (bkz. ADR 0012, madde 2): `builder` asamasi derleme
# araclarini icerir, final `runtime` asamasi ise SADECE calisma zamani
# icin gerekli dosyalari tasir -- guvenlik odakli bir aracin kendi
# dagitim imajinin saldiri yuzeyini kucultmesi tematik olarak da
# tutarlidir.

# ---------------------------------------------------------------------------
# Asama 1: builder
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

# networkx/pandas/numpy gibi bilimsel paketlerin bazi surumleri C
# extension derlemesi gerektirebilir -- bu yuzden builder asamasinda
# gcc bulunur (runtime asamasinda BULUNMAZ, bkz. asagida).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Once sadece bagimlilik tanimlarini kopyala -- Docker layer cache'i
# sayesinde, kaynak kod degistiginde bagimliliklarin yeniden kurulmasi
# GEREKMEZ (sadece pyproject.toml degisirse yeniden kurulur).
COPY pyproject.toml README.md ./
COPY src ./src

# Venv icinde kur (sistem Python'unu kirletmemek icin) -- api ekstra
# grubu (FastAPI + uvicorn) dahil. network/ml/gnn ekstralari BILEREK
# DAHIL EDILMEDI: bu servis sadece HTTP API'yi sunar, pcap okuma
# (network) veya model karsilastirma (ml) is'i bu konteynerin
# sorumlulugunda degildir (bkz. ARCHITECTURE.md, katman ayrimlari).
#
# NOT: `-e` (editable) DEGIL, normal bir kurulum yapilir. Gerekce: bir
# editable install, kaynak dizinin YOLUNA (bu asamada /build/src)
# isaret eden bir referans birakir; bu venv `runtime` asamasina
# kopyalandiginda o yol ARTIK GECERSIZ olur (bkz. ADR 0012, bu hata
# Faz 10'da Docker imaji tasarlanirken bulundu). Normal kurulum,
# paketi venv'in SITE-PACKAGES'ina fiilen KOPYALAR -- bu yuzden
# konum-bagimsizdir.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ".[api]"

# ---------------------------------------------------------------------------
# Asama 2: runtime (final image)
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

# Guvenlik: root olmayan bir kullanici olustur ve uygulamayi bu
# kullaniciyla calistir (bir guvenlik aracinin kendi konteyneri root
# olarak calismamalidir).
RUN groupadd --system sentinelpath && \
    useradd --system --gid sentinelpath --create-home sentinelpath

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Statik dashboard dosyalari ACIKCA kopyalanir ve konumu bir ortam
# degiskeniyle isaret edilir -- bu, wheel'in bu dosyalari fiilen
# icerip icermedigine dair belirsizlige BAGIMLI KALMAZ (bkz.
# api/main.py'deki SENTINELPATH_STATIC_DIR yorum). Bu sandbox'ta
# hatchling kurulu olmadigi icin wheel paketleme davranisi test
# EDILEMEDI -- bu yuzden konum acikca, Docker seviyesinde garanti
# altina alinir.
COPY src/sentinelpath/static/dashboard ./static/dashboard
ENV SENTINELPATH_STATIC_DIR=/app/static/dashboard

RUN chown -R sentinelpath:sentinelpath /app
USER sentinelpath

EXPOSE 8000

# HEALTHCHECK: Faz 9'daki GET /health endpoint'ini kullanir.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "sentinelpath.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
