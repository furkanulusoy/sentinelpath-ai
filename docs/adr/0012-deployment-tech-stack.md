# ADR 0012: Deployment yigin secimleri (Docker, docker-compose, CI)

**Durum:** Kabul edildi
**Tarih:** Faz 10
**Baglam:** Konteynerlestirme ve CI/CD (sistem promptunun orijinal 10 fazlik yol haritasinda Faz 10)

## Kararlar

### 1. Base image: `python:3.11-slim` (Alpine veya tam image DEGIL)

| Secenek | Degerlendirme |
|---|---|
| `python:3.11-alpine` | En kucuk boyut, ama musl libc, numpy/pandas/networkx gibi C-extension bagimliliklarinin derlenmesinde SIK KARSILASILAN bir sorun kaynagidir (glibc varsayan wheel'ler calismaz, kaynaktan derleme gerekir -- build suresi ve karmasikligi artar) |
| `python:3.11` (tam) | Gereksiz buyuk, kullanilmayan sistem araclarini icerir |
| **`python:3.11-slim`** | **Secildi** -- glibc tabanli (bilimsel Python paketleriyle uyumlu), tam image'dan onemli olcude kucuk |

### 2. Coklu-asamali (multi-stage) Docker build

Tek asamali build yerine iki asama kullanilir: `builder` (derleme
araclarini ve bagimliliklari kurar) ve final `runtime` asamasi (SADECE
calisma zamani icin gerekli dosyalari kopyalar). Gerekce: bu, guvenlik
odakli bir arac oldugu icin, kendi dagitim imajinin saldiri yuzeyini
kucultmek tematik olarak da tutarli bir mühendislik pratiğidir --
derleme araclari (gcc, vb.) production image'da BULUNMAMALIDIR.

### 3. docker-compose kapsami: SADECE `api` servisi (henuz veritabani servisi YOK)

Pyproject.toml'da SQLite/PostgreSQL bagimliliklari listeli olsa da,
su ana kadar HICBIR fazda gercek bir veritabani persistans kodu
YAZILMADI (Baseline Behavior bile bilerek in-memory, bkz. Faz 5). Bu
yuzden docker-compose'a bir `db` servisi eklemek, karsiligi olmayan
altyapi kurmak olurdu -- ADR 0001'deki "erken optimizasyon yapma"
ilkesiyle ayni gerekce. `docker-compose.yml` icinde, persistans
implementasyonu yazildiginda kullanilmak uzere YORUM SATIRI olarak bir
`db` servisi sablonu birakildi.

### 4. CI/CD platformu: GitHub Actions

Proje acikca GitHub'da barindirilmak uzere tasarlandi (README, ARCHITECTURE.md
referanslari). GitHub Actions, ek bir hesap/entegrasyon gerektirmeden
dogrudan calisir -- baska bir CI platformu (GitLab CI, CircleCI)
degerlendirilmedi cunku bu secim icin gercek bir alternatif yok.

### 5. CI kapsami: TUM opsiyonel bagimliliklar KURULACAK

Bu, projenin gelistirilmesi boyunca tekrar eden bir kisitlamayi COZER:
bu sandbox ortaminda internet erisimi kapali oldugu icin `scapy`,
`pydantic`, `fastapi`, `pytest` gibi bagimliliklar KURULAMADI ve bircok
test (`test_pcap_adapter.py`, `test_weighted_markov_model.py`'nin
pytest kismi, API katmani) sadece SOZDIZIMI seviyesinde dogrulanabildi.

GitHub Actions runner'lari GERCEK internet erisimine sahiptir. CI
is akisi `pip install -e ".[dev,api,network,ml]"` calistirarak TUM
bu bagimliliklari kurar ve TUM test paketini (Scapy/FastAPI dahil)
gercekten calistirir. `torch` (gnn ekstra grubu) BILEREK CI'a dahil
EDILMEDI -- agir bir bagimliliktir ve henuz hicbir GNN implementasyonu
yazilmadi (bkz. ADR 0009), CI suresini gereksiz uzatirdi.

## Sonuclar

- **Olumlu:** CI, bu projenin gelistirme sirasinda "bu ortamda test
  edemedim" diye isaretlenen HER SEYI nihayet gercekten dogrulayacak.
  Bu, projenin kendi durustluk ilkesinin (bkz. tum ADR'ler ve fazlardaki
  "durustluk notlari") dogal bir tamamlanma noktasidir.
- **Olumsuz:** Bu sandbox'ta Docker daemon KURULU DEGIL -- `docker build`
  bu ortamda calistirilarak dogrulanamadi. Dockerfile ve docker-compose.yml
  sozdizimi/mantik olarak gozden gecirildi ama GERCEK bir build/run
  denemesi kullanicinin kendi ortaminda yapilmalidir.
