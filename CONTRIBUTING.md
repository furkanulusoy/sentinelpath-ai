# Katkida Bulunma

SentinelPath AI, acik kaynak bir arastirma platformu olarak
tasarlanmistir. Katkida bulunmadan once:

1. **Mimari kararlari okuyun.** Bircok "neden boyle?" sorusunun cevabi
   zaten [ARCHITECTURE.md](ARCHITECTURE.md) ve [`docs/adr/`](docs/adr/)
   klasorunde gerekceli olarak yazilidir.
2. **Gelistirme felsefesini takip edin.** Her yeni ozellik/modul icin:
   problemi analiz edin, alternatifleri karsilastirin, secilen
   yaklasimi gerekcelendirin, unit test yazin. Bkz. ARCHITECTURE.md
   bolum 1.
3. **Port sozlesmelerini (domain/ports.py) degistiriyorsaniz, bir ADR
   ekleyin.** Bu projede port revizyonlari SIK gorulur (bkz. ADR
   0004-0010) -- onemli olan bunun GEREKCELI ve KAYITLI yapilmasidir.

## Yerel Gelistirme Kurulumu

```bash
git clone <repo-url>
cd sentinelpath-ai
pip install -e ".[dev,api,network,ml]"
pytest -v
ruff check src tests
mypy src
node tests/dashboard/test_app_pure_functions.js
```

## Pull Request Kontrol Listesi

- [ ] `pytest` tum testleri geciyor
- [ ] `ruff check` temiz
- [ ] Yeni bir port sozlesmesi degisikligi varsa, bir ADR eklendi
  (`docs/adr/NNNN-kisa-baslik.md`)
- [ ] README.md'deki Faz Haritasi / Kullanim bolumu (gerekiyorsa)
  guncellendi
- [ ] CI (`.github/workflows/ci.yml`) yesil

## Docker ile Calistirma

```bash
docker compose up --build
# http://localhost:8000/dashboard/
```

## Sorular

Bir mimari karar hakkinda emin degilseniz, once `docs/adr/` klasorune
bakin -- benzer bir karar zaten alinmis ve gerekcelendirilmis olabilir.
