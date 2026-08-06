# ADR 0011: Dashboard teknoloji secimi -- FastAPI JSON API + statik HTML/vanilla JS

**Durum:** Kabul edildi
**Tarih:** Faz 9
**Baglam:** Dashboard (sistem promptunun orijinal 10 fazlik yol haritasinda Faz 9)

## Karar

Dashboard, **FastAPI tabanli bir JSON API** ile **statik bir HTML/vanilla
JS sayfasi** olarak insa edilecektir. Graf gorsellestirmesi icin CDN
uzerinden yuklenen `vis-network` kutuphanesi kullanilacaktir. React/Vue
gibi bir JS framework'u veya Streamlit KULLANILMAYACAKTIR.

## Gerekce

| Yaklasim | Degerlendirme |
|---|---|
| Streamlit | Hizli gelistirme sunar ama proje tech stack'inde (pyproject.toml) yer almiyor; Python-only render modeli, sistem promptunun acikca istedigi "FastAPI" hedefiyle celisir |
| React/Vue + npm build zinciri | MVP icin oransiz karmasiklik -- bundler, node_modules, ayri bir build adimi gerektirir; proje tech stack'i bunu icermiyor |
| Statik HTML + vanilla JS + FastAPI JSON API | Sifir ekstra build araci; API'nin kendisi "urun" olarak kalir -- bir SOC ekibi dashboard'u hic kullanmadan API'yi kendi araclarina (SOAR, SIEM) entegre edebilir |

**Karar: Statik HTML + vanilla JS + FastAPI.** Bu, ADR 0001'deki
"erken optimizasyon yapma" mantiginin bir baska uygulamasidir -- bir
JS framework'unun getirecegi deger (bilesen yeniden kullanimi, state
yonetimi), tek sayfalik bir MVP dashboard icin henuz gerekcelendirilemez.

## Kritik Mimari Karar: Orchestrator/API Ayrimi

Bu fazda, gelistirme ortaminda (bu sandbox) `pydantic`/`fastapi`
KURULU DEGIL ve internet erisimi kapali oldugu icin API katmani
CALISTIRILARAK DOGRULANAMADI. Bu, Faz 2'deki (Scapy) ayni kisitlamadir
ve AYNI cozum uygulanmistir:

- **`PipelineOrchestrator`** (saf Python, HICBIR web framework'une
  bagimli degil) -- tum 8 fazi (Feature Extraction -> ... -> Reporting)
  zincirleyen is mantigi. Bu sinif bu sandbox'ta TAM olarak test edildi.
- **`api/main.py`** (FastAPI, ince katman) -- SADECE HTTP istek/yanit
  donusumunu yapar, orchestrator'i cagirir. Bu dosya sadece sozdizimi
  seviyesinde dogrulanabildi.

Bu ayrim, ADR 0003'teki "framework I/O ile saf mantigin ayrilmasi"
deseninin bu kez bir web framework'u (Scapy yerine FastAPI) icin
uygulanmis halidir -- ayni prensip, farkli bir framework sinirinda.

## Sonuclar

- **Olumlu:** `PipelineOrchestrator` framework'ten bagimsiz oldugu icin
  hem test edilebilir hem de ileride FastAPI disinda baska bir arayuz
  (orn. bir CLI, bir Slack bot) tarafindan da kullanilabilir.
- **Olumsuz:** API katmaninin GERCEK HTTP davranisi (routing, hata
  kodlari, Pydantic dogrulama hatalari) kullanicinin kendi ortaminda
  `pip install -e ".[api]"` sonrasi test edilmelidir.
