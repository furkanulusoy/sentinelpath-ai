# ADR 0001: Graf katmani icin NetworkX (Neo4j degil)

**Durum:** Kabul edildi
**Tarih:** Faz 1
**Baglam:** Graph Builder katmani (bkz. ARCHITECTURE.md)

## Karar

MVP ve ongorulebilir sonraki fazlar (Faz 8'e kadar) icin attack graph
temsili NetworkX (in-memory Python graf kutuphanesi) ile yapilacaktir.
Neo4j gibi dedike bir graf veritabani KULLANILMAYACAKTIR.

## Gerekce

| Kriter | NetworkX | Neo4j |
|---|---|---|
| Kurulum karmasikligi | Sifir (pip install) | Ayri servis, Docker container |
| MVP veri hacmi (yuzlerce host) | Rahat yeterli | Gereksiz overhead |
| Persistans | Yok (manuel serialize) | Native |
| Concurrent yazma | Zayif | Guclu |
| Python algoritma ekosistemi | Native (shortest_path, centrality hazir) | Cypher sorgusu gerekir |
| Olceklenebilirlik (100k+ node) | Zayiflar | Guclu |

Bu asamada projenin en buyuk riski "veritabani olceklenmiyor" degil,
"deterministik graf akil yurutme + olasiliksal tahmin ayrimi dogru
tasarlanmis mi" sorusudur. Neo4j kurmak bu asamada erken optimizasyondur
(premature optimization) ve gelistirme hizini dusurur.

## Sonuclar

- **Olumlu:** Hizli iterasyon, harici servis bagimliligi yok, NetworkX'in
  hazir algoritma kutuphanesi (shortest_path, all_simple_paths,
  betweenness_centrality vb.) Attack Path Engine'i hizlandirir.
- **Olumsuz:** Graf persistans'i (uygulama yeniden baslatildiginda
  kaybolmamasi) manuel olarak cozulmelidir (Faz 4'te ele alinacak --
  muhtemel cozum: periyodik pickle/JSON serialize + SQLite'a yazma).
- **Riskler:** Node/edge sayisi cok buyurse (>50k-100k) performans
  duser. Bu senaryo Faz 9-10 (Dashboard/Deployment) tartismasinda
  yeniden degerlendirilecektir.

## Yeniden Degerlendirme Tetikleyicileri

Bu karar asagidaki durumlardan biri gerceklestiginde yeniden gozden
gecirilmelidir:
1. Tek bir attack graph'ta 50.000+ node ihtiyaci ortaya cikarsa.
2. Coklu es zamanli yazici (concurrent writer) ihtiyaci dogarsa
   (orn. birden fazla collector instance'i ayni graf'a yaziyorsa).
3. Graf sorgu gecikmesi (latency) API SLA'sini ihlal etmeye baslarsa.

Bu tetikleyicilerden biri gerceklestiginde, `graph_builder/domain/ports.py`
sozlesmesi DEGISMEDEN sadece `infrastructure/` katmaninda yeni bir
Neo4j adapter'i yazilarak gecis yapilabilir -- bu ADR'nin Hexagonal
Architecture kararindan aldigi somut fayda budur.
