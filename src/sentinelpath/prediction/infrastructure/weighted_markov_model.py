"""
prediction.infrastructure.weighted_markov_model
====================================================

PredictionModelPort'un MVP implementasyonu. Model secim gerekcesi icin
bkz. docs/adr/0009-prediction-model-selection.md -- ozet: bu proje yeni
kuruldugu icin etiketli egitim verisi yok, bu yuzden gozlemlenen graf
agirliklarini (ampirik gozlem sikligi) dogrudan olasilik tahmini olarak
kullanan, egitim gerektirmeyen bir yontem seciyoruz.

ONEMLI DURUSTLUK NOTU: Bu, formel anlamda kalibre edilmis bir Bayesian
posterior DEGILDIR. Verilen aday kumesi (candidate_paths) uzerinde
GORELI bir siralama uretir ve bunu bir olasilik dagilimina (toplam=1.0)
normalize eder. "Bu yolun GERCEK olasiligi %62" gibi bir istatistiksel
iddia değil; "verilen adaylar arasinda, gozlemlenen frekanslara gore
bu yolun goreli agirligi %62" seklinde okunmalidir. Faz 7+ (gercek
etiketli geri bildirim biriktiginde) daha once ADR 0009'da belirtilen
tetikleyicilerle bu yontem yeniden degerlendirilmelidir.

IKINCI DURUSTLUK NOTU (implementasyon sirasinda kendi kendini duzelten
bir hata): Ilk tasarimda "daha uzun zincirler carpimsal olarak dogal
bir ceza alir" varsayimiyla yola cikilmisti. Bu YANLIS cikti: agirliklar
(weight) GOZLEM SAYISIdir ve genelde >=1'dir; >=1 degerleri carpmak
skoru BUYUTUR, kucultmez. Yani 2 hop'luk guclu-gozlemlenmis bir zincir,
1 hop'luk zayif-gozlemlenmis bir zincirden DAHA YUKSEK skor alabilir --
ki bu aslinda MANTIKSIZ degildir (her iki adimda da guclu kanit varsa,
bu gercekten daha "guclu" bir senaryo olabilir). Bu yuzden "kisa yol
=her zaman daha olasi" iddiasi KALDIRILDI. Bu skorlama, hop sayisina
gore degil, TOPLAM KANIT AGIRLIGINA gore siralar. Dogru bir Markov
zinciri (her hop icin lokal gecis olasiligi, kaynak node'un TUM cikis
agirligina bolunerek normalize edilmis) bu ozelligi saglar ama bu,
CandidatePath'in her hop icin kaynak node'un toplam cikis agirligini
da tasimasini gerektirirdi (ADR 0008'i bir kez daha genisletmek) --
bu, MVP kapsaminin disina cikildigi icin bilerek ERTELENDI ve burada
acikca belgeleniyor.

UCUNCU DURUSTLUK NOTU (SentinelBench ile gercek veride bulundu, ADR
0017): Ham agirlik (weight = Graph Builder'da gozlemlenen HAM EVENT
SAYISI, bkz. networkx_adapter.py) dogrudan carpana sokuluyordu. Gercek
LANL verisiyle (C17693 senaryosu) test edildiginde, bunun ciddi bir
sorun oldugu ortaya cikti: yuksek hacimli MESRU trafik (orn. 496 kez
tekrarlanan bir servis baglantisi) skoru, nadir ama GERCEK bir kimlik
dogrulama olayini (weight=1) 744 KAT ezebiliyordu -- gercek redteam.txt
saldirganinin tum hedefleri, 343 adayin en altina (~250. sira) dusuyordu.
Duzeltme: agirlik, kullanilmadan once log1p ile sikistirilir. Bu,
siralamayi KORUR (daha fazla gozlem hala daha guclu kanittir) ama
acik uctu buyumeyi sinirlar (744 kat fark ~13 kata indi). Bu, projenin
Tukey IQR'da (discovery_detection) kullandigi ayni "agir kuyruklu
dagilimlari sikistirma" felsefesinin burada da uygulanmasidir.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime

from sentinelpath.core.models import (
    CandidatePath,
    PredictionResult,
    RelationType,
    TechniquePrediction,
)

# Iliski tipi basina, bir hop'un "saldiri-iliskili" agirligini
# carpan olarak ayarlayan onceki (prior). Degerler kesin bir bilim
# degil, guvenlik alan bilgisine dayanan MAKUL varsayimlardir --
# gercek etiketli veri biriktiginde bu carpanlarin YERINE ogrenilmis
# agirliklar konulabilir (bkz. ADR 0009).
DEFAULT_RELATION_PRIORS: dict[RelationType, float] = {
    RelationType.OBSERVED_LATERAL_MOVEMENT: 3.0,
    RelationType.AUTHENTICATES_TO: 2.0,
    RelationType.TRUSTS: 1.5,
    RelationType.NETWORK_REACHABLE: 1.0,
    # Faz B / ADR 0015: Discovery taktigi (TA0007), Lateral Movement'tan
    # ONCE ve ondan daha ZAYIF bir kanittir -- mevcut olcegin (1.0-3.0)
    # bir basamak ALTINA yerlestirilir. Bu deger ground truth'a (redteam.txt)
    # gore AYARLANMAMISTIR -- tablonun kendi ic mantigina dayanir.
    RelationType.OBSERVED_SCANNING: 0.5,
}

# Bilinen MITRE ATT&CK teknik ID -> insan-okunur isim eslemesi. MVP
# kapsaminda yalnizca bu projede fiilen uretilen teknikleri icerir
# (bkz. Faz 2 PORT_TO_TECHNIQUE tablosu). Bilinmeyen bir ID icin
# teknigin kendisi isim olarak kullanilir (asagida _technique_name).
MITRE_TECHNIQUE_NAMES: dict[str, str] = {
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.003": "Remote Services: Distributed Component Object Model",
    "T1021.004": "Remote Services: SSH",
    "T1021.005": "Remote Services: VNC",
    "T1021.006": "Remote Services: Windows Remote Management",
    "T1078": "Valid Accounts",
}


def _technique_name(technique_id: str) -> str:
    return MITRE_TECHNIQUE_NAMES.get(technique_id, technique_id)


class WeightedMarkovPredictionModel:
    """PredictionModelPort'u agirlikli-Markov yontemiyle karsilayan
    adapter. `domain.ports.PredictionModelPort`'tan miras ALMAZ
    (Protocol, yapisal tiplemedir).
    """

    def __init__(self, relation_priors: dict[RelationType, float] | None = None) -> None:
        self._relation_priors = relation_priors or DEFAULT_RELATION_PRIORS

    def model_name(self) -> str:
        return "weighted_markov_v1"

    def predict(self, candidate_paths: list[CandidatePath]) -> PredictionResult:
        if not candidate_paths:
            raise ValueError("predict() en az bir CandidatePath gerektirir")

        target_node = self._infer_target_node(candidate_paths)

        # Adim 1: her yol icin HAM skor (hop agirliklari x iliski-tipi
        # onceligi carpimi). Bu, hop sayisina gore DEGIL, TOPLAM
        # GOZLEMLENMIS KANIT AGIRLIGINA gore siralar -- "kisa yol =
        # daha olasi" gibi bir iddia BILEREK yapilmiyor (bkz. modul
        # docstring'indeki "IKINCI DURUSTLUK NOTU").
        raw_scores: list[float] = []
        for path in candidate_paths:
            score = 1.0
            for relation, weight in zip(path.hop_relations, path.hop_weights, strict=True):
                # bkz. modul docstring'i "UCUNCU DURUSTLUK NOTU" / ADR 0017:
                # ham agirlik (gozlemlenen event SAYISI) dogrudan carpana
                # sokulmadan once log1p ile sikistirilir -- yuksek hacimli
                # mesru trafigin nadir ama gercek kanitlari ezmesini onler.
                dampened_weight = math.log1p(weight)
                score *= dampened_weight * self._relation_priors.get(relation, 1.0)
            raw_scores.append(score)

        # Adim 2: sadece SON hop'ta bilinen teknigi olan yollari
        # (technique, path, raw_score) uclulerine genislet. Teknik
        # bilinmeyen yollar (orn. sadece network_reachable, hic MITRE
        # teknigi gozlemlenmemis) bu asamada elenir -- PredictionResult
        # ozellikle MITRE teknik tahmini icindir (bkz. modul docstring'i).
        scored_predictions: list[tuple[str, CandidatePath, float]] = []
        for path, raw_score in zip(candidate_paths, raw_scores, strict=True):
            last_hop_techniques = self._last_hop_techniques(path)
            for technique_id in last_hop_techniques:
                scored_predictions.append((technique_id, path, raw_score))

        if not scored_predictions:
            return PredictionResult(
                target_node=target_node,
                predictions=(),
                model_name=self.model_name(),
                generated_at=datetime.now(UTC),
            )

        # Adim 3: normalize et (toplam = 1.0) ve azalan olasiliga gore sirala.
        total_score = sum(score for _, _, score in scored_predictions)
        predictions = tuple(
            sorted(
                (
                    TechniquePrediction(
                        technique_id=technique_id,
                        technique_name=_technique_name(technique_id),
                        probability=score / total_score,
                        contributing_path=path,
                    )
                    for technique_id, path, score in scored_predictions
                ),
                key=lambda p: p.probability,
                reverse=True,
            )
        )

        return PredictionResult(
            target_node=target_node,
            predictions=predictions,
            model_name=self.model_name(),
            generated_at=datetime.now(UTC),
        )

    @staticmethod
    def _infer_target_node(candidate_paths: list[CandidatePath]) -> str:
        """Tum adaylarin AYNI baslangic node'undan geldigi varsayilir
        (Attack Path Engine'in find_candidate_paths(start_node=X) tek
        bir X icin cagrilmasindan dogal olarak gelir). Bu varsayim
        ihlal edilirse (orn. yanlislikla farkli start_node'lardan gelen
        adaylar karistirilirsa), acikca hata veriyoruz -- sessiz yanlis
        sonuc yerine.
        """

        origins = {path.path_nodes[0] for path in candidate_paths if path.path_nodes}
        if len(origins) != 1:
            raise ValueError(
                f"Tum candidate_paths ayni baslangic node'undan gelmelidir, "
                f"bulunanlar: {sorted(origins)}"
            )
        return next(iter(origins))

    @staticmethod
    def _last_hop_techniques(path: CandidatePath) -> tuple[str, ...]:
        """Bir yolun SON hop'unda gozlemlenen teknik(ler)i dondurur.
        'Sonraki adim' tahmini, dogasi geregi EN SON gecisi (en yeni
        gozlemi) esas almalidir -- yolun ilk hop'lari zaten gozlemlenmis
        gecmisi temsil eder, tahmin edilen kisim SONdur.

        `hop_technique_ids[-1]` kullanilir (bkz. ADR 0008 guncellemesi)
        -- `plausible_techniques` TUM hop'larin birlesimi oldugu icin
        BURADA KULLANILMAZ (coklu-hop'lu bir yolda ilk hop'un teknigini
        yanlislikla 'sonraki adim' olarak sunardi).
        """

        if not path.hop_technique_ids:
            return ()
        return path.hop_technique_ids[-1]