"""
HYCLEUS — pytest JUnit XML'ini GitHub iş özetine (job summary) çevirir.

Neden bu betik var
------------------
CI'ın `pytest` adımı yeşil yandığında yalnızca "çıkış kodu 0" bilgisi
görünüyordu. Kaç testin KOŞTUĞU görünmüyordu ve depo günlüklerini indirmek
yönetici yetkisi istiyor (API 403 veriyor). Aradaki boşluk teorik değil:
2.7 Faz 2'de `tests/test_lock_overlay.py` bir import hatası yüzünden
sessizce atlanmaya başlamış, 24 test yok olmuş ama paket yeşil kalmıştı.
Çıkış kodu bunu yakalayamaz; test SAYISI yakalar.

Bu yüzden sayılar Actions sekmesinde, günlüğe inmeden görünür oluyor.

Neden ayrı bir Python dosyası (satır içi kabuk değil)
-----------------------------------------------------
İki koşucu iki farklı kabuk kullanıyor ve satır içi bir betik test
EDİLEMEZ. Bu dosyanın kendi testleri var (tests/test_ci_summary.py) —
CI'ın kendi raporlama aracının sessizce bozulması, raporladığı sorunun
aynısı olurdu.

Kullanım:
    python .github/scripts/test_summary.py test-results.xml >> $GITHUB_STEP_SUMMARY
"""
from __future__ import annotations

import sys

from dataclasses import dataclass
from pathlib import Path

# XML ayrıştırıcı — `defusedxml` varsa O kullanılıyor (B-019).
#
# ElementTree "billion laughs" iç varlık genişlemesine açık (dış varlık
# çözümlemesi zaten desteklenmiyor). Buradaki girdi AYNI CI işinde bir
# önceki adımda pytest'in ürettiği `test-results.xml`, yani düşmanca XML
# yazabilen biri zaten CI çalışma alanında kod çalıştırabiliyor demek —
# SECURITY.md §1'in sınırının içinde. Bulgu bu yüzden bir süre bilinçli
# olarak açık bırakılmıştı.
#
# Neden şimdi eklendi: maliyeti iki satır ve `defusedxml` saf Python,
# bağımlılıksız, ~30 KB. "Bağımlılık yüzeyini büyütme" gerekçesi bu ölçekte
# bulgu sayısını sıfırda tutmaktan daha ağır basmıyordu.
#
# İTHALAT KOŞULLU, bilerek: bu betik CI dışında da elle çalıştırılıyor
# (`--annotations` kipi dahil) ve `defusedxml` kurulu olmayan bir ortamda
# ÇALIŞMAYI SÜRDÜRMESİ gerekiyor. Sert bir import, test özetini bir
# bağımlılık eksikliği yüzünden hiç basmamak demek olurdu — özet en çok da
# işler kötü giderken lazım.

# `ParseError` her iki durumda da aynı sınıf: defusedxml ElementTree'yi
# sarmalıyor, değiştirmiyor.
# nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
from xml.etree.ElementTree import ParseError

try:
    from defusedxml.ElementTree import parse as _xml_parse
    from defusedxml.common import DefusedXmlException

    XML_KORUMALI = True
    #: Bozuk VEYA düşmanca XML. defusedxml saldırıyı ayrı bir istisnayla
    #: reddediyor; onu yakalamazsak betik temiz bir mesaj yerine izlemeyle
    #: düşerdi — yani korumayı eklerken raporlamayı bozardık.
    XML_HATALARI: tuple[type[Exception], ...] = (ParseError, DefusedXmlException)
except ImportError:  # pragma: no cover — CI'da defusedxml kurulu
    # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
    from xml.etree.ElementTree import parse as _xml_parse

    XML_KORUMALI = False
    XML_HATALARI = (ParseError,)

# Bu betik `.github/scripts/` altindan calisiyor, yani sys.path[0] depo koku
# degil. Kok elle ekleniyor — CORE/recover_vault.py ile ayni desen.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

try:
    from CORE.console import ensure_utf8_console  # noqa: E402
except ImportError:  # pragma: no cover — depo yapisi bozuksa
    # Bu betigin gorevi CI'in NE DURUMDA oldugunu soylemek; bu yuzden CORE
    # import edilemedigi durumda bile bir sey yazabilmeli. Kucuk bir
    # tekrar, "pytest hic rapor yazamadan dustu" mesajini kaybetmekten iyi.
    def ensure_utf8_console() -> None:  # type: ignore[misc]
        for _akis in (sys.stdout, sys.stderr):
            if hasattr(_akis, "reconfigure"):
                _akis.reconfigure(encoding="utf-8", errors="replace")

#: Özette listelenecek en fazla başarısız test. Yüzlerce hata varsa iş
#: özetini taşırmak yerine ilk birkaçını gösterip geri kalanı sayıyoruz.
_MAX_LISTED = 20

#: Annotation'a giren mesajin ust siniri. Annotation tek satirlik bir
#: yuzey; uzun bir `assert` dokumu onu okunmaz yapardi.
_MESAJ_SINIRI = 220


@dataclass(frozen=True)
class Totals:
    """Bir JUnit raporunun sayıları."""

    tests: int = 0
    failures: int = 0
    errors: int = 0
    skipped: int = 0
    time: float = 0.0

    @property
    def passed(self) -> int:
        """
        Geçen test sayısı.

        JUnit'te `tests` özniteliği atlananları DA içeriyor; geçen sayısı
        ayrı bir alan olarak yok, çıkarmayla bulunuyor.
        """
        return self.tests - self.failures - self.errors - self.skipped

    @property
    def ok(self) -> bool:
        return self.failures == 0 and self.errors == 0


def parse(path: Path) -> tuple[Totals, list[str]]:
    """
    JUnit XML'ini okur; (toplamlar, başarısız test adları) döndürür.

    pytest kök öğe olarak <testsuites> yazıyor ama tek bir <testsuite> de
    geçerli JUnit — ikisi de destekleniyor.
    """
    # YANLIŞ POZİTİF, ve gerekçesi B-019 öncesinden FARKLI: `_xml_parse`
    # artık `defusedxml.ElementTree.parse` (yukarıdaki koşullu import).
    # semgrep takma adın arkasını göremediği için yine `xml.etree` sanıyor.
    # Eskiden bu susturma "riski kabul ediyoruz" demekti; şimdi "araç
    # düzeltmeyi göremiyor" diyor.
    # nosemgrep: python.lang.security.use-defused-xml-parse.use-defused-xml-parse
    root = _xml_parse(path).getroot()
    suites = (
        [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    )

    toplam = Totals()
    for suite in suites:
        toplam = Totals(
            tests=toplam.tests + int(suite.get("tests", 0)),
            failures=toplam.failures + int(suite.get("failures", 0)),
            errors=toplam.errors + int(suite.get("errors", 0)),
            skipped=toplam.skipped + int(suite.get("skipped", 0)),
            time=toplam.time + float(suite.get("time", 0.0)),
        )

    basarisiz: list[Basarisiz] = []
    for case in root.iter("testcase"):
        dugum = case.find("failure")
        if dugum is None:
            dugum = case.find("error")
        if dugum is None:
            continue
        sinif = case.get("classname", "")
        ad = case.get("name", "?")
        basarisiz.append(Basarisiz(
            f"{sinif}::{ad}" if sinif else ad, _ilk_satir(dugum)
        ))

    return toplam, basarisiz


class Basarisiz(str):
    """
    Basarisiz bir testin kimligi — ustune `mesaj` tasiyor.

    Neden `str` alt sinifi, ayri bir dataclass degil: bu deger
    `render()` icinde dogrudan bicimlendiriliyor ve `tests/
    test_ci_summary.py` onu duz dizelerle karsilastiriyor. `str`den
    turemek her iki cagri yerini de DEGISMEDEN birakiyor; ayri bir tip
    ikisini de dokunmayi gerektirirdi ve bu dosya CI'in kendi raporlama
    araci — degistirilen her satiri odemek gerekiyor.
    """

    mesaj: str

    def __new__(cls, ad: str, mesaj: str = "") -> "Basarisiz":
        nesne = super().__new__(cls, ad)
        nesne.mesaj = mesaj
        return nesne


def _ilk_satir(dugum) -> str:  # type: ignore[no-untyped-def]
    """
    `<failure message="...">` iceriginin TEK satirlik ozeti.

    `message` niteligi yoksa govde metnine dusuluyor: pytest kisa
    hatalarda niteligi doldurur, uzun `assert` dokumlerinde asil metin
    govdede olur.

    Yalnizca ILK satir aliniyor. Annotation tek satirlik bir yuzey ve
    tam traceback zaten JUnit XML'inde duruyor; buranin isi "hangi test"
    bilgisinin yanina "neden" bilgisini koymak, gunlugu kopyalamak degil.
    """
    ham = (dugum.get("message") or dugum.text or "").strip()
    if not ham:
        return ""
    ilk = ham.splitlines()[0].strip()
    return ilk[:_MESAJ_SINIRI - 1] + "…" if len(ilk) > _MESAJ_SINIRI else ilk


def _komut_kacisi(metin: str) -> str:
    """
    Workflow komutunun VERI kismi icin kacis.

    GitHub `%`, satir basi ve satir sonunu ozel okuyor; kacilmazsa mesaj
    kirpilir ya da komut bozulur. Sira onemli: `%` ONCE, yoksa sonradan
    eklenen `%25`'lerin kendisi tekrar kacilirdi.
    """
    return (metin.replace("%", "%25")
                 .replace("\r", "%0D")
                 .replace("\n", "%0A"))


def render(totals: Totals, failed: list[str], *, title: str) -> str:
    """İş özetine yazılacak markdown."""
    isaret = "✅" if totals.ok else "❌"
    satirlar = [
        f"### {isaret} {title}",
        "",
        "| Toplam | Geçen | Atlanan | Başarısız | Hata | Süre |",
        "|---:|---:|---:|---:|---:|---:|",
        f"| **{totals.tests}** | {totals.passed} | {totals.skipped} |"
        f" {totals.failures} | {totals.errors} | {totals.time:.0f}s |",
    ]

    if failed:
        satirlar += ["", f"**Başarısız ({len(failed)}):**", ""]
        satirlar += [f"- `{ad}`" for ad in failed[:_MAX_LISTED]]
        if len(failed) > _MAX_LISTED:
            satirlar.append(f"- … ve {len(failed) - _MAX_LISTED} tane daha")

    return "\n".join(satirlar) + "\n"


def render_annotations(failed: list[str], *, title: str) -> str:
    """
    Başarısız test adlarını GitHub Actions *annotation* komutu olarak yazar.

    Neden ayrı bir kip
    ------------------
    Özet tablosu `$GITHUB_STEP_SUMMARY`'ye yönlendiriliyor ve orada duran
    bir şey **yalnızca oturum açmış bir tarayıcıdan** okunabiliyor. İş
    günlükleri de öyle: `GET /actions/jobs/<id>/logs` yetkisiz istekte
    "Must have admin rights" diyor, herkese açık bir depoda bile.

    Annotation'lar farklı: check-run API'sinden **yetkisiz okunabiliyorlar**.
    Yani bir CI hatasının hangi testte olduğunu öğrenmenin, tarayıcıya
    girmeden mümkün olan tek yolu bu.

    Bu bir kolaylık değil, bir gereklilikti: 3.5 turunda Windows ayağı
    kırıldı ve hangi testin düştüğü hiçbir yerden okunamadı.

    NEDEN bilgisi de burada
    -----------------------
    İlk sürüm yalnızca test ADINI basıyordu ve o yarım kalmış bir
    çözümdü: `85c6dcc`'te ubuntu ayağı kırıldığında hangi beş testin
    düştüğü okunabildi ama NİÇİN düştükleri okunamadı — mesaj yalnızca
    yönetici yetkisi isteyen günlükte ve artifact'teydi.

    Artık `<failure message=...>`'in ilk satırı da ekleniyor. Tam
    traceback hâlâ JUnit XML'inde; buradaki iş bir satırlık bir ipucu
    vermek, günlüğü kopyalamak değil.

    Mesajı OLMAYAN girdiler eskisi gibi yalnızca adla basılıyor: bu
    fonksiyon düz dize listeleriyle de çağrılabiliyor ve öyle
    çağrıldığında bozulmamalı.
    """
    if not failed:
        return ""
    satirlar = [
        f"::error title=Basarisiz test ({title})::{ad}"
        + (f" — {_komut_kacisi(getattr(ad, 'mesaj', ''))}"
           if getattr(ad, "mesaj", "") else "")
        for ad in failed[:_MAX_LISTED]
    ]
    if len(failed) > _MAX_LISTED:
        satirlar.append(
            f"::error title=Basarisiz test ({title})::"
            f"… ve {len(failed) - _MAX_LISTED} tane daha"
        )
    return "\n".join(satirlar) + "\n"


def main(argv: list[str]) -> int:
    """
    Her zaman 0 döndürür — bu betik RAPORLAR, karar vermez.

    Sıfırdan farklı bir çıkış, zaten kırmızı olan bir adımın üstüne ikinci
    bir hata eklerdi ve asıl sebebi gölgeleyebilirdi. Testlerin geçip
    geçmediğine `pytest` adımının kendisi karar veriyor.

    `--annotations` verilirse markdown tablosu yerine GitHub Actions
    annotation komutları basılır (bkz. `render_annotations`).
    """
    # Ilk satir, herhangi bir print()'ten once. GITHUB_STEP_SUMMARY UTF-8
    # bekliyor; Windows kosucusu yerel kod sayfasini seciyor ve tablodaki
    # ✅/❌ ile Turkce basliklar dusuyor. Gerekce CORE/console.py'de.
    ensure_utf8_console()

    bayraklar = [a for a in argv[1:] if a.startswith("--")]
    konum = [a for a in argv[1:] if not a.startswith("--")]
    annotations = "--annotations" in bayraklar

    if not konum:
        print("kullanım: test_summary.py <junit.xml> [başlık] [--annotations]",
              file=sys.stderr)
        return 0

    path = Path(konum[0])
    title = konum[1] if len(konum) > 1 else "Test sonuçları"

    if annotations and not path.exists():
        print(f"::error title=Test raporu yok::{path} bulunamadı — "
              "pytest rapor yazamadan düştü.")
        return 0

    if not path.exists():
        # pytest XML yazmadan çöktüyse (toplama hatası, segfault) özet yine
        # bir şey söylemeli — sessiz kalmak "sorun yok" gibi görünürdü.
        print(f"### ⚠️ {title}\n\n`{path}` bulunamadı — pytest rapor yazamadan düştü.\n")
        return 0

    try:
        totals, failed = parse(path)
    except XML_HATALARI as exc:
        if annotations:
            print(f"::error title=Rapor bozuk::{path} ayrıştırılamadı: {exc}")
        else:
            print(f"### ⚠️ {title}\n\n`{path}` ayrıştırılamadı: {exc}\n")
        return 0

    if annotations:
        print(render_annotations(failed, title=title), end="")
    else:
        print(render(totals, failed, title=title))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
