"""
.github/scripts/test_summary.py — CI iş özeti üreticisinin testleri.

Neden bir CI yardımcısı test ediliyor
-------------------------------------
Bu betik, "testler sessizce kayboldu mu" sorusunu yanıtlamak için var.
Kendisi sessizce bozulursa tam da tespit etmesi gereken sorunun aynısını
üretir — yeşil bir CI ve yanlış sayılar. Bu yüzden ayrı bir modül ve
normal paketle birlikte koşuyor.

Betik `.github/scripts/` altında olduğu için normal import yolunda değil;
dosya konumundan yükleniyor.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / ".github" / "scripts" / "test_summary.py"


def _load():
    spec = importlib.util.spec_from_file_location("ci_test_summary", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["ci_test_summary"] = module
    spec.loader.exec_module(module)
    return module


summary = _load()


def _write(tmp_path: Path, body: str, name: str = "junit.xml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


_GERCEK = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" errors="0" failures="0" skipped="2" tests="910"
             time="83.204" timestamp="2026-08-13T14:00:00" hostname="runner">
    <testcase classname="tests.test_crypto" name="test_round_trip" time="0.1"/>
    <testcase classname="tests.test_timestamp" name="test_real_tsa" time="0">
      <skipped type="pytest.skip" message="ag yok"/>
    </testcase>
  </testsuite>
</testsuites>
"""


# ══════════════════════════════════════════════════════════════════════════════
# Sayım
# ══════════════════════════════════════════════════════════════════════════════


def test_counts_match_a_real_pytest_report(tmp_path: Path) -> None:
    totals, failed = summary.parse(_write(tmp_path, _GERCEK))
    assert totals.tests == 910
    assert totals.skipped == 2
    assert totals.failures == 0
    assert totals.errors == 0
    assert failed == []


def test_passed_excludes_skipped(tmp_path: Path) -> None:
    """
    JUnit'te `tests` atlananları DA içeriyor. Bu çıkarma yanlış olsaydı
    özet, koşmayan testleri geçmiş gibi gösterirdi — betiğin var oluş
    sebebinin tam tersi.
    """
    totals, _ = summary.parse(_write(tmp_path, _GERCEK))
    assert totals.passed == 908


def test_failures_and_errors_are_counted_and_named(tmp_path: Path) -> None:
    xml = """<testsuites><testsuite tests="4" failures="1" errors="1" skipped="1" time="2.0">
      <testcase classname="tests.test_a" name="test_ok"/>
      <testcase classname="tests.test_a" name="test_kirik"><failure>bum</failure></testcase>
      <testcase classname="tests.test_b" name="test_patlak"><error>iz</error></testcase>
      <testcase classname="tests.test_b" name="test_atlanan"><skipped/></testcase>
    </testsuite></testsuites>"""
    totals, failed = summary.parse(_write(tmp_path, xml))

    assert (totals.tests, totals.failures, totals.errors, totals.skipped) == (4, 1, 1, 1)
    assert totals.passed == 1
    assert totals.ok is False
    assert failed == ["tests.test_a::test_kirik", "tests.test_b::test_patlak"]


def test_multiple_suites_are_summed(tmp_path: Path) -> None:
    xml = """<testsuites>
      <testsuite tests="3" failures="1" errors="0" skipped="0" time="1.5"/>
      <testsuite tests="7" failures="0" errors="2" skipped="1" time="2.5"/>
    </testsuites>"""
    totals, _ = summary.parse(_write(tmp_path, xml))
    assert totals.tests == 10
    assert totals.failures == 1
    assert totals.errors == 2
    assert totals.time == pytest.approx(4.0)


def test_a_bare_testsuite_root_is_accepted(tmp_path: Path) -> None:
    """Tek <testsuite> kökü de geçerli JUnit — sarmalayıcı şart değil."""
    xml = '<testsuite tests="5" failures="0" errors="0" skipped="1" time="1.0"/>'
    totals, _ = summary.parse(_write(tmp_path, xml))
    assert (totals.tests, totals.passed) == (5, 4)


def test_missing_attributes_default_to_zero(tmp_path: Path) -> None:
    totals, _ = summary.parse(_write(tmp_path, '<testsuite tests="3"/>'))
    assert totals.passed == 3
    assert totals.ok is True


# ══════════════════════════════════════════════════════════════════════════════
# Markdown çıktısı
# ══════════════════════════════════════════════════════════════════════════════


def test_summary_shows_the_real_numbers() -> None:
    çıktı = summary.render(
        summary.Totals(tests=910, skipped=2, time=83.2), [], title="ubuntu-latest"
    )
    assert "ubuntu-latest" in çıktı
    assert "| **910** | 908 | 2 | 0 | 0 | 83s |" in çıktı
    assert "✅" in çıktı


def test_a_failing_run_is_marked_and_lists_names() -> None:
    çıktı = summary.render(
        summary.Totals(tests=10, failures=2), ["a::b", "c::d"], title="windows-latest"
    )
    assert "❌" in çıktı
    assert "`a::b`" in çıktı
    assert "`c::d`" in çıktı


def test_a_long_failure_list_is_truncated() -> None:
    adlar = [f"tests.test_x::test_{i}" for i in range(50)]
    çıktı = summary.render(summary.Totals(tests=50, failures=50), adlar, title="t")
    assert "ve 30 tane daha" in çıktı
    assert çıktı.count("- `") == 20


# ══════════════════════════════════════════════════════════════════════════════
# Bozuk girdi — özet ASLA CI'ı kırmamalı
# ══════════════════════════════════════════════════════════════════════════════


def test_a_missing_report_is_reported_not_crashed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """
    pytest XML yazmadan çökerse (toplama hatası, segfault) özet bunu
    SÖYLEMELİ. Sessiz kalmak "sorun yok" gibi görünürdü.
    """
    assert summary.main(["x", str(tmp_path / "yok.xml"), "ubuntu"]) == 0
    çıktı = capsys.readouterr().out
    assert "⚠️" in çıktı
    assert "pytest rapor yazamadan düştü" in çıktı


def test_a_corrupt_report_does_not_crash(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    assert summary.main(["x", str(_write(tmp_path, "<bu xml degil"))]) == 0
    assert "ayrıştırılamadı" in capsys.readouterr().out


def test_output_survives_a_non_utf8_locale(tmp_path: Path) -> None:
    """
    GERÇEK BİR HATANIN TESTİ.

    Windows koşucusunda Python, yönlendirilmiş stdout için yerel kod
    sayfasını seçiyor; tablodaki ✅ ve Türkçe başlıklar UnicodeEncodeError
    ile düşüyordu. Betik alt süreç olarak, cp1252 dayatılarak çalıştırılıyor
    — düzeltme geri alınırsa bu test kırılır.

    Düzeltmenin kendisi artık `CORE.console.ensure_utf8_console()`; bu test
    onun BU BETİKTE etkili olduğunu sınıyor. Yardımcının kendi testleri
    tests/test_console.py içinde.
    """
    import os
    import subprocess

    rapor = _write(tmp_path, _GERCEK)
    ortam = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    sonuc = subprocess.run(
        [sys.executable, str(_SCRIPT), str(rapor), "ubuntu-latest · Python 3.11"],
        capture_output=True, env=ortam,
    )

    assert sonuc.returncode == 0, sonuc.stderr.decode("utf-8", "replace")
    çıktı = sonuc.stdout.decode("utf-8")
    assert "✅" in çıktı
    assert "Geçen" in çıktı
    assert "| **910** | 908 | 2 |" in çıktı


def test_the_script_never_fails_the_build(tmp_path: Path) -> None:
    """
    Betik RAPORLAR, karar vermez. Sıfırdan farklı bir çıkış, zaten kırmızı
    olan bir adımın üstüne ikinci bir hata ekler ve asıl sebebi gölgelerdi.
    """
    kirik = _write(tmp_path, '<testsuite tests="1" failures="1"><testcase name="x">'
                             '<failure/></testcase></testsuite>')
    assert summary.main(["x", str(kirik)]) == 0
    assert summary.main(["x"]) == 0


# ══════════════════════════════════════════════════════════════════════════════
# --annotations kipi
# ══════════════════════════════════════════════════════════════════════════════

_KIRIK = """<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" errors="1" failures="1" skipped="0" tests="3" time="1.5">
  <testcase classname="tests.test_a" name="test_gecen"/>
  <testcase classname="tests.test_b" name="test_dusen"><failure/></testcase>
  <testcase classname="tests.test_c" name="test_hatali"><error/></testcase>
</testsuite>
"""


def test_annotations_basarisiz_adlari_workflow_komutu_olarak_basar(
    tmp_path: Path, capsys
) -> None:
    """
    ASIL DEĞERİ BURADA: annotation'lar check-run API'sinden yetkisiz
    okunabiliyor; özet tablosu ve iş günlükleri okunamıyor. Bir CI
    hatasının hangi testte olduğunu tarayıcı olmadan öğrenmenin tek yolu.
    """
    rapor = _write(tmp_path, _KIRIK)
    assert summary.main(["x", str(rapor), "ubuntu · 3.11", "--annotations"]) == 0
    cikti = capsys.readouterr().out

    assert "tests.test_b::test_dusen" in cikti
    assert "tests.test_c::test_hatali" in cikti
    assert "tests.test_a::test_gecen" not in cikti
    for satir in cikti.strip().splitlines():
        assert satir.startswith("::error title="), satir
    # Markdown tablosu KARIŞMAMALI — bu çıktı günlük akışına gidiyor.
    assert "|" not in cikti


# ══════════════════════════════════════════════════════════════════════════════
# Annotation'lar "HANGI test"in yanina "NEDEN"i de koyuyor mu
# ══════════════════════════════════════════════════════════════════════════════
#
# Ilk surum yalnizca adi basiyordu ve o yarim bir cozumdu: `85c6dcc`'te
# ubuntu ayagi kirildiginda hangi bes testin dustugu okunabildi ama NICIN
# dustukleri okunamadi — mesaj yalnizca yonetici yetkisi isteyen gunlukte
# ve artifact'teydi.

_MESAJLI = """<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" errors="0" failures="1" skipped="0" tests="1" time="1.0">
  <testcase classname="tests.test_a" name="test_dusen">
    <failure message="AttributeError: nesnede '_tsa_liste' yok">govde metni</failure>
  </testcase>
</testsuite>
"""


def test_annotation_mesaji_da_basiyor(tmp_path: Path, capsys) -> None:
    """Adin yanina hata mesajinin ILK satiri geliyor."""
    rapor = _write(tmp_path, _MESAJLI)
    assert summary.main(["x", str(rapor), "ubuntu", "--annotations"]) == 0
    cikti = capsys.readouterr().out
    assert "tests.test_a::test_dusen" in cikti
    assert "AttributeError: nesnede '_tsa_liste' yok" in cikti


def test_parse_mesaji_TASIYOR(tmp_path: Path) -> None:
    """
    `parse()` geriye donuk uyumlu: donen deger duz dizeyle esit ama
    ustunde `mesaj` var.
    """
    _totals, failed = summary.parse(_write(tmp_path, _MESAJLI))
    assert failed == ["tests.test_a::test_dusen"]
    assert failed[0].mesaj == "AttributeError: nesnede '_tsa_liste' yok"


def test_mesaj_yoksa_GOVDE_metnine_dusuluyor(tmp_path: Path) -> None:
    """
    pytest kisa hatalarda `message` niteligini doldurur, uzun `assert`
    dokumlerinde asil metin govdede olur — ikisi de okunabilmeli.
    """
    xml = (
        '<testsuite tests="1" failures="1">'
        '<testcase classname="t" name="a"><failure>ilk satir' + chr(10) + 'ikinci</failure></testcase>'
        '</testsuite>'
    )
    _totals, failed = summary.parse(_write(tmp_path, xml))
    assert failed[0].mesaj == "ilk satir", "govde metnine dusulmedi ya da coklu satir alindi"


def test_YALNIZCA_ilk_satir_aliniyor(tmp_path: Path) -> None:
    """Annotation tek satirlik bir yuzey; tam traceback JUnit XML'inde."""
    # Gercek pytest, nitelik icindeki satir sonunu `&#10;` olarak yaziyor.
    # DUZ bir satir sonu kullanilamaz: XML nitelik degeri normalizasyonu onu
    # BOSLUGA cevirir (olculdu) ve test hicbir sey kanitlamamis olurdu.
    xml = (
        '<testsuite tests="1" failures="1">'
        '<testcase classname="t" name="a">'
        '<failure message="ilk&#10;ikinci&#10;ucuncu">x</failure>'
        '</testcase></testsuite>'
    )
    _totals, failed = summary.parse(_write(tmp_path, xml))
    assert failed[0].mesaj == "ilk"


def test_uzun_mesaj_kirpiliyor(tmp_path: Path) -> None:
    uzun = "A" * 500
    xml = (
        '<testsuite tests="1" failures="1">'
        '<testcase classname="t" name="a"><failure message="' + uzun + '">x</failure>'
        '</testcase></testsuite>'
    )
    _totals, failed = summary.parse(_write(tmp_path, xml))
    assert len(failed[0].mesaj) <= summary._MESAJ_SINIRI
    assert failed[0].mesaj.endswith("…")


def test_yuzde_isareti_KACILIYOR(tmp_path: Path, capsys) -> None:
    """
    GitHub `%` isaretini workflow komutunda ozel okuyor; kacilmazsa mesaj
    kirpilir. Gercek bir `assert` ciktisinda yuzde bolca gecer.
    """
    xml = (
        '<testsuite tests="1" failures="1">'
        '<testcase classname="t" name="a"><failure message="assert 50%25 != 100%25">x</failure>'
        '</testcase></testsuite>'
    ).replace("%25", "%")
    rapor = _write(tmp_path, xml)
    assert summary.main(["x", str(rapor), "ubuntu", "--annotations"]) == 0
    cikti = capsys.readouterr().out
    assert "assert 50%25 != 100%25" in cikti, cikti


def test_DUZ_DIZE_listesiyle_de_calisiyor() -> None:
    """
    `render_annotations` disaridan duz dize listesiyle de cagrilabiliyor;
    `mesaj` yoksa eskisi gibi yalnizca ad basilmali.
    """
    cikti = summary.render_annotations(["a::b"], title="t")
    assert cikti.strip() == "::error title=Basarisiz test (t)::a::b"


def test_mesaj_OZET_tablosuna_karismiyor(tmp_path: Path, capsys) -> None:
    """
    Genisletilen sey yalnizca annotation. Ozet tablosu adlari listeliyor;
    oraya da mesaj eklemek tabloyu okunmaz yapardi.
    """
    rapor = _write(tmp_path, _MESAJLI)
    assert summary.main(["x", str(rapor), "ubuntu"]) == 0
    cikti = capsys.readouterr().out
    assert "tests.test_a::test_dusen" in cikti
    assert "AttributeError" not in cikti


def test_annotations_gecen_kosuda_sessiz(tmp_path: Path, capsys) -> None:
    """Hiçbir test düşmediyse tek bir annotation bile basılmamalı."""
    rapor = _write(tmp_path, _GERCEK)
    assert summary.main(["x", str(rapor), "t", "--annotations"]) == 0
    assert capsys.readouterr().out == ""


def test_annotations_rapor_yoksa_da_konusur(tmp_path: Path, capsys) -> None:
    """
    pytest XML yazamadan çöktüyse (toplama hatası, segfault) sessizlik en
    kötü sonuç: adım kırmızı ama hiçbir yerde sebep yok.
    """
    assert summary.main(["x", str(tmp_path / "yok.xml"), "t", "--annotations"]) == 0
    cikti = capsys.readouterr().out
    assert cikti.startswith("::error title=Test raporu yok::")


def test_bayrak_konumdan_bagimsiz(tmp_path: Path, capsys) -> None:
    """`--annotations` başta verilse de çalışmalı — yol/başlık ayrıştırması
    bayrakları konumsal argüman sanmamalı."""
    rapor = _write(tmp_path, _KIRIK)
    assert summary.main(["x", "--annotations", str(rapor), "t"]) == 0
    assert "::error" in capsys.readouterr().out


# ══════════════════════════════════════════════════════════════════════════════
# B-019 — defusedxml
# ══════════════════════════════════════════════════════════════════════════════


def test_defusedxml_kullaniliyor() -> None:
    """
    Ayrıştırıcı gerçekten `defusedxml` mi.

    `XML_KORUMALI` bayrağı yalnızca import'un hangi dala girdiğini
    söylüyor; bu test onun DOĞRU dal olduğunu da denetliyor — geliştirme
    ve CI ortamlarında defusedxml kurulu (requirements-dev.txt).
    """
    assert summary.XML_KORUMALI is True, (
        "defusedxml kurulu değil — requirements-dev.txt'ten düşmüş olabilir"
    )
    assert summary._xml_parse.__module__.startswith("defusedxml")


def test_billion_laughs_reddediliyor(tmp_path: Path, capsys) -> None:
    """
    B-019'UN ASIL KAZANCI — iç varlık genişlemesi.

    Stdlib ElementTree bu belgeyi genişletmeye çalışır; defusedxml onu
    ayrıştırmadan reddediyor.
    """
    kotu = tmp_path / "kotu.xml"
    kotu.write_text(
        """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<testsuites><testsuite tests="1" name="&lol3;"/></testsuites>
""",
        encoding="utf-8",
    )
    with pytest.raises(summary.XML_HATALARI):
        summary.parse(kotu)


def test_dusmanca_xml_betigi_dusurmuyor(tmp_path: Path, capsys) -> None:
    """
    KORUMA EKLENİRKEN RAPORLAMA BOZULMAMALI.

    defusedxml saldırıyı `ParseError` ile DEĞİL kendi istisnasıyla
    reddediyor. `XML_HATALARI` demeti onu içermeseydi betik temiz bir
    mesaj yerine izlemeyle düşerdi — yani güvenlik düzeltmesi, betiğin
    tek işini (CI'ın durumunu söylemek) bozardı.
    """
    kotu = tmp_path / "kotu.xml"
    kotu.write_text(
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE t [<!ENTITY a "aa"><!ENTITY b "&a;&a;&a;">]>\n'
        '<testsuites><testsuite tests="1" name="&b;"/></testsuites>\n',
        encoding="utf-8",
    )
    kod = summary.main(["x", str(kotu)])
    cikti = capsys.readouterr().out

    assert kod == 0, "betik derlemeyi düşürmemeli"
    assert "ayrıştırılamadı" in cikti


def test_stdlib_dalinda_da_calisiyor(tmp_path: Path, monkeypatch, capsys) -> None:
    """
    `defusedxml` YOKSA betik yine çalışmalı.

    Koşullu import'un gerekçesi buydu: betik CI dışında da elle
    çalıştırılıyor ve bir bağımlılık eksikliği yüzünden hiç konuşmaması,
    raporladığı sorundan kötü olurdu.
    """
    from xml.etree.ElementTree import parse as stdlib_parse

    monkeypatch.setattr(summary, "_xml_parse", stdlib_parse)
    monkeypatch.setattr(summary, "XML_HATALARI", (summary.ParseError,))

    rapor = tmp_path / "r.xml"
    rapor.write_text(
        '<testsuites><testsuite tests="3" failures="0" errors="0"'
        ' skipped="1" time="1.5"/></testsuites>',
        encoding="utf-8",
    )
    assert summary.main(["x", str(rapor)]) == 0
    assert "3" in capsys.readouterr().out
