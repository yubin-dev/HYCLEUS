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
