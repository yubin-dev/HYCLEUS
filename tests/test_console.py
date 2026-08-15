"""
CORE.console — konsol kodlaması yardımcısının testleri.

Bu yardımcı, projede İKİ KEZ ayrı ayrı bulunan bir hatanın tek noktaya
toplanmış hâli (bkz. CORE/console.py). Dolayısıyla asıl sınanması gereken
şey, yardımcının gerçek bir akış kodlamasında işe yarayıp yaramadığı.

Neden alt süreç
---------------
`capsys` gerçek bir akış kodlaması KULLANMIYOR — yakalayıcı akış her
karakteri kabul eder. Hatanın iki kez gözden kaçmasının sebebi tam olarak
buydu. Bu yüzden kritik testler `PYTHONIOENCODING=cp1252` dayatılmış bir
alt süreçte koşuyor: kodlama gerçekten cp1252 oluyor ve düzeltme geri
alınırsa test kırılıyor.
"""
from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

from CORE.console import ensure_utf8_console

_ROOT = Path(__file__).resolve().parent.parent

#: cp1252'de kodlanamayan üç sınıf: kutu çizgisi, emoji, Türkçe harf.
_ZOR = "└─ ⚠️ ışğ"


def _alt_surec(kod: str, encoding: str = "cp1252") -> subprocess.CompletedProcess:
    """Verilen kodu, kodlaması dayatılmış bir alt süreçte çalıştırır."""
    return subprocess.run(
        [sys.executable, "-c", kod],
        capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": encoding},
        cwd=str(_ROOT),
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. Asıl iş — gerçek bir akış kodlamasında
# ══════════════════════════════════════════════════════════════════════════════


def test_non_ascii_output_fails_without_the_helper() -> None:
    """
    ÖNCE HATAYI GÖSTER. Yardımcı çağrılmazsa cp1252 konsolunda çöküyor —
    yani bu testler bir varsayımı değil, gerçek bir davranışı sınıyor.
    """
    sonuc = _alt_surec(f"print({_ZOR!r})")
    assert sonuc.returncode != 0
    assert b"UnicodeEncodeError" in sonuc.stderr


def test_the_helper_makes_non_ascii_output_work() -> None:
    """Aynı çıktı, yardımcı çağrıldıktan sonra sorunsuz yazılıyor."""
    sonuc = _alt_surec(
        "from CORE.console import ensure_utf8_console\n"
        "ensure_utf8_console()\n"
        f"print({_ZOR!r})"
    )
    assert sonuc.returncode == 0, sonuc.stderr.decode("utf-8", "replace")
    assert b"Traceback" not in sonuc.stderr
    assert sonuc.stdout.decode("utf-8").strip() == _ZOR


def test_stderr_is_reconfigured_too() -> None:
    """Hata mesajları da Türkçe — stdout'u düzeltip stderr'i bırakmak yarım iş."""
    sonuc = _alt_surec(
        "import sys\n"
        "from CORE.console import ensure_utf8_console\n"
        "ensure_utf8_console()\n"
        f"print({_ZOR!r}, file=sys.stderr)"
    )
    assert sonuc.returncode == 0
    assert sonuc.stderr.decode("utf-8").strip() == _ZOR


def test_a_turkish_codepage_also_fails_on_box_characters() -> None:
    """
    "Türkçe Windows'ta çalışıyor" YETERLİ DEĞİL.

    cp1254 Türkçe harfleri kodlayabiliyor ama kutu çizgilerini ve emojiyi
    kodlayamıyor. Yardımcı ikisini de kurtarıyor.
    """
    kirik = _alt_surec("print('└─ ⚠️')", encoding="cp1254")
    assert kirik.returncode != 0

    duzgun = _alt_surec(
        "from CORE.console import ensure_utf8_console\n"
        "ensure_utf8_console()\n"
        "print('└─ ⚠️')",
        encoding="cp1254",
    )
    assert duzgun.returncode == 0


# ══════════════════════════════════════════════════════════════════════════════
# 2. Güvenli çağrılabilirlik
# ══════════════════════════════════════════════════════════════════════════════


def test_streams_can_be_passed_explicitly() -> None:
    class _Akis:
        def __init__(self) -> None:
            self.cagrilar: list[dict] = []

        def reconfigure(self, **kw) -> None:
            self.cagrilar.append(kw)

    a, b = _Akis(), _Akis()
    ensure_utf8_console(a, b)
    assert a.cagrilar == [{"encoding": "utf-8", "errors": "replace"}]
    assert b.cagrilar == a.cagrilar


def test_a_stream_without_reconfigure_is_skipped() -> None:
    """StringIO ve pytest'in yakalayıcısı `reconfigure` taşımıyor."""
    ensure_utf8_console(io.StringIO())  # istisna fırlatmamalı


def test_a_failing_reconfigure_is_swallowed() -> None:
    """
    Yardımcının kendisi hiçbir aracı kırmamalı: görevi bir hatayı
    önlemek, yenisini eklemek değil.
    """
    class _Kapali:
        def reconfigure(self, **kw):
            raise ValueError("underlying buffer has been detached")

    ensure_utf8_console(_Kapali())  # istisna fırlatmamalı


def test_errors_replace_is_used_not_strict() -> None:
    """
    'strict' olsaydı yardımcı sorunu çözmek yerine yerini değiştirirdi.
    Bir denetim aracının '?' yazması, tamamen çökmesinden iyidir.
    """
    class _Akis:
        kw: dict = {}

        def reconfigure(self, **kw):
            _Akis.kw = kw

    ensure_utf8_console(_Akis())
    assert _Akis.kw["errors"] == "replace"


def test_calling_it_twice_is_harmless() -> None:
    ensure_utf8_console()
    ensure_utf8_console()


# ══════════════════════════════════════════════════════════════════════════════
# 3. Çağrı yerleri gerçekten yardımcıyı kullanıyor mu
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("yol", [
    "CORE/verify_timestamp_cli.py",
    ".github/scripts/test_summary.py",
])
def test_the_known_call_sites_use_the_helper(yol: str) -> None:
    """
    Bu iki araç kendi kopyasına geri dönerse yakalansın.

    Kopyaya dönmek sessiz bir gerileme olurdu: araç çalışmaya devam eder,
    yalnızca düzeltme tek noktadan yönetilemez hâle gelir.
    """
    src = (_ROOT / yol).read_text(encoding="utf-8")
    assert "ensure_utf8_console" in src
    assert "reconfigure(encoding=" not in src.replace(
        # test_summary.py'deki ImportError yedeği bilinçli — bkz. oradaki yorum
        "_akis.reconfigure(encoding=\"utf-8\", errors=\"replace\")", ""
    )
