"""
Paketleme yapılandırması — Windows .spec ve Linux AppImage.

Neden bu dosya var
------------------
Paketleme, CI'ın en geç haber veren parçası: bir spec dosyası yanlış
olduğunda testler yeşil kalır, uygulama geliştirme ortamında sorunsuz
çalışır ve hata ancak DAĞITILAN yapıyı biri açtığında görünür.

Buradaki testlerin çoğu yapı ÜRETMİYOR (o CI'ın `appimage` işinde, gerçek
bir Linux koşucusunda). Ölçtükleri şey, yapının bağlı olduğu sözleşmeler:
elle tutulan modül listesi güncel mi, .desktop dosyasının simge adı gerçek
dosyayla eşleşiyor mu, betikler LF ile mi duruyor.

main.py İÇE AKTARILMIYOR — AST ile okunuyor. main.py modül seviyesinde
PySide6 ve UI/ import ediyor; başsız bir koşucuda Qt'nin sistem
kütüphanelerini çekmesi bu testleri paketlemeyle ilgisiz bir sebeple
kırardı.
"""
from __future__ import annotations

import ast
import configparser
from pathlib import Path

import pytest

KOK = Path(__file__).resolve().parent.parent
PAKET = KOK / "packaging" / "linux"

WINDOWS_SPEC = KOK / "HYCLEUS.spec"
LINUX_SPEC   = KOK / "HYCLEUS-linux.spec"


def _sabit(dosya: Path, ad: str) -> object:
    """Modülü içe aktarmadan bir modül seviyesi sabitini okur."""
    agac = ast.parse(dosya.read_text(encoding="utf-8"))
    for dugum in agac.body:
        hedefler = (
            [dugum.target] if isinstance(dugum, ast.AnnAssign)
            else dugum.targets if isinstance(dugum, ast.Assign)
            else []
        )
        for hedef in hedefler:
            if isinstance(hedef, ast.Name) and hedef.id == ad and dugum.value:
                return ast.literal_eval(dugum.value)
    raise AssertionError(f"{dosya.name} içinde {ad} bulunamadı")


# ── --selftest modül listesi ──────────────────────────────────────────────────

def _depodaki_moduller() -> set[str]:
    bulunan = set()
    for paket in ("CORE", "DB"):
        for yol in (KOK / paket).glob("*.py"):
            if yol.stem == "__init__":
                continue
            bulunan.add(f"{paket}.{yol.stem}")
    return bulunan


def test_selftest_listesi_depodaki_her_modulu_kapsiyor():
    """
    Liste elle tutuluyor; elle tutulan listeler sessizce eskir.

    Yeni bir CORE/ modülü eklenip listeye girmezse --selftest onu hiç
    denemez ve donmuş yapıda EKSİK kalması fark edilmez. Bu test o boşluğu
    ekleyen commit'te kapatıyor.
    """
    listede = set(_sabit(KOK / "main.py", "_SELFTEST_MODULLERI"))
    depoda = _depodaki_moduller()

    eksik = depoda - listede
    assert not eksik, (
        "Bu modüller main.py::_SELFTEST_MODULLERI listesinde yok:\n  "
        + "\n  ".join(sorted(eksik))
    )


def test_selftest_listesinde_olmayan_modul_yok():
    """Ters yön: silinmiş bir modül listede kalırsa --selftest hep kırılır."""
    listede = set(_sabit(KOK / "main.py", "_SELFTEST_MODULLERI"))
    fazla = listede - _depodaki_moduller()
    assert not fazla, f"Artık var olmayan modüller listede: {sorted(fazla)}"


def test_ucuncu_taraf_listesi_fonksiyon_ici_importlari_kapsiyor():
    """
    Liste, PyInstaller'ın gözden kaçırma İHTİMALİ olan modülleri hedefliyor:
    yalnızca fonksiyon içinde import edilenler. Üçü depoda gerçekten öyle —
    isimleri burada sabitleniyor ki liste amaçsızca genişlemesin.
    """
    listede = set(_sabit(KOK / "main.py", "_SELFTEST_UCUNCU_TARAF"))
    # reportlab → CORE/inventory.py, qrcode → CORE/recovery_share.py,
    # keyring → CORE/secret_store.py; üçü de fonksiyon gövdesinde.
    assert {"reportlab.platypus", "qrcode", "keyring"} <= listede


# ── Linux spec ────────────────────────────────────────────────────────────────

def test_linux_spec_var():
    assert LINUX_SPEC.is_file(), "HYCLEUS-linux.spec yok"


def test_linux_spec_windows_bagimliliklarini_eliyor():
    """
    `wmi`/`pywin32` Linux'ta KURULAMAZ (requirements.txt'te platform
    işaretçisi var). Spec onları isterse yapı hiç başlamaz.
    """
    for dugum in ast.walk(ast.parse(LINUX_SPEC.read_text(encoding="utf-8"))):
        if isinstance(dugum, ast.keyword) and dugum.arg == "excludes":
            excludes = ast.literal_eval(dugum.value)
            assert {"wmi", "pythoncom", "win32api"} <= set(excludes)
            return
    pytest.fail("Linux spec `excludes` vermiyor")


def test_linux_spec_uygulama_modullerini_hiddenimportsa_uretiyor():
    """
    ÖLÇÜLMÜŞ HATA. İlk hâli Windows spec'ini birebir izliyor ve CORE/DB'yi
    VERİ olarak kopyalıyordu. Veri kopyası dosyaları pakete koyar ama
    PyInstaller'ın onları analiz etmesini SAĞLAMAZ: donmuş yapıda
    `main.py`'nin import etmediği her modül kendi bağımlılıkları olmadan
    gitti (getpass, asn1crypto, reportlab, qrcode.image.svg — 11 modül).

    Liste `os.listdir` ile ÜRETİLİYOR; elle yazılsaydı ilk yeni modülde
    sessizce eskirdi. Bu test o üretimin yerinde durduğunu sabitliyor.
    """
    metin = LINUX_SPEC.read_text(encoding="utf-8")
    assert "_uygulama_modulleri()" in metin
    assert "os.listdir" in metin
    assert "collect_all('reportlab')" in metin, "reportlab yazı tipleri veri dosyası"
    assert "collect_submodules('qrcode')" in metin


def test_linux_spec_var_olmayan_yol_istemiyor():
    """
    Windows spec'i `('data', 'data')` istiyor ama data/ .gitignore'da —
    ölçüldü: temiz bir ağaçta PyInstaller "Unable to find ...\\data" ile
    düşüyor (BACKLOG / B-024). Linux spec'i sabit bir `datas` listesi
    taşımıyor; taşırsa CI'ın `appimage` işi ilk adımda kırılır.
    """
    for dugum in ast.walk(ast.parse(LINUX_SPEC.read_text(encoding="utf-8"))):
        if isinstance(dugum, ast.keyword) and dugum.arg == "datas":
            # Değer bir ad (rl_datas) — sabit liste DEĞİL. Sabit bir liste
            # yazılmışsa içindeki her yolun var olduğu denetleniyor.
            if isinstance(dugum.value, ast.Name):
                return
            for kaynak, _ in ast.literal_eval(dugum.value):
                assert (KOK / kaynak).exists(), f"spec olmayan yolu istiyor: {kaynak}"
            return
    pytest.fail("Linux spec `datas` vermiyor")


def test_linux_spec_onedir_uretiyor():
    """
    AppImage'ın içine onefile koymak her açılışta iki kez açma demek
    (squashfs + PyInstaller'ın /tmp çıkarması). COLLECT bunun işareti.
    """
    metin = LINUX_SPEC.read_text(encoding="utf-8")
    assert "COLLECT(" in metin
    assert "exclude_binaries=True" in metin


def test_windows_spec_dokunulmadi():
    """
    Linux ayağı eklenirken Windows yapısı DEĞİŞMEMELİ. Bu test, ikisinin
    ayrı dosyalar olduğunu ve Windows'unkinin hâlâ wmi topladığını sabitler.
    """
    metin = WINDOWS_SPEC.read_text(encoding="utf-8")
    assert "collect_all('wmi')" in metin
    assert "COLLECT(" not in metin, "Windows tarafı tek dosya EXE üretmeye devam etmeli"


# ── AppDir varlıkları ─────────────────────────────────────────────────────────

def test_appimage_varliklari_yerinde():
    for ad in ("AppRun", "hycleus.desktop", "hycleus.png",
               "build-appimage.sh", "smoke-test.sh"):
        assert (PAKET / ad).is_file(), f"packaging/linux/{ad} yok"


def test_desktop_dosyasi_gecerli_ve_simge_adi_eslesiyor():
    """
    appimagetool, `Icon=` değeriyle AppDir kökündeki simgenin uzantısız
    adı eşleşmezse yapıyı REDDEDİYOR. İkisi iki ayrı dosyada durduğu için
    ayrışmaları kolay.
    """
    ayrist = configparser.ConfigParser(interpolation=None)
    ayrist.optionxform = str  # type: ignore[method-assign]
    ayrist.read(PAKET / "hycleus.desktop", encoding="utf-8")

    assert "Desktop Entry" in ayrist
    girdi = ayrist["Desktop Entry"]
    assert girdi["Type"] == "Application"
    assert girdi["Name"] == "HYCLEUS"
    assert girdi["Exec"]
    assert girdi["Categories"].endswith(";"), "Categories ';' ile bitmeli"

    simge = girdi["Icon"]
    assert (PAKET / f"{simge}.png").is_file(), (
        f".desktop 'Icon={simge}' diyor ama packaging/linux/{simge}.png yok"
    )


def test_simge_appimagetoolun_istedigi_bicimde():
    """256×256 PNG — appimagetool kare olmayan/okunamayan simgeyi reddediyor."""
    PIL = pytest.importorskip("PIL.Image")
    with PIL.open(PAKET / "hycleus.png") as gorsel:
        assert gorsel.format == "PNG"
        assert gorsel.size == (256, 256)


# ── Kabuk betikleri ───────────────────────────────────────────────────────────

_KABUK = ("AppRun", "build-appimage.sh", "smoke-test.sh")


@pytest.mark.parametrize("ad", _KABUK)
def test_kabuk_betikleri_CRLF_tasimiyor(ad: str):
    """
    Depo Windows'ta geliştiriliyor. CRLF ile açılan bir betiğin ilk satırı
    `#!/usr/bin/env bash\\r` olur ve Linux "bad interpreter: bash^M" der —
    görünmez bir karakteri işaret ettiği için tanınması zor bir hata.
    Koruma .gitattributes'ta (`*.sh text eol=lf`); bu test onun gerçekten
    işlediğini çalışma ağacında ölçüyor.
    """
    ham = (PAKET / ad).read_bytes()
    assert b"\r\n" not in ham, f"packaging/linux/{ad} CRLF taşıyor"


@pytest.mark.parametrize("ad", _KABUK)
def test_kabuk_betikleri_shebang_tasiyor(ad: str):
    ilk = (PAKET / ad).read_bytes().split(b"\n", 1)[0]
    assert ilk.startswith(b"#!"), f"packaging/linux/{ad} shebang taşımıyor"


# ── CI ile bağ ────────────────────────────────────────────────────────────────
#
# Aşağıdakiler ci.yml'yi METİN olarak okuyor, YAML olarak değil. PyYAML
# requirements-dev.txt'te yok ve yalnızca bu iki denetim için bir bağımlılık
# eklemek pahalı; `importorskip` ise korumayı CI'da sessizce kapatırdı —
# depoda tam olarak kaçınılan şey (bkz. tests/test_static_analysis.py).

CI = KOK / ".github" / "workflows" / "ci.yml"


def test_ci_appimage_isi_var_olan_betikleri_cagiriyor():
    """
    Betikler yeniden adlandırılırsa CI ancak o push'ta, yapı adımında
    kırılır. Bu test onu commit anında söylüyor.
    """
    metin = CI.read_text(encoding="utf-8")
    for betik in ("packaging/linux/build-appimage.sh",
                  "packaging/linux/smoke-test.sh"):
        assert betik in metin, f"ci.yml {betik} çağırmıyor"
        assert (KOK / betik).is_file(), f"ci.yml var olmayan {betik} çağırıyor"


def test_ci_appimage_isi_yapi_bagimliliklarini_kuruyor():
    metin = CI.read_text(encoding="utf-8")
    assert "requirements-build.txt" in metin
    assert (KOK / "requirements-build.txt").is_file()


def test_ci_test_matrisi_iki_ayak():
    """
    Matris ubuntu + windows. Yapı işi AYRI bir iş olarak duruyor; matrise
    girseydi Windows ayağında da koşup orada anlamsız olurdu.
    """
    metin = CI.read_text(encoding="utf-8")
    assert "os: [ubuntu-latest, windows-latest]" in metin


@pytest.mark.parametrize("ad", ("build-appimage.sh", "smoke-test.sh"))
def test_kabuk_betikleri_hata_durumunda_duruyor(ad: str):
    """
    `set -e` olmadan bir yapı betiği başarısız adımı yutup "tamam" der.
    Yapı betiğinin en kötü hâli, kırık bir çıktıyı sessizce üretmesidir.
    """
    metin = (PAKET / ad).read_text(encoding="utf-8")
    assert "set -euo pipefail" in metin
