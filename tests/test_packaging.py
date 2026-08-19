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
import os
from pathlib import Path

import pytest

KOK = Path(__file__).resolve().parent.parent
PAKET = KOK / "packaging" / "linux"
PAKET_WIN = KOK / "packaging" / "windows"

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


# ── Spec okuma yardımcıları ───────────────────────────────────────────────────
#
# Hepsi AST, hiçbiri metin araması DEĞİL. Mutasyon testi bunu gerektirdi:
# ilk hâlleri `assert "upx=True" in metin` gibiydi ve `upx=False`'a çevrilen
# bir spec testi GEÇİYORDU — çünkü dosyanın başındaki AÇIKLAMA SATIRI da
# "upx=True" yazıyor. Aynı sınıf hata bu depoda dördüncü kez çıktı
# (bkz. tests/test_session_user.py, test_disposal.py, test_console.py):
# bir kuralı düz metinle denetlemek, kuralı ANLATAN metni de eşleştirir.

def _agac(spec: Path) -> ast.Module:
    return ast.parse(spec.read_text(encoding="utf-8"))


def _cagri_anahtari(spec: Path, cagri_adi: str, anahtar: str) -> ast.expr:
    """`Analysis(...)` / `EXE(...)` çağrısındaki bir anahtar argümanın düğümü."""
    for dugum in ast.walk(_agac(spec)):
        if (isinstance(dugum, ast.Call) and isinstance(dugum.func, ast.Name)
                and dugum.func.id == cagri_adi):
            for kw in dugum.keywords:
                if kw.arg == anahtar:
                    return kw.value
    raise AssertionError(f"{spec.name}: {cagri_adi}(…) içinde `{anahtar}` yok")


def _cagiriyor_mu(dugum: ast.expr, ad: str, ilk_arg: str | None = None) -> bool:
    """İfadenin içinde `ad(...)` çağrısı geçiyor mu."""
    for alt in ast.walk(dugum):
        if not (isinstance(alt, ast.Call) and isinstance(alt.func, ast.Name)):
            continue
        if alt.func.id != ad:
            continue
        if ilk_arg is None:
            return True
        if alt.args and isinstance(alt.args[0], ast.Constant) \
                and alt.args[0].value == ilk_arg:
            return True
    return False


def _demet_sabitleri(dugum: ast.expr) -> list[tuple]:
    """İfadenin içindeki tüm sabit demetler — `a + b + [('x','y')]` dahil."""
    bulunan = []
    for alt in ast.walk(dugum):
        if isinstance(alt, ast.Tuple):
            try:
                bulunan.append(ast.literal_eval(alt))
            except ValueError:
                pass
    return bulunan


def _modul_ureticisini_calistir(spec: Path) -> list[str]:
    """
    Spec'teki `_uygulama_modulleri()` fonksiyonunu SÖKÜP ÇALIŞTIRIR.

    Metin araması "fonksiyon tanımlı mı" sorusunu cevaplıyor; asıl soru
    "doğru listeyi üretiyor mu". Mutasyon testinde gövdesi `pass` yapılan
    bir üretici metin denetiminden geçmişti.
    """
    for dugum in _agac(spec).body:
        if isinstance(dugum, ast.FunctionDef) and dugum.name == "_uygulama_modulleri":
            kod = compile(ast.Module(body=[dugum], type_ignores=[]),
                          filename=str(spec), mode="exec")
            ad_alani: dict = {"os": os}
            exec(kod, ad_alani)  # noqa: S102  # kaynak DEPONUN kendi spec dosyası
            onceki = os.getcwd()
            os.chdir(KOK)   # spec göreli yol kullanıyor ("CORE", "DB")
            try:
                return list(ad_alani["_uygulama_modulleri"]())
            finally:
                os.chdir(onceki)
    raise AssertionError(f"{spec.name}: `_uygulama_modulleri` tanımı yok")


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


def test_platform_listesi_windowsta_wmi_grubunu_iceriyor():
    """
    B-024'ün ikinci yarısının kapısı. Linux spec'i `wmi`/`pywin32`'yi
    `excludes` ile eliyor (Linux'ta kurulamıyorlar); o satırın Windows
    spec'ine kopyalanması HWID okumasını SESSİZCE bozardı —
    `get_usb_hwid()` her iki yöntemi de `except Exception: pass` ile
    sarıyor, yani eksik `wmi` bir hata değil "USB bulunamadı" olarak
    görünür ve uygulama açılmayı reddeder.

    Bu grup listeden silinirse CI'ın `exe` işi paketi doğrulamayı bırakır
    ve kapı sessizce açılır — testin var olma sebebi bu.
    """
    platform = _sabit(KOK / "main.py", "_SELFTEST_PLATFORM")
    assert isinstance(platform, dict)
    assert {"wmi", "pythoncom", "win32api", "win32con"} <= set(platform["win32"])


def test_platform_listesi_linuxa_windows_modulu_koymuyor():
    """`wmi` Linux'ta kurulamaz; orada denenirse AppImage duman testi kırılır."""
    platform = _sabit(KOK / "main.py", "_SELFTEST_PLATFORM")
    for anahtar, moduller in platform.items():
        if anahtar != "win32":
            assert not ({"wmi", "pythoncom", "win32api"} & set(moduller)), \
                f"{anahtar} altında Windows modülü var: {moduller}"


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


# ── İKİ SPEC İÇİN ORTAK — B-024 ───────────────────────────────────────────────
#
# Aşağıdaki üç test HER İKİ spec'e birden uygulanıyor. Sebep, hatanın nasıl
# ortaya çıktığı: Windows spec'i referans alınıp Linux'a kopyalandı ve
# bozukluk da kopyalandı. İki dosyayı ayrı ayrı denetlemek, birinin
# düzeltilip diğerinin unutulmasına açık kapı bırakırdı.
#
# ÖLÇÜLEN HATA (B-024), her iki yapıda da aynıydı:
# CORE/DB VERİ olarak kopyalanıyordu. Veri kopyası .py dosyalarını pakete
# koyar ama PyInstaller'ın onları ANALİZ etmesini sağlamaz — dolayısıyla
# main.py'nin import etmediği her modül kendi bağımlılıkları olmadan gitti.
# Windows yapısında ölçülen: 53 modülün 10'u yüklenemiyordu.
#
#     getpass          ← backup_cli, recover_vault, setup_usb
#     asn1crypto       ← timestamp, timestamp_verify
#     reportlab        ← inventory
#     qrcode.image.svg ← recovery_share
#
# Düzeltmeden sonra ikisi de 53/53.

SPECLER = [pytest.param(WINDOWS_SPEC, id="windows"),
           pytest.param(LINUX_SPEC, id="linux")]


@pytest.mark.parametrize("spec", SPECLER)
def test_spec_uygulama_modullerini_hiddenimportsa_veriyor(spec: Path):
    """`Analysis(hiddenimports=…)` GERÇEKTEN üreticiyi çağırıyor mu."""
    hidden = _cagri_anahtari(spec, "Analysis", "hiddenimports")
    assert _cagiriyor_mu(hidden, "_uygulama_modulleri"), (
        f"{spec.name}: CORE/DB modülleri hiddenimports'a girmiyor — B-024 geri geldi"
    )


@pytest.mark.parametrize("spec", SPECLER)
def test_spec_modul_uretici_depoyla_ayni_listeyi_veriyor(spec: Path):
    """
    Üreticiyi ÇALIŞTIRIP sonucu depoyla karşılaştırır.

    "Fonksiyon tanımlı mı" yetmiyor: mutasyon testinde gövdesi boş
    döndürülen bir üretici, tanımı yerinde durduğu için metin
    denetiminden geçmişti. Ölçülen şey artık davranış.
    """
    assert set(_modul_ureticisini_calistir(spec)) == _depodaki_moduller()


@pytest.mark.parametrize("spec", SPECLER)
def test_spec_gizli_ucuncu_taraf_bagimliliklarini_topluyor(spec: Path):
    """
    `collect_all` reportlab için ZORUNLU (saf Python değil — gömülü Type-1
    yazı tipleri taşıyor; onlarsız PDF üretimi çalışma anında düşer, modül
    yüklenmiş görünürken). qrcode'un görüntü arka ucu çalışma anında
    seçiliyor, statik analiz göremiyor.
    """
    agac = _agac(spec)
    assert any(_cagiriyor_mu(d, "collect_all", "reportlab")
               for d in agac.body if isinstance(d, ast.Assign)), \
        f"{spec.name}: reportlab collect_all ile toplanmıyor"
    assert any(_cagiriyor_mu(d, "collect_submodules", "qrcode")
               for d in agac.body if isinstance(d, ast.Assign)), \
        f"{spec.name}: qrcode alt modülleri toplanmıyor"

    # Toplananlar Analysis'e GERÇEKTEN bağlanmalı; değişkene atayıp
    # kullanmamak sessizce aynı hatayı geri getirirdi.
    hidden = ast.dump(_cagri_anahtari(spec, "Analysis", "hiddenimports"))
    assert "rl_hiddenimports" in hidden and "qr_hiddenimports" in hidden
    datas = ast.dump(_cagri_anahtari(spec, "Analysis", "datas"))
    assert "rl_datas" in datas, "reportlab yazı tipleri datas'a bağlanmamış"


@pytest.mark.parametrize("spec", SPECLER)
def test_spec_var_olmayan_yol_istemiyor(spec: Path):
    """
    `('data', 'data')` istiyordu ama data/ .gitignore'da — ölçüldü, temiz
    bir ağaçta PyInstaller "Unable to find …\\data" ile HİÇ BAŞLAMIYORDU.
    Satır ayrıca gereksizdi: data_dir() donmuş modda EXE'nin yanına bakıyor.

    Denetim `datas` ifadesinin TAMAMINI geziyor. İlk hâli yalnızca düz bir
    liste bekliyordu ve `[('data','data')] + wmi_datas` biçimindeki bir
    toplamı görmeden geçiyordu — mutasyon testi yakaladı.
    """
    for anahtar in ("datas", "binaries"):
        for kaynak, *_ in _demet_sabitleri(_cagri_anahtari(spec, "Analysis", anahtar)):
            assert (KOK / kaynak).exists(), \
                f"{spec.name}: `{anahtar}` var olmayan '{kaynak}' yolunu istiyor"


# ── Platforma özgü farklar ────────────────────────────────────────────────────

def test_linux_spec_onedir_uretiyor():
    """
    AppImage'ın içine onefile koymak her açılışta iki kez açma demek
    (squashfs + PyInstaller'ın /tmp çıkarması). COLLECT bunun işareti.
    """
    assert any(isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
               and d.func.id == "COLLECT" for d in ast.walk(_agac(LINUX_SPEC)))
    ayri = _cagri_anahtari(LINUX_SPEC, "EXE", "exclude_binaries")
    assert isinstance(ayri, ast.Constant) and ayri.value is True


def test_windows_spec_tek_dosya_ve_wmi_toplamaya_devam_ediyor():
    """
    B-024 düzeltmesi Windows'a ÖZGÜ olanı değiştirmemeli: tek dosya EXE,
    wmi/pywin32 toplama, upx. Değişen yalnızca modül/bağımlılık toplaması.
    """
    agac = _agac(WINDOWS_SPEC)
    assert any(_cagiriyor_mu(d, "collect_all", "wmi")
               for d in agac.body if isinstance(d, ast.Assign)), "wmi toplanmıyor"

    hidden = ast.dump(_cagri_anahtari(WINDOWS_SPEC, "Analysis", "hiddenimports"))
    for ad in ("wmi", "pythoncom", "win32api", "win32con"):
        assert f"'{ad}'" in hidden, f"{ad} hiddenimports'tan düşmüş"

    # `upx=True` DOSYA AÇIKLAMASINDA da geçiyor; metin araması `upx=False`'a
    # çevrilmiş bir spec'i yakalayamıyordu (mutasyon testi gösterdi).
    upx = _cagri_anahtari(WINDOWS_SPEC, "EXE", "upx")
    assert isinstance(upx, ast.Constant) and upx.value is True

    assert not any(isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
                   and d.func.id == "COLLECT" for d in ast.walk(agac)), \
        "Windows tarafı tek dosya EXE üretmeye devam etmeli"


def test_windows_spec_wmi_excludelamiyor():
    """
    Linux spec'i wmi'yi `excludes` ile eliyor. O satırın Windows'a
    kopyalanması, HWID okumasını sessizce mock'a düşürürdü.
    """
    for dugum in ast.walk(ast.parse(WINDOWS_SPEC.read_text(encoding="utf-8"))):
        if isinstance(dugum, ast.keyword) and dugum.arg == "excludes":
            assert ast.literal_eval(dugum.value) == []
            return
    pytest.fail("Windows spec `excludes` vermiyor")


# ── AppDir varlıkları ─────────────────────────────────────────────────────────

def test_appimage_varliklari_yerinde():
    for ad in ("AppRun", "hycleus.desktop", "hycleus.png",
               "build-appimage.sh", "smoke-test.sh"):
        assert (PAKET / ad).is_file(), f"packaging/linux/{ad} yok"


def test_windows_paketleme_varliklari_yerinde():
    for ad in ("build-exe.ps1", "smoke-test.ps1"):
        assert (PAKET_WIN / ad).is_file(), f"packaging/windows/{ad} yok"


def test_iki_platformun_da_yapi_ve_duman_testi_var():
    """
    Simetri denetimi. Bir platformun duman testi olmadan kalması, B-024'ün
    ortaya çıktığı durumun aynısı: yapı üretiliyor ama kimse açıp bakmıyor.
    """
    assert (PAKET / "build-appimage.sh").is_file()
    assert (PAKET / "smoke-test.sh").is_file()
    assert (PAKET_WIN / "build-exe.ps1").is_file()
    assert (PAKET_WIN / "smoke-test.ps1").is_file()


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


def test_ci_yapi_isleri_var_olan_betikleri_cagiriyor():
    """
    Betikler yeniden adlandırılırsa CI ancak o push'ta, yapı adımında
    kırılır. Bu test onu commit anında söylüyor.
    """
    metin = CI.read_text(encoding="utf-8")
    for betik, cagri in (
        ("packaging/linux/build-appimage.sh", "packaging/linux/build-appimage.sh"),
        ("packaging/linux/smoke-test.sh", "packaging/linux/smoke-test.sh"),
        ("packaging/windows/build-exe.ps1", r"packaging\windows\build-exe.ps1"),
        ("packaging/windows/smoke-test.ps1", r"packaging\windows\smoke-test.ps1"),
    ):
        assert cagri in metin, f"ci.yml {betik} çağırmıyor"
        assert (KOK / betik).is_file(), f"ci.yml var olmayan {betik} çağırıyor"


def test_ci_exe_isi_temiz_agac_olcuyor():
    """
    `-TemizAgac` olmadan iş, `data/` dizinini zaten üretmiş bir ortamda da
    yeşil geçerdi — B-024'ün birinci yarısı tam olarak buydu ve tam da bu
    yüzden kimsenin makinesinde görünmüyordu.
    """
    assert "-TemizAgac" in CI.read_text(encoding="utf-8")


def test_ci_yapi_isleri_test_matrisinin_disinda():
    """
    İki yapı işi de AYRI job. Matrise girselerdi her biri yanlış platformda
    da koşardı (AppImage Windows'ta, EXE Ubuntu'da) ve orada anlamsızdı.
    """
    metin = CI.read_text(encoding="utf-8")
    assert "os: [ubuntu-latest, windows-latest]" in metin
    for isim in ("  appimage:", "  exe:"):
        assert isim in metin, f"ci.yml'de {isim.strip()} işi yok"


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
