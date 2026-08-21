"""
HYCLEUS — Katman kuralı koruması

Tek kural: **CORE/ ve DB/ altındaki hiçbir modül Qt'ye ya da UI'a bağlı
olmamalı.** Bu kural bugüne kadar disiplinle korundu ama hiçbir yerde
ZORUNLU değildi — tek bir `from PySide6.QtWidgets import QMessageBox`
satırı sessizce girebilir ve fark edilmesi aylar alabilirdi.

Neden bu kural
--------------
Üç somut sonucu var:

  1. **CORE başsız çalışabiliyor.** Zamanlanmış görevler
     (CORE/scheduler.py), CLI araçları (CORE/recover_vault.py,
     CORE/setup_usb.py) ve denetim raporu üretimi (CORE/inventory.py) bir
     QApplication örneği olmadan çalışmak zorunda.
  2. **CORE test edilebiliyor.** Bu paketteki 550 testin ezici çoğunluğu
     Qt'ye hiç dokunmuyor; CORE Qt'ye bağlansaydı hepsi bir ekran
     sunucusuna bağımlı hâle gelirdi. Nitekim Qt gerektiren tek test paketi
     (test_lock_overlay.py) CI'ın Linux ayağında ATLANMAK zorunda.
  3. **İş mantığı diyalog açamıyor.** CORE bir QMessageBox gösteremezse,
     kararı çağırana döndürmek zorunda kalır. Bu, mantığın test edilebilir
     kalmasını mekanik olarak garanti ediyor.

Bu dersin bedeli bir kez ödendi: `added_by` kolonu, SQL `UI/main_window.py`
içinde satır içi durduğu için Qt olmadan çalıştırılamıyordu ve düşen kolonu
kimse fark etmemişti (bkz. CORE/file_records.py docstring'i).

Neden AST, neden metin araması değil
------------------------------------
`grep "PySide6"` yorum satırlarına ve docstring'lere de takılır — bu
dosyalarda ikisi de bol. AST yalnızca GERÇEK import ifadelerini görüyor,
üstelik fonksiyon içine gizlenmiş yerel import'ları da (ast.walk tüm ağacı
geziyor) yakalıyor.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: Temiz kalması gereken katmanlar.
_PURE_LAYERS = ("CORE", "DB")

#: Bu köklerden hiçbiri CORE/DB içinde import edilemez.
_FORBIDDEN_ROOTS = frozenset({"PySide6", "UI", "shiboken6"})


def _python_files(layer: str) -> list[Path]:
    return sorted(
        p for p in (_PROJECT_ROOT / layer).rglob("*.py")
        if "__pycache__" not in p.parts
    )


def _imported_roots(path: Path) -> set[str]:
    """
    Dosyadaki her import ifadesinin KÖK modül adını döndürür.

    `import a.b.c`      → "a"
    `from a.b import c` → "a"
    `from . import x`   → (göreli import, atlanır — katman dışına çıkamaz)

    ast.walk kullanılıyor: modül seviyesindeki import'lar kadar fonksiyon
    içine yazılmış yerel import'lar da yakalanıyor. HYCLEUS'ta yerel import
    yaygın bir desen (döngüsel bağımlılıktan kaçınmak için), dolayısıyla
    yalnızca `tree.body`'ye bakmak kuralda kocaman bir delik bırakırdı.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        roots.update(kok for kok, _ in _ithal_edilenler(node))
    return roots


def _ithal_edilenler(dugum: ast.AST) -> list[tuple[str, str]]:
    """
    Tek bir import dugumunden `(kok, tam_ad)` ciftleri.

    `import a.b.c`      -> ("a", "a.b.c")
    `from a.b import c` -> ("a", "a.b")
    `from . import x`   -> goreli, atlanir (katman disina cikamaz)

    Import dugumunu cozen TEK yer burasi: hem `_imported_roots` hem de
    asagidaki toplama-hatasi denetimi bunu kullaniyor. Iki ayri cozucu
    yazmak, bu deponun bes kez urettigi kusurun (ayni is icin iki ayri
    uygulama) tam giris kosulu olurdu.
    """
    if isinstance(dugum, ast.Import):
        return [(a.name.split(".")[0], a.name) for a in dugum.names]
    if isinstance(dugum, ast.ImportFrom) and dugum.level == 0 and dugum.module:
        return [(dugum.module.split(".")[0], dugum.module)]
    return []


def _all_pure_files() -> list[Path]:
    return [p for layer in _PURE_LAYERS for p in _python_files(layer)]


def test_pure_layers_actually_contain_modules():
    """
    Koruma testinin kendisi boşa düşmesin.

    Dizin adı değişirse (ya da glob bozulursa) aşağıdaki testler HİÇBİR
    dosya gezmeden yeşil kalırdı — kural korunuyor görünür, korunmaz.
    """
    for layer in _PURE_LAYERS:
        dosyalar = _python_files(layer)
        assert dosyalar, f"{layer}/ altında hiç Python dosyası bulunamadı"
    assert len(_all_pure_files()) >= 15


@pytest.mark.parametrize(
    "path", _all_pure_files(), ids=lambda p: str(p.relative_to(_PROJECT_ROOT))
)
def test_pure_layer_module_has_no_forbidden_import(path: Path):
    """CORE/ ve DB/ altındaki her modül Qt'den ve UI'dan bağımsız olmalı."""
    yasakli = _imported_roots(path) & _FORBIDDEN_ROOTS
    assert not yasakli, (
        f"{path.relative_to(_PROJECT_ROOT)} yasak import içeriyor: "
        f"{sorted(yasakli)}.\n"
        "CORE/ ve DB/ katmanları Qt'ye ve UI'a bağlanamaz — gerekçe için "
        "tests/test_layering.py docstring'ine bakın. İş mantığı bir diyalog "
        "göstermek yerine sonucu çağırana döndürmelidir."
    )


def test_forbidden_import_would_actually_be_caught(tmp_path: Path):
    """
    Denetimin işe yaradığını göster — kural gerçekten uygulanıyor mu?

    Yasak import'un her iki biçimi de (modül seviyesi ve fonksiyon içi)
    yakalanmalı; ikincisi HYCLEUS'ta yaygın olduğu için asıl önemlisi o.
    """
    modul_seviyesi = tmp_path / "ihlal_modul.py"
    modul_seviyesi.write_text(
        "from PySide6.QtWidgets import QMessageBox\n", encoding="utf-8"
    )
    assert "PySide6" in _imported_roots(modul_seviyesi)

    fonksiyon_ici = tmp_path / "ihlal_fonksiyon.py"
    fonksiyon_ici.write_text(
        "def f():\n    import PySide6.QtCore\n", encoding="utf-8"
    )
    assert "PySide6" in _imported_roots(fonksiyon_ici)

    ui_ithali = tmp_path / "ihlal_ui.py"
    ui_ithali.write_text("from UI.main_window import HycleusWindow\n", encoding="utf-8")
    assert "UI" in _imported_roots(ui_ithali)


def test_comments_and_docstrings_do_not_trigger_the_check(tmp_path: Path):
    """
    Yorumda geçen "PySide6" ihlal DEĞİL.

    CORE dosyalarında Qt'den söz eden yorumlar var (ör. CORE/inventory.py
    QPdfWriter'ı neden kullanmadığını anlatıyor). Metin araması bunlara
    takılırdı; AST takılmamalı.
    """
    temiz = tmp_path / "temiz.py"
    temiz.write_text(
        '"""PySide6 kullanmıyoruz çünkü QApplication gerektirir."""\n'
        "# from PySide6.QtWidgets import QMessageBox  <- bilerek yapılmadı\n"
        "MESAJ = 'PySide6'\n",
        encoding="utf-8",
    )
    assert not (_imported_roots(temiz) & _FORBIDDEN_ROOTS)


# ══════════════════════════════════════════════════════════════════════════════
# Qt test dosyalari: offscreen korumasi ZORUNLU
# ══════════════════════════════════════════════════════════════════════════════
#
# Ayri bir kural ama ayni sinif: bir dosyanin CALISMASI, baska bir dosyanin
# yan etkisine bagli olmamali.
#
# QApplication kuran bir test dosyasi `QT_QPA_PLATFORM` kurulmadan
# calistirilirsa, ekransiz bir Linux'ta Qt varsayilan `xcb` eklentisini
# yukleyemez ve `qFatal` ile SURECI OLDURUR. Olculdu: yakalanabilir bir
# istisna DEGIL, yani `try/except -> pytest.skip` deseni kurtarmiyor.
#
# Tam pakette degisken, alfabetik olarak once toplanan baska bir modulun
# modul seviyesindeki `setdefault`'undan geliyor. Yani korumasi olmayan bir
# dosya TAM PAKETTE calisir, TEK BASINA cokerdi — ve tek basina calistirmak
# hata ayiklamanin en sik yapilan hareketi.
#
# Iki dosya tam olarak bu durumdaydi (`test_trusted_roots.py`,
# `test_guvenlik_view.py`); B-013 ve B-020 ile ayni tekrar sinifi: ortama
# bagli, yalnizca bir platformda gorunur, ve sessiz.


def _qapplication_kuran_dosyalar() -> list[Path]:
    """
    `QApplication(...)` CAGRISI yapan test dosyalari.

    Metin aramasi DEGIL, AST: bu deponun docstring'lerinde ve
    yorumlarinda "QApplication" bolca geciyor (`test_layering.py` dahil,
    bu yorum da oyle) ve metin aramasi onlara takilirdi — B-024.
    """
    bulunan = []
    for yol in sorted((_PROJECT_ROOT / "tests").glob("test_*.py")):
        agac = ast.parse(yol.read_text(encoding="utf-8"))
        for d in ast.walk(agac):
            if (isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
                    and d.func.id == "QApplication"):
                bulunan.append(yol)
                break
    return bulunan


def _offscreen_koruyor_mu(yol: Path) -> bool:
    """`os.environ.setdefault("QT_QPA_PLATFORM", ...)` cagrisi var mi — AST ile."""
    agac = ast.parse(yol.read_text(encoding="utf-8"))
    for d in ast.walk(agac):
        if (isinstance(d, ast.Call)
                and isinstance(d.func, ast.Attribute)
                and d.func.attr == "setdefault"
                and d.args
                and isinstance(d.args[0], ast.Constant)
                and d.args[0].value == "QT_QPA_PLATFORM"):
            return True
    return False


def test_qapplication_kuran_dosyalar_gercekten_bulunuyor():
    """Bos kume donen bir tarayici asagidaki kurali sessizce gecirirdi."""
    dosyalar = _qapplication_kuran_dosyalar()
    assert len(dosyalar) >= 7, (
        f"QApplication kuran yalnizca {len(dosyalar)} dosya bulundu — tarayici kor"
    )


@pytest.mark.parametrize(
    "yol", _qapplication_kuran_dosyalar(), ids=lambda p: p.name
)
def test_qapplication_kuran_dosya_offscreen_KURUYOR(yol: Path):
    """
    Her QApplication kuran test dosyasi kendi platformunu kurmali.

    Gerekce yukaridaki blokta; kisaca: baska bir dosyanin toplama
    yan etkisine guvenen bir dosya, tek basina calistirildiginda
    ekransiz Linux'ta sureci oldurur.
    """
    assert _offscreen_koruyor_mu(yol), (
        f"{yol.name} QApplication kuruyor ama QT_QPA_PLATFORM kurmuyor. "
        'Import blogunun basina ekleyin: '
        'os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")'
    )


def test_offscreen_denetimi_EKSIGI_gercekten_yakaliyor(tmp_path: Path):
    """Denetimin kendisi calisiyor mu — korumasiz bir dosya uydurulup olculuyor."""
    korumasiz = tmp_path / "test_korumasiz.py"
    korumasiz.write_text(
        "from PySide6.QtWidgets import QApplication\n"
        "def test_x():\n    app = QApplication([])\n",
        encoding="utf-8")
    assert not _offscreen_koruyor_mu(korumasiz)

    korumali = tmp_path / "test_korumali.py"
    korumali.write_text(
        "import os\n"
        'os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")\n'
        "from PySide6.QtWidgets import QApplication\n"
        "def test_x():\n    app = QApplication([])\n",
        encoding="utf-8")
    assert _offscreen_koruyor_mu(korumali)


def test_YORUMDAKI_setdefault_denetimi_kandirmiyor(tmp_path: Path):
    """
    Bu deponun dort kez yasadigi hata: kurali ANLATAN metnin kurala
    takilmasi (son ornek B-024). AST kullaniliyor, metin aramasi degil.
    """
    sahte = tmp_path / "test_sahte.py"
    sahte.write_text(
        "# os.environ.setdefault(\"QT_QPA_PLATFORM\", \"offscreen\") yazmali\n"
        '"""os.environ.setdefault("QT_QPA_PLATFORM", "offscreen") kurmuyor."""\n'
        "from PySide6.QtWidgets import QApplication\n"
        "def test_x():\n    app = QApplication([])\n",
        encoding="utf-8")
    assert not _offscreen_koruyor_mu(sahte), "yorum/docstring denetimi kandirdi"


def test_ui_layer_may_import_core_freely():
    """
    Kural TEK YÖNLÜ: UI → CORE serbest, CORE → UI yasak.

    Bağımlılık yönünün doğru olduğunu sabitliyor; biri kuralı "hiçbir katman
    diğerini import etmesin" diye yorumlarsa bu test onu düzeltir.
    """
    ui_dosyalari = _python_files("UI")
    assert ui_dosyalari, "UI/ altında hiç Python dosyası bulunamadı"
    core_kullanan = [p for p in ui_dosyalari if "CORE" in _imported_roots(p)]
    assert core_kullanan, "UI katmanı CORE'u hiç kullanmıyor — beklenmedik"


# ══════════════════════════════════════════════════════════════════════════════
#
# Ayni ailenin ucuncu uyesi. Yukaridaki iki kural bir dosyanin CALISMASIYLA
# ilgiliydi; bu kural TOPLANMASIYLA ilgili — ve daha yikici.
#
# Modul seviyesinde patlayan bir import pytest'te ATLAMA degil TOPLAMA
# HATASI olur: oturum `Interrupted` ile biter, cikis kodu 2, ve paketin
# GERI KALANI HIC KOSMAZ. Olculdu (run 32526378278, ubuntu-latest): pytest
# adimi 45 s yerine 3 s surdu, JUnit ciktisi 32 230 bayt yerine 935 bayt
# geldi, ve o kosuda zaten kirmizi olan bes test hic gorunmedi — B-046
# maskelendi.
#
# Neden Qt'de oluyor: PySide6 kurulu olsa bile alt moduller sistem
# kutuphanelerine bagli (libEGL.so.1, libxkbcommon). Ciplak bir Linux
# runner'inda `from PySide6...` ImportError veriyor; `importorskip` bunu
# KURTARMIYOR cunku paket kurulu. Depo bunu iki kez yasadi: 297327f
# (test_lock_overlay.py yorumunda kayitli) ve 89826bd (B-047).
#
# Kapsam neden yalnizca MODUL SEVIYESI: fonksiyon/sinif govdesindeki bir
# import calisma aninda patlar — o bir TEST BASARISIZLIGIDIR, paketi
# durdurmaz. Ayrimi olcen ornek elimizde: `test_trusted_roots.py`
# AdminPanel'i test govdelerinin icinde ice aliyor; Linux'ta sorunsuz
# TOPLANDI ve kosu evresinde dustu (cikis kodu 1, 2200+ test kostu —
# B-046). `test_guvenlik_view.py` ayni bagimliligi modul seviyesinde
# tutuyordu ve butun paketi durdurdu (cikis kodu 2, sifir test — B-047).
# Ayni bagimlilik, iki farkli sonuc.


#: Modul seviyesinde korumasiz ithal edilemeyecek kokler.
#:
#: Bilerek `_FORBIDDEN_ROOTS`'un ta kendisi: CORE/DB'ye girmesi yasak olan
#: kokler ile toplama aninda cokebilen kokler ayni kume. Iki ayri liste
#: tutulsa biri guncellenip digeri unutulurdu.
_TOPLAMADA_RISKLI_KOKLER = _FORBIDDEN_ROOTS


def _test_dosyalari() -> list[Path]:
    """
    `tests/` altindaki her modul — `conftest.py` DAHIL.

    conftest'in toplanamamasi daha da kotu: tek bir dosyayi degil butun
    oturumu goturur.
    """
    return sorted(
        p for p in (_PROJECT_ROOT / "tests").glob("*.py")
        if "__pycache__" not in p.parts
    )


def _yakalanan_tipler(isleyici: ast.ExceptHandler) -> set[str]:
    """`except X:` / `except (X, Y):` -> {"X", "Y"}; ciplak `except:` -> {"*"}."""
    tip = isleyici.type
    if tip is None:
        return {"*"}
    parcalar = tip.elts if isinstance(tip, ast.Tuple) else [tip]
    adlar: set[str] = set()
    for parca in parcalar:
        if isinstance(parca, ast.Name):
            adlar.add(parca.id)
        elif isinstance(parca, ast.Attribute):
            adlar.add(parca.attr)
    return adlar


def _modul_seviyesinde_atliyor(isleyici: ast.ExceptHandler) -> bool:
    """Isleyici `pytest.skip(..., allow_module_level=True)` cagiriyor mu."""
    for ifade in isleyici.body:
        for dugum in ast.walk(ifade):
            if not (isinstance(dugum, ast.Call)
                    and isinstance(dugum.func, ast.Attribute)
                    and dugum.func.attr == "skip"):
                continue
            for kw in dugum.keywords:
                if (kw.arg == "allow_module_level"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True):
                    return True
    return False


def _referans_deseni_mi(dugum: ast.Try) -> bool:
    """
    `try` blogu, diger yedi UI test dosyasindaki KORUMANIN aynisi mi.

    Iki kosul birden: ImportError yakalaniyor VE modul seviyesinde
    atlaniyor. Yalnizca ilki saglanirsa (`except ImportError: pass`)
    toplama gecerdi ama testler NameError yagdirirdi — koruma degil,
    kusurun yerini degistirmek olurdu.
    """
    return any(
        ({"ImportError", "*"} & _yakalanan_tipler(isleyici))
        and _modul_seviyesinde_atliyor(isleyici)
        for isleyici in dugum.handlers
    )


def _modul_seviyesi_importlari(
    govde: list[ast.stmt], *, korumali: bool
) -> list[tuple[ast.stmt, bool]]:
    """
    Modul seviyesindeki import dugumlerini `(dugum, korumali_mi)` olarak toplar.

    Fonksiyon/sinif govdelerine GIRMIYOR — gerekcesi yukaridaki blokta.
    `if`/`for`/`while`/`with` govdelerine giriyor: modul seviyesinde
    kosullu bir import da toplama aninda calisir.
    """
    bulunan: list[tuple[ast.stmt, bool]] = []
    for dugum in govde:
        if isinstance(dugum, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(dugum, (ast.Import, ast.ImportFrom)):
            bulunan.append((dugum, korumali))
        elif isinstance(dugum, ast.Try):
            ic = korumali or _referans_deseni_mi(dugum)
            bulunan += _modul_seviyesi_importlari(dugum.body, korumali=ic)
            bulunan += _modul_seviyesi_importlari(dugum.orelse, korumali=ic)
            # Isleyici ve `finally` govdeleri korumanin DISI: oradaki bir
            # import'u yakalayacak baska bir sey yok.
            for isleyici in dugum.handlers:
                bulunan += _modul_seviyesi_importlari(
                    isleyici.body, korumali=korumali)
            bulunan += _modul_seviyesi_importlari(
                dugum.finalbody, korumali=korumali)
        elif isinstance(dugum, (ast.If, ast.For, ast.While, ast.With,
                                ast.AsyncFor, ast.AsyncWith)):
            bulunan += _modul_seviyesi_importlari(dugum.body, korumali=korumali)
            bulunan += _modul_seviyesi_importlari(
                getattr(dugum, "orelse", []), korumali=korumali)
    return bulunan


def _korumasiz_qt_importlari(yol: Path) -> list[tuple[int, str]]:
    """`(satir, modul)` — modul seviyesinde, korumasiz Qt/UI ithalleri."""
    agac = ast.parse(yol.read_text(encoding="utf-8"), filename=str(yol))
    bulunan: set[tuple[int, str]] = set()
    for dugum, korumali in _modul_seviyesi_importlari(agac.body, korumali=False):
        if korumali:
            continue
        for kok, tam in _ithal_edilenler(dugum):
            if kok in _TOPLAMADA_RISKLI_KOKLER:
                bulunan.add((dugum.lineno, tam))
    return sorted(bulunan)


def test_toplama_denetimi_dosyalari_gercekten_geziyor():
    """Bos liste donen bir tarayici asagidaki kurali sessizce gecirirdi."""
    dosyalar = _test_dosyalari()
    assert len(dosyalar) >= 40, f"yalnizca {len(dosyalar)} test modulu bulundu"
    adlar = {p.name for p in dosyalar}
    assert "conftest.py" in adlar, "conftest.py kapsam disi kaldi"
    assert "test_guvenlik_view.py" in adlar


def test_koruma_deseni_gercekten_taniniyor():
    """
    Denetim, korumali yedi dosyayi KORUMALI sayiyor mu.

    Bu olmadan kural "her seyi yakala" hatasina dusup yedi dosyayi kirmizi
    gosterebilir ve kendini kullanilamaz kilardi. Ayrica her dosyanin
    gercekten modul seviyesinde Qt/UI ithal ettigini de dogruluyor — aksi
    halde test bos yere yesil olurdu.
    """
    for ad in ("test_backup_verify_ui.py", "test_checkout_ui.py",
               "test_duplicate_prompt.py", "test_lock_overlay.py",
               "test_main_window_smoke.py", "test_pin_rotation_ui.py",
               "test_timestamp_ui.py", "test_guvenlik_view.py"):
        yol = _PROJECT_ROOT / "tests" / ad
        assert yol.exists(), f"{ad} yok — referans listesi eskimis"
        agac = ast.parse(yol.read_text(encoding="utf-8"))
        riskli = [
            (dugum, korumali)
            for dugum, korumali in _modul_seviyesi_importlari(
                agac.body, korumali=False)
            if any(kok in _TOPLAMADA_RISKLI_KOKLER
                   for kok, _ in _ithal_edilenler(dugum))
        ]
        assert riskli, f"{ad} modul seviyesinde Qt/UI ithal etmiyor — liste eskimis"
        assert all(korumali for _, korumali in riskli), f"{ad} korumali sayilmadi"


@pytest.mark.parametrize("yol", _test_dosyalari(), ids=lambda p: p.name)
def test_test_modulu_TOPLAMA_HATASI_uretemiyor(yol: Path):
    """
    Hicbir test modulu, modul seviyesinde korumasiz Qt/UI ithal etmemeli.

    Gerekce yukaridaki blokta; kisaca: patlayan bir modul seviyesi import
    tek bir dosyayi degil BUTUN PAKETI durdurur.
    """
    kusurlar = _korumasiz_qt_importlari(yol)
    assert not kusurlar, (
        f"{yol.name} modul seviyesinde korumasiz Qt/UI ithal ediyor:\n"
        + "\n".join(f"  · {yol.name}:{satir} -> {modul}"
                    for satir, modul in kusurlar)
        + "\n\nCiplak bir Linux runner'inda bu ImportError verir ve pytest'i "
          "TOPLAMA HATASIYLA durdurur (cikis kodu 2) — paketin geri kalani "
          "hic kosmaz. Diger yedi UI test dosyasindaki desene sarin:\n"
          "    try:\n"
          "        from PySide6.QtWidgets import ...\n"
          "        from UI.X import ...\n"
          "    except ImportError as _exc:\n"
          "        pytest.skip(f\"...({_exc})...\", allow_module_level=True)"
    )


def test_toplama_denetimi_KORUMASIZ_dosyayi_yakaliyor(tmp_path: Path):
    """Denetimin kendisi calisiyor mu — satir numarasi dahil olculuyor."""
    korumasiz = tmp_path / "test_korumasiz.py"
    korumasiz.write_text(
        "import os\n"
        "from PySide6.QtWidgets import QApplication\n"
        "from UI.main_window import HycleusWindow\n",
        encoding="utf-8")
    assert _korumasiz_qt_importlari(korumasiz) == [
        (2, "PySide6.QtWidgets"), (3, "UI.main_window")]


def test_toplama_denetimi_KORUMALI_dosyayi_geciriyor(tmp_path: Path):
    korumali = tmp_path / "test_korumali.py"
    korumali.write_text(
        "import pytest\n"
        "try:\n"
        "    from PySide6.QtWidgets import QApplication\n"
        "    from UI.main_window import HycleusWindow\n"
        "except ImportError as _exc:\n"
        "    pytest.skip(str(_exc), allow_module_level=True)\n",
        encoding="utf-8")
    assert _korumasiz_qt_importlari(korumali) == []


def test_YARIM_koruma_yeterli_sayilmiyor(tmp_path: Path):
    """
    Uc yarim koruma, ucu de reddedilmeli.

    `except ImportError: pass` toplamayi gecirir ama testleri NameError'a
    bogar; yanlis istisna tipi hic yakalamaz; atlamasiz `pytest.skip`
    modul seviyesinde calismaz (pytest'in kendisi hata verir).
    """
    yarim = tmp_path / "test_yarim.py"
    yarim.write_text(
        "try:\n"
        "    from PySide6.QtWidgets import QApplication\n"
        "except ImportError:\n"
        "    pass\n",
        encoding="utf-8")
    assert _korumasiz_qt_importlari(yarim) == [(2, "PySide6.QtWidgets")]

    yanlis_tip = tmp_path / "test_yanlis_tip.py"
    yanlis_tip.write_text(
        "import pytest\n"
        "try:\n"
        "    from UI.main_window import HycleusWindow\n"
        "except KeyError:\n"
        "    pytest.skip('x', allow_module_level=True)\n",
        encoding="utf-8")
    assert _korumasiz_qt_importlari(yanlis_tip) == [(3, "UI.main_window")]

    sessiz = tmp_path / "test_sessiz.py"
    sessiz.write_text(
        "import pytest\n"
        "try:\n"
        "    from UI.main_window import HycleusWindow\n"
        "except ImportError:\n"
        "    pytest.skip('x')\n",
        encoding="utf-8")
    assert _korumasiz_qt_importlari(sessiz) == [(3, "UI.main_window")]


def test_FONKSIYON_ICI_import_kapsam_disi(tmp_path: Path):
    """
    Bilincli muafiyet — `test_trusted_roots.py`'nin yaptigi sey.

    Fonksiyon govdesindeki import calisma aninda patlar: o bir test
    basarisizligidir, toplama hatasi degil. Olculdu: `85c6dcc`'de ubuntu
    cikis kodu 1 verdi ve 2200+ test kostu; `89826bd`'de modul seviyesi
    import yuzunden cikis kodu 2 verdi ve hicbir test kosmadi.
    """
    yerel = tmp_path / "test_yerel.py"
    yerel.write_text(
        "def test_x():\n"
        "    from PySide6.QtWidgets import QApplication\n"
        "    from UI.AdminPanel import AdminPanel\n"
        "    assert QApplication and AdminPanel\n"
        "class T:\n"
        "    from UI.main_window import HycleusWindow\n",
        encoding="utf-8")
    assert _korumasiz_qt_importlari(yerel) == []


def test_KOSULLU_modul_seviyesi_import_kapsam_ICI(tmp_path: Path):
    """
    `if`/`with` govdesindeki modul seviyesi import de toplama aninda calisir.

    Kural "yalnizca `tree.body`'nin ilk seviyesi" diye yazilsaydi, tek bir
    `if True:` satiri onu atlatirdi.
    """
    kosullu = tmp_path / "test_kosullu.py"
    kosullu.write_text(
        "import sys\n"
        "if sys.platform == 'win32':\n"
        "    from UI.main_window import HycleusWindow\n",
        encoding="utf-8")
    assert _korumasiz_qt_importlari(kosullu) == [(3, "UI.main_window")]


def test_YORUMDAKI_import_toplama_denetimini_kandirmiyor(tmp_path: Path):
    """Kurali ANLATAN metin kurala takilmamali (B-024 sinifi)."""
    sahte = tmp_path / "test_sahte.py"
    sahte.write_text(
        '"""from PySide6.QtWidgets import QApplication yazmayin."""\n'
        "# from UI.main_window import HycleusWindow  <- yasak\n"
        "SABIT = 'from PySide6.QtCore import Qt'\n",
        encoding="utf-8")
    assert _korumasiz_qt_importlari(sahte) == []
