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
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
    return roots


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
