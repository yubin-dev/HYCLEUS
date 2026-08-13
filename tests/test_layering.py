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
