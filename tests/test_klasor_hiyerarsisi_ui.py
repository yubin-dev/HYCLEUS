"""
HYCLEUS — Klasör hiyerarşisi UI (B-123)

Onaylanan üç madde:
  1. Alt klasör oluşturma — sağ tık "Buraya Alt Klasör Ekle"
     (`_on_create_subfolder()`), `_on_create_folder()`'ın parent_id'li hâli.
  2. Klasör taşıma — sağ tık "Taşı…" dialogu (`_on_move_folder()`),
     drag-drop DEĞİL (gerekçe: BACKLOG B-123, döngü koruması ve test
     edilebilirlik). Hedef listesi kendini VE kendi alt ağacını
     `is_descendant()` ile BAŞTAN eler.
  3. Kenar çubuğu artık TÜM hiyerarşiyi (girinti) VE klasör başına dosya
     sayısını (`list_folders()`, zaten vardı ama sidebar'a hiç bağlı
     değildi) gösteriyor.

`CORE/folders.py`'nin kendi (döngü koruması dahil) testleri
`tests/test_folders.py`'de; bu dosya yalnızca UI KATMANINI — doğru CORE
fonksiyonunun doğru parametrelerle çağrıldığını ve sonucun kenar
çubuğuna doğru yansıdığını — sınıyor.

Not: `QInputDialog.getText`/`getItem` STATIK metotlar oldukları için
güvenle monkeypatch'lenebiliyor (canlı doğrulandı) — ama `QMenu.exec()`
(sağ tık menüsünün kendisi) bir ÖRNEK metodu ve monkeypatch'e KAPALI
(denendi: gerçek modal döngü açılıp sonsuza kadar bekliyor). Bu yüzden
context menu WIRING'i (`_on_folder_context_menu()`) AST ile denetleniyor
(bkz. `tests/test_kasa_ekrani_kozmetik_ve_usb_rozeti.py`'nin AYNI
gerekçeli testi), doğrudan çağrılmıyor.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication

    from UI.main_window import HycleusWindow
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE.folders import create_folder

_HWID = "TEST-HWID-DB"
_KEY = b"K" * 32


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


@pytest.fixture
def isolate_safezone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from CORE.safezone import SAFEZONE_ENV_VAR
    hedef = tmp_path / "safezone"
    monkeypatch.setenv(SAFEZONE_ENV_VAR, str(hedef))
    return hedef


@pytest.fixture
def win(qapp, db, isolate_safezone, monkeypatch):
    from UI import main_window as mw

    monkeypatch.setattr(mw, "get_usb_hwid", lambda: _HWID)
    cur = db.execute(
        "INSERT INTO users (username, password_hash, hwid, role) VALUES (?, ?, ?, ?)",
        ("ay", "argon2$sahte", _HWID, "admin"),
    )
    uid = int(cur.lastrowid)
    window = HycleusWindow(hwid=_HWID, key=_KEY, role="Yönetici", username="ay", user_id=uid)
    window._usb_timer.stop()
    try:
        yield window
    finally:
        for ad in ("_usb_timer", "_expiry_timer", "_idle_timer"):
            timer = getattr(window, ad, None)
            if timer is not None:
                timer.stop()
        app = QApplication.instance()
        if app is not None:
            app.removeEventFilter(window)
        window.close()
        window.deleteLater()


def _dosya_ekle(db, folder_id: int, ad: str = "a.pdf") -> int:
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label, folder_id) VALUES (?,?,?,?)",
        (ad, f"/vault/{ad}.hcl", "Genel", folder_id),
    )
    return int(cur.lastrowid)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Kenar çubuğu — hiyerarşi + dosya sayısı
# ══════════════════════════════════════════════════════════════════════════════


def test_sidebar_uc_seviyeyi_de_gosteriyor(win, db) -> None:
    """Eskiden yalnızca kök seviye görünürdü — üç seviye de listede olmalı."""
    ust = create_folder(db, "Ust", owner_id=win._user_id)
    orta = create_folder(db, "Orta", owner_id=win._user_id, parent_id=ust)
    alt = create_folder(db, "Alt", owner_id=win._user_id, parent_id=orta)

    win._refresh_folder_sidebar()

    assert set(win._folder_btns) == {ust, orta, alt}


def test_sidebar_derinlik_arttikca_girinti_artiyor(win, db) -> None:
    ust = create_folder(db, "Ust", owner_id=win._user_id)
    alt = create_folder(db, "Alt", owner_id=win._user_id, parent_id=ust)
    torun = create_folder(db, "Torun", owner_id=win._user_id, parent_id=alt)

    win._refresh_folder_sidebar()

    girinti_ust = len(win._folder_btns[ust].text()) - len(win._folder_btns[ust].text().lstrip())
    girinti_alt = len(win._folder_btns[alt].text()) - len(win._folder_btns[alt].text().lstrip())
    girinti_torun = len(win._folder_btns[torun].text()) - len(win._folder_btns[torun].text().lstrip())
    assert girinti_ust < girinti_alt < girinti_torun


def test_sidebar_klasor_basina_dosya_sayisini_gosteriyor(win, db) -> None:
    fid = create_folder(db, "Belgeler", owner_id=win._user_id)
    _dosya_ekle(db, fid, "a.pdf")
    _dosya_ekle(db, fid, "b.pdf")

    win._refresh_folder_sidebar()

    assert win._folder_btns[fid].text().rstrip().endswith("2")


# ══════════════════════════════════════════════════════════════════════════════
# 2. Alt klasör oluşturma
# ══════════════════════════════════════════════════════════════════════════════


def test_on_create_subfolder_dogru_parenti_yaziyor(win, db, monkeypatch) -> None:
    import UI.main_window_tree as mwt

    ust = create_folder(db, "Ust", owner_id=win._user_id)
    monkeypatch.setattr(mwt.QInputDialog, "getText", lambda *a, **k: ("YeniAlt", True))

    win._on_create_subfolder(ust, "Ust")

    satir = db.fetchone("SELECT parent_id FROM folders WHERE name = 'YeniAlt'")
    assert satir is not None
    assert satir["parent_id"] == ust


def test_on_create_subfolder_bos_ad_ile_hicbir_sey_olusturmuyor(win, monkeypatch) -> None:
    import UI.main_window_tree as mwt

    monkeypatch.setattr(mwt.QInputDialog, "getText", lambda *a, **k: ("   ", True))
    onceki = win._folder_btns.copy()

    win._on_create_subfolder(1, "Ust")

    assert win._folder_btns.keys() == onceki.keys()


def test_root_olusturma_hala_parentsiz(win, db, monkeypatch) -> None:
    """`_on_create_folder()` (kök düğmesi) DEĞİŞMEDİ — parent_id=None kalmalı."""
    import UI.main_window_tree as mwt

    monkeypatch.setattr(mwt.QInputDialog, "getText", lambda *a, **k: ("KokKlasor", True))
    win._on_create_folder()
    satir = db.fetchone("SELECT parent_id FROM folders WHERE name = 'KokKlasor'")
    assert satir["parent_id"] is None


# ══════════════════════════════════════════════════════════════════════════════
# 3. Taşıma — hedef listesi ve gerçek taşıma
# ══════════════════════════════════════════════════════════════════════════════


def test_move_folder_secenek_listesi_kendini_ve_alt_agacini_haric_tutuyor(
    win, db, monkeypatch
) -> None:
    import UI.main_window_tree as mwt

    a = create_folder(db, "A", owner_id=win._user_id)
    create_folder(db, "B", owner_id=win._user_id, parent_id=a)  # A'nın çocuğu
    create_folder(db, "C", owner_id=win._user_id)  # alakasız

    yakalanan: dict = {}

    def sahte_getItem(*args, **kwargs):
        yakalanan["items"] = args[3]
        return (args[3][0], True)

    monkeypatch.setattr(mwt.QInputDialog, "getItem", sahte_getItem)

    win._on_move_folder(a, "A")

    assert "A" not in yakalanan["items"], "kendisi seçenek olarak sunulmuş"
    assert "B" not in yakalanan["items"], "kendi alt ağacı seçenek olarak sunulmuş"
    assert "C" in yakalanan["items"]


def test_move_folder_secilen_hedefe_gercekten_tasiyor(win, db, monkeypatch) -> None:
    import UI.main_window_tree as mwt

    a = create_folder(db, "A", owner_id=win._user_id)
    b = create_folder(db, "B", owner_id=win._user_id)
    monkeypatch.setattr(mwt.QInputDialog, "getItem", lambda *a2, **k: ("B", True))

    win._on_move_folder(a, "A")

    assert db.fetchone("SELECT parent_id FROM folders WHERE id = ?", (a,))["parent_id"] == b


def test_move_folder_kok_secilince_parentsiz_kaliyor(win, db, monkeypatch) -> None:
    import UI.main_window_tree as mwt

    ust = create_folder(db, "Ust", owner_id=win._user_id)
    alt = create_folder(db, "Alt", owner_id=win._user_id, parent_id=ust)
    monkeypatch.setattr(
        mwt.QInputDialog, "getItem",
        lambda *a2, **k: ("— Kök (üst klasör yok) —", True),
    )

    win._on_move_folder(alt, "Alt")

    assert db.fetchone("SELECT parent_id FROM folders WHERE id = ?", (alt,))["parent_id"] is None


def test_move_folder_iptal_edilirse_HICBIR_SEY_degismiyor(win, db, monkeypatch) -> None:
    import UI.main_window_tree as mwt

    a = create_folder(db, "A", owner_id=win._user_id)
    create_folder(db, "B", owner_id=win._user_id)
    monkeypatch.setattr(mwt.QInputDialog, "getItem", lambda *a2, **k: ("B", False))  # ok=False

    win._on_move_folder(a, "A")

    assert db.fetchone("SELECT parent_id FROM folders WHERE id = ?", (a,))["parent_id"] is None


# ══════════════════════════════════════════════════════════════════════════════
# 4. Silme onayı — alt ağaç boyutu
# ══════════════════════════════════════════════════════════════════════════════


def test_silme_onayi_yaprak_klasor_icin_alt_klasorden_bahsetmiyor(
    win, db, monkeypatch
) -> None:
    fid = create_folder(db, "Yaprak", owner_id=win._user_id)
    _dosya_ekle(db, fid)
    yakalanan: dict = {}

    def sahte_question(_self, _baslik, mesaj, *a, **k):
        yakalanan["mesaj"] = mesaj
        from PySide6.QtWidgets import QMessageBox
        return QMessageBox.No  # işlemi iptal et, yalnızca metni oku

    import UI.main_window_tree as mwt
    monkeypatch.setattr(mwt.QMessageBox, "question", sahte_question)

    win._on_folder_delete(fid, "Yaprak")

    assert "alt klasör" not in yakalanan["mesaj"]
    assert "1 dosya" in yakalanan["mesaj"]


def test_silme_onayi_alt_agacli_klasor_icin_kapsami_gosteriyor(win, db, monkeypatch) -> None:
    ust = create_folder(db, "Ust", owner_id=win._user_id)
    alt1 = create_folder(db, "Alt1", owner_id=win._user_id, parent_id=ust)
    create_folder(db, "Alt2", owner_id=win._user_id, parent_id=ust)
    _dosya_ekle(db, ust, "u.pdf")
    _dosya_ekle(db, alt1, "a.pdf")
    yakalanan: dict = {}

    def sahte_question(_self, _baslik, mesaj, *a, **k):
        yakalanan["mesaj"] = mesaj
        from PySide6.QtWidgets import QMessageBox
        return QMessageBox.No

    import UI.main_window_tree as mwt
    monkeypatch.setattr(mwt.QMessageBox, "question", sahte_question)

    win._on_folder_delete(ust, "Ust")

    assert "2 alt klasörü" in yakalanan["mesaj"]
    assert "2 dosya" in yakalanan["mesaj"]


def test_silme_onayinda_hayir_denince_HICBIR_SEY_silinmiyor(win, db, monkeypatch) -> None:
    ust = create_folder(db, "Ust", owner_id=win._user_id)
    create_folder(db, "Alt", owner_id=win._user_id, parent_id=ust)

    import UI.main_window_tree as mwt
    from PySide6.QtWidgets import QMessageBox
    monkeypatch.setattr(mwt.QMessageBox, "question", lambda *a, **k: QMessageBox.No)

    win._on_folder_delete(ust, "Ust")

    assert db.fetchone("SELECT id FROM folders WHERE id = ?", (ust,)) is not None


# ══════════════════════════════════════════════════════════════════════════════
# 5. Sağ tık menüsü kablolaması — AST (gerçek modal AÇILMADAN)
# ══════════════════════════════════════════════════════════════════════════════


def test_folder_context_menu_yeni_iki_eylemi_dogru_metotlara_bagliyor() -> None:
    """
    `_on_folder_context_menu()` GERÇEK bir `QMenu.exec()` çağırıyor — bu
    kod tabanında monkeypatch'e KAPALI olduğu ayrıca doğrulandı (bkz. bu
    paketteki `test_kasa_ekrani_kozmetik_ve_usb_rozeti.py`'nin aynı
    gerekçeli testi). Aynı yol: kaynak ayrıştırılıp iki YENİ eylemin
    (alt klasör ekle, taşı) doğru metotlara bağlı olduğu doğrulanıyor.
    """
    import ast

    kaynak = (
        Path(__file__).resolve().parent.parent / "UI" / "main_window_tree.py"
    ).read_text(encoding="utf-8")
    agac = ast.parse(kaynak)
    fn = next(
        n for n in ast.walk(agac)
        if isinstance(n, ast.FunctionDef) and n.name == "_on_folder_context_menu"
    )
    cagrilar = {
        n.func.attr for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert "_on_create_subfolder" in cagrilar, "'Buraya Alt Klasör Ekle' bağlı değil"
    assert "_on_move_folder" in cagrilar, "'Taşı…' bağlı değil"
    # Mevcut üç eylem de KAYBOLMAMALI (B-123 öncesi davranış).
    assert "_on_folder_download" in cagrilar
    assert "_on_folder_move_to_imha" in cagrilar
    assert "_on_folder_delete" in cagrilar
