"""
HYCLEUS — HycleusWindow duman testi (refactor emniyet ağı)

Bu paketin amacı hata aramak DEĞİL, 2.7 refactor'ünün davranışı
DEĞİŞTİRMEDİĞİNİ kanıtlayacak bir taban çizgisi kurmak. main_window.py 2960
satır ve mixin'lere bölünecek; bölme sırasında bir metodun düşmesi, bir
sinyalin bağlanmaması ya da bir widget'ın kurulmaması sessizce olabilir.

Bu yüzden testler ÖZELLİKLE yüzeye bakıyor:
  · pencere kuruluyor mu, widget ağacının omurgası yerinde mi
  · HycleusWindow'un metot envanteri eksilmiş mi (mixin bölmesinin ağı)
  · tema, rol kısıtlamaları, kilit döngüsü, etiket geçişi çalışıyor mu

Metot envanteri ALT KÜME olarak denetleniyor, eşitlik olarak değil: yeni
metot eklemek serbest, mevcut birini KAYBETMEK değil. Refactor'ün
kaybedebileceği tek şey bu.

Fizibilite notu
---------------
Plan aşamasında "DB + anahtar + USB polling yüzünden kurulamayabilir"
demiştim; denendi ve KURULUYOR. QTimer'lar __init__'te başlıyor ama olay
döngüsü çalışmadığı için tetiklenmiyorlar, dolayısıyla USB yoklaması bu
testlerde hiç çalışmıyor. Beklenenden geniş bir ağ kurulabildi.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Qt import'ları tek korumanın altında — gerekçe: tests/test_lock_overlay.py
try:
    from PySide6.QtWidgets import QApplication, QMainWindow

    from UI.main_window import HycleusWindow
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )


_KEY = b"K" * 32
_HWID = "SMOKE-HWID"

#: 2.7 refactor'ünden ÖNCEKİ metot envanteri (2960 satırlık main_window.py,
#: commit 1a55568). Mixin'lere bölündükten sonra bu adların HEPSİ hâlâ
#: HycleusWindow üzerinde çözümlenebilir olmalı.
_BASELINE_METHODS = frozenset({
    "_apply_role_restrictions", "_apply_tag_theme", "_apply_theme", "_build_ui",
    "_fmt_size", "_folder_btn_style", "_get_imha_ttl_hours", "_handle_dropped_file",
    "_handle_dropped_folder", "_insert_row", "_load_folder_files", "_load_label",
    "_load_tag_files", "_lock", "_make_action_bar", "_make_content",
    "_make_sidebar", "_make_top_bar", "_nav_btn_style", "_on_add_file",
    "_on_add_folder", "_on_batch_complete", "_on_blacklist_usb", "_on_bulk_context_menu",
    "_on_context_menu", "_on_create_folder", "_on_ctx_assign_tags", "_on_ctx_bulk_approve",
    "_on_ctx_bulk_assign_tags", "_on_ctx_bulk_download", "_on_ctx_bulk_move_to_imha",
    "_on_ctx_bulk_move_to_kritik", "_on_ctx_download", "_on_ctx_move_label",
    "_on_ctx_move_to_folder", "_on_ctx_move_to_imha", "_on_ctx_move_to_kritik",
    "_on_ctx_scan", "_on_ctx_scan_done", "_on_file_done", "_on_folder_click",
    "_on_folder_context_menu", "_on_folder_delete", "_on_folder_download",
    "_on_folder_move_to_imha", "_on_hamburger_menu", "_on_new_tag", "_on_open_usb_tokens",
    "_on_open_pending", "_on_open_admin_settings",
    "_on_open_audit_log", "_on_open_contact", "_on_open_profile", "_on_overlay_clicked",
    "_on_scan_all", "_on_scan_done", "_on_sidebar_click", "_on_tag_click",
    "_on_tag_context_menu", "_on_tag_delete", "_poll_usb", "_populate_table",
    "_purge_expired_file", "_refresh_folder_sidebar", "_refresh_tag_sidebar",
    "_refresh_usb_badge", "_reset_drop_hint_style", "_search_files", "_set_scan_badge",
    "_start_batch", "_start_scan", "_tag_btn_style", "_tick_expiry", "_tick_idle",
    "_toggle_maximize", "_toggle_theme", "_trigger_usb_reauth", "_unlock",
    "_unlock_idle", "_update_progress_banner", "reload_idle_timeout",
})

#: Pencerede bulunması gereken alanlar. Mixin'lere bölünürken __init__'in
#: bir alanı kurmayı unutması, ilk kullanımına kadar fark edilmezdi.
_BASELINE_ATTRS = (
    "_hwid", "_key", "_role", "_user_id", "_table", "_nav_btns", "_current_label",
    "_locked", "_lock_reasons", "_overlay", "_blur", "_idle", "_pool",
    "_usb_timer", "_expiry_timer", "_idle_timer", "_T", "_dark",
)


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
    """
    Gerçek HycleusWindow — izole DB, sahte USB.

    get_usb_hwid sabitleniyor: gerçek donanım yoklaması test makinesine göre
    farklı sonuç verir ve testleri makineye bağımlı yapardı.

    Teardown'da zamanlayıcılar durduruluyor ve olay filtresi kaldırılıyor;
    aksi hâlde her test QApplication'a bir filtre daha ekler ve sonrakiler
    birbirini etkiler.
    """
    from UI import main_window as mw

    monkeypatch.setattr(mw, "get_usb_hwid", lambda: _HWID)
    window = HycleusWindow(hwid=_HWID, key=_KEY, role="Yönetici")
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


# ══════════════════════════════════════════════════════════════════════════════
# 1. Kurulum
# ══════════════════════════════════════════════════════════════════════════════


def test_window_constructs(win):
    assert isinstance(win, QMainWindow)
    assert win.windowTitle() == "HYCLEUS"


def test_central_widget_and_table_exist(win):
    assert win.centralWidget() is not None
    assert win._table.columnCount() == 5


def test_navigation_buttons_cover_every_label(win):
    assert set(win._nav_btns) == {"Genel", "Kritik", "Karantina", "Imha"}


def test_starts_on_the_general_label_unlocked(win):
    assert win._current_label == "Genel"
    assert win._locked is False
    assert win._lock_reasons == set()


@pytest.mark.parametrize("attr", _BASELINE_ATTRS)
def test_expected_attribute_is_initialised(win, attr: str):
    assert hasattr(win, attr), f"__init__ '{attr}' alanını kurmuyor"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Metot envanteri — mixin bölmesinin asıl ağı
# ══════════════════════════════════════════════════════════════════════════════


def test_no_baseline_method_is_lost():
    """
    Refactor öncesi var olan HER metot hâlâ çözümlenebilmeli.

    Alt küme denetimi: yeni metot eklemek serbest, mevcut birini kaybetmek
    değil. Bir metot mixin'e taşınırken sınıf listesinden düşerse ya da adı
    yanlış yazılırsa bu test tam olarak hangisi olduğunu söyler.
    """
    eksik = sorted(ad for ad in _BASELINE_METHODS if not hasattr(HycleusWindow, ad))
    assert not eksik, f"Refactor sırasında kaybolan metotlar: {eksik}"


@pytest.mark.parametrize("ad", sorted(_BASELINE_METHODS))
def test_baseline_method_is_callable(ad: str):
    """Ad var ama çağrılabilir değilse (ör. yanlışlıkla alan olmuşsa) yakala."""
    assert callable(getattr(HycleusWindow, ad, None)), f"{ad} çağrılabilir değil"


def test_qt_event_handlers_are_still_overridden():
    """
    Qt geri çağrımları HycleusWindow üzerinde TANIMLI kalmalı.

    Bunlar Qt tarafından ada göre çağrılıyor; bir mixin'e taşınıp
    MRO'dan düşerlerse sürükle-bırak ve hareketsizlik kilidi sessizce
    çalışmaz hâle gelir — istisna da fırlamaz.
    """
    for ad in ("dragEnterEvent", "dragMoveEvent", "dragLeaveEvent",
               "dropEvent", "resizeEvent", "eventFilter"):
        assert ad in vars(HycleusWindow) or any(
            ad in vars(taban) for taban in HycleusWindow.__mro__
            if taban.__module__.startswith("UI.")
        ), f"{ad} artık UI katmanında tanımlı değil"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Davranış — refactor'ün korunması gereken kısmı
# ══════════════════════════════════════════════════════════════════════════════


def test_theme_toggle_switches_and_restores(win):
    ilk = win._dark
    win._toggle_theme()
    assert win._dark is not ilk
    win._toggle_theme()
    assert win._dark is ilk


def test_theme_palette_has_the_expected_keys(win):
    for anahtar in ("red", "yellow", "green", "sidebar", "subtext"):
        assert anahtar in win._T, f"tema paletinde '{anahtar}' yok"


@pytest.mark.parametrize("role", ["Yönetici", "Standart", "Salt Okunur"])
def test_role_restrictions_apply_without_error(qapp, db, isolate_safezone,
                                               monkeypatch, role: str):
    from UI import main_window as mw

    monkeypatch.setattr(mw, "get_usb_hwid", lambda: _HWID)
    window = HycleusWindow(hwid=_HWID, key=_KEY, role=role)
    try:
        window._apply_role_restrictions()
        assert window._role == role
    finally:
        for ad in ("_usb_timer", "_expiry_timer", "_idle_timer"):
            getattr(window, ad).stop()
        QApplication.instance().removeEventFilter(window)
        window.close()


@pytest.mark.parametrize("label", ["Genel", "Kritik", "Karantina", "Imha"])
def test_switching_labels_loads_without_error(win, label: str):
    win._on_sidebar_click(label, win._nav_btns[label])
    assert win._current_label == label


def test_lock_and_unlock_cycle(win):
    win._lock("usb")
    assert win._locked is True
    assert win.centralWidget().isEnabled() is False

    win._unlock("usb")
    assert win._locked is False
    assert win.centralWidget().isEnabled() is True


def test_idle_lock_survives_a_usb_unlock(win):
    """test_lock_overlay.py'deki senaryonun gerçek pencerede karşılığı."""
    win._lock("idle")
    win._lock("usb")
    win._unlock("usb")
    assert win._locked is True
    assert win._lock_reasons == {"idle"}


def test_table_populates_from_database_rows(win, db, tmp_path: Path):
    """DB'den tabloya giden yol — refactor'ün en çok dokunacağı akış."""
    for i in range(3):
        db.execute(
            "INSERT INTO files (filename, filepath, label, size_bytes)"
            " VALUES (?, ?, ?, ?)",
            (f"belge{i}.pdf", str(tmp_path / f"belge{i}.pdf.hcl"), "Genel", 1234),
        )
    win._load_label("Genel")
    assert win._table.rowCount() == 3


def test_search_filters_the_table(win, db, tmp_path: Path):
    db.execute(
        "INSERT INTO files (filename, filepath, label) VALUES (?, ?, ?)",
        ("rapor_2026.pdf", str(tmp_path / "rapor.hcl"), "Genel"),
    )
    db.execute(
        "INSERT INTO files (filename, filepath, label) VALUES (?, ?, ?)",
        ("sozlesme.docx", str(tmp_path / "sozlesme.hcl"), "Genel"),
    )
    win._search_files("rapor")
    assert win._table.rowCount() == 1


def test_empty_search_restores_the_current_label(win, db, tmp_path: Path):
    db.execute(
        "INSERT INTO files (filename, filepath, label) VALUES (?, ?, ?)",
        ("a.pdf", str(tmp_path / "a.hcl"), "Genel"),
    )
    win._search_files("bulunamayacak_bir_sey")
    assert win._table.rowCount() == 0
    win._search_files("")
    assert win._table.rowCount() == 1


@pytest.mark.parametrize(("bayt", "beklenen"), [
    (0,             "0.0 B"),
    (1,             "1.0 B"),
    (1023,          "1023.0 B"),
    (1024,          "1.0 KB"),
    (1536,          "1.5 KB"),
    (1024**2,       "1.0 MB"),
    (1024**3,       "1.0 GB"),
    (1024**4,       "1.0 TB"),
])
def test_fmt_size_output_is_frozen(bayt: int, beklenen: str):
    """
    Saf yardımcı — refactor'de taşınacak, çıktısı BİREBİR aynı kalmalı.

    Beklenen değerler mevcut davranıştan ÖLÇÜLEREK alındı, tahmin edilerek
    değil ("0.0 B", "1023.0 B" — biçim güzel olmayabilir ama karakterizasyon
    testinin işi güzelleştirmek değil, mevcut davranışı sabitlemek).
    Biçimi düzeltmek ayrı bir iş; bu test onu bilinçli bir karar hâline
    getiriyor.
    """
    assert HycleusWindow._fmt_size(bayt) == beklenen


def test_imha_ttl_default_is_read_from_settings(win, db):
    assert win._get_imha_ttl_hours() == 24
    db.set_setting("imha_ttl_hours", "6")
    assert win._get_imha_ttl_hours() == 6


def test_tag_and_folder_sidebars_refresh(win):
    win._refresh_tag_sidebar()
    win._refresh_folder_sidebar()


def test_expiry_tick_is_a_noop_outside_the_imha_label(win):
    win._on_sidebar_click("Genel", win._nav_btns["Genel"])
    win._tick_expiry()          # istisna fırlatmamalı
    assert win._current_label == "Genel"
