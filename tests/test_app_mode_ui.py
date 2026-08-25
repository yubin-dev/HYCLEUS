"""
Bireysel/Kurumsal görünüm modu — UI entegrasyonu

CORE/app_mode.py'nin kendisi tests/test_app_mode.py'de ölçülüyor. Bu
paket "mod gerçekten neyi gizliyor, neyi GİZLEMİYOR" sorusunu soruyor:

  1. Ana pencere: Bireysel'de yalnızca "YÖNETİCİ" başlığı kayboluyor,
     USB Yönetimi/Kara Listeye Al/Denetim Günlüğü/Destek düğmeleri KALIYOR.
  2. RBAC MUTASYONLA doğrulanıyor: Salt Okunur/Standart rolde mod ne
     olursa olsun Yönetici bölümü hâlâ tamamen gizli — mod hiçbir zaman
     bir görünürlüğü GENİŞLETMİYOR, yalnızca daraltabiliyor.
  3. AdminPanel: Bireysel'de "Bekleyen Kayıtlar" sekmesi gizleniyor ama
     altındaki veri ve akış (`_load_pending`, `_on_approve`) silinmiyor —
     Kurumsal'a dönünce var olan bir bekleyen kayıt hâlâ görünüyor.
  4. Mod değişimi `settings` tablosu DIŞINDA hiçbir tabloya dokunmuyor —
     ileri-geri geçiş kasayı/veritabanını bozmuyor.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QMessageBox

    from UI.AdminPanel import AdminPanel
    from UI.main_window import HycleusWindow
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE.app_mode import BIREYSEL, KURUMSAL, get_app_mode, set_app_mode

_KEY = b"K" * 32
_HWID = "MODE-TEST-HWID"

_ADMIN_WIDGETS = (
    "_admin_sep", "_blacklist_btn", "_audit_log_btn",
    "_admin_panel_btn", "_support_btn",
)


@pytest.fixture
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


def _pencere(qapp, db, isolate_safezone, monkeypatch, role: str) -> HycleusWindow:
    from UI import main_window as mw

    monkeypatch.setattr(mw, "get_usb_hwid", lambda: _HWID)
    window = HycleusWindow(hwid=_HWID, key=_KEY, role=role)
    return window


def _pencereyi_kapat(window: HycleusWindow) -> None:
    for ad in ("_usb_timer", "_expiry_timer", "_idle_timer"):
        getattr(window, ad).stop()
    QApplication.instance().removeEventFilter(window)
    window.close()


@pytest.fixture(autouse=True)
def _admin_panel_canli_yetki(db, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    B-064/B-066: `AdminPanel` artık her yetkili işlemden (ör.
    `_on_save_settings`) önce USB'nin hâlâ takılı olduğunu VE DB'deki
    yetkinin hâlâ girişteki gibi olduğunu canlı doğruluyor
    (`UI.AdminPanel._yonetici_hala_yetkili`). Bu dosyadaki testler hep
    `_HWID` kullanıyor; o USB'nin takılı kaldığını simüle edip ona
    karşılık gelen onaylı yönetici satırını ekliyoruz — aksi hâlde
    her `AdminPanel(current_hwid=_HWID, role="Yönetici")` sonrası
    çağrılan yetkili bir işlem sessizce reddedilir (panel kapanır).
    """
    import UI.AdminPanel as _ap

    monkeypatch.setattr(_ap, "get_usb_hwid", lambda: _HWID)
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, 'admin', 'approved', ?)",
        ("app-mode-test-admin", "x", _HWID),
    )


@pytest.fixture(autouse=True)
def _diyalog_engelle(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """AdminPanel'in `QMessageBox.information/...` çağrıları testi bloklamasın."""
    gosterilen: list[tuple[str, str]] = []

    def _yakala(tur: str):
        def _f(_parent, baslik, metin, *a, **kw):
            gosterilen.append((tur, f"{baslik}: {metin}"))
            return 0
        return _f

    for ad in ("warning", "critical", "information", "question"):
        monkeypatch.setattr(QMessageBox, ad, staticmethod(_yakala(ad)))
    return gosterilen


# ══════════════════════════════════════════════════════════════════════════════
# 1-2. Ana pencere — hangi widget gizleniyor, hangisi kalıyor
# ══════════════════════════════════════════════════════════════════════════════


#: Pencere hiç `show()` edilmediğinde `isVisible()` üst pencereye bağlı
#: olduğu için her zaman False döner (main.py'nin de bilerek ele aldığı
#: Qt tuhaflığı — `_apply_role_restrictions()` show() SONRASI çağrılıyor).
#: `isHidden()` widget'ın KENDİSİNE `setVisible(False)` çağrılıp
#: çağrılmadığını söylüyor, üst pencerenin gösterilip gösterilmediğinden
#: bağımsız — burada ölçülmek istenen tam olarak bu.
def _gizli_mi(widget) -> bool:
    return widget.isHidden()


def test_varsayilan_KURUMSALDA_hicbir_sey_gizlenmiyor(qapp, db, isolate_safezone, monkeypatch):
    window = _pencere(qapp, db, isolate_safezone, monkeypatch, "Yönetici")
    try:
        assert get_app_mode(db) == KURUMSAL
        window._apply_role_restrictions()
        assert _gizli_mi(window._admin_label) is False
    finally:
        _pencereyi_kapat(window)


def test_BIREYSELDE_yalnizca_baslik_gizlenir_dugmeler_kalir(qapp, db, isolate_safezone, monkeypatch):
    window = _pencere(qapp, db, isolate_safezone, monkeypatch, "Yönetici")
    try:
        set_app_mode(db, BIREYSEL)
        window.reload_app_mode()

        assert _gizli_mi(window._admin_label) is True, (
            "'Yönetici' başlığı Bireysel modda hâlâ görünüyor"
        )
        for ad in _ADMIN_WIDGETS:
            assert _gizli_mi(getattr(window, ad)) is False, (
                f"{ad} Bireysel modda gizlenmemeliydi — yalnızca başlık gizlenir"
            )
    finally:
        _pencereyi_kapat(window)


@pytest.mark.parametrize("role", ["Standart", "Salt Okunur"])
def test_BIREYSELDE_yetkisiz_rol_YONETICI_BOLUMUNU_GOREMEZ(
    qapp, db, isolate_safezone, monkeypatch, role: str,
):
    """
    RBAC MUTASYONU: mod hiçbir zaman bir yetkiyi GENİŞLETMEZ.

    Bireysel mod Yönetici için başlığı gizliyor diye Standart/Salt Okunur
    rolün Yönetici bölümüne erişim kazanması KABUL EDİLEMEZ — is_admin_role
    hâlâ tek karar noktası (CORE/roles.py, B-028).
    """
    window = _pencere(qapp, db, isolate_safezone, monkeypatch, role)
    try:
        set_app_mode(db, BIREYSEL)
        window.reload_app_mode()

        assert _gizli_mi(window._admin_label) is True
        for ad in _ADMIN_WIDGETS:
            assert _gizli_mi(getattr(window, ad)) is True, (
                f"{role} rolü Bireysel modda {ad}'ı görüyor — RBAC ihlali"
            )
    finally:
        _pencereyi_kapat(window)


# ══════════════════════════════════════════════════════════════════════════════
# 3. AdminPanel — sekme gizleniyor, veri/akış SİLİNMİYOR
# ══════════════════════════════════════════════════════════════════════════════


def test_admin_panel_KURUMSALDA_bekleyen_sekmesi_gorunur(qapp, db):
    panel = AdminPanel(current_hwid=_HWID, role="Yönetici")
    try:
        assert panel._tabs.isTabVisible(panel._pending_tab_index) is True
    finally:
        panel._yetki_timer.stop()
        panel.close()


def test_admin_panel_mod_degisince_sekme_ILERI_GERI_dogru_gorunurluk(qapp, db):
    panel = AdminPanel(current_hwid=_HWID, role="Yönetici")
    try:
        # Bireysel'e geç
        idx = panel._mode_combo.findData(BIREYSEL)
        panel._mode_combo.setCurrentIndex(idx)
        panel._on_save_settings()
        assert panel._tabs.isTabVisible(panel._pending_tab_index) is False
        assert get_app_mode(db) == BIREYSEL

        # Kurumsal'a geri dön
        idx = panel._mode_combo.findData(KURUMSAL)
        panel._mode_combo.setCurrentIndex(idx)
        panel._on_save_settings()
        assert panel._tabs.isTabVisible(panel._pending_tab_index) is True
        assert get_app_mode(db) == KURUMSAL
    finally:
        panel._yetki_timer.stop()
        panel.close()


def test_bekleyen_tablosu_kullanici_adi_sutunu_ILERI_GERI_dogru_gorunurluk(qapp, db):
    """
    "Kullanıcı Adı" sütunu (_pending_table, sütun 0) Bireysel'de gizli,
    Kurumsal'da görünür olmalı — sekmenin kendi görünürlüğünden AYRI bir
    kontrol, aynı `_apply_mode_visibility()` çağrısıyla uygulanıyor.
    """
    panel = AdminPanel(current_hwid=_HWID, role="Yönetici")
    try:
        assert panel._pending_table.isColumnHidden(0) is False

        idx = panel._mode_combo.findData(BIREYSEL)
        panel._mode_combo.setCurrentIndex(idx)
        panel._on_save_settings()
        assert panel._pending_table.isColumnHidden(0) is True

        idx = panel._mode_combo.findData(KURUMSAL)
        panel._mode_combo.setCurrentIndex(idx)
        panel._on_save_settings()
        assert panel._pending_table.isColumnHidden(0) is False
    finally:
        panel._yetki_timer.stop()
        panel.close()


def test_bekleyen_kayit_BIREYSELDE_kaybolmuyor_KURUMSALDA_yine_gorunur(qapp, db):
    """
    "Gizlemek silmek değil" — gerçek bir bekleyen kayıtla.

    Bireysel moddayken eklenmiş bir bekleyen kullanıcı (akış moddan
    habersiz — LoginDialog'dan gelir), Kurumsal'a dönüldüğünde hiçbir
    veri kaybı olmadan Bekleyen Kayıtlar sekmesinde görünmeli.
    """
    set_app_mode(db, BIREYSEL)
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, ?, ?, ?)",
        ("yeni.kullanici", "x", "user", "pending", "PENDING-HWID-1"),
    )

    panel = AdminPanel(current_hwid=_HWID, role="Yönetici")
    try:
        # Sekme gizli ama veri hâlâ orada — _load_pending() sekme
        # görünürlüğünden bağımsız çalışıyor (widget silinmedi).
        assert panel._tabs.isTabVisible(panel._pending_tab_index) is False
        panel._load_pending()
        assert panel._pending_table.rowCount() == 1

        idx = panel._mode_combo.findData(KURUMSAL)
        panel._mode_combo.setCurrentIndex(idx)
        panel._on_save_settings()
        assert panel._tabs.isTabVisible(panel._pending_tab_index) is True
        panel._load_pending()
        assert panel._pending_table.rowCount() == 1
    finally:
        panel._yetki_timer.stop()
        panel.close()


# ══════════════════════════════════════════════════════════════════════════════
# 4. Mod değişimi başka HİÇBİR tabloya dokunmuyor
# ══════════════════════════════════════════════════════════════════════════════


def _tum_tablolar_disinda_settings(db) -> dict[str, list[tuple]]:
    tablolar = [
        r[0] for r in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
            " AND name NOT IN ('settings', 'schema_migrations', 'audit_log',"
            " 'sqlite_sequence')"
        )
    ]
    return {
        t: sorted(tuple(r) for r in db.conn.execute(f"SELECT * FROM {t}").fetchall())
        for t in tablolar
    }


def test_mod_degisimi_SADECE_settings_tablosuna_yaziyor(db):
    """
    audit_log ve schema_migrations hariç tutuldu: ikisi de her yazımda
    yeni satır alması BEKLENEN tablolar (denetim kaydı, göç defteri).
    sqlite_sequence de hariç — audit_log'un AUTOINCREMENT sayacını
    tutan SQLite-içi bir yan etki, "veri" değil. Asıl iddia:
    users/files/usb_tokens/... gibi VERİ tabloları hiç değişmiyor.
    """
    once = _tum_tablolar_disinda_settings(db)

    set_app_mode(db, BIREYSEL)
    set_app_mode(db, KURUMSAL)
    set_app_mode(db, BIREYSEL)

    sonra = _tum_tablolar_disinda_settings(db)
    assert once == sonra, "Mod değişimi settings dışında bir tabloyu değiştirdi"
