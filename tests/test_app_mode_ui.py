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
    "_usb_tokens_btn", "_pending_btn", "_admin_settings_btn", "_support_btn",
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
    B-064/B-066: USB Yönetim Paneli'nin üç sayfası artık her yetkili
    işlemden (ör. `AdminSettingsView._on_save_settings`) önce USB'nin
    hâlâ takılı olduğunu VE DB'deki yetkinin hâlâ girişteki gibi
    olduğunu canlı doğruluyor (`UI.admin_common.yonetici_hala_yetkili`).
    Bu dosyadaki testler hep `_HWID` kullanıyor; o USB'nin takılı
    kaldığını simüle edip ona karşılık gelen onaylı yönetici satırını
    ekliyoruz — aksi hâlde çağrılan yetkili bir işlem sessizce reddedilir
    (oturum "revoked" nedeniyle kilitlenir).
    """
    import UI.admin_common as _ac

    monkeypatch.setattr(_ac, "get_usb_hwid", lambda: _HWID)
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, 'admin', 'approved', ?)",
        ("app-mode-test-admin", "x", _HWID),
    )


@pytest.fixture(autouse=True)
def _diyalog_engelle(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Ayarlar sayfasının `QMessageBox.information/...` çağrıları testi bloklamasın."""
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


def test_BIREYSELDE_baslik_ve_bekleyen_kayitlar_gizlenir_digerleri_kalir(
    qapp, db, isolate_safezone, monkeypatch,
):
    """
    "Bekleyen Kayıtlar" eskiden (`UI/AdminPanel.py`, kaldırıldı) panel
    İÇİNDEKİ bir sekmeydi ve AYNI gerekçeyle (tek kullanıcı, onaylanacak
    kimse yok) Bireysel'de gizlenirdi — üçe bölünmenin ardından karşılığı
    bu kenar çubuğu düğmesinin gizlenmesi (bkz. `UI/main_window.py::
    _apply_role_restrictions`). Diğer admin düğmeleri (USB Tokenlar,
    Ayarlar dahil) KALIR.
    """
    window = _pencere(qapp, db, isolate_safezone, monkeypatch, "Yönetici")
    try:
        set_app_mode(db, BIREYSEL)
        window.reload_app_mode()

        assert _gizli_mi(window._admin_label) is True, (
            "'Yönetici' başlığı Bireysel modda hâlâ görünüyor"
        )
        assert _gizli_mi(window._pending_btn) is True, (
            "'Bekleyen Kayıtlar' düğmesi Bireysel modda hâlâ görünüyor"
        )
        for ad in _ADMIN_WIDGETS:
            if ad == "_pending_btn":
                continue
            assert _gizli_mi(getattr(window, ad)) is False, (
                f"{ad} Bireysel modda gizlenmemeliydi — yalnızca başlık ve "
                "Bekleyen Kayıtlar gizlenir"
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
# 3. Bekleyen Kayıtlar — düğme gizleniyor, veri/akış SİLİNMİYOR
# ══════════════════════════════════════════════════════════════════════════════
#
# Eskiden (`UI/AdminPanel.py`, kaldırıldı) bu bir `QTabWidget` sekmesiydi;
# üçe bölünmenin ardından karşılığı kenar çubuğu düğmesi (bkz. `UI/
# main_window.py::_apply_role_restrictions`) — testler artık standalone
# bir panel yerine GERÇEK `HycleusWindow` üzerinden çalışıyor, çünkü
# görünürlük kararı artık panelin kendisinde değil, pencerede.


def test_pending_KURUMSALDA_dugmesi_gorunur(qapp, db, isolate_safezone, monkeypatch):
    window = _pencere(qapp, db, isolate_safezone, monkeypatch, "Yönetici")
    try:
        assert _gizli_mi(window._pending_btn) is False
    finally:
        _pencereyi_kapat(window)


def test_pending_mod_degisince_dugme_ILERI_GERI_dogru_gorunurluk(
    qapp, db, isolate_safezone, monkeypatch,
):
    window = _pencere(qapp, db, isolate_safezone, monkeypatch, "Yönetici")
    try:
        ayarlar = window._admin_settings_view

        # Bireysel'e geç
        idx = ayarlar._mode_combo.findData(BIREYSEL)
        ayarlar._mode_combo.setCurrentIndex(idx)
        ayarlar._on_save_settings()
        assert _gizli_mi(window._pending_btn) is True
        assert get_app_mode(db) == BIREYSEL

        # Kurumsal'a geri dön
        idx = ayarlar._mode_combo.findData(KURUMSAL)
        ayarlar._mode_combo.setCurrentIndex(idx)
        ayarlar._on_save_settings()
        assert _gizli_mi(window._pending_btn) is False
        assert get_app_mode(db) == KURUMSAL
    finally:
        _pencereyi_kapat(window)


def test_bekleyen_tablosu_kullanici_adi_sutunu_ILERI_GERI_dogru_gorunurluk(
    qapp, db, isolate_safezone, monkeypatch,
):
    """
    "Kullanıcı Adı" sütunu (_pending_table, sütun 0) Bireysel'de gizli,
    Kurumsal'da görünür olmalı — düğmenin kendi görünürlüğünden AYRI bir
    kontrol, aynı `_apply_role_restrictions()` çağrısıyla uygulanıyor.
    """
    window = _pencere(qapp, db, isolate_safezone, monkeypatch, "Yönetici")
    try:
        ayarlar = window._admin_settings_view
        tablo = window._pending_view._pending_table
        assert tablo.isColumnHidden(0) is False

        idx = ayarlar._mode_combo.findData(BIREYSEL)
        ayarlar._mode_combo.setCurrentIndex(idx)
        ayarlar._on_save_settings()
        assert tablo.isColumnHidden(0) is True

        idx = ayarlar._mode_combo.findData(KURUMSAL)
        ayarlar._mode_combo.setCurrentIndex(idx)
        ayarlar._on_save_settings()
        assert tablo.isColumnHidden(0) is False
    finally:
        _pencereyi_kapat(window)


def test_bekleyen_kayit_BIREYSELDE_kaybolmuyor_KURUMSALDA_yine_gorunur(
    qapp, db, isolate_safezone, monkeypatch,
):
    """
    "Gizlemek silmek değil" — gerçek bir bekleyen kayıtla.

    Bireysel moddayken eklenmiş bir bekleyen kullanıcı (akış moddan
    habersiz — LoginDialog'dan gelir), Kurumsal'a dönüldüğünde hiçbir
    veri kaybı olmadan Bekleyen Kayıtlar sayfasında görünmeli.
    """
    set_app_mode(db, BIREYSEL)
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, ?, ?, ?)",
        ("yeni.kullanici", "x", "user", "pending", "PENDING-HWID-1"),
    )

    window = _pencere(qapp, db, isolate_safezone, monkeypatch, "Yönetici")
    try:
        # `HycleusWindow.__init__` başlangıç modunu OKUYOR (`self._app_mode`)
        # ama UYGULAMIYOR — gerçek uygulamada bunu `main.py`'nin
        # `QTimer.singleShot(0, win._apply_role_restrictions)` çağrısı
        # yapar; testte AYNI adımı elle taklit ediyoruz.
        window._apply_role_restrictions()

        ayarlar = window._admin_settings_view
        pending = window._pending_view

        # Düğme gizli ama veri hâlâ orada — _load_pending() düğmenin
        # görünürlüğünden bağımsız çalışıyor (widget silinmedi).
        assert _gizli_mi(window._pending_btn) is True
        pending._load_pending()
        assert pending._pending_table.rowCount() == 1

        idx = ayarlar._mode_combo.findData(KURUMSAL)
        ayarlar._mode_combo.setCurrentIndex(idx)
        ayarlar._on_save_settings()
        assert _gizli_mi(window._pending_btn) is False
        pending._load_pending()
        assert pending._pending_table.rowCount() == 1
    finally:
        _pencereyi_kapat(window)


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
