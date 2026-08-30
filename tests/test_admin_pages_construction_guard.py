"""
HYCLEUS — USB Yönetim Paneli'nin üç sayfası: guard SIRASI ve rol-değişikliği
koruması, VARSAYIM YAPILMADAN ölçülüyor.

Bu paket şu soruyu soruyor: `UI/UsbTokensView.py`, `UI/
PendingRegistrationsView.py`, `UI/AdminSettingsView.py` — `main_window.py::
_make_govde_yigini()`'nin bu üçünü YÖNETİCİ OLMAYAN bir oturum için de
KOŞULSUZ kurduğu artık biliniyor (bkz. `UI/admin_common.py` modül
docstring'i, SECURITY.md §4.24). Peki `is_admin_role()` kapısı TAM OLARAK
NEREDE çalışıyor — nesne hiç kurulmadan ÖNCE mi (`__init__` hiç
tetiklenmiyor), yoksa `__init__` çalışıp bir DB sorgusu ATILDIKTAN sonra mı
(nesne var, sorgu koştu, yalnızca EKRANA basılmadı)?


1 — İnşa-zamanı sorgu denetimi (bölüm "Construction")
------------------------------------------------------
Cevap: KARIŞIK, ve bu paket bunu ÖLÇEREK buluyor.

`UsbTokensView`/`PendingRegistrationsView`: `__init__` yalnızca BOŞ
widget'lar kuruyor (`_make_table`/`_make_pending_table`), veri yükü TAMAMEN
`.yenile()`'ye ertelenmiş — `__init__` sırasında HİÇBİR DB sorgusu
ÇALIŞMIYOR. Rol kapısı (`main_window.py::_on_open_usb_tokens`/
`_on_open_pending`) bu yüzden `__init__`'ten SONRA ama İLK sorgudan ÖNCE
oturuyor (sorgu zaten `.yenile()` çağrılmadan hiç yok).

`AdminSettingsView`: BU PAKETİ YAZARKEN `__init__` `_load_settings()`'i
(DB: `get_setting`/`get_idle_timeout_minutes`/`get_app_mode`) VE
`_tsa_kok_bloku()` üzerinden `_tsa_yukle()`'yi (DB: `trusted_roots` tablosu)
KOŞULSUZ çağırıyordu — yönetici olmayan bir oturum için de. Yani sorgu
`is_admin_role()` kapısından ÖNCE, HER pencerede çalışıyordu; yalnızca
SAYFA GÖRÜNMÜYORDU. Düzeltildi: `_load_settings()`/`_tsa_yukle()` artık
YALNIZCA `.yenile()`'de — üç sayfa şimdi TUTARLI.


2 — Doğrudan örnekleme (K1-14 deseni)
----------------------------------------
Testler `main_window._on_open_*()`'i HİÇ ÇAĞIRMIYOR — gerçek bir
`HycleusWindow`'un YÖNETİCİ OLMAYAN rolüyle kurduğu, `_make_govde_yigini()`
tarafından ZATEN inşa edilmiş `window._usb_tokens_view`/`_pending_view`/
`_admin_settings_view` nesnelerinin DOĞRUDAN durumuna bakıyor — tam olarak
üretimde yönetici olmayan bir oturumun sahip olduğu nesnelere.


3 — Rol-değişikliği penceresi (B-064/B-066'nın SAYFA guard'ı için karşılığı)
-------------------------------------------------------------------------------
`tests/test_authz_invariants.py`'deki B-064 testleri USB'nin FİZİKSEL
ÇEKİLMESİNİ ölçüyor; B-066 testi `_poll_usb()`'u (ana pencere zamanlayıcısı)
ölçüyor — İKİSİ DE `UI.admin_common.yonetici_hala_yetkili()`'nin KENDİSİNİ,
DB'de rol DÜŞÜRÜLÜP USB HİÇ ÇEKİLMEDİĞİNDE, doğrudan bir sayfa eylemi
üzerinden ÖLÇMÜYORDU. Bu paket o boşluğu kapatıyor:
`test_sayfa_guard_rol_dusurulunce_usb_takiliyken_de_reddediyor` ve
mutasyon-kontrastlı kardeşi.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QMessageBox

    from UI.AdminSettingsView import AdminSettingsView
    from UI.main_window import HycleusWindow
    from UI.PendingRegistrationsView import PendingRegistrationsView
    from UI.UsbTokensView import UsbTokensView
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE.app_mode import BIREYSEL, KURUMSAL, get_app_mode, set_app_mode
from CORE.roles import can_write, is_admin_role

_KEY = b"K" * 32
_HWID = "GUARD-TEST-HWID"


@pytest.fixture
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


@pytest.fixture(autouse=True)
def _diyalog_engelle(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """QMessageBox çağrıları (onay/bilgi/hata) testi bloklamasın."""
    gosterilen: list[tuple[str, str]] = []

    def _yakala(sonuc):
        def _f(_parent, baslik, metin, *a, **kw):
            gosterilen.append((baslik, str(metin)))
            return sonuc
        return _f

    monkeypatch.setattr(QMessageBox, "warning", staticmethod(_yakala(0)))
    monkeypatch.setattr(QMessageBox, "critical", staticmethod(_yakala(0)))
    monkeypatch.setattr(QMessageBox, "information", staticmethod(_yakala(0)))
    monkeypatch.setattr(QMessageBox, "question", staticmethod(_yakala(QMessageBox.Yes)))
    return gosterilen


def _pencere(db, sahte_usb, hwid: str, role: str, *, username: str = "test.kullanici",
             user_id: int = 1):
    sahte_usb(hwid)
    return HycleusWindow(hwid=hwid, key=_KEY, role=role, username=username, user_id=user_id)


def _pencereyi_kapat(window) -> None:
    for ad in ("_usb_timer", "_expiry_timer", "_idle_timer"):
        t = getattr(window, ad, None)
        if t is not None:
            t.stop()
    QApplication.instance().removeEventFilter(window)
    window.close()


def _kullanici_ekle(db, hwid: str, username: str, role: str = "admin",
                     status: str = "approved") -> int:
    cur = db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, ?, ?, ?)",
        (username, "!x", role, status, hwid),
    )
    return cur.lastrowid


def _token_ekle(db, hwid: str, token_id: str = "TOKEN-X") -> None:
    db.execute(
        "INSERT INTO usb_tokens (hwid, share_2, token_id, blacklisted) VALUES (?, ?, ?, 0)",
        (hwid, "share-2-degeri", token_id),
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1 — İnşa-zamanı sorgu denetimi: is_admin_role() rol kapısından ÖNCE,
#     YÖNETİCİ OLMAYAN bir oturum için, __init__ sırasında sorgu ATILMIYOR mu.
# ══════════════════════════════════════════════════════════════════════════════
#
# Rol KASITLI OLARAK "Standart": `can_write("Standart") is True` (bkz.
# tests/test_roles.py) — yani DB yazma katmanı bu rolü READONLY diye
# reddetmez. Eğer buradaki denetimler yalnızca "Salt Okunur" ile
# geçiyor olsaydı, asıl kanıtladıkları şey DB'nin salt-okunur engeli
# olurdu, sayfa seviyesindeki `is_admin_role()` kapısı DEĞİL.


def test_usb_tokens_view_ADMIN_OLMAYAN_pencerede_construction_sirasinda_sorgu_atmiyor(
    qapp, db, sahte_usb,
):
    assert can_write("Standart") is True and is_admin_role("Standart") is False

    _kullanici_ekle(db, "BASKA-HWID", "baskasi")
    _token_ekle(db, "BASKA-HWID", token_id="GORUNMEMELI")

    window = _pencere(db, sahte_usb, _HWID, "Standart")
    try:
        # `window._usb_tokens_view` main_window_layout.py::_make_govde_yigini()
        # tarafından ZATEN kurulmuş — burada YENİDEN inşa edilmiyor,
        # üretimde yönetici olmayan bir oturumun SAHİP OLDUĞU AYNI nesne.
        sayfa = window._usb_tokens_view
        assert isinstance(sayfa, UsbTokensView)
        assert sayfa._table.rowCount() == 0, (
            "GUARD REGRESYONU: __init__ sırasında (rol kapısından önce) "
            "bir sorgu çalışmış — tablo dolu"
        )

        # Sorgu mekanizmasının KENDİSİ BOZUK olmadığını kanıtla — aksi
        # hâlde yukarıdaki "0 satır" iddiası "hiçbir zaman dolmuyor"
        # anlamına da gelebilirdi, "henüz dolmadı" değil.
        sayfa.yenile()
        assert sayfa._table.rowCount() == 1, (
            "yenile() çağrıldığında sorgu HİÇ çalışmadı — üstteki '0 satır' "
            "iddiası anlamsızdı"
        )
    finally:
        _pencereyi_kapat(window)


def test_pending_view_ADMIN_OLMAYAN_pencerede_construction_sirasinda_sorgu_atmiyor(
    qapp, db, sahte_usb,
):
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, ?, ?, ?)",
        ("bekleyen.kullanici", "x", "user", "pending", "PENDING-HWID-X"),
    )

    window = _pencere(db, sahte_usb, _HWID, "Standart")
    try:
        sayfa = window._pending_view
        assert isinstance(sayfa, PendingRegistrationsView)
        assert sayfa._pending_table.rowCount() == 0, (
            "GUARD REGRESYONU: __init__ sırasında bir sorgu çalışmış — "
            "tablo dolu"
        )

        sayfa.yenile()
        assert sayfa._pending_table.rowCount() == 1, (
            "yenile() çağrıldığında sorgu HİÇ çalışmadı"
        )
    finally:
        _pencereyi_kapat(window)


def test_admin_settings_view_ADMIN_OLMAYAN_pencerede_construction_sirasinda_sorgu_atmiyor(
    qapp, db, sahte_usb,
):
    """
    Bu test YAZILDIĞINDA kırmızıydı: `AdminSettingsView.__init__`
    `_load_settings()`'i VE `_tsa_yukle()`'yi koşulsuz çağırıyordu.
    Düzeltme: ikisi de artık YALNIZCA `.yenile()`'de (bkz. `UI/
    AdminSettingsView.py::__init__`'in docstring'i).
    """
    set_app_mode(db, BIREYSEL)
    assert get_app_mode(db) == BIREYSEL

    window = _pencere(db, sahte_usb, _HWID, "Standart")
    try:
        sayfa = window._admin_settings_view
        assert isinstance(sayfa, AdminSettingsView)

        # `_mode_combo`'ya EKLENEN İLK öğe "Kurumsal" — `_load_settings()`
        # hiç çalışmadıysa combo bu VARSAYILANDA kalır, DB'deki GERÇEK
        # (Bireysel) değeri YANSITMAZ.
        assert sayfa._mode_combo.currentData() == KURUMSAL, (
            "GUARD REGRESYONU: _load_settings() construction sırasında "
            "çalışmış — combo DB'deki Bireysel değerini gösteriyor"
        )
        # `_tsa_liste` HİÇ dokunulmamış olmalı — `_tsa_yukle()` çalışsaydı
        # DB boş olsa BİLE en az BİR öğe ("eklenmemiş" yer tutucusu) eklerdi.
        assert sayfa._tsa_liste.count() == 0, (
            "GUARD REGRESYONU: _tsa_yukle() construction sırasında çalışmış"
        )

        sayfa.yenile()
        assert sayfa._mode_combo.currentData() == BIREYSEL, (
            "yenile() çağrıldığında _load_settings() HİÇ çalışmadı"
        )
        assert sayfa._tsa_liste.count() == 1, (
            "yenile() çağrıldığında _tsa_yukle() HİÇ çalışmadı"
        )
    finally:
        _pencereyi_kapat(window)


# ══════════════════════════════════════════════════════════════════════════════
# 2 — "Standart" rolüyle DOĞRUDAN çağrı: is_admin_role() kapısı, DB yazma
#     katmanının (can_write) YAKALAMAYACAĞI bir durumu YAKALIYOR mu.
# ══════════════════════════════════════════════════════════════════════════════
#
# can_write("Standart") is True (tests/test_roles.py) — yani DB_manager.
# execute()'un _yazma_yetkisini_dogrula() kapısı BU rolü hiç reddetmez.
# Buradaki denetim SIRF is_admin_role()'un kendisini ölçüyor.


def test_pending_view_STANDART_rolle_dogrudan_onay_REDDEDILIYOR(
    db, sahte_usb, qapp,
):
    pending_hwid = "STANDART-PENDING-HWID"
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, ?, ?, ?)",
        ("bekleyen.standart.test", "x", "user", "pending", pending_hwid),
    )

    window = _pencere(db, sahte_usb, _HWID, "Standart")
    try:
        sayfa = window._pending_view
        sayfa.yenile()
        sayfa._pending_table.selectRow(0)

        sayfa._on_approve()

        row = db.fetchone("SELECT status FROM users WHERE hwid = ?", (pending_hwid,))
        assert row["status"] == "pending", (
            "GUARD REGRESYONU: 'Standart' rol (can_write=True, "
            "is_admin_role=False) doğrudan çağrıyla onayı GEÇTİ"
        )
        assert window._locked is True
        assert "revoked" in window._lock_reasons
    finally:
        _pencereyi_kapat(window)


def test_pending_view_guard_kaldirilirsa_STANDART_rol_gercekten_onaylayabiliyor(
    db, sahte_usb, qapp, monkeypatch: pytest.MonkeyPatch,
):
    """Mutasyon kontrastı — yukarıdaki testin gerçekten bir şey ölçtüğünü
    kanıtlar: `yonetici_hala_yetkili` devre dışı bırakılırsa AYNI 'Standart'
    rol onayı GERÇEKTEN geçirir (DB yazma katmanı TEK BAŞINA onu
    durdurmazdı — can_write('Standart') is True)."""
    import UI.PendingRegistrationsView as prv

    pending_hwid = "STANDART-MUTASYON-PENDING-HWID"
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, ?, ?, ?)",
        ("bekleyen.standart.mutasyon", "x", "user", "pending", pending_hwid),
    )

    window = _pencere(db, sahte_usb, _HWID, "Standart")
    try:
        sayfa = window._pending_view
        sayfa.yenile()
        sayfa._pending_table.selectRow(0)

        monkeypatch.setattr(prv.admin_common, "yonetici_hala_yetkili", lambda *a, **k: True)
        sayfa._on_approve()

        row = db.fetchone("SELECT status FROM users WHERE hwid = ?", (pending_hwid,))
        assert row["status"] == "approved", (
            "guard devre dışıyken bile onay engellendi — bu test is_admin_role() "
            "kapısını gerçekten ölçmüyor olabilir"
        )
    finally:
        _pencereyi_kapat(window)


def test_usb_tokens_view_STANDART_rolle_dogrudan_kara_listeye_alma_REDDEDILIYOR(
    db, sahte_usb, qapp,
):
    hedef_hwid = "STANDART-BLACKLIST-HEDEF"
    _kullanici_ekle(db, hedef_hwid, "hedef.kullanici", role="user")
    _token_ekle(db, hedef_hwid)

    window = _pencere(db, sahte_usb, _HWID, "Standart")
    try:
        sayfa = window._usb_tokens_view
        sayfa.yenile()
        # Tek satır var (hedef_hwid) ve pencerenin KENDİ HWID'inden
        # (_HWID) farklı — "kendi USB'si kara listeye alınamaz" kuralına
        # takılmadan seçilebilir.
        sayfa._table.selectRow(0)

        sayfa._on_toggle_blacklist()

        row = db.fetchone(
            "SELECT blacklisted FROM usb_tokens WHERE hwid = ?", (hedef_hwid,)
        )
        assert row["blacklisted"] == 0, (
            "GUARD REGRESYONU: 'Standart' rol doğrudan çağrıyla kara "
            "listeye almayı GEÇTİ"
        )
        assert window._locked is True
        assert "revoked" in window._lock_reasons
    finally:
        _pencereyi_kapat(window)


def test_admin_settings_view_STANDART_rolle_dogrudan_ayar_kaydi_REDDEDILIYOR(
    db, sahte_usb, qapp,
):
    onceki_mod = get_app_mode(db)
    assert onceki_mod == KURUMSAL

    window = _pencere(db, sahte_usb, _HWID, "Standart")
    try:
        sayfa = window._admin_settings_view
        sayfa.yenile()
        idx = sayfa._mode_combo.findData(BIREYSEL)
        sayfa._mode_combo.setCurrentIndex(idx)

        sayfa._on_save_settings()

        assert get_app_mode(db) == KURUMSAL, (
            "GUARD REGRESYONU: 'Standart' rol doğrudan çağrıyla ayar "
            "kaydını GEÇTİ"
        )
        assert window._locked is True
        assert "revoked" in window._lock_reasons
    finally:
        _pencereyi_kapat(window)


# ══════════════════════════════════════════════════════════════════════════════
# 3 — Rol-değişikliği penceresi: DB'de rol düşürülüyor, USB HİÇ ÇEKİLMİYOR,
#     sayfa AÇIK KALIYOR. `_poll_usb()`'i (B-066) BEKLEMEDEN, sayfanın
#     KENDİ eylem-öncesi guard'ı (`yonetici_hala_yetkili`) bunu yakalıyor mu?
# ══════════════════════════════════════════════════════════════════════════════
#
# `tests/test_authz_invariants.py`'deki B-064 testleri USB'nin fiziksel
# çekilmesini, B-066 testi `_poll_usb()`'u (ayrı bir zamanlayıcı yolu)
# ölçüyor. Burada ölçülen ÜÇÜNCÜ, dar bir soru: `_poll_usb()` hiç
# ÇALIŞMASA bile (bu testte bilerek çağrılmıyor), sayfanın KENDİ
# `_on_approve()`'u DB'deki güncel rolü görüp reddediyor mu — yoksa
# sayfa açık kaldığı sürece pencerenin `_role`'ünde donmuş kalan
# ESKİ yetkiyle mi çalışıyor?


def test_sayfa_guard_rol_dusurulunce_usb_takiliyken_de_reddediyor(db, sahte_usb, qapp):
    admin_hwid = "ROLDUSUS-ADMIN-HWID"
    pending_hwid = "ROLDUSUS-PENDING-HWID"
    _kullanici_ekle(db, admin_hwid, "dusurulecek.yonetici", role="admin")
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, ?, ?, ?)",
        ("bekleyen.roldusus", "x", "user", "pending", pending_hwid),
    )

    window = _pencere(db, sahte_usb, admin_hwid, "Yönetici")
    try:
        sayfa = window._pending_view
        sayfa.yenile()
        sayfa._pending_table.selectRow(0)

        # Başka bir yerden (ör. ikinci bir oturum/yönetici) rol DB'de
        # düşürülüyor. USB HİÇ ÇIKARILMIYOR — sahte_usb hâlâ admin_hwid
        # döndürüyor. window._role hâlâ "Yönetici" (giriş anındaki
        # DONMUŞ değer) — _poll_usb() bu testte HİÇ çağrılmıyor.
        db.execute("UPDATE users SET role = 'user' WHERE hwid = ?", (admin_hwid,))

        sayfa._on_approve()

        row = db.fetchone("SELECT status FROM users WHERE hwid = ?", (pending_hwid,))
        assert row["status"] == "pending", (
            "REGRESYON: DB'de rol düştüğü hâlde (USB hiç çekilmeden, "
            "_poll_usb() hiç çalışmadan) sayfa hâlâ eski yetkiyle onay verdi"
        )
        assert window._locked is True
        assert "revoked" in window._lock_reasons
    finally:
        _pencereyi_kapat(window)


def test_sayfa_guard_kaldirilirsa_rol_dususu_gercekten_gecerdi(
    db, sahte_usb, qapp, monkeypatch: pytest.MonkeyPatch,
):
    """Mutasyon kontrastı — bir önceki testin `oturum_yetkisi_gecerli_mi()`
    çağrısını GERÇEKTEN ölçtüğünü kanıtlar."""
    import UI.PendingRegistrationsView as prv

    admin_hwid = "ROLDUSUS-MUTASYON-ADMIN-HWID"
    pending_hwid = "ROLDUSUS-MUTASYON-PENDING-HWID"
    _kullanici_ekle(db, admin_hwid, "dusurulecek.yonetici.2", role="admin")
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, ?, ?, ?)",
        ("bekleyen.roldusus.2", "x", "user", "pending", pending_hwid),
    )

    window = _pencere(db, sahte_usb, admin_hwid, "Yönetici")
    try:
        sayfa = window._pending_view
        sayfa.yenile()
        sayfa._pending_table.selectRow(0)

        db.execute("UPDATE users SET role = 'user' WHERE hwid = ?", (admin_hwid,))
        monkeypatch.setattr(prv.admin_common, "yonetici_hala_yetkili", lambda *a, **k: True)

        sayfa._on_approve()

        row = db.fetchone("SELECT status FROM users WHERE hwid = ?", (pending_hwid,))
        assert row["status"] == "approved", (
            "guard devre dışıyken bile onay engellendi — bu test rol-düşüşü "
            "denetimini gerçekten ölçmüyor olabilir"
        )
    finally:
        _pencereyi_kapat(window)
