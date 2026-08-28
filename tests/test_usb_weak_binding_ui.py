"""
Zayıf USB bağlaması (BACKLOG B-025) — ARAYÜZ tarafı.

`tests/test_usb_weak_binding.py` reddin CORE katmanında (USBAuthError +
audit_log) gerçekleştiğini doğruluyor. Burada sınanan şey: bu red gerçekten
kullanıcının GÖRDÜĞÜ ekrana ulaşıyor mu — `test_pin_rotation_ui.py`'nin
kullandığı gerçek `LoginDialog` + offscreen Qt deseniyle aynı yöntem.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication

    from UI.login_dialog import LoginDialog
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE import usb_manager, vault_manager
from CORE.vault_manager import create_vault

_HWID = "USB-WEAKBIND-UI"
_PIN = "gecerli-pin-123"
_ROLE = "Yönetici"
_TOTP = "000000"


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


@pytest.fixture
def vault_dizini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    monkeypatch.setattr(usb_manager, "_USB_IDS_FILE", tmp_path / "usb_ids.json")
    return tmp_path


@pytest.fixture
def totp_gecerli(monkeypatch):
    """TOTP doğrulamasını sabitler — bkz. test_pin_rotation_ui.py, aynı gerekçe."""
    import UI.login_dialog as ld

    class _SahteTOTP:
        def __init__(self, *a, **kw) -> None: ...
        def verify(self, *a, **kw) -> bool: return True

    monkeypatch.setattr(ld.pyotp, "TOTP", _SahteTOTP)
    monkeypatch.setattr(ld, "_load_secret", lambda: "A" * 32)
    monkeypatch.setattr(ld, "load_totp_secret_for_hwid", lambda hwid: "A" * 32)


@pytest.fixture
def zayif_kullanici(db, vault_dizini, totp_gecerli, qapp) -> str:
    """
    ÖNCEDEN KAYITLI, sonradan zayıf çıkan bir kullanıcı — bkz.
    test_usb_weak_binding.py::zayif_vault için aynı gerekçe: create_vault()
    artık YENİ bir zayıf hwid'i reddediyor, o yüzden vault ÖNCE güçlü bir
    kimlikle kuruluyor, zayıflık SONRADAN usb_ids.json'a yazılarak ekleniyor.
    """
    create_vault(_HWID, _PIN, _ROLE)
    db.execute(
        "INSERT INTO users (id, username, password_hash, role, status, hwid)"
        " VALUES (9, 'zayif_kullanici', '', 'admin', 'approved', ?)", (_HWID,))

    dosya = vault_dizini / "usb_ids.json"
    dosya.write_text('{"\\u0000\\u0000": "' + _HWID + '"}', encoding="utf-8")
    assert usb_manager.is_uuid_fallback_hwid(_HWID) is True  # ön koşul
    return _HWID


def _giris(qapp, hwid: str, pin: str) -> LoginDialog:
    dlg = LoginDialog(hwid=hwid, first_run=False, use_vault=True)
    dlg._pin_input.setText(pin)
    dlg._totp_input.setText(_TOTP)
    return dlg


def test_zayif_hwid_ile_giris_ACIKCA_REDDEDILIR(qapp, zayif_kullanici) -> None:
    """
    ASIL DENETİM: doğru PIN + doğru TOTP olsa bile, zayıf bağlı bir hwid'le
    giriş kabul edilmemeli VE kullanıcı NEDENİNİ ekranda görmeli — genel
    "PIN hatalı" mesajına düşmemeli (aksi hâlde kullanıcı doğru PIN'i
    tekrar tekrar dener ve kendini rate limit'e kilitler — bkz.
    login_dialog.py'deki kara liste yorumu, aynı gerekçe).
    """
    dlg = _giris(qapp, zayif_kullanici, _PIN)
    dlg._on_login()

    assert dlg.result() != LoginDialog.Accepted, "zayıf bağlı hwid ile giriş kabul edildi"
    # Dialog bu headless testte hiç show() edilmedi, o yüzden isVisible()
    # üst pencere gösterilmediği için hiyerarşik olarak False kalır —
    # asıl kanıt _show_error()'ın metni gerçekten YAZDIĞI (bkz. login_dialog.py
    # ._show_error: msg varsa setText + show() çağrılıyor).
    gosterilen = dlg._error_label.text()
    assert "donanım seri numarası okunamıyor" in gosterilen, (
        f"hata ekranda görünmüyor ya da yanlış mesaj: {gosterilen!r}"
    )


def test_zayif_hwid_reddi_denetim_kaydina_dusuyor(qapp, zayif_kullanici, db) -> None:
    """UI reddi CORE'un aynı denetim kaydını üretmeli — iki katman tutarlı."""
    dlg = _giris(qapp, zayif_kullanici, _PIN)
    dlg._on_login()

    kayitlar = db.fetchall(
        "SELECT detail FROM audit_log WHERE action = 'weak_hwid_binding_rejected'"
    )
    assert len(kayitlar) == 1
    assert f"hwid={zayif_kullanici}" in kayitlar[0]["detail"]
