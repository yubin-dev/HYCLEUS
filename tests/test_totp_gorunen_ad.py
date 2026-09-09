"""
İlk Kurulum — TOTP QR'ının "Görünen Ad" ile eşleşmesi (B-11X / Madde 3b).

Doğrulama turunda gerçek çalıştırmayla saptandı: setup sihirbazında
`provisioning_uri`'nin `name=` parametresi sabit "admin" idi — kullanıcıya
hiç ad sorulmuyordu. Birden fazla HYCLEUS kurulumu authenticator
uygulamasında AYIRT EDİLEMİYORDU (hepsi "admin" görünüyor). Bu paket iki
şeyi ölçüyor:

1. Kullanıcı bir ad girerse QR'ın provisioning_uri'si GERÇEKTEN o adı
   taşıyor mu (canlı güncelleme — `_setup_display_name.textChanged`).
2. Ad boş bırakılırsa varsayılan `vault:<hwid>` — DB'ye GERÇEKTEN
   yazılacak kimlikle (`CORE.session_user.vault_username`) tutarlı,
   rastgele "admin" DEĞİL.

Mutasyon-kanıtlı: `_yenile_setup_qr()` geçici olarak eski sabit "admin"
davranışına döndürülüp testlerin GERÇEKTEN düştüğü doğrulandı (bkz.
oturum notları / commit mesajı), sonra geri alındı.
"""
from __future__ import annotations

import os

import pyotp
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

from CORE.session_user import vault_username

_HWID = "USB-TOTP-AD-TEST"


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


@pytest.fixture
def kurulum_dlg(qapp, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(LoginDialog, "_show_referans_id_dialog", lambda self, rid: None)
    dlg = LoginDialog(hwid=_HWID, first_run=True, use_vault=True)
    try:
        yield dlg
    finally:
        dlg.close()


def _uri_name(dlg: LoginDialog) -> str | None:
    """Dialogun O ANKİ pixmap'inin ürettiği provisioning_uri'nin name= parametresini,
    gerçek pyotp çağrısını yeniden yaparak DEĞİL, doğrudan casus ile ölçer."""
    yakalanan: dict[str, str] = {}
    gercek = pyotp.TOTP.provisioning_uri

    def _casus(self, *a, **kw):
        yakalanan["name"] = kw.get("name")
        return gercek(self, *a, **kw)

    import unittest.mock as mock
    with mock.patch.object(pyotp.TOTP, "provisioning_uri", _casus):
        dlg._yenile_setup_qr()
    return yakalanan.get("name")


def test_bos_ad_vault_hwid_varsayilanina_duser(kurulum_dlg):
    assert kurulum_dlg._setup_display_name.text() == ""
    assert _uri_name(kurulum_dlg) == vault_username(_HWID)


def test_bos_ad_ARTIK_sabit_admin_DEGIL(kurulum_dlg):
    """Doğrudan regresyon: eski hatanın somut hâli — çıktı "admin" OLMAMALI."""
    assert _uri_name(kurulum_dlg) != "admin"


def test_girilen_ad_qr_ya_GERCEKTEN_yansiyor(kurulum_dlg):
    kurulum_dlg._setup_display_name.setText("Ahmet Yilmaz")
    assert _uri_name(kurulum_dlg) == "Ahmet Yilmaz"


def test_ad_degistikce_qr_CANLI_guncelleniyor(kurulum_dlg, qapp):
    """`textChanged` sinyali gerçekten bağlı mı — yalnızca `_yenile_setup_qr()`'ı
    ELLE çağırmak değil, kullanıcının YAZMASI da pixmap'i değiştirmeli."""
    onceki_pixmap = kurulum_dlg._setup_qr_lbl.pixmap().toImage()

    kurulum_dlg._setup_display_name.setText("Farkli Bir Ad")
    qapp.processEvents()

    sonraki_pixmap = kurulum_dlg._setup_qr_lbl.pixmap().toImage()
    assert onceki_pixmap != sonraki_pixmap, (
        "ad değişti ama QR pixmap'i aynı kaldı — textChanged sinyali bağlı değil"
    )


def test_bosluklu_ad_trim_ediliyor(kurulum_dlg):
    kurulum_dlg._setup_display_name.setText("   ")
    assert _uri_name(kurulum_dlg) == vault_username(_HWID), (
        "yalnızca boşluktan oluşan ad boş sayılmalı"
    )


def test_kayit_ol_akisi_ETKİLENMEDİ(qapp, db):
    """Karar sınırı: bu değişiklik yalnızca İlk Kurulum'u etkiliyor — Kayıt
    Ol (self-servis) akışının `name=username` davranışı DEĞİŞMEDİ."""
    from UI import totp_enrollment

    yakalanan: dict[str, str] = {}
    gercek = pyotp.TOTP.provisioning_uri

    def _casus(self, *a, **kw):
        yakalanan["name"] = kw.get("name")
        return gercek(self, *a, **kw)

    import unittest.mock as mock
    with mock.patch.object(pyotp.TOTP, "provisioning_uri", _casus), \
         mock.patch.object(totp_enrollment, "QMessageBox") as sahte:
        sahte.return_value.exec.return_value = None
        totp_enrollment.show_totp_enrollment_dialog(None, "SECRET123", "gercek_kullanici")

    assert yakalanan.get("name") == "gercek_kullanici"
