"""
B-058 (devam) — "Kayıt için Yönetici USB'si takılı olmalıdır" metni ile
gerçek davranış arasındaki fark, ve taze kurulumda ilk admin'in nasıl
oluştuğu.

Bu paket YALNIZCA KANITLIYOR — düzeltme yazmıyor. Görev kod yazılmamasını
istedi; bulgu ve önerilen yaklaşım ayrı bir raporda.

Bulgu 1 — taze kurulumda ilk kullanıcı
----------------------------------------
`users` tablosu boşken, `LoginDialog` "Kayıt Ol" sekmesinden DEĞİL,
"İlk Kurulum" sihirbazından (`_build_setup_ui`/`_on_setup_confirm`)
geçiyor. O yol `users` tablosuna HİÇ dokunmuyor — satırı `main.py`'nin
`dialog.exec()` SONRASI çağırdığı `sync_session_user()`
(`CORE/session_user.py`) yazıyor, doğrudan `status='approved'` ile.
Yani "hiçbir onaylayan admin yokken sistem hiç kullanılabilir hale
gelmiyor" korkusu asılsız: ilk kullanıcı otomatik onaylı — ama "Kayıt
Ol" sekmesinin `status='pending'` yazan koduyla HİÇBİR ilgisi yok, iki
ayrı fonksiyon.

Bulgu 2 — bu yol "İLK" ile sınırlı değil (asıl mesele bu)
-----------------------------------------------------------
`_first_run` hesabı iki şeye bakıyor: TOTP sırrının varlığı (GLOBAL —
tek bir anahtar kasası girdisi, `CORE/secret_store.py::TOTP_USERNAME`)
ve vault dosyasının varlığı (HWID BAŞINA,
`CORE/vault_manager.py::_read_vault_path`). Sır bir kez kaydedildikten
SONRA bile, DAHA ÖNCE HİÇ GÖRÜLMEMİŞ herhangi bir USB takıldığında (o
HWID için vault dosyası yok) `_first_run` yine `True` çıkıyor — yani
"Kayıt Ol" (pending onay) sekmesi değil, İLK KURULUM SİHİRBAZI yeniden
açılıyor. Sihirbaz rolü SERBEST seçtiriyor (varsayılan "Yönetici") ve
`_on_setup_confirm()` sonunda PAYLAŞILAN TOTP sırrını YENİ bir rastgele
değerle EZİYOR (`_save_secret`).

Sonuç: kurulu bir sistemde daha önce hiç kullanılmamış bir USB takan
biri (a) hiçbir onay olmadan "Yönetici" rolüyle `status='approved'` bir
hesap açabiliyor, (b) bunun yan etkisi olarak TÜM mevcut kullanıcıların
paylaştığı TOTP sırrını değiştirip onların authenticator kodunu
geçersiz kılıyor.
"""
from __future__ import annotations

import os
from pathlib import Path

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

from CORE import vault_manager
from CORE.secret_store import load_totp_secret
from CORE.session_user import sync_session_user

_HWID_ILK    = "USB-B058-ILK-ADMIN"
_HWID_IKINCI = "USB-B058-IKINCI-CALISAN"
_PIN_ILK     = "ilkKurulumPIN1"
_PIN_IKINCI  = "ikinciCalisanPIN2"


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


@pytest.fixture
def kasa_dizini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    return tmp_path


def _ilk_kurulumu_tamamla(qapp, hwid: str, pin: str) -> LoginDialog:
    """
    `first_run` ELLE VERİLMİYOR — `main.py`'nin gerçek otomatik hesabına
    (TOTP sırrı + o HWID için vault var mı) güveniliyor. Sahne
    kurulmuşsa (`_role_group` varsa) İlk Kurulum sihirbazı açılmış demektir.
    """
    dlg = LoginDialog(hwid=hwid, first_run=None, use_vault=True)
    assert hasattr(dlg, "_role_group"), (
        "beklenen İlk Kurulum sihirbazı açılmadı — ön koşul sağlanmıyor, "
        "bu test artık geçerli bir sahneyi ölçmüyor"
    )
    kod = pyotp.TOTP(dlg._secret).now()
    dlg._pin_input.setText(pin)
    dlg._pin_confirm_input.setText(pin)
    dlg._totp_input.setText(kod)
    dlg._on_setup_confirm()
    return dlg


# ══════════════════════════════════════════════════════════════════════════════
# 1. Taze kurulum — ilk kullanıcı otomatik onaylı mı, 'pending' mi düşüyor
# ══════════════════════════════════════════════════════════════════════════════


def test_taze_kurulumda_ILK_kullanici_PENDING_DEGIL_otomatik_onayli(
    qapp, db, kasa_dizini,
) -> None:
    """
    Görevin 1. sorusu. Cevap: (a) — otomatik onaylı — AMA "Kayıt Ol"
    sekmesinin `status='pending'` yazan koduyla hiç ilgisi yok; ayrı bir
    yol (`sync_session_user`, ayrı bir dosyada) bunu yapıyor.
    """
    assert db.fetchone("SELECT COUNT(*) AS n FROM users")["n"] == 0, (
        "ön koşul: users tablosu taze/boş olmalı"
    )

    dlg = _ilk_kurulumu_tamamla(qapp, _HWID_ILK, _PIN_ILK)
    assert dlg.result() == LoginDialog.Accepted
    assert dlg._role == "Yönetici", "sihirbazın varsayılan rolü değişmiş — test kör"

    # `main.py`'nin `dialog.exec()` SONRASI attığı adım — burada simüle ediliyor.
    sync_session_user(db, hwid=_HWID_ILK, role=dlg._role)

    satir = db.fetchone("SELECT * FROM users WHERE hwid = ?", (_HWID_ILK,))
    assert satir is not None, "ilk kullanıcı users tablosuna hiç yazılmadı"
    assert satir["status"] == "approved", (
        "ilk kullanıcı 'pending' düşüyor — onaylayacak admin yok, sistem kilitli kalırdı"
    )
    assert satir["role"] == "admin"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Kurulumdan SONRA, hiç görülmemiş bir USB da AYNI (onaysız) yoldan geçiyor
# ══════════════════════════════════════════════════════════════════════════════


def test_KURULUMDAN_SONRA_farkli_bir_USB_de_ILK_KURULUM_SIHIRBAZINA_dusuyor(
    qapp, db, kasa_dizini,
) -> None:
    """
    Asıl bulgu. "Kayıt Ol" sekmesinin varlığı "yeni kullanıcı → pending →
    admin onayı" akışının TEK yolu olduğu izlenimi veriyor. Değil: bu
    sekmeye ancak ZATEN vault'u olan bir HWID'le ulaşılıyor (`_first_run`
    o zaman `False`). Vault'u OLMAYAN (yani gerçekten YENİ) her USB,
    sistem daha önce hiç kurulmamış gibi, yeniden İlk Kurulum
    sihirbazına düşüyor.
    """
    _ilk_kurulumu_tamamla(qapp, _HWID_ILK, _PIN_ILK)
    sync_session_user(db, hwid=_HWID_ILK, role="Yönetici")
    ilk_sonra_kullanici_sayisi = db.fetchone("SELECT COUNT(*) AS n FROM users")["n"]
    assert ilk_sonra_kullanici_sayisi == 1

    ikinci = LoginDialog(hwid=_HWID_IKINCI, first_run=None, use_vault=True)

    assert hasattr(ikinci, "_role_group"), (
        "beklenen (ve sorunlu) davranış: 'Kayıt Ol' sekmesi DEĞİL, İlk "
        "Kurulum sihirbazı yeniden açıldı — açılmadıysa bulgu artık "
        "geçerli değil, bu testi güncelle"
    )
    assert not hasattr(ikinci, "_stack"), (
        "ikinci/farklı USB normal giriş+kayıt ekranına düştü (beklenmiyordu)"
    )

    kod = pyotp.TOTP(ikinci._secret).now()
    ikinci._pin_input.setText(_PIN_IKINCI)
    ikinci._pin_confirm_input.setText(_PIN_IKINCI)
    ikinci._totp_input.setText(kod)
    ikinci._on_setup_confirm()

    assert ikinci.result() == LoginDialog.Accepted
    assert ikinci._role == "Yönetici", (
        "sihirbaz ikinci USB'ye de rolü SERBEST bıraktı, onay istemedi"
    )
    sync_session_user(db, hwid=_HWID_IKINCI, role=ikinci._role)

    ikinci_satir = db.fetchone("SELECT * FROM users WHERE hwid = ?", (_HWID_IKINCI,))
    assert ikinci_satir is not None
    assert ikinci_satir["status"] == "approved", (
        "ikinci kullanıcı da HİÇBİR onay olmadan 'approved' yazıldı"
    )
    assert ikinci_satir["role"] == "admin", (
        "ikinci kullanıcı varsayılan rol seçimiyle (Yönetici) onaysız admin oldu"
    )

    toplam = db.fetchone("SELECT COUNT(*) AS n FROM users")["n"]
    assert toplam == 2, "iki ayrı, onaysız 'approved' admin — ikisi de kayıtlı"


def test_IKINCI_kurulum_PAYLASILAN_totp_sirrini_EZIYOR(
    qapp, db, kasa_dizini,
) -> None:
    """
    Bulgu 2'nin yan etkisi. TOTP sırrı GLOBAL (`CORE/secret_store.py`) —
    ikinci sihirbaz kendi rastgele sırrını kaydederken ilk kullanıcının
    sırrını da EZİYOR. Sonuç: ilk kullanıcının authenticator uygulaması
    artık geçersiz kod üretiyor, kendi hesabına giremiyor.
    """
    _ilk_kurulumu_tamamla(qapp, _HWID_ILK, _PIN_ILK)
    sync_session_user(db, hwid=_HWID_ILK, role="Yönetici")
    ilk_kullanicinin_sirri = load_totp_secret()
    assert ilk_kullanicinin_sirri is not None

    ikinci = LoginDialog(hwid=_HWID_IKINCI, first_run=None, use_vault=True)
    assert hasattr(ikinci, "_role_group")
    kod = pyotp.TOTP(ikinci._secret).now()
    ikinci._pin_input.setText(_PIN_IKINCI)
    ikinci._pin_confirm_input.setText(_PIN_IKINCI)
    ikinci._totp_input.setText(kod)
    ikinci._on_setup_confirm()
    assert ikinci.result() == LoginDialog.Accepted

    sirdan_sonra = load_totp_secret()
    assert sirdan_sonra != ilk_kullanicinin_sirri, (
        "paylaşılan TOTP sırrı ikinci kurulumla EZİLMEDİ — bulgu artık "
        "geçerli değil, bu testi güncelle"
    )

    # İlk kullanıcının kendi authenticator kodu artık DOĞRULANAMIYOR —
    # login akışının kendisi çökmüyor, ama TOTP kontrolü kalıcı olarak yanlış.
    ilk_kullanicinin_guncel_kodu = pyotp.TOTP(ilk_kullanicinin_sirri).now()
    assert not pyotp.TOTP(sirdan_sonra).verify(
        ilk_kullanicinin_guncel_kodu, valid_window=1
    ), "ilk kullanıcının kodu hâlâ geçerliyse sır aslında ezilmemiş demektir"
