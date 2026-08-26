"""
B-058 — kök neden düzeltmesi + savunma derinliği.

Önceki tur (bu dosyanın önceki hâli) YALNIZCA kanıtlıyordu, düzeltmiyordu:
`_first_run` hesabı "bu HWID'nin vault dosyası var mı" sorusuna bakıyordu
(HWID BAŞINA) ama TOTP sırrı GLOBAL'di — sonuç, kurulu bir sistemde daha
önce hiç görülmemiş HER USB'nin "Kayıt Ol" (pending onay) sekmesine değil,
yeniden İlk Kurulum sihirbazına (serbest rol seçimi, onaysız doğrudan
'approved' yazımı) düşmesiydi.

Bu tur kök nedeni düzeltiyor: doğru soru "sistemde onaylı en az bir
kullanıcı var mı" — `CORE.session_user.sistem_kurulmus_mu()`, HEM
`main.py` HEM `UI/login_dialog.py`'nin kendi fallback hesabında AYNI
fonksiyon (tek kaynak — iki ayrı tanım İKİ AYRI KARAR NOKTASI demek
olurdu, bu deponun B-028/B-030/B-033'te defalarca düzelttiği kusur).
Savunma derinliği için `_on_setup_confirm()`'ün başına da AYNI kontrolle
bir guard eklendi — `_first_run` hesabı bir yerde atlanırsa (ör. ileride
`first_run=True` sabitlenmiş bir çağrı yolu eklenirse) sessizce ikinci
bir onaysız admin üretmek yerine `RuntimeError` fırlatıyor.

Bu paket dört şeyi ölçüyor
---------------------------
1. Taze kurulumda ilk kullanıcı hâlâ otomatik onaylı (değişmedi).
2. Kurulumdan SONRA, daha önce hiç görülmemiş bir USB artık İlk Kurulum
   sihirbazına DÜŞMÜYOR — "Kayıt Ol" (pending) yoluna gidiyor.
3. Bu yönlendirme düzeltmesinin yan etkisi: ikinci USB artık ilk
   kullanıcının TOTP sırrına hiç DOKUNMUYOR (sihirbaza hiç girmediği
   için). TOTP'nin o zamanlar GLOBAL olması ayrı bir açıktı (B-059);
   sonraki bir turda TOTP HWID başına taşındı (`tests/test_authz_invariants.py`,
   `CORE/secret_migration.py::migrate_totp_to_per_hwid`) — bu paketteki
   test artık HWID başına saklanan sırrı okuyor, ama "ikinci USB
   birincininkini ezmiyor" iddiasının kendisi değişmedi.
4. Guard mutasyonla doğrulanıyor: onaylı kullanıcı VARKEN sihirbaz
   zorla çağrılırsa patlıyor; YOKKEN aynı zorlama patlamıyor — guard'ın
   gerçekten KOŞULA bağlı olduğu, kör bir `raise` olmadığı kanıtlanıyor.
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
from CORE.app_mode import BIREYSEL, set_app_mode
from CORE.secret_store import load_totp_secret_for_hwid
from CORE.session_user import sistem_kurulmus_mu, sync_session_user

_HWID_ILK    = "USB-B058-ILK-ADMIN"
_HWID_IKINCI = "USB-B058-IKINCI-CALISAN"
_HWID_UCUNCU = "USB-B058-UCUNCU-CALISAN"
_PIN_ILK     = "ilkKurulumPIN1"
_PIN_IKINCI  = "ikinciCalisanPIN2"
_ROL_IKINCI  = "Standart"


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


@pytest.fixture(autouse=True)
def referans_id_dialog_susturuldu(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Arayüz güncellemesi (2026-08-26): sihirbazda Kurumsal VARSAYILAN olarak
    seçili — `_on_setup_confirm()` artık Kurumsal seçiliyken modal bir
    Referans ID diyaloğu (`.exec()`) gösteriyor (bkz. CORE/referans_id.py).
    Bu dosyanın testleri o akışı hiç ölçmüyor (kendi paketi var, bkz.
    tests/test_kayit_kurumsal_referans.py) — susturulmazsa başsız test
    koşucusunda SONSUZA KADAR bloklardı (`show_totp_enrollment_dialog`
    için zaten uygulanan aynı desen).
    """
    monkeypatch.setattr(LoginDialog, "_show_referans_id_dialog", lambda self, rid: None)


def _ilk_kurulumu_tamamla(qapp, hwid: str, pin: str) -> LoginDialog:
    """
    `first_run` ELLE VERİLMİYOR — gerçek otomatik hesaba (artık
    `sistem_kurulmus_mu()`) güveniliyor. Sahne kurulmuşsa (`_role_group`
    varsa) İlk Kurulum sihirbazı açılmış demektir.
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
# 1. Taze kurulum — ilk kullanıcı otomatik onaylı (değişmedi)
# ══════════════════════════════════════════════════════════════════════════════


def test_taze_kurulumda_ILK_kullanici_PENDING_DEGIL_otomatik_onayli(
    qapp, db, kasa_dizini,
) -> None:
    assert db.fetchone("SELECT COUNT(*) AS n FROM users")["n"] == 0, (
        "ön koşul: users tablosu taze/boş olmalı"
    )
    assert not sistem_kurulmus_mu(db), "boş tabloda sistem kurulmuş görünüyor — kör"

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
    assert sistem_kurulmus_mu(db), "onaylı kullanıcı yazıldıktan sonra hâlâ 'kurulmamış' görünüyor"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Düzeltme — kurulumdan SONRA yeni bir USB artık 'Kayıt Ol' (pending) yolunda
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("hwid", [_HWID_IKINCI, _HWID_UCUNCU])
def test_KURULUMDAN_SONRA_yeni_bir_USB_ARTIK_sihirbaza_DUSMUYOR(
    qapp, db, kasa_dizini, hwid: str,
) -> None:
    """
    (a) — users tablosu doluyken sihirbaz HİÇBİR HWID için tetiklenmiyor.
    İki farklı, daha önce hiç görülmemiş HWID ile ayrı ayrı sınanıyor —
    tek bir HWID'e özel bir tesadüf olmadığını göstermek için.
    """
    _ilk_kurulumu_tamamla(qapp, _HWID_ILK, _PIN_ILK)
    sync_session_user(db, hwid=_HWID_ILK, role="Yönetici")

    yeni = LoginDialog(hwid=hwid, first_run=None, use_vault=True)

    assert not hasattr(yeni, "_role_group"), (
        f"{hwid}: İlk Kurulum sihirbazı hâlâ açılıyor — kök neden düzeltmesi çalışmıyor"
    )
    assert hasattr(yeni, "_stack"), (
        f"{hwid}: normal Giriş/Kayıt Ol ekranı (ana UI) açılmadı"
    )


def test_KURULUMDAN_SONRA_yeni_USB_KAYIT_OL_ile_PENDING_uretiyor_ASLA_approved_degil(
    qapp, db, kasa_dizini, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    (b) — daha önce görülmemiş bir HWID, "Kayıt Ol" sekmesinden geçtiğinde
    her koşulda `status='pending'` üretiyor; `approved`/`admin` ASLA değil.
    """
    _ilk_kurulumu_tamamla(qapp, _HWID_ILK, _PIN_ILK)
    sync_session_user(db, hwid=_HWID_ILK, role="Yönetici")

    # Bu test "ikinci USB → pending" davranışını ölçüyor, Kurumsal Referans
    # Kodu akışını DEĞİL (o ayrı bir pakette, bkz. test_kayit_kurumsal_
    # referans.py) — Bireysel'e geçilerek o alan devre dışı bırakılıyor.
    set_app_mode(db, BIREYSEL)

    import UI.login_dialog as ld
    monkeypatch.setattr(ld, "get_usb_hwid", lambda: _HWID_IKINCI)
    # B-059: kayıt artık kendi TOTP sırrını üretip modal bir QR mesaj
    # kutusu gösteriyor -- testte bloklamasın diye susturuluyor.
    monkeypatch.setattr(ld, "show_totp_enrollment_dialog", lambda *a, **k: None)

    ikinci = LoginDialog(hwid=_HWID_IKINCI, first_run=None, use_vault=True)
    assert hasattr(ikinci, "_stack"), "ana UI açılmadı — ön koşul sağlanmıyor"

    ikinci._reg_username.setText("ikinci_calisan")
    ikinci._reg_pin.setText(_PIN_IKINCI)
    ikinci._reg_pin2.setText(_PIN_IKINCI)
    ikinci._reg_role.setCurrentText(_ROL_IKINCI)
    ikinci._on_register()

    assert ikinci._reg_error.isHidden(), (
        f"kayıt hata verdi: {ikinci._reg_error.text()}"
    )
    satir = db.fetchone("SELECT * FROM users WHERE hwid = ?", (_HWID_IKINCI,))
    assert satir is not None, "ikinci kullanıcı hiç yazılmadı"
    assert satir["status"] == "pending", (
        f"ikinci kullanıcı 'pending' DEĞİL — status={satir['status']!r}"
    )
    assert satir["role"] != "admin", (
        "ikinci kullanıcı onaysız şekilde admin oldu"
    )

    toplam_approved = db.fetchone(
        "SELECT COUNT(*) AS n FROM users WHERE status = 'approved'"
    )["n"]
    assert toplam_approved == 1, (
        "onaylı kullanıcı sayısı hâlâ 1 olmalı — ikinci kullanıcı onaysız "
        "'approved' listesine sızmamalı"
    )


def test_IKINCI_USB_ARTIK_ILK_KULLANICININ_totp_sirrini_EZMIYOR(
    qapp, db, kasa_dizini,
) -> None:
    """
    Yönlendirme düzeltmesinin yan etkisi: ikinci USB artık
    `_on_setup_confirm()`'e hiç GİRMİYOR, dolayısıyla ilk kullanıcının
    TOTP sırrına dokunmuyor.

    B-059 (ayrı bir tarama turunda kapatıldı) TOTP'yi HWID başına
    taşıdığı için "paylaşılan sırrı ezme" ihtimali artık YAPISAL olarak
    da yok (her HWID kendi keyring kaydında) — bu test yine de ilk
    kullanıcının KENDİ sırrının ikinci bir USB'nin varlığından
    etkilenmediğini doğrudan ölçüyor.
    """
    ilk = _ilk_kurulumu_tamamla(qapp, _HWID_ILK, _PIN_ILK)
    sync_session_user(db, hwid=_HWID_ILK, role="Yönetici")
    ilk_sir = load_totp_secret_for_hwid(_HWID_ILK)
    assert ilk_sir is not None
    assert ilk_sir == ilk._secret

    ikinci = LoginDialog(hwid=_HWID_IKINCI, first_run=None, use_vault=True)
    assert not hasattr(ikinci, "_role_group"), (
        "sihirbaz hâlâ açılıyor — bu test artık B-058'in düzeltilmiş "
        "hâlini ölçmüyor"
    )

    sir_degismedi = load_totp_secret_for_hwid(_HWID_ILK)
    assert sir_degismedi == ilk_sir, (
        "ilk kullanıcının TOTP sırrı hâlâ değişiyor — yönlendirme "
        "düzeltmesi bu yan etkiyi kapatmamış"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 3. Guard — mutasyon kanıtı
# ══════════════════════════════════════════════════════════════════════════════
#
# `_first_run` hesabı doğru çalışsa bile, savunma derinliği
# `_on_setup_confirm()`'ün KENDİSİNİN de aynı korumayı taşımasını
# istiyor. Bunu ölçmenin tek yolu, dış kapıyı (`_first_run`) BİLEREK
# atlayıp sihirbazı `first_run=True` ile ZORLA açmak — gerçek bir kod
# yolunda hiç olmaması gereken ama "ileride biri first_run'u yanlış
# sabitlerse" senaryosunu taklit eden bir durum.


def test_GUARD_onayli_kullanici_VARKEN_sihirbaz_ZORLA_cagrilirsa_PATLAR(
    qapp, db, kasa_dizini,
) -> None:
    _ilk_kurulumu_tamamla(qapp, _HWID_ILK, _PIN_ILK)
    sync_session_user(db, hwid=_HWID_ILK, role="Yönetici")
    assert sistem_kurulmus_mu(db)

    zorla = LoginDialog(hwid=_HWID_IKINCI, first_run=True, use_vault=True)
    kod = pyotp.TOTP(zorla._secret).now()
    zorla._pin_input.setText(_PIN_IKINCI)
    zorla._pin_confirm_input.setText(_PIN_IKINCI)
    zorla._totp_input.setText(kod)

    with pytest.raises(RuntimeError, match="B-058"):
        zorla._on_setup_confirm()

    # Guard PATLADIKTAN SONRA bile ikinci bir onaysız kullanıcı yazılmamalı.
    toplam = db.fetchone("SELECT COUNT(*) AS n FROM users")["n"]
    assert toplam == 1, "guard patladı ama satır yine de yazılmış"


def test_GUARD_onayli_kullanici_YOKKEN_zorla_first_run_PATLAMAZ(
    qapp, db, kasa_dizini,
) -> None:
    """
    Mutasyon kontrastı: guard KOŞULA bağlı, kör bir `raise` değil. Users
    tablosu boşken (gerçek ilk kurulum) `first_run=True` ZORLAMASI bile
    normal şekilde tamamlanabilmeli — guard yalnızca "onaylı kullanıcı
    zaten var" durumunda devreye giriyor.
    """
    assert db.fetchone("SELECT COUNT(*) AS n FROM users")["n"] == 0

    zorla = LoginDialog(hwid=_HWID_ILK, first_run=True, use_vault=True)
    kod = pyotp.TOTP(zorla._secret).now()
    zorla._pin_input.setText(_PIN_ILK)
    zorla._pin_confirm_input.setText(_PIN_ILK)
    zorla._totp_input.setText(kod)

    zorla._on_setup_confirm()  # PATLAMAMALI

    assert zorla.result() == LoginDialog.Accepted
