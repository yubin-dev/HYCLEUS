"""
CORE.usb_takeover — kayıp bir yönetici USB'sini kurtarma parçasıyla
YENİ bir USB'ye devretme (B-11X, doğrulama turu 2026-09-09, Madde 2).

Doğrulama turunda gerçek çalıştırmayla saptandı: tek onaylı yöneticinin
USB'si kaybolursa sistem kalıcı kilitleniyordu — `register_new_user()`
hiçbir koşulda ikinci bir admin üretmiyor, ve mevcut "Sil"/"Reddet"
eylemleri zaten oturum açmış bir admin gerektiriyordu. Bu paket YENİ
`takeover_usb()` fonksiyonunun üç iddiasını gerçek vault/DB üzerinde
ölçüyor:

1. Devralma sonrası `users` tablosunda HÂLÂ TEK satır var (yeni satır
   OLUŞTURULMADI, var olanın `hwid`'i güncellendi).
2. Yeni USB ile GERÇEKTEN giriş yapılabiliyor (`open_vault` başarılı,
   doğru rol dönüyor, TOTP sırrı taşınmış).
3. Eski USB artık GERÇEKTEN reddediliyor (`open_vault(eski_hwid, ...)`
   `FileNotFoundError` fırlatıyor — vault dosyası silinmiş).

Mutasyon-kanıtlı doğrulama (bu paketin BİR PARÇASI DEĞİL —
`tests/test_kayit_kurumsal_referans.py`'nin madde 4'ündeki AYNI
gerekçeyle, mutasyon üretim dosyasını geçici değiştirmeyi gerektiriyor,
kalıcı bir test hâline getirilmedi; bkz. commit mesajı / oturum notları):
`takeover_usb()`'daki `discard_vault(old_hwid)` çağrısı geçici olarak
no-op yapıldı → `test_eski_usb_ARTIK_GERCEKTEN_reddediliyor` GERÇEKTEN
düştü (eski USB hâlâ açılabiliyordu) → geri alındı. `db.execute("UPDATE
...")` satırı geçici olarak bir `INSERT`e çevrildi →
`test_devralma_sonrasi_TEK_satir_kaliyor_hwid_guncellenmis` GERÇEKTEN
düştü (2 satır belirdi) → geri alındı.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from CORE import vault_manager
from CORE.secret_store import load_totp_secret_for_hwid, store_totp_secret_for_hwid
from CORE.usb_takeover import TakeoverError, TakeoverResult, takeover_usb
from CORE.vault_manager import (
    create_vault,
    export_recovery_share,
    open_vault,
)

_HWID_ESKI = "USB-DEVRALMA-ESKI"
_HWID_YENI = "USB-DEVRALMA-YENI"
_PIN_ESKI = "eskiPIN123456"
_PIN_YENI = "yeniPIN654321"
_TOTP_SIR = "JBSWY3DPEHPK3PXP"


@pytest.fixture
def kasa_dizini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    return tmp_path


def _admin_kur_ve_kurtarma_parcasi_al(db, kasa_dizini) -> str:
    """Gerçek İlk Kurulum'un yaptığının aynısı: create_vault() + users
    INSERT + TOTP sırrı + kurtarma parçası dışa aktarımı (mockup'ın
    "Tanıtım" adımı — yönetici bunu güvenli bir yerde saklar)."""
    create_vault(_HWID_ESKI, _PIN_ESKI, "Yönetici")
    store_totp_secret_for_hwid(_HWID_ESKI, _TOTP_SIR)
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid) "
        "VALUES ('admin1', 'x', 'admin', 'approved', ?)",
        (_HWID_ESKI,),
    )
    return export_recovery_share(_HWID_ESKI, _PIN_ESKI)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Temel akış — PIN biliniyor (share_1 yoluyla kurtarma)
# ══════════════════════════════════════════════════════════════════════════════


def test_devralma_sonrasi_TEK_satir_kaliyor_hwid_guncellenmis(db, kasa_dizini):
    share_3 = _admin_kur_ve_kurtarma_parcasi_al(db, kasa_dizini)

    sonuc = takeover_usb(
        db, old_hwid=_HWID_ESKI, new_hwid=_HWID_YENI,
        recovery_share=share_3, new_pin=_PIN_YENI, old_pin=_PIN_ESKI,
    )
    assert isinstance(sonuc, TakeoverResult)
    assert sonuc.username == "admin1"
    assert sonuc.role == "Yönetici"

    satirlar = db.fetchall("SELECT id, username, hwid, status FROM users")
    assert len(satirlar) == 1, f"beklenen 1 satır, bulunan: {[dict(r) for r in satirlar]}"
    assert satirlar[0]["hwid"] == _HWID_YENI
    assert satirlar[0]["username"] == "admin1"
    assert satirlar[0]["status"] == "approved"


def test_yeni_usb_ile_GERCEKTEN_giris_yapilabiliyor(db, kasa_dizini):
    share_3 = _admin_kur_ve_kurtarma_parcasi_al(db, kasa_dizini)
    takeover_usb(
        db, old_hwid=_HWID_ESKI, new_hwid=_HWID_YENI,
        recovery_share=share_3, new_pin=_PIN_YENI, old_pin=_PIN_ESKI,
    )

    role, session_key = open_vault(_HWID_YENI, _PIN_YENI)
    assert role == "Yönetici"
    assert len(session_key) == 32


def test_totp_sirri_yeni_hwide_TASINMIS(db, kasa_dizini):
    share_3 = _admin_kur_ve_kurtarma_parcasi_al(db, kasa_dizini)
    takeover_usb(
        db, old_hwid=_HWID_ESKI, new_hwid=_HWID_YENI,
        recovery_share=share_3, new_pin=_PIN_YENI, old_pin=_PIN_ESKI,
    )
    assert load_totp_secret_for_hwid(_HWID_YENI) == _TOTP_SIR
    assert load_totp_secret_for_hwid(_HWID_ESKI) is None


def test_eski_usb_ARTIK_GERCEKTEN_reddediliyor(db, kasa_dizini):
    share_3 = _admin_kur_ve_kurtarma_parcasi_al(db, kasa_dizini)
    takeover_usb(
        db, old_hwid=_HWID_ESKI, new_hwid=_HWID_YENI,
        recovery_share=share_3, new_pin=_PIN_YENI, old_pin=_PIN_ESKI,
    )

    with pytest.raises(FileNotFoundError):
        open_vault(_HWID_ESKI, _PIN_ESKI)


def test_denetim_gunlugune_ACIKCA_yaziliyor(db, kasa_dizini):
    share_3 = _admin_kur_ve_kurtarma_parcasi_al(db, kasa_dizini)
    takeover_usb(
        db, old_hwid=_HWID_ESKI, new_hwid=_HWID_YENI,
        recovery_share=share_3, new_pin=_PIN_YENI, old_pin=_PIN_ESKI,
    )
    kayit = db.fetchone(
        "SELECT action, detail FROM audit_log WHERE action = 'usb_devralindi'"
        " ORDER BY id DESC LIMIT 1"
    )
    assert kayit is not None, "usb_devralindi denetim kaydı hiç düşmemiş"
    assert _HWID_ESKI in kayit["detail"]
    assert _HWID_YENI in kayit["detail"]


# ══════════════════════════════════════════════════════════════════════════════
# 2. Alternatif akış — PIN bilinmiyor (share_2 yoluyla kurtarma)
# ══════════════════════════════════════════════════════════════════════════════


def test_share2_yoluyla_da_devralma_calisiyor(db, kasa_dizini):
    """`old_pin=None` — vault dosyası kayıp/bozuk sayılıyor, kalan pay
    bu makinenin anahtar kasasındaki share_2."""
    share_3 = _admin_kur_ve_kurtarma_parcasi_al(db, kasa_dizini)

    sonuc = takeover_usb(
        db, old_hwid=_HWID_ESKI, new_hwid=_HWID_YENI,
        recovery_share=share_3, new_pin=_PIN_YENI, old_pin=None,
    )
    assert sonuc.role == "Yönetici"
    role, _key = open_vault(_HWID_YENI, _PIN_YENI)
    assert role == "Yönetici"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Reddedilme senaryoları
# ══════════════════════════════════════════════════════════════════════════════


def test_olmayan_eski_hwid_reddedilir(db, kasa_dizini):
    with pytest.raises(TakeoverError, match="devralınacak"):
        takeover_usb(
            db, old_hwid="HIC-YOK", new_hwid=_HWID_YENI,
            recovery_share="3:deadbeef", new_pin=_PIN_YENI, old_pin=None,
        )


def test_yeni_hwid_zaten_baskasina_baGLiysa_reddedilir(db, kasa_dizini):
    share_3 = _admin_kur_ve_kurtarma_parcasi_al(db, kasa_dizini)
    # Yeni HWID zaten BAŞKA bir hesaba bağlı olsun.
    create_vault(_HWID_YENI, "baskaPIN12345", "Standart")
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid) "
        "VALUES ('baska_kullanici', 'x', 'user', 'approved', ?)",
        (_HWID_YENI,),
    )

    with pytest.raises(TakeoverError, match="zaten başka bir hesaba"):
        takeover_usb(
            db, old_hwid=_HWID_ESKI, new_hwid=_HWID_YENI,
            recovery_share=share_3, new_pin=_PIN_YENI, old_pin=_PIN_ESKI,
        )

    # Reddedilince HİÇBİR şey değişmemiş olmalı — iki satır da eskisi gibi.
    satirlar = db.fetchall("SELECT username, hwid FROM users ORDER BY id")
    assert [dict(r) for r in satirlar] == [
        {"username": "admin1", "hwid": _HWID_ESKI},
        {"username": "baska_kullanici", "hwid": _HWID_YENI},
    ]


def test_yeni_hwid_BEKLEYEN_bir_hesaba_baGLiysa_da_reddedilir(db, kasa_dizini):
    """
    Çakışma kontrolü yalnızca 'approved' satırlara bakarsa (zayıflatılmış
    hâli), `new_hwid` bekleyen (henüz onaylanmamış) bir kayda bağlıysa
    kontrolden GEÇER ve devralma devam eder. Bu ÖZELLİKLE tehlikelidir:
    `discard_vault(old_hwid)` GERİ ALINAMAZ biçimde eski vault'u siler,
    ve ancak ONDAN SONRA gelen `UPDATE users SET hwid=...` adımı
    `users.hwid` üzerindeki UNIQUE indekse (B-060) çarpıp patlar — yani
    eski vault YOK OLUR ama devralma yine de BAŞARISIZ kalır. Kontrol
    durumdan (approved/pending) BAĞIMSIZ olmalı; hiçbir yan etki
    başlamadan EN BAŞTA reddetmeli.
    """
    share_3 = _admin_kur_ve_kurtarma_parcasi_al(db, kasa_dizini)
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid) "
        "VALUES ('bekleyen_kullanici', 'x', 'user', 'pending', ?)",
        (_HWID_YENI,),
    )

    with pytest.raises(TakeoverError, match="zaten başka bir hesaba"):
        takeover_usb(
            db, old_hwid=_HWID_ESKI, new_hwid=_HWID_YENI,
            recovery_share=share_3, new_pin=_PIN_YENI, old_pin=_PIN_ESKI,
        )

    # Hiçbir yan etki başlamamış olmalı: eski vault hâlâ açılabiliyor,
    # users tablosu değişmemiş.
    _rol, _key = open_vault(_HWID_ESKI, _PIN_ESKI)
    satirlar = db.fetchall("SELECT username, hwid, status FROM users ORDER BY id")
    assert [dict(r) for r in satirlar] == [
        {"username": "admin1", "hwid": _HWID_ESKI, "status": "approved"},
        {"username": "bekleyen_kullanici", "hwid": _HWID_YENI, "status": "pending"},
    ]


def test_yanlis_kurtarma_parcasi_reddedilir_DB_DEGISMEZ(db, kasa_dizini):
    _admin_kur_ve_kurtarma_parcasi_al(db, kasa_dizini)

    with pytest.raises(Exception):
        takeover_usb(
            db, old_hwid=_HWID_ESKI, new_hwid=_HWID_YENI,
            recovery_share="3:" + "00" * 32, new_pin=_PIN_YENI, old_pin=_PIN_ESKI,
        )

    satirlar = db.fetchall("SELECT username, hwid FROM users")
    assert len(satirlar) == 1
    assert satirlar[0]["hwid"] == _HWID_ESKI, "yanlış parçayla bile hwid DEĞİŞMEMELİ"


def test_yanlis_eski_pin_reddedilir(db, kasa_dizini):
    share_3 = _admin_kur_ve_kurtarma_parcasi_al(db, kasa_dizini)

    with pytest.raises(Exception):
        takeover_usb(
            db, old_hwid=_HWID_ESKI, new_hwid=_HWID_YENI,
            recovery_share=share_3, new_pin=_PIN_YENI, old_pin="yanlisPINxxxx",
        )
