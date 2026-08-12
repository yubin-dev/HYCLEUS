"""
Uçtan uca kurtarma senaryosu — TAM KAYIP simülasyonu.

Bu dosya "kurtarma çalışıyor" iddiasını ilk kurulumda değil, GERÇEK kayıp
akışında sınar: dosya şifrele → kurtarma parçasını al → USB'yi kaybet →
kurtar → yeni USB'ye yeniden kur → her şey hâlâ çalışıyor mu.

Sınanan asıl risk: yeniden kurulum yeni bir master_key veya yeni bir polinom
üretirse, kullanıcı bunu ancak İKİNCİ kayıpta fark eder — o noktada ne
dosyaları ne de basılı parçası işe yarar.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from CORE import crypto, vault_manager
from CORE.crypto import decrypt_file, encrypt_file
from CORE.recovery_share import decode_share, encode_share
from CORE.secret_store import erase, share_2_username
from CORE.vault_manager import (
    create_vault,
    export_recovery_share,
    open_vault,
    recover_master_key,
    reprovision_vault,
)

_ESKI_HWID = "USB-ESKI-0001"
_YENI_HWID = "USB-YENI-0002"
_ESKI_PIN = "orijinal-pin-1"
_YENI_PIN = "kurtarma-pin-2"
_ROLE = "Yönetici"


@pytest.fixture
def ortam(db, tmp_path: Path, monkeypatch):
    """İzole vault dizini + karantina dizini."""
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", tmp_path / "quarantine")
    return tmp_path


def _usbyi_kaybet(hwid: str) -> None:
    """share_2'yi anahtar kasasından siler — USB/kasa kaybı senaryosu."""
    erase(share_2_username(hwid))


# ── Ana senaryo ───────────────────────────────────────────────────────────────

def test_full_loss_and_recovery_cycle(ortam: Path, db) -> None:
    """
    1. Vault oluştur, dosya şifrele, kurtarma parçasını al
    2. USB'yi kaybet (share_2 sil)
    3. share_1 + basılı parça ile master_key'i kurtar
    4. Yeni USB'ye yeniden kur
    5a. Yeni USB + yeni PIN ile vault açılıyor mu
    5b. ÖNCEDEN şifrelenmiş .hcl hâlâ çözülüyor mu
    5c. Basılı parça hâlâ geçerli mi
    """
    # ── 1. Kurulum + dosya + kurtarma parçası ────────────────────────────────
    create_vault(_ESKI_HWID, _ESKI_PIN, _ROLE)
    _role, master_key_ilk = open_vault(_ESKI_HWID, _ESKI_PIN)

    kaynak = ortam / "onemli_rapor.txt"
    icerik = b"kurtarma sonrasi da okunabilmeli\n" * 500
    kaynak.write_bytes(icerik)
    hcl_yolu, sha_ilk, _aad = encrypt_file(kaynak, master_key_ilk, user_id=1, hwid=_ESKI_HWID)

    share_3 = export_recovery_share(_ESKI_HWID, _ESKI_PIN)
    basili_parca = encode_share(share_3)  # kullanıcının kâğıda yazdığı hâli

    # ── 2. USB kaybı ─────────────────────────────────────────────────────────
    _usbyi_kaybet(_ESKI_HWID)
    with pytest.raises(ValueError, match="anahtar kasasında bulunamadı"):
        open_vault(_ESKI_HWID, _ESKI_PIN)

    # ── 3. Kurtarma: share_1 (vault + PIN) + basılı parça ────────────────────
    kagittan_okunan = decode_share(basili_parca.lower().replace("-", " "))
    master_key_kurtarilan = recover_master_key(
        _ESKI_HWID, recovery_share=kagittan_okunan, pin=_ESKI_PIN
    )
    assert master_key_kurtarilan == master_key_ilk, "kurtarılan anahtar farklı"

    # ── 4. Yeni USB'ye yeniden kurulum ───────────────────────────────────────
    reprovision_vault(
        _YENI_HWID, _YENI_PIN, _ROLE,
        master_key=master_key_kurtarilan,
        recovery_share=kagittan_okunan,
    )

    # ── 5a. Yeni USB + yeni PIN ile açılıyor mu ──────────────────────────────
    role_sonra, master_key_sonra = open_vault(_YENI_HWID, _YENI_PIN)
    assert role_sonra == _ROLE
    assert master_key_sonra == master_key_ilk, (
        "yeniden kurulum master_key'i değiştirdi — mevcut .hcl dosyaları kaybolurdu"
    )

    # ── 5b. Önceden şifrelenmiş dosya hâlâ çözülüyor mu ──────────────────────
    cozulen, meta = decrypt_file(hcl_yolu, master_key_sonra, hwid=_ESKI_HWID)
    assert cozulen == icerik, "kurtarma öncesi şifrelenmiş dosya artık açılamıyor"
    assert meta["original_sha256"] == sha_ilk

    # ── 5c. Basılı parça hâlâ geçerli mi ─────────────────────────────────────
    yeni_share_3 = export_recovery_share(_YENI_HWID, _YENI_PIN)
    assert yeni_share_3 == kagittan_okunan, (
        "kurtarma parçası değişti — kullanıcının kâğıdı sessizce geçersizleşti"
    )
    # Ve gerçekten kurtarma yapabilmeli
    assert recover_master_key(
        _YENI_HWID, recovery_share=kagittan_okunan, pin=None
    ) == master_key_ilk


def test_second_loss_after_recovery_also_works(ortam: Path, db) -> None:
    """
    İKİNCİ kayıp da çalışmalı.

    "Kurtarma çalışıyor" demek ilk kurulumda çalıştığı anlamına gelmez;
    asıl sınav, kurtarılmış bir vault'un yeniden kurtarılabilmesidir.
    """
    create_vault(_ESKI_HWID, _ESKI_PIN, _ROLE)
    _r, master_key = open_vault(_ESKI_HWID, _ESKI_PIN)
    basili = encode_share(export_recovery_share(_ESKI_HWID, _ESKI_PIN))

    # 1. kayıp → kurtar → yeniden kur
    _usbyi_kaybet(_ESKI_HWID)
    k1 = recover_master_key(_ESKI_HWID, recovery_share=decode_share(basili), pin=_ESKI_PIN)
    reprovision_vault(
        _YENI_HWID, _YENI_PIN, _ROLE, master_key=k1, recovery_share=decode_share(basili)
    )

    # 2. kayıp → AYNI kâğıtla tekrar kurtar
    _usbyi_kaybet(_YENI_HWID)
    ucuncu_hwid = "USB-UCUNCU-0003"
    k2 = recover_master_key(_YENI_HWID, recovery_share=decode_share(basili), pin=_YENI_PIN)
    assert k2 == master_key, "ikinci kurtarmada anahtar bozuldu"

    reprovision_vault(
        "USB-UCUNCU-0003", "ucuncu-pin-3", _ROLE,
        master_key=k2, recovery_share=decode_share(basili),
    )
    _r3, k3 = open_vault(ucuncu_hwid, "ucuncu-pin-3")
    assert k3 == master_key


def test_recovery_when_vault_file_is_gone(ortam: Path, db) -> None:
    """share_1 kayıp senaryosu: vault dosyası yok, share_2 + parça yeterli."""
    create_vault(_ESKI_HWID, _ESKI_PIN, _ROLE)
    _r, master_key = open_vault(_ESKI_HWID, _ESKI_PIN)
    basili = encode_share(export_recovery_share(_ESKI_HWID, _ESKI_PIN))

    vault_dosyasi = vault_manager._read_vault_path(_ESKI_HWID)
    vault_manager._clear_readonly(vault_dosyasi)
    vault_dosyasi.unlink()

    kurtarilan = recover_master_key(
        _ESKI_HWID, recovery_share=decode_share(basili), pin=None
    )
    assert kurtarilan == master_key

    reprovision_vault(
        _YENI_HWID, _YENI_PIN, _ROLE,
        master_key=kurtarilan, recovery_share=decode_share(basili),
    )
    _r2, k2 = open_vault(_YENI_HWID, _YENI_PIN)
    assert k2 == master_key


# ── Regresyon koruması: create_vault'un yıkıcı varsayılanı ────────────────────

def test_plain_create_vault_generates_a_new_key(ortam: Path, db) -> None:
    """
    master_key VERİLMEZSE yeni anahtar üretilir — bu bilinçli varsayılan.

    Bu testin amacı davranışı onaylamak değil, KAYIT ALTINA ALMAK: kurtarma
    akışının neden reprovision_vault kullanmak ZORUNDA olduğunu gösterir.
    """
    create_vault(_ESKI_HWID, _ESKI_PIN, _ROLE)
    _r, ilk = open_vault(_ESKI_HWID, _ESKI_PIN)

    create_vault(_YENI_HWID, _YENI_PIN, _ROLE)
    _r2, ikinci = open_vault(_YENI_HWID, _YENI_PIN)

    assert ikinci != ilk, "create_vault aynı anahtarı üretti — beklenmedik"


def test_reprovision_without_anchor_would_invalidate_the_paper(ortam: Path, db) -> None:
    """
    Çıpasız yeniden bölme basılı parçayı geçersizleştirir.

    reprovision_vault bunu ÖNLEMEK için recovery_share'i zorunlu tutuyor;
    bu test o kararın neden gerekli olduğunu gösterir.
    """
    create_vault(_ESKI_HWID, _ESKI_PIN, _ROLE)
    _r, master_key = open_vault(_ESKI_HWID, _ESKI_PIN)
    eski_parca = export_recovery_share(_ESKI_HWID, _ESKI_PIN)

    # Çıpa VERMEDEN yeniden kur (anahtar korunur ama polinom değişir)
    create_vault(_YENI_HWID, _YENI_PIN, _ROLE, master_key=master_key)
    yeni_parca = export_recovery_share(_YENI_HWID, _YENI_PIN)

    assert yeni_parca != eski_parca, "polinom değişmemiş — test kurulumu hatalı"
    # Eski kâğıt artık yanlış anahtar verir (veya hata)
    try:
        yanlis = recover_master_key(_YENI_HWID, recovery_share=eski_parca, pin=None)
    except (ValueError, OverflowError):
        return
    assert yanlis != master_key, "çıpasız yeniden bölmede eski parça hâlâ çalıştı"


def test_anchored_split_reproduces_every_share(ortam: Path, db) -> None:
    """Çıpalı bölme üç payın da AYNISINI üretmeli — sadece f(3)'ü değil."""
    secret = bytes(range(32))
    s1, s2, s3 = vault_manager._sss_split(secret)

    for cipa in (s1, s2, s3):
        y1, y2, y3 = vault_manager._sss_split(secret, anchor=cipa)
        assert (y1, y2, y3) == (s1, s2, s3), f"çıpa {cipa[:2]} ile paylar farklı çıktı"
