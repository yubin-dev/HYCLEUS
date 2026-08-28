"""
CORE.vault_manager — vault HMAC imza anahtarının share_2-bazlı şemaya geçişi.

Eski şema: imza anahtarı HKDF(info=hwid) idi. HWID sır değil — vault
dosyasının kendi adında (vaults/<hwid>.hclv) açık yazıyor — yani dosyayı
eline geçiren HERKES aynı anahtarı türetip geçerli bir HMAC üretebiliyordu
(SECURITY.md §4.2). Yeni şema imza anahtarını share_2'den türetiyor; share_2
yalnızca OS anahtar kasasında durur, dosyada ya da AAD'da hiç görünmez.

Gerçek vault dosyaları (tmp_path'e yönlendirilmiş _VAULT_DIR) ve gerçek
bellek-içi keyring (fake_keyring, autouse — bkz. conftest.py) kullanılır;
mock yoktur.
"""
from __future__ import annotations

import hmac as _stdlib_hmac
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from CORE import vault_manager
from CORE.vault_manager import VaultTamperedError, create_vault, verify_vault

_HWID = "USB-HMAC-MIGRATION-TEST"
_PIN = "gizli-pin-456"
_ROLE = "Standart"


@pytest.fixture
def vault_dizini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / "legacy.hclv")
    return tmp_path


def _vault_path(hwid: str) -> Path:
    return vault_manager._read_vault_path(hwid)


def _resign_with_legacy_scheme(hwid: str) -> None:
    """
    Diskteki vault dosyasını ESKİ (HWID-bazlı) şemayla yeniden imzalar.

    Bu düzeltme öncesi oluşturulmuş, üretimde kalmış bir vault'u simüle
    eder — o zaman imza anahtarı yalnızca hwid'den türüyordu.
    """
    path = _vault_path(hwid)
    raw = path.read_bytes()
    protected = raw[: -vault_manager._HMAC_SIZE]
    eski_imza = vault_manager._sign(
        vault_manager._derive_signing_key_legacy_hwid(hwid), protected
    )
    # create_vault() dosyayı readonly bırakıyor (Windows) — _writable() ile
    # geçici olarak kaldırıp geri koymadan doğrudan yazmak PermissionError verir.
    with vault_manager._writable(path):
        path.write_bytes(protected + eski_imza)


# ── Ana düzeltme: HWID-bazlı sahte imza artık geçersiz ────────────────────────

def test_forged_hwid_only_hmac_no_longer_verifies(vault_dizini, db) -> None:
    """
    ASIL DÜZELTME: HWID'i bilen ama share_2'ye erişemeyen biri artık
    geçerli bir vault HMAC'ı ÜRETEMEMELİ.

    HWID sır değil — vault dosyasının kendi ADINDA açık yazıyor (bkz.
    BACKLOG B-025) — bu test, saldırganın bildiği TEK şeyle (hwid) forge
    ettiği bir imzanın artık kabul edilmediğini kanıtlıyor. Düzeltmeden
    önce bu test AssertionError yerine sessizce geçerdi (verify_vault
    istisna atmazdı).
    """
    create_vault(_HWID, _PIN, _ROLE)

    _resign_with_legacy_scheme(_HWID)

    with pytest.raises(VaultTamperedError):
        verify_vault(_HWID)


def test_share2_based_signature_verifies(vault_dizini, db) -> None:
    """Karşıt durum: gerçek share_2-bazlı imza normal şekilde doğrulanmalı."""
    create_vault(_HWID, _PIN, _ROLE)
    verify_vault(_HWID)  # istisna atmamalı


def test_new_vault_signature_does_not_match_legacy_scheme(vault_dizini, db) -> None:
    """
    create_vault() artık HWID-bazlı imza ÜRETMİYOR — bunu doğrudan kontrol et.

    Yukarıdaki iki test davranışı sınıyor; bu, üretilen dosyanın BİÇİMİNİ
    kontrol ediyor: eski şemayla hesaplanan imza, yeni dosyanın trailer'ıyla
    eşleşmemeli.
    """
    create_vault(_HWID, _PIN, _ROLE)
    raw = _vault_path(_HWID).read_bytes()
    protected = raw[: -vault_manager._HMAC_SIZE]
    stored_hmac = raw[-vault_manager._HMAC_SIZE :]

    eski_imza = vault_manager._sign(
        vault_manager._derive_signing_key_legacy_hwid(_HWID), protected
    )
    assert not _stdlib_hmac.compare_digest(eski_imza, stored_hmac)


# ── HKDF domain separation ─────────────────────────────────────────────────────

def test_hkdf_info_label_changes_output_for_same_share_2() -> None:
    """
    Aynı share_2 (anahtar materyali) farklı `info` etiketleriyle türetilirse
    farklı çıktı üretmeli.

    Bu, share_2'yi gelecekte BAŞKA bir amaçla (bu HMAC dışında, varsayımsal
    bir ikinci HKDF tüketicisi) kullanan bir çağrının — aynı etiketi
    kullanmadığı sürece — bu vault-HMAC anahtarıyla ÇAKIŞMAYACAĞINI garanti
    eden özelliği doğrudan kanıtlıyor.
    """
    share_2 = "2:" + "ab" * 33

    anahtar_1 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=vault_manager._HKDF_LABEL,
        info=vault_manager._HMAC_INFO_PREFIX + b"USB-A",
    ).derive(share_2.encode())

    anahtar_2 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=vault_manager._HKDF_LABEL,
        info=b"varsayimsal-baska-amac:USB-A",
    ).derive(share_2.encode())

    assert anahtar_1 != anahtar_2


def test_derive_signing_key_matches_documented_hkdf_parameters() -> None:
    """_derive_signing_key() belgelenen HKDF parametrelerini (salt/info) kullanıyor."""
    share_2 = "2:" + "cd" * 33
    beklenen = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=vault_manager._HKDF_LABEL,
        info=vault_manager._HMAC_INFO_PREFIX + _HWID.encode(),
    ).derive(share_2.encode())

    assert vault_manager._derive_signing_key(_HWID, share_2) == beklenen


def test_signing_key_depends_on_share_2_not_just_hwid() -> None:
    """Aynı HWID, farklı share_2 → farklı imza anahtarı üretmeli."""
    k1 = vault_manager._derive_signing_key(_HWID, "2:" + "11" * 33)
    k2 = vault_manager._derive_signing_key(_HWID, "2:" + "22" * 33)
    assert k1 != k2


# ── Migration ───────────────────────────────────────────────────────────────

def test_migration_resigns_legacy_vault(vault_dizini, db) -> None:
    """
    Eski şemayla imzalanmış bir vault, migration sonrası YENİ şemayla
    doğrulanmalı — kullanıcı hiçbir şey yapmadan kesintisiz geçiş.
    """
    create_vault(_HWID, _PIN, _ROLE)
    _resign_with_legacy_scheme(_HWID)  # "üretimde kalmış eski vault" simülasyonu

    # Ön koşul: migration öncesi yeni şemayla doğrulanmıyor
    with pytest.raises(VaultTamperedError):
        verify_vault(_HWID)

    sonuc = vault_manager.migrate_vault_hmac_to_share2(_HWID)

    assert sonuc == "migrated"
    verify_vault(_HWID)  # artık istisna atmamalı


def test_migration_is_idempotent(vault_dizini, db) -> None:
    create_vault(_HWID, _PIN, _ROLE)
    _resign_with_legacy_scheme(_HWID)

    ilk = vault_manager.migrate_vault_hmac_to_share2(_HWID)
    ikinci = vault_manager.migrate_vault_hmac_to_share2(_HWID)

    assert ilk == "migrated"
    assert ikinci == "already_new"


def test_migration_noop_for_already_new_vault(vault_dizini, db) -> None:
    """create_vault() zaten yeni şemayla imzalıyor — migration'ın yapacak işi yok."""
    create_vault(_HWID, _PIN, _ROLE)
    assert vault_manager.migrate_vault_hmac_to_share2(_HWID) == "already_new"


def test_migration_does_not_touch_genuinely_corrupt_vault(vault_dizini, db) -> None:
    """
    Ne eski ne yeni şemayla doğrulanan bir dosya (gerçekten bozuk/kurcalanmış)
    migration tarafından "düzeltilmemeli" — sessizce yeniden imzalamak,
    gerçek bir kurcalamayı gizlerdi. O karar bütünlük taramasına bırakılır.
    """
    create_vault(_HWID, _PIN, _ROLE)
    path = _vault_path(_HWID)
    once = path.read_bytes()
    # Trailer'ı sabit baytlarla değiştir — ne yeni ne eski anahtarla eşleşir
    bozuk = once[: -vault_manager._HMAC_SIZE] + b"\x00" * vault_manager._HMAC_SIZE
    with vault_manager._writable(path):
        path.write_bytes(bozuk)

    sonuc = vault_manager.migrate_vault_hmac_to_share2(_HWID)

    assert sonuc == "skipped_unverifiable"
    assert path.read_bytes() == bozuk, "dosyaya dokunulmamalıydı"


def test_migration_skips_hwid_without_vault_file(db) -> None:
    assert vault_manager.migrate_vault_hmac_to_share2("HIC-VAULT-YOK") == "skipped_no_vault"


def test_migration_skips_when_share_2_missing(vault_dizini, db) -> None:
    """
    share_2 kasada yoksa (USB kaydı silinmiş/migration hiç çalışmamış)
    migration atlanmalı — dosyaya dokunmamalı, hata fırlatmamalı.
    """
    create_vault(_HWID, _PIN, _ROLE)
    vault_manager.delete_usb_token(_HWID)  # share_2'yi kasadan siler

    assert vault_manager.migrate_vault_hmac_to_share2(_HWID) == "skipped_no_share_2"
