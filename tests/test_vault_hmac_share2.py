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
from CORE.vault_manager import (
    VaultTamperedError,
    create_vault,
    export_recovery_share,
    recover_master_key,
    reprovision_vault,
    verify_vault,
)

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


# ── Adversarial: share_2-siz kurtarma yolunda AAD-dışı alan (token_id) ────────
#
# _rewrite_vault() outer HMAC'ı `protected` üzerinden hesaplıyor —
# magic + version + salt + nonce + token_id + ciphertext + gcm_tag (bkz.
# CORE/vault_manager.py::create_vault, `protected = (...)` satırı). GCM'in
# KENDİ AAD'ı yalnızca hwid'dir (`authenticate_additional_data(hwid.encode())`)
# — token_id GCM'in kapsamı DIŞINDA, salt/nonce'un aksine yanlış olduklarında
# GCM'i de bozmuyor (token_id şifre çözmeye hiç girmiyor). Yani token_id'nin
# TEK koruması outer HMAC.
#
# _decrypt_vault() share_2 yokken (recover_master_key'in "share_2 kayıp, PIN
# + share_1 + kurtarma parçası" dalı) outer HMAC kontrolünü ATLIYOR — bu
# testler o atlamanın token_id'yi GERÇEKTEN korumasız bıraktığını VE bunun
# bu akışta sömürülebilir bir sonucu olmadığını (SECURITY.md §4.2'deki
# gerekçe) kanıtlıyor: recover_master_key token_id'yi hiç okumuyor/kullanmıyor
# ve hemen ardından gelen reprovision_vault() dosyayı zaten TAMAMEN yeniden
# yazıyor (taze token_id dahil).

def test_tampered_token_id_is_not_read_by_share2_less_recovery(vault_dizini, db) -> None:
    """
    ASIL SORU: token_id kurcalandığında share_2-siz kurtarma reddediliyor mu?

    Ampirik cevap: HAYIR — kurtarma token_id'yi hiç okumuyor, bu yüzden
    doğru master_key'i üretmeye devam ediyor. Bu, "sessizce atlama" değil;
    SECURITY.md §4.2 bu davranışı ve neden zararsız olduğunu açıkça
    belgeliyor. Bu test o belgelenen gerçeği koda bağlıyor: biri ileride
    _decrypt_vault'a token_id okuma/GÜVENME ekler de bu testi fark etmezse,
    aşağıdaki `master_key == orijinal` doğrulaması hâlâ geçer ama en azından
    davranış burada sabitlenmiş olur.
    """
    master_key = bytes(range(32))  # sabit, tanınabilir bir anahtar
    create_vault(_HWID, _PIN, _ROLE, master_key=master_key)
    recovery_share = export_recovery_share(_HWID, _PIN)  # share_2 hâlâ kasadayken

    path = _vault_path(_HWID)
    raw = bytearray(path.read_bytes())
    offset = vault_manager._TOKEN_ID_OFFSET
    once_token_id = bytes(raw[offset : offset + vault_manager._TOKEN_ID_SIZE])
    raw[offset] ^= 0xFF  # token_id içinde tek bir bit çevir
    with vault_manager._writable(path):
        path.write_bytes(bytes(raw))

    vault_manager.delete_usb_token(_HWID)  # share_2 kaybı simülasyonu

    kurtarilan = recover_master_key(_HWID, recovery_share=recovery_share, pin=_PIN)

    assert kurtarilan == master_key, (
        "kurtarma token_id kurcalamasından ETKİLENMEMELİ — Shamir matematiği "
        "token_id'yi hiç kullanmıyor (bkz. SECURITY.md §4.2)"
    )
    # Kurcalanan değer dosyada hâlâ duruyor — kurtarma onu OKUMADIĞI için,
    # SİLMEDİĞİ için de değil.
    guncel = path.read_bytes()[offset : offset + vault_manager._TOKEN_ID_SIZE]
    assert guncel != once_token_id


def test_tampered_token_id_does_not_survive_reprovisioning(vault_dizini, db) -> None:
    """
    Kurtarmanın ASIL akışı (recover_vault.py --recover) recover_master_key'i
    HEP reprovision_vault() izler. Bu test o adımın kurcalanan token_id'yi
    KALICI OLARAK sildiğini kanıtlıyor — token_id'nin korumasız kalması yalnızca
    reprovisioning'e kadar süren, geçici bir pencere.
    """
    master_key = bytes(range(32))
    create_vault(_HWID, _PIN, _ROLE, master_key=master_key)
    recovery_share = export_recovery_share(_HWID, _PIN)

    path = _vault_path(_HWID)
    raw = bytearray(path.read_bytes())
    offset = vault_manager._TOKEN_ID_OFFSET
    raw[offset] ^= 0xFF
    with vault_manager._writable(path):
        path.write_bytes(bytes(raw))
    tampered_token_id = path.read_bytes()[offset : offset + vault_manager._TOKEN_ID_SIZE]

    vault_manager.delete_usb_token(_HWID)
    kurtarilan = recover_master_key(_HWID, recovery_share=recovery_share, pin=_PIN)

    reprovision_vault(
        _HWID, "yeni-pin-789", _ROLE,
        master_key=kurtarilan, recovery_share=recovery_share,
    )

    yeni_token_id = path.read_bytes()[offset : offset + vault_manager._TOKEN_ID_SIZE]
    assert yeni_token_id != tampered_token_id, "kurcalanan token_id reprovision sonrası hâlâ duruyor"
    verify_vault(_HWID)  # taze share_2 + taze outer HMAC — istisna atmamalı
