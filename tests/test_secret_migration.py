"""
CORE.secret_migration — düz metin sırların anahtar kasasına taşınması.

Gerçek SQLite dosyası, gerçek keyring API'si (bellek içi arka uçla) kullanılır.
Migration mantığı mock'lanmaz; yalnızca kasa arka ucu değiştirilir.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from CORE import secret_migration, secret_store, vault_manager
from CORE.secret_migration import MigrationError
from CORE.secret_store import KeyringUnavailableError
from CORE.vault_manager import VaultTamperedError, create_vault, verify_vault

from conftest import BrokenKeyring, SilentlyFailingKeyring

_HWID_A = "USB-AAA-111"
_HWID_B = "USB-BBB-222"
_SHARE_A = "2:" + "a1" * 33
_SHARE_B = "2:" + "b2" * 33


def _seed_legacy_token(db, hwid: str, share_2: str, token_id: str = "tok") -> None:
    """Migration ÖNCESİ hâli kurar — share_2 düz metin olarak DB'de."""
    db.execute(
        "INSERT OR REPLACE INTO usb_tokens (hwid, share_2, token_id) VALUES (?, ?, ?)",
        (hwid, share_2, token_id),
    )


def _db_share_2(db, hwid: str) -> str | None:
    row = db.fetchone("SELECT share_2 FROM usb_tokens WHERE hwid = ?", (hwid,))
    return None if row is None else row["share_2"]


def _all_db_bytes(db) -> bytes:
    """Ana DB dosyası + WAL + SHM ham baytları — düz metin kalıntısı taraması için."""
    base = Path(db._db_path)
    blob = b""
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(base) + suffix)
        if p.exists():
            blob += p.read_bytes()
    return blob


# ── Şema versiyonu ────────────────────────────────────────────────────────────

def test_fresh_db_starts_at_version_zero(db) -> None:
    assert secret_migration.get_schema_version(db) == 0


def test_set_schema_version_rejects_invalid(db) -> None:
    with pytest.raises(ValueError):
        secret_migration.set_schema_version(db, -1)
    with pytest.raises(ValueError):
        secret_migration.set_schema_version(db, "1; DROP TABLE users")  # type: ignore[arg-type]


# ── share_2 round-trip ────────────────────────────────────────────────────────

def test_share_2_migration_round_trip(db, fake_keyring) -> None:
    """Taşı → oku → orijinal share_2 ile birebir eşleşmeli."""
    _seed_legacy_token(db, _HWID_A, _SHARE_A)
    _seed_legacy_token(db, _HWID_B, _SHARE_B)

    report = secret_migration.run_migrations(db)

    assert report.ran is True
    assert report.share_2_migrated == 2
    assert report.to_version == secret_migration.CURRENT_SCHEMA_VERSION

    # Kasadan okunan değer orijinalle aynı olmalı
    assert secret_store.load(secret_store.share_2_username(_HWID_A)) == _SHARE_A
    assert secret_store.load(secret_store.share_2_username(_HWID_B)) == _SHARE_B

    # Kasa kaydı HWID ile anahtarlanmış — iki USB birbirini ezmemiş
    assert fake_keyring.store[("HYCLEUS", f"share_2:{_HWID_A}")] == _SHARE_A
    assert fake_keyring.store[("HYCLEUS", f"share_2:{_HWID_B}")] == _SHARE_B


def test_share_2_migration_leaves_no_plaintext_in_db(db) -> None:
    """Migration sonrası ham DB baytlarında (WAL dahil) düz metin kalmamalı."""
    _seed_legacy_token(db, _HWID_A, _SHARE_A)

    # Ön koşul: migration öncesi düz metin GERÇEKTEN dosyada olmalı,
    # yoksa test boşuna geçer
    db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    assert _SHARE_A.encode() in _all_db_bytes(db), "test kurulumu hatalı: düz metin yazılmamış"

    secret_migration.run_migrations(db)

    assert _SHARE_A.encode() not in _all_db_bytes(db), "DB dosyasında düz metin kalıntısı var"
    assert _db_share_2(db, _HWID_A) == ""


def test_share_2_migration_keeps_the_row(db) -> None:
    """Satır silinmemeli — HWID kaydı, token_id ve blacklisted ona bağlı."""
    _seed_legacy_token(db, _HWID_A, _SHARE_A, token_id="tok-abc")

    secret_migration.run_migrations(db)

    row = db.fetchone("SELECT * FROM usb_tokens WHERE hwid = ?", (_HWID_A,))
    assert row is not None, "usb_tokens satırı silinmiş — USB kimlik doğrulaması bozulur"
    assert row["token_id"] == "tok-abc"
    assert row["blacklisted"] == 0


# ── İdempotanlık / versiyon kapısı ────────────────────────────────────────────

def test_migration_does_not_run_twice(db) -> None:
    _seed_legacy_token(db, _HWID_A, _SHARE_A)

    first = secret_migration.run_migrations(db)
    assert first.ran is True and first.share_2_migrated == 1

    second = secret_migration.run_migrations(db)
    assert second.ran is False, "tamamlanmış migration tekrar çalışmamalı"
    assert second.share_2_migrated == 0

    # Sır hâlâ yerinde
    assert secret_store.load(secret_store.share_2_username(_HWID_A)) == _SHARE_A


def test_interrupted_migration_is_safe_to_rerun(db, fake_keyring) -> None:
    """
    Kasaya yazıldı ama versiyon yükseltilmeden çökme senaryosu.

    Yeniden çalıştırıldığında sır kaybolmamalı ve DB temiz kalmalı.
    """
    _seed_legacy_token(db, _HWID_A, _SHARE_A)
    report = secret_migration.MigrationReport()
    secret_migration.migrate_share_2(db, report)
    assert secret_migration.get_schema_version(db) == 0  # versiyon yükselmedi

    rerun = secret_migration.run_migrations(db)

    assert rerun.ran is True
    assert secret_store.load(secret_store.share_2_username(_HWID_A)) == _SHARE_A
    assert _db_share_2(db, _HWID_A) == ""


def test_migration_with_no_tokens_is_noop(db) -> None:
    report = secret_migration.run_migrations(db)
    assert report.ran is True
    assert report.share_2_migrated == 0
    assert secret_migration.get_schema_version(db) == secret_migration.CURRENT_SCHEMA_VERSION


# ── Kasa erişilemez: sessizce eski davranışa DÜŞMEMELİ ────────────────────────

def test_migration_refuses_when_keyring_unavailable(db, use_keyring_backend) -> None:
    """
    Kasa yoksa migration hiç başlamamalı ve DB'ye DOKUNMAMALI.

    Düz metin yerinde kalmalı — silinip sır kaybedilmemeli — ama uygulama da
    açılmamalı (main.py bu istisnayı yakalayıp sys.exit(1) yapıyor).
    """
    _seed_legacy_token(db, _HWID_A, _SHARE_A)
    use_keyring_backend(BrokenKeyring())

    with pytest.raises(KeyringUnavailableError):
        secret_migration.run_migrations(db)

    # DB'ye dokunulmamış olmalı — sır kaybı olmasın
    assert _db_share_2(db, _HWID_A) == _SHARE_A
    assert secret_migration.get_schema_version(db) == 0


def test_migration_aborts_when_keyring_silently_drops_write(db, use_keyring_backend) -> None:
    """
    Kasa yazmayı kabul edip saklamıyorsa DB temizlenmemeli.

    Aksi halde sır hem kasada hem DB'de olmaz — kalıcı veri kaybı.
    """
    _seed_legacy_token(db, _HWID_A, _SHARE_A)
    use_keyring_backend(SilentlyFailingKeyring())

    with pytest.raises(KeyringUnavailableError):
        secret_migration.run_migrations(db)

    assert _db_share_2(db, _HWID_A) == _SHARE_A, "yazma doğrulanmadan DB temizlenmiş — sır kaybı"
    assert secret_migration.get_schema_version(db) == 0


# ── TOTP migration ────────────────────────────────────────────────────────────

_TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def _write_legacy_totp(tmp_path: Path, secret: str = _TOTP_SECRET) -> Path:
    path = tmp_path / "totp_secret.json"
    path.write_text(json.dumps({"secret": secret}), encoding="utf-8")
    return path


def test_totp_migration_round_trip(tmp_path: Path) -> None:
    """Taşı → kasadan oku → orijinal TOTP sırrı ile eşleşmeli."""
    path = _write_legacy_totp(tmp_path)

    moved = secret_migration.migrate_totp_secret(path)

    assert moved == _TOTP_SECRET
    assert secret_store.load_totp_secret() == _TOTP_SECRET


def test_totp_migration_shreds_the_file(tmp_path: Path) -> None:
    """Dosya silinmeli ve içindeki sır diskte kalmamalı."""
    path = _write_legacy_totp(tmp_path)
    assert _TOTP_SECRET.encode() in path.read_bytes()  # ön koşul

    secret_migration.migrate_totp_secret(path)

    assert not path.exists(), "totp_secret.json silinmemiş"
    # Aynı dizinde sırrı içeren başka bir kalıntı da olmamalı
    for leftover in tmp_path.rglob("*"):
        if leftover.is_file():
            assert _TOTP_SECRET.encode() not in leftover.read_bytes(), f"kalıntı: {leftover}"


def test_totp_migration_is_idempotent(tmp_path: Path) -> None:
    path = _write_legacy_totp(tmp_path)
    secret_migration.migrate_totp_secret(path)

    # İkinci çağrı: dosya yok, sır kasada duruyor
    assert secret_migration.migrate_totp_secret(path) is None
    assert secret_store.load_totp_secret() == _TOTP_SECRET


def test_totp_migration_keeps_file_when_keyring_write_fails(
    tmp_path: Path, use_keyring_backend
) -> None:
    """Kasaya yazılamazsa dosya İMHA EDİLMEMELİ — yoksa TOTP kalıcı kaybolur."""
    path = _write_legacy_totp(tmp_path)
    use_keyring_backend(SilentlyFailingKeyring())

    with pytest.raises(KeyringUnavailableError):
        secret_migration.migrate_totp_secret(path)

    assert path.exists(), "kasaya yazılamadı ama dosya silinmiş — TOTP sırrı kayboldu"
    assert json.loads(path.read_text(encoding="utf-8"))["secret"] == _TOTP_SECRET


def test_totp_migration_rejects_corrupt_file(tmp_path: Path) -> None:
    """Bozuk dosya silinmemeli — elle kurtarma şansı bırakılmalı."""
    path = tmp_path / "totp_secret.json"
    path.write_text("{bozuk json", encoding="utf-8")

    with pytest.raises(MigrationError):
        secret_migration.migrate_totp_secret(path)

    assert path.exists(), "bozuk dosya silinmemeli"


def test_totp_migration_missing_file_is_noop(tmp_path: Path) -> None:
    assert secret_migration.migrate_totp_secret(tmp_path / "yok.json") is None


# ── Vault HMAC migration (SECURITY.md §4.2) ────────────────────────────────────
#
# CORE.vault_manager.migrate_vault_hmac_to_share2() taşıyor bu satırı;
# ayrıntılı testleri tests/test_vault_hmac_share2.py'de. Burada yalnızca
# run_migrations()'ın onu doğru şema adımında ÇAĞIRDIĞINI ve gerçek bir
# dosyayı gerçekten yeniden imzaladığını doğruluyoruz.

_HWID_VAULT = "USB-HMAC-MIG-INTEGRATION"
_PIN_VAULT = "gizli-pin-789"


@pytest.fixture
def vault_dizini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / "legacy.hclv")
    return tmp_path


def _resign_with_legacy_scheme(hwid: str) -> None:
    """"Üretimde kalmış eski vault" simülasyonu — bkz. test_vault_hmac_share2.py."""
    path = vault_manager._read_vault_path(hwid)
    raw = path.read_bytes()
    protected = raw[: -vault_manager._HMAC_SIZE]
    eski_imza = vault_manager._sign(
        vault_manager._derive_signing_key_legacy_hwid(hwid), protected
    )
    with vault_manager._writable(path):
        path.write_bytes(protected + eski_imza)


def test_run_migrations_resigns_legacy_vault_hmac(db, vault_dizini) -> None:
    """
    Eski şemayla imzalanmış GERÇEK bir vault dosyası, run_migrations()
    çağrıldıktan sonra yeni share_2-bazlı şemayla doğrulanmalı.
    """
    create_vault(_HWID_VAULT, _PIN_VAULT, "Standart")
    _resign_with_legacy_scheme(_HWID_VAULT)

    with pytest.raises(VaultTamperedError):
        verify_vault(_HWID_VAULT)  # ön koşul: migration öncesi geçmiyor

    rapor = secret_migration.run_migrations(db)

    assert rapor.vault_hmac_migrated == 1
    assert rapor.to_version == secret_migration.CURRENT_SCHEMA_VERSION
    verify_vault(_HWID_VAULT)  # artık istisna atmamalı


def test_run_migrations_vault_hmac_step_is_idempotent(db, vault_dizini) -> None:
    create_vault(_HWID_VAULT, _PIN_VAULT, "Standart")
    _resign_with_legacy_scheme(_HWID_VAULT)

    ilk = secret_migration.run_migrations(db)
    assert ilk.vault_hmac_migrated == 1

    # Şema versiyonu zaten güncel — ikinci çağrı hiçbir adımı çalıştırmamalı
    ikinci = secret_migration.run_migrations(db)
    assert ikinci.ran is False
    assert ikinci.vault_hmac_migrated == 0
    verify_vault(_HWID_VAULT)


def test_run_migrations_vault_hmac_step_noop_for_new_vault(db, vault_dizini) -> None:
    """create_vault() zaten yeni şemayla imzalıyor — migration'ın taşıyacak bir şeyi yok."""
    create_vault(_HWID_VAULT, _PIN_VAULT, "Standart")

    rapor = secret_migration.run_migrations(db)

    assert rapor.vault_hmac_migrated == 0
    assert rapor.vault_hmac_already_new == 1
    verify_vault(_HWID_VAULT)


# ── Uçtan uca: iki migration birlikte ─────────────────────────────────────────

def test_run_migrations_reaches_current_version(db, monkeypatch, tmp_path: Path) -> None:
    """share_2 + TOTP + TOTP-per-HWID (B-059) birlikte şemayı güncel versiyona getirmeli."""
    _seed_legacy_token(db, _HWID_A, _SHARE_A)
    totp_path = _write_legacy_totp(tmp_path)
    monkeypatch.setattr(secret_migration, "_TOTP_FILE", totp_path)
    # B-059 (v2→v3) global TOTP sırrını EN ESKİ onaylı kullanıcının HWID'ine
    # devrediyor — bu satır olmadan devredilecek kimse yok, sır kasadan
    # SİLİNİR (bkz. test_totp_per_hwid_step_below). Uçtan uca "her şey
    # erişilebilir kalıyor" senaryosu için _HWID_A'yı onaylı yapıyoruz.
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid) "
        "VALUES ('gonderen', '!x', 'admin', 'approved', ?)",
        (_HWID_A,),
    )

    report = secret_migration.run_migrations(db)

    assert report.ran is True
    assert report.share_2_migrated == 1
    assert report.totp_migrated is True
    assert report.totp_per_hwid_migrated_to == _HWID_A
    assert report.to_version == secret_migration.CURRENT_SCHEMA_VERSION
    assert secret_migration.get_schema_version(db) == secret_migration.CURRENT_SCHEMA_VERSION

    # share_2 kasadan okunabilir, orijinaliyle aynı
    assert secret_store.load(secret_store.share_2_username(_HWID_A)) == _SHARE_A
    # TOTP artık HWID başına (B-059) — eski GLOBAL okuma artık boş.
    assert secret_store.load_totp_secret() is None
    assert secret_store.load_totp_secret_for_hwid(_HWID_A) == _TOTP_SECRET

    # Her iki eski konum da temiz
    assert _db_share_2(db, _HWID_A) == ""
    assert not totp_path.exists()
    assert _SHARE_A.encode() not in _all_db_bytes(db)

    # Tekrar çalıştırılırsa hiçbir şey yapmamalı
    assert secret_migration.run_migrations(db).ran is False
