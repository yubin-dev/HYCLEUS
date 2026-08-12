"""
CORE.secret_migration — düz metin sırların anahtar kasasına taşınması.

Gerçek SQLite dosyası, gerçek keyring API'si (bellek içi arka uçla) kullanılır.
Migration mantığı mock'lanmaz; yalnızca kasa arka ucu değiştirilir.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from CORE import secret_migration, secret_store
from CORE.secret_store import KeyringUnavailableError

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
    assert report.to_version == secret_migration.SCHEMA_SHARE_2

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
    assert secret_migration.get_schema_version(db) == secret_migration.SCHEMA_SHARE_2


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
