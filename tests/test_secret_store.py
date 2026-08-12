"""
CORE.secret_store + CORE.secure_erase — anahtar kasası sarmalayıcısı testleri.

keyring arka ucu bellek içi gerçek bir KeyringBackend ile değiştirilir
(conftest.InMemoryKeyring); secret_store kodu hiç değiştirilmeden normal
keyring API'si üzerinden çalışır.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from CORE import secret_store
from CORE.secret_store import SERVICE, KeyringUnavailableError
from CORE.secure_erase import overwrite_text_column, purge_sqlite_residue, shred_file

from conftest import BrokenKeyring, SilentlyFailingKeyring


# ── Adlandırma şeması ─────────────────────────────────────────────────────────

def test_share_2_username_is_keyed_by_hwid() -> None:
    """share_2 cihaz başına olduğundan kullanıcı adı HWID içermeli."""
    assert secret_store.share_2_username("USB-AAA") == "share_2:USB-AAA"
    assert secret_store.share_2_username("USB-BBB") == "share_2:USB-BBB"

    # İki farklı USB birbirinin payını ezmemeli
    assert secret_store.share_2_username("USB-AAA") != secret_store.share_2_username("USB-BBB")

    with pytest.raises(ValueError):
        secret_store.share_2_username("")


def test_totp_username_is_stable() -> None:
    """TOTP sırrı global olduğundan sabit ad kullanılır."""
    assert secret_store.TOTP_USERNAME == "totp_secret"
    assert SERVICE == "HYCLEUS"


# ── Temel round-trip ──────────────────────────────────────────────────────────

def test_store_load_erase_round_trip(fake_keyring) -> None:
    secret_store.store("deneme", "gizli-deger-123")
    assert secret_store.load("deneme") == "gizli-deger-123"
    assert fake_keyring.store[(SERVICE, "deneme")] == "gizli-deger-123"

    assert secret_store.erase("deneme") is True
    assert secret_store.load("deneme") is None

    # Zaten yok olan kaydı silmek hata değil
    assert secret_store.erase("deneme") is False


def test_load_missing_returns_none_not_error(fake_keyring) -> None:
    """Kayıt yokluğu ile kasa erişilemezliği karıştırılmamalı."""
    assert secret_store.load("hic-yazilmadi") is None


def test_ensure_available_passes_and_leaves_no_probe(fake_keyring) -> None:
    secret_store.ensure_available()
    probe_keys = [k for k in fake_keyring.store if "probe" in k[1]]
    assert probe_keys == [], f"sonda kaydı temizlenmemiş: {probe_keys}"


# ── Erişilemezlik: sessizce eski davranışa DÜŞMEMELİ ──────────────────────────

def test_ensure_available_raises_when_backend_missing(use_keyring_backend) -> None:
    """Başsız Linux / Secret Service yok senaryosu — açık hata fırlatmalı."""
    use_keyring_backend(BrokenKeyring())

    with pytest.raises(KeyringUnavailableError) as exc:
        secret_store.ensure_available()

    msg = str(exc.value)
    assert "anahtar kasası" in msg.lower() or "kasa" in msg.lower()
    assert "başlatılamaz" in msg, "kullanıcıya uygulamanın açılmayacağı söylenmeli"


def test_ensure_available_raises_when_write_is_silently_dropped(use_keyring_backend) -> None:
    """
    Kasa yazmayı kabul edip saklamıyorsa da reddedilmeli.

    İstisna fırlamadığı için en sinsi senaryo bu; yalnızca geri okuma yakalar.
    """
    use_keyring_backend(SilentlyFailingKeyring())

    with pytest.raises(KeyringUnavailableError, match="tutmadı|güvenilir değil"):
        secret_store.ensure_available()


def test_store_verifies_readback(use_keyring_backend) -> None:
    """store() yazdıktan sonra geri okumalı — sır sessizce kaybolmamalı."""
    use_keyring_backend(SilentlyFailingKeyring())

    with pytest.raises(KeyringUnavailableError, match="eşleşmedi"):
        secret_store.store("kayip", "deger")


@pytest.mark.parametrize("fn", ["load", "store", "erase"])
def test_all_operations_raise_on_broken_backend(use_keyring_backend, fn: str) -> None:
    """Hiçbir işlem sessizce None/False dönüp hatayı yutmamalı."""
    use_keyring_backend(BrokenKeyring())

    with pytest.raises(KeyringUnavailableError):
        if fn == "load":
            secret_store.load("x")
        elif fn == "store":
            secret_store.store("x", "y")
        else:
            secret_store.erase("x")


# ── secure_erase ──────────────────────────────────────────────────────────────

def test_overwrite_text_column_removes_plaintext_and_keeps_row(tmp_path: Path) -> None:
    """Sütun temizlenmeli ama satır (HWID, token_id) yerinde kalmalı."""
    db_path = tmp_path / "t.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("CREATE TABLE usb_tokens (hwid TEXT UNIQUE, share_2 TEXT NOT NULL, token_id TEXT)")
    secret = "2:" + "ab" * 33
    conn.execute(
        "INSERT INTO usb_tokens (hwid, share_2, token_id) VALUES (?, ?, ?)",
        ("HW-1", secret, "tok-1"),
    )
    conn.commit()

    overwrite_text_column(
        conn, table="usb_tokens", column="share_2",
        where_column="hwid", where_value="HW-1",
    )
    purge_sqlite_residue(conn)

    row = conn.execute("SELECT * FROM usb_tokens WHERE hwid = 'HW-1'").fetchone()
    assert row is not None, "satır silinmemeli — HWID kaydı ve token_id gerekli"
    assert row["share_2"] == ""
    assert row["token_id"] == "tok-1"
    conn.close()

    # Ham dosya baytlarında düz metin kalmamalı
    raw = db_path.read_bytes()
    assert secret.encode() not in raw
    for suffix in ("-wal", "-shm"):
        side = Path(str(db_path) + suffix)
        if side.exists():
            assert secret.encode() not in side.read_bytes()


def test_shred_file_overwrites_before_unlink(tmp_path: Path) -> None:
    target = tmp_path / "totp_secret.json"
    payload = '{"secret": "JBSWY3DPEHPK3PXP"}'
    target.write_text(payload, encoding="utf-8")

    assert shred_file(target) is True
    assert not target.exists()

    # Zaten yok olan dosya hata değil
    assert shred_file(target) is False


def test_shred_file_handles_empty_file(tmp_path: Path) -> None:
    target = tmp_path / "bos.json"
    target.touch()
    assert shred_file(target) is True
    assert not target.exists()
