"""
CORE.vault_manager — share_2'nin anahtar kasası entegrasyonu.

Migration sonrası davranışı sınar: yazma kasaya gider, okuma kasadan gelir,
silme iki kaynağı birlikte temizler ve DB'ye ASLA geri düşülmez.
"""
from __future__ import annotations

import pytest

from CORE import secret_store, vault_manager
from CORE.secret_store import KeyringUnavailableError

from conftest import BrokenKeyring

_HWID = "USB-VAULT-TEST"
_SHARE_2 = "2:" + "c3" * 33
_TOKEN_ID = "0123456789abcdef"


def test_save_usb_token_writes_to_keyring_not_db(db, fake_keyring) -> None:
    """share_2 kasaya gitmeli; DB sütunu boş kalmalı."""
    vault_manager._save_usb_token(_HWID, _SHARE_2, _TOKEN_ID)

    assert fake_keyring.store[("HYCLEUS", f"share_2:{_HWID}")] == _SHARE_2

    row = db.fetchone("SELECT share_2, token_id FROM usb_tokens WHERE hwid = ?", (_HWID,))
    assert row is not None
    assert row["share_2"] == "", "share_2 DB'ye düz metin yazılmış"
    assert row["token_id"] == _TOKEN_ID

    # Ham DB baytlarında da bulunmamalı
    db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    assert _SHARE_2.encode() not in db._db_path.read_bytes()


def test_load_share_2_round_trip(db) -> None:
    vault_manager._save_usb_token(_HWID, _SHARE_2, _TOKEN_ID)
    assert vault_manager._load_share_2(_HWID) == _SHARE_2


def test_load_share_2_does_not_fall_back_to_db(db) -> None:
    """
    Kasada kayıt yokken DB'de düz metin DURUYORSA bile okunmamalı.

    Sessiz geri düşüş migration'ın amacını yok eder: sır düz metin olarak
    kullanılmaya devam eder ve kimse fark etmez.
    """
    db.execute(
        "INSERT INTO usb_tokens (hwid, share_2, token_id) VALUES (?, ?, ?)",
        (_HWID, _SHARE_2, _TOKEN_ID),
    )
    assert secret_store.load(secret_store.share_2_username(_HWID)) is None

    with pytest.raises(ValueError, match="anahtar kasasında bulunamadı"):
        vault_manager._load_share_2(_HWID)


def test_save_usb_token_does_not_touch_db_when_keyring_fails(db, use_keyring_backend) -> None:
    """Kasaya yazılamazsa DB'ye yarım kayıt düşmemeli."""
    use_keyring_backend(BrokenKeyring())

    with pytest.raises(KeyringUnavailableError):
        vault_manager._save_usb_token(_HWID, _SHARE_2, _TOKEN_ID)

    assert db.fetchone("SELECT hwid FROM usb_tokens WHERE hwid = ?", (_HWID,)) is None


def test_delete_usb_token_clears_both_sources(db, fake_keyring) -> None:
    """Silme hem DB satırını hem kasadaki sırrı kaldırmalı — yetim sır kalmasın."""
    vault_manager._save_usb_token(_HWID, _SHARE_2, _TOKEN_ID)

    vault_manager.delete_usb_token(_HWID)

    assert db.fetchone("SELECT hwid FROM usb_tokens WHERE hwid = ?", (_HWID,)) is None
    assert secret_store.load(secret_store.share_2_username(_HWID)) is None
    assert ("HYCLEUS", f"share_2:{_HWID}") not in fake_keyring.store


def test_two_usb_devices_keep_separate_shares(db, fake_keyring) -> None:
    """HWID ile anahtarlama sayesinde ikinci USB birincinin payını ezmemeli."""
    share_a = "2:" + "aa" * 33
    share_b = "2:" + "bb" * 33

    vault_manager._save_usb_token("USB-1", share_a, "tok1")
    vault_manager._save_usb_token("USB-2", share_b, "tok2")

    assert vault_manager._load_share_2("USB-1") == share_a
    assert vault_manager._load_share_2("USB-2") == share_b

    # Birini silmek diğerini etkilememeli
    vault_manager.delete_usb_token("USB-1")
    assert vault_manager._load_share_2("USB-2") == share_b
