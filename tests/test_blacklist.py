"""
CORE.vault_manager — kara liste kontrolü.

Gerçek vault oluşturulup gerçek open_vault() ile açılır (Argon2id dahil);
yalnızca vault dizini tmp_path'e yönlendirilir.

Geçmiş: kara liste yalnızca authenticate_usb() içinde kontrol ediliyordu,
oysa giriş ekranı open_vault()'u doğrudan çağırıyor — kara listedeki bir USB
geçerli PIN'le vault'u açabiliyordu (SECURITY.md §4.1). Bu testler iki giriş
yolunun da aynı kontrolden geçtiğini garanti eder.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from CORE import vault_manager
from CORE.vault_manager import (
    USBAuthError,
    blacklist_usb,
    create_vault,
    open_vault,
    read_vault_role,
)

_HWID = "USB-BL-TEST"
_PIN = "gizli-pin-123"
_ROLE = "Yönetici"


@pytest.fixture
def vault(db, tmp_path: Path, monkeypatch) -> str:
    """tmp_path içinde gerçek bir vault oluşturur ve HWID'i döndürür."""
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    create_vault(_HWID, _PIN, _ROLE)
    return _HWID


def _unblacklist(db, hwid: str) -> None:
    """AdminPanel'in 'Kara Listeden Çıkar' işlemiyle aynı SQL."""
    db.execute("UPDATE usb_tokens SET blacklisted = 0 WHERE hwid = ?", (hwid,))


# ── Temel davranış ────────────────────────────────────────────────────────────

def test_vault_opens_normally_before_blacklisting(vault, db) -> None:
    """Ön koşul: kara listeye alınmadan önce açılabiliyor olmalı."""
    role, master_key = open_vault(vault, _PIN)
    assert role == _ROLE
    assert len(master_key) == 32


def test_blacklisted_usb_cannot_open_vault(vault, db) -> None:
    """
    ASIL DÜZELTME: kara listedeki USB, DOĞRU PIN ile bile açamamalı.

    Bu test düzeltmeden önce başarısız olurdu — open_vault kara listeye
    hiç bakmıyordu.
    """
    blacklist_usb(vault)

    with pytest.raises(USBAuthError, match="kara listede"):
        open_vault(vault, _PIN)


def test_blacklist_is_checked_before_pin_work(vault, db) -> None:
    """
    Kara liste kontrolü PIN'den ÖNCE gelmeli.

    Yanlış PIN'le bile USBAuthError gelmeli (ValueError değil): kontrol
    Argon2id maliyetine girmeden, en başta çalışıyor demektir.
    """
    blacklist_usb(vault)

    with pytest.raises(USBAuthError):
        open_vault(vault, "tamamen-yanlis-pin")


def test_unblacklisted_usb_can_open_again(vault, db) -> None:
    """Kara listeden çıkarılan USB tekrar açabilmeli."""
    blacklist_usb(vault)
    with pytest.raises(USBAuthError):
        open_vault(vault, _PIN)

    _unblacklist(db, vault)

    role, master_key = open_vault(vault, _PIN)
    assert role == _ROLE
    assert len(master_key) == 32


def test_master_key_is_identical_after_unblacklist(vault, db) -> None:
    """
    Kara liste bir İPTAL değil — paylar geçerliliğini korur.

    Çıkarıldıktan sonra kurtarılan master_key, kara listeye alınmadan
    öncekiyle birebir aynı olmalı. Bu, SECURITY.md §4.1'deki "idari işaret,
    iptal mekanizması değil" ifadesini koda bağlar.
    """
    _, before = open_vault(vault, _PIN)

    blacklist_usb(vault)
    _unblacklist(db, vault)

    _, after = open_vault(vault, _PIN)
    assert after == before, "paylar değişmiş — kara liste iptal gibi davranmış"


# ── İki giriş yolu da aynı kontrolden geçiyor ─────────────────────────────────

def test_both_entry_paths_reject_blacklisted_device(vault, db) -> None:
    """
    authenticate_usb (USB yeniden takma) ve open_vault (PIN girişi)
    aynı kontrolden geçmeli — biri açık kalırsa bypass geri gelir.
    """
    blacklist_usb(vault)

    with pytest.raises(USBAuthError, match="kara listede"):
        vault_manager.authenticate_usb(vault)

    with pytest.raises(USBAuthError, match="kara listede"):
        open_vault(vault, _PIN)


def test_read_vault_role_still_reachable_for_clean_device(vault, db) -> None:
    """Kara liste kontrolü temiz cihazın normal akışını bozmamalı."""
    assert read_vault_role(vault, _PIN) == _ROLE


# ── Yardımcının kendisi ───────────────────────────────────────────────────────

def test_helper_is_noop_for_unregistered_hwid(db) -> None:
    """
    Kayıtlı olmayan HWID burada reddedilmez — "kayıtlı değil" durumunu
    çağıranlar kendi mesajlarıyla ele alır.
    """
    vault_manager._reject_if_blacklisted("HIC-KAYITLI-DEGIL")  # istisna yok


def test_blacklist_rejection_is_audited(vault, db) -> None:
    blacklist_usb(vault)

    with pytest.raises(USBAuthError):
        open_vault(vault, _PIN)

    kayitlar = db.fetchall(
        "SELECT detail FROM audit_log WHERE action = 'usb_auth_rejected'"
    )
    assert len(kayitlar) == 1
    assert vault in kayitlar[0]["detail"]
    assert "kara listede" in kayitlar[0]["detail"]
