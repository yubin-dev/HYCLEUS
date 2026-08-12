"""
CORE.recover_vault — kurtarma CLI akışı.

CLI fonksiyonları gerçek vault üzerinde, girdi/parola istemleri
monkeypatch'lenerek çalıştırılır.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from CORE import recover_vault, vault_manager
from CORE.recovery_share import decode_share
from CORE.vault_manager import create_vault, export_recovery_share, open_vault

_HWID = "USB-CLI-TEST"
_PIN = "cli-pin-4567"
_ROLE = "Yönetici"


@pytest.fixture
def vault(db, tmp_path: Path, monkeypatch) -> str:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    monkeypatch.setattr(recover_vault, "get_usb_hwid", lambda: _HWID)
    create_vault(_HWID, _PIN, _ROLE)
    return _HWID


def _args(**kw):
    return type("Args", (), {"qr_out": None, **kw})()


# ── --status ──────────────────────────────────────────────────────────────────

def test_status_warns_when_recovery_share_missing(vault, db, capsys) -> None:
    """Kurtarma parçası alınmamışsa açıkça uyarmalı — sessiz 2-of-2 olmaz."""
    recover_vault._cmd_status(_args())

    cikti = capsys.readouterr().out
    assert "ALINMAMIS" in cikti
    assert "2-of-2" in cikti
    assert "recover_vault.py --export" in cikti


def test_status_reports_when_share_was_issued(vault, db, capsys) -> None:
    export_recovery_share(vault, _PIN)

    recover_vault._cmd_status(_args())

    cikti = capsys.readouterr().out
    assert "ALINMIS" in cikti
    assert "2-of-2" not in cikti


# ── --export ──────────────────────────────────────────────────────────────────

def test_export_shows_warning_and_share(vault, db, capsys, monkeypatch) -> None:
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: _PIN)

    recover_vault._cmd_export(_args())

    cikti = capsys.readouterr().out
    assert "HYCLEUS-R3-" in cikti
    assert "FİZİKSEL" in cikti
    assert "DİJİTAL OLARAK SAKLAMAYIN" in cikti
    # Gösterilen metin gerçekten geçerli bir pay olmalı
    satir = next(s for s in cikti.splitlines() if "HYCLEUS-R3-" in s and ":" not in s)
    assert decode_share(satir.strip()).startswith("3:")


def test_export_writes_nothing_by_default(vault, db, capsys, monkeypatch, tmp_path) -> None:
    """
    Varsayılan davranış hiçbir şeyi diske yazmamak.

    QR yalnızca kullanıcı --qr-out ile açıkça istediğinde yazılır.
    """
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: _PIN)
    onceki = {p for p in tmp_path.rglob("*") if p.is_file()}

    recover_vault._cmd_export(_args())

    yeni = {p for p in tmp_path.rglob("*") if p.is_file()} - onceki
    assert not yeni, f"beklenmeyen dosya yazıldı: {yeni}"
    assert "--qr-out" in capsys.readouterr().out


def test_export_writes_qr_only_when_asked(vault, db, capsys, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: _PIN)
    hedef = tmp_path / "kurtarma_qr.svg"

    recover_vault._cmd_export(_args(qr_out=str(hedef)))

    assert hedef.exists()
    assert "<svg" in hedef.read_text(encoding="utf-8")
    # Kullanıcıya dosyayı silmesi söylenmeli
    assert "silin" in capsys.readouterr().out


def test_export_aborts_on_wrong_pin(vault, db, monkeypatch) -> None:
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: "yanlis-pin")

    with pytest.raises(SystemExit):
        recover_vault._cmd_export(_args())


# ── --recover ─────────────────────────────────────────────────────────────────

def test_recover_with_vault_and_pin(vault, db, capsys, monkeypatch) -> None:
    """Seçenek 1: vault duruyor, PIN biliniyor (share_2 kayıp)."""
    import hashlib

    from CORE.recovery_share import encode_share

    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)

    yanitlar = iter([encode_share(share_3), _PIN])
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: next(yanitlar))
    monkeypatch.setattr("builtins.input", lambda *_a: "1")

    recover_vault._cmd_recover(_args())

    cikti = capsys.readouterr().out
    assert "MASTER KEY KURTARILDI" in cikti
    # Anahtarın kendisi değil yalnızca özeti gösterilmeli
    assert beklenen.hex() not in cikti
    assert hashlib.sha256(beklenen).hexdigest() in cikti


def test_recover_without_pin_uses_keyring_share(vault, db, capsys, monkeypatch) -> None:
    """Seçenek 2: vault dosyası yok, share_2 kasadan okunur."""
    import hashlib

    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)

    from CORE.recovery_share import encode_share

    vault_dosyasi = vault_manager._read_vault_path(vault)
    vault_manager._clear_readonly(vault_dosyasi)
    vault_dosyasi.unlink()

    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: encode_share(share_3))
    monkeypatch.setattr("builtins.input", lambda *_a: "2")

    recover_vault._cmd_recover(_args())

    assert hashlib.sha256(beklenen).hexdigest() in capsys.readouterr().out


def test_recover_aborts_on_malformed_share(vault, db, monkeypatch) -> None:
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: "tamamen-bozuk")

    with pytest.raises(SystemExit):
        recover_vault._cmd_recover(_args())


def test_recover_aborts_on_foreign_share(vault, db, capsys, monkeypatch) -> None:
    """Başka bir vault'un parçası ya reddedilmeli ya da doğru anahtarı vermemeli."""
    import hashlib

    from CORE.recovery_share import encode_share

    _role, beklenen = open_vault(vault, _PIN)
    _b1, _b2, yabanci = vault_manager._sss_split(b"\x3c" * 32)

    yanitlar = iter([encode_share(yabanci), _PIN])
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: next(yanitlar))
    monkeypatch.setattr("builtins.input", lambda *_a: "1")

    try:
        recover_vault._cmd_recover(_args())
    except SystemExit:
        return  # net hata — kabul edilebilir sonuç

    # Hata vermediyse en azından DOĞRU anahtarı üretmemiş olmalı
    cikti = capsys.readouterr().out
    assert hashlib.sha256(beklenen).hexdigest() not in cikti, (
        "yabancı kurtarma parçası doğru master_key'i üretti"
    )
