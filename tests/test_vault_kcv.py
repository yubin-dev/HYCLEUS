"""
CORE.vault_manager — master_key anahtar doğrulama değeri (KCV, B-160).

KCV, kurtarma parçasından elde edilen anahtarın DOĞRU anahtar olup
olmadığını söyleyen tek yönlü değer. Bu dosya onun YAZILDIĞI yerleri
sınıyor: yeni kasa (`create_vault`) ve eski kasaların ilk başarılı
açılışı (`open_vault`, geriye dönük doldurma). Kurtarmada nasıl
KULLANILDIĞI tests/test_recovery_share.py ve tests/test_usb_takeover.py'de.

Gerçek vault, gerçek Argon2id/GCM ve bellek-içi keyring; mock yok.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from CORE import vault_manager
from CORE.vault_manager import create_vault, open_vault

_HWID = "USB-KCV-TEST"
_PIN = "kcvPIN-123456"


@pytest.fixture
def kasa(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    create_vault(_HWID, _PIN, "Yönetici")
    return _HWID


def _kcv_satiri(db, hwid: str) -> str | None:
    return db.fetchone("SELECT kcv FROM usb_tokens WHERE hwid = ?", (hwid,))["kcv"]


def test_usb_tokens_kcv_sutunu_var(db) -> None:
    sutunlar = {r["name"] for r in db.fetchall("PRAGMA table_info(usb_tokens)")}
    assert "kcv" in sutunlar


def test_create_vault_kasanin_GERCEK_anahtarinin_kcvsini_yaziyor(kasa, db) -> None:
    _rol, anahtar = open_vault(kasa, _PIN)
    assert _kcv_satiri(db, kasa) == vault_manager._kcv_hesapla(anahtar).hex()


def test_kcv_anahtarin_kendisi_degil(kasa, db) -> None:
    _rol, anahtar = open_vault(kasa, _PIN)
    assert bytes.fromhex(_kcv_satiri(db, kasa)) != anahtar


def test_open_vault_gocten_onceki_kasanin_kcvsini_dolduruyor(kasa, db) -> None:
    """Göç 29'dan önce kurulmuş kasa: kcv NULL. İlk başarılı açılış doldurur."""
    db.execute("UPDATE usb_tokens SET kcv = NULL WHERE hwid = ?", (kasa,))
    assert _kcv_satiri(db, kasa) is None

    _rol, anahtar = open_vault(kasa, _PIN)

    assert _kcv_satiri(db, kasa) == vault_manager._kcv_hesapla(anahtar).hex()


def test_open_vault_var_olan_kcvnin_UZERINE_YAZMAZ(kasa, db) -> None:
    """
    Geriye dönük doldurma yalnızca EKSİK olanı yazar. Var olan bir KCV'nin
    üzerine yazsaydı, bir hata yanlış bir KCV'yi sessizce "düzeltip"
    kurtarma kontrolünü anlamsızlaştırabilirdi.
    """
    db.execute("UPDATE usb_tokens SET kcv = ? WHERE hwid = ?", ("ab" * 32, kasa))

    open_vault(kasa, _PIN)

    assert _kcv_satiri(db, kasa) == "ab" * 32


def test_open_vault_kcv_yazamazsa_giris_yine_basarili(kasa, db, monkeypatch) -> None:
    """Geriye dönük doldurma best-effort: DB hatası girişi engellememeli."""
    db.execute("UPDATE usb_tokens SET kcv = NULL WHERE hwid = ?", (kasa,))

    def _patla(*_a, **_k):
        raise RuntimeError("DB yazılamıyor")

    monkeypatch.setattr(vault_manager, "_kcv_eksikse_yaz", _patla)
    rol, anahtar = open_vault(kasa, _PIN)
    assert rol == "Yönetici"
    assert len(anahtar) == 32
