"""
CORE.setup_usb — USB vault kurulum aracı (main()), doğrudan testler.

`main()` şimdiye kadar hiç doğrudan test edilmemişti (yalnızca `_prompt_pin()`
tests/test_pin_policy.py'de sınanıyordu). Burada iki güvenlik kapısı
hedefleniyor:

  · `--reset` — mevcut PIN doğrulanmadan reset reddedilmeli (sahiplik kanıtı).
    Aksi halde fiziksel USB'ye erişimi olan ama PIN'i bilmeyen biri, USB'yi
    sıfırlayıp KENDİ PIN'iyle yeniden kurabilirdi.
  · Normal kurulum — mevcut bir vault dosyası varsa açık onay olmadan
    ÜZERİNE YAZILMAMALI.

USB donanımı, DBManager ve getpass/input hep sahte (monkeypatch) — gerçek
donanım/DB gerekmiyor, yalnızca `main()`'in KARAR mantığı ölçülüyor.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from CORE import setup_usb as su

_HWID = "USB-SETUP-TEST-HWID"


class _SahteDB:
    def connect(self, *a, **k):
        pass

    def log(self, *a, **k):
        pass

    def close(self):
        pass


@pytest.fixture(autouse=True)
def _ortak_yamalar(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(su, "get_usb_hwid", lambda: _HWID)
    monkeypatch.setattr(su, "DBManager", lambda: _SahteDB())


def test_reset_yanlis_pin_ile_reddediliyor(monkeypatch: pytest.MonkeyPatch):
    """Mevcut PIN doğrulanamazsa reset EN BAŞTA, create_vault'a hiç gelmeden durmalı."""
    monkeypatch.setattr(sys, "argv", ["setup_usb.py", "--role", "standart", "--reset"])
    monkeypatch.setattr(su.getpass, "getpass", lambda *_a, **_k: "yanlis-pin")

    def patlayan_read_vault_role(hwid, pin):
        raise ValueError("PIN yanlis")

    monkeypatch.setattr(su, "read_vault_role", patlayan_read_vault_role)

    cagrildi = []
    monkeypatch.setattr(su, "create_vault", lambda *a, **k: cagrildi.append(1))

    with pytest.raises(SystemExit) as hata:
        su.main()

    assert hata.value.code == 1
    assert not cagrildi, "PIN yanlış olduğu hâlde create_vault() çağrıldı — reset guard'ı atlanmış"


def test_reset_dogru_pin_ile_devam_ediyor(monkeypatch: pytest.MonkeyPatch):
    """Karşı kanıt: doğru PIN'de guard yolu ENGELLEMEMELİ (yanlış-pozitif değil)."""
    monkeypatch.setattr(sys, "argv", ["setup_usb.py", "--role", "standart", "--reset"])
    monkeypatch.setattr(su.getpass, "getpass", lambda *_a, **_k: "dogru-pin")
    monkeypatch.setattr(su, "read_vault_role", lambda hwid, pin: "Standart")
    monkeypatch.setattr(
        __import__("builtins"), "input", lambda *_a, **_k: "SIFIRLA"
    )
    monkeypatch.setattr(su, "_do_reset", lambda hwid, db: None)
    cagrildi = []
    monkeypatch.setattr(su, "create_vault", lambda *a, **k: cagrildi.append(1) or "path")

    su.main()

    assert cagrildi, "doğru PIN ile bile reset guard'ı ilerlemeyi engelledi"


def test_mevcut_vault_onaysiz_UZERINE_YAZILMIYOR(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """
    Reset OLMADAN normal kurulumda, aynı HWID için zaten bir vault dosyası
    varsa, kullanıcı "e" demeden create_vault() ÇAĞRILMAMALI.
    """
    monkeypatch.setattr(sys, "argv", ["setup_usb.py", "--role", "standart"])
    monkeypatch.setattr(su, "_VAULT_DIR", tmp_path)
    monkeypatch.setattr(su, "_VAULT_FILE", tmp_path / "yok-olan-eski-dosya.hclv")
    (tmp_path / f"{_HWID}.hclv").write_bytes(b"mevcut vault")

    monkeypatch.setattr(
        __import__("builtins"), "input", lambda *_a, **_k: "h"  # "Hayır"
    )
    cagrildi = []
    monkeypatch.setattr(su, "create_vault", lambda *a, **k: cagrildi.append(1))

    with pytest.raises(SystemExit) as hata:
        su.main()

    assert hata.value.code == 0
    assert not cagrildi, "onay verilmediği hâlde create_vault() çağrıldı — mevcut vault üzerine yazılmış olurdu"
