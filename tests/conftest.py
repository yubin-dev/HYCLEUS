"""Ortak pytest yapılandırması — proje kökünü sys.path'e ekler.

Uygulama importları (CORE.*, DB.*) HYCLEUS/ dizinini kök kabul eder;
testler tests/ altından çalıştığı için kökü elle eklemek gerekir.

Ayrıca anahtar kasası (keyring) ve veritabanı için izole test fixture'ları
sağlar. keyring fixture'ı AUTOUSE'dur: hiçbir test kullanıcının gerçek
Windows Credential Manager / Keychain / Secret Service kaydına dokunmaz.
"""
from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import keyring  # noqa: E402
import keyring.backend  # noqa: E402
import keyring.errors  # noqa: E402


class InMemoryKeyring(keyring.backend.KeyringBackend):
    """
    Testler için bellek içi keyring arka ucu.

    Mock değil — gerçek bir KeyringBackend implementasyonu; secret_store
    kodu hiç değişmeden normal keyring API'si üzerinden buna konuşur.
    """

    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        if (service, username) not in self.store:
            raise keyring.errors.PasswordDeleteError(f"kayıt yok: {service}/{username}")
        del self.store[(service, username)]


class BrokenKeyring(keyring.backend.KeyringBackend):
    """
    Erişilemeyen kasa taklidi — başsız Linux'ta Secret Service yokken
    keyring'in davranışı budur (her çağrıda NoKeyringError).
    """

    priority = 1  # type: ignore[assignment]

    def get_password(self, service: str, username: str) -> str | None:
        raise keyring.errors.NoKeyringError("Test: kullanılabilir keyring arka ucu yok")

    def set_password(self, service: str, username: str, password: str) -> None:
        raise keyring.errors.NoKeyringError("Test: kullanılabilir keyring arka ucu yok")

    def delete_password(self, service: str, username: str) -> None:
        raise keyring.errors.NoKeyringError("Test: kullanılabilir keyring arka ucu yok")


class SilentlyFailingKeyring(InMemoryKeyring):
    """
    Yazmayı kabul eder ama saklamaz — kilitli/bozuk kasa senaryosu.

    En tehlikeli durum bu: istisna yok, ama sır kaybolmuş oluyor. Migration'ın
    "yazdıktan sonra geri oku" kontrolü tam da bunu yakalamalı.
    """

    def set_password(self, service: str, username: str, password: str) -> None:
        pass  # sessizce yut


@pytest.fixture(autouse=True)
def fake_keyring() -> Iterator[InMemoryKeyring]:
    """
    Tüm testler için gerçek OS anahtar kasasını bellek içi arka uçla değiştirir.

    autouse — hiçbir test kullanıcının gerçek kasasına yazmasın diye.
    Erişilemezlik senaryosunu test edenler use_keyring_backend ile üzerine yazar.
    """
    original = keyring.get_keyring()
    backend = InMemoryKeyring()
    keyring.set_keyring(backend)
    try:
        yield backend
    finally:
        keyring.set_keyring(original)


@pytest.fixture(autouse=True)
def isolate_totp_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """
    Migration'ın baktığı totp_secret.json yolunu her test için tmp_path'e taşır.

    autouse — migrate_totp_secret() dosyayı İMHA EDER. Bu koruma olmadan
    testleri canlı bir kurulumda çalıştırmak kullanıcının gerçek TOTP sırrını
    kalıcı olarak yok ederdi.
    """
    from CORE import secret_migration

    isolated = tmp_path / "isolated_totp_secret.json"
    monkeypatch.setattr(secret_migration, "_TOTP_FILE", isolated)
    return isolated


@pytest.fixture
def use_keyring_backend():
    """Test içinde keyring arka ucunu değiştirmek için yardımcı (teardown fake_keyring'de)."""

    def _use(backend: keyring.backend.KeyringBackend) -> keyring.backend.KeyringBackend:
        keyring.set_keyring(backend)
        return backend

    return _use


@pytest.fixture
def db(tmp_path: Path) -> Iterator["object"]:
    """
    Geçici dosya üzerinde izole DBManager örneği.

    DBManager bir singleton olduğu için _instance elle sıfırlanır; aksi halde
    testler birbirinin veritabanını görür.
    """
    from DB.db_manager import DBManager

    DBManager._instance = None
    manager = DBManager(tmp_path / "hycleus_test.db")
    manager.connect(hwid="TEST-HWID-DB")
    try:
        yield manager
    finally:
        manager.close()
        DBManager._instance = None
