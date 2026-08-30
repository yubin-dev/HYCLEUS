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
def tpm_kapali(request: pytest.FixtureRequest) -> Iterator[None]:
    """
    Varsayılan olarak TPM mühürlemesini KAPATIR.

    autouse ve gerekçesi ölçüldü: bu geliştirme makinesinde gerçek bir
    TPM 2.0 var (AMD fTPM), CI'ın Linux koşucusunda yok. Fixture olmadan
    aynı test paketi iki makinede FARKLI sonuç veriyor — ölçüldü,
    `test_secret_store.py::test_store_load_erase_round_trip` ve
    `test_vault_keyring.py::test_save_usb_token_writes_to_keyring_not_db`
    kasadaki HAM değere bakıyor ve TPM'li makinede `TPM1:…` görüp
    düşüyorlar.

    Makineye göre değişen bir test paketi güven veremez: yeşil bir CI,
    geliştiricinin makinesinde kırmızı olanı gizler. O yüzden varsayılan
    tek ve sabit: mühürsüz. TPM yolunu ölçmek isteyen testler
    `gercek_tpm` fixture'ını isteyerek bunu devre dışı bırakıyor.
    """
    from CORE import tpm_sealing

    if "gercek_tpm" in request.fixturenames:
        yield  # `gercek_tpm` durumu kendisi ayarlıyor
        return

    onceki = tpm_sealing._durum_onbellek
    tpm_sealing.zorla_durum(
        tpm_sealing.TpmDurum(False, "test: TPM bilerek devre dışı (conftest)")
    )
    try:
        yield
    finally:
        tpm_sealing._durum_onbellek = onceki


@pytest.fixture
def gercek_tpm():  # type: ignore[no-untyped-def]
    """
    GERÇEK TPM donanımını kullanır; yoksa testi atlar.

    `tpm_kapali` bu fixture'ın varlığını görüp kenara çekiliyor.
    """
    from CORE import tpm_sealing

    onceki = tpm_sealing._durum_onbellek
    tpm_sealing.sifirla_onbellek()
    d = tpm_sealing.durum()
    if not d.kullanilabilir:
        tpm_sealing._durum_onbellek = onceki
        pytest.skip(f"Bu makinede TPM mühürlemesi yok: {d.neden}")
    try:
        yield d
    finally:
        tpm_sealing._durum_onbellek = onceki


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


@pytest.fixture(autouse=True)
def isolate_audit_anchor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """
    Denetim zinciri çıpasını her test için tmp_path'e taşır.

    autouse — isolate_totp_file ile aynı gerekçe: çıpa dosyası varsayılan
    olarak data/audit_anchor.log'dur ve testlerin kullanıcının gerçek
    denetim çıpasına satır eklemesi, o dosyanın kendi zincirini bozardı.
    """
    from CORE.audit_chain import ANCHOR_ENV_VAR

    isolated = tmp_path / "audit_anchor.log"
    monkeypatch.setenv(ANCHOR_ENV_VAR, str(isolated))
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


class SahteUSB:
    """
    Gerçek USB donanımı olmadan "takılı fiziksel USB"yi simüle eder (B-067).

    B-064/B-065/B-066 PoC'larında ve testlerinde tekrar tekrar elle
    yazılan `monkeypatch.setattr(<modül>, "get_usb_hwid", lambda: hwid)`
    deseninin kalıcı hâli. Tek bir yeri yamamak YETMEZ: her modül
    `from CORE.usb_manager import get_usb_hwid` ile KENDİ isim uzayına
    kendi bağlı adını alıyor, `CORE.usb_manager.get_usb_hwid`'i
    değiştirmek o modüllerin GÖRDÜĞÜ referansı etkilemiyor (ölçüldü) --
    o yüzden `_HEDEF_MODULLER` listesindeki HEPSİ ayrı ayrı yamalanıyor.

    `.hwid` alanı doğrudan değiştirilebilir (`.tak()`/`.cikar()` sadece
    okunabilir kısayollar) -- yamalar `lambda: self.hwid` ile KAPALI
    (closure), yani `self.hwid`'i değiştirmek TÜM hedef modüllere aynı
    anda, yeniden yamalamaya gerek kalmadan yansır (fiziksel bir USB'nin
    takılıp çıkarılmasının birebir karşılığı).
    """

    #: `get_usb_hwid`'i kendi isim uzayına içe aktaran TÜM modüller.
    #: Yeni bir modül `from CORE.usb_manager import get_usb_hwid` yazarsa
    #: buraya eklenmeli -- eklenmezse o modül simülasyondan HABERSİZ kalır
    #: ve testte sessizce GERÇEK donanımı görmeye devam eder.
    _HEDEF_MODULLER = (
        "UI.main_window",
        "UI.main_window_lock",
        "UI.main_window_table",
        "UI.UsbTokensView",
        "UI.PendingRegistrationsView",
        "UI.AdminSettingsView",
        "UI.admin_common",
        "UI.ProfileView",
        "UI.RegisterDialog",
        "UI.login_dialog",
        "CORE.recover_vault",
        "CORE.setup_usb",
    )

    def __init__(self, monkeypatch: pytest.MonkeyPatch, hwid: str | None) -> None:
        import importlib

        self.hwid = hwid
        for ad in self._HEDEF_MODULLER:
            modul = importlib.import_module(ad)  # ImportError bilerek YUTULMUYOR
            monkeypatch.setattr(modul, "get_usb_hwid", lambda: self.hwid, raising=False)

    def tak(self, hwid: str) -> None:
        """USB'yi (yeni bir HWID ile) takar."""
        self.hwid = hwid

    def cikar(self) -> None:
        """USB'yi fiziksel olarak çıkarır -- get_usb_hwid() artık None döner."""
        self.hwid = None


@pytest.fixture
def sahte_usb(monkeypatch: pytest.MonkeyPatch):
    """
    Fabrika fixture: `sahte_usb(hwid)` çağrısı bir `SahteUSB` döndürür.

    `UI.*` modülleri Qt gerektirir; bu ortamda Qt katmanı yüklenemiyorsa
    (diğer Qt test dosyalarındaki aynı korumalı-import deseni) testi
    ATLAR -- sessizce hiçbir modülü yamamadan devam etmek, "donanım simüle
    ediliyor sanılan" ama aslında hâlâ GERÇEK donanımı gören yanıltıcı bir
    teste yol açardı.
    """
    def _kur(hwid: str | None = None) -> SahteUSB:
        try:
            return SahteUSB(monkeypatch, hwid)
        except ImportError as exc:
            pytest.skip(f"Qt katmanı bu ortamda yüklenemedi ({exc})")
    return _kur
