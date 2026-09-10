"""
HYCLEUS — CORE.usb_manager.get_usb_hwid() (B-112/B-114)

2026-09-08'e KADAR bu fonksiyonun yalnızca Windows dalları vardı
(`wmi`/`wmic`); Linux/macOS'ta HER ZAMAN `None` dönüyordu — USB takılı
olsun ya da olmasın (bkz. docs/hwid-crossplatform.md). `main.py::main()`
bunu açılışta koşulsuz çağırdığı için paketlenmiş bir Linux/macOS
derlemesi hiç açılamıyordu. Bu dosya, Linux/macOS için eklenen üçüncü ve
dördüncü yöntemi (`CORE/hwid_probe.py::read_linux()`/`read_macos()`
üzerinden) doğrudan sınıyor — `get_usb_hwid()`'in kendisinin daha önce
HİÇ doğrudan test edilmediği de ayrıca not: yalnızca kardeşi
`get_usb_mount_root()` (`tests/test_usb_mount_root.py`) test ediliyordu.

Bu dosyanın testleri `CORE.hwid_probe.read_linux`/`read_macos`'u sahte
veri döndürecek şekilde monkeypatch'liyor — `tests/test_hwid_probe.py`
o iki fonksiyonun KENDİ ayrıştırma mantığını (gerçek pyudev/ioreg
biçimleriyle) zaten sınıyor; burada sınanan şey yalnızca BAĞLANTI:
`get_usb_hwid()` onları doğru çağırıyor mu, sonucu doğru
`_sanitize_hwid()`'den geçiriyor mu, hiçbir aygıt yokken çökmeden
(sessizce None ile) dönüyor mu.

Gerçek donanımla da doğrulandı (bu turda, elde GERÇEKTEN takılı iki USB
depolama aygıtıyla): `get_usb_hwid()` gerçek `4C530301470118102554`
serisini döndürdü — ayrıntı BACKLOG.md/B-114.
"""
from __future__ import annotations

import sys

import pytest

from CORE import hwid_probe, usb_manager
from CORE.hwid_probe import UsbIdentity
from CORE.usb_manager import get_usb_hwid


@pytest.fixture(autouse=True)
def _gercek_donanima_dokunma(monkeypatch: pytest.MonkeyPatch) -> None:
    """DEV_MODE'u KAPALI tut — bu dosyanın testleri sahte veri üzerinden
    çalışıyor, gerçek/DEV kısayolu araya girmemeli."""
    monkeypatch.setattr(usb_manager, "DEV_MODE", False)


@pytest.fixture(autouse=True)
def _wmi_hicbir_zaman_bulunmasin(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    `import wmi` (Yöntem 1) bu makinede zaten `ImportError` veriyor
    (Linux) — ama testin bunu VARSAYMASI kırılgan olurdu (CI bir gün
    Windows'ta da koşabilir). `sys.modules['wmi']` içinde gerçek bir
    şey yoksa `import wmi` başarısız olsun diye açıkça `None` konuyor
    (Python bunu "bu modül yok" olarak yorumluyor).
    """
    monkeypatch.setitem(sys.modules, "wmi", None)


def _kimlik(seri: str | None, **kw) -> UsbIdentity:
    return UsbIdentity(
        platform="linux", source="test", vendor_id="0781", product_id="5567",
        descriptor_serial=seri, generated=not seri, **kw,
    )


# ── Linux (Yöntem 3) ────────────────────────────────────────────────────────


def test_linux_gercek_seri_hwid_olarak_donuyor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hwid_probe, "read_linux", lambda: [_kimlik("4C530301470118102554")])
    assert get_usb_hwid() == "4C530301470118102554"


def test_linux_hicbir_usb_yokken_none_donuyor_cokme_yok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ASIL REGRESYON TESTİ: B-112'nin bulduğu senaryo — Linux'ta USB
    hiç takılı değilken (ya da hiç okunamıyorken) fonksiyon sessizce
    `None` dönmeli, İSTİSNA FIRLATMAMALI."""
    monkeypatch.setattr(hwid_probe, "read_linux", lambda: [])
    assert get_usb_hwid() is None


def test_linux_ikinci_aygit_serisiz_ilki_kullaniliyor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Birden fazla USB varsa GEÇERLİ seriye sahip İLKİ alınıyor —
    Windows dalıyla (`get_usb_hwid`'in kendi docstring'i) aynı kural."""
    monkeypatch.setattr(
        hwid_probe, "read_linux",
        lambda: [_kimlik(None), _kimlik("IKINCI-SERI")],
    )
    assert get_usb_hwid() == "IKINCI-SERI"


def test_linux_pyudev_okuyucusu_patlarsa_cokmeden_devam_ediyor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`read_linux()` beklenmeyen bir istisna fırlatırsa (ör. pyudev'in
    kendi iç hatası) `get_usb_hwid()` yine de çökmemeli — sonraki
    yönteme (macOS, sonra None) sessizce geçmeli."""
    def _patlayan() -> list[UsbIdentity]:
        raise RuntimeError("beklenmeyen pyudev hatası")

    monkeypatch.setattr(hwid_probe, "read_linux", _patlayan)
    monkeypatch.setattr(hwid_probe, "read_macos", lambda: [])
    assert get_usb_hwid() is None


# ── macOS (Yöntem 4) ─────────────────────────────────────────────────────────


def test_macos_gercek_seri_hwid_olarak_donuyor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux boş dönerse (bu makine Linux olduğu için read_linux()
    gerçekten çağrılabiliyor — sahtelenmesi gerekiyor) macOS yolu
    denenmeli."""
    monkeypatch.setattr(hwid_probe, "read_linux", lambda: [])
    monkeypatch.setattr(
        hwid_probe, "read_macos",
        lambda: [UsbIdentity(platform="darwin", source="test",
                              descriptor_serial="MACOS-SERI-001", generated=False)],
    )
    assert get_usb_hwid() == "MACOS-SERI-001"


def test_hicbir_platformda_usb_yokken_none_donuyor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hwid_probe, "read_linux", lambda: [])
    monkeypatch.setattr(hwid_probe, "read_macos", lambda: [])
    assert get_usb_hwid() is None


# ── Sanitizasyon zincirinin korunduğu ────────────────────────────────────────


def test_linux_serisi_ayni_sanitize_zincirinden_geciyor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows yoluyla AYNI `_sanitize_hwid()` çağrılıyor — kontrol
    karakteri/boşluk temizliği iki platformda da tutarlı olmalı."""
    monkeypatch.setattr(
        hwid_probe, "read_linux", lambda: [_kimlik("  seri-ile-boşluk  \x00")],
    )
    assert get_usb_hwid() == usb_manager._sanitize_hwid("  seri-ile-boşluk  \x00")


def test_linux_bos_seri_uuid_yedegine_dusuyor(monkeypatch: pytest.MonkeyPatch) -> None:
    """`descriptor_serial` boş/None ise Linux dalı hiç girmemeli — sonraki
    yöntemlere (ve nihayetinde None'a) düşmeli, sahte bir seri
    UYDURMAMALI. (Gerçek boş-seri UUID yedeği zaten `usb_manager`'ın
    kendi `_get_or_create_uuid()`'ü — burada sınanan yalnızca bu yolun
    boş seriyi geçerli bir hwid gibi DÖNDÜRMEDİĞİ.)"""
    monkeypatch.setattr(hwid_probe, "read_linux", lambda: [_kimlik(None)])
    monkeypatch.setattr(hwid_probe, "read_macos", lambda: [])
    assert get_usb_hwid() is None


# ── DEV_MODE, yalnızca DONMAMIŞ (paketlenmemiş) çalışırken geçerli ───────────
#
# `if DEV_MODE and not hasattr(sys, "frozen"):` — paketlenmiş bir EXE'de
# `sys.frozen` ayarlı olur (PyInstaller vb.). Bu kontrolün amacı: dağıtılan
# bir .exe, ortamda yanlışlıkla/kötü niyetle `HYCLEUS_DEV_MODE=true`
# ayarlansa bile GERÇEK USB donanımı gerektirmeye devam etmeli — sahte
# `DEV-HWID-1234` asla üretime sızmamalı.


def test_dev_mode_donmus_yapida_GECERSIZ_gercek_donanima_dusuyor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(usb_manager, "DEV_MODE", True)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(hwid_probe, "read_linux", lambda: [])
    monkeypatch.setattr(hwid_probe, "read_macos", lambda: [])

    assert get_usb_hwid() != usb_manager._DEV_HWID
    assert get_usb_hwid() is None


def test_dev_mode_donmamis_yapida_hala_gecerli(monkeypatch: pytest.MonkeyPatch) -> None:
    """Karşı kanıt: donmamış (normal `python ...` çalıştırması) DEV_MODE
    hâlâ kısayolu vermeli — yanlış-pozitif değil."""
    monkeypatch.setattr(usb_manager, "DEV_MODE", True)
    assert not hasattr(sys, "frozen")
    assert get_usb_hwid() == usb_manager._DEV_HWID


# ══════════════════════════════════════════════════════════════════════════════
# MC-Kataloğu (2026-09-10) — Windows/Yöntem 1 (wmi) dalı (MC-M058)
# ══════════════════════════════════════════════════════════════════════════════


def test_windows_yontem1_gercek_usb_seriyi_donduruyor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    MC-Kataloğu M058: `get_usb_hwid()`'in Windows dalı (Yöntem 1, `wmi`)
    bu dosyanın KENDİ otomatik fixture'ı (`_wmi_hicbir_zaman_bulunmasin`)
    tarafından HER testte `wmi` ImportError'a düşürülerek devre dışı
    bırakılıyordu — yani gerçek USB serisini mi okuduğu, yoksa USB'yi
    yok sayıp makine geneli sabit bir kimlik (ör. machine GUID) mi
    döndürdüğü bugüne kadar HİÇ test edilmemişti (bu dosyanın kendi
    docstring'i de bunu ayrıca not ediyor: "get_usb_hwid()'in kendisi
    daha önce hiç doğrudan test edilmedi").

    Mutasyon-kanıt: Yöntem 1'de `serial = getattr(disk, "SerialNumber",
    "")` satırı `serial = "SABIT-MAKINE-KIMLIGI"` ile (USB'yi yok sayıp
    hep aynı değeri dönecek şekilde) değiştirilse, tam test paketinin
    HİÇBİRİ fark etmezdi — Yöntem 1 hiçbir testte fiilen ÇALIŞMIYORDU.
    """
    class _SahteAygit:
        def __init__(self, **alanlar):
            self.__dict__.update(alanlar)

    class _SahteWmiYontem1:
        def __init__(self, diskler):
            self._diskler = diskler

        def WMI(self):  # noqa: N802 — wmi paketinin API'si
            return self

        def Win32_DiskDrive(self):  # noqa: N802
            return self._diskler

    sahte = _SahteWmiYontem1([
        _SahteAygit(InterfaceType="SCSI", SerialNumber="DAHILI-DISK-SERI"),
        _SahteAygit(InterfaceType="USB", SerialNumber="GERCEK-USB-SERI-001"),
    ])
    monkeypatch.setitem(sys.modules, "wmi", sahte)

    assert get_usb_hwid() == "GERCEK-USB-SERI-001"


def test_windows_yontem1_usb_yoksa_dahili_diski_kullanmiyor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MC-Kataloğu M058'in karşı kanıtı: yalnızca dahili (USB olmayan)
    disk varsa Yöntem 1 onu HWID olarak kullanmamalı — Yöntem 3/4'e
    (burada boş) düşüp `None` dönmeli."""
    class _SahteAygit:
        def __init__(self, **alanlar):
            self.__dict__.update(alanlar)

    class _SahteWmiYontem1:
        def __init__(self, diskler):
            self._diskler = diskler

        def WMI(self):  # noqa: N802
            return self

        def Win32_DiskDrive(self):  # noqa: N802
            return self._diskler

    sahte = _SahteWmiYontem1([
        _SahteAygit(InterfaceType="SCSI", SerialNumber="DAHILI-DISK-SERI"),
    ])
    monkeypatch.setitem(sys.modules, "wmi", sahte)
    monkeypatch.setattr(hwid_probe, "read_linux", lambda: [])
    monkeypatch.setattr(hwid_probe, "read_macos", lambda: [])

    assert get_usb_hwid() is None


def test_windows_yontem1_seri_harf_buyuklugu_degistirilmeden_kullaniliyor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    MC-Kataloğu M059: `_sanitize_hwid()` (tek karar noktası, TÜM
    platformlarda aynı) seriyi harf büyüklüğü değiştirmeden geçiriyor —
    Yöntem 1/2/3/4'ten HERHANGİ biri seriye sessizce `.upper()`/`.lower()`
    uygulasa, o metotla yazılan bir vault başka bir metotla (ya da aynı
    metodun farklı bir sürümüyle) AÇILAMAZ hâle gelirdi (dosya adı/DB/
    keyring kaydı `vaults/<hwid>.hclv` tam string eşleşmesi bekliyor).

    Önceki test (`..._gercek_usb_seriyi_donduruyor`) bunu YAKALAMAZDI:
    kullandığı örnek seri zaten tamamen büyük harfti, `.upper()` onu
    değiştirmezdi. Mutasyon-kanıt: Yöntem 1'de `_sanitize_hwid(str(
    serial))` → `_sanitize_hwid(str(serial).upper())` yapılınca (karışık
    harfli bir seriyle) mevcut test paketinin HİÇBİRİ fark etmezdi.
    """
    class _SahteAygit:
        def __init__(self, **alanlar):
            self.__dict__.update(alanlar)

    class _SahteWmiYontem1:
        def __init__(self, diskler):
            self._diskler = diskler

        def WMI(self):  # noqa: N802
            return self

        def Win32_DiskDrive(self):  # noqa: N802
            return self._diskler

    karisik_seri = "4c53AbC0011f"
    sahte = _SahteWmiYontem1([
        _SahteAygit(InterfaceType="USB", SerialNumber=karisik_seri),
    ])
    monkeypatch.setitem(sys.modules, "wmi", sahte)

    assert get_usb_hwid() == karisik_seri


def test_windows_yontem1_ikinci_aygit_serisiz_ilki_kullaniliyor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    MC-Kataloğu M064: Boş seri "geçerli" bir bileşen SAYILMAMALI — birden
    fazla USB disk varsa, seri BOŞ olan ilk aygıtta durup onu (UUID
    yedeğiyle) döndürmek yerine, GERÇEK seriye sahip bir SONRAKİ aygıta
    geçilmeli. Linux dalında bu zaten test ediliyordu
    (`test_linux_ikinci_aygit_serisiz_ilki_kullaniliyor`); Windows/Yöntem
    1'de eşdeğeri yoktu.

    Mutasyon-kanıt: `if serial and serial != "?":` → `if serial != "?":`
    (boş dizeyi de "geçerli" sayıp `_sanitize_hwid("")`'in UUID yedeğini
    İLK aygıt için hemen döndürmesi — ikinci, gerçek serili aygıta hiç
    bakmadan) yapılınca test paketinin HİÇBİRİ fark etmiyordu.
    """
    class _SahteAygit:
        def __init__(self, **alanlar):
            self.__dict__.update(alanlar)

    class _SahteWmiYontem1:
        def __init__(self, diskler):
            self._diskler = diskler

        def WMI(self):  # noqa: N802
            return self

        def Win32_DiskDrive(self):  # noqa: N802
            return self._diskler

    sahte = _SahteWmiYontem1([
        _SahteAygit(InterfaceType="USB", SerialNumber=""),
        _SahteAygit(InterfaceType="USB", SerialNumber="IKINCI-GERCEK-SERI"),
    ])
    monkeypatch.setitem(sys.modules, "wmi", sahte)

    assert get_usb_hwid() == "IKINCI-GERCEK-SERI"
