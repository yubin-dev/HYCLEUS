"""
HYCLEUS — CORE.usb_manager.get_usb_mount_root() (B-090)

`get_usb_hwid()` yalnızca donanım KİMLİĞİNİ (WMI `Win32_DiskDrive.
SerialNumber`) okur — bugüne kadar bu modül USB'nin kendi dosya sistemine
hiç YAZMADI. `CORE/audit_chain.py`'nin denetim çıpasına GERÇEKTEN izole
(makineden fiziksel olarak sökülebilir) bir ikinci kopya yazabilmesi için
o diskin bağlama kökünü (sürücü harfini) bulan yeni bir fonksiyon gerekti:
`get_usb_mount_root(hwid)`.

Bu dosya `tests/test_hwid_probe.py`'nin ZATEN kurduğu `wmi` sahteleme
desenini (`monkeypatch.setitem(sys.modules, "wmi", ...)`) genişletiyor:
gerçek donanım/WMI GEREKMİYOR.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from CORE import usb_manager
from CORE.usb_manager import get_usb_mount_root


class _SahteWmiNesnesi:
    """Bir WMI nesnesinin (disk, bölüm, mantıksal disk) asgari sahtesi."""

    def __init__(self, *, assoc: dict[str, list["_SahteWmiNesnesi"]] | None = None, **alanlar):
        self.__dict__.update(alanlar)
        self._assoc = assoc or {}

    def associators(self, wmi_association_class: str):  # noqa: N803 — wmi paketinin API'si
        return self._assoc.get(wmi_association_class, [])


class _SahteWMI:
    """`wmi.WMI()` yerine geçen asgari sahte — `test_hwid_probe.py::_SahteWMI` ile AYNI desen."""

    def __init__(self, diskler: list[_SahteWmiNesnesi]) -> None:
        self._diskler = diskler

    def WMI(self):  # noqa: N802 — wmi paketinin API'si
        return self

    def Win32_DiskDrive(self):  # noqa: N802
        return self._diskler


def _usb_diski(
    *, serial: str | None, mount_letter: str | None, interface: str = "USB"
) -> _SahteWmiNesnesi:
    """Disk→bölüm→mantıksal-disk WMI ilişki zincirini KURAR (gerçek WMI'ın
    `associators()` API'sini taklit ederek)."""
    if mount_letter is None:
        bolum = _SahteWmiNesnesi(assoc={"Win32_LogicalDiskToPartition": []})
    else:
        mantiksal = _SahteWmiNesnesi(DeviceID=mount_letter)
        bolum = _SahteWmiNesnesi(
            assoc={"Win32_LogicalDiskToPartition": [mantiksal]}
        )
    return _SahteWmiNesnesi(
        InterfaceType=interface,
        SerialNumber=serial,
        assoc={"Win32_DiskDriveToDiskPartition": [bolum]},
    )


@pytest.fixture(autouse=True)
def _gercek_donanima_dokunma(monkeypatch: pytest.MonkeyPatch) -> None:
    """DEV_MODE'u KAPALI tut — bu dosyanın tüm testleri WMI sahtesi
    üzerinden çalışıyor, gerçek/DEV kısayolu araya girmemeli."""
    monkeypatch.setattr(usb_manager, "DEV_MODE", False)


def test_eslesen_hwid_surucu_harfini_donduruyor(monkeypatch: pytest.MonkeyPatch) -> None:
    disk = _usb_diski(serial="SERI-ABC-123", mount_letter="E:")
    monkeypatch.setitem(sys.modules, "wmi", _SahteWMI([disk]))

    assert get_usb_mount_root("SERI-ABC-123") == Path("E:\\")


def test_eslesmeyen_hwid_none_donduruyor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Diskin SERİSİ var ama aranan hwid'le uyuşmuyor — yanlış sürücüye
    YAZILMAMALI."""
    disk = _usb_diski(serial="BASKA-SERI", mount_letter="F:")
    monkeypatch.setitem(sys.modules, "wmi", _SahteWMI([disk]))

    assert get_usb_mount_root("SERI-ABC-123") is None


def test_usb_olmayan_disk_atlaniyor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Aynı seriyle bile olsa InterfaceType != USB olan bir disk asla
    eşleşmemeli — get_usb_hwid()'in AYNI filtresi burada da geçerli."""
    disk = _usb_diski(serial="SERI-ABC-123", mount_letter="G:", interface="SCSI")
    monkeypatch.setitem(sys.modules, "wmi", _SahteWMI([disk]))

    assert get_usb_mount_root("SERI-ABC-123") is None


def test_birden_fazla_usb_dogru_olani_seciyor(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    İki USB takılıyken, hwid'i EŞLEŞEN diskin bağlama kökü dönmeli — "ilk
    USB" değil. `get_usb_hwid()`'in kendi basitleştirmesinden ("birden
    fazla USB varsa ilki alınır") BİLEREK farklı: kimlik ve bağlama kökü
    ayrı WMI sorgularından geldiği için, eşleştirme olmadan "ilk disk" ile
    "ilk diskin bağlama kökü" farklı fiziksel cihazlara denk gelebilirdi.
    """
    birinci = _usb_diski(serial="USB-BIRINCI", mount_letter="D:")
    ikinci = _usb_diski(serial="USB-IKINCI", mount_letter="H:")
    monkeypatch.setitem(sys.modules, "wmi", _SahteWMI([birinci, ikinci]))

    assert get_usb_mount_root("USB-IKINCI") == Path("H:\\")
    assert get_usb_mount_root("USB-BIRINCI") == Path("D:\\")


def test_kontrol_karakterli_seri_uuid_yedegiyle_de_eslesiyor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    Yalnızca kontrol karakteri taşıyan bir seri numarası (B-025 zayıf
    bağlama — gerçek bir KIOXIA cihazında ölçüldü, bkz. modül docstring'i)
    `_sanitize_hwid()` üzerinden kalıcı bir UUID'ye düşer; o UUID'yle de
    eşleştirilebilmeli — `get_usb_hwid()`'in zayıf-bağlama davranışıyla
    TUTARLI kalması için.

    Tümüyle BOŞ (`""`) bir seri BİLEREK kullanılmadı: hem `get_usb_hwid()`
    hem burası WMI'dan boş seriyi `if not serial: continue` ile baştan
    atlıyor — `_sanitize_hwid()`'e hiç ulaşmıyor. Zayıf-bağlama yolunu
    gerçekten tetikleyen, WMI'da NON-EMPTY ama saflaştırmadan sonra boşa
    düşen bir değer (kontrol karakterleri) — `tests/
    test_usb_weak_binding.py`'nin kullandığı AYNI `"\\x00\\x00"` deseni.
    """
    monkeypatch.setattr(usb_manager, "_USB_IDS_FILE", tmp_path / "usb_ids.json")
    uretilen_uuid = usb_manager._sanitize_hwid("\x00\x00")  # ilk çağrı UUID atar

    disk = _usb_diski(serial="\x00\x00", mount_letter="Z:")
    monkeypatch.setitem(sys.modules, "wmi", _SahteWMI([disk]))

    assert get_usb_mount_root(uretilen_uuid) == Path("Z:\\")


def test_esleseni_bulunamayan_bolum_none_donduruyor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disk eşleşiyor ama WMI ilişki zinciri hiçbir mantıksal disk
    döndürmüyor (ör. bölümlenmemiş/RAW disk) — çökmek yerine None."""
    disk = _usb_diski(serial="SERI-ABC-123", mount_letter=None)
    monkeypatch.setitem(sys.modules, "wmi", _SahteWMI([disk]))

    assert get_usb_mount_root("SERI-ABC-123") is None


def test_dev_modeda_gercek_donanim_aranmiyor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(usb_manager, "DEV_MODE", True)
    disk = _usb_diski(serial=usb_manager._DEV_HWID, mount_letter="E:")
    monkeypatch.setitem(sys.modules, "wmi", _SahteWMI([disk]))

    assert get_usb_mount_root(usb_manager._DEV_HWID) is None


def test_wmi_yoksa_hata_firlatmiyor_none_donuyor(monkeypatch: pytest.MonkeyPatch) -> None:
    """`wmi` paketi hiç kurulu değilse (Linux, wmi eksik) sessizce None —
    `get_usb_hwid()` ile AYNI "best-effort, hata değil" disiplini."""
    monkeypatch.setitem(sys.modules, "wmi", None)  # import wmi -> ImportError

    assert get_usb_mount_root("HERHANGI-BIR-HWID") is None


def test_wmi_sorgusu_patlarsa_hata_firlatmiyor_none_donuyor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _PatlayanWMI:
        def WMI(self):  # noqa: N802
            raise RuntimeError("WMI servisi çalışmıyor")

    monkeypatch.setitem(sys.modules, "wmi", _PatlayanWMI())

    assert get_usb_mount_root("HERHANGI-BIR-HWID") is None
