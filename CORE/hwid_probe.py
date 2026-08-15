"""
HYCLEUS — Çapraz platform USB kimliği PROTOTİPİ (3.4)

**Bu modül uygulamaya BAĞLI DEĞİL.** `CORE/usb_manager.py` hâlâ tek
yetkili okuyucu. Buradaki kod bir mimari soruyu yanıtlamak için var:

    Aynı USB çubuğu Windows, Linux ve macOS'ta AYNI kimliği verir mi?

Yanıt kısaca: **hayır, güvenilir biçimde vermiyor.** Ayrıntı ve kanıt
aşağıda; sonuç `docs/hwid-crossplatform.md` içinde raporlandı.


Üç platform hangi alanı okuyor
------------------------------
Teorik ortak alan USB aygıt tanımlayıcısındaki **iSerialNumber** (USB 2.0
spec §9.6.1, `bLength`/`iSerialNumber` dizin numarası). Üçü de ona
ulaşabiliyor ama FARKLI yığınlardan:

    Windows  Win32_DiskDrive.SerialNumber   → DEPOLAMA yığını (SCSI/USBSTOR)
    Linux    ID_SERIAL_SHORT (udev)         → USB yığını (usb_id) ya da
                                              SCSI INQUIRY VPD 0x80 (scsi_id)
    macOS    kUSBSerialNumberString (IOKit) → USB yığını, doğrudan tanımlayıcı

Windows'un depolama yığınından okuması işin can alıcı yeri: orada dönen
değer USB tanımlayıcısındaki dize OLMAK ZORUNDA DEĞİL. Aygıtın SCSI
köprüsü VPD 0x80 (Unit Serial Number) sayfası sunuyorsa Windows onu
tercih edebiliyor ve iki alan aynı aygıtta farklı olabiliyor.


ÖLÇÜLEN KANIT — iSerialNumber çoğu zaman YOK
---------------------------------------------
USB spec'inde `iSerialNumber` OPSİYONEL. Bu, teorik bir uyarı değil:
geliştirme makinesinde (Windows 11) `Win32_PnPEntity` ile listelenen
**12 USB aygıtının 12'sinde de** tanımlayıcı serisi yok. Hepsinin
PNPDeviceID'si şu biçimde:

    USB\\VID_046D&PID_C52B\\8&F2CB6FA&0&9
                            ^^^^^^^^^^^^^ Windows'un ÜRETTİĞİ kimlik

Serisi OLAN bir aygıtta üçüncü segment doğrudan seri dizesidir:

    USB\\VID_0781&PID_5567\\4C530001120523104381

Üretilen kimlik hub ve port yoluna bağlı: aygıt başka bir porta
takıldığında DEĞİŞİYOR. Yani serisiz bir çubukta kimlik ne platformlar
arasında ne de aynı makinede portlar arasında sabit.


HYCLEUS'ta durum bugün ne
-------------------------
`usb_manager._sanitize_hwid()` boş ya da "0" seri için
`_get_or_create_uuid()`'ye düşüyor ve o UUID `data_dir()/usb_ids.json`
içinde, YANİ MAKİNEYE ÖZEL tutuluyor. Sonuç:

    aynı USB + aynı makine   → aynı HWID  (JSON'dan)
    aynı USB + başka makine  → FARKLI HWID

Yani taşınabilirlik serisiz aygıtlarda ZATEN kırık — çapraz platform
sorununa gelmeden, tek platformda bile. Bu, aşağıdaki öneriyi tek başına
haklı çıkarıyor.
"""
from __future__ import annotations

import logging
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable

_log = logging.getLogger("hycleus.hwid_probe")

#: Windows'un serisi olmayan aygıtlar için ürettiği kimlik: ikinci karakteri
#: '&' olan segment. Bkz. Microsoft "Device instance IDs" — üretilen
#: kimliklerde ilk alan hub/port sayacıdır.
_GENERATED_INSTANCE_RE = re.compile(r"^[0-9a-fA-F]+&")

#: Windows'un depolama serilerinde gördüğümüz biçimlendirme: gruplar arası
#: alt çizgi ve sonda nokta. Ölçüm: NVMe diskinde '6479_A7FF_F000_0285.'
_WINDOWS_FORMATTING_RE = re.compile(r"[^0-9A-Za-z]")


@dataclass(frozen=True)
class UsbIdentity:
    """Tek bir USB depolama aygıtının okunabilen kimlik alanları."""

    platform: str
    source: str
    vendor_id: str | None = None
    product_id: str | None = None
    #: USB tanımlayıcısındaki iSerialNumber — YOKSA None.
    descriptor_serial: str | None = None
    #: Depolama/SCSI yığınının bildirdiği seri (Windows'ta asıl kullanılan).
    storage_serial: str | None = None
    #: Windows'ta üretilmiş (hub/port'a bağlı) kimlik mi.
    generated: bool = False
    raw: str | None = None

    @property
    def stable_id(self) -> str | None:
        """
        Platformlar arası KARŞILAŞTIRILABİLİR kimlik — yoksa None.

        Yalnızca tanımlayıcı serisi sayılıyor. Depolama serisi
        kullanılmıyor çünkü platformlar arası aynı olduğu garanti değil
        (bkz. modül docstring'i).
        """
        if self.generated or not self.descriptor_serial:
            return None
        return normalize_serial(self.descriptor_serial)


def normalize_serial(raw: str) -> str:
    """
    Seri dizesini platformlar arası karşılaştırılabilir hâle getirir.

    Windows depolama yığını serileri biçimlendirilmiş döndürüyor (ölçüm:
    `6479_A7FF_F000_0285.` — gruplar arası alt çizgi, sonda nokta). Linux
    ve macOS aynı aygıt için biçimlendirmesiz dize veriyor. Karşılaştırma
    yapılacaksa ikisinin de aynı biçime indirgenmesi gerekiyor.

    DİKKAT: bu normalleştirme biçim farkını kapatıyor, ALAN farkını
    kapatmıyor. İki platform farklı ALANLARI okuyorsa normalleştirme
    sonucu yine farklı olur.
    """
    return _WINDOWS_FORMATTING_RE.sub("", raw).upper().lstrip("0") or "0"


# ══════════════════════════════════════════════════════════════════════════════
# Windows — WMI
# ══════════════════════════════════════════════════════════════════════════════


def parse_windows_pnp_id(pnp_id: str) -> tuple[str | None, str | None, str, bool]:
    """
    `USB\\VID_xxxx&PID_yyyy\\<instance>` biçimini ayrıştırır.

    Returns:
        (vendor_id, product_id, instance, generated)

    `generated=True` ise `instance` bir SERİ NUMARASI DEĞİL, Windows'un
    hub/port'tan ürettiği kimliktir ve aygıt başka porta takılınca değişir.
    Bu ayrım, saf metin karşılaştırmasının neden yeterli olmadığının
    özeti — ikisi de aynı alanda duruyor.
    """
    parcalar = pnp_id.split("\\")
    vid = pid = None
    if len(parcalar) >= 2:
        m = re.search(r"VID_([0-9A-Fa-f]{4})", parcalar[1])
        vid = m.group(1).upper() if m else None
        m = re.search(r"PID_([0-9A-Fa-f]{4})", parcalar[1])
        pid = m.group(1).upper() if m else None
    instance = parcalar[2] if len(parcalar) >= 3 else ""
    return vid, pid, instance, bool(_GENERATED_INSTANCE_RE.match(instance))


def read_windows() -> list[UsbIdentity]:
    """
    Windows'ta USB depolama kimliklerini okur — İKİ yığından birden.

    `usb_manager.get_usb_hwid()` yalnızca depolama yığınına bakıyor. Burada
    ayrıca PNPDeviceID ayrıştırılıyor, çünkü tanımlayıcı serisinin VAR OLUP
    OLMADIĞI ancak oradan anlaşılıyor — depolama serisi boş değilse bile
    üretilmiş olabilir.
    """
    try:
        import wmi  # type: ignore[import]
    except ImportError:
        _log.info("wmi yok — Windows okuyucusu atlandı")
        return []

    sonuc: list[UsbIdentity] = []
    try:
        for disk in wmi.WMI().Win32_DiskDrive():
            if getattr(disk, "InterfaceType", "") != "USB":
                continue
            pnp = getattr(disk, "PNPDeviceID", "") or ""
            vid, pid, instance, generated = parse_windows_pnp_id(pnp)
            depolama = getattr(disk, "SerialNumber", None)
            sonuc.append(UsbIdentity(
                platform="windows",
                source="Win32_DiskDrive + PNPDeviceID",
                vendor_id=vid, product_id=pid,
                descriptor_serial=None if generated else (instance or None),
                storage_serial=str(depolama).strip() if depolama else None,
                generated=generated,
                raw=pnp,
            ))
    except Exception as exc:  # pragma: no cover — ortama bağlı
        _log.warning("WMI okunamadı: %s", exc)
    return sonuc


# ══════════════════════════════════════════════════════════════════════════════
# Linux — pyudev / sysfs
# ══════════════════════════════════════════════════════════════════════════════


def read_linux() -> list[UsbIdentity]:
    """
    Linux'ta USB depolama kimliklerini `pyudev` ile okur.

    Okunan alanlar:
        ID_SERIAL_SHORT  — asıl seri. `usb_id` builtin'i onu USB
                           tanımlayıcısındaki iSerialNumber'dan üretiyor;
                           aygıt SCSI VPD 0x80 sunuyorsa `scsi_id` oradan
                           da doldurabiliyor (ALAN BELİRSİZLİĞİ burada).
        ID_SERIAL        — bileşik: <vendor>_<model>_<serial>. Seri yoksa
                           yalnızca vendor_model kalıyor — "seri var mı"
                           sorusunun cevabı bu farkta.
        ID_VENDOR_ID / ID_MODEL_ID — VID/PID, Windows'takiyle karşılaştırılabilir.

    `pyudev` yoksa sysfs'e düşüyor: `/sys/block/<dev>/device/../../serial`
    USB aygıt düğümünün `serial` özniteliği ve o DOĞRUDAN iSerialNumber.
    sysfs yolu aslında daha KESİN — belirsizlik udev kurallarından geliyor.
    """
    if not sys.platform.startswith("linux"):
        return []
    try:
        import pyudev  # type: ignore[import]
    except ImportError:
        return _read_linux_sysfs()

    sonuc: list[UsbIdentity] = []
    try:
        ctx = pyudev.Context()
        for dev in ctx.list_devices(subsystem="block", DEVTYPE="disk"):
            if dev.get("ID_BUS") != "usb":
                continue
            seri = dev.get("ID_SERIAL_SHORT")
            sonuc.append(UsbIdentity(
                platform="linux",
                source="pyudev ID_SERIAL_SHORT",
                vendor_id=(dev.get("ID_VENDOR_ID") or "").upper() or None,
                product_id=(dev.get("ID_MODEL_ID") or "").upper() or None,
                descriptor_serial=seri or None,
                storage_serial=dev.get("ID_SCSI_SERIAL") or seri or None,
                generated=not seri,
                raw=dev.get("ID_SERIAL"),
            ))
    except Exception as exc:  # pragma: no cover — ortama bağlı
        _log.warning("pyudev okunamadı: %s", exc)
    return sonuc


def _read_linux_sysfs() -> list[UsbIdentity]:
    """
    pyudev olmadan sysfs'ten okur.

    `/sys/block/sdX/device` SCSI aygıtına, iki üst dizin USB aygıtına
    çıkıyor; oradaki `serial`, `idVendor`, `idProduct` doğrudan USB
    tanımlayıcısından geliyor — udev kurallarının belirsizliği yok.
    """
    from pathlib import Path

    sonuc: list[UsbIdentity] = []
    kok = Path("/sys/block")
    if not kok.is_dir():
        return sonuc

    for blok in sorted(kok.iterdir()):
        usb = (blok / "device").resolve().parent.parent
        seri_yolu = usb / "serial"
        if not seri_yolu.is_file():
            continue

        def _oku(ad: str) -> str | None:
            p = usb / ad
            try:
                return p.read_text(encoding="utf-8", errors="replace").strip() or None
            except OSError:
                return None

        seri = _oku("serial")
        sonuc.append(UsbIdentity(
            platform="linux",
            source="sysfs /sys/.../serial",
            vendor_id=(_oku("idVendor") or "").upper() or None,
            product_id=(_oku("idProduct") or "").upper() or None,
            descriptor_serial=seri,
            generated=not seri,
            raw=str(usb),
        ))
    return sonuc


# ══════════════════════════════════════════════════════════════════════════════
# macOS — IOKit (ioreg)
# ══════════════════════════════════════════════════════════════════════════════
#
# DÜRÜST SINIR: bu kod GERÇEK DONANIMDA ÇALIŞTIRILMADI. Elimde macOS test
# cihazı yok ve CI'da da yok. Aşağıdaki ayrıştırıcı `ioreg` çıktısının
# belgelenmiş biçimine göre yazıldı ve KAYDEDİLMİŞ örnek çıktı üzerinde
# test edildi (tests/test_hwid_probe.py). Canlı doğrulama yapılmadı;
# bir Mac'te ilk çalıştırmada ayrıştırma düzeltmesi gerekebilir.


#: `ioreg -p IOUSB -l` çıktısındaki alan adları. Anahtar olan
#: "USB Serial Number": IOKit bunu doğrudan aygıt tanımlayıcısının
#: iSerialNumber alanından dolduruyor — yani macOS, üç platform içinde
#: alanı en NET olanı.
_IOREG_SERIAL_RE = re.compile(r'"USB Serial Number"\s*=\s*"([^"]*)"')
_IOREG_VID_RE = re.compile(r'"idVendor"\s*=\s*(\d+)')
_IOREG_PID_RE = re.compile(r'"idProduct"\s*=\s*(\d+)')
_IOREG_NODE_RE = re.compile(r"^\s*\+-o ", re.MULTILINE)


def parse_ioreg(output: str) -> list[UsbIdentity]:
    """
    `ioreg -p IOUSB -l -w 0` çıktısını ayrıştırır.

    Çıktı ağaç biçiminde; her düğüm `+-o <ad>` ile başlıyor ve
    özellikleri onu izliyor. Düğüm sınırlarından bölüp her bloktan
    seri/VID/PID çıkarılıyor.

    Ayrı bir fonksiyon olması bilinçli: macOS olmadan test edilebilsin.
    Ayrıştırma mantığı test edilebiliyor, `ioreg`'in gerçekten böyle
    çıktı verdiği ise EDİLEMİYOR (bkz. yukarıdaki dürüst sınır).
    """
    sonuc: list[UsbIdentity] = []
    bloklar = _IOREG_NODE_RE.split(output)
    for blok in bloklar:
        m_seri = _IOREG_SERIAL_RE.search(blok)
        m_vid = _IOREG_VID_RE.search(blok)
        m_pid = _IOREG_PID_RE.search(blok)
        if not (m_seri or m_vid):
            continue
        seri = m_seri.group(1).strip() if m_seri else ""
        sonuc.append(UsbIdentity(
            platform="darwin",
            source="ioreg -p IOUSB (USB Serial Number)",
            vendor_id=f"{int(m_vid.group(1)):04X}" if m_vid else None,
            product_id=f"{int(m_pid.group(1)):04X}" if m_pid else None,
            descriptor_serial=seri or None,
            generated=not seri,
            raw=blok.splitlines()[0].strip() if blok.strip() else None,
        ))
    return sonuc


def read_macos(*, runner: Callable[[list[str]], str] | None = None) -> list[UsbIdentity]:
    """
    macOS'ta USB kimliklerini `ioreg` ile okur.

    `runner` testlerin kaydedilmiş çıktı verebilmesi için; normalde
    gerçek `ioreg` çağrılıyor.
    """
    if runner is None:
        if sys.platform != "darwin":
            return []

        def runner(cmd: list[str]) -> str:  # noqa: E306
            return subprocess.check_output(cmd, text=True, timeout=10)

    try:
        return parse_ioreg(runner(["ioreg", "-p", "IOUSB", "-l", "-w", "0"]))
    except Exception as exc:  # pragma: no cover — ortama bağlı
        _log.warning("ioreg okunamadı: %s", exc)
        return []


# ══════════════════════════════════════════════════════════════════════════════
# Karşılaştırma
# ══════════════════════════════════════════════════════════════════════════════


def read_current_platform() -> list[UsbIdentity]:
    """Bu platformda okunabilen USB kimlikleri."""
    if sys.platform == "win32":
        return read_windows()
    if sys.platform.startswith("linux"):
        return read_linux()
    if sys.platform == "darwin":
        return read_macos()
    return []


def compare(a: UsbIdentity, b: UsbIdentity) -> tuple[bool, str]:
    """
    İki platformdan okunan kimliğin AYNI aygıtı gösterip göstermediği.

    Returns:
        (eşleşiyor, gerekçe)

    Kararı `stable_id` veriyor; ikisinden biri None ise eşleştirme
    YAPILAMIYOR ve bu bir "hayır" değil, "bilinmiyor" — ayrımı korumak
    önemli, çünkü "seri yok" ile "seriler farklı" farklı sorunlar.
    """
    if a.stable_id is None or b.stable_id is None:
        eksik = [x.platform for x in (a, b) if x.stable_id is None]
        return False, f"tanımlayıcı serisi yok: {', '.join(eksik)}"
    if a.stable_id != b.stable_id:
        return False, f"seriler farklı: {a.stable_id} ≠ {b.stable_id}"
    if a.vendor_id and b.vendor_id and a.vendor_id != b.vendor_id:
        return False, f"VID farklı: {a.vendor_id} ≠ {b.vendor_id}"
    return True, f"eşleşiyor: {a.stable_id}"


def summarise(devices: list[UsbIdentity]) -> str:
    """İnsan okunur özet — prototip CLI'ı bunu basıyor."""
    if not devices:
        return "USB depolama aygıtı bulunamadı."
    satirlar = []
    for d in devices:
        kimlik = d.stable_id or "(yok)"
        satirlar.append(
            f"  {d.platform:8} {d.vendor_id or '????'}:{d.product_id or '????'}  "
            f"tanımlayıcı_seri={kimlik}  depolama_seri={d.storage_serial or '(yok)'}  "
            f"üretilmiş={'EVET' if d.generated else 'hayır'}"
        )
        satirlar.append(f"           kaynak: {d.source}")
    return "\n".join(satirlar)


if __name__ == "__main__":  # pragma: no cover — elle çalıştırılan prototip
    from CORE.console import ensure_utf8_console

    ensure_utf8_console()
    aygitlar = read_current_platform()
    print(f"Platform: {sys.platform}")
    print(summarise(aygitlar))
    kararsiz = [d for d in aygitlar if d.stable_id is None]
    if kararsiz:
        print(f"\nUYARI: {len(kararsiz)} aygıtta taşınabilir kimlik YOK.")
        print("Bu aygıtlar platformlar arasında (hatta portlar arasında)")
        print("aynı HWID'yi vermez — bkz. docs/hwid-crossplatform.md")
