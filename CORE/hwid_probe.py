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


DÜZELTİLDİ (B-022) — eskiden serili aygıta "serisiz" diyordu
-------------------------------------------------------------
2026-08-16'da gerçek HYCLEUS token USB'si takılı halde ölçüm yapıldı ve
aygıtın serisi ÇIKTI (bkz. BACKLOG.md / B-016). Bu modül ise ona
`üretilmiş=EVET, tanımlayıcı_seri=(yok)` demişti — yani ters yönde kanıt
üretiyordu.

Sebep `read_windows()`'un YALNIZCA `Win32_DiskDrive.PNPDeviceID`'yi
okumasıydı: o, USB yığını düğümü değil DEPOLAMA yığını düğümü ve seriye
`&0` örnek soneki ekliyor. Onaltılık görünen bir seri (`4C5303…`) artı
`&0`, `_GENERATED_INSTANCE_RE` desenine tam uyuyordu — SanDisk gibi
tümüyle onaltılık seri kullanan üreticilerde SİSTEMATİK bir yanlış
pozitif.

Artık iki yığın birden okunuyor ve seriyle eşleştiriliyor:

    Win32_DiskDrive   → depolama serisi + USBSTOR düğümü
    Win32_PnPEntity   → USB düğümü: VID, PID ve TANIMLAYICI serisi

"Üçüncü segmentte `&` yok → gerçek seri" kuralı yalnızca USB düğümünde
geçerli (Microsoft "Device instance IDs"); USBSTOR düğümünde değil. VID/PID
de yalnızca orada bulunuyor — eski kodun `????:????` basması bunun
belirtisiydi ama biçime yorulmuştu.

`usb_manager.get_usb_hwid()` bu hatadan hiç etkilenmemişti — o
`PNPDeviceID`'ye bakmıyor, doğrudan `SerialNumber` alanını okuyor.


ÖLÇÜLEN KANIT — iSerialNumber çoğu zaman YOK
---------------------------------------------
(Aşağıdaki sayım DOĞRU ama dar: sayılan 12 aygıt dahili çevre birimiydi.
USB *depolama* aygıtları seri taşıyor — 2026-08-16 ölçümünde aynı
makinedeki 14 USB düğümünden yalnızca token'da seri vardı.)

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

import argparse
import json
import logging
import re
import subprocess
import sys
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Callable

_log = logging.getLogger("hycleus.hwid_probe")

#: Windows'un serisi olmayan aygıtlar için ürettiği kimlik: ikinci karakteri
#: '&' olan segment. Bkz. Microsoft "Device instance IDs" — üretilen
#: kimliklerde ilk alan hub/port sayacıdır.
_GENERATED_INSTANCE_RE = re.compile(r"^[0-9a-fA-F]+&")

#: Windows'un depolama serilerinde gördüğümüz biçimlendirme: gruplar arası
#: alt çizgi ve sonda nokta. Ölçüm: NVMe diskinde '6479_A7FF_F000_0285.'
_WINDOWS_FORMATTING_RE = re.compile(r"[^0-9A-Za-z]")

#: USBSTOR düğümünün örnek kimliğine eklediği sonek: `<seri>&0`. Sondaki
#: rakam aygıtın LUN/örnek sayacı, serinin parçası DEĞİL. Ayıklanmadan
#: `_GENERATED_INSTANCE_RE`'ye verilirse onaltılık her seri "üretilmiş"
#: sanılır (B-022).
_USBSTOR_SUFFIX_RE = re.compile(r"&\d+$")


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

    BAŞTAKİ SIFIRLAR KIRPILMIYOR (B-022)
    ------------------------------------
    Bu fonksiyon eskiden sonda `.lstrip("0")` uyguluyordu. Amaç dolgu
    farklarını kapatmaktı ama sonuç ÇAKIŞMAYDI: `0123ABC` ile `123ABC`
    aynı değere iniyordu, yani iki FARKLI aygıt aynı kimliği alabiliyordu.
    Kimlik üreten bir fonksiyonda çakışma, kapatmaya çalıştığı biçim
    farkından çok daha ağır bir hata.

    Kırpmanın kapattığı varsayılan sorun ayrıca ÖLÇÜLMEMİŞTİ: elimizdeki
    hiçbir platform çiftinde aynı serinin farklı sıfır dolgusuyla geldiği
    görülmedi. Ölçülmemiş bir sorunu, ölçülebilir bir çakışma pahasına
    çözmek yanlış takas.

    DİKKAT: bu normalleştirme biçim farkını kapatıyor, ALAN farkını
    kapatmıyor. İki platform farklı ALANLARI okuyorsa normalleştirme
    sonucu yine farklı olur.
    """
    return _WINDOWS_FORMATTING_RE.sub("", raw).upper() or "0"


def usbstor_instance(instance: str) -> str:
    """
    USBSTOR örnek kimliğinden Windows'un eklediği `&<n>` sonekini ayıklar.

    `4C530301470118102554&0` → `4C530301470118102554`

    Sonek ayıklanmadan `_GENERATED_INSTANCE_RE`'ye verilirse onaltılık
    görünen HER seri "üretilmiş kimlik" sanılır — B-022'nin kök nedeni.
    """
    return _USBSTOR_SUFFIX_RE.sub("", instance)


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


def build_windows_identity(
    disk_pnp_id: str,
    storage_serial: str | None,
    usb_nodes: dict[str, tuple[str | None, str | None]],
) -> UsbIdentity:
    """
    Bir USB diskin iki yığındaki kaydını BİRLEŞTİRİR — WMI'siz, saf.

    Args:
        disk_pnp_id:    `Win32_DiskDrive.PNPDeviceID` (USBSTOR düğümü).
        storage_serial: `Win32_DiskDrive.SerialNumber`.
        usb_nodes:      USB yığını düğümleri, `{örnek_kimliği: (vid, pid)}`.
                        Yalnızca GERÇEK serisi olan düğümler (üçüncü
                        segmentinde `&` bulunmayanlar) burada.

    Eşleştirme USBSTOR örnek kimliğinden `&<n>` soneki atılarak yapılıyor;
    kalan dize, serisi olan bir aygıtta USB düğümünün örnek kimliğinin ta
    kendisi.

    Ayrı ve saf bir fonksiyon olması bilinçli: B-022'nin kök nedeni tam
    olarak burada yaşıyordu ve WMI olmadan test edilemiyordu. Artık iki
    gerçek `PNPDeviceID` dizesiyle sınanabiliyor.
    """
    _v, _p, ham_instance, _g = parse_windows_pnp_id(disk_pnp_id)
    instance = usbstor_instance(ham_instance)

    if instance in usb_nodes:
        vid, pid = usb_nodes[instance]
        return UsbIdentity(
            platform="windows",
            source="Win32_DiskDrive + Win32_PnPEntity (USB düğümü)",
            vendor_id=vid, product_id=pid,
            descriptor_serial=instance,
            storage_serial=str(storage_serial).strip() if storage_serial else None,
            generated=False,
            raw=disk_pnp_id,
        )

    # USB düğümü bulunamadı → tanımlayıcı serisi YOK sayılıyor. İki
    # olasılık var: aygıt gerçekten serisiz (Windows kimlik üretmiş) ya da
    # düğüm okunamadı. İkisini ayırt EDEMİYORUZ, o yüzden `stable_id`
    # None dönsün diye `generated=True` veriliyor — "bilmiyoruz"u
    # "biliyoruz" gibi göstermek, B-022'nin ters yönden tekrarı olurdu.
    return UsbIdentity(
        platform="windows",
        source="Win32_DiskDrive (USB düğümü eşleşmedi)",
        vendor_id=None, product_id=None,
        descriptor_serial=None,
        storage_serial=str(storage_serial).strip() if storage_serial else None,
        generated=True,
        raw=disk_pnp_id,
    )


def _windows_usb_nodes(wmi_modulu: Any) -> dict[str, tuple[str | None, str | None]]:
    """
    USB yığınındaki, GERÇEK serisi olan düğümler: `{seri: (vid, pid)}`.

    "Üçüncü segmentte `&` yok → gerçek seri" kuralı yalnızca burada
    geçerli (Microsoft "Device instance IDs").

    `generated` filtresi ÇAKIŞMAYI önlüyor ve gereklidir: serisiz bir
    diskin USBSTOR kimliği `7&1441131D&0`, `&0` ayıklanınca `7&1441131D`
    oluyor. Örnek kimliği tam olarak bu olan üretilmiş bir USB düğümü
    haritaya girerse ikisi eşleşir ve üretilmiş bir kimlik "tanımlayıcı
    serisi" diye raporlanır — B-022'nin ters yönden aynası. Bu senaryo
    mutasyon testinde ortaya çıktı ve `tests/test_hwid_probe.py::
    test_uretilmis_dugumler_haritaya_girmiyor` ile sabitlendi.

    Kök hub atlaması (`USB\\ROOT_HUB...`) ise fazladan bir emniyet: kök
    hub kimlikleri zaten üretilmiş olduğu için yukarıdaki filtreye
    takılıyorlar. Davranışı değiştirmiyor, niyeti okunur kılıyor.
    """
    dugumler: dict[str, tuple[str | None, str | None]] = {}
    for ent in wmi_modulu.WMI().Win32_PnPEntity():
        pnp = getattr(ent, "PNPDeviceID", "") or ""
        if not pnp.startswith("USB\\") or pnp.startswith("USB\\ROOT_HUB"):
            continue
        vid, pid, instance, generated = parse_windows_pnp_id(pnp)
        if generated or not instance:
            continue
        dugumler[instance] = (vid, pid)
    return dugumler


def read_windows() -> list[UsbIdentity]:
    """
    Windows'ta USB depolama kimliklerini okur — İKİ yığından birden.

    `usb_manager.get_usb_hwid()` yalnızca depolama yığınına bakıyor. Burada
    ayrıca USB yığını düğümü okunuyor, çünkü tanımlayıcı serisinin VAR OLUP
    OLMADIĞI ve VID/PID ancak oradan anlaşılıyor (B-022).
    """
    try:
        import wmi  # type: ignore[import]
    except ImportError:
        _log.info("wmi yok — Windows okuyucusu atlandı")
        return []

    sonuc: list[UsbIdentity] = []
    try:
        usb_dugumleri = _windows_usb_nodes(wmi)
        for disk in wmi.WMI().Win32_DiskDrive():
            if getattr(disk, "InterfaceType", "") != "USB":
                continue
            sonuc.append(build_windows_identity(
                getattr(disk, "PNPDeviceID", "") or "",
                getattr(disk, "SerialNumber", None),
                usb_dugumleri,
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


def to_dict(identity: UsbIdentity) -> dict[str, Any]:
    """
    `UsbIdentity`'yi JSON'a yazılabilir bir sözlüğe çevirir — 2026-08-29
    eklendi, gerçek çapraz platform karşılaştırmasını MÜMKÜN kılmak için.

    Bu okuyucular gerçek donanım gerektiriyor ve elde tek seferde tek
    platform oluyor (bkz. `docs/hwid-crossplatform.md`'nin "Sonraki adım
    için gereken" bölümü). Karşılaştırmayı canlı bellekte yapamıyoruz;
    bir platformun çıktısını dosyaya yazıp diğerine TAŞIMAK gerekiyor.

    `stable_id` BİLİNÇLİ OLARAK yazılmıyor: o bir `@property`, ham
    alanlardan (`generated`, `descriptor_serial`) HER ZAMAN yeniden
    hesaplanıyor. Onu da sözlüğe yazmak iki kaynağın (ham alanlar ile
    yazılmış değer) birbirinden sapabileceği bir çakışma alanı açardı —
    tam olarak bu depodaki "tek karar noktası" kuralının ihlali
    (bkz. `CORE/pin_rotation.py`'nin aynı gerekçesi). `from_dict()` ham
    alanlardan `UsbIdentity`'yi YENİDEN kuruyor, `stable_id` orada kendi
    kendine hesaplanıyor.
    """
    return {f.name: getattr(identity, f.name) for f in fields(identity)}


def from_dict(data: dict[str, Any]) -> UsbIdentity:
    """`to_dict()`'in tersi — bir JSON dump'ından `UsbIdentity` kurar."""
    return UsbIdentity(**data)


def dump_json(devices: list[UsbIdentity]) -> str:
    """Bu platformda okunan aygıtları JSON dizesine çevirir (`--json`)."""
    return json.dumps([to_dict(d) for d in devices], ensure_ascii=False, indent=2)


def load_json(text: str) -> list[UsbIdentity]:
    """`dump_json()`'un tersi — başka bir platformdan taşınan dosyayı okur."""
    return [from_dict(d) for d in json.loads(text)]


def compare_all(
    a: list[UsbIdentity], b: list[UsbIdentity]
) -> list[tuple[UsbIdentity, UsbIdentity, bool, str]]:
    """
    İki platform dump'ındaki OLASI TÜM aygıt çiftlerini karşılaştırır.

    Her iki taraf da birden çok USB depolama aygıtı içerebilir (ör. dahili
    kart okuyucu + gerçek token). Hangi çiftin "asıl" karşılaştırma olduğu
    burada BİLİNEMİYOR — kullanıcı hangi aygıtın aynı fiziksel çubuk
    olduğunu biliyor, bu fonksiyon değil. Bu yüzden tek bir karar
    dönmüyor: TÜM çiftler, her biri kendi `compare()` sonucuyla dönüyor;
    çağıran (`main()` ya da bir insan) gerçek eşleşmeyi seçiyor.
    """
    return [(x, y, *compare(x, y)) for x in a for y in b]


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


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════
#
# Kullanim:
#     python -m CORE.hwid_probe                    → bu platformun ozeti (eski davranis)
#     python -m CORE.hwid_probe --json > win.json   → dosyaya yaz, DIGER platforma tasi
#     python -m CORE.hwid_probe --compare win.json linux.json
#
# Cikis kodlari (backup_cli.py ile AYNI desen — bir betik ya da zamanlanmis
# bir is okuyabilsin diye):
#     0  --compare: en az bir aygit ciftinde AYNI kimlik bulundu
#        (--json / varsayilan mod: her zaman 0, bunlar bir iddia
#        SINAMIYOR, yalniz okuyor)
#     1  --compare: hicbir ciftte eslesme yok
#     2  kullanim hatasi (argparse)
#
# BU IKI BAYRAK, "aynı USB çubuğu üç işletim sisteminde de takılıp ...
# çıktılar karşılaştırılmalı" adımını (docs/hwid-crossplatform.md, "Sonraki
# adım için gereken") somut, çalıştırılabilir bir betiğe çeviriyor. Önceden
# bu adım "elle bak ve karşılaştır" demekti; artık --json iki dosya
# üretiyor ve --compare onları OTOMATIK karşılaştırıyor.


def main(argv: list[str] | None = None) -> int:
    from CORE.console import ensure_utf8_console

    ensure_utf8_console()

    p = argparse.ArgumentParser(
        prog="hwid_probe.py",
        description=(
            "HYCLEUS — capraz platform USB kimligi PROTOTIPI. Uygulamaya "
            "bagli DEGIL (bkz. modul dosya-ustu docstring'i)."
        ),
    )
    p.add_argument("--json", action="store_true",
                    help="Ozet yerine JSON dump bas (baska platforma tasimak icin)")
    p.add_argument("--compare", nargs=2, metavar=("A.json", "B.json"),
                    help="Iki platformdan --json ile alinmis dump'i karsilastir")
    args = p.parse_args(argv)

    if args.compare:
        yol_a, yol_b = args.compare
        aygitlar_a = load_json(Path(yol_a).read_text(encoding="utf-8"))
        aygitlar_b = load_json(Path(yol_b).read_text(encoding="utf-8"))
        sonuclar = compare_all(aygitlar_a, aygitlar_b)
        if not sonuclar:
            print("Karsilastirilacak aygit cifti yok (dosyalardan biri bos).")
            return 1
        eslesen = False
        for x, y, ok, neden in sonuclar:
            eslesen = eslesen or ok
            print(f"  {x.platform} x {y.platform}: {'ESLESIYOR' if ok else 'hayir'} — {neden}")
        return 0 if eslesen else 1

    aygitlar = read_current_platform()
    if args.json:
        print(dump_json(aygitlar))
        return 0

    print(f"Platform: {sys.platform}")
    print(summarise(aygitlar))
    kararsiz = [d for d in aygitlar if d.stable_id is None]
    if kararsiz:
        print(f"\nUYARI: {len(kararsiz)} aygıtta taşınabilir kimlik YOK.")
        print("Bu aygıtlar platformlar arasında (hatta portlar arasında)")
        print("aynı HWID'yi vermez — bkz. docs/hwid-crossplatform.md")
    return 0


if __name__ == "__main__":  # pragma: no cover — elle çalıştırılan prototip
    sys.exit(main())
