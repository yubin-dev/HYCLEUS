"""
CORE.hwid_probe — çapraz platform USB kimliği prototipinin testleri (3.4).

Neyin test EDİLEBİLDİĞİ, neyin edilemediği
-----------------------------------------
Bu prototip donanım okuyor; CI'da fiziksel USB yok ve elimde Linux/macOS
test cihazı da yok. Dolayısıyla test edilen şey **ayrıştırma mantığı**:
her platformun gerçek araç çıktısı KAYDEDİLMİŞ örnekler olarak veriliyor
ve doğru alanların çıkarıldığı doğrulanıyor.

Test EDİLEMEYEN, açıkça söylenmesi gereken: `ioreg`, `pyudev` ve WMI'nin
gerçekten bu biçimde çıktı verdiği. Windows örnekleri bu makineden GERÇEK
olarak alındı; Linux ve macOS örnekleri belgelenmiş biçimlere göre
yazıldı ve canlı doğrulanmadı.

Bu ayrım korunmalı — "testler geçiyor" ile "üç platformda çalışıyor"
aynı şey değil ve bu modülde arası açık.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from CORE.hwid_probe import (
    UsbIdentity,
    compare,
    compare_all,
    dump_json,
    from_dict,
    load_json,
    main,
    normalize_serial,
    parse_ioreg,
    parse_windows_pnp_id,
    read_linux,
    read_macos,
    summarise,
    read_windows,
    build_windows_identity,
    to_dict,
    usbstor_instance,
)

# ══════════════════════════════════════════════════════════════════════════════
# Kaydedilmiş gerçek çıktılar
# ══════════════════════════════════════════════════════════════════════════════

#: GERÇEK — geliştirme makinesinden (Windows 11) alındı. On iki USB
#: aygıtının hiçbirinde tanımlayıcı serisi yok; üçüncü segment Windows'un
#: hub/port'tan ürettiği kimlik.
_GERCEK_WINDOWS_PNP = [
    r"USB\VID_046D&PID_C52B&MI_01\9&2F9A62E0&0&0001",
    r"USB\VID_05E3&PID_0608\6&26C36CB0&0&1",
    r"USB\VID_0C45&PID_7672\7&1441131D&0&3",
    r"USB\VID_048D&PID_5702\8&F2CB6FA&0&16",
]

#: Serisi OLAN bir USB çubuğun PNPDeviceID'si (SanDisk Cruzer biçimi).
_SERILI_WINDOWS_PNP = r"USB\VID_0781&PID_5567\4C530001120523104381"

#: `ioreg -p IOUSB -l -w 0` çıktısının belgelenmiş biçimi. CANLI
#: DOĞRULANMADI — modül docstring'indeki dürüst sınıra bakın.
_IOREG_ORNEK = """
+-o Root Hub Simulation Simulation@14000000  <class AppleUSBRootHubDevice>
    {
      "idProduct" = 32773
      "idVendor" = 32902
      "USB Serial Number" = ""
    }
    +-o Cruzer Blade@14100000  <class IOUSBHostDevice, id 0x100000abc>
        {
          "idProduct" = 21863
          "idVendor" = 1921
          "USB Product Name" = "Cruzer Blade"
          "USB Serial Number" = "4C530001120523104381"
          "USB Vendor Name" = "SanDisk"
        }
    +-o USB2.0 Hub@14200000  <class IOUSBHostDevice, id 0x100000def>
        {
          "idProduct" = 1544
          "idVendor" = 1507
          "USB Serial Number" = ""
        }
"""


# ══════════════════════════════════════════════════════════════════════════════
# 1. Windows PNPDeviceID ayrıştırması
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("pnp", _GERCEK_WINDOWS_PNP)
def test_real_windows_devices_have_no_descriptor_serial(pnp: str) -> None:
    """
    ANA BULGU — ölçüm, varsayım değil.

    Geliştirme makinesindeki USB aygıtlarının hiçbirinde iSerialNumber
    yok. Üçüncü segment Windows'un ürettiği, hub/port'a bağlı kimlik:
    aygıt başka porta takılınca değişiyor.
    """
    _vid, _pid, instance, generated = parse_windows_pnp_id(pnp)
    assert generated is True, f"{instance} seri sanıldı ama üretilmiş kimlik"


def test_a_device_with_a_serial_is_recognised() -> None:
    vid, pid, instance, generated = parse_windows_pnp_id(_SERILI_WINDOWS_PNP)
    assert (vid, pid) == ("0781", "5567")
    assert instance == "4C530001120523104381"
    assert generated is False


def test_vid_and_pid_are_extracted_from_real_ids() -> None:
    vid, pid, _i, _g = parse_windows_pnp_id(_GERCEK_WINDOWS_PNP[0])
    assert (vid, pid) == ("046D", "C52B")


def test_a_malformed_id_does_not_crash() -> None:
    assert parse_windows_pnp_id("SCSI\\DISK&VEN_NVME") == (None, None, "", False)
    assert parse_windows_pnp_id("") == (None, None, "", False)


# ══════════════════════════════════════════════════════════════════════════════
# 1b. B-022 — iki yığın, iki düğüm
# ══════════════════════════════════════════════════════════════════════════════
#
# Aşağıdaki iki dize 2026-08-16'da gerçek HYCLEUS token USB'si takılıyken
# ölçüldü. Seri maskeli: `hwid`, kasa imza anahtarının HKDF girdisi
# (CORE/vault_manager.py::_derive_signing_key), yani depoya yazılmamalı.
# Maskeleme testin ölçtüğü şeyi değiştirmiyor — önemli olan BİÇİM.

#: Depolama yığını düğümü. Dikkat: seriye `&0` soneki eklenmiş.
_USBSTOR_PNP = (
    r"USBSTOR\DISK&VEN_SANDISK&PROD_CRUZER_BLADE&REV_1.00"
    r"\4C53AAAABBBBCCCCDDDD&0"
)

#: Aynı aygıtın USB yığını düğümü. Üçüncü segment SERİNİN KENDİSİ.
_USB_PNP = r"USB\VID_0781&PID_5567\4C53AAAABBBBCCCCDDDD"

_SERI = "4C53AAAABBBBCCCCDDDD"


def test_usbstor_soneki_ayikaniyor() -> None:
    """`<seri>&0` → `<seri>`. B-022'nin kök nedeni bu sonekti."""
    assert usbstor_instance(f"{_SERI}&0") == _SERI
    assert usbstor_instance(f"{_SERI}&12") == _SERI
    assert usbstor_instance(_SERI) == _SERI


def test_usbstor_soneki_uretilmis_kimligi_bozmuyor() -> None:
    """
    Üretilmiş kimlikler de `&<n>` ile bitebiliyor; ayıklama onları
    "gerçek seri"ye çevirmemeli — geriye hâlâ `&` kalıyor.
    """
    uretilmis = usbstor_instance("7&1441131D&0")
    assert "&" in uretilmis


def test_REGRESYON_serili_aygita_serisiz_denmiyor() -> None:
    """
    B-022 REGRESYON TESTİ #1 — hatanın ta kendisi.

    Prototip, serisi OLAN token'a `üretilmiş=EVET, tanımlayıcı_seri=(yok)`
    diyordu. Sebep: `Win32_DiskDrive.PNPDeviceID` USBSTOR düğümü ve seriye
    `&0` ekliyor; onaltılık bir seri artı `&0`, "üretilmiş kimlik"
    desenine (`^[0-9a-fA-F]+&`) tam uyuyor. SanDisk için SİSTEMATİK.

    Bu, ters yönde kanıt üreten bir ölçüm aracıydı: B-016 kararı buna
    bakarak verilseydi gereksiz bir mimari geçiş başlatılırdı.
    """
    kimlik = build_windows_identity(
        _USBSTOR_PNP, _SERI, {_SERI: ("0781", "5567")}
    )
    assert kimlik.generated is False
    assert kimlik.descriptor_serial == _SERI
    assert kimlik.stable_id == _SERI
    assert (kimlik.vendor_id, kimlik.product_id) == ("0781", "5567")


def test_REGRESYON_vid_pid_usb_dugumunden_geliyor() -> None:
    """
    B-022 REGRESYON TESTİ #2 — `????:????` çıktısının sebebi.

    USBSTOR düğümünde VID/PID YOK. Eski kod yalnızca oraya baktığı için
    ikisi de None kalıyordu ve çıktıda `????:????` görünüyordu. Bu, kök
    nedenin görünen belirtisiydi ama biçime yorulmuştu.

    Buradaki iddia: USB düğümü eşleşmezse VID/PID uydurulmamalı ve seri
    "var" sayılmamalı.
    """
    # USBSTOR tek başına ayrıştırıldığında VID/PID vermiyor.
    vid, pid, _i, _g = parse_windows_pnp_id(_USBSTOR_PNP)
    assert (vid, pid) == (None, None)

    # USB düğümü haritada yoksa iddia edilmiyor.
    eslesmeyen = build_windows_identity(_USBSTOR_PNP, _SERI, {})
    assert eslesmeyen.vendor_id is None
    assert eslesmeyen.descriptor_serial is None
    assert eslesmeyen.generated is True
    assert eslesmeyen.stable_id is None

    # Ama depolama serisi yine de raporlanıyor — bilgi kaybı yok.
    assert eslesmeyen.storage_serial == _SERI


def test_gercekten_serisiz_aygit_hala_serisiz_raporlaniyor() -> None:
    """
    Düzeltme YALNIZCA yanlış pozitifi kaldırmalı.

    Bu test olmadan "her şeye seri var de" mutasyonu da geçerdi.
    """
    serisiz_usbstor = (
        r"USBSTOR\DISK&VEN_GENERIC&PROD_FLASH&REV_1.00\7&1441131D&0"
    )
    kimlik = build_windows_identity(serisiz_usbstor, None, {})
    assert kimlik.generated is True
    assert kimlik.stable_id is None


class _SahteAygit:
    def __init__(self, **alanlar):
        self.__dict__.update(alanlar)


class _SahteWMI:
    """`wmi.WMI()` yerine geçen asgari sahte — gerçek donanım gerekmesin."""

    def __init__(self, diskler, varliklar):
        self._diskler = diskler
        self._varliklar = varliklar

    def WMI(self):  # noqa: N802 — wmi paketinin API'si
        return self

    def Win32_DiskDrive(self):  # noqa: N802
        return self._diskler

    def Win32_PnPEntity(self):  # noqa: N802
        return self._varliklar


def test_read_windows_iki_okuyucuyu_birlestiriyor(monkeypatch) -> None:
    """
    UÇTAN UCA — `_windows_usb_nodes()` ile `build_windows_identity()`
    arasındaki bağlantı.

    Saf fonksiyon ayrı ayrı sınanıyor ama ikisini birbirine bağlayan kod
    (hangi düğümler haritaya giriyor, eşleştirme gerçekten oluyor mu)
    yalnızca burada kapsanıyor. Gerçek donanım gerekmiyor: `wmi` modülü
    sahtesiyle değiştiriliyor.
    """
    import sys

    sahte = _SahteWMI(
        diskler=[
            _SahteAygit(
                InterfaceType="USB", PNPDeviceID=_USBSTOR_PNP, SerialNumber=_SERI
            ),
            # USB olmayan disk atlanmalı.
            _SahteAygit(
                InterfaceType="SCSI", PNPDeviceID=r"SCSI\DISK&VEN_NVME\x",
                SerialNumber="NVME1",
            ),
        ],
        varliklar=[
            _SahteAygit(PNPDeviceID=_USB_PNP),
            # Kök hub haritaya GİRMEMELİ.
            _SahteAygit(PNPDeviceID=r"USB\ROOT_HUB30\5&18297C0C&0&0"),
            # Serisiz aygıt haritaya GİRMEMELİ.
            _SahteAygit(PNPDeviceID=_GERCEK_WINDOWS_PNP[0]),
        ],
    )
    monkeypatch.setitem(sys.modules, "wmi", sahte)

    sonuc = read_windows()

    assert len(sonuc) == 1, "USB olmayan disk de raporlanmış"
    (kimlik,) = sonuc
    assert kimlik.stable_id == _SERI
    assert kimlik.generated is False
    assert (kimlik.vendor_id, kimlik.product_id) == ("0781", "5567")


def test_uretilmis_dugumler_haritaya_girmiyor(monkeypatch) -> None:
    """
    ÇAKIŞMA KORUMASI — `generated` filtresi olmadan yanlış eşleşme olur.

    Serisiz bir USB diskin USBSTOR örnek kimliği `7&1441131D&0`; `&0`
    ayıklanınca geriye `7&1441131D` kalıyor. Aynı makinede örnek kimliği
    tam olarak `7&1441131D` olan ÜRETİLMİŞ bir USB düğümü varsa, filtre
    olmadan ikisi eşleşir ve prototip üretilmiş bir kimliği "tanımlayıcı
    serisi" diye raporlar — B-022'nin aynası, ters yönden.

    Bu senaryo mutasyon testinde ortaya çıktı: `generated` filtresini
    kaldıran mutasyon hayatta kalmıştı, çünkü hiçbir test çakışmayı
    kurmuyordu.
    """
    import sys

    carpisan = "7&1441131D"
    sahte = _SahteWMI(
        diskler=[
            _SahteAygit(
                InterfaceType="USB",
                PNPDeviceID=(
                    r"USBSTOR\DISK&VEN_GENERIC&PROD_FLASH&REV_1.00"
                    rf"\{carpisan}&0"
                ),
                SerialNumber=None,
            )
        ],
        varliklar=[_SahteAygit(PNPDeviceID=rf"USB\VID_1234&PID_5678\{carpisan}")],
    )
    monkeypatch.setitem(sys.modules, "wmi", sahte)

    (kimlik,) = read_windows()
    assert kimlik.generated is True, "üretilmiş kimlik seri sanıldı"
    assert kimlik.stable_id is None


def test_usb_dugum_haritasi_iki_yigini_baglıyor() -> None:
    """
    Eşleştirmenin sözleşmesi: USBSTOR örnek kimliği (`&<n>` atılmış hâli)
    USB düğümünün örnek kimliğine EŞİT olmalı. İki gerçek dize üzerinde.
    """
    _v, _p, usb_instance, generated = parse_windows_pnp_id(_USB_PNP)
    _v2, _p2, stor_instance, _g2 = parse_windows_pnp_id(_USBSTOR_PNP)

    assert generated is False
    assert usbstor_instance(stor_instance) == usb_instance


# ══════════════════════════════════════════════════════════════════════════════
# 2. macOS ioreg ayrıştırması
# ══════════════════════════════════════════════════════════════════════════════


def test_ioreg_finds_the_device_with_a_serial() -> None:
    aygitlar = parse_ioreg(_IOREG_ORNEK)
    serili = [d for d in aygitlar if d.descriptor_serial]
    assert len(serili) == 1
    assert serili[0].descriptor_serial == "4C530001120523104381"
    assert serili[0].vendor_id == "0781"     # 1921 == 0x0781, SanDisk
    assert serili[0].product_id == "5567"    # 21863 == 0x5567


def test_ioreg_marks_serialless_devices_as_generated() -> None:
    """Boş `USB Serial Number` "seri yok" demek — boş dize sayılmamalı."""
    aygitlar = parse_ioreg(_IOREG_ORNEK)
    serisiz = [d for d in aygitlar if d.generated]
    assert len(serisiz) == 2
    assert all(d.stable_id is None for d in serisiz)


def test_ioreg_reports_the_documented_source() -> None:
    """Hangi alanın okunduğu çıktıda görünmeli — mimari kararın dayanağı."""
    aygitlar = parse_ioreg(_IOREG_ORNEK)
    assert "USB Serial Number" in aygitlar[0].source


def test_empty_ioreg_output_is_harmless() -> None:
    assert parse_ioreg("") == []


def test_read_macos_accepts_an_injected_runner() -> None:
    """
    macOS olmadan tam yolun koşabilmesi için `runner` enjekte edilebiliyor.
    Gerçek `ioreg` çağrısı bu ortamda DOĞRULANAMIYOR.
    """
    aygitlar = read_macos(runner=lambda cmd: _IOREG_ORNEK)
    assert any(d.descriptor_serial == "4C530001120523104381" for d in aygitlar)


def test_read_macos_survives_a_failing_runner() -> None:
    def _patlar(cmd):
        raise FileNotFoundError("ioreg yok")

    assert read_macos(runner=_patlar) == []


# ══════════════════════════════════════════════════════════════════════════════
# 3. Normalleştirme
# ══════════════════════════════════════════════════════════════════════════════


def test_windows_formatting_is_stripped() -> None:
    """
    GERÇEK ÖLÇÜM: bu makinedeki NVMe diskinin Windows serisi
    `6479_A7FF_F000_0285.` — alt çizgili ve sonu noktalı. Linux aynı
    aygıt için biçimlendirmesiz dize veriyor.
    """
    assert normalize_serial("6479_A7FF_F000_0285.") == "6479A7FFF0000285"


def test_case_is_normalised() -> None:
    assert normalize_serial("4c530001120523104381") == normalize_serial(
        "4C530001120523104381")


def test_bastaki_sifirlar_KIRPILMIYOR() -> None:
    """
    DAVRANIŞ DEĞİŞİKLİĞİ (B-022) — bu testin iddiası BİLEREK tersine çevrildi.

    Eski hâli `assert normalize_serial("0004C53") == "4C53"` idi, yani
    `.lstrip("0")` davranışını SABİTLİYORDU. O kırpma bir çakışma
    üretiyordu: iki FARKLI aygıtın serisi aynı kimliğe iniyordu.

    Kimlik üreten bir fonksiyonda çakışma, kapatmaya çalıştığı dolgu
    farkından ağır basar — üstelik o dolgu farkının gerçekten var olduğu
    hiç ölçülmemişti.
    """
    assert normalize_serial("0004C53") == "0004C53"
    assert normalize_serial("0123ABC") != normalize_serial("123ABC")


def test_sifirla_baslayan_iki_seri_cakismiyor() -> None:
    """
    Kırpmanın somut zararı: eskiden bu üçü de "4C53" oluyordu.

    `stable_id` bu değeri platformlar arası KİMLİK olarak kullanıyor,
    yani çakışma "iki farklı USB aynı token sayılır" demekti.
    """
    seriler = ["04C53", "004C53", "0004C53", "4C53"]
    assert len({normalize_serial(s) for s in seriler}) == len(seriler)


def test_normalisation_does_not_invent_an_id() -> None:
    """
    Alfanümerik hiçbir karakter kalmazsa "0" dönüyor — boş dize değil.

    Tamamen sıfırlardan oluşan bir seri artık OLDUĞU GİBİ kalıyor
    ("0000" → "0000"); eskiden kırpılıp "0"a iniyordu. İkisi farklı
    aygıtların bildirdiği farklı dizeler ve öyle kalmalı.
    """
    assert normalize_serial("----") == "0"
    assert normalize_serial("") == "0"
    assert normalize_serial("0000") == "0000"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Karşılaştırma — "eşleşmiyor" ile "bilinmiyor" farkı
# ══════════════════════════════════════════════════════════════════════════════


def _kimlik(platform: str, seri: str | None, *, vid="0781", generated=False):
    return UsbIdentity(
        platform=platform, source="test", vendor_id=vid, product_id="5567",
        descriptor_serial=seri, generated=generated,
    )


def test_the_same_serial_matches_across_platforms() -> None:
    ok, neden = compare(
        _kimlik("windows", "4C530001120523104381"),
        _kimlik("linux", "4c530001120523104381"),
    )
    assert ok, neden


def test_windows_formatting_does_not_break_the_match() -> None:
    ok, _ = compare(
        _kimlik("windows", "4C53_0001_1205_2310_4381."),
        _kimlik("linux", "4C530001120523104381"),
    )
    assert ok


def test_different_serials_do_not_match() -> None:
    ok, neden = compare(
        _kimlik("windows", "AAAA"), _kimlik("linux", "BBBB"))
    assert not ok and "seriler farklı" in neden


def test_a_missing_serial_is_unknown_not_a_mismatch() -> None:
    """
    "Seri yok" ile "seriler farklı" FARKLI sorunlar ve gerekçe metni
    ikisini ayırt etmeli — biri format uyumsuzluğu, diğeri aygıtın
    kimliğinin hiç olmaması.
    """
    ok, neden = compare(
        _kimlik("windows", None, generated=True),
        _kimlik("linux", "4C53"),
    )
    assert not ok
    assert "tanımlayıcı serisi yok" in neden
    assert "windows" in neden


def test_a_vid_mismatch_is_reported() -> None:
    ok, neden = compare(
        _kimlik("windows", "4C53", vid="0781"),
        _kimlik("linux", "4C53", vid="0930"),
    )
    assert not ok and "VID farklı" in neden


def test_a_generated_id_is_never_a_stable_id() -> None:
    """
    Windows'un ürettiği kimlik metin olarak dolu ama TAŞINABİLİR DEĞİL;
    `stable_id` bunu None yapmalı, yoksa port değişince kimlik değişirdi.
    """
    d = _kimlik("windows", "8&F2CB6FA&0&16", generated=True)
    assert d.stable_id is None


# ══════════════════════════════════════════════════════════════════════════════
# 5. Özet çıktısı
# ══════════════════════════════════════════════════════════════════════════════


def test_the_summary_flags_devices_without_a_portable_id() -> None:
    metin = summarise([
        _kimlik("windows", None, generated=True),
        _kimlik("linux", "4C53"),
    ])
    assert "üretilmiş=EVET" in metin
    assert "tanımlayıcı_seri=(yok)" in metin


def test_the_summary_names_the_source_field() -> None:
    """Hangi alandan okunduğu görünmeli — mimari tartışmanın dayanağı bu."""
    metin = summarise(parse_ioreg(_IOREG_ORNEK))
    assert "USB Serial Number" in metin


def test_an_empty_list_is_reported_clearly() -> None:
    assert "bulunamadı" in summarise([])


# ══════════════════════════════════════════════════════════════════════════════
# 6. Bu platformda gerçek okuma
# ══════════════════════════════════════════════════════════════════════════════


def test_reading_the_current_platform_does_not_crash() -> None:
    """
    Donanım yoksa boş liste dönmeli, istisna değil. CI'da fiziksel USB
    yok; sınanan şey yalnızca yolun güvenli olduğu.
    """
    from CORE.hwid_probe import read_current_platform

    aygitlar = read_current_platform()
    assert isinstance(aygitlar, list)
    assert all(isinstance(d, UsbIdentity) for d in aygitlar)



# ══════════════════════════════════════════════════════════════════════════════
# 7. Gerçek çapraz platform karşılaştırması — JSON dump + --compare (2026-08-29)
# ══════════════════════════════════════════════════════════════════════════════
#
# Bu bölümden ÖNCEKİ testler (1-6) yalnızca AYRIŞTIRMA mantığını sınıyor.
# Burada sınanan, "aynı USB çubuğu üç işletim sisteminde de takılıp
# çıktılar karşılaştırılmalı" adımının kendisini gerçekleştiren ARAÇ:
# `--json` bir platformun okumasını dosyaya yazılabilir hâle getiriyor,
# `--compare` iki dosyayı karşılaştırıyor. Bu araç da GERÇEK donanım
# gerektirmiyor — girdisi zaten serileştirilmiş veri, sınanan şey
# round-trip'in ve karşılaştırma mantığının kendisi.


def _kimlik(platform: str, seri: str | None, *, vid="0781", generated=False):
    return UsbIdentity(
        platform=platform, source="test", vendor_id=vid, product_id="5567",
        descriptor_serial=seri, generated=generated,
    )


def test_to_dict_from_dict_ROUND_TRIP() -> None:
    """Serileştirme kayıpsız olmalı — `stable_id` hariç, o türetilmiş."""
    orijinal = _kimlik("windows", "4C53AAAA")
    geri = from_dict(to_dict(orijinal))
    assert geri == orijinal
    assert geri.stable_id == orijinal.stable_id


def test_to_dict_stable_id_YAZMIYOR() -> None:
    """
    `stable_id` bir `@property` — sözlükte AYRI bir anahtar olarak
    durmamalı, yoksa ham alanlarla yazılmış değer birbirinden sapabilir
    (bkz. fonksiyon docstring'i, CORE/pin_rotation.py'nin aynı gerekçesi).
    """
    d = to_dict(_kimlik("windows", "4C53AAAA"))
    assert "stable_id" not in d


def test_dump_json_load_json_ROUND_TRIP() -> None:
    orijinal = [_kimlik("windows", "4C53AAAA"), _kimlik("windows", None, generated=True)]
    geri = load_json(dump_json(orijinal))
    assert geri == orijinal


def test_dump_json_turkce_karakterleri_KACIRMIYOR() -> None:
    """`ensure_ascii=False` — kaynak alanı Türkçe metin içerebiliyor
    (ör. `build_windows_identity`'nin "eşleşmedi" mesajı)."""
    d = _kimlik("windows", "4C53AAAA")
    d = UsbIdentity(**{**to_dict(d), "source": "Win32_DiskDrive (eşleşmedi)"})
    metin = dump_json([d])
    assert "eşleşmedi" in metin
    assert "\\u" not in metin


def test_compare_all_ESLESEN_cifti_buluyor() -> None:
    a = [_kimlik("windows", "AAAA", vid="0781"), _kimlik("windows", None, generated=True)]
    b = [_kimlik("linux", "AAAA", vid="0781")]
    sonuclar = compare_all(a, b)
    assert len(sonuclar) == 2, "kartezyen çarpım eksik — bazı çiftler atlanmış"
    eslesenler = [(x, y) for x, y, ok, _ in sonuclar if ok]
    assert len(eslesenler) == 1
    assert eslesenler[0][0].descriptor_serial == "AAAA"


def test_compare_all_HICBIR_cift_eslesmezse_BOS_donmuyor() -> None:
    """Eşleşme yokluğu, karşılaştırmanın YAPILMADIĞI anlamına gelmemeli —
    her çift kendi (False, gerekçe) sonucuyla dönmeli."""
    a = [_kimlik("windows", "AAAA")]
    b = [_kimlik("linux", "BBBB")]
    (sonuc,) = compare_all(a, b)
    _x, _y, ok, neden = sonuc
    assert ok is False
    assert "farklı" in neden


def test_compare_all_bos_listeyle_BOS_donuyor() -> None:
    assert compare_all([], [_kimlik("linux", "AAAA")]) == []


# ── CLI: --json ve --compare ─────────────────────────────────────────────────


def test_cli_json_bayragi_gecerli_JSON_basiyor(capsys, monkeypatch) -> None:
    """`--json` çıktısı `load_json()` ile GERİ okunabilmeli — bu, bir
    platformda üretilip diğerine taşınacak dosyanın ta kendisi."""
    from CORE import hwid_probe as modul

    monkeypatch.setattr(modul, "read_current_platform", lambda: [_kimlik("windows", "AAAA")])
    rc = main(["--json"])
    assert rc == 0
    cikti = capsys.readouterr().out
    (aygit,) = load_json(cikti)
    assert aygit.descriptor_serial == "AAAA"


def test_cli_compare_ESLESIRSE_cikis_kodu_0(tmp_path, capsys) -> None:
    a = tmp_path / "windows.json"
    b = tmp_path / "linux.json"
    a.write_text(dump_json([_kimlik("windows", "AAAA")]), encoding="utf-8")
    b.write_text(dump_json([_kimlik("linux", "aaaa")]), encoding="utf-8")

    rc = main(["--compare", str(a), str(b)])
    assert rc == 0
    assert "ESLESIYOR" in capsys.readouterr().out


def test_cli_compare_ESLESMEZSE_cikis_kodu_1(tmp_path, capsys) -> None:
    """
    Bu paketin ana iddiası — MUTASYON KANITI olmadan da doğrudan gözlenir:
    `--compare` başarısız bir eşleşmede sıfırdan farklı çıkış kodu
    dönmezse, bir CI/betik akışı sessizce "sorun yok" sanabilirdi.
    """
    a = tmp_path / "windows.json"
    b = tmp_path / "linux.json"
    a.write_text(dump_json([_kimlik("windows", "AAAA")]), encoding="utf-8")
    b.write_text(dump_json([_kimlik("linux", "ZZZZ")]), encoding="utf-8")

    rc = main(["--compare", str(a), str(b)])
    assert rc == 1


def test_cli_compare_esitsiz_uzunluktaki_dosyalarda_da_calisiyor(tmp_path) -> None:
    """Bir tarafta 3 aygıt, diğerinde 1 — kartezyen karşılaştırma hâlâ
    doğru çifti bulmalı, aygıt sayıları eşit olmasa bile."""
    a = tmp_path / "windows.json"
    b = tmp_path / "linux.json"
    a.write_text(dump_json([
        _kimlik("windows", None, generated=True),
        _kimlik("windows", "AAAA"),
        _kimlik("windows", None, generated=True),
    ]), encoding="utf-8")
    b.write_text(dump_json([_kimlik("linux", "AAAA")]), encoding="utf-8")

    assert main(["--compare", str(a), str(b)]) == 0


def test_cli_gecersiz_bayrak_KULLANIM_HATASI_veriyor() -> None:
    """argparse kullanım hatası — `backup_cli.py`'deki `2` çıkış kodu
    deseniyle AYNI (`SystemExit(2)`)."""
    with pytest.raises(SystemExit) as exc:
        main(["--boyle-bir-bayrak-yok"])
    assert exc.value.code == 2


def test_okuyucular_yalnizca_usb_manager_uzerinden_uretime_bagli() -> None:
    """
    2026-09-08 (B-112/B-114) ÖNCESİNDE bu test `hwid_probe`nin HİÇ bir
    üretim dosyasından import edilmediğini denetliyordu — o zamanki
    mimari karar buydu ("yanlışlıkla bağlanırsa yakalansın, mimari karar
    verilmeden üretime girmesin"). Karar artık VERİLDİ:
    `CORE/usb_manager.py::get_usb_hwid()` main.py'nin açılışta koşulsuz
    çağırdığı bir fonksiyondu ve Linux/macOS'ta HER ZAMAN `None`
    dönüyordu (paketlenmiş bir derleme USB takılı olsun olmasın hiç
    açılamıyordu) — ayrıntı docs/hwid-crossplatform.md, BACKLOG.md/B-114.

    Bu testin YENİ işi: bağlantının TEK bir yerden, TEK bir biçimde
    kalmasını denetlemek — `read_linux`/`read_macos` DIŞINDA bir isim
    (ör. `main()`, `parse_windows_pnp_id`, CLI'a özgü herhangi bir şey)
    üretime SIZMAMALI, ve bağlayan dosya `CORE/usb_manager.py`'DEN
    BAŞKASI OLMAMALI — ikinci bir uygulama (ör. bir UI dosyasının
    doğrudan `hwid_probe`ye bağlanması) sessizce ayrışabilirdi.
    """
    import ast
    from pathlib import Path

    kok = Path(__file__).resolve().parent.parent
    _IZINLI_ISIMLER = {"read_linux", "read_macos"}
    _IZINLI_DOSYA = "CORE/usb_manager.py"

    for yol in sorted(kok.rglob("*.py")):
        if yol.name in ("hwid_probe.py", "test_hwid_probe.py", "test_usb_manager.py"):
            continue
        if any(p in yol.parts for p in ("__pycache__", ".venv")):
            continue
        agac = ast.parse(yol.read_text(encoding="utf-8"))
        for n in ast.walk(agac):
            if isinstance(n, ast.ImportFrom) and (n.module or "").endswith("hwid_probe"):
                # B-117: `str(Path)` Windows'ta `\` ayırıcı kullanır — sabit
                # kodlanmış `_IZINLI_DOSYA` ("/" ayırıcı) ile birebir string
                # karşılaştırması Windows'ta HER ZAMAN düşerdi (platformdan
                # bağımsız tek doğru dosya olsa bile). `.as_posix()` platform
                # ayırıcısından bağımsız, karşılaştırılabilir bir biçim verir.
                goreli = yol.relative_to(kok).as_posix()
                assert goreli == _IZINLI_DOSYA, (
                    f"{goreli} hwid_probe'u import ediyor — TEK yetkili "
                    f"çağıran {_IZINLI_DOSYA} olmalı (ikinci bir bağlanma "
                    "yolu sessizce ayrışabilir)."
                )
                ithal_edilenler = {a.name for a in n.names}
                assert ithal_edilenler <= _IZINLI_ISIMLER, (
                    f"{goreli}, hwid_probe'dan {ithal_edilenler - _IZINLI_ISIMLER} "
                    f"içe aktarıyor — yalnızca {_IZINLI_ISIMLER} beklenirdi."
                )
            if isinstance(n, ast.Import):
                assert not any(a.name.endswith("hwid_probe") for a in n.names), (
                    f"{yol} hwid_probe'u `import hwid_probe` biçiminde alıyor — "
                    "yalnızca `from CORE.hwid_probe import read_linux/read_macos` "
                    "bekleniyor."
                )


# ══════════════════════════════════════════════════════════════════════════════
# MC-Kataloğu (2026-09-10) — Linux/pyudev dalı (MC-M056/M057)
# ══════════════════════════════════════════════════════════════════════════════
#
# Bu dosyanın kendi docstring'i "ioreg/pyudev gerçekten bu biçimde çıktı
# veriyor mu test EDİLEMİYOR" diyor — ama `read_linux()`'un pyudev dalının
# AYRIŞTIRMA MANTIĞININ KENDİSİ de (macOS'un `parse_ioreg()`'i gibi) bugüne
# kadar hiç sürülmemişti: fonksiyon `sys.platform.startswith("linux")`
# olmadıkça anında `[]` döner. Aşağıdaki fixture `sys.platform`'u ve
# `sys.modules["pyudev"]`'i sahteleyip, GERÇEK pyudev/Linux olmadan
# ayrıştırma mantığını sürüyor — modülün kendi kabul ettiği sınırla
# (donanım/araç çıktısı doğrulanamaz, mantık doğrulanabilir) aynı ilke.


class _SahteUdevAygit(dict):
    def get(self, anahtar, varsayilan=None):  # pyudev.Device.get() imzası
        return dict.get(self, anahtar, varsayilan)


class _SahteUdevBaglam:
    def __init__(self, aygitlar: list["_SahteUdevAygit"]) -> None:
        self._aygitlar = aygitlar

    def list_devices(self, subsystem=None, DEVTYPE=None):
        return self._aygitlar


@pytest.fixture
def sahte_linux_pyudev(monkeypatch: pytest.MonkeyPatch):
    import sys as _sys
    import types

    def kur(aygitlar: list[dict]):
        sahte_modul = types.ModuleType("pyudev")
        sahte_modul.Context = lambda: _SahteUdevBaglam(  # type: ignore[attr-defined]
            [_SahteUdevAygit(a) for a in aygitlar]
        )
        monkeypatch.setitem(_sys.modules, "pyudev", sahte_modul)
        monkeypatch.setattr(_sys, "platform", "linux")

    return kur


def test_linux_serisiz_aygitta_device_path_kimlik_olarak_kullanilmiyor(
    sahte_linux_pyudev,
) -> None:
    """
    MC-Kataloğu M056: `ID_SERIAL_SHORT` boşsa `read_linux()` bir DEVICE
    PATH'i (ör. `/dev/sdb`) hash'leyip `descriptor_serial`'a KOYMAMALI —
    böyle bir kimlik ne platformlar arası ne de aynı makinede portlar
    arası KARARLIDIR (aygıt başka porta takılınca düğüm adı değişir,
    bkz. modül docstring'i "Üretilen kimlik hub ve port yoluna bağlı").
    Serisiz aygıt `generated=True` ve `stable_id=None` KALMALI.

    Bu, `read_linux()`'un pyudev dalını GERÇEKTEN süren TEK testtir —
    bugüne kadar fonksiyon yalnızca Windows dışı platformlarda `[]`
    döndüğü için (ve CI/geliştirme burada hep Windows) bu mantık hiç
    çalıştırılmamıştı.
    """
    sahte_linux_pyudev([{
        "ID_BUS": "usb",
        "ID_SERIAL_SHORT": None,
        "ID_VENDOR_ID": "0781",
        "ID_MODEL_ID": "5567",
        "ID_SERIAL": None,
    }])

    sonuc = read_linux()
    assert len(sonuc) == 1
    aygit = sonuc[0]
    assert aygit.descriptor_serial is None, (
        f"seri yok ama descriptor_serial doldu: {aygit.descriptor_serial!r} "
        "— kararsız bir alan (ör. device path) kimlik yerine geçmiş olabilir."
    )
    assert aygit.generated is True
    assert aygit.stable_id is None


def test_linux_bilinmeyen_udev_alanlari_kimlige_karismiyor(
    sahte_linux_pyudev,
) -> None:
    """
    MC-Kataloğu M057: Bağlama noktası (mount point, ör.
    "/media/ay/USBDRIVE") ya da aygıt düğümü (`/dev/sdb1`) gibi kararsız
    alanlar HWID'e HİÇ karışmamalı — ikisi de USB'nin TAKILDIĞI porta/
    bağlama sırasına bağlı, aynı fiziksel USB farklı bir bağlamada farklı
    "kimlik" üretirdi. `read_linux()`'un pyudev dalı yalnızca 5 belgelenmiş
    özelliği (ID_BUS, ID_SERIAL_SHORT, ID_VENDOR_ID, ID_MODEL_ID,
    ID_SERIAL/ID_SCSI_SERIAL) okumalı — başka bir udev alanı eklenip
    sessizce bir kimlik alanına sızabilir mi diye izlenen bir iz bırakıyor.
    """
    IZ = "__BAGLAMA_NOKTASI_VEYA_DEVICE_NODE_IZI__"
    sahte_linux_pyudev([{
        "ID_BUS": "usb",
        "ID_SERIAL_SHORT": "ABC123",
        "ID_VENDOR_ID": "0781",
        "ID_MODEL_ID": "5567",
        "ID_SERIAL": "SanDisk_ABC123",
        "ID_FS_MOUNT_POINT": IZ,
        "DEVNAME": IZ,
        "MOUNT_POINT": IZ,
    }])

    sonuc = read_linux()
    assert len(sonuc) == 1
    from dataclasses import asdict
    degerler = [str(v) for v in asdict(sonuc[0]).values()]
    assert not any(IZ in v for v in degerler), (
        f"bağlama noktası/aygıt düğümü kimlik alanlarından birine sızmış: {degerler}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# Linux — sysfs (pyudev YOKKEN düşülen fallback, 2026-09-11 regresyonu)
# ══════════════════════════════════════════════════════════════════════════════
#
# `pyudev` paketlenmiş derlemede hiç YOK (`requirements.txt`'te yok,
# `HYCLEUS-linux.spec`'in `hiddenimports`'unda yok) — yani üretimde
# `read_linux()` HER ZAMAN aşağıdaki `_read_linux_sysfs()` dalına düşer.
# Bu bölümden ÖNCE bu dal hiç test edilmiyordu (yukarıdaki modül
# docstring'i "CI'da fiziksel USB yok" diyordu — ama `_read_linux_sysfs()`
# donanım OLMADAN da, sentetik bir `/sys/block` ağacıyla test edilebilir).
#
# Gerçek donanımla (bu makineye takılı iki USB flash sürücü, usb-storage/
# SCSI sürücüsü üzerinden) ölçüldü: eski `.parent.parent` varsayımı HER
# ZAMAN boş liste döndürüyordu, çünkü zincir gerçekte
# `<usbN>/<X-Y>/<X-Y:1.0>/hostN/targetN:0:0/N:0:0:0` — `idVendor`/`serial`
# dört seviye yukarıda, iki değil. B-112/B-114'ün "Linux'ta USB HWID artık
# okunuyor" düzeltmesi bu yüzden paketlenmiş bir derlemede fiilen HİÇ
# çalışmıyordu. Düzeltme: `_usb_aygit_kok_dizini()`, sabit derinlik yerine
# `idVendor` dosyasını arayarak yukarı yürüyor.


def _sahte_sysfs_usb_agaci(tmp_path, *, derinlik: int) -> Path:
    """
    `/sys/block/sda` → `device` (sembolik bağ) → SCSI yaprağı, ve
    yapraktan `derinlik` seviye yukarıda `idVendor`/`idProduct`/`serial`
    taşıyan gerçek USB düğümü içeren sentetik bir ağaç kurar.

    `derinlik=2`: eski (yanlış) `.parent.parent` varsayımının doğru
    olduğu basit durum. `derinlik=4`: bu makinede GERÇEKTEN ölçülen,
    SCSI-köprülü usb-storage durumu — eski kod burada başarısız oluyordu.
    """
    kok = tmp_path / "sys_block"
    blok = kok / "sda"
    blok.mkdir(parents=True)

    usb_dugumu = tmp_path / "gercek_usb_dugumu"
    usb_dugumu.mkdir(parents=True)
    (usb_dugumu / "idVendor").write_text("0951\n")
    (usb_dugumu / "idProduct").write_text("1666\n")
    (usb_dugumu / "serial").write_text("C87F54C69E2FE85109441C9D\n")

    yaprak = usb_dugumu
    for i in range(derinlik):
        yaprak = yaprak / f"ara-kademe-{i}"
        yaprak.mkdir()

    (blok / "device").symlink_to(yaprak)
    return kok


def test_sysfs_iki_seviye_yukaridaki_eski_basit_durumda_calisir(tmp_path) -> None:
    """Eski `.parent.parent` varsayımının doğru olduğu (basit, USB
    interface'inin doğrudan altında) durum — bu HÂLÂ çalışmalı."""
    from CORE.hwid_probe import _read_linux_sysfs

    kok = _sahte_sysfs_usb_agaci(tmp_path, derinlik=2)
    sonuc = _read_linux_sysfs(kok)

    assert len(sonuc) == 1
    assert sonuc[0].descriptor_serial == "C87F54C69E2FE85109441C9D"
    assert sonuc[0].vendor_id == "0951"
    assert sonuc[0].product_id == "1666"


def test_sysfs_dort_seviye_yukaridaki_gercek_usb_storage_durumunda_calisir(
    tmp_path,
) -> None:
    """
    REGRESYON — bu makinede GERÇEK donanımla ölçülen durum:
    `<usbN>/<X-Y>/<X-Y:1.0>/hostN/targetN:0:0/N:0:0:0` — dört ara kademe.
    Eski `.parent.parent` (yalnızca iki seviye) burada `idVendor`'ı hiç
    BULAMAZDI ve `_read_linux_sysfs()` sessizce boş liste dönerdi —
    istisna yok, hata yok, yalnızca "USB bulunamadı".
    """
    from CORE.hwid_probe import _read_linux_sysfs

    kok = _sahte_sysfs_usb_agaci(tmp_path, derinlik=4)
    sonuc = _read_linux_sysfs(kok)

    assert len(sonuc) == 1, (
        "dört seviye derinlikte GERÇEK USB aygıtı bulunamadı — "
        "_usb_aygit_kok_dizini() regresyonu"
    )
    assert sonuc[0].descriptor_serial == "C87F54C69E2FE85109441C9D"


def test_sysfs_idvendor_hic_bulunamazsa_sessizce_atlaniyor_cokme_yok(
    tmp_path,
) -> None:
    """USB olmayan bir blok aygıtı (ör. `nvme0n1`, `zram0`) hiçbir zaman
    `idVendor` içermez — yürüme sınırına (12 seviye) çarpıp `None` ile
    sessizce atlanmalı, istisna FIRLATMAMALI."""
    from CORE.hwid_probe import _read_linux_sysfs

    kok = tmp_path / "sys_block"
    blok = kok / "nvme0n1"
    blok.mkdir(parents=True)
    yaprak = tmp_path / "pci_agaci_idvendorsiz" / "cok" / "derin" / "bir" / "yol"
    yaprak.mkdir(parents=True)
    (blok / "device").symlink_to(yaprak)

    sonuc = _read_linux_sysfs(kok)

    assert sonuc == []


def test_sysfs_bos_kok_dizininde_cokmeden_bos_liste_donuyor(tmp_path) -> None:
    """`/sys/block` boşsa (ya da hiç yoksa) `_read_linux_sysfs()` çökmemeli."""
    from CORE.hwid_probe import _read_linux_sysfs

    assert _read_linux_sysfs(tmp_path / "hic_olmayan_dizin") == []
