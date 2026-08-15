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

import pytest

from CORE.hwid_probe import (
    UsbIdentity,
    compare,
    normalize_serial,
    parse_ioreg,
    parse_windows_pnp_id,
    read_macos,
    summarise,
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


def test_case_and_padding_are_normalised() -> None:
    assert normalize_serial("4c530001120523104381") == normalize_serial(
        "4C530001120523104381")
    assert normalize_serial("0004C53") == "4C53"


def test_normalisation_does_not_invent_an_id() -> None:
    """Tamamen sıfır bir seri, "0" olarak kalmalı — boş dizeye dönmemeli."""
    assert normalize_serial("0000") == "0"
    assert normalize_serial("----") == "0"


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


def test_the_prototype_is_not_wired_into_the_app() -> None:
    """
    `hwid_probe` bir PROTOTİP; canlı kimlik yolu hâlâ `usb_manager`.
    Yanlışlıkla bağlanırsa yakalansın — mimari karar verilmeden
    üretime girmemeli.
    """
    import ast
    from pathlib import Path

    kok = Path(__file__).resolve().parent.parent
    for yol in sorted(kok.rglob("*.py")):
        if yol.name in ("hwid_probe.py", "test_hwid_probe.py"):
            continue
        if any(p in yol.parts for p in ("__pycache__", ".venv")):
            continue
        agac = ast.parse(yol.read_text(encoding="utf-8"))
        for n in ast.walk(agac):
            if isinstance(n, ast.ImportFrom) and (n.module or "").endswith("hwid_probe"):
                pytest.fail(f"{yol.relative_to(kok)} prototipi import ediyor")
            if isinstance(n, ast.Import):
                assert not any(a.name.endswith("hwid_probe") for a in n.names), yol
