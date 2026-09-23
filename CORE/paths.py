"""HYCLEUS — Merkezi data dizini çözümleyici.

PyInstaller EXE olarak çalışırken __file__ geçici extraction dizinine işaret eder.
Bu modül her iki ortamda da doğru data/ yolunu döndürür.

AppImage neden ayrı bir dal
---------------------------
Bir AppImage, çalıştırıldığında SALT OKUNUR bir squashfs olarak
`/tmp/.mount_XXXXXX` altına bağlanır. `sys.executable` o bağlama noktasının
içini gösterir, yani "EXE'nin yanındaki data/" kuralı orada
`/tmp/.mount_.../usr/bin/data` demek olur: yazılamaz, ve bağlama noktası
her çalıştırmada değiştiği için yazılabilse bile veriler kaybolurdu.

AppImage çalışma zamanı `APPIMAGE` ortam değişkenini süreç başlamadan ÖNCE
tanımlıyor. Bu modülü içe aktaran birçok yer yolunu import anında
hesapladığı için (`_USB_IDS_FILE`, `_TOTP_FILE`, `_DEFAULT_DB_PATH`, …)
kararın o anda verilebiliyor olması şart — sonradan düzeltme şansı yok.

Linux'ta veri XDG'ye gidiyor, `.AppImage` dosyasının yanına DEĞİL: AppImage
dosyaları çoğu zaman `/opt`, `/usr/local/bin` ya da salt okunur bir
`~/Applications` altında duruyor ve bir kasa uygulamasının verisini oraya
yazmaya çalışmak Windows'taki "EXE'nin yanı" alışkanlığını yanlış bir
platforma taşımak olurdu.

Windows davranışı DEĞİŞMEDİ.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

#: XDG Base Directory: kullanıcıya özel veri dizini.
XDG_DATA_HOME = "XDG_DATA_HOME"

#: AppImage çalışma zamanının tanımladığı değişken; değeri kullanıcının
#: çalıştırdığı `.AppImage` dosyasının yoludur. Varlığı "salt okunur bir
#: bağlama noktasının içindeyiz" demek.
APPIMAGE_ENV = "APPIMAGE"

#: XDG altındaki dizin adı.
APP_DIRNAME = "HYCLEUS"

#: Test izolasyonu için data dizini geçersiz kılma değişkeni (B-067).
#:
#: Yalnızca AÇIKÇA ayarlanırsa etkin olur; boş/tanımsızsa aşağıdaki üç
#: normal dal (AppImage / EXE / geliştirme) hiç değişmeden çalışır.
#: `main.py`, HERHANGİ bir HYCLEUS modülü içe aktarılmadan ÖNCE bunu
#: ayarlıyor (`--test-data-dir` bayrağı ya da bu değişkenin doğrudan
#: kendisi) -- çünkü bu modülün üstteki docstring'inin de uyardığı gibi,
#: `_DEFAULT_DB_PATH`, `_VAULT_DIR`, `_TOTP_FILE`, `_USB_IDS_FILE` gibi
#: birçok yer bu kararı İÇE AKTARILDIKLARI ANDA veriyor -- sonradan
#: düzeltme şansı yok.
TEST_DATA_DIR_ENV = "HYCLEUS_TEST_DATA_DIR"


def _xdg_data_home() -> Path:
    """`$XDG_DATA_HOME`, tanımsız ya da göreliyse `~/.local/share`.

    Spesifikasyon "mutlak olmayan değer yok sayılmalı" diyor; göreli bir
    değeri kabul etmek veriyi o anki çalışma dizinine yazmak olurdu.
    """
    ham = os.environ.get(XDG_DATA_HOME, "")
    if ham:
        aday = Path(ham)
        if aday.is_absolute():
            return aday
    return Path.home() / ".local" / "share"


def running_in_appimage() -> bool:
    """AppImage bağlama noktasından mı çalışıyoruz."""
    return bool(os.environ.get(APPIMAGE_ENV))


#: Bilinen dev/test override ortam değişkenleri ve karşılıklarının bir
#: cümlelik açıklaması — yalnızca `reddet_paketlenmis_override()`'ın hata
#: mesajında kullanılıyor. Yeni bir override eklerken buraya da eklenmeli
#: (bkz. `tests/test_paths.py::test_bilinen_override_listesi_...`).
BILINEN_OVERRIDE_ACIKLAMALARI: dict[str, str] = {
    TEST_DATA_DIR_ENV: "veri dizini (DB, vault, TOTP, denetim çıpası, SafeZone)",
    "HYCLEUS_AUDIT_ANCHOR": "yerel denetim çıpası dosyası (CORE/audit_chain.py)",
    "HYCLEUS_SAFEZONE": "SafeZone dizini — geçici, ÇÖZÜLMÜŞ dosya alanı (CORE/safezone.py)",
}


def reddet_paketlenmis_override(env_var: str) -> None:
    """
    Bir geliştirme/test amaçlı override ortam değişkeni PAKETLENMİŞ bir
    yapıda (`sys.frozen`) ayarlanmışsa `SystemExit(2)` ile reddeder,
    ayarlanmamışsa ya da geliştirme ortamındaysa hiçbir şey yapmaz (B-154).

    `DEV_MODE`'un `CORE/usb_manager.py`'de zaten güvendiği AYNI sinyale
    dayanıyor: `sys.frozen`, PyInstaller'ın bootloader'ının KENDİSİNİN
    koyduğu bir bayrak — bir ortam değişkeni onu taklit edemez.

    `data_dir()` (`HYCLEUS_TEST_DATA_DIR`), `CORE/audit_chain.py::
    anchor_path()` (`HYCLEUS_AUDIT_ANCHOR`) ve `CORE/safezone.py::
    safezone_dir()` (`HYCLEUS_SAFEZONE`) — üçü de aynı desen: sessizce
    kabul edilirse paketlenmiş bir EXE/AppImage'ı dev ortamındaki gibi
    keyfi bir yola yönlendirebiliyorlardı (B-154, veri dizini için
    bulundu; aynı denetim SafeZone/denetim çıpası override'larına da
    genişletildi — ikisi de tek başına HİÇBİR yerde sınanmıyordu). Tek bir
    karar noktası, tek bir mesaj biçimi.

    Raises:
        SystemExit(2) — `env_var` paketlenmiş bir yapıda ayarlanmışsa.
    """
    if not hasattr(sys, "frozen"):
        return
    aciklama = BILINEN_OVERRIDE_ACIKLAMALARI.get(env_var, "bir dev/test yolu")
    print(
        f"{env_var} paketlenmiş bir HYCLEUS yapısında (EXE/AppImage) "
        f"desteklenmiyor -- reddedildi ({aciklama}). Bu değişken yalnızca "
        "geliştirme ortamı içindir; paketlenmiş bir yapıyı izole veriyle "
        "sınamak için işletim sisteminin kendi mekanizmasını kullanın "
        "(Windows: EXE'yi ayrı bir klasöre kopyalayıp data/ klasörünün "
        "yanında oluşmasına izin verin; Linux/AppImage: XDG_DATA_HOME'u "
        "geçici bir dizine ayarlayın). Bkz. SECURITY.md, BACKLOG B-154.",
        file=sys.stderr,
    )
    sys.exit(2)


def data_dir() -> Path:
    """data/ klasörünün mutlak yolunu döndürür.

    - Test izolasyonu: `HYCLEUS_TEST_DATA_DIR` ayarlıysa DOĞRUDAN o (B-067) —
      AMA yalnızca geliştirme ortamında; paketlenmiş yapıda REDDEDİLİR
      (B-154, `reddet_paketlenmis_override()`).
    - AppImage:         $XDG_DATA_HOME/HYCLEUS  (varsayılan ~/.local/share/HYCLEUS)
    - EXE (sys.frozen): EXE'nin yanındaki data/ klasörü
    - Geliştirme:       proje kökündeki data/ klasörü

    Raises:
        SystemExit — bkz. `reddet_paketlenmis_override()`.
    """
    override = os.environ.get(TEST_DATA_DIR_ENV, "")
    if override:
        reddet_paketlenmis_override(TEST_DATA_DIR_ENV)
        return Path(override)
    if hasattr(sys, "frozen"):
        if running_in_appimage():
            return _xdg_data_home() / APP_DIRNAME
        return Path(sys.executable).parent / "data"
    return Path(__file__).parent.parent / "data"
