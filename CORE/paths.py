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


def data_dir() -> Path:
    """data/ klasörünün mutlak yolunu döndürür.

    - AppImage:         $XDG_DATA_HOME/HYCLEUS  (varsayılan ~/.local/share/HYCLEUS)
    - EXE (sys.frozen): EXE'nin yanındaki data/ klasörü
    - Geliştirme:       proje kökündeki data/ klasörü
    """
    if hasattr(sys, "frozen"):
        if running_in_appimage():
            return _xdg_data_home() / APP_DIRNAME
        return Path(sys.executable).parent / "data"
    return Path(__file__).parent.parent / "data"
