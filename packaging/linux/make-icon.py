#!/usr/bin/env python3
"""
HYCLEUS — AppImage simgesini üretir.

Neden bir üretici betik, hazır bir PNG değil
--------------------------------------------
Depoda hiç simge yoktu; Windows spec'i de `icon=` vermiyor, yani EXE
PyInstaller'ın varsayılanını taşıyor. AppImage'da bu seçenek yok:
appimagetool `.DirIcon` olmadan yapıyı REDDEDİYOR. Yani simge, tasarım
kararı olduğu için değil, biçimin zorunlu kıldığı için var.

Bu yüzden simge GEÇİCİ ve betik yanında duruyor: nereden geldiği, kimin
çizdiği, hangi araçla üretildiği sorularının cevabı burada. Gerçek bir
simge geldiğinde `hycleus.png` değiştirilir ve bu betik silinir.

Yazı tipi KULLANILMIYOR — "H" üç dikdörtgenden çiziliyor. Bir sistem yazı
tipine bağlanmak, çıktıyı üretildiği makineye bağımlı yapardı; aynı
komut her platformda bayt bayt aynı dosyayı üretmeli.

Çalıştırma:  python packaging/linux/make-icon.py
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

BOYUT = 256
CIKTI = Path(__file__).with_name("hycleus.png")

LACIVERT = (18, 38, 58, 255)
KENAR    = (96, 165, 250, 255)
BEYAZ    = (255, 255, 255, 255)


def kalkan(cizim: ImageDraw.ImageDraw, boyut: int) -> None:
    """Omuzları düz, ucu sivri bir kalkan."""
    u = boyut / 16
    nokta = [
        (3 * u, 2 * u), (13 * u, 2 * u), (13 * u, 8.5 * u),
        (8 * u, 14.5 * u), (3 * u, 8.5 * u),
    ]
    cizim.polygon(nokta, fill=LACIVERT, outline=KENAR, width=int(u * 0.55))


def harf_h(cizim: ImageDraw.ImageDraw, boyut: int) -> None:
    """Üç dikdörtgen: iki dikey bacak ve bir yatay bağlantı.

    `alt` değeri kalkanın yan kenarının o x konumundaki yüksekliğine göre
    seçildi: sol bacak x = 5.5u'da ve kenar orada y ≈ 11.5u'ya iniyor.
    11u yazılsaydı çizgi kalınlığı bacakları kalkanın dışına taşırırdı.
    """
    u = boyut / 16
    kalinlik, ust, alt = 1.5 * u, 4.6 * u, 10.4 * u
    sol, sag = 5.5 * u, 10.5 * u
    cizim.rectangle([sol - kalinlik / 2, ust, sol + kalinlik / 2, alt], fill=BEYAZ)
    cizim.rectangle([sag - kalinlik / 2, ust, sag + kalinlik / 2, alt], fill=BEYAZ)
    orta = (ust + alt) / 2
    cizim.rectangle([sol, orta - kalinlik / 2, sag, orta + kalinlik / 2], fill=BEYAZ)


def main() -> int:
    # 4× çizip küçültmek kenarları yumuşatıyor; PIL'in polygon'u
    # kenar yumuşatma yapmıyor ve ham hâli 256'da tırtıklı görünüyor.
    olcek = 4
    tam = BOYUT * olcek
    gorsel = Image.new("RGBA", (tam, tam), (0, 0, 0, 0))
    cizim = ImageDraw.Draw(gorsel)
    kalkan(cizim, tam)
    harf_h(cizim, tam)

    gorsel.resize((BOYUT, BOYUT), Image.LANCZOS).save(CIKTI, "PNG", optimize=True)
    print(f"yazıldı: {CIKTI}  ({CIKTI.stat().st_size} bayt)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
