"""
Giriş ekranı sol paneli — doğrulanmamış mimari iddia sızıntısı, ikinci kez

İki-sütunlu düzen turunda (2026-08-26) mockup'ın sol paneli tasarlanırken
"HYCLEUS v2.5 · AIR-GAPPED" ve "● ÇEVRİMDIŞI" metni mockup'tan olduğu gibi
kopyalandı — SECURITY.md ile ÇELİŞEN, doğrulanmamış bir mimari iddia
("hava boşluklu"/tamamen ağ dışı). Bu iddia bir kez daha önce, tema
portlama turunda (`UI/main_window_palette.py`, `_AURORA_BOREALIS` üstündeki
yorum) BİLEREK dışarıda bırakılmıştı; sol panel yazılırken o karar
atlanmış oldu.

SECURITY.md §M1 açıkça bir ağ üzerinden ulaşılan tehdit yüzeyi tanımlıyor
(zaman damgası otoritesi yanıtı) — yani "air-gapped"/"çevrimdışı" gerçek
bir mimari özellik DEĞİL. Bu test, bu iki metnin `UI/login_dialog.py`'ye
BİR DAHA sızmadığını doğruluyor.
"""
from __future__ import annotations

from pathlib import Path

_LOGIN_DOSYASI = Path(__file__).resolve().parent.parent / "UI" / "login_dialog.py"

#: SECURITY.md'yle çelişen, doğrulanmamış mimari iddialar. Büyük/küçük
#: harf varyantları ELLE listelendi — Türkçe'nin noktalı/noktasız I
#: kuralları `str.upper()/.lower()`'ın yerleşik (yerel ayardan bağımsız)
#: Unicode eşlemesiyle DOĞRU dönüşmüyor (`i`.upper() -> `I`, `İ` DEĞİL),
#: yani otomatik büyütme/küçültmeye güvenmek yanlış-negatif üretebilirdi.
_DOGRULANMAMIS_IDDIALAR = (
    "AIR-GAPPED", "air-gapped", "Air-Gapped", "Air-gapped",
    "ÇEVRİMDIŞI", "çevrimdışı", "Çevrimdışı",
)


def test_air_gapped_iddiasi_login_dialogda_YOK() -> None:
    kaynak = _LOGIN_DOSYASI.read_text(encoding="utf-8")
    bulunan = [m for m in _DOGRULANMAMIS_IDDIALAR if m in kaynak]
    assert not bulunan, (
        f"UI/login_dialog.py: SECURITY.md'yle çelişen doğrulanmamış "
        f"mimari iddia(lar) bulundu: {bulunan}"
    )
