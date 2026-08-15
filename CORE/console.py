"""
HYCLEUS — Konsol çıktısı kodlaması

**Windows'ta ASCII dışı çıktı üreten her yeni CLI/betik
`ensure_utf8_console()` çağırmalı.**

Neden bu modül var
------------------
Aynı hata bu projede iki kez, iki ayrı yerde bulundu:

  · `.github/scripts/test_summary.py` — iş özetindeki ✅/❌ ve Türkçe
    başlıklar CI'ın Windows ayağında `UnicodeEncodeError` verdi.
  · `CORE/verify_timestamp_cli.py` — sertifika zinciri ağacının `└─`
    karakterleri ve doğrulama mesajlarındaki Türkçe harfler yerel konsolda
    düştü. Araç doğru sonucu HESAPLAYIP onu YAZDIRIRKEN çöküyordu.

İkisi de aynı kök nedene sahip: Windows'ta Python, konsol ve yönlendirilmiş
çıktı için yerel kod sayfasını seçiyor (Batı Avrupa kurulumunda cp1252,
Türkçe kurulumda cp1254). Bu kod sayfaları ASCII dışı karakterlerin çoğunu
kodlayamıyor ve `print()` istisna fırlatıyor.

Sinsi yanı şu: hata çıktı üretilirken oluşuyor, HESAPLAMA doğru bitmiş
oluyor. Yani araç işini yapıyor, sonucu söylerken çöküyor — ve bu, testte
en kolay gözden kaçan yer, çünkü `capsys` gerçek bir akış kodlaması
kullanmıyor. Bu tür bir çıktıyı sınayan test, alt süreç olarak ve
`PYTHONIOENCODING` dayatılarak koşmalı (örnek: `tests/test_console.py`).

Kod sayfalarının kapsamı (neden "Türkçe'de çalışıyor" yeterli değil)
--------------------------------------------------------------------
    karakter          cp1252 (Batı)   cp1254 (Türkçe)
    ─────────────────────────────────────────────────
    · — “ ”           ✓               ✓
    ı ş ğ (Türkçe)    ✗               ✓
    ✅ ⚠ └ ─ (kutu)   ✗               ✗

Yani bir aracın "Türkçe Windows'ta çalışıyor olması" onu güvenli yapmıyor:
aynı kod, İngilizce bir kurulumda `ı` yüzünden düşebiliyor.
"""
from __future__ import annotations

from typing import Any

__all__ = ["ensure_utf8_console"]

#: Kodlanamayan karakterlerde ne yapılacağı. "replace" bilinçli: bir denetim
#: aracının '?' yazması, tamamen çökmesinden iyidir. "strict" olsaydı bu
#: yardımcı sorunu çözmek yerine yerini değiştirirdi.
_ERRORS = "replace"


def ensure_utf8_console(*streams: Any) -> None:
    """
    Verilen metin akışlarını UTF-8'e sabitler; verilmezse stdout + stderr.

    Args:
        streams: Yeniden yapılandırılacak akışlar. Test kolaylığı için
            dışarıdan verilebiliyor; normal kullanımda boş bırakılır.

    Çağrılması güvenlidir:
      · `reconfigure` taşımayan bir akış (StringIO, pytest'in yakalayıcısı)
        sessizce atlanıyor.
      · Yeniden yapılandırma başarısız olursa (kapalı ya da ayrılmış akış)
        istisna YUTULUYOR. Bu yardımcının kendisi hiçbir aracı kırmamalı;
        görevi bir hatayı önlemek, yenisini eklemek değil.

    Çağrı noktası `main()`'in ilk satırı olmalı — herhangi bir `print()`
    çalışmadan önce.
    """
    if not streams:
        import sys

        streams = (sys.stdout, sys.stderr)

    for stream in streams:
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors=_ERRORS)
        except Exception:  # kapalı/ayrılmış akış — bkz. docstring
            pass
