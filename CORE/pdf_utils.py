"""HYCLEUS — reportlab `Paragraph` metinleri için PAYLAŞILAN kaçış yardımcısı.

`CORE/inventory.py`'nin PDF dışa aktarımı (KVKK envanteri) ve `CORE/
audit_report.py`'nin PDF dışa aktarımı (Denetim Günlüğü) AYNI ihtiyacı
paylaşıyor: hücre metni kullanıcı girdisi olabilir (dosya adı, kullanıcı
adı, denetim `detail` alanı) ve reportlab `Paragraph` içeriğini mini-HTML
olarak ayrıştırıyor — kaçırılmadan geçen bir `&`/`<` belgeyi bozar ya da
üretimi düşürür. İki ayrı kopya YAZILMADI.
"""
from __future__ import annotations


def escape_for_reportlab(text: str) -> str:
    """Hücre metnini reportlab `Paragraph` için güvenli hâle getirir."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
