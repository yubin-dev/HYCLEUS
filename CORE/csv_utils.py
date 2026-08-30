"""HYCLEUS — CSV formül enjeksiyonuna (CWE-1236) karşı PAYLAŞILAN savunma.

`CORE/audit_report.py::export_csv()` (Denetim Günlüğü "Tablo" dışa
aktarımı) ve `CORE/inventory.py::export_inventory_csv()` (KVKK envanteri)
AYNI riski taşıyor: ikisi de kullanıcı girdisi içerebilen metin alanlarını
(kullanıcı adı, dosya adı, denetim `detail` alanı) hiçbir kaçışlama
yapmadan `csv.writer`'a veriyordu.

`csv` modülünün kendi kaçışlaması (virgül/tırnak/satır-içi-yenisatır,
RFC 4180) BU riski KAPSAMIYOR — o CSV SÖZDİZİMİNİ korur, hedef
uygulamanın (Excel/LibreOffice Calc) bir hücreyi FORMÜL sanmasını DEĞİL;
ikisi tamamen ayrı kusur sınıfı. Gerçek veriyle ölçüldü (bkz. `tests/
test_audit_report.py`): kullanıcı adı `=1+1` olan bir kullanıcının
denetim kaydı dışa aktarıldığında, üretilen CSV'de o hücre TAM OLARAK
`=1+1` olarak, hiç kaçışlanmadan yazılıyordu — Excel/LibreOffice'te
açıldığında formül olarak DEĞERLENDİRİLİRDİ.

İki ayrı kopya YAZILMADI — `CORE/pdf_utils.py::escape_for_reportlab()`
ile AYNI paylaşım gerekçesi (iki modülün AYNI ihtiyacı, tek kaynak).
"""
from __future__ import annotations

#: Excel/LibreOffice Calc'in bir hücreyi FORMÜL olarak yorumlamasına yol
#: açan önekler — OWASP'ın CSV Injection (CWE-1236) rehberinin standart
#: kümesi. Sekme/CR de dahil: bazı elektronik tablo uygulamaları hücre
#: başındaki bu kontrol karakterlerini de formül tetikleyicisi sayıyor.
_TEHLIKELI_ONEKLER = ("=", "+", "-", "@", "\t", "\r")


def csv_hucre_guvenli(deger: object) -> object:
    """
    Hücreyi CSV formül enjeksiyonuna karşı etkisizleştirir.

    Standart savunma: tehlikeli bir önekle başlayan hücrenin BAŞINA tek
    bir tek-tırnak (`'`) ekler — Excel/LibreOffice bunu "bu hücre
    KESİNLİKLE metin" işareti olarak okur, formül olarak DEĞERLENDİRMEZ.

    Yalnızca GERÇEKTEN tehlikeli önekle başlayan hücreler değişir;
    sayılar (`int`/`None`) ve tehlikeli önekle başlamayan metinler (ör.
    "Ahmet Yılmaz", "2026-08-30") OLDUĞU GİBİ, hiç dokunulmadan döner —
    yanlış pozitif üretmemek kadar önemli.
    """
    metin = str(deger)
    if metin.startswith(_TEHLIKELI_ONEKLER):
        return "'" + metin
    return deger
