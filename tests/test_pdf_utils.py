"""
CORE.pdf_utils.escape_for_reportlab() — doğrudan birim testleri.

Bu fonksiyon hiç doğrudan test edilmiyordu. Yalnızca dolaylı, "PDF üretimi
çökmüyor mu" testleri vardı (`tests/test_audit_report.py::
test_pdf_html_karakterleri_bozmuyor`, `tests/test_inventory.py::
test_html_karakterleri_pdf_i_bozmuyor`) — escape'in TAMAMEN kaldırıldığı
bir mutasyonla ölçüldü: `test_inventory.py`'deki test payload'ı reportlab'ın
paraparser'ında "unclosed tag" hatasına yol açtığı için TESADÜFEN
yakalıyordu, ama `test_audit_report.py`'deki AYNI mutasyonla YEŞİL kalmaya
devam etti — reportlab'ın lenient parser'ı o payload'ı hatasız kabul etti.
Yani "PDF üretimi çökmüyor" testleri escape'in GERÇEKTEN çalıştığını
kanıtlamıyor, yalnızca BAZI payload'larda tesadüfen bir yan etkiyi
yakalıyor. Bu dosya escape'in kendisini, reportlab'a hiç dokunmadan,
doğrudan ölçüyor.
"""
from __future__ import annotations

from CORE.pdf_utils import escape_for_reportlab


def test_ampersand_kaciyor():
    assert escape_for_reportlab("a & b") == "a &amp; b"


def test_kucuktir_buyuktur_kaciyor():
    assert escape_for_reportlab("<script>x</script>") == "&lt;script&gt;x&lt;/script&gt;"


def test_zararsiz_metin_degismiyor():
    assert escape_for_reportlab("Ahmet Yılmaz") == "Ahmet Yılmaz"


def test_kacis_sirasi_cift_kacislama_yaratmiyor():
    """
    `&` MUTLAKA `<`/`>`'den ÖNCE kaçmalı — aksi hâlde `<` → `&lt;`
    ürettikten SONRA `&`'yi kaçırmak, o `&lt;`'nin kendi `&`'sini de
    kaçırıp `&amp;lt;` gibi çift-kaçışlanmış, YANLIŞ bir çıktı üretirdi.
    """
    assert escape_for_reportlab("<") == "&lt;"
    assert "&amp;lt;" not in escape_for_reportlab("<")


def test_sayi_olmayan_deger_str_e_ceviriliyor():
    assert escape_for_reportlab(42) == "42"
