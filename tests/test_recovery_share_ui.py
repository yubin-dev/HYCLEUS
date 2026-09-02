"""
Kurtarma parçası modalı — QR, onay kutusu, yazdırma.

Bu pencere sistemin gösterdiği en tehlikeli ekran: içeriği, kalan tek payla
birlikte kasadaki her dosyanın anahtarını veriyor. Üç şey ölçülüyor:

  1. QR ile base32 AYNI payı taşıyor mu — gerçek çözümlemeyle.
  2. Onay kutusu işaretlenmeden "Tamam" basılamıyor, ama pencere
     kapanabiliyor (B-003: kullanıcıyı hapsetmek bilgilendirmiyor).
  3. Panoya kopyalama seçeneği TAMAMEN KALDIRILDI (B-091) — ekran koruması
     Windows'ta HYCLEUS'un kontrolü altında (WDA_EXCLUDEFROMCAPTURE), ama
     pano geçmişi HİÇBİR platformda değil; "kopyalamadan önce uyar" bir
     düğme hâlâ "bu güvenli bir yol" izlenimi veriyordu. Yerine gerçek bir
     yazdırma akışı (QPrinter/QPrintDialog) eklendi — QR + base32 metnini
     içeren belgeyi doğru kurduğu ve düğmenin/uyarının ekranda olduğu
     ölçülüyor; gerçek bir yazıcı sürücüsüne basmak (`QTextDocument.
     print_()`'in kendisi) testte ÇAĞRILMIYOR — `QPrintDialog.exec()`
     monkeypatch'leniyor.

QR ÇÖZÜMLEMESİ NEDEN ELLE YAZILDI
----------------------------------
Ortamda QR okuyan bir kütüphane yok (pyzbar/opencv kurulu değil) ve
`qrcode` yalnızca üretiyor. Matrisleri karşılaştırmak — yani aynı metinden
ikinci bir QR üretip eşitliğine bakmak — kolay olurdu ama ZAYIF bir test
olurdu: sorulan soru "QR ne KODLUYOR", "iki üretim aynı mı" değil.

Bu yüzden aşağıda gerçek bir çözümleyici var: SVG → modül matrisi → format
bilgisinden maske → zikzak bit okuma → RS bloklarının ayrıştırılması →
kip/uzunluk/yük. Yazarken ölçülen bir şey de bunu haklı çıkardı: base32
metni salt büyük harf, rakam ve tire olduğu için `qrcode` BAYT kipini
değil ALFANUMERİK kipi seçiyor. Matris karşılaştırması bu ayrıntıyı hiç
göstermezdi.

Reed-Solomon DÜZELTMESİ yapılmıyor: veri bozulmamış olduğu için gerek yok.
Yani bu çözümleyici hasarlı bir QR'ı okuyamaz — okuması da gerekmiyor.
"""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path

import pytest

# QApplication kurulmadan ÖNCE (B-046).
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from CORE.recovery_share import WARNING_TEXT, RecoveryExport, build_export, encode_share

# Qt ve UI TEK korumanın altında (B-047).
try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QDialog

    from UI.RecoveryShareDialog import (
        KORUMA_ETKIN,
        KORUMA_YOK,
        ONAY_METNI,
        YAZDIRMA_UYARISI,
        RecoveryShareDialog,
        ekran_yakalamayi_engelle,
    )
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

KOK = Path(__file__).resolve().parent.parent

_ORNEK_PAY = "3:" + "ab" * 33


# ══════════════════════════════════════════════════════════════════════════════
# QR çözümleyici — yalnızca test için
# ══════════════════════════════════════════════════════════════════════════════

#: Format bilgisindeki hata düzeltme biti → `qrcode` sabiti.
_EC_KODU = {0b01: 1, 0b00: 0, 0b11: 3, 0b10: 2}

#: QR alfanumerik kipinin karakter kümesi (ISO/IEC 18004 Tablo 5).
_ALFANUMERIK = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def _svg_matris(svg: str) -> list[list[bool]]:
    """SVG yolundan modül matrisi — sessiz kenar çıkarılmış."""
    koyu = {(int(x), int(y)) for x, y in re.findall(r"M(\d+),(\d+)H", svg)}
    n = int(re.search(r'viewBox="0 0 (\d+) ', svg).group(1))
    kenar = min(x for x, _ in koyu)
    boyut = n - 2 * kenar
    return [[(x + kenar, y + kenar) in koyu for x in range(boyut)]
            for y in range(boyut)]


def _fonksiyon_haritasi(boyut: int, surum: int) -> list[list[bool]]:
    """Veri taşımayan modüller: bulucular, zamanlama, hizalama, format."""
    from qrcode.util import pattern_position

    f = [[False] * boyut for _ in range(boyut)]

    def doldur(r0: int, c0: int, r1: int, c1: int) -> None:
        for r in range(max(0, r0), min(boyut, r1)):
            for c in range(max(0, c0), min(boyut, c1)):
                f[r][c] = True

    doldur(0, 0, 9, 9)                        # sol üst bulucu + ayraç + format
    doldur(0, boyut - 8, 9, boyut)            # sağ üst
    doldur(boyut - 8, 0, boyut, 9)            # sol alt
    for i in range(boyut):
        f[6][i] = True                        # yatay zamanlama
        f[i][6] = True                        # dikey zamanlama

    konum = pattern_position(surum)
    for r in konum:
        for c in konum:
            kose = ((r < 9 and c < 9) or (r < 9 and c > boyut - 10)
                    or (r > boyut - 10 and c < 9))
            if not kose:
                doldur(r - 2, c - 2, r + 3, c + 3)

    if surum >= 7:                            # sürüm bilgisi blokları
        doldur(boyut - 11, 0, boyut - 8, 6)
        doldur(0, boyut - 11, 6, boyut - 8)
    return f


def _format_bilgisi(m: list[list[bool]]) -> tuple[int, int]:
    """`(ec_biti, maske)` — sol üst bulucunun çevresindeki 15 bit."""
    bitler = [m[8][i] for i in range(6)]
    bitler += [m[8][7], m[8][8], m[7][8]]
    bitler += [m[5 - i][8] for i in range(6)]
    ham = 0
    for b in bitler:
        ham = (ham << 1) | int(b)
    f = ham ^ 0x5412                          # ISO/IEC 18004 format maskesi
    return (f >> 13) & 0b11, (f >> 10) & 0b111


def _bit_akisi(m: list[list[bool]], f: list[list[bool]],
               boyut: int, maske: int) -> list[int]:
    """Sağ alttan başlayan zikzak okuma; maske aynı anda kaldırılıyor."""
    from qrcode.util import mask_func

    uygula = mask_func(maske)
    bitler: list[int] = []
    yukari = True
    sutun = boyut - 1
    while sutun > 0:
        if sutun == 6:                        # dikey zamanlama sütunu atlanır
            sutun -= 1
        for i in range(boyut):
            satir = (boyut - 1 - i) if yukari else i
            for dx in (0, 1):
                s = sutun - dx
                if f[satir][s]:
                    continue
                bitler.append(int(m[satir][s]) ^ int(uygula(satir, s)))
        yukari = not yukari
        sutun -= 2
    return bitler


def qr_coz(svg: str) -> str:
    """QR SVG'sini metne çevirir. Gerçek çözümleme — yeniden üretim değil."""
    from qrcode.base import rs_blocks

    m = _svg_matris(svg)
    boyut = len(m)
    surum = (boyut - 17) // 4
    ec_biti, maske = _format_bilgisi(m)
    bitler = _bit_akisi(m, _fonksiyon_haritasi(boyut, surum), boyut, maske)

    kodlar = [int("".join(str(b) for b in bitler[i:i + 8]), 2)
              for i in range(0, len(bitler) - 7, 8)]

    # Veri kod sözcükleri bloklar arasında SIRALI DEĞİL, iç içe geçmiş.
    sayilar = [b.data_count for b in rs_blocks(surum, _EC_KODU[ec_biti])]
    parcalar: list[list[int]] = [[] for _ in sayilar]
    i = 0
    for sira in range(max(sayilar)):
        for b, adet in enumerate(sayilar):
            if sira < adet:
                parcalar[b].append(kodlar[i])
                i += 1
    akis = "".join(f"{k:08b}" for p in parcalar for k in p)

    kip = int(akis[:4], 2)
    if kip == 0b0100:                                     # bayt
        n_bit = 8 if surum < 10 else 16
        uzunluk = int(akis[4:4 + n_bit], 2)
        bas = 4 + n_bit
        return bytes(int(akis[bas + 8 * j: bas + 8 * j + 8], 2)
                     for j in range(uzunluk)).decode("utf-8")
    if kip == 0b0010:                                     # alfanumerik
        n_bit = 9 if surum < 10 else (11 if surum < 27 else 13)
        uzunluk = int(akis[4:4 + n_bit], 2)
        bas = 4 + n_bit
        cikti: list[str] = []
        kalan = uzunluk
        while kalan >= 2:
            v = int(akis[bas:bas + 11], 2)
            cikti += [_ALFANUMERIK[v // 45], _ALFANUMERIK[v % 45]]
            bas += 11
            kalan -= 2
        if kalan:
            cikti.append(_ALFANUMERIK[int(akis[bas:bas + 6], 2)])
        return "".join(cikti)
    raise AssertionError(f"Desteklenmeyen QR kipi: {kip:04b}")


# ══════════════════════════════════════════════════════════════════════════════
# Fikstürler
# ══════════════════════════════════════════════════════════════════════════════


def _nesne(pencere, ad: str):  # type: ignore[no-untyped-def]
    """`objectName`'i verilen alt parçayı bulur; yoksa `None`."""
    for w in pencere.findChildren(object):
        if getattr(w, "objectName", lambda: "")() == ad:
            return w
    return None


@pytest.fixture(scope="module")
def qapp():  # type: ignore[no-untyped-def]
    yield QApplication.instance() or QApplication([])


@pytest.fixture
def disa_aktarim() -> RecoveryExport:
    return build_export(_ORNEK_PAY)


class _SahteYazici:
    """`QPrinter` yerine — bkz. `_yazici_sahtele()` docstring'i."""

    HighResolution = 0  # `QPrinter(QPrinter.HighResolution)` çağrısının beklediği öznitelik

    def __init__(self, *a, **k):  # type: ignore[no-untyped-def]
        pass


def _sahte_yazici_diyalogu_sinifi(sonuc: int, cagrilar: list[bool]):  # type: ignore[no-untyped-def]
    """`QPrintDialog` yerine geçecek sınıfı üretir — `exec()` sabit `sonuc`u
    döner, GERÇEK bir pencere/COM sorgusu AÇMADAN."""

    class _SahteDiyalog:
        def __init__(self, printer, parent=None):  # type: ignore[no-untyped-def]
            self.printer = printer

        def exec(self):  # type: ignore[no-untyped-def]
            cagrilar.append(True)
            return sonuc

    return _SahteDiyalog


def _yazici_sahtele(monkeypatch: pytest.MonkeyPatch, sonuc: int) -> list[bool]:
    """
    `PySide6.QtPrintSupport.QPrinter`/`QPrintDialog`'u sahtelerle değiştirir.

    GERÇEK bir `QPrinter` inşa etmek BİLE bu makinede Windows'un yazıcı COM
    arabirimlerini sorguluyor — ölçüldü: pytest altında (düz bir betikte
    DEĞİL) `0x80040155` COM istisnası fırlatıyor. `_on_yazdir()`'in
    `QPrinter`/`QPrintDialog`'u YEREL olarak içe aktardığı (her çağrıda
    `PySide6.QtPrintSupport` modülünden TAZE okunuyor) gerçeğinden
    yararlanıp bu modülün KENDİSİNDEKİ adları değiştiriyoruz — gerçek
    donanıma/COM'a HİÇ dokunmadan.
    """
    import PySide6.QtPrintSupport as _qps

    cagrilar: list[bool] = []
    monkeypatch.setattr(_qps, "QPrinter", _SahteYazici)
    monkeypatch.setattr(_qps, "QPrintDialog", _sahte_yazici_diyalogu_sinifi(sonuc, cagrilar))
    return cagrilar


@pytest.fixture
def yazdirma_kabul(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Kullanıcı bir yazıcı SEÇMİŞ gibi `QDialog.Accepted` döner."""
    return _yazici_sahtele(monkeypatch, QDialog.Accepted)


@pytest.fixture
def yazdirma_iptal(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Aynısı ama kullanıcı yazdırma diyaloğunu İPTAL etti."""
    return _yazici_sahtele(monkeypatch, QDialog.Rejected)


@pytest.fixture
def yazdirma_yakala(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """
    `QTextDocument.print_()`'i yakalar — sahte `QPrinter` nesnesi GERÇEK
    `print_()`'e verilirse (C++ tarafı gerçek bir `QPrinter` bekliyor) tip
    hatası fırlardı; bu yüzden `print_()`'in KENDİSİ de sahteleniyor,
    hangi nesneyle çağrıldığını kaydediyor.
    """
    from PySide6.QtGui import QTextDocument

    cagrilar: list[object] = []

    def _yakala(self, yazici):  # type: ignore[no-untyped-def]
        cagrilar.append(yazici)

    monkeypatch.setattr(QTextDocument, "print_", _yakala)
    return cagrilar


@pytest.fixture
def modal(qapp, disa_aktarim: RecoveryExport) -> RecoveryShareDialog:
    d = RecoveryShareDialog(disa_aktarim)
    yield d
    d.deleteLater()


# ══════════════════════════════════════════════════════════════════════════════
# 1. QR ↔ base32 — aynı payı taşıyorlar mı
# ══════════════════════════════════════════════════════════════════════════════


def test_cozumleyici_KENDI_dogru_calisiyor():
    """
    Çözümleyici bilinen bir metni geri veriyor mu.

    Bu olmadan aşağıdaki test, bozuk bir çözümleyiciyle de "geçebilirdi"
    (ikisi de aynı yanlışı üretirse fark edilmez).
    """
    from CORE.recovery_share import render_qr_svg

    for metin in ("HYCLEUS-R3-ABCD", "HYCLEUS-R3-" + "AB23-" * 12 + "XY"):
        assert qr_coz(render_qr_svg(metin)) == metin


def test_QR_base32_ile_AYNI_veriyi_kodluyor(disa_aktarim: RecoveryExport):
    """Zincirin can alıcı halkası: kâğıda basılan iki biçim aynı payı vermeli."""
    assert disa_aktarim.qr_svg is not None, "QR üretilmedi — qrcode paketi yok mu?"
    assert qr_coz(disa_aktarim.qr_svg) == disa_aktarim.base32_text


def test_QR_paya_kadar_GERI_donuyor(disa_aktarim: RecoveryExport):
    """QR → base32 → "3:<hex>" payı. Uçtan uca tur."""
    from CORE.recovery_share import decode_share

    assert decode_share(qr_coz(disa_aktarim.qr_svg)) == _ORNEK_PAY


def test_karsilastirma_YUK_TASIYOR(disa_aktarim: RecoveryExport):
    """Farklı bir pay farklı bir QR vermeli — yoksa üstteki testler boş."""
    from CORE.recovery_share import render_qr_svg

    baska = encode_share("3:" + "cd" * 33)
    assert baska != disa_aktarim.base32_text
    assert qr_coz(render_qr_svg(baska)) != disa_aktarim.base32_text


def test_modaldaki_QR_ile_METIN_ayni(modal: RecoveryShareDialog,
                                     disa_aktarim: RecoveryExport):
    """
    Ekranda GÖRÜNEN iki şey aynı mı.

    Üstteki testler `build_export` çıktısını ölçüyor; bu test pencerenin o
    çıktıyı doğru yerleştirdiğini ölçüyor. İkisi ayrı sorular: doğru veriyi
    yanlış parçaya koymak da bir ayrışmadır.
    """
    assert modal._metin.toPlainText() == disa_aktarim.base32_text
    assert qr_coz(disa_aktarim.qr_svg) == modal._metin.toPlainText()


def test_QR_yoksa_kullaniciya_SOYLENIYOR(qapp):  # type: ignore[no-untyped-def]
    """
    `qrcode` yoksa QR alanı sessizce boş kalmamalı.

    Boş bir kutu, kullanıcının "bir şey bozuldu" diye okuyacağı bir şey;
    base32'nin tek başına yeterli olduğunu söylemek gerekiyor.
    """
    d = RecoveryShareDialog(RecoveryExport(base32_text="HYCLEUS-R3-AAAA",
                                           qr_svg=None))
    try:
        aciklama = _nesne(d, "kurtarma_qr_yok")
        assert aciklama is not None, "QR yokken açıklama gösterilmiyor"
        assert "yeterlidir" in aciklama.text()
        assert _nesne(d, "kurtarma_qr") is None, "QR yokken boş bir görsel duruyor"
    finally:
        d.deleteLater()


# ══════════════════════════════════════════════════════════════════════════════
# 2. Onay kutusu
# ══════════════════════════════════════════════════════════════════════════════


def test_onaysiz_TAMAM_pasif(modal: RecoveryShareDialog):
    assert not modal._btn_tamam.isEnabled()


def test_onay_TAMAMI_aciyor(modal: RecoveryShareDialog):
    modal._onay.setChecked(True)
    assert modal._btn_tamam.isEnabled()


def test_onay_geri_alininca_TEKRAR_pasif(modal: RecoveryShareDialog):
    """Tek yönlü bir kapı, kullanıcı fikrini değiştirdiğinde yanıltırdı."""
    modal._onay.setChecked(True)
    modal._onay.setChecked(False)
    assert not modal._btn_tamam.isEnabled()


def test_pasif_TAMAM_modali_kapatmiyor(modal: RecoveryShareDialog):
    """Düğmenin görünüşte pasif olması yetmez; tıklama da geçmemeli."""
    modal._btn_tamam.click()
    assert modal.result() != QDialog.Accepted


def test_onaydan_sonra_TAMAM_kabul_ediyor(modal: RecoveryShareDialog):
    modal._onay.setChecked(True)
    modal._btn_tamam.click()
    assert modal.result() == QDialog.Accepted


def test_ESC_ile_kapanabiliyor(modal: RecoveryShareDialog):
    """
    Onay kutusu bir DİKKAT kontrolü, kapatma engeli DEĞİL.

    B-003'ün dersi: kullanıcıyı pencerede hapsetmek onu bilgilendirmiyor,
    rastgele bir düğmeye basmaya itiyor. Yazıcıyı hazırlamaya gitmek için
    pencereyi kapatmak meşru bir karar.
    """
    modal.show()
    modal.reject()
    assert not modal.isVisible()
    assert modal.result() == QDialog.Rejected


def test_onay_metni_TEK_yerde():
    """Etiket sabitten geliyor mu — iki yerde yazılsa biri güncellenmezdi."""
    kaynak = (KOK / "UI" / "RecoveryShareDialog.py").read_text(encoding="utf-8")
    assert kaynak.count(f'"{ONAY_METNI}"') == 1
    assert "QCheckBox(ONAY_METNI)" in kaynak


# ══════════════════════════════════════════════════════════════════════════════
# 3. Pano KALDIRILDI + Yazdırma (B-091)
# ══════════════════════════════════════════════════════════════════════════════


def test_panoya_kopyalama_dugmesi_YOK(modal: RecoveryShareDialog):
    """
    Çekirdek iddia: "Panoya Kopyala" düğmesi ARTIK YOK.

    Ekran koruması/pano geçmişi HYCLEUS'un kontrolünde değil — kaldırma
    kararının kendisi bu. `objectName` üzerinden arıyor (metin/etiket
    değişse bile eski davranışın izi kalmasın diye).
    """
    assert not hasattr(modal, "_btn_pano")
    assert _nesne(modal, "kurtarma_btn_pano") is None


def test_pano_ile_ilgili_HICBIR_SEY_kaynakta_yok():
    """
    Kaynak dosyada panoyla ilgili hiçbir iz kalmamalı — yarım bir kaldırma
    (düğme silinmiş ama yardımcı metotlar/sabitler unutulmuş) bu testle
    yakalanır.
    """
    kaynak = (KOK / "UI" / "RecoveryShareDialog.py").read_text(encoding="utf-8")
    for iz in ("clipboard", "Clipboard", "QGuiApplication", "PANO_", "_pano_", "Panoya"):
        assert iz not in kaynak, f"pano izi hâlâ kaynakta: {iz!r}"


def test_yazdir_dugmesi_VAR(modal: RecoveryShareDialog):
    assert _nesne(modal, "kurtarma_btn_yazdir") is not None


def test_yazdirma_uyarisi_HER_ZAMAN_gorunuyor(modal: RecoveryShareDialog):
    """Paylaşılan yazıcı riski GİZLENMİYOR — panonun "sessiz" riskinin
    aksine, buton tıklanmadan ÖNCE bile ekranda."""
    etiket = _nesne(modal, "kurtarma_yazdir_uyarisi")
    assert etiket is not None
    assert etiket.text() == YAZDIRMA_UYARISI


def test_yazdirma_uyarisi_MODULDEN_geliyor():
    """Uyarı metni sabitten okunuyor mu — ikinci bir kopya olmasın."""
    kaynak = (KOK / "UI" / "RecoveryShareDialog.py").read_text(encoding="utf-8")
    assert "QLabel(YAZDIRMA_UYARISI)" in kaynak


def test_yazdir_tiklaninca_YAZICI_DIYALOGU_aciliyor(
    modal: RecoveryShareDialog, yazdirma_kabul: list[bool], yazdirma_yakala: list[object],
):
    """Uçtan uca: düğme → `QPrintDialog` → kabul → `QTextDocument.print_()`."""
    modal._btn_yazdir.click()
    assert len(yazdirma_kabul) == 1, "yazıcı diyaloğu hiç açılmadı"
    assert len(yazdirma_yakala) == 1, "belge yazdırılmadı"
    assert "gönderildi" in modal._yazdir_durum.text()


def test_yazdirma_IPTAL_edilirse_YAZDIRILMIYOR(
    modal: RecoveryShareDialog, yazdirma_iptal: list[bool], yazdirma_yakala: list[object],
):
    """
    Kullanıcı yazıcı diyaloğunu kapatırsa belge HİÇ basılmamalı.

    Panonun "önce uyar, sonra yaz" ilkesinin karşılığı: burada onay
    ZATEN `QPrintDialog`'un kendisi, o reddedilince akış durmalı.
    """
    modal._btn_yazdir.click()
    assert len(yazdirma_iptal) == 1
    assert len(yazdirma_yakala) == 0, "iptal edilmesine rağmen belge basıldı"
    assert "iptal" in modal._yazdir_durum.text().lower()


def test_yazdirilan_belge_QR_ve_BASE32_ikisini_de_iceriyor(
    modal: RecoveryShareDialog, disa_aktarim: RecoveryExport,
):
    """
    Kâğıda basılan tek nüsha hem QR'ı hem metni taşımalı — ekrandakiyle
    AYNI bilgi, ikinci bir üretim yolu OLMADAN (bkz. `_yazdirilabilir_belge()`
    docstring'i ve aşağıdaki AST testi).
    """
    belge = modal._yazdirilabilir_belge()
    assert disa_aktarim.base32_text in belge.toPlainText()
    assert "kurtarma://qr" in belge.toHtml(), "QR görseli belgeye hiç eklenmemiş"


def test_yazdirilan_belge_UYARI_metnini_de_iceriyor(
    modal: RecoveryShareDialog, disa_aktarim: RecoveryExport,
):
    belge = modal._yazdirilabilir_belge()
    assert disa_aktarim.warning in belge.toPlainText()


def test_QR_yokken_belge_YINE_DE_kuruluyor(qapp):  # type: ignore[no-untyped-def]
    """`qrcode` paketi yoksa (`qr_svg is None`) yazdırma HİÇ patlamamalı —
    base32 tek başına yeterli, `_qr_bloku()`'nun aynı kuralı burada da."""
    d = RecoveryShareDialog(RecoveryExport(base32_text="HYCLEUS-R3-AAAA", qr_svg=None))
    try:
        belge = d._yazdirilabilir_belge()
        assert "HYCLEUS-R3-AAAA" in belge.toPlainText()
        assert "kurtarma://qr" not in belge.toHtml()
    finally:
        d.deleteLater()


# ══════════════════════════════════════════════════════════════════════════════
# 4. Ekran yakalama koruması
# ══════════════════════════════════════════════════════════════════════════════


def test_koruma_durumu_HER_ZAMAN_yaziliyor(modal: RecoveryShareDialog):
    """
    Yalnızca sorun varken yazmak, "yazmıyorsa her şey yolunda" diye okunur
    ve o çıkarım sessiz bir düşüşte yanlış olur (B-025).
    """
    etiket = _nesne(modal, "kurtarma_koruma_durumu")
    assert etiket is not None, "koruma durumu hiç gösterilmiyor"
    metin = etiket.text()
    assert metin, "koruma durumu boş"
    assert metin.startswith(KORUMA_YOK.split("{")[0]), (
        "offscreen platformda yerli pencere yok, koruma KURULAMAMALI")


def test_koruma_ETKINKEN_de_yaziliyor(qapp, disa_aktarim: RecoveryExport,
                                      monkeypatch: pytest.MonkeyPatch):
    """
    Korumanın ÇALIŞTIĞI durum da ekranda görünmeli.

    Bu test olmadan "başarı" dalı hiç gezilmiyordu: `offscreen` platformda
    yerli pencere olmadığı için koruma her zaman başarısız oluyor.
    Mutasyonla ölçüldü — başarı dalını boş dizeye çeviren mutasyon HAYATTA
    KALMIŞTI, yani o dal test edilmiyordu.
    """
    monkeypatch.setattr("UI.RecoveryShareDialog.ekran_yakalamayi_engelle",
                        lambda pencere: (True, ""))
    d = RecoveryShareDialog(disa_aktarim)
    try:
        etiket = _nesne(d, "kurtarma_koruma_durumu")
        assert etiket is not None
        assert etiket.text() == KORUMA_ETKIN, (
            "koruma çalışıyorken kullanıcıya hiçbir şey söylenmiyor")
    finally:
        d.deleteLater()


def test_koruma_BASARISIZLIGI_pencereyi_engellemiyor(modal: RecoveryShareDialog):
    """
    Koruma kurulamasa bile modal çalışmalı.

    `offscreen` platformda yerli pencere yok, yani bu koşuda koruma
    KURULAMIYOR — test tam da o yolu geziyor.
    """
    assert modal._metin.toPlainText()
    assert modal._btn_yazdir.isEnabled()


def test_koruma_yardimcisi_TEK_karar_noktasi():
    """
    `SetWindowDisplayAffinity` yalnızca bir yerden çağrılmalı.

    İkinci bir çağrı yeri bayrağı unutabilir ve fark edilmezdi — koruma
    "bazen açık" olurdu ki bu, hiç olmamasından kötü.
    """
    ihlal = []
    for katman in ("UI", "CORE", "DB"):
        for yol in (KOK / katman).rglob("*.py"):
            if "__pycache__" in yol.parts:
                continue
            agac = ast.parse(yol.read_text(encoding="utf-8"), filename=str(yol))
            for dugum in ast.walk(agac):
                if (isinstance(dugum, ast.Call)
                        and getattr(dugum.func, "attr", "") == "SetWindowDisplayAffinity"
                        and yol.name != "RecoveryShareDialog.py"):
                    ihlal.append(f"{yol.name}:{dugum.lineno}")
    assert not ihlal, f"Ekran koruması ikinci bir yerden çağrılıyor: {ihlal}"


def test_windows_disinda_ACIK_gerekce(monkeypatch: pytest.MonkeyPatch,
                                      modal: RecoveryShareDialog):
    """Windows dışı platformda neden çalışmadığı yazılmalı — B-049."""
    monkeypatch.setattr("UI.RecoveryShareDialog.sys.platform", "linux")
    tamam, neden = ekran_yakalamayi_engelle(modal)
    assert tamam is False
    assert "Windows" in neden and "linux" in neden


# ══════════════════════════════════════════════════════════════════════════════
# 5. TEK ÜRETİM YOLU — AST
# ══════════════════════════════════════════════════════════════════════════════


def test_modal_QR_uretmiyor_GOSTERIYOR():
    """
    Arayüz kendi QR'ını çizerse iki biçim ayrışabilir: kullanıcı QR'ı basar,
    base32'yi okur ve ikisi farklı payı taşır.
    """
    agac = ast.parse((KOK / "UI" / "RecoveryShareDialog.py").read_text(encoding="utf-8"))
    for dugum in ast.walk(agac):
        if isinstance(dugum, (ast.Import, ast.ImportFrom)):
            adlar = ([a.name for a in dugum.names] if isinstance(dugum, ast.Import)
                     else [dugum.module or ""])
            for ad in adlar:
                assert not ad.startswith("qrcode"), f"modal qrcode'u içe aktarıyor: {ad}"
        if isinstance(dugum, ast.Call):
            cagri = getattr(dugum.func, "attr", getattr(dugum.func, "id", ""))
            assert cagri not in ("render_qr_svg", "encode_share", "build_export"), (
                f"modal {cagri} çağırıyor — üretmemeli, göstermeli")


def test_uyari_metni_YENIDEN_yazilmamis(disa_aktarim: RecoveryExport):
    """Komut satırı ve arayüz AYNI cümleleri söylemeli."""
    assert disa_aktarim.warning == WARNING_TEXT
    kaynak = (KOK / "UI" / "RecoveryShareDialog.py").read_text(encoding="utf-8")
    assert "FİZİKSEL" not in kaynak, "uyarı metni arayüzde yeniden yazılmış"
    assert "self._export.warning" in kaynak


def test_modal_paya_DOKUNMUYOR():
    """
    Pencere ham payı ("3:<hex>") hiç görmüyor — yalnızca `RecoveryExport`.

    Görseydi onu bir yere yazma ihtimali doğardı; görmediği için o soru
    hiç sorulmuyor.
    """
    kaynak = (KOK / "UI" / "RecoveryShareDialog.py").read_text(encoding="utf-8")
    assert "share_3" not in kaynak
    assert "export_recovery_share" not in kaynak


# ══════════════════════════════════════════════════════════════════════════════
# 6. AdminSettingsView girişi + Doğrulama Merkezi girişi — İKİ ÇAĞIRAN, TEK GÖVDE
# ══════════════════════════════════════════════════════════════════════════════
#
# B-093'ten itibaren gövde `UI/security_actions.py::kurtarma_parcasini_
# goster()`'e taşındı — Doğrulama Merkezi'nin (`UI/GuvenlikView.py`) AYNI
# eylemi çağırabilmesi için (bkz. o modülün "iki çağıran, tek gövde"
# gerekçesi). Aşağıdaki testler artık İKİ şeyi ayrı ayrı ölçüyor:
#   · AdminSettingsView/GuvenlikView'ın KENDİSİ ikinci bir uygulama
#     KURMADIĞI — ikisi de aynı paylaşılan fonksiyonu çağırıyor.
#   · Gerçek zincirin (PIN → export → build_export → modal, hiçbir yere
#     kayıt) paylaşılan gövdenin İÇİNDE, eksiksiz durduğu.


def test_adminpanel_dugmesi_PAYLASILAN_govdeyi_CAGIRIYOR():
    """
    `_on_kurtarma_parcasi` artık ikinci bir uygulama DEĞİL, TEK bir çağrı —
    zincirin kendisi `security_actions.py`'de (aşağıdaki test).
    """
    kaynak = (KOK / "UI" / "AdminSettingsView.py").read_text(encoding="utf-8")
    agac = ast.parse(kaynak)
    govde = next(
        (d for d in ast.walk(agac)
         if isinstance(d, ast.FunctionDef) and d.name == "_on_kurtarma_parcasi"),
        None)
    assert govde is not None, "_on_kurtarma_parcasi tanımlı değil"
    cagrilar = _cagri_adlari(govde)
    assert cagrilar == {"kurtarma_parcasini_goster"}, (
        f"AdminSettingsView ikinci bir uygulama kuruyor olabilir: {cagrilar}"
    )
    assert "self._btn_kurtarma.clicked.connect(self._on_kurtarma_parcasi)" in kaynak


def test_gorunum_dugmesi_de_AYNI_govdeyi_CAGIRIYOR():
    """Doğrulama Merkezi'nin kartı da AYNI paylaşılan fonksiyonu çağırıyor."""
    kaynak = (KOK / "UI" / "GuvenlikView.py").read_text(encoding="utf-8")
    agac = ast.parse(kaynak)
    govde = next(
        (d for d in ast.walk(agac)
         if isinstance(d, ast.FunctionDef) and d.name == "_kurtarma_parcasi"),
        None)
    assert govde is not None, "_kurtarma_parcasi tanımlı değil"
    cagrilar = _cagri_adlari(govde)
    assert cagrilar == {"kurtarma_parcasini_goster"}, (
        f"GuvenlikView ikinci bir uygulama kuruyor olabilir: {cagrilar}"
    )


def test_kurtarma_govdesi_PAYLASILAN_yerde_ZINCIRIN_TAMAMI():
    """
    Düğme → PIN → `export_recovery_share` → `build_export` → modal —
    zincirin her halkası `security_actions.py::kurtarma_parcasini_goster()`
    içinde, İKİ çağıranın da ULAŞTIĞI TEK yerde duruyor mu.
    """
    kaynak = (KOK / "UI" / "security_actions.py").read_text(encoding="utf-8")
    agac = ast.parse(kaynak)
    govde = next(
        (d for d in ast.walk(agac)
         if isinstance(d, ast.FunctionDef) and d.name == "kurtarma_parcasini_goster"),
        None)
    assert govde is not None, "kurtarma_parcasini_goster tanımlı değil"
    metin = ast.unparse(govde)
    for beklenen in ("has_recovery_share", "export_recovery_share",
                     "build_export", "RecoveryShareDialog", "del share_3",
                     "yonetici_hala_yetkili"):
        assert beklenen in metin, f"zincirde eksik: {beklenen}"

    # Ve İKİ çağıranın ikisi de AYNI ada gidiyor mu (kör bir tarayıcı
    # olmasın — biri farklı bir isimle çağırıp yine "geçerdi" diyebilirdi).
    for dosya in ("UI/AdminSettingsView.py", "UI/GuvenlikView.py"):
        icerik = (KOK / dosya).read_text(encoding="utf-8")
        assert "kurtarma_parcasini_goster" in icerik, (
            f"{dosya} paylaşılan gövdeyi çağırmıyor"
        )


def test_PIN_gercekten_KULLANICIDAN_geliyor():
    """
    `pin` değişkeninin değeri DOĞRUDAN `QInputDialog.getText` çağrısı olmalı.

    "Kaynakta `QInputDialog.getText` geçiyor mu" diye bakmak YETMİYOR:
    mutasyonla ölçüldü — `pin, ok = ('0000', True) or QInputDialog.getText(...)`
    o denetimi geçiyordu. Çağrı duruyor ama artık PIN'i o vermiyor.
    """
    agac = ast.parse((KOK / "UI" / "security_actions.py").read_text(encoding="utf-8"))
    govde = next(d for d in ast.walk(agac)
                 if isinstance(d, ast.FunctionDef) and d.name == "kurtarma_parcasini_goster")

    atamalar = [
        d for d in ast.walk(govde)
        if isinstance(d, ast.Assign)
        and any(isinstance(h, ast.Tuple)
                and [getattr(e, "id", "") for e in h.elts] == ["pin", "ok"]
                for h in d.targets)
    ]
    assert len(atamalar) == 1, "`pin, ok = ...` ataması tekil değil"
    deger = atamalar[0].value
    assert isinstance(deger, ast.Call), (
        f"PIN doğrudan bir çağrıdan gelmiyor: {ast.unparse(deger)}")
    assert ast.unparse(deger.func) == "QInputDialog.getText", (
        f"PIN'i veren çağrı QInputDialog.getText değil: {ast.unparse(deger.func)}")

    # Ve PIN doğrulamaya GİDİYOR mu — sorulup atılması da bir kusur olurdu.
    cagri = next(d for d in ast.walk(govde)
                 if isinstance(d, ast.Call)
                 and getattr(d.func, "id", "") == "export_recovery_share")
    assert "pin" in ast.unparse(cagri), "sorulan PIN doğrulamada kullanılmıyor"


#: Kurtarma parçasını kalıcılaştırabilecek çağrılar.
_YAZAN_CAGRILAR = frozenset({
    "write_text", "write_bytes", "writelines", "write", "dump", "dumps",
    "log", "info", "debug", "warning", "error", "getSaveFileName",
})


def _cagri_adlari(dugum: ast.AST) -> set[str]:
    """Bir gövdedeki çağrı adları — AST, metin araması DEĞİL."""
    return {
        getattr(d.func, "attr", getattr(d.func, "id", ""))
        for d in ast.walk(dugum) if isinstance(d, ast.Call)
    }


def test_adminpanel_payi_DISKE_yazmiyor():
    """
    Kurtarma parçasının KENDİSİ hiçbir yere kaydedilmez — modülün ilk kuralı.

    B-104 SONRASI GÜNCEL DURUM: görüntüleme OLAYININ KENDİSİ artık
    `_kaydet_ve_cipaya_kazi()` ile denetim kaydına/çıpaya düşüyor — bu
    yüzden "log" içeren HİÇBİR çağrı olmamalı denetimi artık YANLIŞ
    olurdu. Doğru soru "log çağrısı var mı" değil, "payın KENDİSİ o
    çağrıya ARGÜMAN olarak gidiyor mu" — bkz. aşağıdaki
    `test_the_recovery_share_value_never_reaches_a_persisting_call`, asıl
    güvenceyi VEREN test bu. Burası yalnızca `_kaydet_ve_cipaya_kazi`
    DIŞINDA beklenmedik bir yazan çağrı sızmadığını doğruluyor.

    Denetim AST ile: ilk yazımda `"log(" in metin` kullanılmıştı ve
    `RecoveryShareDialog(` içindeki "log(" hecesine takıldı. Bu deponun
    tekrarlayan hatası (son örnek B-024) — metin araması, kuralın kendisini
    anlatan ya da ona benzeyen her şeye takılıyor.

    Paylaşılan gövdenin KENDİSİ ölçülüyor — AdminSettingsView'ınki artık
    boş bir delegasyon, riskin gerçekten durduğu yer değil.
    """
    agac = ast.parse((KOK / "UI" / "security_actions.py").read_text(encoding="utf-8"))
    govde = next(d for d in ast.walk(agac)
                 if isinstance(d, ast.FunctionDef) and d.name == "kurtarma_parcasini_goster")
    yazanlar = _cagri_adlari(govde) & _YAZAN_CAGRILAR
    assert not yazanlar, f"pay diske/kayda gidiyor olabilir: {sorted(yazanlar)}"


def test_the_recovery_share_value_never_reaches_a_persisting_call():
    """
    ASIL GÜVENCE (B-104) — `share_3`/`disa_aktarim` (payın KENDİSİ), payı
    ALMASI GEREKEN iki halka (`build_export`, `RecoveryShareDialog`) DIŞINDA
    HİÇBİR çağrıya ARGÜMAN olarak gitmiyor.

    Bu, üstteki testin BOŞLUĞUNU kapatıyor: "log(" gibi bir çağrı ADI
    aramak, payı BAŞKA bir yardımcıya (`_kaydet_ve_cipaya_kazi(share_3)`
    gibi) parametre olarak geçirip yine "temiz" görünmeyi engellemezdi —
    çağrı adı "log" değil "_kaydet_ve_cipaya_kazi" olurdu. Burada
    ÇAĞRININ ADINA değil ARGÜMANLARINA bakılıyor.
    """
    agac = ast.parse((KOK / "UI" / "security_actions.py").read_text(encoding="utf-8"))
    govde = next(d for d in ast.walk(agac)
                 if isinstance(d, ast.FunctionDef) and d.name == "kurtarma_parcasini_goster")

    yasakli = {"share_3", "disa_aktarim"}
    izinli_cagrilar = {"build_export", "RecoveryShareDialog"}

    for cagri in ast.walk(govde):
        if not isinstance(cagri, ast.Call):
            continue
        cagri_adi = getattr(cagri.func, "attr", getattr(cagri.func, "id", ""))
        if cagri_adi in izinli_cagrilar:
            continue
        argumanlar = list(cagri.args) + [kw.value for kw in cagri.keywords]
        kullanilan_isimler = {
            n.id for a in argumanlar for n in ast.walk(a) if isinstance(n, ast.Name)
        }
        cakisan = kullanilan_isimler & yasakli
        assert not cakisan, (
            f"{ast.unparse(cagri.func)}() payı taşıyor olabilir: {sorted(cakisan)}"
        )


def test_yazan_cagri_denetimi_KOR_degil():
    """Tarayıcı gerçekten yakalıyor mu — sahte bir gövdeyle ölçülüyor."""
    sahte = ast.parse(
        "def f():\n"
        "    Path('x').write_text(share_3)\n"
        "    DBManager().log('a', detail=share_3)\n")
    assert _cagri_adlari(sahte) & _YAZAN_CAGRILAR == {"write_text", "log"}


def test_the_persisting_call_argument_scanner_is_not_blind():
    """`test_the_recovery_share_value_never_reaches_a_persisting_call`'ın
    tarayıcısı gerçekten yakalıyor mu — sahte bir gövdeyle ölçülüyor."""
    sahte = ast.parse(
        "def kurtarma_parcasini_goster():\n"
        "    _kaydet_ve_cipaya_kazi(share_3)\n"
        "    build_export(share_3)\n")
    govde = sahte.body[0]
    yasakli = {"share_3", "disa_aktarim"}
    izinli_cagrilar = {"build_export", "RecoveryShareDialog"}
    yakalanan = []
    for cagri in ast.walk(govde):
        if not isinstance(cagri, ast.Call):
            continue
        cagri_adi = getattr(cagri.func, "attr", getattr(cagri.func, "id", ""))
        if cagri_adi in izinli_cagrilar:
            continue
        argumanlar = list(cagri.args) + [kw.value for kw in cagri.keywords]
        kullanilan_isimler = {
            n.id for a in argumanlar for n in ast.walk(a) if isinstance(n, ast.Name)
        }
        if kullanilan_isimler & yasakli:
            yakalanan.append(cagri_adi)
    assert yakalanan == ["_kaydet_ve_cipaya_kazi"], (
        "tarayıcı ya kaçırdı ya da izinli çağrıyı da yanlışlıkla yakaladı"
    )


def test_modal_key_press_ESC(qapp, disa_aktarim: RecoveryExport):
    """Gerçek Esc tuşu — `reject()` çağrısı değil, kullanıcının yaptığı şey."""
    from PySide6.QtGui import QKeyEvent

    d = RecoveryShareDialog(disa_aktarim)
    try:
        d.show()
        d.keyPressEvent(QKeyEvent(QKeyEvent.KeyPress, Qt.Key_Escape, Qt.NoModifier))
        assert d.result() == QDialog.Rejected
        assert not d.isVisible()
    finally:
        d.deleteLater()
