"""
HYCLEUS — Kullanıcı rehberinin ÜÇ erişim yolu, TEK kaynağı

Neden bu modül var
------------------
`docs/kullanici-rehberi.md` üç ayrı yerden okunuyor:

    1. Web / PDF   — asıl kopya (`docs/kullanici-rehberi.pdf`)
    2. Uygulama    — hamburger menüsündeki "Kullanım Rehberi"
    3. `.hclx`     — teslim paketine gömülen kopya

Üç erişim yolu ama **tek bakım yeri**: hepsi aynı Markdown'dan türüyor ve
PDF'i üreten tek fonksiyon `pdf_uret()`. İkinci bir üretim yolu açmak, bu
deponun beş kez ürettiği kusurun (aynı iş için iki uygulama — B-004/B-008,
B-007, B-010, B-011, pay ayrıştırıcı) tam giriş koşulu olurdu; bir AST
denetimi (`tests/test_rehber_kopyalari.py`) ikinci yolu yakalıyor.

Zincir şöyle kapanıyor:

    kullanici-rehberi.md ──SHA-256──▶ PDF'in /Subject alanına gömülü özet
    kullanici-rehberi.pdf ──BAYT BAYT──▶ .hclx içindeki kopya

Yani "PDF markdown ile güncel mi" sorusu PDF'in KENDİSİNE sorulabiliyor —
elde markdown olmasa bile. Ve gömülü kopyanın doğrulanması karşılaştırma,
yeniden üretim değil: `.hclx` PDF'i ÜRETMİYOR, var olan dosyayı okuyor.


PDF NEDEN ELLE ÜRETİLİYOR, CI'DA DEĞİL
---------------------------------------
Karar: **yerelde üretilip depoya işleniyor; CI yalnızca DOĞRULUYOR.**
Dört gerekçe, önem sırasıyla:

1. **PDF'in çalışma zamanında var olması gerekiyor.** Menü onu açıyor ve
   `.hclx` onu gömüyor. CI artifact'i kullanıcının kurulu uygulamasında
   yok; artifact olarak üretmek üç erişim yolundan ikisini çalışmaz
   bırakırdı.
2. **CI'ın depoya yazması gerekirdi.** Üretim CI'da olsaydı sonucu
   işlemek için CI'ın push etmesi gerekirdi. Bu depoda push insanın
   kararı; bir iş akışına o yetkiyi vermek belge üretmekten çok daha
   büyük bir değişiklik olurdu.
3. **Bayt düzeyinde yeniden üretilebilirlik garanti edilemez.** Çıktı
   `invariant=1` ile aynı reportlab sürümünde kararlı, ama sürüm
   yükseldiğinde baytlar değişebilir. CI "yeniden üret ve baytları
   karşılaştır" yapsaydı, reportlab'ın her yamasında kırmızıya düşerdi.
   Bunun yerine CI **özet sözleşmesini** doğruluyor: sürümden bağımsız.
4. **Üretim tek komut.** `python CORE/rehber.py --uret`. Test ayrışmayı
   bulduğunda hata mesajı bu komutu söylüyor.

CI tarafındaki doğrulama ayrı bir iş akışı adımı DEĞİL: `tests/` zaten
CI'da koşuyor ve `test_rehber_kopyalari.py` oradan çalışıyor.


Yazı tipi ve simgeler
---------------------
reportlab'ın gömülü standart yazı tipleri (Helvetica, Courier) WinAnsi
kodlamalı ve Türkçe'nin `ğ ı İ ş` harfleri o kodlamada YOK — sessizce
kutuya dönerler. Bu yüzden reportlab'la birlikte gelen **Bitstream Vera**
kullanılıyor (izin verici lisans, paketin içinde, ek bağımlılık yok).

Vera Türkçe'nin tamamını kapsıyor ama emoji kapsamıyor. Rehberde geçen 13
simge `_SIMGE` tablosuyla ASCII karşılıklarına çevriliyor; tablonun
EKSİKSİZ olduğu test edilmiş durumda — rehbere yeni bir simge girerse
test düşüyor, PDF'te boş kutu çıkmıyor.

Çıktıda yine de bir `/BaseFont /Helvetica` girdisi görünüyor. ÖLÇÜLDÜ:
yalnızca Vera kullanan en küçük belgede bile çıkıyor — reportlab tuvalin
başlangıç yazı tipini koşulsuz yazıyor. Hiçbir metin onu kullanmıyor;
`test_stiller_TAMAMEN_Vera` bunu sabitliyor.
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import re
import sys
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# Donmuş yapıda (`sys.frozen`) kaynak ağacı YOK; PDF paketin açıldığı
# geçici köke (`sys._MEIPASS`) kopyalanıyor. `CORE/paths.py::data_dir()`
# YAZILABİLİR bir dizin arıyor ve EXE'nin yanına bakıyor; buradaki dosya
# SALT OKUNUR bir varlık, o yüzden kök farklı. İki soru, iki yanıt.
if getattr(sys, "frozen", False):  # pragma: no cover — yalnızca donmuş yapıda
    _KOK = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
else:
    _KOK = Path(__file__).resolve().parent.parent

#: Tek kaynak. Diğer her şey bundan türüyor.
KAYNAK = _KOK / "docs" / "kullanici-rehberi.md"

#: Asıl kopya. Menü bunu açıyor, `.hclx` bunu gömüyor.
PDF = _KOK / "docs" / "kullanici-rehberi.pdf"

#: PDF yoksa menünün düştüğü adres.
WEB = "https://github.com/yubin-dev/HYCLEUS/blob/main/docs/kullanici-rehberi.md"

#: PDF'in `/Subject` alanına yazılan sözleşme. Değeri kaynak Markdown'ın
#: SHA-256'sı; okuyucu PDF'e bakarak "bu hangi sürümden üretildi" diyebiliyor.
OZET_ONEKI = "HYCLEUS-rehber-kaynak-sha256="

#: PDF'in `/Creator` alanına yazılan üretici imzası. Sürüm numarası BİLEREK
#: içeride: bayt düzeyinde yeniden üretilebilirlik yalnızca AYNI reportlab
#: sürümünde geçerli ve testin bunu bilmesi gerekiyor (bkz. modül başlığı,
#: 3. gerekçe). Sürüm farklıysa test bayt karşılaştırmasını ATLIYOR —
#: sessizce geçmiyor, atladığını söylüyor.
#:
#: Dize SALT ASCII: PDF bilgi sözlüğü ASCII dışını sekizli kaçışa çeviriyor
#: (ölçüldü — `·` baytlarda `\267` oldu) ve ham bayt üzerinde arayan okuyucu
#: onu bulamıyordu.
URETICI_ONEKI = "HYCLEUS CORE/rehber.py reportlab "

#: Menüdeki etiket. Rehberin kendisi de bu etiketten söz ediyor ve
#: `tests/test_rehber_kopyalari.py` ikisinin eşleştiğini doğruluyor.
MENU_ETIKETI = "📘  Kullanım Rehberi"

#: `.hclx` içine gömülürken kullanılan ad.
PAKET_ADI = "kullanici-rehberi.pdf"


class RehberError(RuntimeError):
    """Rehber üretilemedi ya da bulunamadı."""


# ══════════════════════════════════════════════════════════════════════════════
# 1. Kaynak ve özet
# ══════════════════════════════════════════════════════════════════════════════


def kanonik(ham: bytes) -> bytes:
    """
    Satır sonlarını LF'e indirger — özet İÇERİĞİ imzalıyor, KODLAMAYI değil.

    Neden gerekli, ve neden bu bir gevşetme DEĞİL
    ---------------------------------------------
    `pdf_uret()` metni zaten satır sonundan bağımsız işliyor: `akis()`
    ilk iş olarak `metin.replace("\\r\\n", "\\n")` yapıyor. Yani CRLF ve LF
    kaynaklardan üretilen PDF'ler ÖLÇÜLDÜ — aynı uzunlukta ve tek fark
    gömülü özetin kendisi:

        CRLF kaynaktan  59368 bayt  özet 13be125c...
        LF   kaynaktan  59368 bayt  özet 552117f7...

    Yani ham baytları imzalamak, PDF'in TAŞIMADIĞI bir özelliği
    belgeliyordu. Depo Windows'ta geliştirilip Linux'ta koşuyor; git
    `text=auto` ile içeride LF tutup Windows çalışma ağacına CRLF veriyor
    (bkz. `.gitattributes`). İki ortam ham baytta hiçbir zaman anlaşamaz.

    Normalleştirme hiçbir gerçek değişikliği gizlemiyor: tek bir harf,
    boşluk ya da satır eklense özet yine değişiyor. Yalnızca "aynı belge,
    farklı satır sonu" durumunu ayrışma saymaktan vazgeçiyor.
    """
    return ham.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def kaynak_ozeti(kaynak: Path | str | None = None) -> str:
    """Markdown kaynağının SHA-256'sı (hex) — satır sonundan bağımsız."""
    yol = Path(kaynak) if kaynak else KAYNAK
    try:
        return hashlib.sha256(kanonik(yol.read_bytes())).hexdigest()
    except OSError as exc:
        raise RehberError(f"Rehber kaynağı okunamadı: {exc}") from exc


def pdf_kaynak_ozeti(pdf: Path | str | None = None) -> str | None:
    """
    PDF'in içine gömülü kaynak özeti — PDF'i açmadan, ham baytlardan.

    `None` dönerse PDF ya yok ya da bu modülün üretmediği bir dosya.
    """
    yol = Path(pdf) if pdf else PDF
    try:
        ham = yol.read_bytes()
    except OSError:
        return None
    eslesme = re.search(
        rb"/Subject\s*\(" + re.escape(OZET_ONEKI.encode("ascii")) + rb"([0-9a-f]{64})\)",
        ham,
    )
    return eslesme.group(1).decode("ascii") if eslesme else None


def pdf_uretici_surumu(pdf: Path | str | None = None) -> str | None:
    """PDF'i üreten reportlab sürümü — ham baytlardan, `None` bilinmiyorsa."""
    yol = Path(pdf) if pdf else PDF
    try:
        ham = yol.read_bytes()
    except OSError:
        return None
    eslesme = re.search(
        rb"/Creator\s*\(" + re.escape(URETICI_ONEKI.encode("utf-8")) + rb"([0-9.]+)\)",
        ham,
    )
    return eslesme.group(1).decode("ascii") if eslesme else None


def guncel_mi(pdf: Path | str | None = None, kaynak: Path | str | None = None) -> bool:
    """PDF, elimizdeki Markdown'dan mı üretilmiş."""
    return pdf_kaynak_ozeti(pdf) == kaynak_ozeti(kaynak)


def erisim_yolu() -> tuple[str, str]:
    """
    Rehbere BUGÜN nasıl ulaşılır: `("pdf", yol)` ya da `("web", adres)`.

    Menü bu kararı kendisi vermiyor — vermeye kalksaydı ikinci bir karar
    noktası olurdu ve biri güncellenip diğeri unutulurdu.
    """
    return ("pdf", str(PDF)) if PDF.is_file() else ("web", WEB)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Markdown → akış (flowable) çevirisi
# ══════════════════════════════════════════════════════════════════════════════

#: Vera'nın kapsamadığı simgelerin ASCII karşılıkları.
#:
#: Boş dize = yalnızca süs, atılıyor (menü etiketlerindeki 📋/🔍 gibi).
#: Tablonun eksiksizliği test ediliyor: rehbere yeni bir simge girerse
#: `test_simge_tablosu_EKSIKSIZ` düşüyor.
_SIMGE = {
    "→": "->",          # →
    "⏸": "||",          # ⏸
    "⚠": "(!)",         # ⚠
    "⛔": "(DUR)",       # ⛔
    "✅": "(+)",         # ✅
    "✔": "(+)",         # ✔
    "✖": "(x)",         # ✖
    "⧉": "[kopyala]",   # ⧉
    "☰": "[menu]",      # ☰ — hamburger düğmesi
    "\U0001f4d8": "",        # 📘
    "\U0001f4cb": "",        # 📋
    "\U0001f50d": "",        # 🔍
    "️": "",            # varyasyon seçici (görünmez)
}

_KALIN = re.compile(r"\*\*(.+?)\*\*", re.S)
_KOD = re.compile(r"`([^`]+)`")
_TABLO_AYIRAC = re.compile(r"^\|[\s:|-]+\|$")


def simgeleri_cevir(metin: str) -> str:
    """Yazı tipinin tanımadığı simgeleri ASCII karşılıklarıyla değiştirir."""
    for simge, karsilik in _SIMGE.items():
        metin = metin.replace(simge, karsilik)
    return metin


def _kacir(metin: str) -> str:
    """reportlab Paragraph içeriği mini-HTML — `&<>` kaçırılmalı."""
    return metin.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _satir_ici(metin: str) -> str:
    """`**kalın**` ve `` `kod` `` işaretlerini mini-HTML'e çevirir."""
    metin = _kacir(simgeleri_cevir(metin))
    metin = _KOD.sub(r'<font face="VeraMono" size="8.5">\1</font>', metin)
    return _KALIN.sub(r"<b>\1</b>", metin)


def yazi_tipleri_kur() -> None:
    """
    Bitstream Vera'yı kaydeder — reportlab'ın kendi paketinden.

    Standart yazı tipleri Türkçe'yi taşımıyor (modül başlığı). Kayıt
    tekrarlanabilir: reportlab aynı adı yeniden kaydetmeye izin veriyor.
    """
    import reportlab
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    dizin = Path(reportlab.__file__).parent / "fonts"
    for ad, dosya in (("Vera", "Vera.ttf"), ("Vera-Bold", "VeraBd.ttf"),
                      ("Vera-Italic", "VeraIt.ttf")):
        pdfmetrics.registerFont(TTFont(ad, str(dizin / dosya)))
    # Kod blokları için ayrı bir tek aralıklı yüz YOK (reportlab yalnızca
    # Vera'nın oransal kesimlerini taşıyor). Aynı yüz daha küçük punto ve
    # gri zeminle ayrışıyor; uydurma bir bağımlılık eklemekten iyi.
    pdfmetrics.registerFont(TTFont("VeraMono", str(dizin / "Vera.ttf")))
    pdfmetrics.registerFontFamily(
        "Vera", normal="Vera", bold="Vera-Bold", italic="Vera-Italic",
        boldItalic="Vera-Bold")


def _stiller() -> dict[str, Any]:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.styles import ParagraphStyle

    # `bulletFontName` TEMEL stilde: reportlab'ın varsayılanı Helvetica ve
    # o yüz Türkçe taşımıyor. Madde imi "•" ile rakamlar Helvetica'da VAR,
    # yani hata GÖRÜNMEZ olurdu — numaralı bir maddeye Türkçe karakter
    # girdiği gün sessizce boş kutu çıkardı. Temelde tanımlanıyor ki
    # sonradan eklenen her stil de devralsın.
    govde = ParagraphStyle(
        "Govde", fontName="Vera", bulletFontName="Vera", fontSize=9.5,
        leading=13.5, spaceAfter=6, alignment=TA_LEFT,
        textColor=colors.HexColor("#1F2937"))
    return {
        "h1": ParagraphStyle("H1", parent=govde, fontName="Vera-Bold",
                             fontSize=19, leading=24, spaceBefore=0, spaceAfter=14),
        "h2": ParagraphStyle("H2", parent=govde, fontName="Vera-Bold",
                             fontSize=14, leading=19, spaceBefore=16, spaceAfter=8),
        "h3": ParagraphStyle("H3", parent=govde, fontName="Vera-Bold",
                             fontSize=11, leading=15, spaceBefore=12, spaceAfter=6),
        "govde": govde,
        "madde": ParagraphStyle("Madde", parent=govde, leftIndent=14,
                                bulletIndent=4, spaceAfter=3,
                                bulletFontSize=9.5),
        "alinti": ParagraphStyle(
            "Alinti", parent=govde, leftIndent=12, spaceBefore=4,
            textColor=colors.HexColor("#4B5563"), borderPadding=0),
        "kod": ParagraphStyle(
            "Kod", parent=govde, fontName="VeraMono", fontSize=8.5, leading=11,
            leftIndent=8, rightIndent=8, spaceBefore=4, spaceAfter=8,
            backColor=colors.HexColor("#F3F4F6"), borderPadding=6),
        "hucre": ParagraphStyle("Hucre", parent=govde, fontSize=8.5, leading=11,
                                spaceAfter=0),
        "hucre_baslik": ParagraphStyle("HucreBaslik", parent=govde,
                                       fontName="Vera-Bold", fontSize=8.5,
                                       leading=11, spaceAfter=0),
    }


def _tablo(satirlar: list[str], stil: dict[str, Any]) -> Any:
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Table, TableStyle

    hucreler = [
        [h.strip() for h in s.strip().strip("|").split("|")]
        for s in satirlar if not _TABLO_AYIRAC.match(s.strip())
    ]
    if not hucreler:
        return None
    sutun = max(len(s) for s in hucreler)
    veri = [
        [Paragraph(_satir_ici(h), stil["hucre_baslik" if i == 0 else "hucre"])
         for h in (s + [""] * (sutun - len(s)))]
        for i, s in enumerate(hucreler)
    ]
    genislik = (170 * mm) / sutun
    tablo = Table(veri, colWidths=[genislik] * sutun, repeatRows=1, hAlign="LEFT")
    tablo.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E7EB")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9CA3AF")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return tablo


def akis(metin: str) -> list[Any]:
    """
    Markdown metnini reportlab akış nesnelerine çevirir.

    Desteklenen ne varsa rehberde GEÇEN o: başlıklar, paragraf, çitli kod
    bloğu, alıntı, madde/numaralı liste, yatay çizgi, boru tablosu, satır
    içi `**kalın**` ve `` `kod` ``. Rehberde olmayan bir yapı (bağlantı,
    resim, iç içe liste) bilerek desteklenmiyor — kullanılmayan kod ölü
    koddur ve bu depo onu siliyor.
    """
    from reportlab.lib.units import mm
    from reportlab.platypus import HRFlowable, Paragraph, Preformatted, Spacer

    stil = _stiller()
    parcalar: list[Any] = []
    satirlar = metin.replace("\r\n", "\n").split("\n")
    i = 0
    paragraf: list[str] = []
    tablo_tamponu: list[str] = []

    def paragrafi_bosalt() -> None:
        if paragraf:
            parcalar.append(Paragraph(_satir_ici(" ".join(paragraf)), stil["govde"]))
            paragraf.clear()

    def tabloyu_bosalt() -> None:
        if tablo_tamponu:
            t = _tablo(tablo_tamponu, stil)
            if t is not None:
                parcalar.append(t)
                parcalar.append(Spacer(1, 6))
            tablo_tamponu.clear()

    while i < len(satirlar):
        ham = satirlar[i]
        s = ham.strip()

        if s.startswith("```"):
            paragrafi_bosalt()
            tabloyu_bosalt()
            i += 1
            kod: list[str] = []
            while i < len(satirlar) and not satirlar[i].strip().startswith("```"):
                kod.append(simgeleri_cevir(satirlar[i]))
                i += 1
            i += 1
            parcalar.append(Preformatted("\n".join(kod) or " ", stil["kod"]))
            continue

        if s.startswith("|"):
            paragrafi_bosalt()
            tablo_tamponu.append(s)
            i += 1
            continue
        tabloyu_bosalt()

        if not s:
            paragrafi_bosalt()
        elif s.startswith("### "):
            paragrafi_bosalt()
            parcalar.append(Paragraph(_satir_ici(s[4:]), stil["h3"]))
        elif s.startswith("## "):
            paragrafi_bosalt()
            parcalar.append(Paragraph(_satir_ici(s[3:]), stil["h2"]))
        elif s.startswith("# "):
            paragrafi_bosalt()
            parcalar.append(Paragraph(_satir_ici(s[2:]), stil["h1"]))
        elif s in ("---", "***", "___"):
            paragrafi_bosalt()
            parcalar.append(Spacer(1, 4))
            parcalar.append(HRFlowable(width="100%", thickness=0.6,
                                       color="#D1D5DB", spaceAfter=8))
        elif s.startswith("> "):
            paragrafi_bosalt()
            parcalar.append(Paragraph(_satir_ici(s[2:]), stil["alinti"]))
        elif re.match(r"^[-*]\s+", s):
            paragrafi_bosalt()
            parcalar.append(Paragraph(_satir_ici(re.sub(r"^[-*]\s+", "", s)),
                                      stil["madde"], bulletText="•"))
        elif re.match(r"^\d+\.\s+", s):
            paragrafi_bosalt()
            numara = s.split(".", 1)[0]
            parcalar.append(Paragraph(_satir_ici(re.sub(r"^\d+\.\s+", "", s)),
                                      stil["madde"], bulletText=f"{numara}."))
        else:
            paragraf.append(s)
        i += 1

    paragrafi_bosalt()
    tabloyu_bosalt()
    parcalar.append(Spacer(1, 6 * mm))
    return parcalar


# ══════════════════════════════════════════════════════════════════════════════
# 3. TEK ÜRETİM YOLU
# ══════════════════════════════════════════════════════════════════════════════


def pdf_uret(hedef: Path | str | None = None,
             kaynak: Path | str | None = None) -> Path:
    """
    Markdown'dan PDF üretir — rehberin PDF'ini üreten TEK fonksiyon.

    İkinci bir üretim yolu açılırsa iki kopya ayrışır ve ayrışma sessiz
    olur; `tests/test_rehber_kopyalari.py` bunu AST ile yakalıyor.

    Çıktı `invariant=1` ile üretiliyor: aynı girdi + aynı reportlab sürümü
    = aynı baytlar. Belge kimliği ve tarih damgası sabitleniyor, yoksa her
    üretim farklı bayt verir ve "değişti mi" sorusu yanıtlanamaz.

    Returns:
        Yazılan PDF'in yolu.

    Raises:
        RehberError: reportlab yoksa, kaynak okunamazsa ya da yazma
            başarısız olursa.
    """
    try:
        import reportlab
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate
    except ImportError as exc:  # pragma: no cover — bağımlılık kurulu
        raise RehberError(
            "Rehber PDF'i için reportlab gerekli. "
            "Kurulum: pip install -r requirements.txt") from exc

    kaynak_yolu = Path(kaynak) if kaynak else KAYNAK
    cikti = Path(hedef) if hedef else PDF
    try:
        metin = kaynak_yolu.read_text(encoding="utf-8")
    except OSError as exc:
        raise RehberError(f"Rehber kaynağı okunamadı: {exc}") from exc

    yazi_tipleri_kur()
    # Özet `kaynak_ozeti()`'nden alınıyor, burada YENİDEN hesaplanmıyor.
    # İlk yazımda satır içi bir `sha256(read_bytes())` vardı: iki kopya, iki
    # kural. Doğrulayan taraf normalleştirip üreten taraf normalleştirmese
    # sorun çözülmez, yalnızca yer değiştirirdi.
    ozet = kaynak_ozeti(kaynak_yolu)

    cikti.parent.mkdir(parents=True, exist_ok=True)
    try:
        belge = SimpleDocTemplate(
            str(cikti),
            pagesize=A4,
            leftMargin=20 * mm, rightMargin=20 * mm,
            topMargin=18 * mm, bottomMargin=18 * mm,
            title="HYCLEUS — Kullanım Rehberi",
            author="HYCLEUS",
            creator=f"{URETICI_ONEKI}{reportlab.Version}",
            # Sözleşme: PDF hangi kaynaktan üretildiğini KENDİ İÇİNDE
            # taşıyor. Markdown elde olmasa bile sorulabilir.
            subject=f"{OZET_ONEKI}{ozet}",
            invariant=1,
        )
        belge.build(akis(metin))
    except Exception as exc:  # noqa: BLE001 — reportlab çeşitli tip atıyor
        raise RehberError(f"Rehber PDF'i üretilemedi: {exc}") from exc

    _log.info("rehber_pdf_uretildi hedef=%s ozet=%s", cikti.name, ozet[:12])
    return cikti


# ══════════════════════════════════════════════════════════════════════════════
# 4. CLI — yapı adımı
# ══════════════════════════════════════════════════════════════════════════════


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python CORE/rehber.py",
        description="Kullanıcı rehberinin PDF kopyasını üretir/denetler.")
    ap.add_argument("--uret", action="store_true",
                    help="docs/kullanici-rehberi.pdf dosyasını yeniden üretir")
    ap.add_argument("--denetle", action="store_true",
                    help="PDF, Markdown ile güncel mi — üretmeden bakar")
    a = ap.parse_args(argv)

    if not (a.uret or a.denetle):
        ap.print_help()
        return 2

    if a.denetle:
        if guncel_mi():
            print(f"GUNCEL   {PDF.name}  ({kaynak_ozeti()[:12]})")
            return 0
        print(f"AYRISMIS {PDF.name}")
        print(f"  kaynak : {kaynak_ozeti()[:12]}")
        print(f"  pdf    : {(pdf_kaynak_ozeti() or 'yok')[:12]}")
        print("  cozum  : python CORE/rehber.py --uret")
        return 1

    yol = pdf_uret()
    print(f"URETILDI {yol}  ({kaynak_ozeti()[:12]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
