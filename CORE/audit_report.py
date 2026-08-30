"""
HYCLEUS — denetim zinciri raporu (B-006)

Sorun
-----
Zincir doğrulaması üç yerden çağrılabiliyordu (`verify_audit_chain`,
`verify_against_anchor`, `verify_anchor_file`) ama hiçbirinin arayüzde
düğmesi yoktu. Kullanıcının zinciri kontrol edebildiği tek an açılıştı ve
o da yalnızca uyuşmazlık varsa konuşuyordu.

**Kurcalama kanıtı, ancak birileri kanıta BAKABİLİYORSA işe yarar.**

İkinci boşluk: `AuditLogDialog._export_txt()` yalnızca dört sütun
yazıyordu (zaman, işlem, kullanıcı, HWID). Hash yok, zincirin son ucu yok,
doğrulama durumu yok. Halbuki bu dışa aktarım, kullanıcının denetim
kaydını makine dışına taşıdığı tek yol — yani SECURITY.md §4.6'nın
"çıpayı başka bir güven alanına taşıyın" tavsiyesinin pratikteki karşılığı
olabilecek şey. O hâliyle dışa aktarılan dosyayla veritabanının tutarlı
olup olmadığı sonradan gösterilemiyordu.

Bu modül neden CORE'da
----------------------
Rapor METNİNİ üretiyor, diyalog açmıyor. Böylece Qt olmadan test
edilebiliyor (bkz. tests/test_layering.py) ve aynı metin hem "Zincir
Doğrula" düğmesinde hem TXT başlığında kullanılıyor — iki ayrı biçim
yazılsaydı biri güncellenip diğeri geride kalırdı.

İki doğrulama BİRLİKTE anlamlı
------------------------------
`verify_audit_chain()` zincirin İÇ tutarlılığını ölçüyor: her kaydın
hash'i bir öncekini doğru zincirliyor mu. Yakalayamadığı iki durum var —
kuyruğun kesilmesi ve zincirin baştan yeniden yazılması. İkisi de
kendi içinde tutarlı bir zincir üretir.

`verify_against_anchor()` tam olarak onları yakalıyor, çünkü çıpa
veritabanının DIŞINDA duruyor. Rapor ikisini birden veriyor; yalnızca
birine bakmak yanlış bir güven duygusu üretirdi.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from CORE.audit_chain import (
    LINK_BROKEN,
    LINK_INTACT,
    AnchorCheck,
    ChainVerification,
    anchor_path,
    verify_against_anchor,
    verify_audit_chain,
)
from CORE.pdf_utils import escape_for_reportlab as _escape

#: HALKA durumu → görüntü metni. TEK yerden: `UI/AuditLogView.py` (tablo
#: sütunu) ve buradaki CSV/PDF dışa aktarımı AYNI sözlüğü kullanıyor —
#: ikinci bir eşleme YAZILMADI (B-055'in "ikinci bir renk/metin yolu
#: açma" ilkesiyle aynı gerekçe).
HALKA_METNI = {
    LINK_INTACT: "Sağlam",
    LINK_BROKEN: "Kopuk",
    "out_of_scope": "Kapsam Dışı",
}

#: TXT başlığındaki ayraç genişliği — `UI/AuditLogView.py` (eskiden
#: `AuditLogDialog`, tam sayfaya taşındı) sütun genişlikleriyle aynı
#: toplamı hedefliyor.
_AYRAC = "-" * 95


@dataclass(frozen=True)
class ZincirRaporu:
    """Zincirin ve çıpanın birlikte değerlendirilmiş durumu."""

    zincir: ChainVerification
    cipa: AnchorCheck
    #: Çıpa dosyasının yolu — kullanıcıya nereye bakacağı söylenebilsin.
    cipa_yolu: Path | None = None

    @property
    def saglam(self) -> bool:
        """
        İKİSİ de geçtiyse sağlam.

        Çıpa hiç yoksa (`anchors_checked == 0`) `AnchorCheck.ok` True
        döner ama tek başına anlam taşımaz — o durum `cipa_var` ile ayrıca
        görünüyor, çünkü "doğrulandı" ile "karşılaştıracak bir şey yoktu"
        aynı cümle değil.
        """
        return self.zincir.ok and self.cipa.ok

    @property
    def cipa_var(self) -> bool:
        return self.cipa.anchors_checked > 0

    @property
    def ilk_kirilma_id(self) -> int | None:
        return self.zincir.first_broken_id

    def baslik(self) -> str:
        """Tek satırlık durum — düğme sonucunun ilk satırı."""
        if self.saglam:
            return "Denetim zinciri SAĞLAM"
        if not self.zincir.ok:
            nerede = (
                f" (ilk kırılma: id={self.ilk_kirilma_id})"
                if self.ilk_kirilma_id is not None
                else ""
            )
            return f"Denetim zinciri KIRIK{nerede}"
        return "Denetim zinciri kendi içinde tutarlı ama ÇIPA UYUŞMUYOR"

    def ayrinti(self) -> str:
        """Düğmeye basınca gösterilen tam metin."""
        parcalar = [self.zincir.summary(), "", self.cipa.summary()]
        if not self.cipa_var:
            parcalar.append(
                "\nÇıpa, veritabanının DIŞINDAKİ tek referans. Yoksa "
                "zincirin baştan yeniden yazılması tespit edilemez."
            )
        if self.cipa_yolu is not None:
            parcalar.append(f"\nÇıpa dosyası: {self.cipa_yolu}")
            parcalar.append(
                "Bu yol HYCLEUS_AUDIT_ANCHOR ortam değişkeniyle "
                "değiştirilebilir (ör. USB'ye)."
            )
        return "\n".join(parcalar)


def zincir_raporu(db: Any, *, cipa_yolu: Path | None = None) -> ZincirRaporu:
    """
    Zinciri ve çıpayı birlikte doğrular.

    Args:
        cipa_yolu: Test ve özel kurulumlar için; verilmezse `anchor_path()`.
    """
    # İkisi de `_connection()` üzerinden hem DBManager hem ham
    # sqlite3.Connection kabul ediyor — burada ayrıca çözmeye gerek yok.
    yol = cipa_yolu or anchor_path()
    return ZincirRaporu(
        zincir=verify_audit_chain(db),
        cipa=verify_against_anchor(db, path=yol),
        cipa_yolu=yol,
    )


def txt_basligi(
    rapor: ZincirRaporu,
    *,
    kayit_sayisi: int,
    simdi: datetime | None = None,
) -> list[str]:
    """
    TXT dışa aktarımının başlık satırları — zincir durumu DAHİL.

    Neden dışa aktarıma giriyor
    ---------------------------
    Dışa aktarılan dosya, denetim kaydının makine dışına çıkan tek
    biçimi. İçinde zincirin son ucu ve doğrulama durumu yoksa, dosyayla
    veritabanının tutarlı olup olmadığı sonradan gösterilemez — yani dosya
    bir kanıt değil, yalnızca bir liste olur.

    DIŞA AKTARIMIN KENDİSİ İMZALI DEĞİL. Buradaki satırlar dosyanın
    yazıldığı ANDAKİ durumu bildiriyor; dosyanın sonradan
    değiştirilmediğini kanıtlamıyorlar. Kanıt zincirin kendisinde ve
    çıpada; bu başlık ikisine bakmayı mümkün kılan referansı taşıyor.
    """
    an = simdi or datetime.now(timezone.utc)
    satirlar = [
        "HYCLEUS — Denetim Günlüğü",
        f"Dışa aktarım: {an.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        _AYRAC,
        f"Zincir durumu : {rapor.baslik()}",
        f"Doğrulanan    : {rapor.zincir.checked} kayıt"
        f" (başlangıç id={rapor.zincir.start_id};"
        f" {rapor.zincir.unchained_before} eski kayıt kapsam dışı)",
        f"Son kayıt     : id={rapor.zincir.last_id}",
        f"Son hash      : {rapor.zincir.last_hash or '—'}",
    ]
    if rapor.ilk_kirilma_id is not None:
        satirlar.append(f"İlk kırılma   : id={rapor.ilk_kirilma_id}")
    for kirik in rapor.zincir.breaks:
        satirlar.append(f"                · {kirik}")

    satirlar.append(
        f"Çıpa          : {rapor.cipa.summary().splitlines()[0]}"
        if rapor.cipa_var
        else "Çıpa          : yok — dış referans bulunamadı"
    )
    if not rapor.cipa.ok:
        satirlar.extend(f"                · {p}" for p in rapor.cipa.problems)

    satirlar.append(
        "NOT           : bu dosya imzalı DEĞİLDİR; yukarıdaki durum "
        "yazıldığı andaki durumdur."
    )
    satirlar.append(_AYRAC)
    satirlar.append(f"Bu dışa aktarımdaki kayıt sayısı: {kayit_sayisi}")
    satirlar.append(_AYRAC)
    return satirlar


# ══════════════════════════════════════════════════════════════════════════════
# Üç format — Düz metin (üstte), Tablo (CSV), İmzalı Rapor (PDF)
# ══════════════════════════════════════════════════════════════════════════════
#
# Görev: mockup üç dışa aktarım seçeneği istiyor. TXT zaten vardı (üstte).
# Bu iki fonksiyon, `UI/AuditLogView.py`'nin AYNI filtrelenmiş satır
# kümesinden (tarih aralığı + işlem + sekme — TXT'nin zaten kullandığı
# süzgeç) beslenir; ikinci bir SQL sorgusu YAZILMADI, UI zaten `_load()`'da
# hesapladığı satırları burada tüketilecek HAM (kırpılmamış) hâliyle de
# topluyor (bkz. `AuditLogView._load()`'daki `_son_export_satirlari`).
#
# CSV, XLSX DEĞİL — kasıtlı: `export_inventory_csv()`'nin zaten kullandığı
# `utf-8-sig` kodlaması Excel'de doğru açılıyor VE SIEM'lerin evrensel
# girdi formatı CSV/JSON, özel bir .xlsx ayrıştırıcısı DEĞİL. Gerçek bir
# .xlsx yeni bir bağımlılık (openpyxl) gerektirirdi — CSV'nin zaten
# kapattığı ihtiyaç için gereksiz. Ayrıntı: BACKLOG.md B-086.


@dataclass(frozen=True)
class DenetimSatiri:
    """Bir denetim kaydının dışa aktarım için AYRIK sütunlu, HAM hâli.

    `UI/AuditLogView.py`'nin tablosu bu alanların İNSAN İÇİN kırpılmış/
    biçimlendirilmiş bir alt kümesini gösteriyor (ör. HWID 16 karaktere
    kırpılır, zaman "2026-08-30 12:00:00" biçimine çevrilir — bkz.
    `AuditLogView._insert_row()`). Bu sınıf HAM hâli taşıyor: "Tablo"
    (CSV) dışa aktarımının amacı Excel/SIEM için ayrık, kırpılmamış
    sütunlar — UI'nin okunabilirlik kırpması burada YOK.
    """

    id: int
    zaman: str            # ISO 8601, UTC, ham (`audit_log.timestamp`)
    islem: str             # ham action adı (kategori değil)
    kullanici: str
    kullanici_id: int | None
    hwid: str              # TAM, kırpılmamış — detail alanından çıkarılmış
    detay: str              # ham `detail` alanı, TAM
    halka: str              # ham kod: "intact"/"broken"/"out_of_scope"


#: CSV başlık satırı — sütun sırası `DenetimSatiri` alan sırasıyla AYNI.
CSV_BASLIKLAR = [
    "ID", "Zaman (UTC)", "İşlem", "Kullanıcı", "Kullanıcı ID", "HWID",
    "Detay", "Zincir Halkası",
]


def export_csv(satirlar: list[DenetimSatiri], path: str | Path) -> Path:
    """
    Denetim kayıtlarını CSV olarak yazar — Excel/SIEM için ayrık sütunlu.

    `CORE/inventory.py::export_inventory_csv()` ile AYNI kodlama kararı:
    `utf-8-sig` (BOM'lu) — Excel, BOM olmadan UTF-8'i sistem kod sayfası
    sanıp Türkçe karakterleri bozuyor. `newline=""` ZORUNLU: csv modülü
    satır sonunu kendi yönetir, aksi hâlde Windows'ta satır araları
    boşluklu çıkar.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_BASLIKLAR)
        for s in satirlar:
            writer.writerow([
                s.id, s.zaman, s.islem, s.kullanici,
                s.kullanici_id if s.kullanici_id is not None else "",
                s.hwid, s.detay, HALKA_METNI.get(s.halka, s.halka),
            ])
    return out


#: PDF tablosu — CSV'nin AKSİNE insan-okunur bir özet, `kullanici_id`/
#: `detay` sütunları YOK (rapor amacı "kim ne yaptı, zincir sağlam mı",
#: ham SIEM verisi değil — o CSV'nin işi).
_PDF_BASLIKLAR = ["ID", "Zaman (UTC)", "İşlem", "Kullanıcı", "HWID", "Halka"]
_PDF_COL_WIDTHS = (35, 95, 190, 120, 130, 70)


def export_pdf(
    satirlar: list[DenetimSatiri],
    rapor: ZincirRaporu,
    path: str | Path,
    *,
    title: str = "HYCLEUS — Denetim Günlüğü (İmzalı Rapor)",
    generated_at: datetime | None = None,
    filters_note: str = "",
) -> Path:
    """
    Denetim günlüğünü PDF "imzalı rapor" olarak yazar.

    "İmzalı" NE ANLAMA GELİYOR — kasıtlı bir kapsam sınırı
    -----------------------------------------------------------
    Rapor zincirin KENDİ kanıtını (hash zinciri + dış çıpa karşılaştırması,
    `zincir_raporu()`) GÖMÜLÜ taşıyor — okuyanın ayrıca bir komut
    çalıştırmasına gerek yok, "İmzalı" burada BUNU ifade ediyor.

    RFC 3161 mührü İSE (PDF DOSYASININ KENDİSİNİ bir zaman damgası
    otoritesine imzalatıp, dosyanın sonradan değiştirilmediğini
    KRİPTOGRAFİK olarak kanıtlamak) BU FONKSİYONUN KAPSAMINDA DEĞİL —
    kasıtlı bir karar, sessizce ertelenmedi: bkz. BACKLOG.md B-087,
    SECURITY.md §4.25. PDF bunu ASLA sessizce iddia etmiyor — aşağıdaki
    gövde açıkça "RFC 3161 ile mühürlenmedi" diyor, `txt_basligi()`'nin
    "bu dosya imzalı DEĞİLDİR" notuyla AYNI dürüstlük ilkesi.

    Raises:
        RuntimeError: reportlab kurulu değilse. İçe aktarım fonksiyon
            İÇİNDE — `CORE/inventory.py::export_inventory_pdf()`'in aynı
            deseni, ki reportlab yokken TXT/CSV dışa aktarımı çalışmaya
            devam etsin.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover — bağımlılık kurulu
        raise RuntimeError(
            "PDF dışa aktarımı için reportlab gerekli. "
            "Kurulum: pip install -r requirements.txt"
        ) from exc

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    stamp = generated_at or datetime.now(timezone.utc)

    styles = getSampleStyleSheet()
    cell_style = ParagraphStyle(
        "Hucre", parent=styles["BodyText"], fontSize=7, leading=8.5, spaceAfter=0,
    )
    header_style = ParagraphStyle(
        "Baslik", parent=cell_style, fontName="Helvetica-Bold", textColor=colors.white,
    )
    ozet_style = ParagraphStyle("Ozet", parent=styles["Normal"], fontSize=9, leading=12)
    saglam_style = ParagraphStyle(
        "Saglam", parent=ozet_style, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#15803D"),
    )
    kirik_style = ParagraphStyle(
        "Kirik", parent=ozet_style, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#B91C1C"),
    )

    doc = SimpleDocTemplate(
        str(out),
        pagesize=landscape(A4),
        leftMargin=10 * mm, rightMargin=10 * mm,
        topMargin=12 * mm, bottomMargin=12 * mm,
        title=title,
        # `pageCompression=0` — `CORE/inventory.py::export_inventory_pdf()`
        # sıkıştırmadığı için `tests/test_inventory.py` içeriği ham baytlarda
        # aranarak doğrulanabiliyordu (`b"KVKK" in out.read_bytes()`); o
        # dosyada bu YALNIZCA `title=` metadata'sı için tesadüfen doğruydu
        # (PDF Info sözlüğü sıkıştırılmaz), gövde metni İSE varsayılan
        # sıkıştırmayla aranamaz çıktı — ölçüldü. Burada AÇIKÇA kapatıldı:
        # yeni bir test bağımlılığı (pypdf vb.) eklemeden zincir durumu/HALKA
        # gibi gövde metnini `tests/test_audit_log_view.py`'de ham baytlarda
        # doğrulayabilmek için.
        pageCompression=0,
    )

    story: list[Any] = [
        Paragraph(_escape(title), styles["Title"]),
        Paragraph(
            f"Oluşturulma: {stamp.strftime('%Y-%m-%d %H:%M:%S')} UTC &nbsp;·&nbsp; "
            f"Toplam kayıt: {len(satirlar)}",
            styles["Normal"],
        ),
    ]
    if filters_note:
        story.append(Paragraph(f"Filtre: {_escape(filters_note)}", styles["Normal"]))
    story.append(Spacer(1, 4 * mm))

    # ── Zincir doğrulama özeti — "imzalı" olan kısım BU: rapor kendi
    # kanıtını taşıyor, okuyan zincirin sağlam olup olmadığını ayrıca bir
    # komut çalıştırmadan görebiliyor. Dış çıpa (`rapor.cipa`) `ayrinti()`
    # içinde ZATEN var — ikinci bir metin üretim yolu AÇILMADI.
    story.append(
        Paragraph(_escape(rapor.baslik()), saglam_style if rapor.saglam else kirik_style)
    )
    for satir in rapor.ayrinti().split("\n"):
        if satir.strip():
            story.append(Paragraph(_escape(satir), ozet_style))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        "NOT: Bu PDF dosyası RFC 3161 zaman damgasıyla MÜHÜRLENMEMİŞTİR. "
        "Yukarıdaki zincir/çıpa durumu dosyanın ÜRETİLDİĞİ ANDAKİ veritabanı "
        "durumunu yansıtır; dosyanın KENDİSİNİN sonradan değiştirilmediğini "
        "KANITLAMAZ.",
        kirik_style,
    ))
    story.append(Spacer(1, 6 * mm))

    data: list[list[Any]] = [[Paragraph(h, header_style) for h in _PDF_BASLIKLAR]]
    for s in satirlar:
        data.append([
            Paragraph(_escape(str(v)), cell_style)
            for v in (s.id, s.zaman, s.islem, s.kullanici, s.hwid,
                      HALKA_METNI.get(s.halka, s.halka))
        ])

    if len(data) == 1:
        story.append(Paragraph("Bu filtreyle eşleşen kayıt yok.", styles["Normal"]))
    else:
        table = Table(data, colWidths=_PDF_COL_WIDTHS, repeatRows=1)
        table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9CA3AF")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#F3F4F6")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ])
        )
        story.append(table)

    doc.build(story)
    return out
