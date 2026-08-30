"""
HYCLEUS — KVKK saklama envanteri (rapor + dışa aktarım)

Bu modül yeni bilgi ÜRETMEZ; var olanı bir araya getirir. Her satır bir
dosyadır: kimin yüklediği, hangi saklama profiline bağlı olduğu, ne zaman
imha edilebileceği ve o dosyaya en son ne zaman dokunulduğu.

Tutarlılık güvencesi — rapor ile uygulama ayrışamaz
---------------------------------------------------
İmha tarihi `retention.destruction_date_for_file()`, durum ise
`disposal.check_disposal()` üzerinden hesaplanıyor — yani raporun kullandığı
mantık, silmeyi fiilen ENGELLEYEN mantığın ta kendisi. Rapor kendi kopyasını
tutsaydı ikisi zamanla ayrışırdı: denetime "bu dosya imha edilebilir" diyen
bir belge üretilirken uygulama silmeyi reddedebilirdi. Bir denetim belgesinin
en kötü kusuru budur — sistemin gerçekte yaptığını yanlış anlatmak.

Bu N+1 sorgu demektir (dosya başına birkaç sorgu). Bilinçli takas: envanter
raporu nadiren ve elle üretilir; doğruluğu hızından önemlidir.

Bilinen boşluk — sahip alanı
----------------------------
`files.added_by` şemada var ama HİÇBİR KOD onu yazmıyor (UI'daki dosya ekleme
INSERT'ü bu kolonu atlıyor). Yani bugün her dosyanın sahibi NULL görünür ve
raporda "bilinmiyor" yazar. Bu rapor kusuru değil, veri kusurudur; envanterin
uydurma bir sahip yazması KVKK belgesinde daha kötü olurdu. Bkz. BACKLOG B-005.
"""
from __future__ import annotations

import csv
import logging
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from CORE.csv_utils import csv_hucre_guvenli
from CORE.disposal import LABEL_IMHA, check_disposal
from CORE.pdf_utils import escape_for_reportlab as _escape
from CORE.retention import RetentionError, parse_date

if TYPE_CHECKING:  # pragma: no cover
    from DB.db_manager import DBManager

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Durum değerleri
# ──────────────────────────────────────────────────────────────────────────────

#: Saklama süresi işliyor — imha edilemez.
STATUS_ACTIVE = "aktif"

#: Saklama süresi doldu, dosya hâlâ yerinde — imha onayı bekliyor.
STATUS_EXPIRED_PENDING = "suresi_dolmus_onay_bekliyor"

#: Dosya İmha Odası'nda. Etiket, saklama durumundan ÖNCE gelir: dosyanın
#: fiilen nerede olduğu, süresinin ne durumda olduğundan daha belirleyicidir.
STATUS_IN_IMHA = "imha_odasinda"

#: Saklama profiline bağlı değil — hiçbir saklama kuralına tabi değil.
STATUS_NO_PROFILE = "profil_yok"

#: İmha tarihi hesaplanamadı (ör. elle giriş gereken profilde başlangıç tarihi
#: boş). Satır rapordan DÜŞÜRÜLMEZ: denetimde eksik veri, görünmeyen veriden
#: iyidir — envanterden sessizce kaybolan dosya tam da raporun yakalaması
#: gereken şeydir.
STATUS_UNKNOWN = "hesaplanamadi"

ALL_STATUSES = (
    STATUS_ACTIVE,
    STATUS_EXPIRED_PENDING,
    STATUS_IN_IMHA,
    STATUS_NO_PROFILE,
    STATUS_UNKNOWN,
)

#: Kullanıcıya/denetime gösterilecek Türkçe karşılıklar.
STATUS_LABELS = {
    STATUS_ACTIVE: "Aktif",
    STATUS_EXPIRED_PENDING: "Süresi doldu — onay bekliyor",
    STATUS_IN_IMHA: "İmha Odası'nda",
    STATUS_NO_PROFILE: "Profil atanmamış",
    STATUS_UNKNOWN: "Hesaplanamadı",
}

#: Profili olmayan dosya için profil sütununda yazan metin.
NO_PROFILE_TEXT = "profil atanmamış"

#: added_by boş olduğunda sahip sütununda yazan metin.
UNKNOWN_OWNER_TEXT = "bilinmiyor"

#: CSV/PDF sütun başlıkları — sıra, InventoryRow.as_export_row() ile aynı.
COLUMN_HEADERS = (
    "Dosya adı",
    "Yol",
    "Saklama profili",
    "Sahip",
    "İlk kayıt tarihi",
    "İmha tarihi",
    "Durum",
    "Son işlem",
)


@dataclass(frozen=True)
class InventoryRow:
    """Envanterde tek bir dosya satırı."""

    file_id: int
    filename: str
    filepath: str
    profile_id: int | None
    profile_name: str
    owner: str
    added_at: str
    destruction_date: date | None
    status: str
    last_activity: str | None
    note: str = field(default="")

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)

    @property
    def destruction_date_text(self) -> str:
        """İmha tarihinin metin hâli — boşluk denetimde belirsizdir, açık yazılır."""
        if self.destruction_date is not None:
            return self.destruction_date.isoformat()
        if self.status == STATUS_NO_PROFILE:
            return "—"
        if self.status == STATUS_UNKNOWN:
            return "hesaplanamadı"
        return "süresiz"

    def as_export_row(self) -> list[str]:
        """CSV ve PDF'in ortak kullandığı sütun sırası (COLUMN_HEADERS ile aynı)."""
        return [
            self.filename,
            self.filepath,
            self.profile_name,
            self.owner,
            self.added_at,
            self.destruction_date_text,
            self.status_label,
            self.last_activity or "—",
        ]

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["destruction_date"] = self.destruction_date_text
        data["status_label"] = self.status_label
        return data


# ──────────────────────────────────────────────────────────────────────────────
# Rapor üretimi
# ──────────────────────────────────────────────────────────────────────────────

_BASE_QUERY = """
    SELECT
        f.id                    AS file_id,
        f.filename              AS filename,
        f.filepath              AS filepath,
        f.label                 AS label,
        f.added_at              AS added_at,
        f.retention_profile_id  AS profile_id,
        p.name                  AS profile_name,
        u.username              AS owner,
        (SELECT MAX(a.timestamp) FROM audit_log a
          WHERE a.target_type = 'file' AND a.target_id = f.id) AS last_activity
    FROM files f
    LEFT JOIN retention_profiles p ON p.id = f.retention_profile_id
    LEFT JOIN users             u ON u.id = f.added_by
    ORDER BY f.filename, f.id
"""


def _row_status_and_date(
    db: DBManager, row: Any, today: date | None
) -> tuple[str, date | None, str]:
    """
    Bir satırın durumunu ve imha tarihini belirler.

    Durum sırası (ilk eşleşen kazanır):
      1. Etiket 'Imha'  → imha_odasinda (dosya fiilen orada)
      2. Profil yok     → profil_yok
      3. Süre dolmuş    → suresi_dolmus_onay_bekliyor
      4. Diğer          → aktif

    Returns:
        (durum, imha_tarihi, not)
    """
    file_id = row["file_id"]

    # İmha Odası'ndaki dosyanın imha tarihi yine de hesaplanır — denetim
    # "bu dosya süresi dolmadan mı oraya taşınmış?" diye sorabilir.
    destruction: date | None = None
    note = ""
    try:
        check = check_disposal(db, file_id, today=today)
        destruction = check.destruction_date
    except RetentionError as exc:
        logger.warning("Envanter: durum hesaplanamadı (id=%s): %s", file_id, exc)
        if row["label"] == LABEL_IMHA:
            return STATUS_IN_IMHA, None, str(exc)
        return STATUS_UNKNOWN, None, str(exc)

    if row["label"] == LABEL_IMHA:
        return STATUS_IN_IMHA, destruction, note
    if not check.has_profile:
        return STATUS_NO_PROFILE, None, note
    if check.retention_expired:
        return STATUS_EXPIRED_PENDING, destruction, note
    return STATUS_ACTIVE, destruction, note


def generate_retention_inventory(
    db: DBManager,
    *,
    profile_id: int | None = None,
    status: str | tuple[str, ...] | list[str] | None = None,
    added_from: str | date | None = None,
    added_to: str | date | None = None,
    destruction_from: str | date | None = None,
    destruction_to: str | date | None = None,
    today: date | None = None,
) -> list[InventoryRow]:
    """
    KVKK saklama envanterini üretir — her satır bir dosya.

    Filtrelerin hepsi opsiyoneldir ve VE ile birleşir (hepsi birden geçerli).

    Args:
        profile_id:  yalnızca bu saklama profiline bağlı dosyalar.
        status:      tek durum ya da durum listesi (STATUS_* sabitleri).
        added_from / added_to:
                     yükleme tarihine (`files.added_at`) göre aralık, uç
                     değerler DÂHİL.
        destruction_from / destruction_to:
                     hesaplanan imha tarihine göre aralık, uç değerler DÂHİL.
                     İmha tarihi olmayan satırlar (profilsiz/süresiz) bu filtre
                     verildiğinde ELENİR — "tarihi yok" bir aralığa giremez.
        today:       "bugün" (test için); verilmezse UTC bugün.

    Returns:
        Dosya adına göre sıralı satırlar.

    Not: iki tarih aralığı ayrı tutuldu; "tarih aralığı" tek başına belirsizdi
    (kayıt tarihi mi, imha tarihi mi?). Denetimde ikisi de sorulur.
    """
    if isinstance(status, str):
        status_filter: set[str] | None = {status}
    elif status is not None:
        status_filter = set(status)
    else:
        status_filter = None

    if status_filter is not None:
        unknown = status_filter - set(ALL_STATUSES)
        if unknown:
            raise ValueError(
                f"Bilinmeyen durum: {', '.join(sorted(unknown))}. "
                f"Geçerli değerler: {', '.join(ALL_STATUSES)}"
            )

    added_from_d = parse_date(added_from) if added_from else None
    added_to_d = parse_date(added_to) if added_to else None
    destruction_from_d = parse_date(destruction_from) if destruction_from else None
    destruction_to_d = parse_date(destruction_to) if destruction_to else None

    rows: list[InventoryRow] = []
    # Tutarlılık — TEK bir anlık görüntü, `_BASE_QUERY` İLE per-satır
    # kontroller ARASINDA değil. `_BASE_QUERY` tek bir JOIN (files +
    # retention_profiles + users + audit_log alt sorgusu), ama HER satır
    # için `_row_status_and_date()`'in çağırdığı `check_disposal()`
    # `files`/`retention_profiles`'ı N+1 deseninde AYRICA, YENİDEN okuyor
    # (bkz. modülün "Bu N+1 sorgu demektir" notu). Bu iki okuma kümesi
    # AYNI transaction'da olmazsa, rapor üretimi sırasında araya giren bir
    # yazma (ör. bir saklama profilinin süresi değiştirilmesi, bir dosyanın
    # İmha Odası'na taşınması) bazı satırları ESKİ bazılarını YENİ kurala
    # göre değerlendirebilir — modülün kendi "rapor ile uygulama
    # ayrışamaz" güvencesini KIRAR. Açık bir `BEGIN`...`COMMIT`, WAL'ın
    # anlık-görüntü izolasyonunu TÜM okuma dizisine yayıyor — aynı desen
    # `CORE/backup.py::create_backup()`'ta kullanılıyor.
    db.conn.execute("BEGIN")
    try:
        for raw in db.fetchall(_BASE_QUERY):
            if profile_id is not None and raw["profile_id"] != profile_id:
                continue

            if added_from_d or added_to_d:
                try:
                    added = parse_date(raw["added_at"])
                except RetentionError:
                    continue  # tarihi okunamayan satır aralık filtresine giremez
                if added_from_d and added < added_from_d:
                    continue
                if added_to_d and added > added_to_d:
                    continue

            row_status, destruction, note = _row_status_and_date(db, raw, today)

            if status_filter is not None and row_status not in status_filter:
                continue

            if destruction_from_d or destruction_to_d:
                if destruction is None:
                    continue  # imha tarihi olmayan satır tarih aralığına giremez
                if destruction_from_d and destruction < destruction_from_d:
                    continue
                if destruction_to_d and destruction > destruction_to_d:
                    continue

            rows.append(
                InventoryRow(
                    file_id=raw["file_id"],
                    filename=raw["filename"],
                    filepath=raw["filepath"],
                    profile_id=raw["profile_id"],
                    profile_name=raw["profile_name"] or NO_PROFILE_TEXT,
                    owner=raw["owner"] or UNKNOWN_OWNER_TEXT,
                    added_at=raw["added_at"],
                    destruction_date=destruction,
                    status=row_status,
                    last_activity=raw["last_activity"],
                    note=note,
                )
            )
    finally:
        db.conn.execute("COMMIT")
    return rows


def inventory_summary(rows: list[InventoryRow]) -> dict[str, int]:
    """Duruma göre satır sayıları — rapor başlığında özet göstermek için."""
    counts = dict.fromkeys(ALL_STATUSES, 0)
    for row in rows:
        counts[row.status] = counts.get(row.status, 0) + 1
    return counts


# ──────────────────────────────────────────────────────────────────────────────
# Dışa aktarım — CSV
# ──────────────────────────────────────────────────────────────────────────────


def export_inventory_csv(rows: list[InventoryRow], path: str | Path) -> Path:
    """
    Envanteri CSV olarak yazar.

    Kodlama `utf-8-sig` (BOM'lu): denetim belgeleri Excel'de açılıyor ve Excel,
    BOM olmadan UTF-8'i sistem kod sayfası sanıp Türkçe karakterleri bozuyor
    ("İmha" → "Ä°mha"). BOM tek başına bunu çözüyor; csv modülü ve pandas
    utf-8-sig'i sorunsuz geri okuyor.

    `newline=""` şart — csv modülü satır sonunu kendi yönetir, aksi hâlde
    Windows'ta her satır arasına boş satır girer.

    Her hücre `csv_hucre_guvenli()`'den GEÇİYOR — CSV formül enjeksiyonuna
    (CWE-1236) karşı, bkz. `CORE/csv_utils.py`'nin modül docstring'i.
    `filename`/`owner` kullanıcı girdisi taşıyor (dosya adı, kullanıcı
    adı) — hangisinin "bugün güvenli" olduğuna güvenmek yerine tüm sütunlar
    istisnasız işleniyor.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(COLUMN_HEADERS)
        for row in rows:
            writer.writerow([csv_hucre_guvenli(v) for v in row.as_export_row()])
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Dışa aktarım — PDF
# ──────────────────────────────────────────────────────────────────────────────

#: PDF sütun genişlikleri (punto). Yol sütunu en geniş; toplam A4 yatay
#: yazım alanına (~770pt) sığacak biçimde seçildi.
_PDF_COL_WIDTHS = (95, 175, 105, 60, 85, 65, 100, 85)


def export_inventory_pdf(
    rows: list[InventoryRow],
    path: str | Path,
    *,
    title: str = "KVKK Saklama Envanteri",
    generated_at: datetime | None = None,
    filters_note: str = "",
) -> Path:
    """
    Envanteri PDF olarak yazar — sade, yazdırılabilir bir denetim tablosu.

    A4 yatay; uzun tablolar sayfalara bölünür ve BAŞLIK SATIRI HER SAYFADA
    TEKRARLANIR (`repeatRows=1`) — çok sayfalı bir denetim belgesinde ikinci
    sayfadan itibaren sütunların ne olduğu belli olmalı.

    Raises:
        RuntimeError: reportlab kurulu değilse. İçe aktarım fonksiyon içinde
                      yapılıyor ki reportlab yokken CSV dışa aktarımı ve
                      raporun kendisi çalışmaya devam etsin.
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

    doc = SimpleDocTemplate(
        str(out),
        pagesize=landscape(A4),
        leftMargin=10 * mm, rightMargin=10 * mm,
        topMargin=12 * mm, bottomMargin=12 * mm,
        title=title,
    )

    story: list[Any] = [
        Paragraph(title, styles["Title"]),
        Paragraph(
            f"Oluşturulma: {stamp.strftime('%Y-%m-%d %H:%M:%S')} UTC &nbsp;·&nbsp; "
            f"Toplam kayıt: {len(rows)}",
            styles["Normal"],
        ),
    ]
    if filters_note:
        story.append(Paragraph(f"Filtre: {filters_note}", styles["Normal"]))

    summary = inventory_summary(rows)
    story.append(
        Paragraph(
            " &nbsp;·&nbsp; ".join(
                f"{STATUS_LABELS[key]}: {value}"
                for key, value in summary.items()
                if value
            )
            or "Kayıt yok",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 6 * mm))

    # Paragraph kullanılıyor ki uzun dosya yolları hücre içinde SARSIN;
    # düz metin olsaydı sütun taşar ve yol okunamaz hâle gelirdi.
    data: list[list[Any]] = [[Paragraph(h, header_style) for h in COLUMN_HEADERS]]
    for row in rows:
        data.append([Paragraph(_escape(cell), cell_style) for cell in row.as_export_row()])

    if len(data) == 1:
        story.append(Paragraph("Envanterde kayıt yok.", styles["Normal"]))
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
