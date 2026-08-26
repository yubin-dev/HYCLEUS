"""HYCLEUS — Denetim Günlüğü Diyaloğu"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QDate, Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QComboBox,
    QDateEdit,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from DB.db_manager import DBManager
from UI.main_window_palette import _DARK

_FAIL_KEYWORDS = frozenset(
    {"fail", "denied", "blacklist", "error", "reject", "lock", "invalid", "unauthorized"}
)


def _stil(T: dict[str, str]) -> str:
    """Diyaloğun stil sayfası — kayıtlı tema token'larından (B-055).

    Önceden sabit bir Catppuccin-Mocha paletiydi; preset değişince bu
    diyalog hiç değişmiyordu.
    """
    return f"""
QDialog  {{ background: {T['bg']}; color: {T['text']}; }}
QLabel   {{ color: {T['text']}; }}
QTableWidget {{
    background: {T['search_bg']};
    color: {T['text']};
    gridline-color: {T['border']};
    border: 1px solid {T['border']};
    border-radius: 4px;
    font-size: 12px;
}}
QTableWidget::item:selected {{ background: {T['accent_tint']}; color: {T['tint_text']}; }}
QHeaderView::section {{
    background: {T['bg']};
    color: {T['accent']};
    border: none;
    border-bottom: 1px solid {T['border']};
    padding: 4px 8px;
    font-weight: 600;
    font-size: 12px;
}}
QComboBox {{
    background: {T['search_bg']};
    color: {T['text']};
    border: 1px solid {T['border']};
    border-radius: 4px;
    padding: 4px 8px;
    min-width: 150px;
    font-size: 12px;
}}
QComboBox QAbstractItemView {{
    background: {T['search_bg']};
    color: {T['text']};
    selection-background-color: {T['row_hover']};
    border: 1px solid {T['border']};
}}
QComboBox::drop-down {{ border: none; width: 20px; }}
QDateEdit {{
    background: {T['search_bg']};
    color: {T['text']};
    border: 1px solid {T['border']};
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}}
QDateEdit::drop-down {{ border: none; width: 20px; }}
QCalendarWidget {{ background: {T['search_bg']}; color: {T['text']}; }}
"""


def _btn_stil(T: dict[str, str]) -> str:
    return (
        f"QPushButton{{color:{T['text']};background:{T['hover']};border:none;"
        f"border-radius:6px;padding:5px 14px;font-size:12px;}}"
        f"QPushButton:hover{{background:{T['row_hover']};}}"
    )


def _btn_export_stil(T: dict[str, str]) -> str:
    return (
        f"QPushButton{{color:{T['on_accent']};background:{T['accent']};border:none;"
        f"border-radius:6px;padding:5px 14px;font-size:12px;font-weight:600;}}"
        f"QPushButton:hover{{background:{T['accent_hover']};}}"
    )


def _is_failure(action: str) -> bool:
    low = action.lower()
    return any(k in low for k in _FAIL_KEYWORDS)


class AuditLogDialog(QDialog):
    def __init__(self, parent=None, *, T: dict[str, str] | None = None) -> None:
        """
        Args:
            T: Çağıranın aktif tema token sözlüğü (`HycleusWindow._T`).
                Verilmezse varsayılan "mavi" koyu palete düşer.
        """
        super().__init__(parent)
        self._T: dict[str, str] = T if T is not None else _DARK
        self.setWindowTitle("HYCLEUS — Denetim Günlüğü")
        self.setMinimumSize(900, 540)
        self.setStyleSheet(_stil(self._T))
        self._build_ui()
        self._populate_action_filter()
        self._load()

    # ------------------------------------------------------------------
    # UI kurulumu
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 12)

        title = QLabel("Denetim Günlüğü")
        title.setFont(QFont("Arial", 13, QFont.Bold))
        title.setStyleSheet("color:#cdd6f4; margin-bottom:2px;")
        layout.addWidget(title)

        layout.addLayout(self._make_filter_bar())
        layout.addWidget(self._make_table())
        layout.addLayout(self._make_footer())

    def _make_filter_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        bar.addWidget(QLabel("Başlangıç:"))
        self._date_start = QDateEdit()
        self._date_start.setCalendarPopup(True)
        self._date_start.setDate(QDate.currentDate().addDays(-30))
        self._date_start.setDisplayFormat("dd.MM.yyyy")
        bar.addWidget(self._date_start)

        bar.addWidget(QLabel("Bitiş:"))
        self._date_end = QDateEdit()
        self._date_end.setCalendarPopup(True)
        self._date_end.setDate(QDate.currentDate())
        self._date_end.setDisplayFormat("dd.MM.yyyy")
        bar.addWidget(self._date_end)

        bar.addWidget(QLabel("İşlem:"))
        self._action_combo = QComboBox()
        bar.addWidget(self._action_combo)

        btn_filter = QPushButton("Filtrele")
        btn_filter.setStyleSheet(_btn_stil(self._T))
        btn_filter.setCursor(Qt.PointingHandCursor)
        btn_filter.clicked.connect(self._load)
        bar.addWidget(btn_filter)

        btn_reset = QPushButton("Sıfırla")
        btn_reset.setStyleSheet(_btn_stil(self._T))
        btn_reset.setCursor(Qt.PointingHandCursor)
        btn_reset.clicked.connect(self._reset_filters)
        bar.addWidget(btn_reset)

        bar.addStretch()
        return bar

    def _make_table(self) -> QTableWidget:
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Zaman", "İşlem", "Kullanıcı", "HWID"])
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(False)
        return self._table

    def _make_footer(self) -> QHBoxLayout:
        footer = QHBoxLayout()

        self._count_label = QLabel("Toplam: 0 kayıt")
        self._count_label.setStyleSheet(f"color:{self._T['subtext']}; font-size:11px;")
        footer.addWidget(self._count_label)

        footer.addStretch()

        btn_export = QPushButton("TXT Dışa Aktar")
        btn_export.setStyleSheet(_btn_export_stil(self._T))
        btn_export.setCursor(Qt.PointingHandCursor)
        btn_export.clicked.connect(self._export_txt)
        footer.addWidget(btn_export)

        return footer

    # ------------------------------------------------------------------
    # Veri yükleme
    # ------------------------------------------------------------------

    def _populate_action_filter(self) -> None:
        self._action_combo.addItem("Tümü", None)
        try:
            rows = DBManager().fetchall(
                "SELECT DISTINCT action FROM audit_log ORDER BY action"
            )
            for row in rows:
                self._action_combo.addItem(row["action"], row["action"])
        except Exception:
            pass

    def _reset_filters(self) -> None:
        self._date_start.setDate(QDate.currentDate().addDays(-30))
        self._date_end.setDate(QDate.currentDate())
        self._action_combo.setCurrentIndex(0)
        self._load()

    def _load(self) -> None:
        start_iso = self._date_start.date().toString("yyyy-MM-dd") + "T00:00:00Z"
        end_iso   = self._date_end.date().toString("yyyy-MM-dd") + "T23:59:59Z"
        selected_action = self._action_combo.currentData()

        params: list = [start_iso, end_iso]
        action_clause = ""
        if selected_action is not None:
            action_clause = " AND a.action = ?"
            params.append(selected_action)

        try:
            rows = DBManager().fetchall(
                f"""
                SELECT a.timestamp, a.action, u.username, a.user_id, a.detail
                FROM audit_log a
                LEFT JOIN users u ON u.id = a.user_id
                WHERE a.timestamp >= ? AND a.timestamp <= ?
                {action_clause}
                ORDER BY a.timestamp DESC
                """,
                tuple(params),
            )
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı Hatası", str(exc))
            return

        self._table.setRowCount(0)
        for row in rows:
            username = row["username"]
            if not username:
                username = f"#{row['user_id']}" if row["user_id"] else "—"
            self._insert_row(
                ts=row["timestamp"] or "",
                action=row["action"] or "",
                user=username,
                hwid=self._extract_hwid(row["detail"] or ""),
                failure=_is_failure(row["action"] or ""),
            )

        self._count_label.setText(f"Toplam: {self._table.rowCount()} kayıt")

    # ------------------------------------------------------------------
    # Tablo yardımcıları
    # ------------------------------------------------------------------

    def _insert_row(
        self, ts: str, action: str, user: str, hwid: str, failure: bool
    ) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)

        ts_display = ts.replace("T", " ").rstrip("Z")
        values = [ts_display, action, user, hwid]

        for col, text in enumerate(values):
            item = QTableWidgetItem(text)
            if failure:
                item.setForeground(QColor(self._T["red"]))
                # red_tint token bir CSS rgba() dizesi (QSS için) — QColor
                # onu ayrıştıramaz, aynı görünümü alpha ile üretiyoruz.
                tint = QColor(self._T["red"])
                tint.setAlpha(36)
                item.setBackground(tint)
            self._table.setItem(row, col, item)

    @staticmethod
    def _extract_hwid(detail: str) -> str:
        for part in detail.split():
            if part.startswith("hwid="):
                val = part[5:]
                return val[:16] + "…" if len(val) > 16 else val
        return "—"

    # ------------------------------------------------------------------
    # TXT dışa aktarım
    # ------------------------------------------------------------------

    def _export_txt(self) -> None:
        default_name = (
            f"audit_log_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.txt"
        )
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Denetim Günlüğü Dışa Aktar",
            str(Path.home() / default_name),
            "Text Dosyası (*.txt)",
        )
        if not path:
            return

        col_w = [22, 32, 16, 20]
        header_parts = ["Zaman", "İşlem", "Kullanıcı", "HWID"]
        sep = "-" * (sum(col_w) + len(col_w) * 2 + 1)

        def fmt_row(vals: list[str]) -> str:
            return "  ".join(v.ljust(w)[:w] for v, w in zip(vals, col_w))

        # B-006: dışa aktarım eskiden yalnızca dört sütun yazıyordu — hash
        # yok, zincirin son ucu yok, doğrulama durumu yok. Halbuki bu dosya,
        # denetim kaydının makine dışına çıkan tek biçimi; içinde zincir
        # durumu olmadan dosyayla veritabanının tutarlılığı sonradan
        # gösterilemiyordu. Başlık metni CORE'da üretiliyor, çünkü aynı
        # metin "Zinciri Doğrula" düğmesinde de kullanılıyor.
        try:
            from CORE.audit_report import txt_basligi, zincir_raporu

            lines: list[str] = txt_basligi(
                zincir_raporu(DBManager()),
                kayit_sayisi=self._table.rowCount(),
            )
        except Exception as exc:
            # Zincir okunamazsa dışa aktarım YİNE de yapılmalı — ama bunu
            # sessizce "sağlam" gibi göstermek yanlış olurdu.
            lines = [
                "HYCLEUS — Denetim Günlüğü",
                f"Dışa aktarım: "
                f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
                sep,
                f"Zincir durumu : DOĞRULANAMADI ({exc})",
                sep,
            ]

        lines += [fmt_row(header_parts), sep]

        for row in range(self._table.rowCount()):
            vals = [
                (self._table.item(row, col) or QTableWidgetItem()).text()
                for col in range(4)
            ]
            lines.append(fmt_row(vals))

        lines += [sep, f"Toplam: {self._table.rowCount()} kayıt", ""]

        try:
            Path(path).write_text("\n".join(lines), encoding="utf-8")
            QMessageBox.information(
                self,
                "Dışa Aktarıldı",
                f"Denetim günlüğü başarıyla dışa aktarıldı:\n{path}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Dışa Aktarma Hatası", str(exc))
