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

_FAIL_KEYWORDS = frozenset(
    {"fail", "denied", "blacklist", "error", "reject", "lock", "invalid", "unauthorized"}
)

_STYLE = """
QDialog  { background: #1e1e2e; color: #cdd6f4; }
QLabel   { color: #cdd6f4; }
QTableWidget {
    background: #181825;
    color: #cdd6f4;
    gridline-color: #313244;
    border: 1px solid #313244;
    border-radius: 4px;
    font-size: 12px;
}
QTableWidget::item:selected { background: #313244; }
QHeaderView::section {
    background: #1e1e2e;
    color: #89b4fa;
    border: none;
    border-bottom: 1px solid #313244;
    padding: 4px 8px;
    font-weight: 600;
    font-size: 12px;
}
QComboBox {
    background: #181825;
    color: #cdd6f4;
    border: 1px solid #313244;
    border-radius: 4px;
    padding: 4px 8px;
    min-width: 150px;
    font-size: 12px;
}
QComboBox QAbstractItemView {
    background: #181825;
    color: #cdd6f4;
    selection-background-color: #313244;
    border: 1px solid #313244;
}
QComboBox::drop-down { border: none; width: 20px; }
QDateEdit {
    background: #181825;
    color: #cdd6f4;
    border: 1px solid #313244;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}
QDateEdit::drop-down { border: none; width: 20px; }
QCalendarWidget { background: #181825; color: #cdd6f4; }
"""

_BTN = (
    "QPushButton{color:#cdd6f4;background:#313244;border:none;"
    "border-radius:6px;padding:5px 14px;font-size:12px;}"
    "QPushButton:hover{background:#45475a;}"
)
_BTN_EXPORT = (
    "QPushButton{color:#1e1e2e;background:#89b4fa;border:none;"
    "border-radius:6px;padding:5px 14px;font-size:12px;font-weight:600;}"
    "QPushButton:hover{background:#74c7ec;}"
)


def _is_failure(action: str) -> bool:
    low = action.lower()
    return any(k in low for k in _FAIL_KEYWORDS)


class AuditLogDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("HYCLEUS — Denetim Günlüğü")
        self.setMinimumSize(900, 540)
        self.setStyleSheet(_STYLE)
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
        btn_filter.setStyleSheet(_BTN)
        btn_filter.setCursor(Qt.PointingHandCursor)
        btn_filter.clicked.connect(self._load)
        bar.addWidget(btn_filter)

        btn_reset = QPushButton("Sıfırla")
        btn_reset.setStyleSheet(_BTN)
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
        self._count_label.setStyleSheet("color:#6c7086; font-size:11px;")
        footer.addWidget(self._count_label)

        footer.addStretch()

        btn_export = QPushButton("TXT Dışa Aktar")
        btn_export.setStyleSheet(_BTN_EXPORT)
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
                item.setForeground(QColor("#f38ba8"))
                item.setBackground(QColor("#2d1818"))
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

        lines: list[str] = [
            "HYCLEUS — Denetim Günlüğü",
            f"Dışa aktarım: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
            sep,
            fmt_row(header_parts),
            sep,
        ]

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
