"""HYCLEUS — Etiket Atama Diyaloğu"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from DB.db_manager import DBManager

_TAG_COLORS = [
    "#89b4fa",  # mavi
    "#a6e3a1",  # yeşil
    "#f9e2af",  # sarı
    "#f38ba8",  # kırmızı
    "#cba6f7",  # mor
    "#fab387",  # turuncu
    "#94e2d5",  # turkuaz
    "#eba0ac",  # pembe
]

_STYLE = """
QDialog  { background: #1e1e2e; color: #cdd6f4; }
QLabel   { color: #cdd6f4; background: transparent; }
QLabel#title   { color: #cdd6f4; font-size: 15px; font-weight: bold; }
QLabel#section { color: #89b4fa; font-size: 11px; font-weight: bold; margin-top: 4px; }
QLabel#field   { color: #a6adc8; font-size: 12px; }
QFrame#sep     { background: #313244; max-height: 1px; }
QWidget#tag_bg { background: #181825; }
QLineEdit {
    background: #313244; color: #cdd6f4;
    border: 1px solid #45475a; border-radius: 6px;
    padding: 7px 10px; font-size: 13px;
}
QLineEdit:focus { border-color: #89b4fa; }
QCheckBox { color: #cdd6f4; spacing: 6px; font-size: 12px; background: transparent; }
QCheckBox::indicator {
    width: 15px; height: 15px;
    border: 2px solid #45475a; border-radius: 3px;
    background: #313244;
}
QCheckBox::indicator:checked { background: #89b4fa; border-color: #89b4fa; }
QScrollArea { background: #181825; border: 1px solid #313244; border-radius: 4px; }
QPushButton#primary_btn {
    background: #89b4fa; color: #1e1e2e; border: none;
    border-radius: 6px; padding: 9px; font-size: 13px; font-weight: bold;
}
QPushButton#primary_btn:hover { background: #b4d0ff; }
QPushButton#cancel_btn {
    background: #313244; color: #cdd6f4; border: none;
    border-radius: 6px; padding: 9px; font-size: 13px;
}
QPushButton#cancel_btn:hover { background: #45475a; }
QPushButton#add_btn {
    background: #1a2d1a; color: #a6e3a1;
    border: 1px solid #2a3d2a; border-radius: 6px;
    padding: 6px 14px; font-size: 12px;
}
QPushButton#add_btn:hover { background: #2a3d2a; }
"""


def _sep() -> QFrame:
    f = QFrame()
    f.setObjectName("sep")
    f.setFrameShape(QFrame.HLine)
    return f


class TagDialog(QDialog):
    """Dosyaya etiket atama diyaloğu."""

    def __init__(self, file_id: int, role: str = "", parent=None) -> None:
        super().__init__(parent)
        self._file_id        = file_id
        self._role_norm      = role.strip().lower()
        self._is_admin       = self._role_norm == "yönetici"
        self._selected_color = _TAG_COLORS[0]
        self._color_btns: list[QPushButton]           = []
        self._checkboxes: list[tuple[QCheckBox, int]] = []

        self.setWindowTitle("HYCLEUS — Etiket Ata")
        self.setFixedWidth(360)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setStyleSheet(_STYLE)
        self._build_ui()
        self._load_tags()

    # ------------------------------------------------------------------
    # UI kurulumu
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(8)

        title = QLabel("🏷  Etiket Ata")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        layout.addWidget(_sep())

        lbl_tags = QLabel("Etiketler")
        lbl_tags.setObjectName("section")
        layout.addWidget(lbl_tags)

        # Kaydırılabilir etiket listesi
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFixedHeight(160)

        self._list_widget = QWidget()
        self._list_widget.setObjectName("tag_bg")
        self._list_layout = QVBoxLayout(self._list_widget)
        self._list_layout.setContentsMargins(10, 8, 10, 8)
        self._list_layout.setSpacing(4)
        scroll.setWidget(self._list_widget)
        layout.addWidget(scroll)

        layout.addWidget(_sep())

        lbl_new = QLabel("Yeni Etiket Ekle")
        lbl_new.setObjectName("section")
        layout.addWidget(lbl_new)

        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("Etiket adı (örn: İş 001, Okul 003)")
        layout.addWidget(self._name_input)

        self._private_cb = QCheckBox("🔒  Mahrem (gizli) — sadece Yönetici görebilir")
        self._private_cb.setVisible(self._is_admin)
        self._private_cb.setEnabled(self._is_admin)
        layout.addWidget(self._private_cb)

        # Renk seçici
        color_row = QHBoxLayout()
        color_lbl = QLabel("Renk:")
        color_lbl.setObjectName("field")
        color_row.addWidget(color_lbl)

        for c in _TAG_COLORS:
            btn = QPushButton()
            btn.setFixedSize(20, 20)
            btn.setProperty("color_val", c)
            btn.setCursor(Qt.PointingHandCursor)
            self._color_btns.append(btn)
            btn.clicked.connect(lambda checked=False, col=c: self._select_color(col))
            color_row.addWidget(btn)

        color_row.addStretch()
        layout.addLayout(color_row)
        self._select_color(_TAG_COLORS[0])

        add_btn = QPushButton("Ekle")
        add_btn.setObjectName("add_btn")
        add_btn.setCursor(Qt.PointingHandCursor)
        add_btn.clicked.connect(self._on_create_tag)
        layout.addWidget(add_btn)

        layout.addSpacing(4)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        save_btn = QPushButton("Kaydet")
        save_btn.setObjectName("primary_btn")
        save_btn.setCursor(Qt.PointingHandCursor)
        save_btn.clicked.connect(self._on_save)
        btn_row.addWidget(save_btn)

        cancel_btn = QPushButton("İptal")
        cancel_btn.setObjectName("cancel_btn")
        cancel_btn.setCursor(Qt.PointingHandCursor)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        layout.addLayout(btn_row)

    # ------------------------------------------------------------------
    # Renk seçimi
    # ------------------------------------------------------------------

    def _select_color(self, color: str) -> None:
        self._selected_color = color
        for btn in self._color_btns:
            c = btn.property("color_val")
            if c == color:
                btn.setStyleSheet(
                    f"QPushButton{{background:{c};border:3px solid #cdd6f4;"
                    f"border-radius:10px;width:20px;height:20px;}}"
                )
            else:
                btn.setStyleSheet(
                    f"QPushButton{{background:{c};border:2px solid transparent;"
                    f"border-radius:10px;width:20px;height:20px;}}"
                    f"QPushButton:hover{{border:2px solid #6c7086;}}"
                )

    # ------------------------------------------------------------------
    # Etiket listesi yükleme
    # ------------------------------------------------------------------

    def _load_tags(self) -> None:
        while self._list_layout.count():
            item = self._list_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self._checkboxes.clear()

        try:
            db       = DBManager()
            all_tags = db.fetchall("SELECT id, name, color, is_private FROM tags ORDER BY name")
            assigned = {
                r["tag_id"]
                for r in db.fetchall(
                    "SELECT tag_id FROM file_tags WHERE file_id = ?",
                    (self._file_id,),
                )
            }
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı", str(exc))
            return

        if not all_tags:
            empty = QLabel("Henüz etiket yok. Aşağıdan yeni etiket oluşturun.")
            empty.setStyleSheet("color:#6c7086; font-size:11px;")
            empty.setWordWrap(True)
            self._list_layout.addWidget(empty)
            self._list_layout.addStretch()
            return

        for tag in all_tags:
            # Mahrem etiketler sadece Yönetici tarafından görülebilir
            if tag["is_private"] and not self._is_admin:
                continue

            row_w = QWidget()
            row_w.setObjectName("tag_bg")
            row_h = QHBoxLayout(row_w)
            row_h.setContentsMargins(4, 2, 4, 2)
            row_h.setSpacing(8)

            dot = QLabel("●")
            dot.setStyleSheet(
                f"color:{tag['color']}; font-size:14px; background:transparent;"
            )
            dot.setFixedWidth(18)

            label_text = f"🔒 {tag['name']}" if tag["is_private"] else tag["name"]
            cb = QCheckBox(label_text)
            cb.setChecked(tag["id"] in assigned)

            row_h.addWidget(dot)
            row_h.addWidget(cb)
            row_h.addStretch()

            self._checkboxes.append((cb, tag["id"]))
            self._list_layout.addWidget(row_w)

        self._list_layout.addStretch()

    # ------------------------------------------------------------------
    # Eylemler
    # ------------------------------------------------------------------

    def _on_create_tag(self) -> None:
        name = self._name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "Etiket", "Etiket adı boş olamaz.")
            return

        is_private = 1 if self._private_cb.isChecked() else 0
        try:
            DBManager().execute(
                "INSERT INTO tags (name, color, is_private) VALUES (?, ?, ?)",
                (name, self._selected_color, is_private),
            )
        except Exception as exc:
            if "UNIQUE" in str(exc):
                QMessageBox.warning(self, "Etiket", f"'{name}' etiketi zaten mevcut.")
            else:
                QMessageBox.critical(self, "Hata", str(exc))
            return

        self._name_input.clear()
        self._load_tags()

    def _on_save(self) -> None:
        db        = DBManager()
        to_assign = {tag_id for cb, tag_id in self._checkboxes if cb.isChecked()}

        try:
            prev = {
                r["tag_id"]
                for r in db.fetchall(
                    "SELECT tag_id FROM file_tags WHERE file_id = ?",
                    (self._file_id,),
                )
            }

            for tag_id in to_assign - prev:
                db.execute(
                    "INSERT OR IGNORE INTO file_tags (file_id, tag_id) VALUES (?, ?)",
                    (self._file_id, tag_id),
                )

            for tag_id in prev - to_assign:
                db.execute(
                    "DELETE FROM file_tags WHERE file_id = ? AND tag_id = ?",
                    (self._file_id, tag_id),
                )

            db.log(
                "file_tags_updated",
                target_type="file",
                target_id=self._file_id,
                detail=f"tags={sorted(to_assign)}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return

        self.accept()
