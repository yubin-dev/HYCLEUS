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

from CORE.roles import is_admin_role
from DB.db_manager import DBManager
from UI.main_window_palette import _DARK

# Etiket renk seçici — kullanıcının etikete atadığı GERÇEK renk, tema
# token'ı değil (bir etiket her temada aynı kalmalı). B-055'in "ikinci bir
# renk yolu açma" kuralı burada uygulanmıyor: bu sabit bir stil rengi değil,
# kullanıcının seçtiği veri.
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


def _stil(T: dict[str, str]) -> str:
    """Diyaloğun stil sayfası — kayıtlı tema token'larından (B-055).

    Önceden sabit bir Catppuccin-Mocha paletiydi; preset değişince bu
    diyalog hiç değişmiyordu.
    """
    return f"""
QDialog  {{ background: {T['bg']}; color: {T['text']}; }}
QLabel   {{ color: {T['text']}; background: transparent; }}
QLabel#title   {{ color: {T['text']}; font-size: 15px; font-weight: bold; }}
QLabel#section {{ color: {T['accent']}; font-size: 11px; font-weight: bold; margin-top: 4px; }}
QLabel#field   {{ color: {T['subtext']}; font-size: 12px; }}
QFrame#sep     {{ background: {T['border']}; max-height: 1px; }}
QWidget#tag_bg {{ background: {T['search_bg']}; }}
QLineEdit {{
    background: {T['hover']}; color: {T['text']};
    border: 1px solid {T['border']}; border-radius: 6px;
    padding: 7px 10px; font-size: 13px;
}}
QLineEdit:focus {{ border-color: {T['accent']}; }}
QCheckBox {{ color: {T['text']}; spacing: 6px; font-size: 12px; background: transparent; }}
QCheckBox::indicator {{
    width: 15px; height: 15px;
    border: 2px solid {T['border']}; border-radius: 3px;
    background: {T['hover']};
}}
QCheckBox::indicator:checked {{ background: {T['accent']}; border-color: {T['accent']}; }}
QScrollArea {{ background: {T['search_bg']}; border: 1px solid {T['border']}; border-radius: 4px; }}
QPushButton#primary_btn {{
    background: {T['accent']}; color: {T['on_accent']}; border: none;
    border-radius: 6px; padding: 9px; font-size: 13px; font-weight: bold;
}}
QPushButton#primary_btn:hover {{ background: {T['accent_hover']}; }}
QPushButton#cancel_btn {{
    background: {T['hover']}; color: {T['text']}; border: none;
    border-radius: 6px; padding: 9px; font-size: 13px;
}}
QPushButton#cancel_btn:hover {{ background: {T['row_hover']}; }}
QPushButton#add_btn {{
    background: {T['green_tint']}; color: {T['green']};
    border: 1px solid {T['green']}; border-radius: 6px;
    padding: 6px 14px; font-size: 12px;
}}
QPushButton#add_btn:hover {{ background: {T['green_tint']}; }}
"""


def _sep() -> QFrame:
    f = QFrame()
    f.setObjectName("sep")
    f.setFrameShape(QFrame.HLine)
    return f


def _gorunurluk_rozeti(is_private: bool, T: dict[str, str]) -> QLabel:
    """Etiket satırı için görünürlük rozeti — yalnızca GÖSTERGE, mevcut
    yetki mantığına (satır 287'deki `is_private and not self._is_admin`
    filtresi) dokunmuyor. Renk kaynağı `self._T` — yeni renk İCAT
    EDİLMEDİ (B-055 deseni)."""
    if is_private:
        rozet = QLabel("Yalnızca Yönetici")
        bg, fg = T["red_tint"], T["red"]
    else:
        rozet = QLabel("Herkes")
        bg, fg = T["green_tint"], T["green"]
    rozet.setObjectName("etiket_gorunurluk_rozeti")
    rozet.setProperty("mahrem", is_private)
    rozet.setStyleSheet(
        f"QLabel#etiket_gorunurluk_rozeti {{"
        f" background: {bg}; color: {fg};"
        f" border-radius: 8px; font-size: 10px; font-weight: 600;"
        f" padding: 2px 8px; }}"
    )
    return rozet


class TagDialog(QDialog):
    """Dosyaya etiket atama diyaloğu."""

    def __init__(self, file_id: int, role: str = "", parent=None, *,
                 file_ids: list[int] | None = None,
                 T: dict[str, str] | None = None) -> None:
        """
        Args:
            T: Çağıranın aktif tema token sözlüğü (`HycleusWindow._T`).
                Verilmezse varsayılan "mavi" koyu palete düşer.
        """
        super().__init__(parent)
        self._file_ids: list[int] | None = file_ids
        self._file_id        = file_ids[0] if file_ids else file_id
        self._initial_assigned: set[int] = set()
        # Rol kararı CORE/roles.py'de (B-028). `_role_norm` ara değişkeni
        # KALDIRILDI: tek kullanıcısı bu karşılaştırmaydı.
        self._is_admin       = is_admin_role(role)
        self._T: dict[str, str] = T if T is not None else _DARK
        self._selected_color = _TAG_COLORS[0]
        self._color_btns: list[QPushButton]           = []
        self._checkboxes: list[tuple[QCheckBox, int]] = []

        self.setWindowTitle(
            f"HYCLEUS — {len(file_ids)} Dosyaya Etiket Ata"
            if file_ids else "HYCLEUS — Etiket Ata"
        )
        self.setFixedWidth(360)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setStyleSheet(_stil(self._T))
        self._build_ui()
        self._load_tags()

    # ------------------------------------------------------------------
    # UI kurulumu
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(8)

        n = len(self._file_ids) if self._file_ids else 0
        title = QLabel(f"🏷  Toplu Etiket Ata  ({n} dosya)" if n > 1 else "🏷  Etiket Ata")
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
                    f"QPushButton{{background:{c};border:3px solid {self._T['text']};"
                    f"border-radius:10px;width:20px;height:20px;}}"
                )
            else:
                btn.setStyleSheet(
                    f"QPushButton{{background:{c};border:2px solid transparent;"
                    f"border-radius:10px;width:20px;height:20px;}}"
                    f"QPushButton:hover{{border:2px solid {self._T['subtext']};}}"
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
            if self._file_ids:
                ph = ",".join("?" * len(self._file_ids))
                assigned = {
                    r["tag_id"]
                    for r in db.fetchall(
                        f"SELECT tag_id FROM file_tags WHERE file_id IN ({ph})"
                        f" GROUP BY tag_id HAVING COUNT(DISTINCT file_id) = {len(self._file_ids)}",
                        self._file_ids,
                    )
                }
            else:
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
        self._initial_assigned = assigned

        if not all_tags:
            empty = QLabel("Henüz etiket yok. Aşağıdan yeni etiket oluşturun.")
            empty.setStyleSheet(f"color:{self._T['subtext']}; font-size:11px;")
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
            row_h.addWidget(_gorunurluk_rozeti(bool(tag["is_private"]), self._T))

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
        to_remove = self._initial_assigned - to_assign

        try:
            if self._file_ids:
                for fid in self._file_ids:
                    for tag_id in to_assign:
                        db.execute(
                            "INSERT OR IGNORE INTO file_tags (file_id, tag_id) VALUES (?, ?)",
                            (fid, tag_id),
                        )
                    for tag_id in to_remove:
                        db.execute(
                            "DELETE FROM file_tags WHERE file_id = ? AND tag_id = ?",
                            (fid, tag_id),
                        )
                db.log(
                    "file_tags_bulk_updated",
                    detail=f"file_ids={self._file_ids} tags={sorted(to_assign)}",
                )
            else:
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
