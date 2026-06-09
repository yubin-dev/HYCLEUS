import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

_log = logging.getLogger("hycleus.ui")

from PySide6.QtCore import QObject, QPoint, QThread, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QDragEnterEvent,
    QDragMoveEvent,
    QDropEvent,
    QFont,
    QMouseEvent,
    QPaintEvent,
    QPainter,
    QResizeEvent,
)
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QGraphicsBlurEffect,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

import pyotp

from CORE.crypto import AuthenticationError, decrypt_file, encrypt_file
from CORE.scanner import ScanResult, scan_file
from CORE.usb_manager import get_usb_hwid
from CORE.vault_manager import (
    USBAuthError,
    VaultTamperedError,
    authenticate_usb,
    blacklist_usb,
    read_vault_role,
)
from DB.db_manager import DBManager
from UI.AdminPanel import AdminPanel
from UI.AuditLogDialog import AuditLogDialog

_TOTP_FILE = Path(__file__).parent.parent / "data" / "totp_secret.json"

# ── Renk paletleri ────────────────────────────────────────────────────────
_DARK: dict[str, str] = {
    "bg":         "#1a1a2e",
    "bg2":        "#16213e",
    "bg3":        "#0f3460",
    "accent":     "#6c63ff",
    "accent_dim": "#6c63ff30",
    "text":       "#e0e0e0",
    "subtext":    "#8892a4",
    "border":     "#ffffff20",
    "hover":      "#ffffff15",
    "green":      "#43d9a2",
    "red":        "#ff6b6b",
    "yellow":     "#ffd166",
    "gray":       "#6b7280",
    "purple":     "#b39ddb",
    "hcl_fg":     "#b39ddb",
    "hcl_bg":     "#2a1f5c",
}
_LIGHT: dict[str, str] = {
    "bg":         "#f8f9fa",
    "bg2":        "#ffffff",
    "bg3":        "#e9ecef",
    "accent":     "#2563eb",
    "accent_dim": "#2563eb25",
    "text":       "#1a1a2e",
    "subtext":    "#6b7280",
    "border":     "#dee2e6",
    "hover":      "#00000010",
    "green":      "#16a34a",
    "red":        "#dc2626",
    "yellow":     "#b45309",
    "gray":       "#9ca3af",
    "purple":     "#7c3aed",
    "hcl_fg":     "#7c3aed",
    "hcl_bg":     "#ede9fe",
}

_SIDEBAR_NAV: list[tuple[str, str, str]] = [
    ("📁", "Genel",       "Genel"),
    ("⚠",  "Kritik",     "Kritik"),
    ("🔒", "Karantina",  "Karantina"),
    ("🗑", "İmha Odası", "Imha"),
]

_ROLE_COLORS: dict[str, str] = {
    "Yönetici":    "#6c63ff",
    "Standart":    "#43d9a2",
    "Salt Okunur": "#ffd166",
}

_VERDICT_BADGE: dict[str, tuple[str, str]] = {
    "clean":      ("✓ Temiz",     "#43d9a2"),
    "suspicious": ("⚠ Şüpheli",  "#ffd166"),
    "malicious":  ("✗ Zararlı",   "#ff6b6b"),
    "unknown":    ("? Bilinmiyor","#6b7280"),
}

# Etiket → (metin rengi, arka plan rengi)
_LABEL_PILL: dict[str, tuple[str, str]] = {
    "Genel":     ("green",  ""),
    "Kritik":    ("red",    ""),
    "Karantina": ("yellow", ""),
    "Imha":      ("gray",   ""),
}


class _ScanWorker(QObject):
    """Dosya tarama işçisi — QObject, QThread'den türemez."""

    finished = Signal(int, object)  # (row, ScanResult)

    def __init__(self, path: Path, file_id: int, row: int) -> None:
        super().__init__()
        self._path    = path
        self._file_id = file_id
        self._row     = row

    def run(self) -> None:
        _log.info("worker_run  file=%s  file_id=%d", self._path.name, self._file_id)
        try:
            result = scan_file(self._path, file_id=self._file_id)
            _log.info(
                "worker_done  file=%s  verdict=%s  mal=%d  sus=%d  engines=%d  mock=%s",
                self._path.name, result.verdict,
                result.malicious, result.suspicious, result.engines_total, result.mock,
            )
        except Exception:
            _log.exception("worker_error  file=%s  file_id=%d", self._path.name, self._file_id)
            from CORE.scanner import _mock, _sha256
            result = _mock(_sha256(self._path))
        self.finished.emit(self._row, result)




class _LockOverlay(QWidget):
    """USB çekilince ana pencerenin üstünü örten kilit katmanı."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.hide()
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(16)

        icon = QLabel("🔒")
        icon.setAlignment(Qt.AlignCenter)
        icon.setStyleSheet("font-size:48px; background:transparent;")
        layout.addWidget(icon)

        msg = QLabel("USB Token çıkarıldı\nlütfen yeniden takın")
        msg.setAlignment(Qt.AlignCenter)
        msg.setStyleSheet(
            "color:#e0e0e0; font-size:16px; font-weight:600; background:transparent;"
        )
        layout.addWidget(msg)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(0, 0, 0, 200))


class _TopBar(QFrame):
    """Sürüklenebilir üst çubuk — pencere kontrollerini, logoyu ve sayfa başlığını barındırır."""

    def __init__(self, win: "HycleusWindow") -> None:
        super().__init__()
        self._win  = win
        self._drag: QPoint | None = None
        self.setObjectName("top_bar")
        self.setFixedHeight(56)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton:
            self._drag = event.globalPosition().toPoint() - self._win.frameGeometry().topLeft()
        event.accept()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self._drag is not None and (event.buttons() & Qt.LeftButton):
            self._win.move(event.globalPosition().toPoint() - self._drag)
        event.accept()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        self._drag = None
        event.accept()

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        if self._win.isMaximized():
            self._win.showNormal()
        else:
            self._win.showMaximized()
        event.accept()


class HycleusWindow(QMainWindow):
    def __init__(self, hwid: str, key: bytes, role: str = "Yönetici"):
        super().__init__()
        self._hwid               = hwid
        self._key                = key
        self._role               = role
        self._active_btn: QPushButton | None = None
        self._nav_btns: dict[str, QPushButton] = {}
        self._current_label: str = "Genel"
        self._locked             = False
        self._authenticating     = False
        self._threads: list[QThread]  = []
        self._workers: list[QObject]  = []
        self._dark: bool         = True
        self._T: dict[str, str]  = _DARK.copy()

        self._current_tag_id: int | None         = None
        self._active_tag_btn: QPushButton | None = None
        self._tag_btns: dict[int, QPushButton]   = {}

        _log.info(
            "window_init  hwid=%s  key_len=%d  key_prefix=%s  role=%s",
            hwid, len(key), key[:4].hex(), role,
        )

        self.setWindowTitle("HYCLEUS")
        self.setMinimumSize(1024, 680)
        self.setAcceptDrops(True)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)

        self._build_ui()
        self._apply_role_restrictions()
        self._apply_theme()

        self._blur = QGraphicsBlurEffect(self)
        self._blur.setBlurRadius(12)
        self._overlay = _LockOverlay(self)

        self._usb_timer = QTimer(self)
        self._usb_timer.setInterval(3000)
        self._usb_timer.timeout.connect(self._poll_usb)
        self._usb_timer.start()

        self._expiry_timer = QTimer(self)
        self._expiry_timer.setInterval(1000)
        self._expiry_timer.timeout.connect(self._tick_expiry)
        self._expiry_timer.start()

        self._refresh_usb_badge()
        self._on_sidebar_click("Genel", self._nav_btns["Genel"])
        self._refresh_tag_sidebar()

    # ── UI kurulumu ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("central_root")
        self.setCentralWidget(central)

        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._make_top_bar())

        body = QWidget()
        body.setObjectName("body")
        body_hbox = QHBoxLayout(body)
        body_hbox.setContentsMargins(0, 0, 0, 0)
        body_hbox.setSpacing(0)
        body_hbox.addWidget(self._make_sidebar())
        body_hbox.addWidget(self._make_content())
        root.addWidget(body)

    def _make_top_bar(self) -> _TopBar:
        bar = _TopBar(self)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(18, 0, 8, 0)
        layout.setSpacing(6)

        logo = QLabel("HYCLEUS")
        logo.setObjectName("logo")
        logo.setFont(QFont("Segoe UI", 15, QFont.Bold))
        layout.addWidget(logo)

        layout.addSpacing(20)

        self._page_title = QLabel("Genel")
        self._page_title.setObjectName("page_title")
        layout.addWidget(self._page_title)

        layout.addStretch()

        self._theme_btn = QPushButton("🌙")
        self._theme_btn.setObjectName("theme_btn")
        self._theme_btn.setFixedSize(36, 36)
        self._theme_btn.setCursor(Qt.PointingHandCursor)
        self._theme_btn.setToolTip("Gündüz / Gece modunu değiştir")
        self._theme_btn.clicked.connect(self._toggle_theme)
        layout.addWidget(self._theme_btn)

        layout.addSpacing(8)

        for text, obj_name, slot in (
            ("─",  "btn_min",   self.showMinimized),
            ("□",  "btn_max",   self._toggle_maximize),
            ("✕",  "btn_close", self.close),
        ):
            btn = QPushButton(text)
            btn.setObjectName(obj_name)
            btn.setFixedSize(36, 36)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(slot)
            layout.addWidget(btn)

        return bar

    def _make_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(8, 16, 8, 16)
        layout.setSpacing(2)

        for icon, display_name, db_label in _SIDEBAR_NAV:
            btn = QPushButton(f"  {icon}   {display_name}")
            btn.setFixedHeight(44)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setObjectName(f"nav_{db_label}")
            btn.clicked.connect(
                lambda checked=False, lbl=db_label, b=btn: self._on_sidebar_click(lbl, b)
            )
            self._nav_btns[db_label] = btn
            layout.addWidget(btn)

        # ── Etiketler bölümü ──────────────────────────────────────────────
        tag_sep = QFrame()
        tag_sep.setObjectName("tag_sep")
        tag_sep.setFrameShape(QFrame.HLine)
        layout.addWidget(tag_sep)

        tags_lbl = QLabel("ETİKETLER")
        tags_lbl.setObjectName("tags_label")
        layout.addWidget(tags_lbl)

        self._tag_container = QWidget()
        self._tag_container_layout = QVBoxLayout(self._tag_container)
        self._tag_container_layout.setContentsMargins(0, 0, 0, 0)
        self._tag_container_layout.setSpacing(1)
        layout.addWidget(self._tag_container)

        layout.addStretch()

        self._admin_sep = QFrame()
        self._admin_sep.setObjectName("admin_sep")
        self._admin_sep.setFrameShape(QFrame.HLine)
        layout.addWidget(self._admin_sep)

        self._admin_label = QLabel("YÖNETİCİ")
        self._admin_label.setObjectName("admin_label")
        layout.addWidget(self._admin_label)

        self._blacklist_btn = QPushButton("  🚫  Kara Listeye Al")
        self._blacklist_btn.setObjectName("blacklist_btn")
        self._blacklist_btn.setFixedHeight(40)
        self._blacklist_btn.setCursor(Qt.PointingHandCursor)
        self._blacklist_btn.clicked.connect(self._on_blacklist_usb)
        layout.addWidget(self._blacklist_btn)

        self._audit_log_btn = QPushButton("  📋  Denetim Günlüğü")
        self._audit_log_btn.setObjectName("audit_btn")
        self._audit_log_btn.setFixedHeight(40)
        self._audit_log_btn.setCursor(Qt.PointingHandCursor)
        self._audit_log_btn.clicked.connect(self._on_open_audit_log)
        layout.addWidget(self._audit_log_btn)

        self._admin_panel_btn = QPushButton("  🔌  USB Yönetimi")
        self._admin_panel_btn.setObjectName("admin_panel_btn")
        self._admin_panel_btn.setFixedHeight(40)
        self._admin_panel_btn.setCursor(Qt.PointingHandCursor)
        self._admin_panel_btn.clicked.connect(self._on_open_admin_panel)
        layout.addWidget(self._admin_panel_btn)

        layout.addSpacing(8)

        self._role_badge = QLabel(self._role)
        self._role_badge.setObjectName("role_badge")
        self._role_badge.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._role_badge)

        self._usb_badge = QLabel()
        self._usb_badge.setObjectName("usb_badge")
        self._usb_badge.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._usb_badge)

        return sidebar

    def _make_content(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("content")

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 12)
        layout.setSpacing(12)

        self._search_bar = QLineEdit()
        self._search_bar.setObjectName("search_bar")
        self._search_bar.setPlaceholderText("🔍  Dosya adı, SHA-256 veya etiket ile ara...")
        self._search_bar.setFixedHeight(36)
        self._search_bar.textChanged.connect(self._search_files)
        layout.addWidget(self._search_bar)

        self._expiry_banner = QLabel()
        self._expiry_banner.setObjectName("expiry_banner")
        self._expiry_banner.setAlignment(Qt.AlignCenter)
        self._expiry_banner.setFixedHeight(32)
        self._expiry_banner.setVisible(False)
        layout.addWidget(self._expiry_banner)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Dosya Adı", "Etiket", "Boyut", "Tarih", "Tarama"])
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.Fixed)
        self._table.setColumnWidth(4, 120)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setShowGrid(False)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)
        layout.addWidget(self._table)

        self._drop_hint = QLabel("Dosyaları buraya sürükleyin — otomatik karantinaya alınır")
        self._drop_hint.setObjectName("drop_hint")
        self._drop_hint.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._drop_hint)

        return frame

    # ── Tema ──────────────────────────────────────────────────────────────

    def _toggle_theme(self) -> None:
        self._dark = not self._dark
        self._T = _DARK.copy() if self._dark else _LIGHT.copy()
        self._apply_theme()
        self._load_label(self._current_label)

    def _toggle_maximize(self) -> None:
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def _nav_btn_style(self, *, active: bool) -> str:
        T = self._T
        if active:
            return (
                f"QPushButton{{color:{T['accent']};background:{T['bg2']};"
                f"border:none;border-left:3px solid {T['accent']};"
                f"border-radius:8px;padding:10px 14px 10px 13px;"
                f"text-align:left;font-size:13px;font-weight:600;}}"
                f"QPushButton:hover{{background:{T['bg3']};}}"
            )
        return (
            f"QPushButton{{color:{T['text']};background:transparent;"
            f"border:none;border-left:3px solid transparent;"
            f"border-radius:8px;padding:10px 14px 10px 16px;"
            f"text-align:left;font-size:13px;}}"
            f"QPushButton:hover{{background:{T['hover']};border-left:3px solid {T['accent']}50;}}"
        )

    def _tag_btn_style(self, *, color: str, active: bool) -> str:
        T = self._T
        if active:
            return (
                f"QPushButton{{color:{color};background:{T['bg2']};"
                f"border:none;border-left:3px solid {color};"
                f"border-radius:8px;padding:6px 14px 6px 13px;"
                f"text-align:left;font-size:12px;font-weight:600;}}"
                f"QPushButton:hover{{background:{T['bg3']};}}"
            )
        return (
            f"QPushButton{{color:{T['subtext']};background:transparent;"
            f"border:none;border-left:3px solid transparent;"
            f"border-radius:8px;padding:6px 14px 6px 16px;"
            f"text-align:left;font-size:12px;}}"
            f"QPushButton:hover{{background:{T['hover']};border-left:3px solid {color}50;}}"
        )

    def _apply_tag_theme(self) -> None:
        for btn in self._tag_btns.values():
            color  = btn.property("tag_color") or self._T["accent"]
            active = btn is self._active_tag_btn
            btn.setStyleSheet(self._tag_btn_style(color=color, active=active))

    def _apply_theme(self) -> None:
        T = self._T
        self._theme_btn.setText("☀" if self._dark else "🌙")

        role_color  = _ROLE_COLORS.get(self._role, T["subtext"])

        qss = f"""
            QWidget#central_root, QWidget#body {{ background: {T['bg']}; }}

            QFrame#top_bar {{
                background: {T['bg2']};
                border-bottom: 1px solid {T['border']};
            }}
            QLabel#logo {{
                color: {T['accent']};
                font-weight: 700;
                font-size: 15px;
                background: transparent;
            }}
            QLabel#page_title {{
                color: {T['subtext']};
                font-size: 13px;
                font-weight: 500;
                background: transparent;
            }}
            QPushButton#theme_btn {{
                background: {T['bg3']};
                color: {T['text']};
                border: 1px solid {T['border']};
                border-radius: 18px;
                font-size: 15px;
                padding: 0px;
            }}
            QPushButton#theme_btn:hover {{ background: {T['hover']}; }}
            QPushButton#btn_min, QPushButton#btn_max {{
                background: transparent;
                color: {T['subtext']};
                border: none;
                border-radius: 8px;
                font-size: 13px;
                padding: 0px;
            }}
            QPushButton#btn_min:hover, QPushButton#btn_max:hover {{
                background: {T['hover']};
                color: {T['text']};
            }}
            QPushButton#btn_close {{
                background: transparent;
                color: {T['subtext']};
                border: none;
                border-radius: 8px;
                font-size: 13px;
                padding: 0px;
            }}
            QPushButton#btn_close:hover {{ background: #ff6b6b; color: white; }}

            QFrame#sidebar {{
                background: {T['bg']};
                border-right: 1px solid {T['border']};
            }}
            QFrame#admin_sep {{ color: {T['border']}; margin: 4px 0; }}
            QLabel#admin_label {{
                color: {T['subtext']};
                font-size: 10px;
                font-weight: 600;
                padding: 4px 8px 2px 8px;
                letter-spacing: 1px;
                background: transparent;
            }}
            QPushButton#blacklist_btn {{
                color: {T['red']};
                background: transparent;
                border: none;
                border-left: 3px solid transparent;
                border-radius: 8px;
                padding: 10px 14px 10px 16px;
                text-align: left;
                font-size: 12px;
            }}
            QPushButton#blacklist_btn:hover {{ background: {T['hover']}; }}
            QPushButton#audit_btn {{
                color: {T['accent']};
                background: transparent;
                border: none;
                border-left: 3px solid transparent;
                border-radius: 8px;
                padding: 10px 14px 10px 16px;
                text-align: left;
                font-size: 12px;
            }}
            QPushButton#audit_btn:hover {{ background: {T['hover']}; }}
            QPushButton#admin_panel_btn {{
                color: {T['purple']};
                background: transparent;
                border: none;
                border-left: 3px solid transparent;
                border-radius: 8px;
                padding: 10px 14px 10px 16px;
                text-align: left;
                font-size: 12px;
            }}
            QPushButton#admin_panel_btn:hover {{ background: {T['hover']}; }}
            QLabel#role_badge {{
                color: {role_color};
                font-size: 11px;
                font-weight: 600;
                padding: 5px 14px;
                border: 1px solid {role_color};
                border-radius: 10px;
                background: transparent;
                margin: 2px 10px;
            }}

            QFrame#content {{ background: {T['bg']}; }}
            QLineEdit#search_bar {{
                background: {T['bg3']};
                color: {T['text']};
                border: 1.5px solid transparent;
                border-radius: 18px;
                padding: 7px 16px;
                font-size: 13px;
                selection-background-color: {T['accent']};
            }}
            QLineEdit#search_bar:focus {{
                border: 1.5px solid {T['accent']};
            }}
            QTableWidget {{
                background: {T['bg']};
                alternate-background-color: {T['bg2']};
                color: {T['text']};
                border: none;
                gridline-color: transparent;
                outline: none;
                font-size: 13px;
            }}
            QHeaderView::section {{
                background: {T['bg3']};
                color: {T['subtext']};
                border: none;
                border-right: 1px solid {T['border']};
                border-bottom: 1px solid {T['border']};
                padding: 10px 8px;
                font-size: 11px;
                font-weight: 600;
                letter-spacing: 0.5px;
            }}
            QTableWidget::item {{
                padding: 8px 10px;
                border-bottom: 1px solid {T['border']};
            }}
            QTableWidget::item:selected {{
                background: {T['accent_dim']};
                color: {T['text']};
            }}
            QLabel#drop_hint {{
                color: {T['subtext']};
                font-size: 11px;
                padding: 10px;
                border: 1.5px dashed {T['border']};
                border-radius: 8px;
                background: transparent;
            }}
            QFrame#tag_sep {{
                color: {T['border']};
                margin: 4px 0;
                max-height: 1px;
            }}
            QLabel#tags_label {{
                color: {T['subtext']};
                font-size: 10px;
                font-weight: 600;
                padding: 4px 8px 2px 8px;
                letter-spacing: 1px;
                background: transparent;
            }}
        """

        self.centralWidget().setStyleSheet(qss)

        for db_label, btn in self._nav_btns.items():
            btn.setStyleSheet(self._nav_btn_style(active=(db_label == self._current_label)))

        self._refresh_usb_badge()
        self._apply_tag_theme()

    # ── Rol kısıtlamaları ─────────────────────────────────────────────────

    def _apply_role_restrictions(self) -> None:
        is_admin    = self._role == "Yönetici"
        is_readonly = self._role == "Salt Okunur"

        self._admin_sep.setVisible(is_admin)
        self._admin_label.setVisible(is_admin)
        self._blacklist_btn.setVisible(is_admin)
        self._audit_log_btn.setVisible(is_admin)
        self._admin_panel_btn.setVisible(is_admin)

        self.setAcceptDrops(not is_readonly)
        self._nav_btns["Kritik"].setVisible(not is_readonly)
        self._drop_hint.setVisible(not is_readonly)

        self._role_badge.setText(self._role)

    # ── Yönetici işlemleri ────────────────────────────────────────────────

    def _on_blacklist_usb(self) -> None:
        current_hwid = get_usb_hwid() or ""
        hwid, ok = QInputDialog.getText(
            self, "Kara Listeye Al", "Kara listeye alınacak USB HWID:", text=current_hwid,
        )
        if not ok:
            return
        hwid = hwid.strip()
        if not hwid:
            QMessageBox.warning(self, "Kara Liste", "HWID boş olamaz.")
            return

        confirm = QMessageBox.question(
            self, "Kara Liste — Onay",
            f"Bu USB cihazı kara listeye alınacak:\n\n{hwid}\n\n"
            "Cihaz bir daha giriş yapamayacak. Devam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        try:
            blacklist_usb(hwid)
            QMessageBox.information(self, "Kara Liste",
                                    f"USB cihazı başarıyla kara listeye alındı:\n{hwid}")
        except ValueError as exc:
            QMessageBox.warning(self, "Kara Liste", str(exc))
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))

    def _on_open_audit_log(self) -> None:
        dlg = AuditLogDialog(self)
        dlg.exec()

    def _on_open_admin_panel(self) -> None:
        dlg = AdminPanel(current_hwid=self._hwid, parent=self)
        dlg.exec()

    # ── Sidebar filtresi ──────────────────────────────────────────────────

    def _on_sidebar_click(self, db_label: str, btn: QPushButton) -> None:
        if self._active_tag_btn is not None:
            prev_color = self._active_tag_btn.property("tag_color") or self._T["accent"]
            self._active_tag_btn.setStyleSheet(self._tag_btn_style(color=prev_color, active=False))
            self._active_tag_btn = None
        self._current_tag_id = None

        if self._active_btn is not None:
            self._active_btn.setStyleSheet(self._nav_btn_style(active=False))
        btn.setStyleSheet(self._nav_btn_style(active=True))
        self._active_btn    = btn
        self._current_label = db_label

        display = next(
            (disp for _, disp, lbl in _SIDEBAR_NAV if lbl == db_label), db_label
        )
        self._page_title.setText(display)

        self._search_bar.blockSignals(True)
        self._search_bar.clear()
        self._search_bar.blockSignals(False)
        self._load_label(db_label)

    def _load_label(self, db_label: str) -> None:
        self._table.setRowCount(0)
        in_imha = (db_label == "Imha")
        self._table.horizontalHeaderItem(3).setText(
            "Kalan Süre" if in_imha else "Tarih"
        )
        self._expiry_banner.setVisible(in_imha)
        if in_imha:
            self._expiry_banner.setText("⏱  Hesaplanıyor...")
            self._expiry_banner.setStyleSheet(
                f"color:{self._T['subtext']}; font-size:13px;"
                f"background:{self._T['bg3']}; border-radius:8px; padding:4px 12px;"
            )
        try:
            rows = DBManager().fetchall(
                """
                SELECT f.id, f.filename, f.label, f.size_bytes, f.added_at,
                       f.filepath, f.original_sha256, f.expires_at,
                       (SELECT q.reason FROM quarantine q
                        WHERE q.file_id = f.id
                        ORDER BY q.quarantined_at DESC LIMIT 1) AS scan_reason
                FROM files f
                WHERE f.label = ? ORDER BY f.added_at DESC
                """,
                (db_label,),
            )
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı", str(exc))
            return
        self._populate_table(rows)

    def _load_tag_files(self, tag_id: int) -> None:
        self._table.setRowCount(0)
        try:
            rows = DBManager().fetchall(
                """
                SELECT f.id, f.filename, f.label, f.size_bytes, f.added_at,
                       f.filepath, f.original_sha256, f.expires_at,
                       (SELECT q.reason FROM quarantine q
                        WHERE q.file_id = f.id
                        ORDER BY q.quarantined_at DESC LIMIT 1) AS scan_reason
                FROM files f
                INNER JOIN file_tags ft ON ft.file_id = f.id
                WHERE ft.tag_id = ?
                ORDER BY f.added_at DESC
                """,
                (tag_id,),
            )
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı", str(exc))
            return
        self._populate_table(rows)

    def _refresh_tag_sidebar(self) -> None:
        while self._tag_container_layout.count():
            item = self._tag_container_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        self._tag_btns.clear()
        if self._active_tag_btn is not None:
            self._active_tag_btn = None

        try:
            tags = DBManager().fetchall(
                "SELECT id, name, color FROM tags ORDER BY name"
            )
        except Exception:
            return

        if not tags:
            empty = QLabel("  Henüz etiket yok")
            empty.setStyleSheet(
                f"color:{self._T['subtext']}; font-size:11px; padding:4px 8px;"
                "background:transparent;"
            )
            self._tag_container_layout.addWidget(empty)
            return

        for tag in tags:
            tag_id = tag["id"]
            name   = tag["name"]
            color  = tag["color"]
            is_active = (tag_id == self._current_tag_id)

            btn = QPushButton(f"  ·  {name}")
            btn.setFixedHeight(36)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setProperty("tag_color", color)
            btn.setStyleSheet(self._tag_btn_style(color=color, active=is_active))
            btn.clicked.connect(
                lambda checked=False, tid=tag_id, tname=name, tc=color, b=btn:
                self._on_tag_click(tid, tname, tc, b)
            )
            self._tag_btns[tag_id] = btn
            if is_active:
                self._active_tag_btn = btn
            self._tag_container_layout.addWidget(btn)

    def _on_tag_click(
        self, tag_id: int, tag_name: str, tag_color: str, btn: QPushButton
    ) -> None:
        if self._active_btn is not None:
            self._active_btn.setStyleSheet(self._nav_btn_style(active=False))
            self._active_btn = None

        if self._active_tag_btn is not None and self._active_tag_btn is not btn:
            prev_color = self._active_tag_btn.property("tag_color") or self._T["accent"]
            self._active_tag_btn.setStyleSheet(
                self._tag_btn_style(color=prev_color, active=False)
            )

        self._active_tag_btn = btn
        btn.setStyleSheet(self._tag_btn_style(color=tag_color, active=True))

        self._current_label  = ""
        self._current_tag_id = tag_id
        self._page_title.setText(f"# {tag_name}")

        self._search_bar.blockSignals(True)
        self._search_bar.clear()
        self._search_bar.blockSignals(False)

        self._expiry_banner.setVisible(False)
        self._table.horizontalHeaderItem(3).setText("Tarih")
        self._load_tag_files(tag_id)

    def _search_files(self, term: str) -> None:
        term = term.strip()
        if not term:
            if self._current_tag_id is not None:
                self._load_tag_files(self._current_tag_id)
            else:
                self._load_label(self._current_label)
            return
        self._table.setRowCount(0)
        try:
            like = f"%{term}%"
            rows = DBManager().fetchall(
                """
                SELECT f.id, f.filename, f.label, f.size_bytes, f.added_at,
                       f.filepath, f.original_sha256, f.expires_at,
                       (SELECT q.reason FROM quarantine q
                        WHERE q.file_id = f.id
                        ORDER BY q.quarantined_at DESC LIMIT 1) AS scan_reason
                FROM files f
                WHERE f.filename LIKE ? OR f.original_sha256 LIKE ?
                   OR f.id IN (
                       SELECT ft.file_id FROM file_tags ft
                       INNER JOIN tags t ON t.id = ft.tag_id
                       WHERE t.name LIKE ?
                   )
                ORDER BY f.added_at DESC
                """,
                (like, like, like),
            )
        except Exception as exc:
            QMessageBox.warning(self, "Arama", str(exc))
            return
        self._populate_table(rows)

    def _populate_table(self, rows: list) -> None:
        for row in rows:
            verdict, mock = "", False
            if row["scan_reason"]:
                try:
                    d       = json.loads(row["scan_reason"])
                    verdict = d.get("verdict", "")
                    mock    = d.get("mock", False)
                except Exception:
                    pass
            self._insert_row(
                row["filename"],
                row["label"],
                self._fmt_size(row["size_bytes"] or 0),
                (row["added_at"] or "")[:10],
                scan_verdict=verdict,
                scan_mock=mock,
                file_id=row["id"],
                sha256=row["original_sha256"],
                filepath=row["filepath"] or "",
                expires_at=row["expires_at"] or "",
            )

    # ── Drag & drop ───────────────────────────────────────────────────────

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event: QDragMoveEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        for url in event.mimeData().urls():
            local = url.toLocalFile()
            if local:
                self._handle_dropped_file(Path(local))

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._overlay.resize(self.size())

    def _handle_dropped_file(self, src: Path) -> None:
        _log.info("drop_received  file=%s  exists=%s  size=%s",
                  src.name,
                  src.exists(),
                  src.stat().st_size if src.exists() else "—")
        if not src.is_file():
            _log.warning("drop_ignored   not a file: %s", src)
            return

        live_hwid = get_usb_hwid()
        _log.info("drop_hwid      live=%s  session=%s  match=%s",
                  live_hwid, self._hwid, live_hwid == self._hwid)
        if live_hwid is None:
            QMessageBox.warning(
                self, "USB Bulunamadı",
                "Yetkili USB cihazı takılı değil.\nDosya karantinaya alınamaz.",
            )
            self._refresh_usb_badge()
            return

        try:
            hcl_path, sha256_hex = encrypt_file(src, self._key, user_id=1, hwid=live_hwid)  # TODO: oturum user_id
        except AuthenticationError as exc:
            QMessageBox.critical(self, "Bütünlük Hatası", str(exc))
            return
        except Exception as exc:
            QMessageBox.critical(self, "Şifreleme Hatası", str(exc))
            return

        expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=24)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        today      = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        size_bytes = src.stat().st_size

        try:
            db = DBManager()
            db.execute(
                """
                INSERT INTO files (filename, filepath, label, size_bytes, expires_at, original_sha256)
                VALUES (?, ?, 'Karantina', ?, ?, ?)
                ON CONFLICT(filepath) DO UPDATE SET
                    filename        = excluded.filename,
                    label           = 'Karantina',
                    size_bytes      = excluded.size_bytes,
                    expires_at      = excluded.expires_at,
                    original_sha256 = excluded.original_sha256
                """,
                (src.name, str(hcl_path), size_bytes, expires_at, sha256_hex),
            )
            row_id = db.fetchone(
                "SELECT id FROM files WHERE filepath = ?", (str(hcl_path),)
            )
            if row_id is None:
                raise RuntimeError(f"files kaydı bulunamadı: {hcl_path}")
            file_id = row_id["id"]
            _log.info("drop_db_insert  file_id=%d  filepath=%s", file_id, hcl_path.name)
            db.log(
                "file_quarantined",
                target_type="file",
                target_id=file_id,
                detail=f"hwid={live_hwid} hcl={hcl_path.name}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        self._insert_row(
            src.name, "Karantina", self._fmt_size(size_bytes), today,
            file_id=file_id,
            sha256=sha256_hex,
            filepath=str(hcl_path),
        )
        scan_row = self._table.rowCount() - 1
        self._table.scrollToBottom()
        self._start_scan(src, file_id, scan_row)

    # ── USB kilit ─────────────────────────────────────────────────────────

    def _poll_usb(self) -> None:
        if self._authenticating:
            return
        hwid = get_usb_hwid()
        self._refresh_usb_badge()
        if hwid is None:
            if not self._locked:
                self._lock()
        elif hwid == self._hwid:
            if self._locked:
                self._unlock()
        else:
            self._trigger_usb_reauth(hwid)

    def _trigger_usb_reauth(self, new_hwid: str) -> None:
        """Farklı HWID tespit edilince 3-katman doğrulama + vault rol okuma."""
        self._authenticating = True
        self._lock()

        try:
            authenticate_usb(new_hwid)
        except USBAuthError as exc:
            QMessageBox.warning(self, "USB Reddedildi",
                                f"Yeni USB kimlik doğrulaması başarısız:\n\n{exc}")
            self._authenticating = False
            return
        except Exception as exc:
            QMessageBox.critical(self, "Kimlik Doğrulama Hatası", str(exc))
            self._authenticating = False
            return

        pin, ok = QInputDialog.getText(
            self, "USB Değişti — Yeniden Giriş",
            "USB doğrulandı.\nVault PIN'ini girin:", QLineEdit.Password,
        )
        if not ok or not pin.strip():
            QMessageBox.information(self, "Oturum Kilitli",
                                    "PIN girilmedi — oturum kilitli kaldı.")
            self._authenticating = False
            return

        try:
            new_role = read_vault_role(new_hwid, pin.strip())
        except ValueError as exc:
            QMessageBox.warning(self, "PIN Hatalı", str(exc))
            self._authenticating = False
            return
        except VaultTamperedError as exc:
            QMessageBox.critical(self, "Vault Hatası", str(exc))
            self._authenticating = False
            return
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))
            self._authenticating = False
            return

        prev_hwid  = self._hwid
        self._hwid = new_hwid
        self._role = new_role
        self._apply_role_restrictions()
        self._apply_theme()
        self._unlock()
        self._authenticating = False

        QMessageBox.information(
            self, "USB Oturumu Açıldı",
            f"Yeni USB oturumu başarıyla açıldı.\n\n"
            f"Önceki HWID : {prev_hwid[:16]}...\n"
            f"Yeni HWID   : {new_hwid[:16]}...\n"
            f"Rol         : {new_role}",
        )

    def _lock(self) -> None:
        self._locked = True
        self.centralWidget().setGraphicsEffect(self._blur)
        self._overlay.resize(self.size())
        self._overlay.show()
        self._overlay.raise_()

    def _unlock(self) -> None:
        self._locked = False
        self.centralWidget().setGraphicsEffect(None)
        self._overlay.hide()

    # ── Yardımcılar ───────────────────────────────────────────────────────

    def _insert_row(
        self, name: str, label: str, size: str, date: str,
        scan_verdict: str = "", scan_mock: bool = False,
        file_id: int | None = None,
        sha256: str | None = None,
        filepath: str = "",
        expires_at: str = "",
    ) -> None:
        row    = self._table.rowCount()
        is_hcl = filepath.endswith(".hcl")
        self._table.insertRow(row)

        # Sütun 0 — dosya adı (şifreli dosyalarda kilit ikonu)
        display_name = ("🔒  " + name) if is_hcl else name
        name_item    = QTableWidgetItem(display_name)
        name_item.setData(Qt.UserRole,     file_id)    # int | None
        name_item.setData(Qt.UserRole + 1, sha256)     # str | None
        name_item.setData(Qt.UserRole + 2, label)      # str
        name_item.setData(Qt.UserRole + 3, filepath)   # str
        name_item.setData(Qt.UserRole + 4, expires_at) # str (ISO-8601 UTC)
        if is_hcl:
            name_item.setBackground(QColor(self._T["hcl_bg"]))
            name_item.setForeground(QColor(self._T["hcl_fg"]))
        self._table.setItem(row, 0, name_item)

        # Sütun 1 — etiket (renk kodlu)
        pk        = _LABEL_PILL.get(label, ("text", ""))
        fg_color  = self._T.get(pk[0], self._T["text"])
        label_item = QTableWidgetItem(label)
        label_item.setForeground(QColor(fg_color))
        label_item.setTextAlignment(Qt.AlignCenter)
        if is_hcl:
            label_item.setBackground(QColor(self._T["hcl_bg"]))
        self._table.setItem(row, 1, label_item)

        # Sütunlar 2-3 — boyut, tarih
        size_item = QTableWidgetItem(size)
        date_item = QTableWidgetItem(date)
        if is_hcl:
            size_item.setBackground(QColor(self._T["hcl_bg"]))
            date_item.setBackground(QColor(self._T["hcl_bg"]))
        self._table.setItem(row, 2, size_item)
        self._table.setItem(row, 3, date_item)

        # Sütun 4 — tarama sonucu
        if scan_verdict:
            text, color = _VERDICT_BADGE.get(scan_verdict, ("? Bilinmiyor", "#6b7280"))
            if scan_mock:
                text, color = text + " (m)", "#6b7280"
            self._set_scan_badge(row, text, color)

    def _start_scan(self, path: Path, file_id: int, row: int) -> None:
        _log.info("scan_start  file=%s  file_id=%d  row=%d  active=%d",
                  path.name, file_id, row, len(self._threads))
        self._set_scan_badge(row, "⟳ Taranıyor...", "#6b7280")

        worker = _ScanWorker(path, file_id, row)
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_scan_done)
        worker.finished.connect(thread.quit)
        worker.finished.connect(
            lambda w=worker: self._workers.remove(w) if w in self._workers else None
        )
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(
            lambda t=thread: self._threads.remove(t) if t in self._threads else None
        )
        self._workers.append(worker)
        self._threads.append(thread)
        QTimer.singleShot(0, thread.start)
        _log.info("scan_queued  file=%s  thread_id=%s", path.name, id(thread))

    def _on_scan_done(self, row: int, result: ScanResult) -> None:
        text, color = _VERDICT_BADGE.get(result.verdict, ("? Bilinmiyor", "#6b7280"))
        if result.mock:
            text, color = text + " (m)", "#6b7280"
        self._set_scan_badge(row, text, color)

    # ── Context menu ──────────────────────────────────────────────────────

    def _on_context_menu(self, pos: QPoint) -> None:
        row = self._table.rowAt(pos.y())
        if row < 0:
            return
        name_item = self._table.item(row, 0)
        if name_item is None:
            return
        label: str = name_item.data(Qt.UserRole + 2) or ""

        file_id:  int | None = name_item.data(Qt.UserRole)
        sha256:   str | None = name_item.data(Qt.UserRole + 1)
        filepath: str | None = name_item.data(Qt.UserRole + 3)

        T          = self._T
        menu_style = (
            f"QMenu{{background:{T['bg2']};color:{T['text']};"
            f"border:1px solid {T['border']};border-radius:8px;padding:4px 0;}}"
            f"QMenu::item{{padding:9px 22px;font-size:13px;}}"
            f"QMenu::item:selected{{background:{T['accent_dim']};color:{T['text']};"
            f"border-radius:4px;}}"
            f"QMenu::separator{{height:1px;background:{T['border']};margin:4px 10px;}}"
        )

        menu     = QMenu(self)
        menu.setStyleSheet(menu_style)
        act_tags = menu.addAction("🏷  Etiket Ata")

        act_scan = act_download = act_approve = act_reject = None
        if label == "Karantina":
            menu.addSeparator()
            act_scan     = menu.addAction("🔍  Tara")
            act_download = menu.addAction("⬇  İndir")
            menu.addSeparator()
            act_approve  = menu.addAction("Onayla  →  Genel'e taşı")
            act_reject   = menu.addAction("Reddet  →  İmha Odası'na taşı")

        action = menu.exec(self._table.viewport().mapToGlobal(pos))

        if action == act_tags:
            self._on_ctx_assign_tags(file_id)
        elif action == act_scan:
            self._on_ctx_scan(row, file_id, filepath)
        elif action == act_download:
            self._on_ctx_download(file_id, filepath)
        elif action == act_approve:
            self._on_ctx_move_label(row, file_id, "Genel")
        elif action == act_reject:
            self._on_ctx_move_label(row, file_id, "Imha")

    def _on_ctx_download(
        self, file_id: int | None, filepath: str | None
    ) -> None:
        if not filepath:
            QMessageBox.warning(self, "İndir", "Dosya yolu bulunamadı.")
            return

        # ── TOTP gizli anahtarını oku ──────────────────────────────────────
        try:
            secret = json.loads(_TOTP_FILE.read_text(encoding="utf-8"))["secret"]
        except Exception:
            QMessageBox.critical(self, "İndir", "TOTP anahtarı okunamadı.")
            return

        # ── TOTP kodu sor ─────────────────────────────────────────────────
        code, ok = QInputDialog.getText(
            self,
            "Kimlik Doğrulama",
            "Authenticator kodunu girin (6 hane):",
        )
        if not ok:
            return

        code = code.strip()
        totp_ok = (
            code.isdigit()
            and len(code) == 6
            and pyotp.TOTP(secret).verify(code, valid_window=1)
        )

        db = DBManager()

        if not totp_ok:
            db.log(
                "download_totp_failed",
                target_type="file",
                target_id=file_id,
                detail=f"hwid={self._hwid} filepath={filepath}",
            )
            QMessageBox.warning(
                self, "Erişim Reddedildi",
                "Authenticator kodu geçersiz.\nDosya indirilmedi.",
            )
            return

        # ── Şifre çöz ─────────────────────────────────────────────────────
        try:
            content, meta = decrypt_file(filepath, self._key)
        except AuthenticationError:
            QMessageBox.critical(
                self, "Bütünlük Hatası",
                "Dosya bütünlüğü doğrulanamadı — dosya değiştirilmiş olabilir.",
            )
            return
        except Exception as exc:
            QMessageBox.critical(self, "Şifre Çözme Hatası", str(exc))
            return

        # ── Kayıt yeri seç ────────────────────────────────────────────────
        original_name: str = meta.get("filename", Path(filepath).stem)
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Dosyayı Kaydet",
            original_name,
        )

        if not save_path:
            del content
            return

        try:
            Path(save_path).write_bytes(content)
        except Exception as exc:
            QMessageBox.critical(self, "Kaydetme Hatası", str(exc))
            return
        finally:
            del content

        db.log(
            "file_downloaded",
            target_type="file",
            target_id=file_id,
            detail=f"hwid={self._hwid} dest={save_path}",
        )
        QMessageBox.information(
            self, "İndir",
            f"Dosya başarıyla kaydedildi:\n{save_path}",
        )

    def _on_ctx_assign_tags(self, file_id: int | None) -> None:
        if file_id is None:
            QMessageBox.warning(self, "Etiket", "Dosya kimliği bulunamadı.")
            return
        from UI.TagDialog import TagDialog
        dlg = TagDialog(file_id=file_id, parent=self)
        if dlg.exec() == TagDialog.Accepted:
            self._refresh_tag_sidebar()
            if self._current_tag_id is not None:
                self._load_tag_files(self._current_tag_id)

    def _on_ctx_scan(
        self, row: int, file_id: int | None, filepath: str | None
    ) -> None:
        if not filepath:
            QMessageBox.warning(self, "Tarama", "Dosya yolu bulunamadı.")
            return
        path = Path(filepath)
        if not path.exists():
            QMessageBox.warning(self, "Tarama", f"Dosya bulunamadı:\n{filepath}")
            return

        self._set_scan_badge(row, "⟳ Taranıyor...", "#6b7280")

        worker = _ScanWorker(path, file_id or 0, row)
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(
            lambda r, res, fid=file_id: self._on_ctx_scan_done(r, res, fid)  # type: ignore[arg-type]
        )
        worker.finished.connect(thread.quit)
        worker.finished.connect(
            lambda w=worker: self._workers.remove(w) if w in self._workers else None
        )
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(
            lambda t=thread: self._threads.remove(t) if t in self._threads else None
        )
        self._workers.append(worker)
        self._threads.append(thread)
        QTimer.singleShot(0, thread.start)

    def _on_ctx_scan_done(
        self, row: int, result: ScanResult, file_id: int | None
    ) -> None:
        text, color = _VERDICT_BADGE.get(result.verdict, ("? Bilinmiyor", "#6b7280"))
        if result.mock:
            text, color = text + " (m)", "#6b7280"
        self._set_scan_badge(row, text, color)

        if result.verdict == "malicious":
            QMessageBox.warning(
                self, "Zararlı Dosya",
                "Tarama zararlı içerik tespit etti.\n"
                "Dosya otomatik olarak İmha Odası'na taşınıyor.",
            )
            self._on_ctx_move_label(row, file_id, "Imha", auto=True)

    def _on_ctx_move_label(
        self, row: int, file_id: int | None, new_label: str, *, auto: bool = False,
    ) -> None:
        if file_id is None:
            QMessageBox.warning(self, "Taşıma Hatası", "Dosya kimliği bulunamadı.")
            return

        label_display = "Genel" if new_label == "Genel" else "İmha Odası"

        if not auto:
            fname_item = self._table.item(row, 0)
            fname      = fname_item.text() if fname_item else "?"
            confirm    = QMessageBox.question(
                self, "Dosyayı Taşı",
                f"'{fname}'\n\nKarantina → {label_display}\n\nDevam edilsin mi?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if confirm != QMessageBox.Yes:
                return

        try:
            db = DBManager()
            db.execute("UPDATE files SET label = ? WHERE id = ?", (new_label, file_id))
            db.log(
                "file_label_changed",
                target_type="file",
                target_id=file_id,
                detail=f"hwid={self._hwid} from=Karantina to={new_label} auto={auto}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return

        self._table.removeRow(row)
        if not auto:
            QMessageBox.information(self, "Taşındı",
                                    f"Dosya '{label_display}' etiketine taşındı.")

    def _set_scan_badge(self, row: int, text: str, color: str) -> None:
        if row >= self._table.rowCount():
            return
        item = QTableWidgetItem(text)
        item.setForeground(QColor(color))
        item.setTextAlignment(Qt.AlignCenter)
        self._table.setItem(row, 4, item)

    # ── İmha Odası sayacı ─────────────────────────────────────────────────

    def _tick_expiry(self) -> None:
        """Her saniye çalışır: İmha Odası'ndaki satırların kalan süresini günceller."""
        if self._current_label != "Imha":
            return

        now = datetime.now(timezone.utc)
        expired_rows: list[tuple[int, int | None, str]] = []  # (row, file_id, filepath)
        min_remaining: float | None = None

        for row in range(self._table.rowCount()):
            name_item = self._table.item(row, 0)
            if name_item is None:
                continue

            expires_str: str = name_item.data(Qt.UserRole + 4) or ""
            file_id: int | None = name_item.data(Qt.UserRole)
            filepath: str = name_item.data(Qt.UserRole + 3) or ""

            if not expires_str:
                countdown_item = self._table.item(row, 3)
                if countdown_item:
                    countdown_item.setText("—")
                continue

            try:
                expires_dt = datetime.strptime(
                    expires_str, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

            remaining = (expires_dt - now).total_seconds()

            if remaining <= 0:
                expired_rows.append((row, file_id, filepath))
                continue

            # HH:MM:SS
            total_secs  = int(remaining)
            hrs, rest   = divmod(total_secs, 3600)
            mins, secs  = divmod(rest, 60)
            text = f"{hrs:02d}:{mins:02d}:{secs:02d}"

            if remaining < 600:          # < 10 dakika — kırmızı
                color = self._T["red"]
            elif remaining < 3600:       # < 1 saat — sarı
                color = self._T["yellow"]
            else:                        # > 1 saat — yeşil
                color = self._T["green"]

            countdown_item = self._table.item(row, 3)
            if countdown_item:
                countdown_item.setText(text)
                countdown_item.setForeground(QColor(color))

            if min_remaining is None or remaining < min_remaining:
                min_remaining = remaining

        # Süresi dolan satırları ters sırayla kaldır (indeks kaymaması için)
        for row, file_id, filepath in sorted(expired_rows, key=lambda t: t[0], reverse=True):
            self._table.removeRow(row)
            self._purge_expired_file(file_id, filepath)

        # Üst banner güncelle
        if min_remaining is not None:
            total_secs  = int(min_remaining)
            hrs, rest   = divmod(total_secs, 3600)
            mins, secs  = divmod(rest, 60)
            color = (
                self._T["red"]    if min_remaining < 600  else
                self._T["yellow"] if min_remaining < 3600 else
                self._T["green"]
            )
            self._expiry_banner.setText(
                f"⏱  En yakın imha: {hrs:02d}:{mins:02d}:{secs:02d}"
            )
            self._expiry_banner.setStyleSheet(
                f"color:{color}; font-size:13px; font-weight:600;"
                f"background:{self._T['bg3']}; border-radius:8px;"
                f"padding:4px 12px;"
            )
        elif self._table.rowCount() == 0:
            self._expiry_banner.setText("İmha Odası boş")
            self._expiry_banner.setStyleSheet(
                f"color:{self._T['subtext']}; font-size:13px;"
                f"background:{self._T['bg3']}; border-radius:8px;"
                f"padding:4px 12px;"
            )
        else:
            self._expiry_banner.setText("Süre belirlenmemiş dosyalar")
            self._expiry_banner.setStyleSheet(
                f"color:{self._T['subtext']}; font-size:13px;"
                f"background:{self._T['bg3']}; border-radius:8px;"
                f"padding:4px 12px;"
            )

    def _purge_expired_file(self, file_id: int | None, filepath: str) -> None:
        """Süresi dolan İmha Odası dosyasını diskten ve DB'den siler."""
        if filepath:
            try:
                p = Path(filepath)
                if p.exists():
                    p.unlink()
            except Exception:
                pass
        if file_id is not None:
            try:
                db = DBManager()
                db.execute("DELETE FROM files WHERE id = ?", (file_id,))
                db.log(
                    "expired_purge",
                    target_type="file",
                    target_id=file_id,
                    detail=f"label=Imha filepath={filepath}",
                )
            except Exception:
                pass

    def _refresh_usb_badge(self) -> None:
        hwid = get_usb_hwid()
        if hwid:
            self._usb_badge.setText(f"USB: {hwid[:12]}")
            self._usb_badge.setStyleSheet(
                f"color:{self._T['green']}; font-size:11px; padding:4px 8px;"
                f"border:1px solid {self._T['green']}; border-radius:8px;"
                f"background:transparent;"
            )
        else:
            self._usb_badge.setText("USB Yok")
            self._usb_badge.setStyleSheet(
                f"color:{self._T['red']}; font-size:11px; padding:4px 8px;"
                f"border:1px solid {self._T['red']}; border-radius:8px;"
                f"background:transparent;"
            )

    @staticmethod
    def _fmt_size(size_bytes: int) -> str:
        size: float = float(size_bytes)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
