import json
import logging
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

_log = logging.getLogger("hycleus.ui")

from PySide6.QtCore import QObject, QPoint, QRunnable, QSize, QThread, QThreadPool, Qt, QTimer, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QDragEnterEvent,
    QDragMoveEvent,
    QDropEvent,
    QIcon,
    QPaintEvent,
    QPainter,
    QPixmap,
    QResizeEvent,
)
from PySide6.QtWidgets import (
    QApplication,
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
    QProgressDialog,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

import pyotp

from CORE.crypto import AuthenticationError, decrypt_file, encrypt_file
from CORE.scanner import ScanResult, scan_file
from CORE.usb_manager import DEV_MODE as _DEV_MODE, get_usb_hwid
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

from CORE.paths import data_dir as _data_dir
_TOTP_FILE = _data_dir() / "totp_secret.json"

# ── Renk paletleri ────────────────────────────────────────────────────────────
_DARK: dict[str, str] = {
    "bg":        "#1C1C1E",
    "sidebar":   "#1C1C1E",
    "topbar":    "#2C2C2E",
    "accent":    "#2563EB",
    "text":      "#F9FAFB",
    "subtext":   "#9CA3AF",
    "nav_text":  "#D1D5DB",
    "border":    "#3A3A3C",
    "hover":     "#2C2C2E",
    "search_bg": "#2C2C2E",
    "row_hover": "#2C2C2E",
    "green":     "#059669",
    "red":       "#DC2626",
    "yellow":    "#D97706",
    "gray":      "#6B7280",
    "purple":    "#2563EB",
    "hcl_fg":    "#2563EB",
}
_LIGHT: dict[str, str] = {
    "bg":        "#F9FAFB",
    "sidebar":   "#FFFFFF",
    "topbar":    "#FFFFFF",
    "accent":    "#2563EB",
    "text":      "#111827",
    "subtext":   "#9CA3AF",
    "nav_text":  "#374151",
    "border":    "#E5E7EB",
    "hover":     "#F3F4F6",
    "search_bg": "#F3F4F6",
    "row_hover": "#F0F9FF",
    "green":     "#059669",
    "red":       "#DC2626",
    "yellow":    "#D97706",
    "gray":      "#6B7280",
    "purple":    "#2563EB",
    "hcl_fg":    "#2563EB",
}

_SIDEBAR_NAV: list[tuple[str, str, str]] = [
    ("📁", "Genel",      "Genel"),
    ("🛡", "Kritik",     "Kritik"),
    ("🕐", "Karantina",  "Karantina"),
    ("🗑", "İmha Odası", "Imha"),
]

_ROLE_BADGE: dict[str, tuple[str, str]] = {
    "Yönetici":    ("#DBEAFE", "#2563EB"),
    "Standart":    ("#D1FAE5", "#059669"),
    "Salt Okunur": ("#FEF3C7", "#D97706"),
}

_VERDICT_BADGE: dict[str, tuple[str, str]] = {
    "clean":      ("✓ Temiz",    "#059669"),
    "suspicious": ("⚠ Şüpheli", "#D97706"),
    "malicious":  ("✗ Zararlı",  "#DC2626"),
    "unknown":    ("—",          "#9CA3AF"),
}

_LABEL_PILL_STYLE: dict[str, tuple[str, str]] = {
    "Genel":     ("#059669", "#D1FAE5"),
    "Kritik":    ("#DC2626", "#FEE2E2"),
    "Karantina": ("#D97706", "#FEF3C7"),
    "Imha":      ("#6B7280", "#F3F4F6"),
}

_TAG_COLORS = ["#6366F1", "#EC4899", "#F59E0B", "#10B981", "#3B82F6", "#EF4444", "#8B5CF6"]


def _make_dot_pixmap(color: str, size: int = 8) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(QColor(color)))
    p.drawEllipse(0, 0, size, size)
    p.end()
    return pm


# ── Batch file-processing worker ─────────────────────────────────────────────

class _ProcessSignals(QObject):
    """Main-thread signal bridge for QRunnable workers."""
    file_done = Signal(object)   # dict result


class _FileRunnable(QRunnable):
    """Encrypt → DB insert → scan a single file in the thread pool."""

    def __init__(
        self,
        src: Path,
        key: bytes,
        hwid: str,
        label: str,
        folder_id: int | None,
        signals: _ProcessSignals,
        ttl_hours: int = 24,
        user_id: int = 1,
    ) -> None:
        super().__init__()
        self.setAutoDelete(True)
        self._src       = src
        self._key       = key
        self._hwid      = hwid
        self._label     = label
        self._folder_id = folder_id
        self._signals   = signals
        self._ttl_hours = ttl_hours
        self._user_id   = user_id

    def run(self) -> None:
        from datetime import datetime, timedelta, timezone as _tz
        result: dict = {
            "ok": False, "filename": self._src.name,
            "label": self._label, "folder_id": self._folder_id,
        }

        try:
            hcl_path, sha256_hex, aad_json = encrypt_file(
                self._src, self._key, user_id=self._user_id, hwid=self._hwid,
            )
        except Exception as exc:
            result["error"] = f"Şifreleme: {exc}"
            self._signals.file_done.emit(result)
            return

        expires_at = (
            datetime.now(_tz.utc) + timedelta(hours=self._ttl_hours)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        today      = datetime.now(_tz.utc).strftime("%Y-%m-%d")
        size_bytes = self._src.stat().st_size

        try:
            db = DBManager()
            db.execute(
                """
                INSERT INTO files
                    (filename, filepath, label, size_bytes, expires_at,
                     original_sha256, aad_metadata, folder_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(filepath) DO UPDATE SET
                    filename        = excluded.filename,
                    label           = excluded.label,
                    size_bytes      = excluded.size_bytes,
                    expires_at      = excluded.expires_at,
                    original_sha256 = excluded.original_sha256,
                    aad_metadata    = excluded.aad_metadata,
                    folder_id       = excluded.folder_id
                """,
                (self._src.name, str(hcl_path), self._label, size_bytes,
                 expires_at, sha256_hex, aad_json, self._folder_id),
            )
            row = db.fetchone("SELECT id FROM files WHERE filepath = ?", (str(hcl_path),))
            if row is None:
                raise RuntimeError(f"files kaydı bulunamadı: {hcl_path}")
            file_id = row["id"]
            db.log("file_added", target_type="file", target_id=file_id,
                   detail=f"label={self._label} hwid={self._hwid} hcl={hcl_path.name}")
        except Exception as exc:
            result["error"] = f"Veritabanı: {exc}"
            self._signals.file_done.emit(result)
            return

        verdict = ""
        mock    = False
        try:
            sr      = scan_file(hcl_path, file_id=file_id)
            verdict = sr.verdict
            mock    = sr.mock
        except Exception:
            pass

        result.update({
            "ok": True, "file_id": file_id,
            "filename": self._src.name, "label": self._label,
            "size_bytes": size_bytes, "date": today,
            "sha256": sha256_hex, "filepath": str(hcl_path),
            "expires_at": expires_at, "verdict": verdict, "mock": mock,
        })
        self._signals.file_done.emit(result)


# ── Scan worker ───────────────────────────────────────────────────────────────

class _ScanWorker(QObject):
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
        except Exception:
            _log.exception("worker_error  file=%s", self._path.name)
            from CORE.scanner import _mock, _sha256
            result = _mock(_sha256(self._path))
        self.finished.emit(self._row, result)


# ── Kilit overlay ─────────────────────────────────────────────────────────────

class _LockOverlay(QWidget):
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.hide()

        self._card = QFrame(self)
        self._card.setFixedSize(320, 200)
        self._card.setStyleSheet(
            "QFrame { background: #FFFFFF; border-radius: 16px; border: none; }"
        )

        lay = QVBoxLayout(self._card)
        lay.setAlignment(Qt.AlignCenter)
        lay.setContentsMargins(24, 20, 24, 24)
        lay.setSpacing(10)

        icon = QLabel("🔒")
        icon.setAlignment(Qt.AlignCenter)
        icon.setStyleSheet("font-size: 48px; background: transparent;")
        lay.addWidget(icon)

        title = QLabel("USB Token Çıkarıldı")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            "font-size: 18px; font-weight: 700; color: #111827; background: transparent;"
        )
        lay.addWidget(title)

        sub = QLabel("Lütfen USB'yi yeniden takın")
        sub.setAlignment(Qt.AlignCenter)
        sub.setStyleSheet("font-size: 14px; color: #6B7280; background: transparent;")
        lay.addWidget(sub)

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._card.move((self.width() - 320) // 2, (self.height() - 200) // 2)

    def paintEvent(self, event: QPaintEvent) -> None:
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(0, 0, 0, 204))  # 80% opacity


# ── Ana pencere ───────────────────────────────────────────────────────────────

class HycleusWindow(QMainWindow):
    def __init__(self, hwid: str, key: bytes, role: str = "Yönetici",
                 username: str = "Kullanıcı", user_id: int = 1):
        super().__init__()
        self._hwid               = hwid
        self._key                = key
        self._role               = role
        self._username           = username
        self._user_id            = user_id
        self._active_btn: QPushButton | None = None
        self._nav_btns: dict[str, QPushButton] = {}
        self._current_label: str = "Genel"
        self._locked             = False
        self._authenticating     = False
        self._threads: list[QThread]  = []
        self._workers: list[QObject]  = []
        self._dark: bool         = True

        self._pool = QThreadPool.globalInstance()
        self._pool.setMaxThreadCount(6)
        self._batch_total:      int  = 0
        self._batch_done:       int  = 0
        self._batch_errors:     int  = 0
        self._batch_has_folder: bool = False
        self._batch_signals = _ProcessSignals()
        self._batch_signals.file_done.connect(self._on_file_done)
        self._T: dict[str, str]  = _DARK.copy()
        self._current_tag_id: int | None            = None
        self._active_tag_btn: QPushButton | None    = None
        self._tag_btns: dict[int, QPushButton]      = {}
        self._current_folder_id: int | None         = None
        self._active_folder_btn: QPushButton | None = None
        self._folder_btns: dict[int, QPushButton]   = {}

        _log.info("window_init  hwid=%s  role=%s", hwid, role)

        self.setWindowTitle("HYCLEUS")
        self.setMinimumSize(1100, 700)
        self.setAcceptDrops(True)

        self._build_ui()
        self._apply_theme()

        self._blur    = QGraphicsBlurEffect(self)
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
        self._refresh_folder_sidebar()

    # ── UI kurulumu ───────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("central_root")
        self.setCentralWidget(central)

        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._make_top_bar())
        root.addWidget(self._make_action_bar())

        body = QWidget()
        body.setObjectName("body")
        body_h = QHBoxLayout(body)
        body_h.setContentsMargins(0, 0, 0, 0)
        body_h.setSpacing(0)
        body_h.addWidget(self._make_sidebar())
        body_h.addWidget(self._make_content(), 1)
        root.addWidget(body, 1)

    def _make_top_bar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("top_bar")
        bar.setFixedHeight(60)

        lay = QHBoxLayout(bar)
        lay.setContentsMargins(24, 0, 20, 0)
        lay.setSpacing(0)

        self._page_title = QLabel("Genel")
        self._page_title.setObjectName("page_title")
        lay.addWidget(self._page_title)

        lay.addStretch()

        self._theme_btn = QPushButton("☀")
        self._theme_btn.setObjectName("theme_btn")
        self._theme_btn.setFixedSize(36, 36)
        self._theme_btn.setCursor(Qt.PointingHandCursor)
        self._theme_btn.setToolTip("Gündüz / Gece")
        self._theme_btn.clicked.connect(self._toggle_theme)
        lay.addWidget(self._theme_btn)

        lay.addSpacing(12)

        self._avatar = QLabel(self._username[0].upper() if self._username else "?")
        self._avatar.setObjectName("avatar")
        self._avatar.setFixedSize(32, 32)
        self._avatar.setAlignment(Qt.AlignCenter)
        self._avatar.setCursor(Qt.PointingHandCursor)
        self._avatar.mousePressEvent = lambda _e: self._on_open_profile()
        lay.addWidget(self._avatar)

        return bar

    def _make_action_bar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("action_bar")
        bar.setFixedHeight(52)

        lay = QHBoxLayout(bar)
        lay.setContentsMargins(24, 0, 24, 0)
        lay.setSpacing(8)

        self._btn_add_file = QPushButton("Dosya Ekle")
        self._btn_add_file.setObjectName("btn_primary")
        self._btn_add_file.setFixedHeight(36)
        self._btn_add_file.setCursor(Qt.PointingHandCursor)
        self._btn_add_file.clicked.connect(self._on_add_file)
        lay.addWidget(self._btn_add_file)

        self._btn_add_folder = QPushButton("📁 Klasör Ekle")
        self._btn_add_folder.setObjectName("btn_secondary")
        self._btn_add_folder.setFixedHeight(36)
        self._btn_add_folder.setCursor(Qt.PointingHandCursor)
        self._btn_add_folder.clicked.connect(self._on_add_folder)
        lay.addWidget(self._btn_add_folder)

        self._btn_scan_all = QPushButton("Tümünü Tara")
        self._btn_scan_all.setObjectName("btn_secondary")
        self._btn_scan_all.setFixedHeight(36)
        self._btn_scan_all.setCursor(Qt.PointingHandCursor)
        self._btn_scan_all.clicked.connect(self._on_scan_all)
        lay.addWidget(self._btn_scan_all)

        self._btn_new_tag = QPushButton("Yeni Etiket")
        self._btn_new_tag.setObjectName("btn_secondary")
        self._btn_new_tag.setFixedHeight(36)
        self._btn_new_tag.setCursor(Qt.PointingHandCursor)
        self._btn_new_tag.clicked.connect(self._on_new_tag)
        lay.addWidget(self._btn_new_tag)

        lay.addStretch()

        self._btn_view = QPushButton("☰")
        self._btn_view.setObjectName("btn_secondary")
        self._btn_view.setFixedSize(36, 36)
        self._btn_view.setCursor(Qt.PointingHandCursor)
        self._btn_view.clicked.connect(self._on_hamburger_menu)
        lay.addWidget(self._btn_view)

        return bar

    def _make_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)

        lay = QVBoxLayout(sidebar)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── Sabit üst: logo + nav butonları ──────────────────────────────────
        logo = QLabel("HYCLEUS")
        logo.setObjectName("sidebar_logo")
        lay.addWidget(logo)

        sep = QFrame()
        sep.setObjectName("sidebar_sep")
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        lay.addWidget(sep)

        nav_lbl = QLabel("DOSYALAR")
        nav_lbl.setObjectName("nav_section_label")
        lay.addWidget(nav_lbl)

        for icon, display_name, db_label in _SIDEBAR_NAV:
            btn = QPushButton(f"   {icon}   {display_name}")
            btn.setFixedHeight(44)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setObjectName(f"nav_{db_label}")
            btn.clicked.connect(
                lambda checked=False, lbl=db_label, b=btn: self._on_sidebar_click(lbl, b)
            )
            self._nav_btns[db_label] = btn
            lay.addWidget(btn)

        # ── Scroll alanı: klasörler + etiketler ──────────────────────────────
        scroll = QScrollArea()
        scroll.setObjectName("sidebar_scroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        _scroll_content = QWidget()
        _scroll_content.setObjectName("sidebar_scroll_content")
        _scl = QVBoxLayout(_scroll_content)
        _scl.setContentsMargins(0, 0, 0, 0)
        _scl.setSpacing(0)

        self._folder_container = QWidget()
        self._folder_container.setStyleSheet("background: transparent;")
        self._folder_container_layout = QVBoxLayout(self._folder_container)
        self._folder_container_layout.setContentsMargins(0, 0, 0, 0)
        self._folder_container_layout.setSpacing(1)
        _scl.addWidget(self._folder_container)

        self._btn_new_folder = QPushButton("   ＋  Klasör Ekle")
        self._btn_new_folder.setFixedHeight(32)
        self._btn_new_folder.setCursor(Qt.PointingHandCursor)
        self._btn_new_folder.setObjectName("admin_btn")
        self._btn_new_folder.clicked.connect(self._on_create_folder)
        _scl.addWidget(self._btn_new_folder)

        _scl.addSpacing(8)

        tag_lbl = QLabel("ETİKETLER")
        tag_lbl.setObjectName("nav_section_label")
        _scl.addWidget(tag_lbl)

        self._tag_container = QWidget()
        self._tag_container.setStyleSheet("background: transparent;")
        self._tag_container_layout = QVBoxLayout(self._tag_container)
        self._tag_container_layout.setContentsMargins(0, 0, 0, 0)
        self._tag_container_layout.setSpacing(1)
        _scl.addWidget(self._tag_container)

        _scl.addStretch()

        scroll.setWidget(_scroll_content)
        lay.addWidget(scroll, 1)   # stretch=1 → ortayı doldurur

        # ── Sabit alt: yönetici + badge'ler ──────────────────────────────────
        self._admin_sep = QFrame()
        self._admin_sep.setObjectName("sidebar_sep")
        self._admin_sep.setFrameShape(QFrame.HLine)
        self._admin_sep.setFixedHeight(1)
        lay.addWidget(self._admin_sep)

        self._admin_label = QLabel("YÖNETİCİ")
        self._admin_label.setObjectName("nav_section_label")
        lay.addWidget(self._admin_label)

        self._blacklist_btn = QPushButton("  🚫  Kara Listeye Al")
        self._blacklist_btn.setObjectName("admin_btn")
        self._blacklist_btn.setFixedHeight(40)
        self._blacklist_btn.setCursor(Qt.PointingHandCursor)
        self._blacklist_btn.clicked.connect(self._on_blacklist_usb)
        lay.addWidget(self._blacklist_btn)

        self._audit_log_btn = QPushButton("  📋  Denetim Günlüğü")
        self._audit_log_btn.setObjectName("admin_btn")
        self._audit_log_btn.setFixedHeight(40)
        self._audit_log_btn.setCursor(Qt.PointingHandCursor)
        self._audit_log_btn.clicked.connect(self._on_open_audit_log)
        lay.addWidget(self._audit_log_btn)

        self._admin_panel_btn = QPushButton("  🔌  USB Yönetimi")
        self._admin_panel_btn.setObjectName("admin_btn")
        self._admin_panel_btn.setFixedHeight(40)
        self._admin_panel_btn.setCursor(Qt.PointingHandCursor)
        self._admin_panel_btn.clicked.connect(self._on_open_admin_panel)
        lay.addWidget(self._admin_panel_btn)

        self._support_btn = QPushButton("  💬  Destek")
        self._support_btn.setObjectName("admin_btn")
        self._support_btn.setFixedHeight(40)
        self._support_btn.setCursor(Qt.PointingHandCursor)
        self._support_btn.clicked.connect(self._on_open_contact)
        lay.addWidget(self._support_btn)

        self._role_badge = QLabel(self._role)
        self._role_badge.setObjectName("role_badge")
        self._role_badge.setAlignment(Qt.AlignCenter)
        lay.addWidget(self._role_badge)

        self._usb_badge = QLabel()
        self._usb_badge.setObjectName("usb_badge")
        self._usb_badge.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self._usb_badge.setTextFormat(Qt.RichText)
        lay.addWidget(self._usb_badge)

        return sidebar

    def _make_content(self) -> QWidget:
        frame = QWidget()
        frame.setObjectName("content")

        lay = QVBoxLayout(frame)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # Arama çubuğu
        search_container = QWidget()
        search_container.setObjectName("search_container")
        search_container.setFixedHeight(44)
        sch = QHBoxLayout(search_container)
        sch.setContentsMargins(16, 0, 16, 0)
        sch.setSpacing(8)

        search_icon = QLabel("🔍")
        search_icon.setObjectName("search_icon")
        sch.addWidget(search_icon)

        self._search_bar = QLineEdit()
        self._search_bar.setObjectName("search_bar")
        self._search_bar.setPlaceholderText("Dosya adı, SHA-256 veya etiket ile ara...")
        self._search_bar.textChanged.connect(self._search_files)
        sch.addWidget(self._search_bar)

        lay.addWidget(search_container)

        # İlerleme banner (batch upload)
        self._progress_banner = QLabel()
        self._progress_banner.setObjectName("progress_banner")
        self._progress_banner.setAlignment(Qt.AlignCenter)
        self._progress_banner.setFixedHeight(32)
        self._progress_banner.setVisible(False)
        lay.addWidget(self._progress_banner)

        # İmha banner
        self._expiry_banner = QLabel()
        self._expiry_banner.setObjectName("expiry_banner")
        self._expiry_banner.setAlignment(Qt.AlignCenter)
        self._expiry_banner.setFixedHeight(32)
        self._expiry_banner.setVisible(False)
        lay.addWidget(self._expiry_banner)

        # Tablo
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Dosya Adı", "Etiket", "Boyut", "Tarih", "Tarama"])
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.Fixed)
        hdr.setSectionResizeMode(2, QHeaderView.Fixed)
        hdr.setSectionResizeMode(3, QHeaderView.Fixed)
        hdr.setSectionResizeMode(4, QHeaderView.Fixed)
        self._table.setColumnWidth(1, 100)
        self._table.setColumnWidth(2, 80)
        self._table.setColumnWidth(3, 100)
        self._table.setColumnWidth(4, 120)
        hdr.setFixedHeight(36)
        self._table.verticalHeader().setDefaultSectionSize(48)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setSelectionMode(QTableWidget.ExtendedSelection)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)
        lay.addWidget(self._table, 1)

        # Drag-drop alanı
        self._drop_hint = QLabel("Dosyaları buraya sürükleyin — otomatik karantinaya alınır")
        self._drop_hint.setObjectName("drop_hint")
        self._drop_hint.setAlignment(Qt.AlignCenter)
        self._drop_hint.setFixedHeight(64)
        lay.addWidget(self._drop_hint)

        return frame

    # ── Tema ──────────────────────────────────────────────────────────────────

    def _toggle_theme(self) -> None:
        self._dark = not self._dark
        self._T = _DARK.copy() if self._dark else _LIGHT.copy()
        self._apply_theme()
        self._reset_drop_hint_style()
        if self._current_tag_id is not None:
            self._load_tag_files(self._current_tag_id)
        else:
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
                "QPushButton {"
                " background: #EFF6FF; color: #2563EB;"
                " border: none; border-left: 3px solid #2563EB;"
                " border-radius: 8px; height: 44px;"
                " padding: 0 20px 0 17px; text-align: left;"
                " font-size: 14px; font-weight: 600; margin: 2px 12px;"
                "}"
                "QPushButton:hover { background: #DBEAFE; }"
            )
        return (
            f"QPushButton {{"
            f" background: transparent; color: {T['nav_text']};"
            f" border: none; border-left: 3px solid transparent;"
            f" border-radius: 8px; height: 44px;"
            f" padding: 0 20px; text-align: left;"
            f" font-size: 14px; margin: 2px 12px;"
            f"}}"
            f"QPushButton:hover {{ background: {T['hover']}; }}"
        )

    def _tag_btn_style(self, *, color: str, active: bool) -> str:
        T = self._T
        if active:
            return (
                f"QPushButton {{"
                f" background: #EFF6FF; color: {color};"
                f" border: none; border-left: 3px solid {color};"
                f" border-radius: 8px;"
                f" padding: 6px 20px 6px 17px; text-align: left;"
                f" font-size: 13px; font-weight: 600; margin: 1px 12px;"
                f"}}"
                f"QPushButton:hover {{ background: #DBEAFE; }}"
            )
        return (
            f"QPushButton {{"
            f" background: transparent; color: {T['subtext']};"
            f" border: none; border-left: 3px solid transparent;"
            f" border-radius: 8px;"
            f" padding: 6px 20px; text-align: left;"
            f" font-size: 13px; margin: 1px 12px;"
            f"}}"
            f"QPushButton:hover {{ background: {T['hover']}; }}"
        )

    def _apply_tag_theme(self) -> None:
        for btn in self._tag_btns.values():
            color  = btn.property("tag_color") or self._T["accent"]
            active = btn is self._active_tag_btn
            btn.setStyleSheet(self._tag_btn_style(color=color, active=active))

    def _apply_theme(self) -> None:
        T = self._T
        self._theme_btn.setText("☀" if self._dark else "🌙")
        self._avatar.setText(self._username[0].upper() if self._username else "?")

        bg, fg = _ROLE_BADGE.get(self._role, ("#F3F4F6", "#6B7280"))
        self._role_badge.setStyleSheet(
            f"QLabel {{ color: {fg}; background: {bg}; border-radius: 20px;"
            f" font-size: 12px; font-weight: 600; padding: 4px 12px;"
            f" margin: 8px 20px 4px; }}"
        )

        drop_bg = T["sidebar"] if self._dark else "#FAFAFA"

        qss = f"""
            QWidget#central_root, QWidget#body {{ background: {T['bg']}; }}

            QFrame#top_bar {{
                background: {T['topbar']};
                border-bottom: 1px solid {T['border']};
            }}
            QLabel#page_title {{
                color: {T['text']};
                font-size: 18px;
                font-weight: 600;
                background: transparent;
            }}
            QPushButton#theme_btn {{
                background: transparent;
                color: {T['subtext']};
                border: none;
                border-radius: 18px;
                font-size: 16px;
            }}
            QPushButton#theme_btn:hover {{ background: {T['hover']}; }}
            QLabel#avatar {{
                background: #2563EB;
                color: #FFFFFF;
                font-size: 13px;
                font-weight: 700;
                border-radius: 16px;
            }}

            QFrame#action_bar {{
                background: {T['topbar']};
                border-bottom: 1px solid {T['border']};
            }}
            QPushButton#btn_primary {{
                background: #2563EB;
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                padding: 0 16px;
            }}
            QPushButton#btn_primary:hover {{ background: #1D4ED8; }}
            QPushButton#btn_secondary {{
                background: transparent;
                color: {T['nav_text']};
                border: 1px solid {T['border']};
                border-radius: 8px;
                font-size: 14px;
                padding: 0 16px;
                min-width: 36px;
            }}
            QPushButton#btn_secondary:hover {{ background: {T['hover']}; }}

            QFrame#sidebar {{
                background: {T['sidebar']};
                border-right: 1px solid {T['border']};
            }}
            QLabel#sidebar_logo {{
                color: {T['text']};
                font-size: 16px;
                font-weight: 700;
                padding: 24px 20px 16px;
                background: transparent;
            }}
            QFrame#sidebar_sep {{
                background: {T['border']};
                border: none;
                max-height: 1px;
            }}
            QLabel#nav_section_label {{
                color: #9CA3AF;
                font-size: 11px;
                font-weight: 600;
                letter-spacing: 1px;
                padding: 16px 20px 8px;
                background: transparent;
            }}
            QPushButton#admin_btn {{
                color: {T['subtext']};
                background: transparent;
                border: none;
                border-left: 3px solid transparent;
                border-radius: 8px;
                padding: 10px 14px 10px 16px;
                text-align: left;
                font-size: 12px;
            }}
            QPushButton#admin_btn:hover {{ background: {T['hover']}; }}
            QLabel#usb_badge {{
                background: transparent;
                margin: 4px 20px 16px;
                padding: 0;
            }}
            QScrollArea#sidebar_scroll {{
                background: transparent;
                border: none;
            }}
            QWidget#sidebar_scroll_content {{
                background: transparent;
            }}
            QScrollArea#sidebar_scroll QScrollBar:vertical {{
                background: transparent;
                width: 4px;
                margin: 0;
            }}
            QScrollArea#sidebar_scroll QScrollBar::handle:vertical {{
                background: {T['border']};
                border-radius: 2px;
                min-height: 20px;
            }}
            QScrollArea#sidebar_scroll QScrollBar::add-line:vertical,
            QScrollArea#sidebar_scroll QScrollBar::sub-line:vertical {{
                height: 0;
            }}

            QWidget#content {{ background: {T['bg']}; }}
            QWidget#search_container {{ background: {T['search_bg']}; }}
            QLabel#search_icon {{
                color: #9CA3AF;
                font-size: 16px;
                background: transparent;
            }}
            QLineEdit#search_bar {{
                background: transparent;
                color: {T['text']};
                border: none;
                font-size: 14px;
            }}

            QTableWidget {{
                background: {T['bg']};
                color: {T['text']};
                border: none;
                gridline-color: transparent;
                outline: none;
                font-size: 13px;
            }}
            QHeaderView::section {{
                background: {T['bg']};
                color: #9CA3AF;
                border: none;
                border-bottom: 1px solid {T['border']};
                padding: 0 10px;
                font-size: 12px;
                font-weight: 600;
            }}
            QTableWidget::item {{
                padding: 0 10px;
                border-bottom: 1px solid {T['hover']};
                background: {T['bg']};
            }}
            QTableWidget::item:hover {{ background: {T['row_hover']}; }}
            QTableWidget::item:selected {{
                background: #EFF6FF;
                color: #111827;
            }}
            QLabel#drop_hint {{
                color: #9CA3AF;
                font-size: 13px;
                border: 2px dashed {T['border']};
                border-radius: 8px;
                background: {drop_bg};
                margin: 12px;
            }}
            QLabel#expiry_banner {{
                color: {T['subtext']};
                font-size: 13px;
                background: {T['sidebar']};
                border-radius: 8px;
                padding: 4px 12px;
                margin: 4px 12px 0;
            }}
            QLabel#progress_banner {{
                color: #FFFFFF;
                font-size: 13px;
                font-weight: 600;
                background: #2563EB;
                border-radius: 8px;
                padding: 4px 12px;
                margin: 4px 12px 0;
            }}
        """

        self.centralWidget().setStyleSheet(qss)

        for db_label, btn in self._nav_btns.items():
            btn.setStyleSheet(self._nav_btn_style(active=(db_label == self._current_label)))

        self._refresh_usb_badge()
        self._apply_tag_theme()

    # ── Rol kısıtlamaları ─────────────────────────────────────────────────────

    def _apply_role_restrictions(self) -> None:
        _log.debug("apply_role_restrictions  role=%r", self._role)
        _role_norm  = self._role.strip().lower().replace("_", " ")
        is_admin    = _role_norm == "yönetici"
        is_readonly = _role_norm == "salt okunur"
        # Standart = not admin and not readonly
        can_write   = not is_readonly   # Yönetici + Standart yazabilir

        # ── Yönetici bölümü: sadece Yönetici görür ───────────────────────
        for _w in (self._admin_sep, self._admin_label, self._blacklist_btn,
                   self._audit_log_btn, self._admin_panel_btn, self._support_btn):
            _w.setVisible(is_admin)
            _w.setEnabled(is_admin)

        # ── Yazma/düzenleme işlemleri: Salt Okunur'da tamamen kapalı ─────
        self.setAcceptDrops(can_write)
        for _w in (self._drop_hint, self._btn_add_file, self._btn_add_folder,
                   self._btn_scan_all, self._btn_new_tag, self._btn_new_folder):
            _w.setVisible(can_write)
            _w.setEnabled(can_write)

        # ── Kritik sekmesi: Salt Okunur'da gizli ─────────────────────────
        _kritik = self._nav_btns.get("Kritik")
        if _kritik:
            _kritik.setVisible(can_write)
            _kritik.setEnabled(can_write)

        self._role_badge.setText(self._role)

    # ── Action bar işlemleri ──────────────────────────────────────────────────

    def _on_add_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Dosya Seç")
        if path:
            self._handle_dropped_file(Path(path), label="Karantina")

    def _on_add_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Klasör Seç")
        if not folder:
            return
        self._handle_dropped_folder(Path(folder), label="Karantina")

    def _on_scan_all(self) -> None:
        for row in range(self._table.rowCount()):
            name_item = self._table.item(row, 0)
            if name_item is None:
                continue
            file_id  = name_item.data(Qt.UserRole)
            filepath = name_item.data(Qt.UserRole + 3) or ""
            if filepath and Path(filepath).exists():
                self._start_scan(Path(filepath), file_id or 0, row)

    def _on_new_tag(self) -> None:
        name, ok = QInputDialog.getText(self, "Yeni Etiket", "Etiket adı:")
        if not ok or not name.strip():
            return
        color = random.choice(_TAG_COLORS)
        try:
            DBManager().execute(
                "INSERT OR IGNORE INTO tags (name, color) VALUES (?, ?)",
                (name.strip(), color),
            )
            self._refresh_tag_sidebar()
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))

    # ── Yönetici işlemleri ────────────────────────────────────────────────────

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
        AuditLogDialog(self).exec()

    def _on_open_admin_panel(self) -> None:
        if self._role != "Yönetici":
            QMessageBox.warning(self, "Erişim Reddedildi", "Bu alana erişim yetkiniz yok.")
            return
        AdminPanel(current_hwid=self._hwid, role=self._role, parent=self).exec()

    def _on_open_contact(self) -> None:
        from UI.ContactDialog import ContactDialog
        ContactDialog(self).exec()

    def _on_open_profile(self) -> None:
        from UI.ProfileDialog import ProfileDialog
        ProfileDialog(
            hwid=self._hwid,
            username=self._username,
            role=self._role,
            user_id=self._user_id,
            parent=self,
        ).exec()

    def _on_hamburger_menu(self) -> None:
        T = self._T
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu {{ background:{T['topbar']}; color:{T['text']};"
            f" border:1px solid {T['border']}; border-radius:8px; padding:4px 0; }}"
            f"QMenu::item {{ padding:10px 24px; font-size:13px; }}"
            f"QMenu::item:selected {{ background:#EFF6FF; color:{T['text']}; border-radius:4px; }}"
            f"QMenu::separator {{ height:1px; background:{T['border']}; margin:4px 10px; }}"
        )
        act_audit   = menu.addAction("📋  Denetim Günlüğü")
        act_usb     = menu.addAction("🔌  USB Yönetimi")
        act_support = menu.addAction("💬  Destek")
        menu.addSeparator()
        act_about   = menu.addAction("ℹ  Hakkında")

        btn_pos = self._btn_view.mapToGlobal(self._btn_view.rect().bottomLeft())
        action  = menu.exec(btn_pos)

        if action == act_audit:
            self._on_open_audit_log()
        elif action == act_usb:
            self._on_open_admin_panel()
        elif action == act_support:
            self._on_open_contact()
        elif action == act_about:
            QMessageBox.information(
                self, "HYCLEUS — Hakkında",
                "HYCLEUS v1.6\n"
                "Güvenli Dosya Yönetim Sistemi\n\n"
                f"Derleme tarihi: 2026-06-09\n"
                "Kriptografi: AES-256-GCM + Argon2id\n"
                "Shamir Secret Sharing (2-of-2)\n\n"
                "© 2026 HYCLEUS — Tüm hakları saklıdır.",
            )

    # ── Sidebar filtresi ──────────────────────────────────────────────────────

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

        display = next((d for _, d, l in _SIDEBAR_NAV if l == db_label), db_label)
        self._page_title.setText(display)

        self._search_bar.blockSignals(True)
        self._search_bar.clear()
        self._search_bar.blockSignals(False)
        self._load_label(db_label)

    def _load_label(self, db_label: str) -> None:
        self._table.setRowCount(0)
        in_imha = (db_label == "Imha")
        self._table.horizontalHeaderItem(3).setText("Kalan Süre" if in_imha else "Tarih")
        self._expiry_banner.setVisible(in_imha)
        if in_imha:
            self._expiry_banner.setText("⏱  Hesaplanıyor...")

        is_admin = self._role == "Yönetici"
        if is_admin:
            sql = """
                SELECT f.id, f.filename, f.label, f.size_bytes, f.added_at,
                       f.filepath, f.original_sha256, f.expires_at,
                       (SELECT q.reason FROM quarantine q
                        WHERE q.file_id = f.id
                        ORDER BY q.quarantined_at DESC LIMIT 1) AS scan_reason
                FROM files f
                WHERE f.label = ?
                ORDER BY f.added_at DESC
            """
            params: tuple = (db_label,)
        else:
            sql = """
                SELECT f.id, f.filename, f.label, f.size_bytes, f.added_at,
                       f.filepath, f.original_sha256, f.expires_at,
                       (SELECT q.reason FROM quarantine q
                        WHERE q.file_id = f.id
                        ORDER BY q.quarantined_at DESC LIMIT 1) AS scan_reason
                FROM files f
                WHERE f.label = ?
                  AND f.id NOT IN (
                          SELECT ft.file_id FROM file_tags ft
                          INNER JOIN tags t ON t.id = ft.tag_id
                          WHERE t.is_private = 1
                      )
                ORDER BY f.added_at DESC
            """
            params = (db_label,)

        try:
            rows = DBManager().fetchall(sql, params)
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
            tags = DBManager().fetchall("SELECT id, name, color, is_private FROM tags ORDER BY name")
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
            tag_id     = tag["id"]
            name       = tag["name"]
            color      = tag["color"]
            is_private = bool(tag["is_private"])

            if is_private and self._role != "Yönetici":
                continue

            is_active = (tag_id == self._current_tag_id)
            display   = f"  {'🔒 ' if is_private else ''}{name}"
            btn = QPushButton(display)
            btn.setFixedHeight(36)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setProperty("tag_color", color)
            btn.setIcon(QIcon(_make_dot_pixmap(color)))
            btn.setIconSize(QSize(8, 8))
            btn.setProperty("is_private", is_private)
            btn.setStyleSheet(self._tag_btn_style(color=color, active=is_active))
            btn.clicked.connect(
                lambda checked=False, tid=tag_id, tname=name, tc=color, b=btn:
                self._on_tag_click(tid, tname, tc, b)
            )
            btn.setContextMenuPolicy(Qt.CustomContextMenu)
            btn.customContextMenuRequested.connect(
                lambda pos, tid=tag_id, tname=name, b=btn:
                self._on_tag_context_menu(pos, tid, tname, b)
            )
            self._tag_btns[tag_id] = btn
            if is_active:
                self._active_tag_btn = btn
            self._tag_container_layout.addWidget(btn)

    # ── Klasör sistemi ────────────────────────────────────────────────────────

    def _refresh_folder_sidebar(self) -> None:
        while self._folder_container_layout.count():
            item = self._folder_container_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self._folder_btns.clear()

        try:
            folders = DBManager().fetchall(
                "SELECT id, name FROM folders WHERE parent_id IS NULL ORDER BY name"
            )
        except Exception:
            return

        for folder in folders:
            fid   = folder["id"]
            fname = folder["name"]
            is_active = (fid == self._current_folder_id)

            btn = QPushButton(f"      📂  {fname}")
            btn.setFixedHeight(34)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet(self._folder_btn_style(active=is_active))
            btn.clicked.connect(
                lambda checked=False, fid_=fid, fn=fname, b=btn:
                self._on_folder_click(fid_, fn, b)
            )
            btn.setContextMenuPolicy(Qt.CustomContextMenu)
            btn.customContextMenuRequested.connect(
                lambda pos, fid_=fid, fn=fname, b=btn:
                self._on_folder_context_menu(pos, fid_, fn, b)
            )
            self._folder_btns[fid] = btn
            self._folder_container_layout.addWidget(btn)

    def _folder_btn_style(self, *, active: bool) -> str:
        T = self._T
        if active:
            return (
                "QPushButton {"
                " background: #EFF6FF; color: #2563EB;"
                " border: none; border-left: 3px solid #2563EB;"
                " border-radius: 6px; height: 34px;"
                " padding: 0 20px 0 8px; text-align: left;"
                " font-size: 12px; margin: 1px 12px 1px 24px;"
                "}"
                "QPushButton:hover { background: #DBEAFE; }"
            )
        return (
            f"QPushButton {{"
            f" background: transparent; color: {T['subtext']};"
            f" border: none; border-left: 3px solid transparent;"
            f" border-radius: 6px; height: 34px;"
            f" padding: 0 20px 0 8px; text-align: left;"
            f" font-size: 12px; margin: 1px 12px 1px 24px;"
            f"}}"
            f"QPushButton:hover {{ background: {T['hover']}; }}"
        )

    def _on_folder_click(self, folder_id: int, folder_name: str, btn: QPushButton) -> None:
        if self._active_tag_btn is not None:
            prev = self._active_tag_btn.property("tag_color") or self._T["accent"]
            self._active_tag_btn.setStyleSheet(self._tag_btn_style(color=prev, active=False))
            self._active_tag_btn = None
        self._current_tag_id = None

        if self._active_folder_btn is not None and self._active_folder_btn is not btn:
            try:
                self._active_folder_btn.setStyleSheet(self._folder_btn_style(active=False))
            except RuntimeError:
                pass  # Qt nesnesi sidebar yenilemesinde silinmiş olabilir

        self._active_folder_btn = btn
        btn.setStyleSheet(self._folder_btn_style(active=True))

        if self._active_btn is not None:
            self._active_btn.setStyleSheet(self._nav_btn_style(active=False))
        self._active_btn    = self._nav_btns["Genel"]
        self._active_btn.setStyleSheet(self._nav_btn_style(active=True))

        self._current_label     = "Genel"
        self._current_folder_id = folder_id
        self._page_title.setText(f"📂 {folder_name}")

        self._search_bar.blockSignals(True)
        self._search_bar.clear()
        self._search_bar.blockSignals(False)
        self._expiry_banner.setVisible(False)
        self._table.horizontalHeaderItem(3).setText("Tarih")
        self._load_folder_files(folder_id)

    def _load_folder_files(self, folder_id: int) -> None:
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
                WHERE f.folder_id = ?
                ORDER BY f.added_at DESC
                """,
                (folder_id,),
            )
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı", str(exc))
            return
        self._populate_table(rows)

    def _on_folder_context_menu(self, pos: QPoint, folder_id: int, folder_name: str,
                                btn: QPushButton) -> None:
        if self._role.strip().lower() == "salt okunur":
            _log.debug("context_menu_blocked  fn=_on_folder_context_menu  role=%r", self._role)
            return
        T = self._T
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu {{ background:{T['topbar']}; color:{T['text']};"
            f" border:1px solid {T['border']}; border-radius:8px; padding:4px 0; }}"
            f"QMenu::item {{ padding:9px 22px; font-size:13px; }}"
            f"QMenu::item:selected {{ background:#EFF6FF; color:{T['text']}; border-radius:4px; }}"
        )
        act_dl   = menu.addAction("⬇  Klasörü İndir (ZIP)")
        act_imha = menu.addAction("🔥  İmha Odasına At")
        act_del  = menu.addAction("🗑  Klasörü Sil")

        action = menu.exec(btn.mapToGlobal(pos))
        if action == act_dl:
            self._on_folder_download(folder_id, folder_name)
        elif action == act_imha:
            self._on_folder_move_to_imha(folder_id, folder_name)
        elif action == act_del:
            self._on_folder_delete(folder_id, folder_name)

    def _on_create_folder(self) -> None:
        from PySide6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(self, "Klasör Oluştur", "Klasör adı:")
        if not ok or not name.strip():
            return
        try:
            db = DBManager()
            row = db.fetchone("SELECT id FROM users WHERE id = ?", (self._user_id,))
            if row is None:
                effective_hwid = "DEV-HWID-1234" if _DEV_MODE else (self._hwid or "")
                db.execute(
                    "INSERT INTO users"
                    " (id, username, password_hash, role, status, hwid)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (self._user_id, "yonetici", "", "admin", "approved", effective_hwid),
                )
            db.execute(
                "INSERT INTO folders (name, owner_id) VALUES (?, ?)",
                (name.strip(), self._user_id),
            )
            db.log("folder_created", detail=f"name={name.strip()} hwid={self._hwid}")
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))
            return
        self._refresh_folder_sidebar()

    def _on_folder_move_to_imha(self, folder_id: int, folder_name: str) -> None:
        confirm = QMessageBox.question(
            self, "Klasörü İmha Et",
            f"'{folder_name}' klasöründeki tüm dosyalar İmha Odası'na taşınacak "
            f"ve 24 saat içinde silinecek.\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=self._get_imha_ttl_hours())).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            db    = DBManager()
            rows  = db.fetchall("SELECT id FROM files WHERE folder_id = ?", (folder_id,))
            for r in rows:
                db.execute(
                    "UPDATE files SET label = 'Imha', expires_at = ? WHERE id = ?",
                    (expires_at, r["id"]),
                )
                db.log("file_moved_to_imha", target_type="file", target_id=r["id"],
                       detail=f"hwid={self._hwid} via=folder folder_id={folder_id} expires_at={expires_at}")
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        # Aktif görünüm klasör içindeyse Genel'e dön, değilse tabloyu yenile
        if self._current_folder_id == folder_id:
            self._current_folder_id = None
            self._active_folder_btn = None
            self._on_sidebar_click("Genel", self._nav_btns["Genel"])
        else:
            self._refresh_folder_sidebar()
            if self._current_label:
                self._load_label(self._current_label)
        QMessageBox.information(
            self, "İmha Odasına Taşındı",
            f"'{folder_name}' klasöründeki {len(rows)} dosya 24 saat içinde imha edilecek.",
        )

    def _on_folder_delete(self, folder_id: int, folder_name: str) -> None:
        confirm = QMessageBox.question(
            self, "Klasörü Sil",
            f"'{folder_name}' klasörü silinecek.\n\nDosyalar klasörden çıkarılır ama silinmez.\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            db = DBManager()
            db.execute("UPDATE files SET folder_id = NULL WHERE folder_id = ?", (folder_id,))
            db.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
            db.log("folder_deleted", target_type="folder", target_id=folder_id,
                   detail=f"name={folder_name}")
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))
            return
        if self._current_folder_id == folder_id:
            self._current_folder_id = None
            self._active_folder_btn = None
            self._on_sidebar_click("Genel", self._nav_btns["Genel"])
        else:
            self._refresh_folder_sidebar()

    def _on_folder_download(self, folder_id: int, folder_name: str) -> None:
        import json as _json
        import zipfile

        try:
            secret = _json.loads(_TOTP_FILE.read_text(encoding="utf-8"))["secret"]
        except Exception:
            QMessageBox.critical(self, "İndir", "TOTP anahtarı okunamadı.")
            return

        code, ok = QInputDialog.getText(self, "Kimlik Doğrulama",
                                        "Authenticator kodunu girin (6 hane):")
        if not ok:
            return
        code = code.strip()
        totp_ok = (
            code.isdigit()
            and len(code) == 6
            and pyotp.TOTP(secret).verify(code, valid_window=1)
        )
        if not totp_ok:
            DBManager().log("folder_download_totp_failed", detail=f"folder={folder_name}")
            QMessageBox.warning(self, "Erişim Reddedildi", "Authenticator kodu geçersiz.")
            return

        try:
            files = DBManager().fetchall(
                "SELECT id, filename, filepath, aad_metadata FROM files WHERE folder_id = ?",
                (folder_id,),
            )
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı", str(exc))
            return

        if not files:
            QMessageBox.information(self, "Klasör İndir", "Klasörde dosya bulunamadı.")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self, "ZIP Olarak Kaydet", f"{folder_name}.zip", "ZIP Arşivi (*.zip)"
        )
        if not save_path:
            return

        from CORE.crypto import AuthenticationError as _AE, decrypt_file as _df
        errors = []
        try:
            with zipfile.ZipFile(save_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for f in files:
                    try:
                        aad_hwid: str | None = None
                        if f["aad_metadata"]:
                            aad_hwid = json.loads(f["aad_metadata"]).get("hwid")
                        file_hwid = aad_hwid or ("DEV-HWID-1234" if _DEV_MODE else self._hwid)
                        content, meta = _df(f["filepath"], self._key, hwid=file_hwid)
                        zf.writestr(meta.get("filename", f["filename"]), content)
                        del content
                    except _AE:
                        errors.append(f["filename"] + " (bütünlük hatası)")
                    except Exception as exc:
                        errors.append(f["filename"] + f" ({exc})")
        except Exception as exc:
            QMessageBox.critical(self, "ZIP Hatası", str(exc))
            return

        DBManager().log("folder_downloaded", target_type="folder", target_id=folder_id,
                        detail=f"zip={save_path} hwid={self._hwid}")

        msg = f"ZIP kaydedildi:\n{save_path}"
        if errors:
            msg += f"\n\nAtlanan dosyalar ({len(errors)}):\n" + "\n".join(errors)
        QMessageBox.information(self, "Klasör İndir", msg)

    def _on_ctx_move_to_folder(self, file_id: int | None) -> None:
        if file_id is None:
            return
        try:
            folders = DBManager().fetchall("SELECT id, name FROM folders ORDER BY name")
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))
            return
        if not folders:
            QMessageBox.information(self, "Klasöre Taşı",
                                    "Henüz klasör yok. Önce bir klasör oluşturun.")
            return

        T = self._T
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu {{ background:{T['topbar']}; color:{T['text']};"
            f" border:1px solid {T['border']}; border-radius:8px; padding:4px 0; }}"
            f"QMenu::item {{ padding:9px 22px; font-size:13px; }}"
            f"QMenu::item:selected {{ background:#EFF6FF; color:{T['text']}; border-radius:4px; }}"
        )
        acts = {}
        for folder in folders:
            acts[menu.addAction(f"📂  {folder['name']}")] = folder["id"]

        action = menu.exec(self._table.viewport().mapToGlobal(
            self._table.visualItemRect(self._table.currentItem()).center()
        ))
        if action not in acts:
            return
        target_folder_id = acts[action]
        try:
            db = DBManager()
            db.execute("UPDATE files SET folder_id = ? WHERE id = ?", (target_folder_id, file_id))
            db.log("file_moved_to_folder", target_type="file", target_id=file_id,
                   detail=f"folder_id={target_folder_id} hwid={self._hwid}")
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))

    def _on_tag_click(self, tag_id: int, tag_name: str, tag_color: str, btn: QPushButton) -> None:
        if btn.property("is_private") and self._role != "Yönetici":
            QMessageBox.warning(
                self, "Erişim Reddedildi",
                "Bu klasör gizlidir, erişim yetkiniz yok."
            )
            return
        if self._active_btn is not None:
            self._active_btn.setStyleSheet(self._nav_btn_style(active=False))
            self._active_btn = None

        if self._active_tag_btn is not None and self._active_tag_btn is not btn:
            prev = self._active_tag_btn.property("tag_color") or self._T["accent"]
            self._active_tag_btn.setStyleSheet(self._tag_btn_style(color=prev, active=False))

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

    def _on_tag_context_menu(self, pos: QPoint, tag_id: int, tag_name: str, btn: QPushButton) -> None:
        if self._role.strip().lower() == "salt okunur":
            _log.debug("context_menu_blocked  fn=_on_tag_context_menu  role=%r", self._role)
            return
        T = self._T
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu {{ background:{T['topbar']}; color:{T['text']};"
            f" border:1px solid {T['border']}; border-radius:8px; padding:4px 0; }}"
            f"QMenu::item {{ padding:9px 22px; font-size:13px; }}"
            f"QMenu::item:selected {{ background:#FEE2E2; color:#DC2626; border-radius:4px; }}"
        )
        act_delete = menu.addAction("🗑  Etiketi Sil")
        if menu.exec(btn.mapToGlobal(pos)) == act_delete:
            self._on_tag_delete(tag_id, tag_name)

    def _on_tag_delete(self, tag_id: int, tag_name: str) -> None:
        confirm = QMessageBox.question(
            self, "Etiketi Sil",
            f"'{tag_name}' etiketi silinecek.\n\nDosyalar etkilenmez, sadece etiket kaldırılır.\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            db = DBManager()
            db.execute("DELETE FROM file_tags WHERE tag_id = ?", (tag_id,))
            db.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
            db.log("tag_deleted", target_type="tag", target_id=tag_id,
                   detail=f"name={tag_name} hwid={self._hwid}")
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))
            return
        if self._current_tag_id == tag_id:
            self._current_tag_id = None
            self._active_tag_btn = None
            self._on_sidebar_click("Genel", self._nav_btns["Genel"])
        else:
            self._refresh_tag_sidebar()

    def _search_files(self, term: str) -> None:
        term = term.strip()
        if not term:
            if self._current_tag_id is not None:
                self._load_tag_files(self._current_tag_id)
            else:
                self._load_label(self._current_label)
            return
        self._table.setRowCount(0)
        like = f"%{term}%"
        is_admin = self._role == "Yönetici"
        if is_admin:
            sql = """
                SELECT f.id, f.filename, f.label, f.size_bytes, f.added_at,
                       f.filepath, f.original_sha256, f.expires_at,
                       (SELECT q.reason FROM quarantine q
                        WHERE q.file_id = f.id
                        ORDER BY q.quarantined_at DESC LIMIT 1) AS scan_reason
                FROM files f
                WHERE (f.filename LIKE ? OR f.original_sha256 LIKE ?
                   OR f.id IN (
                       SELECT ft.file_id FROM file_tags ft
                       INNER JOIN tags t ON t.id = ft.tag_id
                       WHERE t.name LIKE ?
                   ))
                ORDER BY f.added_at DESC
            """
            params: tuple = (like, like, like)
        else:
            sql = """
                SELECT f.id, f.filename, f.label, f.size_bytes, f.added_at,
                       f.filepath, f.original_sha256, f.expires_at,
                       (SELECT q.reason FROM quarantine q
                        WHERE q.file_id = f.id
                        ORDER BY q.quarantined_at DESC LIMIT 1) AS scan_reason
                FROM files f
                WHERE (f.filename LIKE ? OR f.original_sha256 LIKE ?
                   OR f.id IN (
                       SELECT ft.file_id FROM file_tags ft
                       INNER JOIN tags t ON t.id = ft.tag_id
                       WHERE t.name LIKE ?
                   ))
                  AND f.id NOT IN (
                          SELECT ft2.file_id FROM file_tags ft2
                          INNER JOIN tags t2 ON t2.id = ft2.tag_id
                          WHERE t2.is_private = 1
                      )
                ORDER BY f.added_at DESC
            """
            params = (like, like, like)
        try:
            rows = DBManager().fetchall(sql, params)
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

    # ── Drag & drop ───────────────────────────────────────────────────────────

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if self._role.strip().lower() == "salt okunur":
            event.ignore()
            return
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._drop_hint.setStyleSheet(
                "QLabel { color: #2563EB; font-size: 13px;"
                " border: 2px dashed #2563EB; border-radius: 8px;"
                " background: #EFF6FF; margin: 12px; }"
            )
        else:
            event.ignore()

    def dragMoveEvent(self, event: QDragMoveEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragLeaveEvent(self, event) -> None:
        self._reset_drop_hint_style()

    def dropEvent(self, event: QDropEvent) -> None:
        self._reset_drop_hint_style()
        if self._role.strip().lower() == "salt okunur":
            _log.debug("drop_blocked  role=%r", self._role)
            event.ignore()
            return
        for url in event.mimeData().urls():
            local = url.toLocalFile()
            if not local:
                continue
            p = Path(local)
            if p.is_dir():
                self._handle_dropped_folder(p, label="Karantina")
            elif p.is_file():
                self._handle_dropped_file(p, label="Karantina")

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._overlay.resize(self.size())

    def _reset_drop_hint_style(self) -> None:
        T = self._T
        bg = T["sidebar"] if self._dark else "#FAFAFA"
        self._drop_hint.setStyleSheet(
            f"QLabel {{ color: #9CA3AF; font-size: 13px;"
            f" border: 2px dashed #D1D5DB; border-radius: 8px;"
            f" background: {bg}; margin: 12px; }}"
        )

    def _handle_dropped_file(self, src: Path, label: str = "Karantina",
                             folder_id: int | None = None) -> None:
        if not src.is_file():
            return
        if get_usb_hwid() is None:
            QMessageBox.warning(self, "USB Bulunamadı",
                                "Yetkili USB cihazı takılı değil.\nDosya eklenemez.")
            self._refresh_usb_badge()
            return
        self._start_batch([(src, label, folder_id)])

    def _handle_dropped_folder(self, folder: Path, label: str = "Karantina") -> None:
        files = sorted(p for p in folder.rglob("*") if p.is_file())
        if not files:
            QMessageBox.information(self, "Klasör Ekle",
                                    f"'{folder.name}' klasöründe dosya bulunamadı.")
            return

        folder_id: int | None = None
        try:
            db = DBManager()
            _urow = db.fetchone("SELECT id FROM users WHERE id = ?", (self._user_id,))
            if _urow is None:
                _ehwid = "DEV-HWID-1234" if _DEV_MODE else (self._hwid or "")
                db.execute(
                    "INSERT INTO users (id, username, password_hash, role, status, hwid)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (self._user_id, "yonetici", "", "admin", "approved", _ehwid),
                )
            db.execute("INSERT INTO folders (name, owner_id) VALUES (?, ?)",
                       (folder.name, self._user_id))
            _frow = db.fetchone(
                "SELECT id FROM folders WHERE name = ? AND owner_id = ? ORDER BY id DESC LIMIT 1",
                (folder.name, self._user_id),
            )
            if _frow:
                folder_id = _frow["id"]
            db.log("folder_created",
                   detail=f"name={folder.name} hwid={self._hwid} via=drag_drop files={len(files)}")
        except Exception as exc:
            _log.warning("folder_create_failed  exc=%s", exc)

        self._start_batch([(f, label, folder_id) for f in files])

    # ── Batch pipeline ────────────────────────────────────────────────────────

    def _start_batch(self, files: list[tuple[Path, str, int | None]]) -> None:
        if self._batch_done >= self._batch_total:
            self._batch_total  = 0
            self._batch_done   = 0
            self._batch_errors = 0
            self._batch_has_folder = False

        self._batch_total += len(files)
        self._batch_has_folder = self._batch_has_folder or any(
            fid is not None for _, _, fid in files
        )
        self._update_progress_banner()

        ttl = self._get_imha_ttl_hours()
        for src, label, folder_id in files:
            runnable = _FileRunnable(
                src=src, key=self._key, hwid=self._hwid,
                label=label, folder_id=folder_id,
                signals=self._batch_signals, ttl_hours=ttl,
            )
            self._pool.start(runnable)

    def _on_file_done(self, result: dict) -> None:
        self._batch_done += 1
        if result.get("ok"):
            self._insert_row(
                result["filename"], result["label"],
                self._fmt_size(result["size_bytes"]),
                result["date"],
                scan_verdict=result["verdict"],
                scan_mock=result["mock"],
                file_id=result["file_id"],
                sha256=result["sha256"],
                filepath=result["filepath"],
                expires_at=result["expires_at"],
            )
            self._table.scrollToBottom()
        else:
            self._batch_errors += 1
            _log.warning("batch_file_error  file=%s  err=%s",
                         result.get("filename"), result.get("error"))
        self._update_progress_banner()
        if self._batch_done >= self._batch_total:
            self._on_batch_complete()

    def _on_batch_complete(self) -> None:
        success = self._batch_done - self._batch_errors
        errors  = self._batch_errors
        self._progress_banner.setVisible(False)
        if self._batch_has_folder:
            self._refresh_folder_sidebar()
        msg = f"Tamamlandı — {success}/{self._batch_done} dosya işlendi"
        if errors:
            msg += f", {errors} hata"
        QMessageBox.information(self, "Yükleme Tamamlandı", msg)

    def _update_progress_banner(self) -> None:
        if self._batch_total == 0:
            self._progress_banner.setVisible(False)
            return
        self._progress_banner.setText(
            f"⏳  {self._batch_done}/{self._batch_total} işlendi"
            + (f"  ({self._batch_errors} hata)" if self._batch_errors else "")
        )
        self._progress_banner.setVisible(True)

    # ── USB kilit ─────────────────────────────────────────────────────────────

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
        self._authenticating = True
        self._lock()
        try:
            authenticate_usb(new_hwid)
        except USBAuthError as exc:
            QMessageBox.warning(self, "USB Reddedildi", f"Kimlik doğrulaması başarısız:\n\n{exc}")
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
            QMessageBox.information(self, "Oturum Kilitli", "PIN girilmedi — oturum kilitli kaldı.")
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
        self.centralWidget().setEnabled(False)
        self.centralWidget().setGraphicsEffect(self._blur)
        self._overlay.resize(self.size())
        self._overlay.show()
        self._overlay.raise_()

    def _unlock(self) -> None:
        self._locked = False
        self.centralWidget().setEnabled(True)
        self.centralWidget().setGraphicsEffect(None)
        self._overlay.hide()

    # ── Tablo yardımcıları ────────────────────────────────────────────────────

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

        # Sütun 0 — dosya adı
        display_name = ("🔒  " + name) if is_hcl else name
        name_item    = QTableWidgetItem(display_name)
        name_item.setData(Qt.UserRole,     file_id)
        name_item.setData(Qt.UserRole + 1, sha256)
        name_item.setData(Qt.UserRole + 2, label)
        name_item.setData(Qt.UserRole + 3, filepath)
        name_item.setData(Qt.UserRole + 4, expires_at)
        if is_hcl:
            name_item.setForeground(QColor("#2563EB"))
        self._table.setItem(row, 0, name_item)

        # Sütun 1 — etiket pill (setCellWidget)
        fg, bg = _LABEL_PILL_STYLE.get(label, ("#6B7280", "#F3F4F6"))
        pill = QLabel(label)
        pill.setAlignment(Qt.AlignCenter)
        pill.setStyleSheet(
            f"QLabel {{ color: {fg}; background: {bg}; border-radius: 12px;"
            f" padding: 2px 8px; font-size: 13px; font-weight: 500; }}"
        )
        pill_wrap = QWidget()
        pill_wrap.setAttribute(Qt.WA_TransparentForMouseEvents)
        pill_wrap.setStyleSheet("background: transparent;")
        ph = QHBoxLayout(pill_wrap)
        ph.setContentsMargins(8, 8, 8, 8)
        ph.addWidget(pill)
        self._table.setCellWidget(row, 1, pill_wrap)

        # Sütunlar 2-3 — boyut, tarih
        size_item = QTableWidgetItem(size)
        date_item = QTableWidgetItem(date)
        size_item.setTextAlignment(Qt.AlignCenter)
        date_item.setTextAlignment(Qt.AlignCenter)
        self._table.setItem(row, 2, size_item)
        self._table.setItem(row, 3, date_item)

        # Sütun 4 — tarama sonucu
        if scan_verdict:
            text, color = _VERDICT_BADGE.get(scan_verdict, ("—", "#9CA3AF"))
            if scan_mock:
                text, color = text + " (m)", "#9CA3AF"
            self._set_scan_badge(row, text, color)

    def _start_scan(self, path: Path, file_id: int, row: int) -> None:
        self._set_scan_badge(row, "⟳ Taranıyor...", "#D97706")
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

    def _on_scan_done(self, row: int, result: ScanResult) -> None:
        text, color = _VERDICT_BADGE.get(result.verdict, ("—", "#9CA3AF"))
        if result.mock:
            text, color = text + " (m)", "#9CA3AF"
        self._set_scan_badge(row, text, color)

    # ── Context menu ──────────────────────────────────────────────────────────

    def _on_context_menu(self, pos: QPoint) -> None:
        if self._role.strip().lower() == "salt okunur":
            _log.debug("context_menu_blocked  fn=_on_context_menu  role=%r", self._role)
            return

        selected_rows = sorted({idx.row() for idx in self._table.selectedIndexes()})
        clicked_row   = self._table.rowAt(pos.y())
        if len(selected_rows) > 1 and clicked_row in selected_rows:
            self._on_bulk_context_menu(pos, selected_rows)
            return

        row = self._table.rowAt(pos.y())
        if row < 0:
            return
        name_item = self._table.item(row, 0)
        if name_item is None:
            return
        label:    str       = name_item.data(Qt.UserRole + 2) or ""
        file_id:  int | None = name_item.data(Qt.UserRole)
        sha256:   str | None = name_item.data(Qt.UserRole + 1)
        filepath: str | None = name_item.data(Qt.UserRole + 3)

        T = self._T
        menu_style = (
            f"QMenu {{ background:{T['topbar']}; color:{T['text']};"
            f" border:1px solid {T['border']}; border-radius:8px; padding:4px 0; }}"
            f"QMenu::item {{ padding:9px 22px; font-size:13px; }}"
            f"QMenu::item:selected {{ background:#EFF6FF; color:{T['text']};"
            f" border-radius:4px; }}"
            f"QMenu::separator {{ height:1px; background:{T['border']}; margin:4px 10px; }}"
        )

        menu     = QMenu(self)
        menu.setStyleSheet(menu_style)
        act_tags = menu.addAction("🏷  Etiket Ata")

        act_scan = act_download = act_approve = act_reject = act_move_folder = act_kritik = act_imha = None
        if label == "Genel":
            menu.addSeparator()
            act_download    = menu.addAction("⬇  İndir")
            act_kritik      = menu.addAction("🛡  Kritik'e Taşı")
            act_move_folder = menu.addAction("📂  Klasöre Taşı")
            act_imha        = menu.addAction("🔥  İmha Odasına At")
        elif label == "Kritik":
            menu.addSeparator()
            act_download    = menu.addAction("⬇  İndir")
            act_move_folder = menu.addAction("📂  Klasöre Taşı")
            act_imha        = menu.addAction("🔥  İmha Odasına At")
        elif label == "Karantina":
            menu.addSeparator()
            act_scan        = menu.addAction("🔍  Tara")
            act_download    = menu.addAction("⬇  İndir")
            act_move_folder = menu.addAction("📂  Klasöre Taşı")
            menu.addSeparator()
            act_kritik  = menu.addAction("🛡  Kritik'e Taşı")
            act_approve = menu.addAction("Onayla  →  Genel'e taşı")
            act_reject  = menu.addAction("Reddet  →  İmha Odası'na taşı")
            act_imha    = menu.addAction("🔥  İmha Odasına At")

        action = menu.exec(self._table.viewport().mapToGlobal(pos))

        if action == act_tags:
            self._on_ctx_assign_tags(file_id)
        elif action == act_scan:
            self._on_ctx_scan(row, file_id, filepath)
        elif action == act_download:
            self._on_ctx_download(file_id, filepath)
        elif action == act_kritik:
            self._on_ctx_move_to_kritik(row, file_id)
        elif action == act_move_folder:
            self._on_ctx_move_to_folder(file_id)
        elif action == act_approve:
            self._on_ctx_move_label(row, file_id, "Genel")
        elif action == act_reject:
            self._on_ctx_move_label(row, file_id, "Imha")
        elif action == act_imha:
            self._on_ctx_move_to_imha(row, file_id)

    def _on_ctx_download(self, file_id: int | None, filepath: str | None) -> None:
        if not filepath:
            QMessageBox.warning(self, "İndir", "Dosya yolu bulunamadı.")
            return
        try:
            secret = json.loads(_TOTP_FILE.read_text(encoding="utf-8"))["secret"]
        except Exception:
            QMessageBox.critical(self, "İndir", "TOTP anahtarı okunamadı.")
            return

        code, ok = QInputDialog.getText(self, "Kimlik Doğrulama",
                                        "Authenticator kodunu girin (6 hane):")
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
            db.log("download_totp_failed", target_type="file", target_id=file_id,
                   detail=f"hwid={self._hwid}")
            QMessageBox.warning(self, "Erişim Reddedildi",
                                "Authenticator kodu geçersiz.\nDosya indirilmedi.")
            return

        aad_hwid: str | None = None
        raw_aad: str | None = None
        if file_id is not None:
            try:
                aad_row = db.fetchone(
                    "SELECT aad_metadata FROM files WHERE id = ?", (file_id,)
                )
                raw_aad = aad_row["aad_metadata"] if aad_row else None
                if raw_aad:
                    aad_hwid = json.loads(raw_aad).get("hwid")
            except Exception:
                pass
        # aad_hwid biliniyorsa GCM + Python HWID kontrolü yap.
        # bilinmiyorsa (eski kayıt veya NULL), hwid=None geç — GCM AAD kimlik
        # doğrulaması zaten hwid'i koruma altına alır.
        _log.debug(
            "download  file_id=%s  self_hwid=%s  aad_hwid=%s  key_len=%s  aad_metadata=%s",
            file_id, self._hwid, aad_hwid,
            len(self._key) if self._key else 0,
            raw_aad[:80] + "..." if raw_aad and len(raw_aad) > 80 else raw_aad,
        )
        try:
            content, meta = decrypt_file(filepath, self._key, hwid=aad_hwid)
        except AuthenticationError as exc:
            _log.error("download_auth_error  file_id=%s  exc=%s", file_id, exc)
            QMessageBox.critical(self, "Bütünlük Hatası",
                                 f"Dosya bütünlüğü doğrulanamadı:\n{exc}")
            return
        except Exception as exc:
            _log.error("download_decrypt_error  file_id=%s  exc=%s", file_id, exc)
            QMessageBox.critical(self, "Şifre Çözme Hatası", str(exc))
            return

        original_name = meta.get("filename", Path(filepath).stem)
        save_path, _  = QFileDialog.getSaveFileName(self, "Dosyayı Kaydet", original_name)
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

        db.log("file_downloaded", target_type="file", target_id=file_id,
               detail=f"hwid={self._hwid} dest={save_path}")
        QMessageBox.information(self, "İndir", f"Dosya başarıyla kaydedildi:\n{save_path}")

    def _on_ctx_assign_tags(self, file_id: int | None) -> None:
        if file_id is None:
            QMessageBox.warning(self, "Etiket", "Dosya kimliği bulunamadı.")
            return
        from UI.TagDialog import TagDialog
        dlg = TagDialog(file_id=file_id, role=self._role, parent=self)
        if dlg.exec() == TagDialog.Accepted:
            self._refresh_tag_sidebar()
            if self._current_tag_id is not None:
                self._load_tag_files(self._current_tag_id)

    def _on_bulk_context_menu(self, pos: QPoint, rows: list[int]) -> None:
        file_ids:  list[int] = []
        labels:    list[str] = []
        filepaths: list[str] = []
        for r in rows:
            item = self._table.item(r, 0)
            if item is not None:
                fid      = item.data(Qt.UserRole)
                label    = item.data(Qt.UserRole + 2) or ""
                filepath = item.data(Qt.UserRole + 3) or ""
                if fid is not None:
                    file_ids.append(fid)
                    labels.append(label)
                    filepaths.append(filepath)
        if not file_ids:
            return

        n              = len(file_ids)
        all_karantina  = all(lbl == "Karantina" for lbl in labels)
        any_not_kritik = any(lbl != "Kritik"    for lbl in labels)
        any_not_imha   = any(lbl != "Imha"      for lbl in labels)

        T = self._T
        mstyle = (
            f"QMenu {{ background:{T['topbar']}; color:{T['text']};"
            f" border:1px solid {T['border']}; border-radius:8px; padding:4px 0; }}"
            f"QMenu::item {{ padding:9px 22px; font-size:13px; }}"
            f"QMenu::item:selected {{ background:#EFF6FF; color:#111827; border-radius:4px; }}"
            f"QMenu::separator {{ height:1px; background:{T['border']}; margin:4px 10px; }}"
        )
        menu = QMenu(self)
        menu.setStyleSheet(mstyle)

        act_tags     = menu.addAction(f"🏷  Toplu Etiket Ata  ({n} dosya)")
        menu.addSeparator()
        act_download = menu.addAction(f"⬇  Seçilenleri İndir  ({n} dosya)")
        menu.addSeparator()
        act_approve  = None
        act_kritik   = None
        act_imha     = None
        if all_karantina:
            act_approve = menu.addAction(f"✅  Karantinadan Çıkar  ({n} dosya)  →  Genel")
        if any_not_kritik:
            act_kritik = menu.addAction(f"🛡  Seçilenleri Kritik'e Taşı  ({n} dosya)")
        if any_not_imha:
            act_imha   = menu.addAction(f"🔥  Seçilenleri İmha Odasına At  ({n} dosya)")

        action = menu.exec(self._table.viewport().mapToGlobal(pos))
        if action == act_tags:
            self._on_ctx_bulk_assign_tags(file_ids)
        elif action == act_download:
            self._on_ctx_bulk_download(file_ids, filepaths)
        elif action == act_approve:
            self._on_ctx_bulk_approve(rows, file_ids)
        elif action == act_kritik:
            self._on_ctx_bulk_move_to_kritik(rows, file_ids, labels)
        elif action == act_imha:
            self._on_ctx_bulk_move_to_imha(rows, file_ids)

    def _on_ctx_bulk_assign_tags(self, file_ids: list[int]) -> None:
        from UI.TagDialog import TagDialog
        dlg = TagDialog(file_id=file_ids[0], role=self._role, parent=self, file_ids=file_ids)
        if dlg.exec() == TagDialog.Accepted:
            self._refresh_tag_sidebar()
            if self._current_tag_id is not None:
                self._load_tag_files(self._current_tag_id)

    def _on_ctx_bulk_approve(self, rows: list[int], file_ids: list[int]) -> None:
        confirm = QMessageBox.question(
            self, "Karantinadan Çıkar",
            f"{len(file_ids)} dosya Karantina → Genel olarak taşınacak.\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            db = DBManager()
            for fid in file_ids:
                db.execute("UPDATE files SET label = 'Genel' WHERE id = ?", (fid,))
                db.log("file_label_changed", target_type="file", target_id=fid,
                       detail=f"hwid={self._hwid} from=Karantina to=Genel auto=False bulk=True")
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        for row in sorted(rows, reverse=True):
            self._table.removeRow(row)
        QMessageBox.information(self, "Taşındı",
                                f"{len(file_ids)} dosya Genel etiketine taşındı.")

    def _on_ctx_bulk_move_to_kritik(
        self, rows: list[int], file_ids: list[int], labels: list[str],
    ) -> None:
        to_move = [(r, fid) for r, fid, lbl in zip(rows, file_ids, labels)
                   if lbl != "Kritik"]
        if not to_move:
            QMessageBox.information(self, "Kritik'e Taşı",
                                    "Seçili dosyaların tümü zaten Kritik etiketinde.")
            return
        confirm = QMessageBox.question(
            self, "Kritik'e Taşı",
            f"{len(to_move)} dosya Kritik etiketine taşınacak.\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        moved = 0
        try:
            db = DBManager()
            for _, fid in to_move:
                db.execute("UPDATE files SET label = 'Kritik' WHERE id = ?", (fid,))
                db.log("file_label_changed", target_type="file", target_id=fid,
                       detail=f"hwid={self._hwid} to=Kritik bulk=True")
                moved += 1
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        for row in sorted((r for r, _ in to_move), reverse=True):
            self._table.removeRow(row)
        QMessageBox.information(self, "Taşındı", f"{moved} dosya Kritik etiketine taşındı.")

    def _on_ctx_bulk_move_to_imha(self, rows: list[int], file_ids: list[int]) -> None:
        confirm = QMessageBox.question(
            self, "İmha Odasına At",
            f"{len(file_ids)} dosya İmha Odası'na taşınacak ve süre sonunda silinecek.\n"
            "Devam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=self._get_imha_ttl_hours())
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        moved = 0
        try:
            db = DBManager()
            for fid in file_ids:
                db.execute(
                    "UPDATE files SET label = 'Imha', expires_at = ? WHERE id = ?",
                    (expires_at, fid),
                )
                db.log("file_moved_to_imha", target_type="file", target_id=fid,
                       detail=f"hwid={self._hwid} expires_at={expires_at} bulk=True")
                moved += 1
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        for row in sorted(rows, reverse=True):
            self._table.removeRow(row)
        QMessageBox.information(self, "İmha Odasına Taşındı",
                                f"{moved} dosya İmha Odası'na taşındı.")

    def _on_ctx_bulk_download(
        self, file_ids: list[int], filepaths: list[str],
    ) -> None:
        try:
            secret = json.loads(_TOTP_FILE.read_text(encoding="utf-8"))["secret"]
        except Exception:
            QMessageBox.critical(self, "İndir", "TOTP anahtarı okunamadı.")
            return

        code, ok = QInputDialog.getText(
            self, "Kimlik Doğrulama", "Authenticator kodunu girin (6 hane):"
        )
        if not ok:
            return
        code = code.strip()
        if not (code.isdigit() and len(code) == 6
                and pyotp.TOTP(secret).verify(code, valid_window=1)):
            DBManager().log("bulk_download_totp_failed",
                            detail=f"hwid={self._hwid} count={len(file_ids)}")
            QMessageBox.warning(self, "Erişim Reddedildi", "Authenticator kodu geçersiz.")
            return

        save_dir = QFileDialog.getExistingDirectory(self, "Dosyaların Kaydedileceği Klasörü Seç")
        if not save_dir:
            return
        dest_dir = Path(save_dir)

        prog = QProgressDialog("Dosyalar indiriliyor…", "İptal", 0, len(file_ids), self)
        prog.setWindowTitle("Toplu İndirme")
        prog.setMinimumDuration(0)
        prog.setValue(0)

        saved: int       = 0
        errors: list[str] = []

        for i, (fid, filepath) in enumerate(zip(file_ids, filepaths)):
            if prog.wasCanceled():
                break
            short = Path(filepath).name if filepath else "?"
            prog.setLabelText(f"İndiriliyor ({i + 1}/{len(file_ids)}): {short}")
            prog.setValue(i)
            QApplication.processEvents()

            if not filepath:
                errors.append(f"#{fid} (dosya yolu yok)")
                continue
            try:
                aad_row  = DBManager().fetchone(
                    "SELECT aad_metadata FROM files WHERE id = ?", (fid,)
                )
                aad_hwid = None
                if aad_row and aad_row["aad_metadata"]:
                    aad_hwid = json.loads(aad_row["aad_metadata"]).get("hwid")
                content, meta = decrypt_file(filepath, self._key, hwid=aad_hwid)
                original_name = meta.get("filename", Path(filepath).stem)
                dest = dest_dir / original_name
                if dest.exists():
                    stem, suffix, n = dest.stem, dest.suffix, 1
                    while dest.exists():
                        dest = dest_dir / f"{stem}_{n}{suffix}"
                        n   += 1
                dest.write_bytes(content)
                del content
                DBManager().log("file_downloaded", target_type="file", target_id=fid,
                                detail=f"hwid={self._hwid} dest={dest} bulk=True")
                saved += 1
            except AuthenticationError:
                errors.append(short + " (bütünlük hatası)")
            except Exception as exc:
                errors.append(f"{short} ({exc})")

        prog.setValue(len(file_ids))
        prog.close()

        msg = f"{saved} dosya kaydedildi:\n{save_dir}"
        if errors:
            preview = "\n".join(errors[:10])
            if len(errors) > 10:
                preview += f"\n… ve {len(errors) - 10} daha"
            msg += f"\n\nAtlanan ({len(errors)}):\n{preview}"
        QMessageBox.information(self, "İndirme Tamamlandı", msg)

    def _on_ctx_scan(self, row: int, file_id: int | None, filepath: str | None) -> None:
        if not filepath:
            QMessageBox.warning(self, "Tarama", "Dosya yolu bulunamadı.")
            return
        path = Path(filepath)
        if not path.exists():
            QMessageBox.warning(self, "Tarama", f"Dosya bulunamadı:\n{filepath}")
            return

        self._set_scan_badge(row, "⟳ Taranıyor...", "#D97706")
        worker = _ScanWorker(path, file_id or 0, row)
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(
            lambda r, res, fid=file_id: self._on_ctx_scan_done(r, res, fid)
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

    def _on_ctx_scan_done(self, row: int, result: ScanResult, file_id: int | None) -> None:
        text, color = _VERDICT_BADGE.get(result.verdict, ("—", "#9CA3AF"))
        if result.mock:
            text, color = text + " (m)", "#9CA3AF"
        self._set_scan_badge(row, text, color)
        if result.verdict == "malicious":
            QMessageBox.warning(self, "Zararlı Dosya",
                                "Tarama zararlı içerik tespit etti.\n"
                                "Dosya otomatik olarak İmha Odası'na taşınıyor.")
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
            db.log("file_label_changed", target_type="file", target_id=file_id,
                   detail=f"hwid={self._hwid} from=Karantina to={new_label} auto={auto}")
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        self._table.removeRow(row)
        if not auto:
            QMessageBox.information(self, "Taşındı", f"Dosya '{label_display}' etiketine taşındı.")

    def _on_ctx_move_to_kritik(self, row: int, file_id: int | None) -> None:
        if file_id is None:
            return
        fname_item = self._table.item(row, 0)
        fname = fname_item.text() if fname_item else "?"
        confirm = QMessageBox.question(
            self, "Kritik'e Taşı",
            f"'{fname}'\n\nDosya Kritik etiketine taşınacak.\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            db = DBManager()
            db.execute("UPDATE files SET label = 'Kritik' WHERE id = ?", (file_id,))
            db.log("file_label_changed", target_type="file", target_id=file_id,
                   detail=f"hwid={self._hwid} to=Kritik")
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))
            return
        self._table.removeRow(row)
        QMessageBox.information(self, "Taşındı", "Dosya Kritik etiketine taşındı.")

    def _on_ctx_move_to_imha(self, row: int, file_id: int | None) -> None:
        if file_id is None:
            return
        fname_item = self._table.item(row, 0)
        fname = fname_item.text() if fname_item else "?"
        confirm = QMessageBox.question(
            self, "İmha Odasına At",
            f"'{fname}'\n\nDosya İmha Odası'na taşınacak ve 24 saat içinde silinecek.\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=self._get_imha_ttl_hours())).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            db = DBManager()
            db.execute(
                "UPDATE files SET label = 'Imha', expires_at = ? WHERE id = ?",
                (expires_at, file_id),
            )
            db.log("file_moved_to_imha", target_type="file", target_id=file_id,
                   detail=f"hwid={self._hwid} expires_at={expires_at}")
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        self._table.removeRow(row)
        QMessageBox.information(self, "İmha Odasına Taşındı",
                                "Dosya İmha Odası'na taşındı. 24 saat içinde silinecek.")

    def _set_scan_badge(self, row: int, text: str, color: str) -> None:
        if row >= self._table.rowCount():
            return
        item = QTableWidgetItem(text)
        item.setForeground(QColor(color))
        item.setTextAlignment(Qt.AlignCenter)
        self._table.setItem(row, 4, item)

    # ── İmha Odası sayacı ─────────────────────────────────────────────────────

    def _tick_expiry(self) -> None:
        if self._current_label != "Imha":
            return
        now = datetime.now(timezone.utc)
        expired_rows: list[tuple[int, int | None, str]] = []
        min_remaining: float | None = None

        for row in range(self._table.rowCount()):
            name_item = self._table.item(row, 0)
            if name_item is None:
                continue
            expires_str: str    = name_item.data(Qt.UserRole + 4) or ""
            file_id: int | None = name_item.data(Qt.UserRole)
            filepath: str       = name_item.data(Qt.UserRole + 3) or ""

            if not expires_str:
                ci = self._table.item(row, 3)
                if ci:
                    ci.setText("—")
                continue

            try:
                expires_dt = datetime.strptime(expires_str, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                continue

            remaining = (expires_dt - now).total_seconds()
            if remaining <= 0:
                expired_rows.append((row, file_id, filepath))
                continue

            total_secs = int(remaining)
            hrs, rest  = divmod(total_secs, 3600)
            mins, secs = divmod(rest, 60)
            text = f"{hrs:02d}:{mins:02d}:{secs:02d}"

            color = (
                self._T["red"]    if remaining < 600  else
                self._T["yellow"] if remaining < 3600 else
                self._T["green"]
            )
            ci = self._table.item(row, 3)
            if ci:
                ci.setText(text)
                ci.setForeground(QColor(color))

            if min_remaining is None or remaining < min_remaining:
                min_remaining = remaining

        for row, file_id, filepath in sorted(expired_rows, key=lambda t: t[0], reverse=True):
            self._table.removeRow(row)
            self._purge_expired_file(file_id, filepath)

        if min_remaining is not None:
            total_secs = int(min_remaining)
            hrs, rest  = divmod(total_secs, 3600)
            mins, secs = divmod(rest, 60)
            color = (
                self._T["red"]    if min_remaining < 600  else
                self._T["yellow"] if min_remaining < 3600 else
                self._T["green"]
            )
            self._expiry_banner.setText(f"⏱  En yakın imha: {hrs:02d}:{mins:02d}:{secs:02d}")
            self._expiry_banner.setStyleSheet(
                f"color:{color}; font-size:13px; font-weight:600;"
                f"background:{self._T['sidebar']}; border-radius:8px; padding:4px 12px;"
                f"margin:4px 12px 0;"
            )
        elif self._table.rowCount() == 0:
            self._expiry_banner.setText("İmha Odası boş")
            self._expiry_banner.setStyleSheet(
                f"color:{self._T['subtext']}; font-size:13px;"
                f"background:{self._T['sidebar']}; border-radius:8px; padding:4px 12px;"
                f"margin:4px 12px 0;"
            )
        else:
            self._expiry_banner.setText("Süre belirlenmemiş dosyalar")
            self._expiry_banner.setStyleSheet(
                f"color:{self._T['subtext']}; font-size:13px;"
                f"background:{self._T['sidebar']}; border-radius:8px; padding:4px 12px;"
                f"margin:4px 12px 0;"
            )

    def _purge_expired_file(self, file_id: int | None, filepath: str) -> None:
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
                db.log("expired_purge", target_type="file", target_id=file_id,
                       detail=f"label=Imha filepath={filepath}")
            except Exception:
                pass

    def _get_imha_ttl_hours(self) -> int:
        try:
            return int(DBManager().get_setting("imha_ttl_hours", "24"))
        except Exception:
            return 24

    def _refresh_usb_badge(self) -> None:
        hwid = get_usb_hwid()
        if hwid:
            self._usb_badge.setText(
                f'<span style="color:#059669; font-size:14px;">●</span>'
                f' <span style="color:#6B7280; font-size:12px;">USB: {hwid[:8]}</span>'
            )
        else:
            self._usb_badge.setText(
                f'<span style="color:#DC2626; font-size:14px;">●</span>'
                f' <span style="color:#6B7280; font-size:12px;">USB Yok</span>'
            )

    @staticmethod
    def _fmt_size(size_bytes: int) -> str:
        size: float = float(size_bytes)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
