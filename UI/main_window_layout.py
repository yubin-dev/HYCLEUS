"""
HYCLEUS — Pencere iskeleti — üst bar, eylem barı, kenar çubuğu, içerik

UI/main_window.py'den 2.7 refactor'ünde ayrıldı. Metot gövdeleri
kelimesi kelimesine taşındı; davranış değişmedi.

`HycleusWindow` bu mixin'i miras alıyor, dolayısıyla `self` hâlâ
pencerenin kendisi ve çağrı yerleri değişmedi.
"""
import logging
# timedelta modül seviyesinde artık kullanılmıyor: "şimdi + TTL" hesabı
# CORE/expiry.py'ye taşındı. _FileRunnable.run() kendi yerel import'unu
# yapıyor (worker thread'inde çalışıyor, bkz. satır ~218).

_log = logging.getLogger("hycleus.ui")

from PySide6.QtCore import (
    QEvent,
    Qt,
)

# Hareketsizlik sayacını sıfırlayan olaylar. Yalnızca GERÇEK kullanıcı
# etkileşimi: zamanlayıcı tik'leri, boyama ve pencere olayları buraya
# GİRMEZ — girseydi ekranda dönen bir ilerleme çubuğu bile oturumu sonsuza
# kadar açık tutardı.
_ACTIVITY_EVENTS = frozenset({
    QEvent.MouseButtonPress,
    QEvent.MouseButtonRelease,
    QEvent.MouseButtonDblClick,
    QEvent.MouseMove,
    QEvent.KeyPress,
    QEvent.KeyRelease,
    QEvent.Wheel,
    QEvent.TouchBegin,
    QEvent.TouchUpdate,
})
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)



from UI.GuvenlikView import SAYFA_ADI as _GUVENLIK_SAYFA_ADI
from UI.main_window_palette import (
    _SIDEBAR_NAV,
)


class LayoutMixin:
    """Pencere iskeleti — üst bar, eylem barı, kenar çubuğu, içerik."""

    # ── UI kurulumu ───────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("central_root")
        self.setCentralWidget(central)

        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._make_top_bar())
        self._action_bar = self._make_action_bar()
        root.addWidget(self._action_bar)

        body = QWidget()
        body.setObjectName("body")
        body_h = QHBoxLayout(body)
        body_h.setContentsMargins(0, 0, 0, 0)
        body_h.setSpacing(0)
        body_h.addWidget(self._make_sidebar())
        body_h.addWidget(self._make_govde_yigini(), 1)
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

        # ── Güvenlik ─────────────────────────────────────────────────────
        # Dosya gezinme düğmelerinden AYRI bir bölüm: bu bir etiket
        # filtresi değil, ayrı bir görünüm. Aynı listeye konsaydı
        # `_on_sidebar_click` onu bir `db_label` sanardı.
        guvenlik_lbl = QLabel("GÜVENLİK")
        guvenlik_lbl.setObjectName("nav_section_label")
        lay.addWidget(guvenlik_lbl)

        self._guvenlik_btn = QPushButton(f"   🛡   {_GUVENLIK_SAYFA_ADI}")
        self._guvenlik_btn.setFixedHeight(44)
        self._guvenlik_btn.setCursor(Qt.PointingHandCursor)
        self._guvenlik_btn.setObjectName("nav_guvenlik")
        self._guvenlik_btn.clicked.connect(self._on_guvenlik_click)
        lay.addWidget(self._guvenlik_btn)

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

    def _make_govde_yigini(self) -> QWidget:
        """
        İçerik alanı artık İKİ SAYFALI: dosya görünümü + Güvenlik.

        `QStackedWidget` seçildi, ikinci bir pencere değil: tablo, arama
        çubuğu ve seçim durumu YERİNDE kalıyor. Güvenlik sayfasından dosya
        görünümüne dönen kullanıcı, bıraktığı yeri buluyor — ayrı bir
        pencere olsaydı ya durum kopyalanır ya kaybolurdu.
        """
        from UI.GuvenlikView import GuvenlikView

        self._govde_yigini = QStackedWidget()
        self._govde_yigini.addWidget(self._make_content())      # 0 — dosyalar
        self._guvenlik_view = GuvenlikView(self)
        self._govde_yigini.addWidget(self._guvenlik_view)       # 1 — güvenlik
        return self._govde_yigini

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

