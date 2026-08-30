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
    QEasingCurve,
    QEvent,
    QPropertyAnimation,
    QRect,
    Qt,
    Signal,
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



from UI.AdminSettingsView import SAYFA_ADI as _ADMIN_SETTINGS_SAYFA_ADI
from UI.AuditLogView import SAYFA_ADI as _AUDIT_SAYFA_ADI
from UI.GuvenlikView import SAYFA_ADI as _GUVENLIK_SAYFA_ADI
from UI.PendingRegistrationsView import SAYFA_ADI as _PENDING_SAYFA_ADI
from UI.UsbTokensView import SAYFA_ADI as _USB_TOKENS_SAYFA_ADI
from UI.main_window_palette import (
    _SIDEBAR_NAV,
)


#: Slide-over panelinin hedef genişliği. Pencere bundan darsa (testlerde
#: `.resize()` hiç çağrılmamışsa, ya da gerçekten dar bir ekranda) panel
#: pencere genişliğine düşer — bkz. `LayoutMixin._slide_over_genislik()`.
_SLIDE_OVER_GENISLIK = 440


class _SlideOverPanel(QFrame):
    """
    Doğrulama/ayar ekranlarının ORTAK gövdesi (tasarım brief'i: "doğrulama
    ve ayar ekranları slide-over panel veya inline sekme olarak açılır,
    yeni pencere açmaz").

    Bu sınıf o panelin TEK uygulaması — her ekran kendi pencere/diyalog
    çözümünü yazmasın diye. Yalnızca ÇERÇEVE burada: başlık çubuğu, kapat
    düğmesi, içerik yuvası. Doğrulama/ayar MANTIĞI yok; `TimestampDialog`,
    `BackupVerifyDialog` gibi içerik widget'ları kendi dosyalarında kalıp
    yalnızca buraya YERLEŞİYOR (bkz. `LayoutMixin._open_slide_over`).
    """

    kapandi = Signal()

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setObjectName("slide_over_panel")
        self.setFocusPolicy(Qt.StrongFocus)
        self._icerik: QWidget | None = None

        dis = QVBoxLayout(self)
        dis.setContentsMargins(0, 0, 0, 0)
        dis.setSpacing(0)

        baslik_cubugu = QFrame()
        baslik_cubugu.setObjectName("slide_over_baslik_cubugu")
        baslik_cubugu.setFixedHeight(52)
        bc = QHBoxLayout(baslik_cubugu)
        bc.setContentsMargins(20, 0, 12, 0)
        bc.setSpacing(8)

        self._baslik_etiketi = QLabel()
        self._baslik_etiketi.setObjectName("slide_over_baslik_etiketi")
        bc.addWidget(self._baslik_etiketi, 1)

        kapat_btn = QPushButton("✕")
        kapat_btn.setObjectName("slide_over_kapat")
        kapat_btn.setFixedSize(32, 32)
        kapat_btn.setCursor(Qt.PointingHandCursor)
        kapat_btn.clicked.connect(self.kapandi.emit)
        bc.addWidget(kapat_btn)

        dis.addWidget(baslik_cubugu)

        self._icerik_yeri = QVBoxLayout()
        self._icerik_yeri.setContentsMargins(0, 0, 0, 0)
        self._icerik_yeri.setSpacing(0)
        dis.addLayout(self._icerik_yeri, 1)

    def baslik_ayarla(self, metin: str) -> None:
        self._baslik_etiketi.setText(metin)

    def icerik_ayarla(self, icerik: QWidget) -> QWidget | None:
        """Eski içeriği yuvadan çıkarır, yeniyi yerleştirir — eskisini döndürür."""
        eski = self._icerik
        if eski is not None:
            self._icerik_yeri.removeWidget(eski)
            eski.setParent(None)
        self._icerik = icerik
        self._icerik_yeri.addWidget(icerik)
        return eski

    def stil_uygula(self, T: dict[str, str]) -> None:
        """
        Panel `central_root`'un DIŞINDA (bkz. `LayoutMixin._open_slide_over`
        docstring'i) — tema QSS kaskadı (`main_window_theme.py::_apply_theme`,
        yalnızca `centralWidget()`'a uygulanıyor) buraya ULAŞMIYOR.
        `UI/main_window_lock.py::_LockOverlay` ile aynı durum: kendi
        stilini kendisi taşıyor.
        """
        self.setStyleSheet(
            f"QFrame#slide_over_panel {{ background: {T['sidebar']};"
            f" border-left: 1px solid {T['border']}; }}"
            f"QFrame#slide_over_baslik_cubugu {{ background: {T['topbar']};"
            f" border-bottom: 1px solid {T['border']}; }}"
            f"QLabel#slide_over_baslik_etiketi {{ color: {T['text']};"
            f" font-size: 14px; font-weight: bold; background: transparent; }}"
            f"QPushButton#slide_over_kapat {{ background: transparent;"
            f" color: {T['subtext']}; border: none; border-radius: 6px;"
            f" font-size: 14px; }}"
            f"QPushButton#slide_over_kapat:hover {{ background: {T['hover']};"
            f" color: {T['text']}; }}"
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
        self._theme_btn.setToolTip("Sol tık: Gündüz / Gece · Sağ tık: Tema seç")
        self._theme_btn.clicked.connect(self._toggle_theme)
        self._theme_btn.setContextMenuPolicy(Qt.CustomContextMenu)
        self._theme_btn.customContextMenuRequested.connect(lambda _pos: self._on_theme_menu())
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

        self._audit_log_btn = QPushButton(f"  📋  {_AUDIT_SAYFA_ADI}")
        self._audit_log_btn.setObjectName("admin_btn")
        self._audit_log_btn.setFixedHeight(40)
        self._audit_log_btn.setCursor(Qt.PointingHandCursor)
        self._audit_log_btn.clicked.connect(self._on_open_audit_log)
        lay.addWidget(self._audit_log_btn)

        self._usb_tokens_btn = QPushButton(f"  🔌  {_USB_TOKENS_SAYFA_ADI}")
        self._usb_tokens_btn.setObjectName("admin_btn")
        self._usb_tokens_btn.setFixedHeight(40)
        self._usb_tokens_btn.setCursor(Qt.PointingHandCursor)
        self._usb_tokens_btn.clicked.connect(self._on_open_usb_tokens)
        lay.addWidget(self._usb_tokens_btn)

        self._pending_btn = QPushButton(f"  📥  {_PENDING_SAYFA_ADI}")
        self._pending_btn.setObjectName("admin_btn")
        self._pending_btn.setFixedHeight(40)
        self._pending_btn.setCursor(Qt.PointingHandCursor)
        self._pending_btn.clicked.connect(self._on_open_pending)
        lay.addWidget(self._pending_btn)

        self._admin_settings_btn = QPushButton(f"  ⚙  {_ADMIN_SETTINGS_SAYFA_ADI}")
        self._admin_settings_btn.setObjectName("admin_btn")
        self._admin_settings_btn.setFixedHeight(40)
        self._admin_settings_btn.setCursor(Qt.PointingHandCursor)
        self._admin_settings_btn.clicked.connect(self._on_open_admin_settings)
        lay.addWidget(self._admin_settings_btn)

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
        İçerik alanı artık YEDİ SAYFALI: dosya görünümü + Güvenlik +
        Denetim Günlüğü + Profil + USB Tokenlar + Bekleyen Kayıtlar +
        Ayarlar.

        `QStackedWidget` seçildi, ikinci bir pencere değil: tablo, arama
        çubuğu ve seçim durumu YERİNDE kalıyor. Güvenlik ya da Denetim
        Günlüğü'nden dosya görünümüne dönen kullanıcı, bıraktığı yeri
        buluyor — ayrı bir pencere olsaydı ya durum kopyalanır ya
        kaybolurdu. Denetim Günlüğü ESKİDEN (`UI/AuditLogDialog.py`,
        kaldırıldı) modal bir `QDialog`'du — aynı gerekçeyle buraya
        taşındı. Profil de AYNI gerekçeyle: eskiden (`UI/ProfileDialog.py`,
        kaldırıldı) modal bir `QDialog`'du, artık `UI/ProfileView.py`.

        USB Yönetim Paneli (eskiden `UI/AdminPanel.py`, kaldırıldı) AYNI
        gerekçeyle üçe bölünerek buraya taşındı — tek bir modal
        `QTabWidget` yerine üç ayrı sayfa/kenar çubuğu girişi (`UI/
        UsbTokensView.py`, `UI/PendingRegistrationsView.py`, `UI/
        AdminSettingsView.py`). Paylaşılan stil/yetki kodu ve "neden üç
        AYRI sayfa" gerekçesi `UI/admin_common.py`'nin modül
        docstring'inde.
        """
        from UI.AdminSettingsView import AdminSettingsView
        from UI.AuditLogView import AuditLogView
        from UI.GuvenlikView import GuvenlikView
        from UI.PendingRegistrationsView import PendingRegistrationsView
        from UI.ProfileView import ProfileView
        from UI.UsbTokensView import UsbTokensView

        self._govde_yigini = QStackedWidget()
        self._govde_yigini.addWidget(self._make_content())      # 0 — dosyalar
        self._guvenlik_view = GuvenlikView(self)
        self._govde_yigini.addWidget(self._guvenlik_view)       # 1 — güvenlik
        self._audit_log_view = AuditLogView(self)
        self._govde_yigini.addWidget(self._audit_log_view)      # 2 — denetim günlüğü
        self._profil_view = ProfileView(self)
        self._govde_yigini.addWidget(self._profil_view)         # 3 — profil
        self._usb_tokens_view = UsbTokensView(self)
        self._govde_yigini.addWidget(self._usb_tokens_view)     # 4 — USB tokenlar
        self._pending_view = PendingRegistrationsView(self)
        self._govde_yigini.addWidget(self._pending_view)        # 5 — bekleyen kayıtlar
        self._admin_settings_view = AdminSettingsView(self)
        self._govde_yigini.addWidget(self._admin_settings_view)  # 6 — ayarlar
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

        # Toplu işlem çubuğu — 1+ dosya kutucuğu işaretlenince görünür.
        # Gövdesi burada YOK: dördü de UI/main_window_bulk.py'nin ZATEN
        # var olan sağ-tık menüsü işleyicilerini çağırıyor (bkz. o
        # dosyanın modül docstring'i) — kutucuklar ikinci bir uygulama
        # DEĞİL, aynı gövdeye giden ikinci bir giriş noktası.
        lay.addWidget(self._make_bulk_toolbar())

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
        # `itemChanged` sütun 0'ın kutucuk durumu DAHİL her veri
        # değişiminde ateşleniyor (satır ekleme/tarama rozeti dahil) —
        # `_on_table_item_changed()` yalnızca sayıyor, ucuz bir işlem,
        # bu yüzden fazladan tetiklenmesi zararsız.
        self._table.itemChanged.connect(self._on_table_item_changed)
        lay.addWidget(self._table, 1)

        # Drag-drop alanı
        self._drop_hint = QLabel("Dosyaları buraya sürükleyin — otomatik karantinaya alınır")
        self._drop_hint.setObjectName("drop_hint")
        self._drop_hint.setAlignment(Qt.AlignCenter)
        self._drop_hint.setFixedHeight(64)
        lay.addWidget(self._drop_hint)

        return frame

    def _make_bulk_toolbar(self) -> QWidget:
        """
        Toplu işlem çubuğu — 1+ dosya kutucuğu işaretliyken görünür.

        Dördü de `UI/main_window_bulk.py`'nin ZATEN var olan sağ-tık
        menüsü gövdelerini çağırıyor (`_on_ctx_bulk_assign_tags`/
        `_move_to_kritik`/`_download`/`_move_to_imha`) — burada YENİ bir
        toplu işlem UYGULANMIYOR, yalnızca aynı gövdeye giden ikinci bir
        giriş noktası açılıyor (bkz. o dosyanın `_on_bulk_toolbar_*`
        metotları). "Karantinadan Çıkar" BİLİNÇLİ olarak burada YOK: o
        yalnızca Karantina etiketindeki dosyalar için anlamlı ve mockup
        onu istemedi; sağ-tık menüsü hâlâ sunuyor.
        """
        cubuk = QWidget()
        cubuk.setObjectName("bulk_toolbar")
        cubuk.setFixedHeight(44)
        cubuk.setVisible(False)

        bh = QHBoxLayout(cubuk)
        bh.setContentsMargins(16, 0, 16, 0)
        bh.setSpacing(10)

        self._bulk_toolbar = cubuk
        self._bulk_toolbar_label = QLabel("")
        self._bulk_toolbar_label.setObjectName("bulk_toolbar_label")
        bh.addWidget(self._bulk_toolbar_label)
        bh.addStretch(1)

        self._btn_bulk_tags = QPushButton("🏷  Etiket Ata")
        self._btn_bulk_tags.setObjectName("bulk_btn_tags")
        self._btn_bulk_tags.setCursor(Qt.PointingHandCursor)
        self._btn_bulk_tags.clicked.connect(self._on_bulk_toolbar_tags)
        bh.addWidget(self._btn_bulk_tags)

        self._btn_bulk_kritik = QPushButton("🛡  Kritik'e Taşı")
        self._btn_bulk_kritik.setObjectName("bulk_btn_kritik")
        self._btn_bulk_kritik.setCursor(Qt.PointingHandCursor)
        self._btn_bulk_kritik.clicked.connect(self._on_bulk_toolbar_kritik)
        bh.addWidget(self._btn_bulk_kritik)

        self._btn_bulk_download = QPushButton("⬇  İndir")
        self._btn_bulk_download.setObjectName("bulk_btn_download")
        self._btn_bulk_download.setCursor(Qt.PointingHandCursor)
        self._btn_bulk_download.clicked.connect(self._on_bulk_toolbar_download)
        bh.addWidget(self._btn_bulk_download)

        self._btn_bulk_imha = QPushButton("🔥  İmhaya At")
        self._btn_bulk_imha.setObjectName("bulk_btn_imha")
        self._btn_bulk_imha.setCursor(Qt.PointingHandCursor)
        self._btn_bulk_imha.clicked.connect(self._on_bulk_toolbar_imha)
        bh.addWidget(self._btn_bulk_imha)

        return cubuk

    # ── Slide-over paneli — doğrulama/ayar ekranlarının ORTAK mekanizması ──────
    #
    # Tasarım brief'i: "doğrulama ve ayar ekranları slide-over panel veya
    # inline sekme olarak açılır, yeni pencere açmaz." Bu turda YALNIZCA
    # `TimestampDialog` ve `BackupVerifyDialog` buraya taşındı.
    #
    # USB Yönetim Paneli (eskiden AdminPanel, üç sekmeli tek bir modal)
    # BİLEREK dışarıda kaldı — en karmaşık ekrandı, kendi turunu hak etti
    # ve sonunda slide-over'a değil tam sayfaya (üç ayrı sayfaya) taşındı
    # (bkz. `UI/admin_common.py`). `RecoveryShareDialog` BİLEREK modal
    # KALIYOR — tek
    # gösterimlik, dikkat gerektiren bir akış; slide-over'a taşımak
    # "yanlışlıkla kapatma" riskini artırırdı (tasarım brief'i Karar 4 de
    # onu modal tarif ediyor).

    def _ensure_slide_over(self) -> None:
        """Panel/scrim'i TEMBEL kurar — hiçbir ekran açılmadıysa hiç var olmazlar."""
        if getattr(self, "_slide_over", None) is not None:
            return

        # `panel.isVisible()` GÜVENİLMEZ: ana pencere henüz `.show()`
        # edilmediyse (kurulum sırası, testler) tüm alt widget'lar `False`
        # döner — `main_window_lock.py::LockMixin`'in `self._overlay.isVisible()`
        # yerine `self._locked` bool'u tutmasıyla AYNI sebep. Açık/kapalı
        # durumu kendi bayrağımızla tutuyoruz.
        self._slide_over_open: bool = False

        # Avatar düğmesiyle AYNI desen (bkz. `_make_top_bar`): tek tıklamalık
        # bir davranış için ayrı bir sınıf açmak yerine örnek metoda atama.
        self._slide_over_scrim = QWidget(self)
        self._slide_over_scrim.setObjectName("slide_over_scrim")
        self._slide_over_scrim.setStyleSheet("background: rgba(0, 0, 0, 0.35);")
        self._slide_over_scrim.setVisible(False)
        self._slide_over_scrim.mousePressEvent = lambda _e: self._close_slide_over()

        self._slide_over = _SlideOverPanel(self)
        self._slide_over.setVisible(False)
        self._slide_over.kapandi.connect(self._close_slide_over)
        if hasattr(self, "_T"):
            self._slide_over.stil_uygula(self._T)

        self._slide_over_anim = QPropertyAnimation(self._slide_over, b"geometry", self)
        self._slide_over_anim.setDuration(180)
        self._slide_over_anim.setEasingCurve(QEasingCurve.OutCubic)

    def _slide_over_acik(self) -> bool:
        """
        `main_window_lock.py::LockMixin._unlock()`'un da sorduğu soru: panel
        şu an ekranda mı. İKİ ayrı sistem `centralWidget()`'ı devre dışı
        bırakıyor (kilit ve bu panel) — biri kapanırken diğerinin hâlâ açık
        olup olmadığını bilmesi gerekiyor, yoksa biri diğerinin korumasını
        (ya da engelini) sessizce kaldırır.
        """
        return getattr(self, "_slide_over_open", False)

    def _slide_over_genislik(self) -> int:
        return min(_SLIDE_OVER_GENISLIK, max(240, self.width()))

    def _konumla_slide_over(self) -> None:
        """Pencere yeniden boyutlanınca panel/scrim'i yeniden yerleştirir."""
        if not self._slide_over_acik():
            return
        self._slide_over_scrim.setGeometry(self.rect())
        genislik = self._slide_over_genislik()
        self._slide_over.setGeometry(self.width() - genislik, 0, genislik, self.height())

    def _open_slide_over(self, baslik: str, icerik: QWidget) -> None:
        """
        Doğrulama/ayar ekranlarının AÇILDIĞI TEK yer.

        `icerik` zaten kurulmuş bir `QWidget` — kendi penceresini AÇMAZ,
        yalnızca burada GÖRÜNÜR olur. `icerik`'in bir `kapat_istendi`
        sinyali varsa (`TimestampDialog`, `BackupVerifyDialog`) otomatik
        bağlanır: içeriğin kendi "Kapat" düğmesi de paneli kapatabilsin diye.

        Ana pencere etkileşimi `centralWidget().setEnabled(False)` ile
        kilitleniyor. Panel/scrim `self`'İN DOĞRUDAN çocuğu — `central`'ın
        değil — o yüzden devre dışı bırakma panelin/scrim'in KENDİSİNİ
        etkilemiyor. Bu, aynı `centralWidget`'ı kilit mekanizmasıyla
        (`main_window_lock.py`) PAYLAŞTIĞI anlamına geliyor; hangisinin ne
        zaman geri AÇACAĞI `_slide_over_acik()` / `self._locked` ile
        karşılıklı kontrol ediliyor (bkz. `_close_slide_over` ve
        `LockMixin._unlock`) — aksi hâlde biri diğerinin kilidini/panelini
        sessizce açardı.

        Kilit AKTİFKEN hiç çağrılmaz: central devre dışıyken kullanıcı bu
        metoda giden hiçbir düğmeye (sağ tık menüsü, Güvenlik sekmesi)
        zaten tıklayamıyor. Yine de tek satırlık bir koruma var — z-sırası
        yarışına (panel, kilit örtüsünün ÜSTÜNE çıkar) hiç girmesin diye.
        """
        if getattr(self, "_locked", False):
            return

        self._ensure_slide_over()
        eski = self._slide_over.icerik_ayarla(icerik)
        if eski is not None:
            eski.deleteLater()
        self._slide_over.baslik_ayarla(baslik)

        kapat_istendi = getattr(icerik, "kapat_istendi", None)
        if kapat_istendi is not None:
            kapat_istendi.connect(self._close_slide_over)

        central = self.centralWidget()
        if central is not None:
            central.setEnabled(False)

        genislik = self._slide_over_genislik()
        self._slide_over_scrim.setGeometry(self.rect())
        self._slide_over_scrim.setVisible(True)
        self._slide_over_scrim.raise_()

        baslangic = QRect(self.width(), 0, genislik, self.height())
        bitis = QRect(self.width() - genislik, 0, genislik, self.height())
        self._slide_over.setGeometry(baslangic)
        self._slide_over.setVisible(True)
        self._slide_over.raise_()
        self._slide_over.setFocus()

        self._slide_over_anim.stop()
        self._slide_over_anim.setStartValue(baslangic)
        self._slide_over_anim.setEndValue(bitis)
        self._slide_over_anim.start()
        self._slide_over_open = True

    def _close_slide_over(self) -> None:
        if not self._slide_over_acik():
            return
        self._slide_over_open = False
        self._slide_over_anim.stop()
        self._slide_over.setVisible(False)
        self._slide_over_scrim.setVisible(False)

        # Kilit hâlâ AKTİFSE (USB/hareketsizlik) central'ı AÇMA — o korumayı
        # `LockMixin._unlock()` yönetiyor, burası kaldırmıyor (bkz.
        # `_open_slide_over` docstring'i).
        central = self.centralWidget()
        if central is not None and not getattr(self, "_locked", False):
            central.setEnabled(True)

    def eventFilter(self, obj, event):
        """
        Uygulama genelinde Esc'i yakalar — panel açıksa kapatır.

        `main_window_lock.py::LockMixin.eventFilter` ile AYNI tek filtre
        zincirine kurulu (bkz. `main_window.py`'deki tek
        `installEventFilter` çağrısı ve sınıfın MRO sırası). Olay
        YUTULMUYOR — yalnızca kapatıp `super()`'a devrediyor, hareketsizlik
        sayacı Esc'i yine ETKİNLİK olarak görsün diye.
        """
        if (
            event.type() == QEvent.KeyPress
            and event.key() == Qt.Key_Escape
            and self._slide_over_acik()
        ):
            self._close_slide_over()
        return super().eventFilter(obj, event)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._konumla_slide_over()

