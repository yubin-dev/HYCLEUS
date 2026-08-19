import logging
# timedelta modül seviyesinde artık kullanılmıyor: "şimdi + TTL" hesabı
# CORE/expiry.py'ye taşındı. _FileRunnable.run() kendi yerel import'unu
# yapıyor (worker thread'inde çalışıyor, bkz. satır ~218).
from pathlib import Path

_log = logging.getLogger("hycleus.ui")

from PySide6.QtCore import (
    QObject,
    QThread,
    QThreadPool,
    Qt,
    QTimer,
)

from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QGraphicsBlurEffect,
    QInputDialog,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
)


from CORE.file_queries import (
    files_by_label,
    search_files,
)
from CORE.idle_lock import (
    DEFAULT_IDLE_MINUTES,
    IdleTracker,
)
from CORE.roles import (
    can_write as rol_yazabilir,
    display_role,
    is_admin_role,
)
from CORE.usb_manager import get_usb_hwid
from CORE.version import surum_etiketi
from CORE.vault_manager import (
    blacklist_usb,
)
from DB.db_manager import DBManager
from UI.main_window_bulk import BulkActionsMixin
from UI.main_window_files import FileActionsMixin
from UI.main_window_layout import LayoutMixin
from UI.main_window_lock import LockMixin, _LockOverlay
from UI.main_window_open import BackupMixin, OpenMixin
from UI.main_window_palette import _DARK, _SIDEBAR_NAV
from UI.main_window_table import TableMixin, _ProcessSignals
from UI.main_window_theme import ThemeMixin
from UI.main_window_tree import TreeMixin
from UI.AdminPanel import AdminPanel
from UI.AuditLogDialog import AuditLogDialog



# ── Ana pencere ───────────────────────────────────────────────────────────────

class HycleusWindow(
    LayoutMixin,
    ThemeMixin,
    TreeMixin,
    TableMixin,
    FileActionsMixin,
    BulkActionsMixin,
    OpenMixin,
    BackupMixin,
    LockMixin,
    QMainWindow,
):
    """
    HYCLEUS ana penceresi.

    Davranışın büyük kısmı mixin'lerde (UI/main_window_*.py). Bu sınıfta
    yalnızca kurulum, rol kısıtlamaları, üst menü eylemleri ve etiket
    gezinmesi kaldı.

    MRO SIRASI ÖNEMLİ: QMainWindow EN SONDA. Qt geri çağrımlarını
    (resizeEvent, dropEvent, eventFilter) mixin'ler geçersiz kılıyor;
    QMainWindow önde olsaydı onun varsayılan uygulamaları kazanır ve
    sürükle-bırak ile hareketsizlik kilidi SESSİZCE çalışmaz hâle
    gelirdi — istisna da fırlamazdı.
    """

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
        # Kilit nedenleri kümesi — biri kalkınca diğeri düşmesin (bkz. _unlock)
        self._lock_reasons: set[str] = set()
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

        # Hareketsizlik kilidi. Sayaç uygulama genelindeki olaylardan
        # besleniyor (eventFilter), kararı saniyelik tik veriyor (_tick_idle).
        self._idle = IdleTracker.from_minutes(DEFAULT_IDLE_MINUTES)
        self.reload_idle_timeout()
        self._overlay.clicked.connect(self._on_overlay_clicked)
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self)

        self._idle_timer = QTimer(self)
        self._idle_timer.setInterval(1000)
        self._idle_timer.timeout.connect(self._tick_idle)
        self._idle_timer.start()

        # Şeffaf erişim: açık belgelerin kaydı + dosya izleyici.
        self._init_checkout()

        self._refresh_usb_badge()
        self._on_sidebar_click("Genel", self._nav_btns["Genel"])
        self._refresh_tag_sidebar()
        self._refresh_folder_sidebar()


    def closeEvent(self, event) -> None:
        """
        Kapanışta açık belgeleri geri şifreler ve geçici kopyaları siler.

        SIRALAMA KRİTİK. `main.py` kapanışta `purge_on_exit()` çağırıyor ve
        o, SafeZone'daki HER dosyayı güvenli siliyor. Geri yazma ondan
        SONRA olsaydı ya da hiç olmasaydı, kullanıcının düzenlemesi
        sessizce yok edilirdi — dosya silinir, `.hcl` eski hâlinde kalır
        ve hiçbir hata görünmezdi.

        `closeEvent` pencere kapanırken, `aboutToQuit` ondan sonra
        çalışıyor; yani check-in temizlikten önce yapılmış oluyor. Bu
        bağımlılık ikisi arasında yazılı bir sözleşme değil, Qt'nin olay
        sırası — bu yüzden burada açıkça belirtiliyor.
        """
        try:
            self._close_all_checkouts(reason="shutdown")
        except Exception as exc:
            _log.error("kapanis check-in basarisiz: %s", exc)
        super().closeEvent(event)

    # ── Rol kısıtlamaları ─────────────────────────────────────────────────────

    def _apply_role_restrictions(self) -> None:
        _log.debug("apply_role_restrictions  role=%r", self._role)
        # Rol kararları TEK yerden: CORE/roles.py (B-028).
        #
        # `is_readonly` ara değişkeni KALDIRILDI: tek kullanıcısı
        # `can_write = not is_readonly` idi ve o hesap artık `can_write()`
        # içinde. Bırakılsaydı "salt okunur mu" sorusunun İKİNCİ bir
        # cevabı burada durmaya devam ederdi — düzeltilen şeyin ta kendisi.
        is_admin  = is_admin_role(self._role)
        can_write = rol_yazabilir(self._role)

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

        self._role_badge.setText(display_role(self._role))

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
        if not is_admin_role(self._role):
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
        act_backup  = menu.addAction("💾  Yedek Al…")
        # Doğrulama, almanın hemen yanında: hiç doğrulanmayan bir yedek,
        # olmayan bir yedektir ve iki işi ayrı yerlere koymak ikincisini
        # bulunmaz yapardı. GERİ YÜKLEME menüye GİRMİYOR — bilinçli,
        # gerekçesi `UI/main_window_open.py::BackupMixin` docstring'inde.
        act_verify_backup = menu.addAction("🔍  Yedek Doğrula…")
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
        elif action == act_backup:
            self._on_create_backup()
        elif action == act_verify_backup:
            self._on_verify_backup()
        elif action == act_about:
            QMessageBox.information(
                self, "HYCLEUS — Hakkında",
                # Sürüm tek kaynaktan: CORE/version.py (BACKLOG B-017).
                # Elle yazılan dize buraya geri getirilmemeli — bildirimci
                # "etkilenen sürüm"ü buradan okuyor (SECURITY.md §6.3).
                f"{surum_etiketi()}\n"
                "Güvenli Dosya Yönetim Sistemi\n\n"
                "Kriptografi: AES-256-GCM + Argon2id\n"
                "Shamir Secret Sharing (2-of-3)\n\n"
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

        display = next((d for _, d, etiket in _SIDEBAR_NAV if etiket == db_label), db_label)
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

        try:
            rows = files_by_label(
                DBManager(), db_label, include_private=is_admin_role(self._role)
            )
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı", str(exc))
            return
        self._populate_table(rows)


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
            rows = search_files(
                DBManager(), term, include_private=is_admin_role(self._role)
            )
        except Exception as exc:
            QMessageBox.warning(self, "Arama", str(exc))
            return
        self._populate_table(rows)


    # ── Kilit — iki tetikleyici, tek örtü ─────────────────────────────────────
    #
    # Kilit NEDENLERİ bir küme olarak tutuluyor. Tek bir _locked bayrağı
    # yeterli değildi: hareketsizlik kilidi devredeyken USB de çekilse ve
    # sonra USB geri takılsa, _poll_usb'nin çağırdığı _unlock() hareketsizlik
    # kilidini de kaldırırdı — yani ekrandan uzaktaki kullanıcının oturumu
    # USB'yi takan kişiye açılırdı. Küme boşalmadan örtü kalkmıyor.

    _LOCK_MESSAGES = {
        "usb": ("USB Token Çıkarıldı", "Lütfen USB'yi yeniden takın"),
        "idle": ("Oturum Kilitlendi", "Hareketsizlik nedeniyle — devam etmek için PIN girin"),
    }


