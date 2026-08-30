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


from CORE.app_mode import KURUMSAL, get_app_mode, is_bireysel
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
from CORE.rehber import MENU_ETIKETI as _REHBER_ETIKETI
from CORE.rehber import erisim_yolu as _rehber_erisim_yolu
from CORE.tpm_sealing import durum as tpm_durum
from CORE.usb_manager import get_usb_hwid
from UI.AdminSettingsView import SAYFA_ADI as _ADMIN_SETTINGS_SAYFA_ADI
from UI.AuditLogView import SAYFA_ADI as _AUDIT_SAYFA_ADI
from UI.GuvenlikView import (
    GUVENLIK_SALT_OKUNURA_ACIK,
    SAYFA_ADI as _GUVENLIK_SAYFA_ADI,
)
from UI.PendingRegistrationsView import SAYFA_ADI as _PENDING_SAYFA_ADI
from UI.ProfileView import SAYFA_ADI as _PROFIL_SAYFA_ADI
from UI.UsbTokensView import SAYFA_ADI as _USB_TOKENS_SAYFA_ADI
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
        # "revoked" kilidinin DB'den gelen dinamik sebebi (B-064/B-066) —
        # bkz. LockMixin._poll_usb / _lock.
        self._revoked_reason: str = ""
        self._authenticating     = False
        self._threads: list[QThread]  = []
        self._workers: list[QObject]  = []
        self._dark: bool         = True
        self._theme_key: str     = "mavi"
        # Bireysel/Kurumsal — YALNIZCA görünürlük filtresi, bkz. CORE/app_mode.py.
        # DB henüz bağlı değilse (beklenmeyen sıralama) KURUMSAL'a düş:
        # hiçbir şey gizlenmemiş hâl, sessiz bir kısıtlama değil.
        try:
            self._app_mode: str = get_app_mode(DBManager())
        except Exception as exc:
            _log.warning("app_mode_okunamadi  exc=%s — varsayilan KURUMSAL", exc)
            self._app_mode = KURUMSAL

        self._pool = QThreadPool.globalInstance()
        self._pool.setMaxThreadCount(6)
        self._batch_total:      int  = 0
        self._batch_done:       int  = 0
        self._batch_errors:     int  = 0
        self._batch_timeouts:   int  = 0
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

        # DB katmanına da bildir (B-0xx): düğmeleri gizlemek yalnızca bu
        # düğmeleri kullanan yolu kapatır — CLI, doğrudan bir CORE
        # çağrısı ya da unutulmuş bir UI kontrolü (ör. TagDialog hiç
        # is_readonly_role'a bakmıyor) hâlâ geçebilirdi. DBManager.execute()
        # artık aynı kararı SON ÇARE olarak tekrar veriyor (bkz.
        # DB/db_manager.py::_yazma_yetkisini_dogrula).
        DBManager().set_active_role(self._role)

        # ── Yönetici bölümü: sadece Yönetici görür ───────────────────────
        for _w in (self._admin_sep, self._admin_label, self._blacklist_btn,
                   self._audit_log_btn, self._usb_tokens_btn, self._pending_btn,
                   self._admin_settings_btn, self._support_btn):
            _w.setVisible(is_admin)
            _w.setEnabled(is_admin)

        # ── Bireysel mod: "YÖNETİCİ" başlığı VE "Bekleyen Kayıtlar" gizlenir ──
        #
        # Tek kullanıcı zaten admin — USB Tokenlar/Ayarlar düğmeleri KALIR,
        # yalnızca başlık metni anlamsız. Bu bir RBAC kararı DEĞİL
        # (CORE/app_mode.py hiçbir rolü değiştirmiyor): is_admin yukarıda
        # zaten karar verdi, burada yalnızca is_admin zaten True olan bir
        # görünürlüğü DAHA DA daraltıyoruz — asla genişletmiyoruz (salt
        # okunur/standart rolde bu satır hiç çalışmaz, çünkü is_admin
        # zaten False).
        #
        # "Bekleyen Kayıtlar" ayrıca gizleniyor: eskiden (`UI/AdminPanel.py`,
        # kaldırıldı) bu, panel İÇİNDEKİ bir sekmeydi ve aynı gerekçeyle
        # (tek kullanıcı, onaylanacak kimse yok) gizlenirdi — üçe
        # bölünmenin ardından karşılığı, o sayfanın kenar çubuğu giriş
        # noktasını gizlemek. "Gizlemek silmek değil" AYNEN geçerli:
        # `_pending_view`in kendisi, verisi ve `_on_approve`/`_on_reject`
        # hiçbiri silinmiyor — yalnızca düğme.
        if is_admin and is_bireysel(self._app_mode):
            self._admin_label.setVisible(False)
            self._pending_btn.setVisible(False)
            self._pending_btn.setEnabled(False)

        # "Kullanıcı Adı" — düğmenin kendi görünürlüğünden AYRI bir
        # kontrol, aynı "gizlemek silmek değil" ilkesiyle burada: düğme
        # zaten gizli olsa da, mod Kurumsal'a dönüp düğme tekrar görünür
        # olduğunda kartların da doğru durumda (isim görünür) olması
        # gerekiyor — tek yerden, aynı çağrıyla (eski `AdminPanel.
        # _apply_mode_visibility`'nin aynı gerekçesi; kartlara taşınırken
        # `set_kullanici_adi_gizli()` oldu, bkz. `UI/
        # PendingRegistrationsView.py`'nin modül docstring'i).
        self._pending_view.set_kullanici_adi_gizli(is_bireysel(self._app_mode))

        # ── Yazma/düzenleme işlemleri: Salt Okunur'da tamamen kapalı ─────
        self.setAcceptDrops(can_write)
        for _w in (self._drop_hint, self._btn_add_file, self._btn_add_folder,
                   self._btn_scan_all, self._btn_new_tag, self._btn_new_folder):
            _w.setVisible(can_write)
            _w.setEnabled(can_write)

        # ── Güvenlik sayfası: B-034'e bağlı, KARAR VERİLMEDİ ─────────────
        #
        # Bugün salt okunur rolde GİZLİ ve bu mevcut kısıtlamayla
        # TUTARLILIK için; bir karar olarak değil. Salt okunur rol zaten
        # dosya sağ tık menüsünü hiç açamıyor ve Yönetim Paneli'ne
        # giremiyor — yani hiçbir doğrulamaya erişemiyor (B-034).
        #
        # B-034'ün "düzeltilmedi" gerekçesi bu yüzeyde GEÇERSİZ: oradaki
        # itiraz sağ tık menüsünün yıkıcı maddeleri sızdırmasıydı, bu
        # sayfada yıkıcı madde yok. Açmak `GUVENLIK_SALT_OKUNURA_ACIK`
        # sabitini `True` yapmak; karar kullanıcıya bırakıldı.
        _guvenlik_gorunur = can_write or GUVENLIK_SALT_OKUNURA_ACIK
        self._guvenlik_btn.setVisible(_guvenlik_gorunur)
        self._guvenlik_btn.setEnabled(_guvenlik_gorunur)

        # ── Kritik sekmesi: Salt Okunur'da gizli ─────────────────────────
        _kritik = self._nav_btns.get("Kritik")
        if _kritik:
            _kritik.setVisible(can_write)
            _kritik.setEnabled(can_write)

        self._role_badge.setText(display_role(self._role))

    def reload_app_mode(self) -> None:
        """Ayar değiştiğinde AdminPanel bunu çağırır — yeniden başlatma gerekmesin.

        `main_window_lock.py::reload_idle_timeout` ile aynı desen.
        """
        try:
            self._app_mode = get_app_mode(DBManager())
        except Exception as exc:
            _log.warning("app_mode_okunamadi  exc=%s", exc)
            return
        self._apply_role_restrictions()

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

    #: Kenar çubuğundaki, "aktif sayfa" vurgusu taşıyan TÜM sayfa-gezinme
    #: düğmeleri. Beşe çıktığında (Güvenlik/Denetim Günlüğü + USB
    #: Tokenlar/Bekleyen Kayıtlar/Ayarlar) her `_on_open_*`'ın kendi
    #: elleriyle "diğer dördünü sıfırla" yazması unutma riski taşırdı —
    #: tek liste, tek sıfırlama metodu (`_reset_page_nav_styles`).
    def _page_nav_btns(self) -> tuple[QPushButton, ...]:
        return (
            self._guvenlik_btn, self._audit_log_btn, self._usb_tokens_btn,
            self._pending_btn, self._admin_settings_btn,
        )

    def _reset_page_nav_styles(self) -> None:
        if self._active_btn is not None:
            self._active_btn.setStyleSheet(self._nav_btn_style(active=False))
            self._active_btn = None
        for _btn in self._page_nav_btns():
            _btn.setStyleSheet(self._nav_btn_style(active=False))

    def _on_open_audit_log(self) -> None:
        """
        Denetim Günlüğü sayfasına geçer — eskiden (`UI/AuditLogDialog.py`,
        kaldırıldı) modal bir `.exec()` idi, `UI/GuvenlikView.py` ile AYNI
        `_govde_yigini` (`QStackedWidget`) deseniyle tam sayfaya taşındı.

        Rol kapısı BURADA YENİ EKLENDİ. Öncesinde YALNIZCA kenar çubuğu
        düğmesi (`_audit_log_btn`) admin'e göre gizleniyordu
        (`_apply_role_restrictions`); hamburger menüsündeki "📋 Denetim
        Günlüğü" (`_on_hamburger_menu`) rol kontrolü YAPMADAN aynı metodu
        çağırıyordu — yani salt okunur/standart bir rol o ikinci yoldan
        denetim kaydını görebiliyordu. Modal bir diyalog için düşük
        önemdeydi; tam sayfaya (kalıcı, kenar çubuğuyla eşdeğer bir görünüm)
        taşırken aynı boşluğu miras almamak için `_on_open_usb_tokens()`
        ile AYNI kapı deseni eklendi.
        """
        if not is_admin_role(self._role):
            QMessageBox.warning(self, "Erişim Reddedildi", "Bu alana erişim yetkiniz yok.")
            return
        self._reset_page_nav_styles()
        self._audit_log_btn.setStyleSheet(self._nav_btn_style(active=True))
        self._govde_yigini.setCurrentWidget(self._audit_log_view)
        self._action_bar.setVisible(False)
        self._page_title.setText(_AUDIT_SAYFA_ADI)
        self._audit_log_view.yenile()

    def _on_open_usb_tokens(self) -> None:
        """
        USB Tokenlar sayfasına geçer — eskiden (`UI/AdminPanel.py`,
        kaldırıldı) tek bir modalin "USB Tokenlar" sekmesiydi. Üçe
        bölünmenin gerekçesi `UI/admin_common.py`'nin modül docstring'inde.
        """
        if not is_admin_role(self._role):
            QMessageBox.warning(self, "Erişim Reddedildi", "Bu alana erişim yetkiniz yok.")
            return
        self._reset_page_nav_styles()
        self._usb_tokens_btn.setStyleSheet(self._nav_btn_style(active=True))
        self._govde_yigini.setCurrentWidget(self._usb_tokens_view)
        self._action_bar.setVisible(False)
        self._page_title.setText(_USB_TOKENS_SAYFA_ADI)
        self._usb_tokens_view.yenile()

    def _on_open_pending(self) -> None:
        """Bekleyen Kayıtlar sayfasına geçer — bkz. `_on_open_usb_tokens()`."""
        if not is_admin_role(self._role):
            QMessageBox.warning(self, "Erişim Reddedildi", "Bu alana erişim yetkiniz yok.")
            return
        self._reset_page_nav_styles()
        self._pending_btn.setStyleSheet(self._nav_btn_style(active=True))
        self._govde_yigini.setCurrentWidget(self._pending_view)
        self._action_bar.setVisible(False)
        self._page_title.setText(_PENDING_SAYFA_ADI)
        self._pending_view.yenile()

    def _on_open_admin_settings(self) -> None:
        """Ayarlar sayfasına geçer — bkz. `_on_open_usb_tokens()`."""
        if not is_admin_role(self._role):
            QMessageBox.warning(self, "Erişim Reddedildi", "Bu alana erişim yetkiniz yok.")
            return
        self._reset_page_nav_styles()
        self._admin_settings_btn.setStyleSheet(self._nav_btn_style(active=True))
        self._govde_yigini.setCurrentWidget(self._admin_settings_view)
        self._action_bar.setVisible(False)
        self._page_title.setText(_ADMIN_SETTINGS_SAYFA_ADI)
        self._admin_settings_view.yenile()

    def _on_open_contact(self) -> None:
        from UI.ContactDialog import ContactDialog
        ContactDialog(self).exec()

    def _on_open_rehber(self) -> None:
        """
        Kullanım rehberini açar: yerel PDF varsa onu, yoksa web adresini.

        Kararı bu metot VERMİYOR — `CORE.rehber.erisim_yolu()` veriyor.
        Burada bir `if PDF.exists()` yazmak ikinci bir karar noktası
        olurdu ve biri güncellenip diğeri unutulurdu.
        """
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices

        tur, hedef = _rehber_erisim_yolu()
        url = QUrl.fromLocalFile(hedef) if tur == "pdf" else QUrl(hedef)
        if not QDesktopServices.openUrl(url):
            QMessageBox.warning(
                self, "HYCLEUS — Kullanım Rehberi",
                "Rehber açılamadı. Dosyayı elle açabilirsiniz:\n\n"
                f"{hedef}")

    def _on_open_profile(self) -> None:
        """
        Profil sayfasına geçer — eskiden (`UI/ProfileDialog.py`, kaldırıldı)
        modal bir `.exec()` idi, `UI/AuditLogView.py`/`UI/GuvenlikView.py`
        ile AYNI `_govde_yigini` (`QStackedWidget`) deseniyle tam sayfaya
        taşındı.

        Rol kapısı YOK — Güvenlik/Denetim Günlüğü'nün aksine bu sayfa
        HERKESE açık (kendi profilin, kendi cihazın, kendi işlemlerin).
        """
        self._reset_page_nav_styles()
        self._govde_yigini.setCurrentWidget(self._profil_view)
        self._action_bar.setVisible(False)
        self._page_title.setText(_PROFIL_SAYFA_ADI)
        self._profil_view.yenile()

    def _on_hamburger_menu(self) -> None:
        """
        2026-08-29: `act_audit`/`act_usb` artık role göre gizleniyor/
        devre dışı bırakılıyor.

        Öncesinde ikisi de HERKESE görünürdü — kenar çubuğundaki eşdeğer
        düğmeler (`_audit_log_btn`/`_usb_tokens_btn`) `_apply_role_
        restrictions()`'ta admin olmayan roller için zaten gizleniyordu,
        ama bu ikinci giriş noktası aynı kararı UYGULAMIYORDU. Admin
        olmayan bir kullanıcı için tek görünen sonuç, tıklayınca çıkan
        "Erişim Reddedildi" uyarısıydı — fonksiyon-içi kontrol (`_on_open_
        audit_log`/`_on_open_usb_tokens`) doğruydu ama görünürlük onunla
        TUTARSIZDI.

        "🔌 USB Yönetimi" burada TEK madde olarak kalıyor (eskiden tek
        modalin girişiydi) — kenar çubuğunda artık üç ayrı düğme (USB
        Tokenlar/Bekleyen Kayıtlar/Ayarlar) olduğu için hamburger menüsü
        üçünü de tekrar ETMİYOR, yalnızca en sık kullanılan USB Tokenlar
        sayfasına açıyor.

        İkisi BİRLİKTE duruyor, biri diğerinin yerine geçmiyor: görünürlük
        kontrolü kullanıcı deneyimi için (reddedilen bir tıklama yerine
        seçenek hiç görünmesin), fonksiyon-içi kontrol gerçek savunma için
        (bu menü tamamen atlanıp metot doğrudan çağrılsa bile kapı
        kapalı kalır — bkz. `tests/test_audit_log_view.py::
        test_yonetici_OLMAYAN_ENGELLENIYOR`, K1-14'ün aynı ilkesi).
        """
        T = self._T
        is_admin = is_admin_role(self._role)
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu {{ background:{T['topbar']}; color:{T['text']};"
            f" border:1px solid {T['border']}; border-radius:8px; padding:4px 0; }}"
            f"QMenu::item {{ padding:10px 24px; font-size:13px; }}"
            f"QMenu::item:selected {{ background:{T['accent_tint']}; color:{T['tint_text']}; border-radius:4px; }}"
            f"QMenu::separator {{ height:1px; background:{T['border']}; margin:4px 10px; }}"
        )
        act_audit   = menu.addAction("📋  Denetim Günlüğü")
        act_audit.setVisible(is_admin)
        act_audit.setEnabled(is_admin)
        act_usb     = menu.addAction("🔌  USB Yönetimi")
        act_usb.setVisible(is_admin)
        act_usb.setEnabled(is_admin)
        act_support = menu.addAction("💬  Destek")
        # Rehberin İKİNCİ erişim yolu. Etiket ve hedef CORE/rehber.py'den
        # geliyor — burada elle yazılsaydı rehber taşındığında menü
        # sessizce boş bir dosyaya bakardı (B-017 sınıfı ayrışma).
        act_rehber  = menu.addAction(_REHBER_ETIKETI)
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
            self._on_open_usb_tokens()
        elif action == act_support:
            self._on_open_contact()
        elif action == act_rehber:
            self._on_open_rehber()
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
                "Shamir Secret Sharing (2-of-3)\n"
                # TPM düşüşünün kullanıcıya ulaşan kanalı. Bu satır
                # KOŞULSUZ: yalnızca sorun varken göstermek, "yazmıyorsa
                # her şey yolunda" gibi okunur ve o çıkarım sessiz bir
                # düşüşte yanlış olur (B-025). İki durum da yazılıyor.
                f"{tpm_durum().ozet()}\n\n"
                "© 2026 HYCLEUS — Tüm hakları saklıdır.",
            )

    # ── Sidebar filtresi ──────────────────────────────────────────────────────

    def _on_guvenlik_click(self) -> None:
        """
        Güvenlik görünümüne geçer.

        Eylem barı (Dosya Ekle, Tara…) GİZLENİYOR: bu sayfada hiçbirinin
        karşılığı yok ve görünür bırakmak, tıklandığında dosya görünümüne
        geri dönmeyen düğmeler demek olurdu.
        """
        self._reset_page_nav_styles()
        self._guvenlik_btn.setStyleSheet(self._nav_btn_style(active=True))
        self._govde_yigini.setCurrentWidget(self._guvenlik_view)
        self._action_bar.setVisible(False)
        self._page_title.setText(_GUVENLIK_SAYFA_ADI)

    def _on_sidebar_click(self, db_label: str, btn: QPushButton) -> None:
        if self._active_tag_btn is not None:
            prev_color = self._active_tag_btn.property("tag_color") or self._T["accent"]
            self._active_tag_btn.setStyleSheet(self._tag_btn_style(color=prev_color, active=False))
            self._active_tag_btn = None
        self._current_tag_id = None

        # Güvenlik/Denetim Günlüğü/USB Tokenlar/Bekleyen Kayıtlar/Ayarlar
        # sayfasından dönüş — yığın ve eylem barı geri alınıyor.
        for _btn in self._page_nav_btns():
            _btn.setStyleSheet(self._nav_btn_style(active=False))
        self._govde_yigini.setCurrentIndex(0)
        self._action_bar.setVisible(True)

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


    # ── Kilit — üç tetikleyici, tek örtü ──────────────────────────────────────
    #
    # Kilit NEDENLERİ bir küme olarak tutuluyor. Tek bir _locked bayrağı
    # yeterli değildi: hareketsizlik kilidi devredeyken USB de çekilse ve
    # sonra USB geri takılsa, _poll_usb'nin çağırdığı _unlock() hareketsizlik
    # kilidini de kaldırırdı — yani ekrandan uzaktaki kullanıcının oturumu
    # USB'yi takan kişiye açılırdı. Küme boşalmadan örtü kalkmıyor.
    #
    # "manual" — Profil sayfasındaki "Oturumu Kapat" (bkz. UI/ProfileView.py::
    # _on_logout, UI/main_window_lock.py::_on_manual_logout/_unlock_manual).
    # "idle" İLE AYNI mekanizma (PIN'le açılır, _poll_usb'nin varsayılan
    # _unlock() çağrısı — yalnızca "usb" nedenini kaldırır — BUNU
    # ETKİLEMEZ, kullanıcının kendi USB'si takılı kalsa bile kilit kendi
    # kendine AÇILMAZ) ama AYRI bir neden: "hareketsizlikten kilitlendi"
    # ile "kullanıcı kendi isteğiyle kilitledi" aynı denetim sinyaline
    # düşerse kayıt yanlış sebep gösterir (bu oturumun defalarca uyguladığı
    # "verdict-distinctness" ilkesi — ör. CORE/scanner_backends.py::
    # timeout_result()'ın mock_result()'tan ayrılması).

    _LOCK_MESSAGES = {
        "usb": (
            "Kayıtlı USB Token Çıkarıldı",
            "Oturuma devam etmek için USB'yi yeniden takın — algılanınca otomatik devam eder",
        ),
        "idle": ("Oturum Kilitlendi", "Hareketsizlik nedeniyle — devam etmek için PIN girin"),
        "manual": ("Oturum Kapatıldı", "Devam etmek için vault PIN'inizi girin"),
        # Alt metin _poll_usb tarafından _revoked_reason'a yazılıp burada
        # üzerine geçiliyor (bkz. LockMixin._lock) — bu yalnızca yedek.
        # PIN girerek açılamaz: yetki DB'de gerçekten iptal edilmiş,
        # yeniden giriş (uygulamayı kapatıp açmak) gerekiyor.
        "revoked": ("Erişim İptal Edildi", "Yetkiniz artık geçerli değil."),
    }


