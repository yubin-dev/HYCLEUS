"""
HYCLEUS — Kilit — USB ve hareketsizlik

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
from PySide6.QtGui import (
    QColor,
    QPaintEvent,
    QPainter,
    QResizeEvent,
)
from PySide6.QtWidgets import (
    QFrame,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)


from CORE.idle_lock import (
    get_idle_timeout_minutes,
    log_idle_lock,
)
from CORE.session_user import (
    kullanici_bilgisi,
    oturum_yetkisi_gecerli_mi,
    sync_session_user,
    vault_username,
)
from CORE.usb_manager import DEV_MODE as _DEV_MODE, get_usb_hwid
from CORE.vault_manager import (
    USBAuthError,
    VaultTamperedError,
    authenticate_usb,
    read_vault_role,
)
from DB.db_manager import DBManager



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


# ── Kilit overlay ─────────────────────────────────────────────────────────────

class _LockOverlay(QWidget):
    """
    Tek kilit örtüsü, İKİ tetikleyici: USB çekilmesi ve hareketsizlik.

    Neden ayrı bir overlay değil
    ----------------------------
    İki ayrı widget, resize/raise/paint mantığının kopyalanması ve iki
    örtünün birbiriyle yarışması demekti: hareketsizlik kilidi devredeyken
    USB de çekilirse üst üste binerler, biri kalkınca diğeri "açık" görünen
    ama devre dışı bir arayüz bırakırdı. Tek örtü + değiştirilebilir metin
    bu sınıf hatalarını baştan siliyor.

    Farklı olan şey görünüm değil, ÇIKIŞ KOŞULU — onu HycleusWindow
    yönetiyor (bkz. _lock/_unlock ve _lock_reasons).
    """

    #: Örtüye tıklandı — hareketsizlik kilidinde PIN sorulması için.
    clicked = Signal()

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

        self._title = QLabel("USB Token Çıkarıldı")
        self._title.setAlignment(Qt.AlignCenter)
        self._title.setStyleSheet(
            "font-size: 18px; font-weight: 700; color: #111827; background: transparent;"
        )
        lay.addWidget(self._title)

        self._sub = QLabel("Lütfen USB'yi yeniden takın")
        self._sub.setAlignment(Qt.AlignCenter)
        self._sub.setStyleSheet("font-size: 14px; color: #6B7280; background: transparent;")
        lay.addWidget(self._sub)

    def set_message(self, title: str, subtitle: str) -> None:
        """Kilit nedenine göre metni değiştirir."""
        self._title.setText(title)
        self._sub.setText(subtitle)

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._card.move((self.width() - 320) // 2, (self.height() - 200) // 2)

    def paintEvent(self, event: QPaintEvent) -> None:
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(0, 0, 0, 204))  # 80% opacity

    def mousePressEvent(self, event) -> None:
        # Örtü tüm arayüzü kapattığı için kilit açma yolu buradan geçiyor.
        # USB kilidinde sinyalin karşılığı yok (USB takılınca kendiliğinden
        # açılıyor); hareketsizlik kilidinde PIN diyaloğunu getiriyor.
        self.clicked.emit()
        super().mousePressEvent(event)


class LockMixin:
    """Kilit — USB ve hareketsizlik."""

    # ── USB kilit ─────────────────────────────────────────────────────────────

    def _poll_usb(self) -> None:
        if self._authenticating:
            return
        hwid = get_usb_hwid()
        self._refresh_usb_badge()
        if hwid is None:
            if not self._locked:
                self._lock()
            return
        if hwid != self._hwid:
            self._trigger_usb_reauth(hwid)
            return

        # Aynı fiziksel USB hâlâ takılı — ama DB'deki yetki hâlâ girişteki
        # gibi mi? (B-064/B-066: eskiden burada HİÇBİR kontrol yoktu; bir
        # yönetici bu HWID'i reddedip (`_on_reject`), silip (`_on_delete`)
        # ya da kara listeye alıp (`_do_blacklist`) DB'yi değiştirse bile,
        # USB'si hâlâ takılı olan bu oturum bundan habersiz kalıp eski
        # yetkisiyle çalışmaya devam ediyordu.)
        try:
            gecerli, sebep = oturum_yetkisi_gecerli_mi(DBManager(), hwid, self._role)
        except Exception as exc:
            # DB'ye ANLIK erişilemedi (ör. yoğun bir toplu işlem sırasında
            # kısa süreli kilit) — bunu "yetki iptal edildi" SAYMIYORUZ,
            # aksi hâlde geçici bir DB tıkanıklığı meşru bir oturumu
            # kilitlerdi. Bir sonraki tik (3 sn sonra) yeniden dener;
            # reload_idle_timeout'un aynı DB hatası karşısındaki tavrıyla
            # tutarlı (bkz. o metot).
            _log.warning("Oturum yetkisi doğrulanamadı (tekrar denenecek): %s", exc)
            return

        if not gecerli:
            if "revoked" not in self._lock_reasons:
                try:
                    DBManager().log(
                        "session_revoked", detail=f"hwid={hwid} sebep={sebep}"
                    )
                except Exception as exc:
                    _log.error("Oturum iptali denetime yazılamadı: %s", exc)
            self._revoked_reason = sebep
            self._lock("revoked")
            return

        if self._locked:
            # `_unlock()` varsayılanı "usb" nedenini kaldırır. Kilitli
            # tek neden "revoked" ise bu çağrı KASITLI OLARAK hiçbir şey
            # açmaz (bkz. _unlock: kalan neden varsa örtü durur) —
            # "revoked" bilerek buradan çıkışı yok: yetki DB'de gerçekten
            # iptal edilmişti, oturumun kendi kendine iyileşmesi yanlış
            # olurdu. Tek çıkış: uygulamayı kapatıp yeniden giriş yapmak.
            self._unlock()

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

        # B-065: eskiden yalnızca _hwid/_role güncelleniyordu — _username/
        # _user_id hiç dokunulmuyordu, yani Profil ekranı ve avatar YENİ
        # kullanıcı yerine ESKİ kullanıcıyı göstermeye devam ediyordu.
        # `sync_session_user()` (main.py'nin normal giriş yolundakiyle
        # AYNI fonksiyon) satırın var olduğunu garanti ediyor;
        # `kullanici_bilgisi()` de main.py'nin kullandığı AYNI salt okunur
        # okuma yolu — ikinci bir sorgu şekli İCAT EDİLMEDİ.
        try:
            new_user_id = sync_session_user(DBManager(), hwid=new_hwid, role=new_role)
            bilgi = kullanici_bilgisi(DBManager(), new_hwid)
        except Exception as exc:
            QMessageBox.critical(self, "Hata", f"Kullanıcı bilgisi okunamadı:\n{exc}")
            self._authenticating = False
            return
        # `sync_session_user()` az önce satırın var olduğunu garanti etti;
        # bu None yalnızca kuramsal (ör. eşzamanlı silme) — yine de
        # `sync_session_user()`'ın kendi auto-provision biçimiyle tutarlı
        # bir yer tutucuya düşüyoruz, eski kullanıcının adında KALMIYORUZ.
        new_username = bilgi[1] if bilgi is not None else vault_username(new_hwid)

        prev_hwid      = self._hwid
        self._hwid     = new_hwid
        self._role     = new_role
        self._username = new_username
        self._user_id  = new_user_id
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

    def _lock(self, reason: str = "usb") -> None:
        self._lock_reasons.add(reason)
        self._locked = True
        # Açık belgeleri kapat: kilit ekranı düz metin kopyaları SafeZone'da
        # bırakırsa, kilidin koruduğu şeyin yanında açık bir kapı kalırdı.
        # getattr koruması, _lock'u tam pencere kurulumu olmadan çalıştıran
        # testler için (tests/test_lock_overlay.py).
        if getattr(self, "_checkouts", None):
            try:
                self._close_all_checkouts(reason=f"lock:{reason}")
            except Exception as exc:
                _log.error("kilit check-in basarisiz: %s", exc)
        title, sub = self._LOCK_MESSAGES.get(reason, self._LOCK_MESSAGES["usb"])
        if reason == "revoked":
            # Sebep DB'den geliyor (rol/durum/kara liste) — sabit
            # sözlükte tutulamaz, _poll_usb her tetiklemede yazıyor.
            sub = getattr(self, "_revoked_reason", "") or sub
        self._overlay.set_message(title, sub)
        self.centralWidget().setEnabled(False)
        self.centralWidget().setGraphicsEffect(self._blur)
        self._overlay.resize(self.size())
        self._overlay.show()
        self._overlay.raise_()

    def _unlock(self, reason: str = "usb") -> None:
        """
        Tek bir kilit nedenini kaldırır; başka neden varsa örtü DURUR.

        Örtü kalkmadığında kalan nedenin mesajı gösterilir, yoksa kullanıcı
        neden hâlâ kilitli olduğunu göremezdi.
        """
        self._lock_reasons.discard(reason)
        if self._lock_reasons:
            kalan = next(iter(self._lock_reasons))
            title, sub = self._LOCK_MESSAGES.get(kalan, self._LOCK_MESSAGES["usb"])
            self._overlay.set_message(title, sub)
            return
        self._locked = False
        # Slide-over paneli (main_window_layout.py) hâlâ AÇIKSA central'ı
        # AÇMA — o kilidi panel yönetiyor, burası kaldırmaz. `_slide_over_acik`
        # yoksa (panel mekanizması hiç kurulmadıysa) `getattr` False'a düşer.
        if not getattr(self, "_slide_over_acik", lambda: False)():
            self.centralWidget().setEnabled(True)
        self.centralWidget().setGraphicsEffect(None)
        self._overlay.hide()

    # ── Hareketsizlik kilidi ──────────────────────────────────────────────────
    #
    # Karar mantığı CORE/idle_lock.py'de (Qt'siz, test edilebilir). Buradaki
    # iş yalnızca olayları dinlemek ve saniyede bir sormak.

    def eventFilter(self, obj, event):
        """
        Uygulama genelindeki fare/klavye olaylarını hareketsizlik sayacına bildirir.

        QApplication'a kurulu olduğu için diyaloglardaki etkileşim de sayılıyor —
        aksi hâlde uzun bir PIN/ayar diyaloğu doldururken oturum kilitlenirdi.

        Olay YUTULMUYOR: yalnızca zaman damgası güncellenip False dönülüyor,
        böylece olay normal alıcısına gitmeye devam ediyor.
        """
        if event.type() in _ACTIVITY_EVENTS and not self._locked:
            self._idle.record_activity()
        return super().eventFilter(obj, event)

    def _on_overlay_clicked(self) -> None:
        """Örtüye tıklandı — hareketsizlik ya da manuel kilit varsa PIN sor."""
        if self._authenticating:
            return
        if "idle" in self._lock_reasons:
            self._unlock_idle()
        elif "manual" in self._lock_reasons:
            self._unlock_manual()

    def _tick_idle(self) -> None:
        """
        Saniyede bir: hareketsizlik eşiği aşıldı mı?

        USB kilidi devredeyken de çalışır. Erken çıksaydı şu boşluk kalırdı:
        kullanıcı USB'yi alıp gider, saatler sonra biri USB'yi takar ve
        oturum PIN sorulmadan açılırdı — çünkü o süre boyunca hareketsizlik
        hiç değerlendirilmemiş olurdu.
        """
        if "idle" in self._lock_reasons or not self._idle.should_lock():
            return
        idle_seconds = self._idle.idle_seconds()
        self._idle.disarm()
        try:
            log_idle_lock(
                DBManager(),
                idle_seconds=idle_seconds,
                timeout_minutes=int(self._idle.timeout_seconds // 60),
                hwid=self._hwid,
            )
        except Exception as exc:
            _log.error("Hareketsizlik kilidi denetime yazılamadı: %s", exc)
        self._lock("idle")

    def reload_idle_timeout(self) -> None:
        """
        Ayar değiştiğinde AdminSettingsView bunu çağırır — yeniden başlatma gerekmesin.

        DEV_MODE'da kilit KAPALI: o modda vault yok (anahtar HWID'den
        türetiliyor, bkz. main.py `_dev_key`), dolayısıyla `read_vault_role`
        doğrulaması yapılamaz ve kilit AÇILAMAZ hâle gelirdi. Çıkışı olmayan
        bir kilit, kilit değil arızadır.
        """
        if _DEV_MODE:
            self._idle.reconfigure(0)
            _log.info("DEV_MODE — hareketsizlik kilidi devre dışı (vault yok).")
            return
        try:
            self._idle.reconfigure(get_idle_timeout_minutes(DBManager()))
        except Exception as exc:
            _log.warning("Hareketsizlik süresi okunamadı: %s", exc)

    def _unlock_idle(self) -> None:
        """
        Hareketsizlik kilidini PIN doğrulamasıyla açar.

        Fare hareketiyle AÇILMAZ — açsaydı bu bir ekran koruyucu olurdu,
        güvenlik kontrolü değil. Ekranın başına geçen biri fareyi oynatarak
        oturuma girerdi ki kilidin kapatmak istediği senaryo tam olarak bu.
        """
        pin, ok = QInputDialog.getText(
            self, "Oturum Kilitli",
            "Hareketsizlik nedeniyle kilitlendi.\nDevam etmek için vault PIN'inizi girin:",
            QLineEdit.Password,
        )
        if not ok or not pin.strip():
            return
        try:
            read_vault_role(self._hwid, pin.strip())
        except Exception as exc:
            QMessageBox.warning(self, "PIN Hatalı", str(exc))
            DBManager().log(
                "idle_unlock_failed", detail=f"hwid={self._hwid} reason={exc}"
            )
            return
        DBManager().log("idle_unlock_success", detail=f"hwid={self._hwid}")
        self._idle.rearm()
        self._unlock("idle")

    # ── Manuel kilit ("Oturumu Kapat") ──────────────────────────────────────
    #
    # `UI/ProfileView.py`'nin "Cihazlar ve oturum" bölümündeki "Oturumu
    # Kapat" düğmesinin çağırdığı giriş noktası. `_unlock_idle()`'ı
    # ÇOĞALTMIYOR (kopyalamıyor) — `_unlock_manual()` AYNI PIN doğrulama
    # deseni ama AYRI denetim eylemleriyle (bkz. `_LOCK_MESSAGES`'ın
    # "manual" girdisindeki gerekçe).

    def _on_manual_logout(self) -> None:
        """`ProfileView._on_logout()`'un onay diyaloğundan SONRA çağırdığı
        tek giriş noktası — onay BURADA değil, çağıranda (UI eylem
        yerinde onay almak, USB Yönetim Paneli sayfalarının kendi
        eylemleriyle AYNI desen)."""
        DBManager().log("session_logged_out", detail=f"hwid={self._hwid}")
        self._lock("manual")

    def _unlock_manual(self) -> None:
        """Manuel kilidi PIN doğrulamasıyla açar — `_unlock_idle()` ile
        AYNI desen, bkz. o metodun docstring'i ve `_LOCK_MESSAGES["manual"]`
        girdisinin gerekçesi."""
        pin, ok = QInputDialog.getText(
            self, "Oturum Kapatıldı",
            "Devam etmek için vault PIN'inizi girin:",
            QLineEdit.Password,
        )
        if not ok or not pin.strip():
            return
        try:
            read_vault_role(self._hwid, pin.strip())
        except Exception as exc:
            QMessageBox.warning(self, "PIN Hatalı", str(exc))
            DBManager().log(
                "manual_unlock_failed", detail=f"hwid={self._hwid} reason={exc}"
            )
            return
        DBManager().log("manual_unlock_success", detail=f"hwid={self._hwid}")
        self._idle.rearm()
        self._unlock("manual")

    def _refresh_usb_badge(self) -> None:
        hwid = get_usb_hwid()
        if hwid:
            self._usb_badge.setText(
                f'<span style="color:#059669; font-size:14px;">●</span>'
                f' <span style="color:#6B7280; font-size:12px;">USB: {hwid[:8]}</span>'
            )
        else:
            self._usb_badge.setText(
                '<span style="color:#DC2626; font-size:14px;">●</span>'
                ' <span style="color:#6B7280; font-size:12px;">USB Yok</span>'
            )

