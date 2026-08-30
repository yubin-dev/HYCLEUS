"""HYCLEUS — Ayarlar: tam sayfa görünüm

`UI/AdminPanel.py`'nin (kaldırıldı) "Ayarlar" sekmesinin yerini alıyor —
üçe bölünmenin gerekçesi `UI/admin_common.py`'nin modül docstring'inde.

Görünüm modu (Bireysel/Kurumsal) burada KAYDEDİLİYOR ama UYGULANMIYOR:
"Bekleyen Kayıtlar" kenar çubuğu düğmesinin (ve o sayfanın "Kullanıcı
Adı" sütununun) görünürlüğü artık `UI/main_window.py::
_apply_role_restrictions()`'ta, TEK yerden — bu sayfa `pencere.
reload_app_mode()`'u çağırıp bırakıyor, kendi tarafında ikinci bir
görünürlük kararı YAZMIYOR (eski `AdminPanel._apply_mode_visibility`'nin
"Bekleyen Kayıtlar" sekmesi + o panelin kendi `_pending_table` sütun
gizleme kararını AYNI ANDA verdiği yerin doğal devamı — artık iki AYRI
sayfa oldukları için o "aynı anda" kararı iki sayfanın ortak ebeveyni
olan `pencere`'ye taşındı).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from CORE.app_mode import BIREYSEL, KURUMSAL, get_app_mode, set_app_mode
from CORE.idle_lock import (
    DEFAULT_IDLE_MINUTES,
    IDLE_DISABLED,
    IDLE_OPTIONS,
    get_idle_timeout_minutes,
    set_idle_timeout_minutes,
)
from CORE.vault_manager import export_recovery_share, has_recovery_share
from DB.db_manager import DBManager
from UI import admin_common

_log = logging.getLogger("hycleus.admin_panel")

#: Sayfa başlığı — kenar çubuğu/üst bar AYNI sabiti kullanıyor.
SAYFA_ADI = "Ayarlar"

_TTL_OPTIONS = (1, 6, 12, 24, 48)


class AdminSettingsView(QWidget):
    def __init__(self, pencere: Any, parent: QWidget | None = None) -> None:
        """
        `_load_settings()` BİLEREK burada ÇAĞRILMIYOR (eskiden çağrılıyordu
        — düzeltildi, bkz. `tests/test_admin_pages_construction_guard.py`).

        Bu sayfa (Güvenlik/Denetim Günlüğü/Profil ile AYNI desen, bkz. `UI/
        main_window_layout.py::_make_govde_yigini`) KOŞULSUZ kuruluyor —
        yönetici OLMAYAN bir oturumun penceresi için de `__init__` çalışır,
        rol kapısı yalnızca `main_window.py::_on_open_admin_settings()`'te
        (giriş noktasında). `_load_settings()`'in DB'ye gitmesi (`get_
        setting`/`get_idle_timeout_minutes`/`get_app_mode`) ve `_tsa_kok_
        bloku()`'nun DAHA ÖNCE burada zincirlediği `_tsa_yukle()`'nin
        `trusted_roots` tablosunu okuması, o rol kapısından ÖNCE, HER
        oturum için gerçekleşiyordu — "render engellendi" ile "sorgu hiç
        çalışmadı" arasındaki farkın yanlış tarafında. `UsbTokensView`/
        `PendingRegistrationsView` zaten bu tuzağa düşmüyordu (ikisi de
        veri yükünü `.yenile()`'ye erteliyor) — bu sayfa artık onlarla
        TUTARLI: `.yenile()` (yalnızca rol kapısından SONRA çağrılıyor)
        hem `_load_settings()`'i hem `_tsa_yukle()`'yi tetikliyor.
        """
        super().__init__(parent)
        self._pencere = pencere
        self.setObjectName("admin_settings_view")
        self._build_ui()

    @property
    def _T(self) -> dict[str, str]:
        return self._pencere._T

    # ------------------------------------------------------------------
    # UI kurulumu
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 20, 16)
        root.setSpacing(14)

        title = QLabel(SAYFA_ADI)
        title.setFont(QFont("Arial", 13, QFont.Bold))
        root.addWidget(title)

        self._sep = QLabel()
        self._sep.setFixedHeight(1)
        root.addWidget(self._sep)

        # ── Görünüm modu (Bireysel/Kurumsal) ───────────────────────────────
        self._mode_lbl = QLabel("Görünüm modu")
        root.addWidget(self._mode_lbl)

        mode_row = QHBoxLayout()
        mode_row.setSpacing(10)

        self._mode_combo = QComboBox()
        self._mode_combo.addItem("Kurumsal", KURUMSAL)
        self._mode_combo.addItem("Bireysel", BIREYSEL)
        self._mode_combo.setFixedWidth(110)
        mode_row.addWidget(self._mode_combo)

        self._mode_hint = QLabel(
            "Bireysel: kenar çubuğundaki \"Bekleyen Kayıtlar\" ve \"Yönetici\" "
            "başlığı gizlenir. Yetkiler DEĞİŞMEZ — yalnızca görünüm."
        )
        self._mode_hint.setWordWrap(True)
        mode_row.addWidget(self._mode_hint, 1)
        root.addLayout(mode_row)

        self._ttl_lbl = QLabel("İmha Odası varsayılan TTL süresi")
        root.addWidget(self._ttl_lbl)

        row = QHBoxLayout()
        row.setSpacing(10)

        self._ttl_combo = QComboBox()
        for h in _TTL_OPTIONS:
            self._ttl_combo.addItem(f"{h} saat", h)
        self._ttl_combo.setFixedWidth(110)
        row.addWidget(self._ttl_combo)

        self._ttl_hint = QLabel("sonra İmha Odası'ndaki dosyalar otomatik silinir")
        row.addWidget(self._ttl_hint)
        row.addStretch()
        root.addLayout(row)

        # ── Hareketsizlik kilidi ──────────────────────────────────────────
        self._idle_lbl = QLabel("Hareketsizlik kilidi")
        root.addWidget(self._idle_lbl)

        idle_row = QHBoxLayout()
        idle_row.setSpacing(10)

        self._idle_combo = QComboBox()
        for m in IDLE_OPTIONS:
            self._idle_combo.addItem("Kapalı" if m == IDLE_DISABLED else f"{m} dakika", m)
        self._idle_combo.setFixedWidth(110)
        idle_row.addWidget(self._idle_combo)

        self._idle_hint = QLabel("hareketsizlikten sonra oturum kilitlenir (USB takılı olsa bile)")
        idle_row.addWidget(self._idle_hint)
        idle_row.addStretch()
        root.addLayout(idle_row)

        self._btn_save = QPushButton("Kaydet")
        self._btn_save.setCursor(Qt.PointingHandCursor)
        self._btn_save.setFixedWidth(100)
        self._btn_save.clicked.connect(self._on_save_settings)
        root.addWidget(self._btn_save)

        root.addWidget(self._tsa_kok_bloku())
        root.addWidget(self._kurtarma_bloku())
        root.addStretch()

    # ------------------------------------------------------------------
    # Sayfa (yeniden) görünür olduğunda — bkz. UsbTokensView.yenile()'nin
    # aynı "bayat stil" gerekçesi.
    # ------------------------------------------------------------------

    def yenile(self) -> None:
        self._restyle()
        self._load_settings()
        self._tsa_yukle()

    def _restyle(self) -> None:
        T = self._T
        self.setStyleSheet(admin_common.stil(T))
        self._sep.setStyleSheet(f"background:{T['border']};")
        for lbl in (self._mode_lbl, self._ttl_lbl, self._idle_lbl):
            lbl.setStyleSheet(admin_common.bolum_baslik_stili(T))
        for lbl in (self._mode_hint, self._ttl_hint, self._idle_hint):
            lbl.setStyleSheet(admin_common.ipucu_stili(T))
        for combo in (self._mode_combo, self._ttl_combo, self._idle_combo):
            combo.setStyleSheet(admin_common.combo_stili(T))
        self._btn_save.setStyleSheet(admin_common.btn_success_stil(T))
        self._btn_tsa_ekle.setStyleSheet(admin_common.btn_success_stil(T))
        self._btn_tsa_sil.setStyleSheet(admin_common.btn_danger_stil(T))
        self._tsa_liste.setStyleSheet(admin_common.liste_stili(T))
        self._tsa_baslik.setStyleSheet(admin_common.bolum_baslik_stili(T))
        self._tsa_ipucu.setStyleSheet(admin_common.ipucu_stili(T))
        self._kurtarma_baslik.setStyleSheet(admin_common.bolum_baslik_stili(T))
        self._kurtarma_ipucu.setStyleSheet(admin_common.ipucu_stili(T))
        self._btn_kurtarma.setStyleSheet(admin_common.btn_danger_stil(T))

    # ── Kurtarma parçası ─────────────────────────────────────────────────────
    #
    # Bugüne kadar yalnızca komut satırından alınabiliyordu
    # (`python CORE/recover_vault.py --export`). Panikleyen bir kullanıcının
    # o komutu bulması beklenemez; rehber de onu "kaybetmeden önce al"
    # diyerek uyarıyor.
    #
    # Buraya konmasının sebebi: bu sayfa zaten yönetici kapısının
    # ARDINDA (`main_window::_on_open_admin_settings`, `is_admin_role`).
    # Ayrı bir rol kontrolü yazmak ikinci bir karar noktası olurdu.

    def _kurtarma_bloku(self) -> QWidget:
        kutu = QWidget()
        lay = QVBoxLayout(kutu)
        lay.setContentsMargins(0, 12, 0, 0)
        lay.setSpacing(8)

        self._kurtarma_baslik = QLabel("Kurtarma parçası")
        lay.addWidget(self._kurtarma_baslik)

        self._kurtarma_ipucu = QLabel(
            "USB ya da anahtar kasası kaybolduğunda kasayı açan üçüncü pay. "
            "Bir kez gösterilir, hiçbir yere kaydedilmez — yazdırıp fiziksel "
            "olarak saklayın."
        )
        self._kurtarma_ipucu.setWordWrap(True)
        lay.addWidget(self._kurtarma_ipucu)

        self._btn_kurtarma = QPushButton("Kurtarma Parçasını Göster…")
        self._btn_kurtarma.setObjectName("admin_btn_kurtarma")
        self._btn_kurtarma.setCursor(Qt.PointingHandCursor)
        self._btn_kurtarma.setFixedWidth(230)
        self._btn_kurtarma.clicked.connect(self._on_kurtarma_parcasi)
        lay.addWidget(self._btn_kurtarma)
        return kutu

    def _on_kurtarma_parcasi(self) -> None:
        """
        Kurtarma parçasını üretir ve modalda gösterir.

        Pay bu metotta da, diyalogda da DİSKE YAZILMIYOR; `build_export`
        yalnızca bellekte yaşayan bir nesne döndürüyor ve blok biterken
        ikisi de bırakılıyor.
        """
        if not admin_common.yonetici_hala_yetkili(self, self._pencere):  # B-064/B-066
            return
        from CORE.recovery_share import build_export
        from UI.RecoveryShareDialog import RecoveryShareDialog

        hwid = self._pencere._hwid
        if has_recovery_share(hwid):
            # Aynı pay yeniden üretiliyor — kasa DEĞİŞMİYOR. Kullanıcı
            # "yeni bir parça mı alıyorum, eskisi geçersiz mi oluyor"
            # sorusunu sorar; yanıtı sormadan veriyoruz.
            if QMessageBox.question(
                self, "Kurtarma Parçası",
                "Bu cihaz için daha önce kurtarma parçası alınmış.\n\n"
                "Yeniden göstermek kasayı DEĞİŞTİRMEZ; aynı parça üretilir "
                "ve eski çıktınız geçerli kalır.\n\nDevam edilsin mi?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            ) != QMessageBox.Yes:
                return

        pin, ok = QInputDialog.getText(
            self, "PIN Doğrulama",
            "Kurtarma parçasını görmek için vault PIN'inizi girin:",
            QLineEdit.Password,
        )
        if not ok or not pin.strip():
            return

        try:
            share_3 = export_recovery_share(hwid, pin.strip())
        except Exception as exc:  # noqa: BLE001 — vault katmanı çeşitli tip atıyor
            QMessageBox.critical(
                self, "Kurtarma Parçası",
                f"Kurtarma parçası üretilemedi:\n\n{exc}")
            return

        try:
            disa_aktarim = build_export(share_3)
            try:
                RecoveryShareDialog(disa_aktarim, self, T=self._T).exec()
            finally:
                del disa_aktarim
        finally:
            del share_3

    # ── Güvenilir zaman damgası kökleri ──────────────────────────────────────
    #
    # Bu bölüm olmadan damga doğrulaması arayüzde HER ZAMAN "kök
    # doğrulanmadı" diyordu: `verify_timestamp()` 3.1b'den beri kök
    # alabiliyor ama yalnızca komut satırı veriyordu. Kurumsal kullanımda
    # kökü bir kez eklemek, sonraki her doğrulamayı etkiliyor.
    #
    # Kaydet düğmesine BAĞLI DEĞİL: ekleme/silme anında yazılıyor ve
    # denetim kaydına düşüyor. Bir güven listesinin "kaydetmeyi unuttum"
    # durumu olmamalı.

    def _tsa_kok_bloku(self) -> QWidget:
        kutu = QWidget()
        lay = QVBoxLayout(kutu)
        lay.setContentsMargins(0, 8, 0, 0)
        lay.setSpacing(8)

        self._tsa_baslik = QLabel("Güvenilir zaman damgası kökleri")
        lay.addWidget(self._tsa_baslik)

        self._tsa_ipucu = QLabel(
            "Kurumunuzun zaman damgası kökünü ekleyin. Liste boşken damgalar "
            "«geçerli — ama kurum doğrulanmadı» olarak gösterilir."
        )
        self._tsa_ipucu.setWordWrap(True)
        lay.addWidget(self._tsa_ipucu)

        self._tsa_liste = QListWidget()
        self._tsa_liste.setFixedHeight(96)
        lay.addWidget(self._tsa_liste)

        satir = QHBoxLayout()
        satir.setSpacing(10)
        self._btn_tsa_ekle = QPushButton("Kök Ekle…")
        self._btn_tsa_ekle.setCursor(Qt.PointingHandCursor)
        self._btn_tsa_ekle.setFixedWidth(120)
        self._btn_tsa_ekle.clicked.connect(self._on_tsa_kok_ekle)
        satir.addWidget(self._btn_tsa_ekle)

        self._btn_tsa_sil = QPushButton("Kaldır")
        self._btn_tsa_sil.setCursor(Qt.PointingHandCursor)
        self._btn_tsa_sil.setFixedWidth(100)
        # Başlangıç durumu BURADA AÇIKÇA veriliyor (`False`) — `_tsa_yukle()`
        # ARTIK burada ÇAĞRILMIYOR (aşağıya bkz.), bu yüzden onun kapatmasına
        # güvenilemez: liste boş dolduğu için buton varsayılan olarak
        # (Qt'nin QPushButton varsayımı `enabled=True`) seçili öğe yokken
        # bile tıklanabilir kalırdı.
        self._btn_tsa_sil.setEnabled(False)
        self._btn_tsa_sil.clicked.connect(self._on_tsa_kok_sil)
        satir.addWidget(self._btn_tsa_sil)
        satir.addStretch()
        lay.addLayout(satir)

        self._tsa_liste.itemSelectionChanged.connect(
            lambda: self._btn_tsa_sil.setEnabled(
                self._tsa_liste.currentItem() is not None)
        )
        # `_tsa_yukle()` BURADA ÇAĞRILMIYOR — bkz. `__init__`'in üstündeki
        # not: bu sayfa (`UsbTokensView`/`PendingRegistrationsView` ile
        # TUTARLI olarak) `__init__` sırasında HİÇBİR DB sorgusu
        # tetiklemiyor, ilk veri yükü yalnızca `.yenile()` ile geliyor.
        return kutu

    def _kim(self) -> int | None:
        """
        Denetim kaydına yazılacak `users.id` — Güvenlik sayfasındaki zincir
        doğrulamasıyla AYNI yol (B-011, yan etkisiz `kullanici_bilgisi`).
        """
        from CORE.session_user import kullanici_bilgisi

        try:
            kim = kullanici_bilgisi(DBManager(), self._pencere._hwid)
        except Exception:  # pragma: no cover — kayıt işlemi engellemez
            return None
        return kim[0] if kim else None

    def _tsa_yukle(self) -> None:
        from CORE.trusted_roots import oku

        self._tsa_liste.clear()
        self._btn_tsa_sil.setEnabled(False)
        try:
            kokler = oku(DBManager())
        except Exception as exc:
            _log.error("tsa_kok_listesi_okunamadi  exc=%s", exc)
            kokler = []
        if not kokler:
            bos = QListWidgetItem("(güvenilir kök eklenmemiş)")
            bos.setFlags(Qt.NoItemFlags)
            self._tsa_liste.addItem(bos)
            return
        for kok in kokler:
            oge = QListWidgetItem(f"{kok.konu}   ·   {kok.kisa_izi()}")
            oge.setData(Qt.UserRole, kok.parmak_izi)
            oge.setToolTip(f"Dosya: {kok.ad}\nEklendi: {kok.eklendi}\n"
                           f"Parmak izi: {kok.parmak_izi}")
            self._tsa_liste.addItem(oge)

    def _on_tsa_kok_ekle(self) -> None:
        if not admin_common.yonetici_hala_yetkili(self, self._pencere):  # B-064/B-066
            return
        from CORE.trusted_roots import TrustedRootError, ekle

        yol, _ = QFileDialog.getOpenFileName(
            self, "Güvenilir kök sertifikası seç", "",
            "Sertifika (*.pem *.crt *.cer *.der);;Tüm dosyalar (*)")
        if not yol:
            return
        try:
            kok = ekle(DBManager(), Path(yol).read_bytes(),
                       ad=Path(yol).name, user_id=self._kim())
        except TrustedRootError as exc:
            QMessageBox.warning(self, "Kök Eklenemedi", str(exc))
            return
        except OSError as exc:
            QMessageBox.warning(self, "Kök Eklenemedi", f"Dosya okunamadı:\n{exc}")
            return
        self._tsa_yukle()
        QMessageBox.information(
            self, "Güvenilir Kök Eklendi",
            f"{kok.konu}\n\nParmak izi: {kok.parmak_izi}\n\n"
            "Bundan sonraki damga doğrulamaları bu kökü kullanacak.\n\n"
            "Not: liste şifresiz veritabanında tutuluyor — veritabanına "
            "yazabilen biri kendi kökünü ekleyebilir (SECURITY.md §4.9).")

    def _on_tsa_kok_sil(self) -> None:
        if not admin_common.yonetici_hala_yetkili(self, self._pencere):  # B-064/B-066
            return
        from CORE.trusted_roots import sil

        oge = self._tsa_liste.currentItem()
        if oge is None:
            return
        izi = oge.data(Qt.UserRole)
        if not izi:
            return
        if QMessageBox.question(
            self, "Güvenilir Kökü Kaldır",
            f"{oge.text()}\n\nBu kök kaldırılsın mı? Bu kökle imzalanmış "
            "damgalar bundan sonra «kurum doğrulanmadı» olarak görünecek.",
        ) != QMessageBox.Yes:
            return
        sil(DBManager(), izi, user_id=self._kim())
        self._tsa_yukle()

    # ------------------------------------------------------------------
    # Genel ayarlar
    # ------------------------------------------------------------------

    def _load_settings(self) -> None:
        try:
            current = int(DBManager().get_setting("imha_ttl_hours", "24"))
        except Exception:
            current = 24
        for i in range(self._ttl_combo.count()):
            if self._ttl_combo.itemData(i) == current:
                self._ttl_combo.setCurrentIndex(i)
                break

        try:
            idle_current = get_idle_timeout_minutes(DBManager())
        except Exception:
            idle_current = DEFAULT_IDLE_MINUTES
        for i in range(self._idle_combo.count()):
            if self._idle_combo.itemData(i) == idle_current:
                self._idle_combo.setCurrentIndex(i)
                break

        mode_current = get_app_mode(DBManager())
        for i in range(self._mode_combo.count()):
            if self._mode_combo.itemData(i) == mode_current:
                self._mode_combo.setCurrentIndex(i)
                break

    def _on_save_settings(self) -> None:
        if not admin_common.yonetici_hala_yetkili(self, self._pencere):  # B-064/B-066
            return
        hours = self._ttl_combo.currentData()
        minutes = self._idle_combo.currentData()
        mode = self._mode_combo.currentData()
        hwid = self._pencere._hwid
        try:
            db = DBManager()
            db.set_setting("imha_ttl_hours", str(hours))
            db.log("setting_changed",
                   detail=f"key=imha_ttl_hours value={hours} hwid={hwid}")

            # Doğrulama ve denetim kaydı CORE tarafında; kilidi KAPATMAK ayrı
            # bir action ile yazılıyor (bkz. CORE/idle_lock.py).
            set_idle_timeout_minutes(db, minutes, hwid=hwid)

            # Doğrulama ve denetim kaydı CORE tarafında (bkz. CORE/app_mode.py).
            set_app_mode(db, mode, hwid=hwid)

            # Açık pencereye anında uygula — yeniden başlatma beklenmesin.
            # "Bekleyen Kayıtlar" düğmesinin/sütununun görünürlüğü de
            # BURADAN, reload_app_mode() → _apply_role_restrictions() ile
            # tek yerden güncelleniyor (bkz. modül docstring'i).
            reload_idle = getattr(self._pencere, "reload_idle_timeout", None)
            if callable(reload_idle):
                reload_idle()
            reload_mode = getattr(self._pencere, "reload_app_mode", None)
            if callable(reload_mode):
                reload_mode()

            idle_text = "kapalı" if minutes == IDLE_DISABLED else f"{minutes} dakika"
            mode_text = "Bireysel" if mode == BIREYSEL else "Kurumsal"
            QMessageBox.information(
                self, "Kaydedildi",
                f"İmha Odası TTL süresi {hours} saat olarak güncellendi.\n"
                f"Hareketsizlik kilidi: {idle_text}.\n"
                f"Görünüm modu: {mode_text}.",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))


__all__ = ["SAYFA_ADI", "AdminSettingsView"]
