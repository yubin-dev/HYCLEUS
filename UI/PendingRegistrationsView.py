"""HYCLEUS — Bekleyen Kayıtlar: tam sayfa görünüm

`UI/AdminPanel.py`'nin (kaldırıldı) "Bekleyen Kayıtlar" sekmesinin yerini
alıyor — üçe bölünmenin gerekçesi `UI/admin_common.py`'nin modül
docstring'inde.

Bireysel/Kurumsal görünürlüğü — artık kenar çubuğu düğmesinde
------------------------------------------------------------------
Eskiden bu, `AdminPanel` İÇİNDEKİ bir `QTabWidget` sekmesiydi ve
Bireysel modda `_apply_mode_visibility()` onu GİZLERDİ (silmeden — veri
ve akış hep oradaydı). Artık ayrı bir sayfa/kenar çubuğu girişi olduğu
için görünürlük kararı `UI/main_window.py::_apply_role_restrictions()`'a
taşındı (`_pending_btn.setVisible(...)`) — AYNI "gizlemek silmek değil"
ilkesiyle: bu sayfa Bireysel modda da KURULU kalıyor, `_load_pending()`/
`_on_approve()`/`_on_reject()` hiçbiri silinmedi, yalnızca kenar
çubuğundaki giriş noktası kayboluyor.

Tablo → kart listesi (kozmetik, mockup güdümlü)
--------------------------------------------------
Görev "veri/mantığa dokunma" dedi — ve dokunulmadı: DB sorgusu
(`_load_pending()`'in `SELECT`'i), onay/red SQL'i, denetim kaydı
`detail=` biçimi, onay diyaloglarının metni HİÇBİRİ değişmedi. Değişen
TEK şey satır → kart eşlemesi: eskiden tek bir `QTableWidget` + SEÇİLİ
satıra göre etkinleşen PAYLAŞILAN "Onayla"/"Reddet" düğmeleri vardı;
artık her bekleyen kayıt kendi "Onayla"/"Reddet" düğmelerini taşıyan
kendi kartı — "seçim" kavramı tamamen ORTADAN KALKTI (bir kartın
düğmesine basmak zaten HANGİ kaydın kastedildiğini belirtiyor, ayrı bir
seçim adımına gerek yok).

Bu, `_on_approve()`/`_on_reject()`'in imzasını DEĞİŞTİRDİ: eskiden
parametresizdi ("şu an seçili olan"ı `_selected_pending_hwid()` ile
buluyordu), şimdi `(hwid, username)` alıyor (hangi kartın düğmesine
basıldığını doğrudan taşıyor — `functools.partial` ile düğmeye
bağlanırken bağlanıyor). GÖVDELERİ (onay diyaloğu, SQL, denetim kaydı)
TEK KARAKTER değişmedi; bkz. Git geçmişi.

Kart görsel deseni — GuvenlikView'dan ÖDÜNÇ ALINDI, ikinci bir renk
yolu İCAT EDİLMEDİ
--------------------------------------------------------------------------
`UI/GuvenlikView.py::_kart()`'ın `#guvenlik_kart` çerçevesiyle (bkz. `UI/
main_window_theme.py`) AYNI görsel — `admin_common.kart_stil()` AYNI
token'lardan (search_bg zemin, border çerçeve, 8px köşe) AYNI görünümü
üretiyor. GuvenlikView B-055 merkezî QSS cascade'ini kullanıyor, bu sayfa
kardeşleri (UsbTokensView/AdminSettingsView) gibi doğrudan
`setStyleSheet()` kullanmaya devam ediyor (bkz. `UI/admin_common.py`
modül docstring'i, "kasıtlı, bir B-055 ihlali görmezden gelinmedi").

"Kullanıcı Adı" gizleme — sütundan karta taşındı, DAVRANIŞ AYNI
--------------------------------------------------------------------------
Eskiden Bireysel modda `_pending_table`'ın 0. sütunu (Kullanıcı Adı)
`setColumnHidden(0, ...)` ile gizlenirdi — sayfanın kendi düğmesi zaten
gizliyken, Kurumsal'a dönüldüğünde sütunun doğru durumda olması için
(bkz. eski `AdminPanel._apply_mode_visibility`'nin "tek yerden, aynı
çağrıyla" gerekçesi). Kartlarda "sütun" YOK — karşılığı
`set_kullanici_adi_gizli()`: bayrağı tutuyor VE (sayfa zaten yüklüyse)
kartları ANINDA yeniden çiziyor, `setColumnHidden`'ın aynı "anında etki
eden" garantisi. `main_window.py::_apply_role_restrictions()` artık
`_pending_table.setColumnHidden(...)` yerine bunu çağırıyor.
"""
from __future__ import annotations

import functools
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from CORE.vault_manager import discard_vault
from DB.db_manager import DBManager
from UI import admin_common

#: Sayfa başlığı — kenar çubuğu/üst bar AYNI sabiti kullanıyor.
SAYFA_ADI = "Bekleyen Kayıtlar"


class PendingRegistrationsView(QWidget):
    def __init__(self, pencere: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._pencere = pencere
        #: Bireysel modda `main_window.py::_apply_role_restrictions()`
        #: tarafından açılıyor — bkz. modül docstring'i.
        self._kullanici_adi_gizli = False
        #: Son `_load_pending()`'in ham satırları — yalnızca `_restyle()`
        #: DB'ye GİTMEDEN kartları yeniden çizebilsin diye tutuluyor
        #: (`UsbTokensView`/`AdminSettingsView`'ın `_restyle()`'ının AYNI
        #: "DB'siz" kuralı).
        self._son_kayitlar: list[Any] = []
        self.setObjectName("pending_registrations_view")
        self._build_ui()

    @property
    def _T(self) -> dict[str, str]:
        return self._pencere._T

    # ------------------------------------------------------------------
    # UI kurulumu
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(16, 16, 16, 12)

        title = QLabel(SAYFA_ADI)
        title.setFont(QFont("Arial", 13, QFont.Bold))
        root.addWidget(title)

        root.addLayout(self._make_top_bar())
        root.addWidget(self._make_kart_alani(), 1)
        self._title = title

    def _make_top_bar(self) -> QHBoxLayout:
        """Sayfa-seviyesi eylemler — kart-başına DEĞİL: "Yeni Kullanıcı
        Kaydet" hiçbir bekleyen kayda ait değil, "Yenile" hepsini
        yeniden yüklüyor."""
        bar = QHBoxLayout()
        bar.setSpacing(8)
        bar.addStretch()

        self._btn_new = QPushButton("＋  Yeni Kullanıcı Kaydet")
        self._btn_new.setCursor(Qt.PointingHandCursor)
        self._btn_new.clicked.connect(self._on_new_user)
        bar.addWidget(self._btn_new)

        self._btn_refresh = QPushButton("Yenile")
        self._btn_refresh.setCursor(Qt.PointingHandCursor)
        self._btn_refresh.clicked.connect(self._load_pending)
        bar.addWidget(self._btn_refresh)

        return bar

    def _make_kart_alani(self) -> QScrollArea:
        self._kart_scroll = QScrollArea()
        self._kart_scroll.setWidgetResizable(True)
        self._kart_scroll.setFrameShape(QFrame.NoFrame)

        self._kart_kutusu = QWidget()
        self._kart_layout = QVBoxLayout(self._kart_kutusu)
        self._kart_layout.setContentsMargins(0, 0, 4, 0)
        self._kart_layout.setSpacing(8)

        self._bos_etiketi = QLabel("Bekleyen kayıt yok.")
        self._bos_etiketi.setAlignment(Qt.AlignCenter)
        self._kart_layout.addWidget(self._bos_etiketi)
        self._bos_etiketi.setVisible(False)

        # Kartlar HEP `_bos_etiketi` ile sondaki stretch ARASINA
        # ekleniyor (bkz. `_kartlari_ciz`) — stretch kartları yukarı
        # yaslıyor, aksi hâlde tek bir kart sayfanın ORTASINDA yüzerdi.
        self._kart_layout.addStretch(1)

        #: `_kartlari_ciz()`'in kurup SİLDİĞİ kart widget'ları — `_bos_
        #: etiketi`/stretch'i YANLIŞLIKLA silmemek için AYRICA tutuluyor
        #: (ikisi de `_kart_layout`'ta, kalıcı; kartlar GEÇİCİ).
        self._kart_widgetleri: list[QFrame] = []

        self._kart_scroll.setWidget(self._kart_kutusu)
        return self._kart_scroll

    def _kart(self, hwid: str, username: str | None, role: str | None,
              created_at: str | None) -> QFrame:
        cerceve = QFrame()
        cerceve.setObjectName("pending_kart")
        cerceve.setProperty("hwid", hwid)
        satir = QHBoxLayout(cerceve)
        satir.setContentsMargins(14, 12, 14, 12)
        satir.setSpacing(14)

        sutun = QVBoxLayout()
        sutun.setSpacing(2)

        isim_metni = "—" if self._kullanici_adi_gizli else (username or "—")
        etiket_isim = QLabel(isim_metni)
        etiket_isim.setObjectName("pending_kart_isim")
        sutun.addWidget(etiket_isim)

        hwid_kisa = hwid[:28] + "…" if hwid and len(hwid) > 28 else (hwid or "—")
        ts = (created_at or "").replace("T", " ").rstrip("Z") or "—"
        etiket_detay = QLabel(
            f"Rol: {role or '—'}   ·   HWID: {hwid_kisa}   ·   Kayıt: {ts}"
        )
        etiket_detay.setObjectName("pending_kart_detay")
        etiket_detay.setWordWrap(True)
        sutun.addWidget(etiket_detay)

        satir.addLayout(sutun, 1)

        btn_onayla = QPushButton("✓  Onayla")
        btn_onayla.setObjectName("pending_kart_btn_onayla")
        btn_onayla.setCursor(Qt.PointingHandCursor)
        btn_onayla.clicked.connect(functools.partial(self._on_approve, hwid, username))
        satir.addWidget(btn_onayla, 0, Qt.AlignVCenter)

        btn_reddet = QPushButton("✕  Reddet")
        btn_reddet.setObjectName("pending_kart_btn_reddet")
        btn_reddet.setCursor(Qt.PointingHandCursor)
        btn_reddet.clicked.connect(functools.partial(self._on_reject, hwid, username))
        satir.addWidget(btn_reddet, 0, Qt.AlignVCenter)

        return cerceve

    # ------------------------------------------------------------------
    # Sayfa (yeniden) görünür olduğunda — bkz. UsbTokensView.yenile()'nin
    # aynı "bayat stil" gerekçesi.
    # ------------------------------------------------------------------

    def yenile(self) -> None:
        # B-085: bkz. `UI/UsbTokensView.py::yenile()`'nin aynı yorumu ve
        # `UI/admin_common.py::sayfa_erisimi_var_mi` docstring'i.
        if not admin_common.sayfa_erisimi_var_mi(self._pencere):
            return
        self._load_pending()  # kartları AYRICA _restyle() ediyor, bkz. altı

    def _restyle(self) -> None:
        T = self._T
        self.setStyleSheet(admin_common.stil(T))
        self._btn_new.setStyleSheet(admin_common.btn_stil(T))
        self._btn_refresh.setStyleSheet(admin_common.btn_stil(T))
        self._bos_etiketi.setStyleSheet(admin_common.ipucu_stili(T))
        for kart in self._kart_widgetleri:
            kart.setStyleSheet(admin_common.kart_stil(T))
            btn_onayla = kart.findChild(QPushButton, "pending_kart_btn_onayla")
            if btn_onayla is not None:
                btn_onayla.setStyleSheet(admin_common.btn_success_stil(T))
            btn_reddet = kart.findChild(QPushButton, "pending_kart_btn_reddet")
            if btn_reddet is not None:
                btn_reddet.setStyleSheet(admin_common.btn_danger_stil(T))

    # ------------------------------------------------------------------
    # "Kullanıcı Adı" gizleme — Bireysel mod, bkz. modül docstring'i.
    # ------------------------------------------------------------------

    def set_kullanici_adi_gizli(self, gizli: bool) -> None:
        if gizli == self._kullanici_adi_gizli:
            return
        self._kullanici_adi_gizli = gizli
        # `setColumnHidden`'ın "anında etki" garantisi: sayfa zaten
        # yüklüyse kartlar HEMEN yeniden çiziliyor, bir sonraki `.yenile()`
        # beklenmiyor. Kartlar SIFIRDAN kuruluyor (bkz. `_kartlari_ciz()`)
        # — yeni widget'lar stilsiz KALMASIN diye `_restyle()` de burada.
        if self._son_kayitlar:
            self._kartlari_ciz(self._son_kayitlar)
            self._restyle()

    # ------------------------------------------------------------------
    # Veri yükleme
    # ------------------------------------------------------------------

    def _load_pending(self) -> None:
        try:
            rows = DBManager().fetchall(
                """
                SELECT username, hwid, role, created_at
                FROM users
                WHERE status = 'pending'
                ORDER BY created_at DESC
                """
            )
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı Hatası", str(exc))
            return

        self._son_kayitlar = rows
        self._kartlari_ciz(rows)
        self._restyle()

    def _kartlari_ciz(self, rows: list[Any]) -> None:
        """`rows`'tan kart widget'larını kurar — DB'ye GİTMİYOR (bkz.
        `set_kullanici_adi_gizli()`'nin de DB'siz çağırdığı yer).

        Yalnızca `self._kart_widgetleri`'DE İZLENEN kartlar kaldırılıyor
        — `_bos_etiketi` ve sondaki stretch, ikisi de AYNI layout'ta
        ama KALICI, bu döngüye hiç GİRMİYOR (eski bir sürümde bu ayrım
        yoktu ve `_bos_etiketi` ilk yüklemede yanlışlıkla siliniyordu).
        """
        for eski_kart in self._kart_widgetleri:
            self._kart_layout.removeWidget(eski_kart)
            eski_kart.deleteLater()
        self._kart_widgetleri = []

        # Yeni kartlar `_bos_etiketi`'nden SONRA, stretch'ten ÖNCE
        # ekleniyor.
        ekleme_noktasi = self._kart_layout.count() - 1
        for row in rows:
            kart = self._kart(row["hwid"], row["username"], row["role"], row["created_at"])
            self._kart_layout.insertWidget(ekleme_noktasi, kart)
            self._kart_widgetleri.append(kart)
            ekleme_noktasi += 1

        self._bos_etiketi.setVisible(not rows)

    def _on_new_user(self) -> None:
        if not admin_common.yonetici_hala_yetkili(self, self._pencere):  # B-064/B-066
            return
        from UI.RegisterDialog import RegisterDialog
        dlg = RegisterDialog(admin_hwid=self._pencere._hwid, parent=self)
        if dlg.exec() == RegisterDialog.Accepted:
            self._load_pending()

    def _on_approve(self, hwid: str, username: str | None) -> None:
        if not admin_common.yonetici_hala_yetkili(self, self._pencere):  # B-064/B-066
            return
        if not hwid:
            return

        confirm = QMessageBox.question(
            self,
            "Kaydı Onayla",
            f"'{username}' kullanıcısının kaydını onaylamak istiyor musunuz?\n\n"
            f"HWID: {hwid}\n\nOnaylandıktan sonra kullanıcı giriş yapabilecek.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        try:
            db = DBManager()
            db.execute(
                "UPDATE users SET status = 'approved' WHERE hwid = ?", (hwid,)
            )
            db.log(
                "user_approved",
                detail=f"hwid={hwid} username={username} approved_by={self._pencere._hwid}",
            )
            QMessageBox.information(
                self, "Onaylandı",
                f"'{username}' kullanıcısı onaylandı. Artık giriş yapabilir.",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))
            return

        self._load_pending()

    def _on_reject(self, hwid: str, username: str | None) -> None:
        if not admin_common.yonetici_hala_yetkili(self, self._pencere):  # B-064/B-066
            return
        if not hwid:
            return

        confirm = QMessageBox.question(
            self,
            "Kaydı Reddet",
            f"'{username}' kullanıcısının kaydını reddetmek istiyor musunuz?\n\n"
            "Kullanıcı kaydı ve USB tokeni silinecek. Bu işlem geri alınamaz.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        try:
            db = DBManager()
            db.execute("DELETE FROM users WHERE hwid = ?", (hwid,))
            # users satırı + usb_tokens/kasa + per-HWID vault dosyası
            # birlikte silinir (bkz. discard_vault() docstring'i, B-060/061)
            discard_vault(hwid)
            db.log(
                "user_rejected",
                detail=f"hwid={hwid} username={username} rejected_by={self._pencere._hwid}",
            )
            QMessageBox.information(
                self, "Reddedildi",
                f"'{username}' kullanıcısının kaydı reddedildi ve silindi.",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))
            return

        self._load_pending()


__all__ = ["SAYFA_ADI", "PendingRegistrationsView"]
