"""HYCLEUS — USB Tokenlar: tam sayfa görünüm

`UI/AdminPanel.py`'nin (kaldırıldı) "USB Tokenlar" sekmesinin yerini
alıyor — üçe bölünmenin gerekçesi, paylaşılan stil/yetki kodu ve "neden
artık kendi zamanlayıcısı yok" açıklaması `UI/admin_common.py`'nin modül
docstring'inde. "Bekleyen Kayıtlar" (`UI/PendingRegistrationsView.py`) ve
"Ayarlar" (`UI/AdminSettingsView.py`) AYRI sayfalar/kenar çubuğu
öğeleri; bu sayfa kendi başına kalıyor — veri ya da davranış değişmedi,
yalnızca modal bir `QTabWidget` sekmesinden `_govde_yigini`'nde bir
sayfaya taşındı.
"""
from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from CORE.roles import is_admin_role
from CORE.usb_tokens import token_kayitlarini_getir
from CORE.vault_manager import (
    VaultTamperedError,
    blacklist_usb,
    change_vault_role,
    discard_vault,
)
from DB.db_manager import DBManager
from UI import admin_common

#: Sayfa başlığı — kenar çubuğu/üst bar AYNI sabiti kullanıyor (bkz.
#: `UI/AuditLogView.py::SAYFA_ADI`'nın aynı deseni).
SAYFA_ADI = "USB Tokenlar"


class UsbTokensView(QWidget):
    def __init__(self, pencere: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._pencere = pencere
        self.setObjectName("usb_tokens_view")
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

        root.addWidget(self._make_table())
        root.addLayout(self._make_btn_bar())
        self._title = title

    def _make_table(self) -> QTableWidget:
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["HWID", "Token ID", "Rol", "Son Giriş", "Durum"]
        )
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setSelectionMode(QTableWidget.SingleSelection)
        self._table.verticalHeader().setVisible(False)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        return self._table

    def _make_btn_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self._btn_blacklist = QPushButton("Kara Listeye Al")
        self._btn_blacklist.setCursor(Qt.PointingHandCursor)
        self._btn_blacklist.setEnabled(False)
        self._btn_blacklist.clicked.connect(self._on_toggle_blacklist)
        bar.addWidget(self._btn_blacklist)

        self._btn_role = QPushButton("Rolü Değiştir")
        self._btn_role.setCursor(Qt.PointingHandCursor)
        self._btn_role.setEnabled(False)
        self._btn_role.clicked.connect(self._on_change_role)
        bar.addWidget(self._btn_role)

        self._btn_delete = QPushButton("Sil")
        self._btn_delete.setCursor(Qt.PointingHandCursor)
        self._btn_delete.setEnabled(False)
        self._btn_delete.clicked.connect(self._on_delete)
        bar.addWidget(self._btn_delete)

        bar.addStretch()

        # B-006: zincir doğrulaması üç yerden çağrılabiliyordu ama hiçbirinin
        # düğmesi yoktu. Rol kapısı ayrıca gerekmiyor: bu sayfa yönetici
        # olmayan bir rol için hiç AÇILMIYOR (bkz. main_window._on_open_usb_tokens).
        self._btn_chain = QPushButton("Zinciri Doğrula")
        self._btn_chain.setCursor(Qt.PointingHandCursor)
        self._btn_chain.clicked.connect(self._on_verify_chain)
        bar.addWidget(self._btn_chain)

        self._btn_refresh = QPushButton("Yenile")
        self._btn_refresh.setCursor(Qt.PointingHandCursor)
        self._btn_refresh.clicked.connect(self._load)
        bar.addWidget(self._btn_refresh)

        return bar

    def _on_verify_chain(self) -> None:
        """
        Denetim zincirini doğrular.

        GÖVDE BURADA DEĞİL: `UI/security_actions.zinciri_dogrula()`.
        Aynı iş Güvenlik sekmesinden de çağrılıyor.
        """
        from UI.security_actions import zinciri_dogrula

        zinciri_dogrula(self, self._pencere._hwid)

    # ------------------------------------------------------------------
    # Sayfa (yeniden) görünür olduğunda — B-055: T her zaman canlı okunuyor
    # olsa da, statik olarak KURULMUŞ stiller (düğmeler, konteyner) tema
    # değiştiğinde kendiliğinden GÜNCELLENMEZ — sayfa arkada dururken tema
    # değişip geri dönüldüğünde bayat renkler görünmesin diye burada
    # yeniden uygulanıyor (`ProfileView.yenile()`'nin aynı "bayat veri/
    # durum" gerekçesi, burada bayat OLAN veri değil stil).
    # ------------------------------------------------------------------

    def yenile(self) -> None:
        # B-085: `_on_open_usb_tokens()`'te ZATEN kontrol edilmiş olsa da
        # (üretimdeki TEK çağrı yeri), bu metot DOĞRUDAN (giriş noktası
        # atlanarak) çağrılırsa kendi başına da güvenli olsun diye —
        # bkz. `UI/admin_common.py::sayfa_erisimi_var_mi` docstring'i.
        if not admin_common.sayfa_erisimi_var_mi(self._pencere):
            return
        self._restyle()
        self._load()

    def _restyle(self) -> None:
        T = self._T
        self.setStyleSheet(admin_common.stil(T))
        self._btn_role.setStyleSheet(admin_common.btn_stil(T))
        self._btn_chain.setStyleSheet(admin_common.btn_stil(T))
        self._btn_refresh.setStyleSheet(admin_common.btn_stil(T))
        self._btn_delete.setStyleSheet(admin_common.btn_danger_stil(T))
        self._on_selection_changed()  # kara listeye al/çıkar rengini tazeler

    # ------------------------------------------------------------------
    # Veri yükleme
    # ------------------------------------------------------------------

    def _load(self) -> None:
        self._table.setRowCount(0)
        try:
            # Sorgu `CORE/usb_tokens.py`'de — Profil sayfasının "Cihazlar ve
            # oturum" bölümüyle PAYLAŞILAN tek kaynak, bkz. o modülün
            # docstring'i.
            kayitlar = token_kayitlarini_getir(DBManager())
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı Hatası", str(exc))
            return

        current_hwid = self._pencere._hwid
        for kayit in kayitlar:
            r = self._table.rowCount()
            self._table.insertRow(r)

            # Col 0 — HWID (full stored in UserRole)
            hwid_item = QTableWidgetItem(
                kayit.hwid[:24] + "…" if len(kayit.hwid) > 24 else kayit.hwid
            )
            hwid_item.setData(admin_common.ROLE_HWID, kayit.hwid)
            hwid_item.setData(admin_common.ROLE_BLACKLISTED, kayit.blacklisted)
            if kayit.hwid == current_hwid:
                hwid_item.setForeground(QColor(self._T["accent"]))
            self._table.setItem(r, 0, hwid_item)

            # Col 1 — Token ID (short)
            token_id = kayit.token_id
            self._table.setItem(
                r, 1,
                QTableWidgetItem(token_id[:12] + "…" if len(token_id) > 12 else token_id or "—"),
            )

            # Col 2 — Rol
            self._table.setItem(r, 2, QTableWidgetItem(kayit.role or "—"))

            # Col 3 — Son Giriş
            self._table.setItem(r, 3, QTableWidgetItem(self._fmt_ts(kayit.last_login)))

            # Col 4 — Durum
            status_item = QTableWidgetItem("Kara Liste" if kayit.blacklisted else "Aktif")
            status_item.setForeground(
                QColor(self._T["red"] if kayit.blacklisted else self._T["green"])
            )
            self._table.setItem(r, 4, status_item)

        self._on_selection_changed()

    @staticmethod
    def _fmt_ts(ts: str) -> str:
        return ts.replace("T", " ").rstrip("Z") if ts else "—"

    # ------------------------------------------------------------------
    # Seçim değişikliği → buton durumu
    # ------------------------------------------------------------------

    def _on_selection_changed(self) -> None:
        selected = self._table.selectionModel().selectedRows()
        has_sel  = bool(selected)

        if not has_sel:
            self._btn_blacklist.setEnabled(False)
            self._btn_role.setEnabled(False)
            self._btn_delete.setEnabled(False)
            self._btn_blacklist.setText("Kara Listeye Al")
            self._btn_blacklist.setStyleSheet(admin_common.btn_danger_stil(self._T))
            return

        row        = selected[0].row()
        item       = self._table.item(row, 0)
        full_hwid  = item.data(admin_common.ROLE_HWID) if item else ""
        blacklisted = bool(item.data(admin_common.ROLE_BLACKLISTED)) if item else False
        is_self    = full_hwid == self._pencere._hwid

        # Kara liste butonu — metin ve stil blacklisted durumuna göre değişir
        if blacklisted:
            self._btn_blacklist.setText("Kara Listeden Çıkar")
            self._btn_blacklist.setStyleSheet(admin_common.btn_success_stil(self._T))
        else:
            self._btn_blacklist.setText("Kara Listeye Al")
            self._btn_blacklist.setStyleSheet(admin_common.btn_danger_stil(self._T))

        # Aktif USB kara listeye alınamaz / silinemez
        self._btn_blacklist.setEnabled(not is_self)
        self._btn_role.setEnabled(True)
        self._btn_delete.setEnabled(not is_self)

    # ------------------------------------------------------------------
    # Seçili satırdan HWID / durum al
    # ------------------------------------------------------------------

    def _selected_hwid(self) -> str | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self._table.item(rows[0].row(), 0)
        return item.data(admin_common.ROLE_HWID) if item else None

    def _selected_blacklisted(self) -> bool:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return False
        item = self._table.item(rows[0].row(), 0)
        return bool(item.data(admin_common.ROLE_BLACKLISTED)) if item else False

    def _selected_role(self) -> str:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return ""
        item = self._table.item(rows[0].row(), 2)
        return item.text() if item else ""

    # ------------------------------------------------------------------
    # Eylem: Kara listeye al / çıkar
    # ------------------------------------------------------------------

    def _on_toggle_blacklist(self) -> None:
        if not admin_common.yonetici_hala_yetkili(self, self._pencere):  # B-064/B-066
            return
        hwid = self._selected_hwid()
        if not hwid:
            return

        if self._selected_blacklisted():
            self._unblacklist(hwid)
        else:
            self._do_blacklist(hwid)

    def _do_blacklist(self, hwid: str) -> None:
        confirm = QMessageBox.question(
            self,
            "Kara Listeye Al — Onay",
            f"Bu USB cihazı kara listeye alınacak:\n\n{hwid}\n\n"
            "Cihaz bir daha giriş yapamayacak. Devam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            blacklist_usb(hwid)  # kendi içinde audit_log'a yazıyor
            QMessageBox.information(
                self, "Kara Listeye Alındı",
                f"USB cihazı kara listeye alındı:\n{hwid}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))
            return
        self._load()

    def _unblacklist(self, hwid: str) -> None:
        confirm = QMessageBox.question(
            self,
            "Kara Listeden Çıkar — Onay",
            f"Bu USB cihazı kara listeden çıkarılacak:\n\n{hwid}\n\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            db = DBManager()
            db.execute(
                "UPDATE usb_tokens SET blacklisted = 0 WHERE hwid = ?", (hwid,)
            )
            db.log("usb_unblacklisted", detail=f"hwid={hwid}")
            QMessageBox.information(
                self, "Kara Listeden Çıkarıldı",
                f"USB cihazı kara listeden çıkarıldı:\n{hwid}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))
            return
        self._load()

    # ------------------------------------------------------------------
    # Eylem: Rol değiştir
    # ------------------------------------------------------------------

    def _on_change_role(self) -> None:
        if not admin_common.yonetici_hala_yetkili(self, self._pencere):  # B-064/B-066
            return
        hwid = self._selected_hwid()
        if not hwid:
            return

        old_role = self._selected_role()

        if is_admin_role(old_role):
            QMessageBox.warning(
                self,
                "İzin Verilmedi",
                "Yönetici rolü değiştirilemez.\n\n"
                "Yönetici hesabının rolünü düşürmek sistemin kilitleneceği anlamına gelir.",
            )
            return

        default_idx = admin_common.ROLES.index(old_role) if old_role in admin_common.ROLES else 0

        new_role, ok = QInputDialog.getItem(
            self,
            "Rol Değiştir",
            f"Yeni rol seçin:\n{hwid[:36]}",
            admin_common.ROLES,
            current=default_idx,
            editable=False,
        )
        if not ok or new_role == old_role:
            return

        pin, ok = QInputDialog.getText(
            self,
            "PIN Doğrulama",
            "Vault'u güncellemek için USB sahibinin PIN'ini girin:",
            QLineEdit.Password,
        )
        if not ok or not pin.strip():
            return

        try:
            change_vault_role(hwid, pin.strip(), new_role)
            DBManager().log(
                "usb_role_changed",
                detail=f"hwid={hwid} role={new_role} old_role={old_role}",
            )
            QMessageBox.information(
                self,
                "Rol Güncellendi",
                f"USB rolü başarıyla değiştirildi.\n\nEski rol: {old_role}\nYeni rol: {new_role}",
            )
        except FileNotFoundError:
            QMessageBox.warning(
                self,
                "Vault Bulunamadı",
                "Bu USB'ye ait vault dosyası disk üzerinde mevcut değil.\n"
                "Rol değiştirmek için USB sahibi yeniden kurulum yapmalıdır.",
            )
            return
        except VaultTamperedError as exc:
            QMessageBox.warning(
                self,
                "Vault Bütünlüğü Hatası",
                "Vault HMAC doğrulaması başarısız — vault başka bir USB'ye ait olabilir.\n\n"
                f"Detay: {exc}",
            )
            return
        except ValueError as exc:
            QMessageBox.warning(
                self, "PIN Hatalı veya Vault Bozuk", str(exc)
            )
            return
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))
            return

        self._load()

    # ------------------------------------------------------------------
    # Eylem: USB kaydını sil
    # ------------------------------------------------------------------

    def _on_delete(self) -> None:
        if not admin_common.yonetici_hala_yetkili(self, self._pencere):  # B-064/B-066
            return
        hwid = self._selected_hwid()
        if not hwid:
            return

        confirm = QMessageBox.question(
            self,
            "USB Sil — Onay",
            f"Bu USB kaydı kalıcı olarak silinecek:\n\n{hwid}\n\n"
            "Bu işlem geri alınamaz. Devam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        try:
            db = DBManager()
            # B-060 düzeltmesi: yalnızca usb_tokens/kasa silmek `users`
            # satırını yetim bırakırdı VE `users.hwid` artık UNIQUE
            # olduğu için (bkz. B-060/061) aynı HWID'in yeniden kaydını
            # KALICI olarak kilitlerdi. Bir USB kaydını silmek, o HWID'i
            # bir yönetici kararıyla yeniden kullanılabilir hale
            # getirmenin TEK yolu — ikisi birlikte silinmeli.
            db.execute("DELETE FROM users WHERE hwid = ?", (hwid,))
            # usb_tokens satırı + kasadaki share_2 + per-HWID vault dosyası
            discard_vault(hwid)
            db.log("usb_deleted", detail=f"hwid={hwid}")
            QMessageBox.information(self, "Silindi", f"USB kaydı silindi:\n{hwid}")
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))
            return

        self._load()


__all__ = ["SAYFA_ADI", "UsbTokensView"]
