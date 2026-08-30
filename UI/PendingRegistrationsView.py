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
"""
from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
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

        root.addWidget(self._make_pending_table())
        root.addLayout(self._make_pending_btn_bar())
        self._title = title

    def _make_pending_table(self) -> QTableWidget:
        self._pending_table = QTableWidget(0, 4)
        self._pending_table.setHorizontalHeaderLabels(
            ["Kullanıcı Adı", "HWID", "Rol", "Kayıt Tarihi"]
        )
        hdr = self._pending_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._pending_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._pending_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._pending_table.setSelectionMode(QTableWidget.SingleSelection)
        self._pending_table.verticalHeader().setVisible(False)
        self._pending_table.itemSelectionChanged.connect(
            self._on_pending_selection_changed
        )
        return self._pending_table

    def _make_pending_btn_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self._btn_approve = QPushButton("✓  Onayla")
        self._btn_approve.setCursor(Qt.PointingHandCursor)
        self._btn_approve.setEnabled(False)
        self._btn_approve.clicked.connect(self._on_approve)
        bar.addWidget(self._btn_approve)

        self._btn_reject = QPushButton("✕  Reddet")
        self._btn_reject.setCursor(Qt.PointingHandCursor)
        self._btn_reject.setEnabled(False)
        self._btn_reject.clicked.connect(self._on_reject)
        bar.addWidget(self._btn_reject)

        self._btn_new = QPushButton("＋  Yeni Kullanıcı Kaydet")
        self._btn_new.setCursor(Qt.PointingHandCursor)
        self._btn_new.clicked.connect(self._on_new_user)
        bar.addWidget(self._btn_new)

        bar.addStretch()

        self._btn_refresh = QPushButton("Yenile")
        self._btn_refresh.setCursor(Qt.PointingHandCursor)
        self._btn_refresh.clicked.connect(self._load_pending)
        bar.addWidget(self._btn_refresh)

        return bar

    # ------------------------------------------------------------------
    # Sayfa (yeniden) görünür olduğunda — bkz. UsbTokensView.yenile()'nin
    # aynı "bayat stil" gerekçesi.
    # ------------------------------------------------------------------

    def yenile(self) -> None:
        self._restyle()
        self._load_pending()

    def _restyle(self) -> None:
        T = self._T
        self.setStyleSheet(admin_common.stil(T))
        self._btn_approve.setStyleSheet(admin_common.btn_success_stil(T))
        self._btn_reject.setStyleSheet(admin_common.btn_danger_stil(T))
        self._btn_new.setStyleSheet(admin_common.btn_stil(T))
        self._btn_refresh.setStyleSheet(admin_common.btn_stil(T))

    # ------------------------------------------------------------------
    # Veri yükleme
    # ------------------------------------------------------------------

    def _load_pending(self) -> None:
        self._pending_table.setRowCount(0)
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

        for row in rows:
            r = self._pending_table.rowCount()
            self._pending_table.insertRow(r)

            username_item = QTableWidgetItem(row["username"] or "—")
            username_item.setData(Qt.UserRole, row["hwid"])        # hwid in UserRole
            username_item.setData(Qt.UserRole + 1, row["username"])
            self._pending_table.setItem(r, 0, username_item)

            hwid = row["hwid"] or ""
            self._pending_table.setItem(
                r, 1,
                QTableWidgetItem(hwid[:28] + "…" if len(hwid) > 28 else hwid or "—"),
            )
            self._pending_table.setItem(r, 2, QTableWidgetItem(row["role"] or "—"))
            ts = (row["created_at"] or "").replace("T", " ").rstrip("Z")
            self._pending_table.setItem(r, 3, QTableWidgetItem(ts or "—"))

        self._on_pending_selection_changed()

    def _on_pending_selection_changed(self) -> None:
        has_sel = bool(self._pending_table.selectionModel().selectedRows())
        self._btn_approve.setEnabled(has_sel)
        self._btn_reject.setEnabled(has_sel)

    def _selected_pending_hwid(self) -> str | None:
        rows = self._pending_table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self._pending_table.item(rows[0].row(), 0)
        return item.data(Qt.UserRole) if item else None

    def _selected_pending_username(self) -> str | None:
        rows = self._pending_table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self._pending_table.item(rows[0].row(), 0)
        return item.data(Qt.UserRole + 1) if item else None

    def _on_approve(self) -> None:
        if not admin_common.yonetici_hala_yetkili(self, self._pencere):  # B-064/B-066
            return
        hwid = self._selected_pending_hwid()
        username = self._selected_pending_username()
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

    def _on_new_user(self) -> None:
        if not admin_common.yonetici_hala_yetkili(self, self._pencere):  # B-064/B-066
            return
        from UI.RegisterDialog import RegisterDialog
        dlg = RegisterDialog(admin_hwid=self._pencere._hwid, parent=self)
        if dlg.exec() == RegisterDialog.Accepted:
            self._load_pending()

    def _on_reject(self) -> None:
        if not admin_common.yonetici_hala_yetkili(self, self._pencere):  # B-064/B-066
            return
        hwid = self._selected_pending_hwid()
        username = self._selected_pending_username()
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
