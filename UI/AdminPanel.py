"""HYCLEUS — USB Yönetim Paneli"""
from __future__ import annotations

import re

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from CORE.vault_manager import (
    VaultTamperedError,
    blacklist_usb,
    change_vault_role,
    delete_usb_token,
)
from DB.db_manager import DBManager

_ROLES = ["Yönetici", "Standart", "Salt Okunur"]

_STYLE = """
QDialog { background: #1e1e2e; color: #cdd6f4; }
QLabel  { color: #cdd6f4; }
QTableWidget {
    background: #181825;
    color: #cdd6f4;
    gridline-color: #313244;
    border: 1px solid #313244;
    border-radius: 4px;
    font-size: 12px;
}
QTableWidget::item:selected { background: #313244; }
QHeaderView::section {
    background: #1e1e2e;
    color: #89b4fa;
    border: none;
    border-bottom: 1px solid #313244;
    padding: 4px 8px;
    font-weight: 600;
    font-size: 12px;
}
"""

_BTN = (
    "QPushButton{color:#cdd6f4;background:#313244;border:none;"
    "border-radius:6px;padding:5px 14px;font-size:12px;}"
    "QPushButton:hover{background:#45475a;}"
    "QPushButton:disabled{color:#45475a;background:#1e1e2e;border:none;}"
)
_BTN_DANGER = (
    "QPushButton{color:#f38ba8;background:#2d1818;border:1px solid #3d2020;"
    "border-radius:6px;padding:5px 14px;font-size:12px;}"
    "QPushButton:hover{background:#3d2020;}"
    "QPushButton:disabled{color:#45475a;background:#1e1e2e;border:1px solid #313244;}"
)
_BTN_SUCCESS = (
    "QPushButton{color:#a6e3a1;background:#1a2d1a;border:1px solid #2a3d2a;"
    "border-radius:6px;padding:5px 14px;font-size:12px;}"
    "QPushButton:hover{background:#2a3d2a;}"
    "QPushButton:disabled{color:#45475a;background:#1e1e2e;border:1px solid #313244;}"
)

# Qt.UserRole slots for column-0 items
_ROLE_HWID        = Qt.UserRole          # str  — tam HWID
_ROLE_BLACKLISTED = Qt.UserRole + 1      # bool — kara liste durumu


class AdminPanel(QDialog):
    def __init__(self, current_hwid: str, role: str = "Yönetici", parent=None) -> None:
        super().__init__(parent)
        self._current_hwid = current_hwid
        self._caller_role  = role
        self.setWindowTitle("HYCLEUS — USB Yönetim Paneli")
        self.setStyleSheet(_STYLE)

        if role != "Yönetici":
            self.setFixedSize(360, 120)
            lay = QVBoxLayout(self)
            lay.setContentsMargins(24, 20, 24, 20)
            lay.setSpacing(16)
            lbl = QLabel("Bu alana erişim yetkiniz yok.")
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet("color:#f38ba8; font-size:13px;")
            lay.addWidget(lbl)
            btn = QPushButton("Kapat")
            btn.setStyleSheet(_BTN)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(self.reject)
            lay.addWidget(btn)
            return

        self.setMinimumSize(960, 540)
        self._build_ui()
        self._load()
        self._load_pending()
        self._load_settings()

    # ------------------------------------------------------------------
    # UI kurulumu
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(16, 16, 16, 12)

        title = QLabel("USB Yönetim Paneli")
        title.setFont(QFont("Arial", 13, QFont.Bold))
        title.setStyleSheet("color:#cdd6f4; margin-bottom:2px;")
        root.addWidget(title)

        tabs = QTabWidget()
        tabs.setStyleSheet(
            "QTabWidget::pane{border:1px solid #313244;border-radius:4px;}"
            "QTabBar::tab{background:#1e1e2e;color:#a6adc8;padding:6px 18px;"
            "border:1px solid #313244;border-bottom:none;border-radius:4px 4px 0 0;}"
            "QTabBar::tab:selected{background:#313244;color:#cdd6f4;}"
        )

        # Sekme 1 — USB Tokenlar
        usb_page = QWidget()
        usb_layout = QVBoxLayout(usb_page)
        usb_layout.setContentsMargins(0, 8, 0, 0)
        usb_layout.setSpacing(8)
        usb_layout.addWidget(self._make_table())
        usb_layout.addLayout(self._make_btn_bar())
        tabs.addTab(usb_page, "USB Tokenlar")

        # Sekme 2 — Bekleyen Kayıtlar
        pending_page = QWidget()
        pending_layout = QVBoxLayout(pending_page)
        pending_layout.setContentsMargins(0, 8, 0, 0)
        pending_layout.setSpacing(8)
        pending_layout.addWidget(self._make_pending_table())
        pending_layout.addLayout(self._make_pending_btn_bar())
        tabs.addTab(pending_page, "Bekleyen Kayıtlar")

        # Sekme 3 — Ayarlar
        tabs.addTab(self._make_settings_page(), "Ayarlar")

        # ÖNERİ (uygulanmadı) — Sekme 4: "Saklama Envanteri"
        #
        # KVKK envanter raporunun CORE tarafı hazır (CORE/inventory.py);
        # burada yalnızca UI eksik. Doğal yeri bu panel: rapor denetim
        # belgesidir ve zaten yönetici yetkisi isteyen bir ekranda durmalı.
        #
        #   from CORE.inventory import (
        #       generate_retention_inventory, export_inventory_csv,
        #       export_inventory_pdf, ALL_STATUSES, STATUS_LABELS,
        #   )
        #
        #   rows = generate_retention_inventory(
        #       DBManager(),
        #       profile_id=secili_profil_id,   # hepsi için None
        #       status=secili_durumlar,        # hepsi için None
        #       added_from=..., added_to=...,  # opsiyonel tarih aralığı
        #   )
        #   # tabloya bas: row.as_export_row() sütun sırası COLUMN_HEADERS ile aynı
        #   # "CSV indir" / "PDF indir" düğmeleri:
        #   path, _ = QFileDialog.getSaveFileName(self, "Kaydet", "envanter.csv")
        #   export_inventory_csv(rows, path)
        #
        # Alternatif yer: main_window.py araç çubuğuna "Envanter Raporu"
        # düğmesi. Panel tercih edilmeli — rapor tüm dosyaları kapsıyor,
        # main_window ise o an seçili klasör/etikete göre çalışıyor.
        #
        # NOT: "Sahip" sütunu yalnızca bu düzeltmeden SONRA eklenen dosyalarda
        # dolu gelir (files.added_by artık yazılıyor — CORE/file_records.py).
        # Daha eski kayıtlarda "bilinmiyor" görünür ve öyle kalmalıdır:
        # kimin yüklediği gerçekten bilinmiyor, geriye dönük dolgu tahmin olurdu.

        root.addWidget(tabs)

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
        self._btn_blacklist.setStyleSheet(_BTN_DANGER)
        self._btn_blacklist.setCursor(Qt.PointingHandCursor)
        self._btn_blacklist.setEnabled(False)
        self._btn_blacklist.clicked.connect(self._on_toggle_blacklist)
        bar.addWidget(self._btn_blacklist)

        self._btn_role = QPushButton("Rolü Değiştir")
        self._btn_role.setStyleSheet(_BTN)
        self._btn_role.setCursor(Qt.PointingHandCursor)
        self._btn_role.setEnabled(False)
        self._btn_role.clicked.connect(self._on_change_role)
        bar.addWidget(self._btn_role)

        self._btn_delete = QPushButton("Sil")
        self._btn_delete.setStyleSheet(_BTN_DANGER)
        self._btn_delete.setCursor(Qt.PointingHandCursor)
        self._btn_delete.setEnabled(False)
        self._btn_delete.clicked.connect(self._on_delete)
        bar.addWidget(self._btn_delete)

        bar.addStretch()

        btn_refresh = QPushButton("Yenile")
        btn_refresh.setStyleSheet(_BTN)
        btn_refresh.setCursor(Qt.PointingHandCursor)
        btn_refresh.clicked.connect(self._load)
        bar.addWidget(btn_refresh)

        return bar

    # ------------------------------------------------------------------
    # Veri yükleme
    # ------------------------------------------------------------------

    def _load(self) -> None:
        self._table.setRowCount(0)
        try:
            rows = DBManager().fetchall(
                """
                SELECT
                    u.hwid,
                    u.token_id,
                    u.blacklisted,
                    u.created_at,
                    (SELECT a.detail FROM audit_log a
                     WHERE a.action IN ('usb_setup_complete', 'usb_role_changed')
                       AND a.detail LIKE 'hwid=' || u.hwid || '%'
                     ORDER BY a.timestamp DESC LIMIT 1)  AS role_detail,
                    (SELECT a.timestamp FROM audit_log a
                     WHERE a.action = 'usb_auth_success'
                       AND a.detail LIKE 'hwid=' || u.hwid || '%'
                     ORDER BY a.timestamp DESC LIMIT 1)  AS last_login
                FROM usb_tokens u
                ORDER BY u.created_at DESC
                """
            )
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı Hatası", str(exc))
            return

        for row in rows:
            hwid       = row["hwid"]
            blacklisted = bool(row["blacklisted"])
            role       = self._parse_field(row["role_detail"] or "", "role")
            last_login = self._fmt_ts(row["last_login"] or "")
            token_id   = row["token_id"] or ""

            r = self._table.rowCount()
            self._table.insertRow(r)

            # Col 0 — HWID (full stored in UserRole)
            hwid_item = QTableWidgetItem(
                hwid[:24] + "…" if len(hwid) > 24 else hwid
            )
            hwid_item.setData(_ROLE_HWID, hwid)
            hwid_item.setData(_ROLE_BLACKLISTED, blacklisted)
            if hwid == self._current_hwid:
                hwid_item.setForeground(QColor("#89b4fa"))
            self._table.setItem(r, 0, hwid_item)

            # Col 1 — Token ID (short)
            self._table.setItem(
                r, 1,
                QTableWidgetItem(token_id[:12] + "…" if len(token_id) > 12 else token_id or "—"),
            )

            # Col 2 — Rol
            self._table.setItem(r, 2, QTableWidgetItem(role or "—"))

            # Col 3 — Son Giriş
            self._table.setItem(r, 3, QTableWidgetItem(last_login))

            # Col 4 — Durum
            status_item = QTableWidgetItem("Kara Liste" if blacklisted else "Aktif")
            status_item.setForeground(
                QColor("#f38ba8" if blacklisted else "#a6e3a1")
            )
            self._table.setItem(r, 4, status_item)

        self._on_selection_changed()

    @staticmethod
    def _parse_field(detail: str, key: str) -> str:
        """key=value çiftini parse eder; değer boşluk içerebilir.

        "hwid=X role=Salt Okunur old_role=Y" formatında çalışır:
        sonraki 'kelime=' kalıbı ya da satır sonu değerin bitişini belirler.
        """
        prefix = f"{key}="
        start = detail.find(prefix)
        if start == -1:
            return ""
        val_start = start + len(prefix)
        m = re.search(r"\s+\w+=", detail[val_start:])
        end = val_start + m.start() if m else len(detail)
        return detail[val_start:end].strip()

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
            self._btn_blacklist.setStyleSheet(_BTN_DANGER)
            return

        row        = selected[0].row()
        item       = self._table.item(row, 0)
        full_hwid  = item.data(_ROLE_HWID) if item else ""
        blacklisted = bool(item.data(_ROLE_BLACKLISTED)) if item else False
        is_self    = full_hwid == self._current_hwid

        # Kara liste butonu — metin ve stil blacklisted durumuna göre değişir
        if blacklisted:
            self._btn_blacklist.setText("Kara Listeden Çıkar")
            self._btn_blacklist.setStyleSheet(_BTN_SUCCESS)
        else:
            self._btn_blacklist.setText("Kara Listeye Al")
            self._btn_blacklist.setStyleSheet(_BTN_DANGER)

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
        return item.data(_ROLE_HWID) if item else None

    def _selected_blacklisted(self) -> bool:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return False
        item = self._table.item(rows[0].row(), 0)
        return bool(item.data(_ROLE_BLACKLISTED)) if item else False

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
        hwid = self._selected_hwid()
        if not hwid:
            return

        old_role = self._selected_role()

        if old_role == "Yönetici":
            QMessageBox.warning(
                self,
                "İzin Verilmedi",
                "Yönetici rolü değiştirilemez.\n\n"
                "Yönetici hesabının rolünü düşürmek sistemin kilitleneceği anlamına gelir.",
            )
            return

        default_idx = _ROLES.index(old_role) if old_role in _ROLES else 0

        new_role, ok = QInputDialog.getItem(
            self,
            "Rol Değiştir",
            f"Yeni rol seçin:\n{hwid[:36]}",
            _ROLES,
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
            # DB satırı + kasadaki share_2 birlikte silinir
            delete_usb_token(hwid)
            db.log("usb_deleted", detail=f"hwid={hwid}")
            QMessageBox.information(self, "Silindi", f"USB kaydı silindi:\n{hwid}")
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))
            return

        self._load()

    # ------------------------------------------------------------------
    # Bekleyen kayıtlar sekmesi
    # ------------------------------------------------------------------

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
        self._btn_approve.setStyleSheet(_BTN_SUCCESS)
        self._btn_approve.setCursor(Qt.PointingHandCursor)
        self._btn_approve.setEnabled(False)
        self._btn_approve.clicked.connect(self._on_approve)
        bar.addWidget(self._btn_approve)

        self._btn_reject = QPushButton("✕  Reddet")
        self._btn_reject.setStyleSheet(_BTN_DANGER)
        self._btn_reject.setCursor(Qt.PointingHandCursor)
        self._btn_reject.setEnabled(False)
        self._btn_reject.clicked.connect(self._on_reject)
        bar.addWidget(self._btn_reject)

        btn_new = QPushButton("＋  Yeni Kullanıcı Kaydet")
        btn_new.setStyleSheet(_BTN)
        btn_new.setCursor(Qt.PointingHandCursor)
        btn_new.clicked.connect(self._on_new_user)
        bar.addWidget(btn_new)

        bar.addStretch()

        btn_refresh = QPushButton("Yenile")
        btn_refresh.setStyleSheet(_BTN)
        btn_refresh.setCursor(Qt.PointingHandCursor)
        btn_refresh.clicked.connect(self._load_pending)
        bar.addWidget(btn_refresh)

        return bar

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
                detail=f"hwid={hwid} username={username} approved_by={self._current_hwid}",
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
        from UI.RegisterDialog import RegisterDialog
        dlg = RegisterDialog(admin_hwid=self._current_hwid, parent=self)
        if dlg.exec() == RegisterDialog.Accepted:
            self._load_pending()

    def _on_reject(self) -> None:
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
            # DB satırı + kasadaki share_2 birlikte silinir
            delete_usb_token(hwid)
            db.log(
                "user_rejected",
                detail=f"hwid={hwid} username={username} rejected_by={self._current_hwid}",
            )
            QMessageBox.information(
                self, "Reddedildi",
                f"'{username}' kullanıcısının kaydı reddedildi ve silindi.",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))
            return

        self._load_pending()

    # ------------------------------------------------------------------
    # Ayarlar sekmesi
    # ------------------------------------------------------------------

    _TTL_OPTIONS = (1, 6, 12, 24, 48)

    def _make_settings_page(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(14)

        header = QLabel("Sistem Ayarları")
        header.setStyleSheet("color:#cdd6f4; font-size:13px; font-weight:bold;")
        lay.addWidget(header)

        sep = QLabel()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background:#313244;")
        lay.addWidget(sep)

        ttl_lbl = QLabel("İmha Odası varsayılan TTL süresi")
        ttl_lbl.setStyleSheet("color:#89b4fa; font-size:12px; font-weight:600;")
        lay.addWidget(ttl_lbl)

        row = QHBoxLayout()
        row.setSpacing(10)

        self._ttl_combo = QComboBox()
        for h in self._TTL_OPTIONS:
            self._ttl_combo.addItem(f"{h} saat", h)
        self._ttl_combo.setFixedWidth(110)
        self._ttl_combo.setStyleSheet(
            "QComboBox{background:#313244;color:#cdd6f4;border:1px solid #45475a;"
            "border-radius:6px;padding:5px 10px;font-size:12px;}"
            "QComboBox::drop-down{border:none;width:20px;}"
            "QComboBox QAbstractItemView{background:#313244;color:#cdd6f4;"
            "border:1px solid #45475a;selection-background-color:#45475a;}"
        )
        row.addWidget(self._ttl_combo)

        hint = QLabel("sonra İmha Odası'ndaki dosyalar otomatik silinir")
        hint.setStyleSheet("color:#a6adc8; font-size:12px;")
        row.addWidget(hint)
        row.addStretch()
        lay.addLayout(row)

        btn_save = QPushButton("Kaydet")
        btn_save.setStyleSheet(_BTN_SUCCESS)
        btn_save.setCursor(Qt.PointingHandCursor)
        btn_save.setFixedWidth(100)
        btn_save.clicked.connect(self._on_save_settings)
        lay.addWidget(btn_save)

        lay.addStretch()
        return page

    def _load_settings(self) -> None:
        try:
            current = int(DBManager().get_setting("imha_ttl_hours", "24"))
        except Exception:
            current = 24
        for i in range(self._ttl_combo.count()):
            if self._ttl_combo.itemData(i) == current:
                self._ttl_combo.setCurrentIndex(i)
                break

    def _on_save_settings(self) -> None:
        hours = self._ttl_combo.currentData()
        try:
            db = DBManager()
            db.set_setting("imha_ttl_hours", str(hours))
            db.log("setting_changed",
                   detail=f"key=imha_ttl_hours value={hours} hwid={self._current_hwid}")
            QMessageBox.information(
                self, "Kaydedildi",
                f"İmha Odası TTL süresi {hours} saat olarak güncellendi.",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))
