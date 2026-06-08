import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QDragEnterEvent,
    QDragMoveEvent,
    QDropEvent,
    QFont,
    QPaintEvent,
    QPainter,
    QResizeEvent,
)
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsBlurEffect,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from CORE.crypto import AuthenticationError, encrypt_file
from CORE.scanner import ScanResult, scan_file
from CORE.usb_manager import get_usb_hwid
from CORE.vault_manager import (
    USBAuthError,
    VaultTamperedError,
    authenticate_usb,
    blacklist_usb,
    read_vault_role,
)
from DB.db_manager import DBManager
from UI.AdminPanel import AdminPanel
from UI.AuditLogDialog import AuditLogDialog

_LABEL_COLORS: dict[str, str] = {
    "Genel":    "#cdd6f4",
    "Kritik":   "#f38ba8",
    "Karantina":"#f9e2af",
    "Imha":     "#a6e3a1",
}

_ROLE_COLORS: dict[str, str] = {
    "Yönetici":    "#89b4fa",
    "Standart":    "#a6e3a1",
    "Salt Okunur": "#f9e2af",
}

# (sidebar_display, db_label)
_SIDEBAR_ITEMS = [
    ("Genel",       "Genel"),
    ("Kritik",      "Kritik"),
    ("Karantina",   "Karantina"),
    ("İmha Odası",  "Imha"),
]

_BTN_STYLE_NORMAL = (
    "QPushButton{color:#cdd6f4;background:transparent;border:none;"
    "border-radius:6px;padding:8px 10px;text-align:left;font-size:13px;}"
    "QPushButton:hover{background:#313244;}"
)
_BTN_STYLE_ACTIVE = (
    "QPushButton{color:#cdd6f4;background:#45475a;border:none;"
    "border-radius:6px;padding:8px 10px;text-align:left;font-size:13px;}"
)

_VERDICT_BADGE: dict[str, tuple[str, str]] = {
    "clean":      ("✓ Temiz",    "#a6e3a1"),
    "suspicious": ("⚠ Şüpheli", "#f9e2af"),
    "malicious":  ("✗ Zararlı",  "#f38ba8"),
    "unknown":    ("? Bilinmiyor","#6c7086"),
}


class _ScanWorker(QObject):
    finished = Signal(int, object)  # (row, ScanResult)

    def __init__(self, path: Path, file_id: int, row: int) -> None:
        super().__init__()
        self._path    = path
        self._file_id = file_id
        self._row     = row

    def run(self) -> None:
        result = scan_file(self._path, file_id=self._file_id)
        self.finished.emit(self._row, result)


class _LockOverlay(QWidget):
    """USB çekilince ana pencerenin üstünü örten kilit katmanı."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.hide()

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(16)

        icon = QLabel("🔒")
        icon.setAlignment(Qt.AlignCenter)
        icon.setStyleSheet("font-size:48px; background:transparent;")
        layout.addWidget(icon)

        msg = QLabel("USB Token çıkarıldı\nlütfen yeniden takın")
        msg.setAlignment(Qt.AlignCenter)
        msg.setStyleSheet(
            "color:#cdd6f4; font-size:16px; font-weight:600; background:transparent;"
        )
        layout.addWidget(msg)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(0, 0, 0, 185))


class HycleusWindow(QMainWindow):
    def __init__(self, hwid: str, key: bytes, role: str = "Yönetici"):
        super().__init__()
        self._hwid = hwid
        self._key = key
        self._role = role
        self._active_btn: QPushButton | None = None
        self._nav_btns: dict[str, QPushButton] = {}
        self._current_label: str = "Genel"
        self._locked = False
        self._authenticating = False
        self._scan_threads: list[QThread] = []
        self.setWindowTitle("HYCLEUS — Beta 1.2")
        self.setMinimumSize(900, 600)
        self.setAcceptDrops(True)
        self._build_ui()
        self._apply_role_restrictions()

        self._blur = QGraphicsBlurEffect(self)
        self._blur.setBlurRadius(10)
        self._overlay = _LockOverlay(self)

        self._usb_timer = QTimer(self)
        self._usb_timer.setInterval(3000)
        self._usb_timer.timeout.connect(self._poll_usb)
        self._usb_timer.start()

        self._refresh_usb_badge()
        self._on_sidebar_click("Genel", self._nav_btns["Genel"])

    # ------------------------------------------------------------------
    # UI kurulumu
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._make_sidebar())
        root.addWidget(self._make_content())

    def _make_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setFixedWidth(180)
        sidebar.setStyleSheet("background:#1e1e2e;")
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(12, 16, 12, 16)

        title = QLabel("HYCLEUS")
        title.setFont(QFont("Arial", 13, QFont.Bold))
        title.setStyleSheet("color:#cdd6f4; margin-bottom:16px;")
        layout.addWidget(title)

        for display_name, db_label in _SIDEBAR_ITEMS:
            btn = QPushButton(display_name)
            btn.setStyleSheet(_BTN_STYLE_NORMAL)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda checked=False, lbl=db_label, b=btn: self._on_sidebar_click(lbl, b))
            self._nav_btns[db_label] = btn
            layout.addWidget(btn)

        layout.addStretch()

        # ── Yönetici araçları — her zaman oluşturulur, _apply_role_restrictions ile gösterilir/gizlenir
        self._admin_sep = QFrame()
        self._admin_sep.setFrameShape(QFrame.HLine)
        self._admin_sep.setStyleSheet("color:#313244; margin:4px 0;")
        layout.addWidget(self._admin_sep)

        self._admin_label = QLabel("Yönetici")
        self._admin_label.setStyleSheet(
            "color:#6c7086; font-size:10px; font-weight:600;"
            "padding:0 4px; letter-spacing:1px;"
        )
        layout.addWidget(self._admin_label)

        self._blacklist_btn = QPushButton("Kara Listeye Al")
        self._blacklist_btn.setStyleSheet(
            "QPushButton{color:#f38ba8;background:transparent;border:none;"
            "border-radius:6px;padding:8px 10px;text-align:left;font-size:13px;}"
            "QPushButton:hover{background:#313244;}"
        )
        self._blacklist_btn.setCursor(Qt.PointingHandCursor)
        self._blacklist_btn.clicked.connect(self._on_blacklist_usb)
        layout.addWidget(self._blacklist_btn)

        self._audit_log_btn = QPushButton("Denetim Günlüğü")
        self._audit_log_btn.setStyleSheet(
            "QPushButton{color:#89b4fa;background:transparent;border:none;"
            "border-radius:6px;padding:8px 10px;text-align:left;font-size:13px;}"
            "QPushButton:hover{background:#313244;}"
        )
        self._audit_log_btn.setCursor(Qt.PointingHandCursor)
        self._audit_log_btn.clicked.connect(self._on_open_audit_log)
        layout.addWidget(self._audit_log_btn)

        self._admin_panel_btn = QPushButton("USB Yönetimi")
        self._admin_panel_btn.setStyleSheet(
            "QPushButton{color:#cba6f7;background:transparent;border:none;"
            "border-radius:6px;padding:8px 10px;text-align:left;font-size:13px;}"
            "QPushButton:hover{background:#313244;}"
        )
        self._admin_panel_btn.setCursor(Qt.PointingHandCursor)
        self._admin_panel_btn.clicked.connect(self._on_open_admin_panel)
        layout.addWidget(self._admin_panel_btn)

        self._role_badge = QLabel(self._role)
        self._role_badge.setAlignment(Qt.AlignCenter)
        self._role_badge.setStyleSheet(
            f"color:{_ROLE_COLORS.get(self._role,'#6c7086')};"
            "font-size:11px; font-weight:600; padding:4px 6px;"
            "border:1px solid #313244; border-radius:4px; margin-bottom:4px;"
        )
        layout.addWidget(self._role_badge)

        self._usb_badge = QLabel()
        self._usb_badge.setStyleSheet("font-size:12px; padding:6px;")
        layout.addWidget(self._usb_badge)

        return sidebar

    def _make_content(self) -> QFrame:
        frame = QFrame()
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 16, 16, 8)

        header = QLabel("Dosyalar")
        header.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(header)

        self._search_bar = QLineEdit()
        self._search_bar.setPlaceholderText("Dosya adı veya SHA-256 ile ara...")
        self._search_bar.setStyleSheet(
            "QLineEdit{background:#1e1e2e;color:#cdd6f4;border:1px solid #313244;"
            "border-radius:4px;padding:5px 10px;font-size:12px;}"
            "QLineEdit:focus{border-color:#89b4fa;}"
        )
        self._search_bar.textChanged.connect(self._search_files)
        layout.addWidget(self._search_bar)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Dosya Adı", "Etiket", "Boyut", "Tarih", "Tarama"])
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.Fixed)
        self._table.setColumnWidth(4, 110)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setStyleSheet("gridline-color: #313244;")
        layout.addWidget(self._table)

        self._drop_hint = QLabel("Dosyaları buraya sürükleyin — otomatik karantinaya alınır")
        self._drop_hint.setAlignment(Qt.AlignCenter)
        self._drop_hint.setStyleSheet(
            "color:#45475a; font-size:11px; padding:6px;"
            "border:1px dashed #313244; border-radius:4px; margin-top:4px;"
        )
        layout.addWidget(self._drop_hint)

        return frame

    # ------------------------------------------------------------------
    # Rol kısıtlamaları
    # ------------------------------------------------------------------

    def _apply_role_restrictions(self) -> None:
        is_admin    = self._role == "Yönetici"
        is_readonly = self._role == "Salt Okunur"

        # Admin araçları — yalnızca Yönetici rolünde görünür
        self._admin_sep.setVisible(is_admin)
        self._admin_label.setVisible(is_admin)
        self._blacklist_btn.setVisible(is_admin)
        self._audit_log_btn.setVisible(is_admin)
        self._admin_panel_btn.setVisible(is_admin)

        # Salt Okunur kısıtlamaları — diğer rollerde geri etkinleştirilir
        self.setAcceptDrops(not is_readonly)
        self._nav_btns["Kritik"].setVisible(not is_readonly)
        self._drop_hint.setVisible(not is_readonly)

        # Rol rozeti güncelle
        self._role_badge.setText(self._role)
        self._role_badge.setStyleSheet(
            f"color:{_ROLE_COLORS.get(self._role, '#6c7086')};"
            "font-size:11px; font-weight:600; padding:4px 6px;"
            "border:1px solid #313244; border-radius:4px; margin-bottom:4px;"
        )

    # ------------------------------------------------------------------
    # Yönetici işlemleri
    # ------------------------------------------------------------------

    def _on_blacklist_usb(self) -> None:
        current_hwid = get_usb_hwid() or ""
        hwid, ok = QInputDialog.getText(
            self,
            "Kara Listeye Al",
            "Kara listeye alınacak USB HWID:",
            text=current_hwid,
        )
        if not ok:
            return
        hwid = hwid.strip()
        if not hwid:
            QMessageBox.warning(self, "Kara Liste", "HWID boş olamaz.")
            return

        confirm = QMessageBox.question(
            self,
            "Kara Liste — Onay",
            f"Bu USB cihazı kara listeye alınacak:\n\n{hwid}\n\n"
            "Cihaz bir daha giriş yapamayacak. Devam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        try:
            blacklist_usb(hwid)
            QMessageBox.information(
                self,
                "Kara Liste",
                f"USB cihazı başarıyla kara listeye alındı:\n{hwid}",
            )
        except ValueError as exc:
            QMessageBox.warning(self, "Kara Liste", str(exc))
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))

    def _on_open_audit_log(self) -> None:
        dlg = AuditLogDialog(self)
        dlg.exec()

    def _on_open_admin_panel(self) -> None:
        dlg = AdminPanel(current_hwid=self._hwid, parent=self)
        dlg.exec()

    # ------------------------------------------------------------------
    # Sidebar filtresi
    # ------------------------------------------------------------------

    def _on_sidebar_click(self, db_label: str, btn: QPushButton) -> None:
        if self._active_btn is not None:
            self._active_btn.setStyleSheet(_BTN_STYLE_NORMAL)
        btn.setStyleSheet(_BTN_STYLE_ACTIVE)
        self._active_btn = btn
        self._current_label = db_label
        # Sidebar tıklamasında arama çubuğunu temizle (textChanged sinyali tetiklemeden)
        self._search_bar.blockSignals(True)
        self._search_bar.clear()
        self._search_bar.blockSignals(False)
        self._load_label(db_label)

    def _load_label(self, db_label: str) -> None:
        self._table.setRowCount(0)
        try:
            rows = DBManager().fetchall(
                """
                SELECT f.filename, f.label, f.size_bytes, f.added_at,
                       (SELECT q.reason FROM quarantine q
                        WHERE q.file_id = f.id
                        ORDER BY q.quarantined_at DESC LIMIT 1) AS scan_reason
                FROM files f
                WHERE f.label = ? ORDER BY f.added_at DESC
                """,
                (db_label,),
            )
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı", str(exc))
            return
        self._populate_table(rows)

    def _search_files(self, term: str) -> None:
        term = term.strip()
        if not term:
            self._load_label(self._current_label)
            return
        self._table.setRowCount(0)
        try:
            like = f"%{term}%"
            rows = DBManager().fetchall(
                """
                SELECT f.filename, f.label, f.size_bytes, f.added_at,
                       (SELECT q.reason FROM quarantine q
                        WHERE q.file_id = f.id
                        ORDER BY q.quarantined_at DESC LIMIT 1) AS scan_reason
                FROM files f
                WHERE f.filename LIKE ? OR f.original_sha256 LIKE ?
                ORDER BY f.added_at DESC
                """,
                (like, like),
            )
        except Exception as exc:
            QMessageBox.warning(self, "Arama", str(exc))
            return
        self._populate_table(rows)

    def _populate_table(self, rows: list) -> None:
        for row in rows:
            verdict, mock = "", False
            if row["scan_reason"]:
                try:
                    d = json.loads(row["scan_reason"])
                    verdict = d.get("verdict", "")
                    mock    = d.get("mock", False)
                except Exception:
                    pass
            self._insert_row(
                row["filename"],
                row["label"],
                self._fmt_size(row["size_bytes"] or 0),
                (row["added_at"] or "")[:10],
                scan_verdict=verdict,
                scan_mock=mock,
            )

    # ------------------------------------------------------------------
    # Drag & drop
    # ------------------------------------------------------------------

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event: QDragMoveEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        for url in event.mimeData().urls():
            local = url.toLocalFile()
            if local:
                self._handle_dropped_file(Path(local))

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._overlay.resize(self.size())

    def _handle_dropped_file(self, src: Path) -> None:
        if not src.is_file():
            return

        # USB kontrolü — giriş sonrası USB çekilmiş olabilir
        live_hwid = get_usb_hwid()
        if live_hwid is None:
            QMessageBox.warning(
                self,
                "USB Bulunamadı",
                "Yetkili USB cihazı takılı değil.\n"
                "Dosya karantinaya alınamaz.",
            )
            self._refresh_usb_badge()
            return

        # Şifrele (SHA-256 şifrelemeden önce hesaplanır, AAD'a bağlanır)
        try:
            hcl_path, sha256_hex = encrypt_file(src, self._key, user_id=1, hwid=live_hwid)  # TODO: oturum user_id
        except AuthenticationError as exc:
            QMessageBox.critical(self, "Bütünlük Hatası", str(exc))
            return
        except Exception as exc:
            QMessageBox.critical(self, "Şifreleme Hatası", str(exc))
            return

        # DB'ye kaydet
        expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=24)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        size_bytes = src.stat().st_size

        try:
            db = DBManager()
            cur = db.execute(
                """
                INSERT INTO files (filename, filepath, label, size_bytes, expires_at, original_sha256)
                VALUES (?, ?, 'Karantina', ?, ?, ?)
                """,
                (src.name, str(hcl_path), size_bytes, expires_at, sha256_hex),
            )
            db.log(
                "file_quarantined",
                target_type="file",
                target_id=cur.lastrowid,
                detail=f"hwid={live_hwid} hcl={hcl_path.name}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return

        self._insert_row(src.name, "Karantina", self._fmt_size(size_bytes), today)
        scan_row = self._table.rowCount() - 1
        self._table.scrollToBottom()
        file_id = cur.lastrowid
        assert file_id is not None  # INSERT INTO ... AUTOINCREMENT her zaman ID üretir
        self._start_scan(src, file_id, scan_row)

    # ------------------------------------------------------------------
    # USB kilit
    # ------------------------------------------------------------------

    def _poll_usb(self) -> None:
        if self._authenticating:
            return
        hwid = get_usb_hwid()
        self._refresh_usb_badge()
        if hwid is None:
            if not self._locked:
                self._lock()
        elif hwid == self._hwid:
            # Aynı yetkili USB — normal kilit aç
            if self._locked:
                self._unlock()
        else:
            # Farklı HWID — yeniden kimlik doğrulama gerekli
            self._trigger_usb_reauth(hwid)

    def _trigger_usb_reauth(self, new_hwid: str) -> None:
        """Farklı HWID tespit edilince 3-katman doğrulama + vault rol okuma."""
        self._authenticating = True
        self._lock()

        # Katman 1-2-3: HWID kayıtlı mı, vault HMAC geçerli mi, token eşleşiyor mu
        try:
            authenticate_usb(new_hwid)
        except USBAuthError as exc:
            QMessageBox.warning(
                self, "USB Reddedildi",
                f"Yeni USB kimlik doğrulaması başarısız:\n\n{exc}",
            )
            self._authenticating = False
            return
        except Exception as exc:
            QMessageBox.critical(self, "Kimlik Doğrulama Hatası", str(exc))
            self._authenticating = False
            return

        # PIN ile vault'tan rolü oku
        pin, ok = QInputDialog.getText(
            self,
            "USB Değişti — Yeniden Giriş",
            f"USB doğrulandı.\nVault PIN'ini girin:",
            QLineEdit.Password,
        )
        if not ok or not pin.strip():
            QMessageBox.information(
                self, "Oturum Kilitli",
                "PIN girilmedi — oturum kilitli kaldı.",
            )
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

        # Durum güncelle
        prev_hwid = self._hwid
        self._hwid = new_hwid
        self._role = new_role
        self._apply_role_restrictions()
        self._unlock()
        self._authenticating = False

        QMessageBox.information(
            self,
            "USB Oturumu Açıldı",
            f"Yeni USB oturumu başarıyla açıldı.\n\n"
            f"Önceki HWID : {prev_hwid[:16]}...\n"
            f"Yeni HWID   : {new_hwid[:16]}...\n"
            f"Rol         : {new_role}",
        )

    def _lock(self) -> None:
        self._locked = True
        self.centralWidget().setGraphicsEffect(self._blur)
        self._overlay.resize(self.size())
        self._overlay.show()
        self._overlay.raise_()

    def _unlock(self) -> None:
        self._locked = False
        self.centralWidget().setGraphicsEffect(None)
        self._overlay.hide()

    # ------------------------------------------------------------------
    # Yardımcılar
    # ------------------------------------------------------------------

    def _insert_row(
        self, name: str, label: str, size: str, date: str,
        scan_verdict: str = "", scan_mock: bool = False,
    ) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._table.setItem(row, 0, QTableWidgetItem(name))

        label_item = QTableWidgetItem(label)
        label_item.setForeground(QColor(_LABEL_COLORS.get(label, "#cdd6f4")))
        self._table.setItem(row, 1, label_item)

        self._table.setItem(row, 2, QTableWidgetItem(size))
        self._table.setItem(row, 3, QTableWidgetItem(date))

        if scan_verdict:
            text, color = _VERDICT_BADGE.get(scan_verdict, ("? Bilinmiyor", "#6c7086"))
            if scan_mock:
                text, color = text + " (m)", "#6c7086"
            self._set_scan_badge(row, text, color)

    def _start_scan(self, path: Path, file_id: int, row: int) -> None:
        self._set_scan_badge(row, "⟳ Taranıyor...", "#6c7086")
        worker = _ScanWorker(path, file_id, row)
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_scan_done)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda t=thread: self._scan_threads.remove(t) if t in self._scan_threads else None)
        self._scan_threads.append(thread)
        thread.start()

    def _on_scan_done(self, row: int, result: ScanResult) -> None:
        text, color = _VERDICT_BADGE.get(result.verdict, ("? Bilinmiyor", "#6c7086"))
        if result.mock:
            text, color = text + " (m)", "#6c7086"
        self._set_scan_badge(row, text, color)

    def _set_scan_badge(self, row: int, text: str, color: str) -> None:
        if row >= self._table.rowCount():
            return
        item = QTableWidgetItem(text)
        item.setForeground(QColor(color))
        item.setTextAlignment(Qt.AlignCenter)
        self._table.setItem(row, 4, item)

    def _refresh_usb_badge(self) -> None:
        hwid = get_usb_hwid()
        if hwid:
            self._usb_badge.setText(f"USB: {hwid[:12]}")
            self._usb_badge.setStyleSheet("color:#a6e3a1; font-size:11px; padding:6px;")
        else:
            self._usb_badge.setText("USB Yok")
            self._usb_badge.setStyleSheet("color:#f38ba8; font-size:12px; padding:6px;")

    @staticmethod
    def _fmt_size(size_bytes: int) -> str:
        size: float = float(size_bytes)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
