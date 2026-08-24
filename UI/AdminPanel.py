"""HYCLEUS — USB Yönetim Paneli"""
from __future__ import annotations

import logging
import re
from pathlib import Path

_log = logging.getLogger("hycleus.admin_panel")

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from CORE.app_mode import BIREYSEL, KURUMSAL, get_app_mode, set_app_mode
from CORE.roles import is_admin_role
from CORE.idle_lock import (
    DEFAULT_IDLE_MINUTES,
    IDLE_DISABLED,
    IDLE_OPTIONS,
    get_idle_timeout_minutes,
    set_idle_timeout_minutes,
)
from CORE.vault_manager import (
    VaultTamperedError,
    blacklist_usb,
    change_vault_role,
    discard_vault,
    export_recovery_share,
    has_recovery_share,
)
from DB.db_manager import DBManager
from UI.main_window_palette import _DARK

_ROLES = ["Yönetici", "Standart", "Salt Okunur"]


def _stil(T: dict[str, str]) -> str:
    """Panelin ana stil sayfası — kayıtlı tema token'larından (B-055).

    Önceden sabit bir Catppuccin-Mocha paletiydi; preset değişince bu
    panel hiç değişmiyordu. Yeni bir token İCAT EDİLMEDİ.
    """
    return f"""
QDialog {{ background: {T['bg']}; color: {T['text']}; }}
QLabel  {{ color: {T['text']}; }}
QTableWidget {{
    background: {T['search_bg']};
    color: {T['text']};
    gridline-color: {T['border']};
    border: 1px solid {T['border']};
    border-radius: 4px;
    font-size: 12px;
}}
QTableWidget::item:selected {{ background: {T['accent_tint']}; }}
QHeaderView::section {{
    background: {T['bg']};
    color: {T['accent']};
    border: none;
    border-bottom: 1px solid {T['border']};
    padding: 4px 8px;
    font-weight: 600;
    font-size: 12px;
}}
"""


def _btn_stil(T: dict[str, str]) -> str:
    return (
        f"QPushButton{{color:{T['text']};background:{T['hover']};border:none;"
        f"border-radius:6px;padding:5px 14px;font-size:12px;}}"
        f"QPushButton:hover{{background:{T['row_hover']};}}"
        f"QPushButton:disabled{{color:{T['gray']};background:{T['bg']};border:none;}}"
    )


def _btn_danger_stil(T: dict[str, str]) -> str:
    return (
        f"QPushButton{{color:{T['red']};background:{T['red_tint']};"
        f"border:1px solid {T['red']};"
        f"border-radius:6px;padding:5px 14px;font-size:12px;}}"
        f"QPushButton:hover{{background:{T['red_tint']};}}"
        f"QPushButton:disabled{{color:{T['gray']};background:{T['bg']};"
        f"border:1px solid {T['border']};}}"
    )


def _btn_success_stil(T: dict[str, str]) -> str:
    return (
        f"QPushButton{{color:{T['green']};background:{T['green_tint']};"
        f"border:1px solid {T['green']};"
        f"border-radius:6px;padding:5px 14px;font-size:12px;}}"
        f"QPushButton:hover{{background:{T['green_tint']};}}"
        f"QPushButton:disabled{{color:{T['gray']};background:{T['bg']};"
        f"border:1px solid {T['border']};}}"
    )

# Qt.UserRole slots for column-0 items
_ROLE_HWID        = Qt.UserRole          # str  — tam HWID
_ROLE_BLACKLISTED = Qt.UserRole + 1      # bool — kara liste durumu


class AdminPanel(QDialog):
    def __init__(self, current_hwid: str, role: str = "Yönetici", parent=None,
                 *, T: dict[str, str] | None = None) -> None:
        """
        Args:
            T: Çağıranın aktif tema token sözlüğü (`HycleusWindow._T`).
                Verilmezse varsayılan "mavi" koyu palete düşer.
        """
        super().__init__(parent)
        self._current_hwid = current_hwid
        self._caller_role  = role
        self._T: dict[str, str] = T if T is not None else _DARK
        self.setWindowTitle("HYCLEUS — USB Yönetim Paneli")
        self.setStyleSheet(_stil(self._T))

        if not is_admin_role(role):
            self.setFixedSize(360, 120)
            lay = QVBoxLayout(self)
            lay.setContentsMargins(24, 20, 24, 20)
            lay.setSpacing(16)
            lbl = QLabel("Bu alana erişim yetkiniz yok.")
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet(f"color:{self._T['red']}; font-size:13px;")
            lay.addWidget(lbl)
            btn = QPushButton("Kapat")
            btn.setStyleSheet(_btn_stil(self._T))
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
        title.setStyleSheet(f"color:{self._T['text']}; margin-bottom:2px;")
        root.addWidget(title)

        tabs = QTabWidget()
        tabs.setStyleSheet(self._tab_stili())

        # Sekme 1 — USB Tokenlar
        usb_page = QWidget()
        usb_layout = QVBoxLayout(usb_page)
        usb_layout.setContentsMargins(0, 8, 0, 0)
        usb_layout.setSpacing(8)
        usb_layout.addWidget(self._make_table())
        usb_layout.addLayout(self._make_btn_bar())
        tabs.addTab(usb_page, "USB Tokenlar")

        # Sekme 2 — Bekleyen Kayıtlar
        #
        # Bireysel modda GİZLENİR (bkz. _apply_mode_visibility) — tek
        # kullanıcı zaten admin, başkasının onayını bekleyen bir kayıt
        # akışı anlamsız. Gizlemek SİLMEK değil: sekme, widget'ları ve
        # `_on_approve`/`_on_reject` hâlâ burada, yalnızca sekme çubuğunda
        # görünmüyor. Kurumsal'a dönünce ya da biri yine de kaydolursa
        # (akış modu bilmiyor, LoginDialog'dan tetikleniyor) hiçbir şey
        # kaybolmadan ortaya çıkar.
        pending_page = QWidget()
        pending_layout = QVBoxLayout(pending_page)
        pending_layout.setContentsMargins(0, 8, 0, 0)
        pending_layout.setSpacing(8)
        pending_layout.addWidget(self._make_pending_table())
        pending_layout.addLayout(self._make_pending_btn_bar())
        self._pending_tab_index = tabs.addTab(pending_page, "Bekleyen Kayıtlar")

        # Sekme 3 — Ayarlar
        tabs.addTab(self._make_settings_page(), "Ayarlar")

        self._tabs = tabs

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

    # ── Paylaşılan stil parçaları ─────────────────────────────────────────────
    #
    # Ayarlar sekmesindeki üç combo (mod/TTL/hareketsizlik) ve dört bölüm
    # başlığı birebir aynı QSS'i tekrar ediyordu. Tek yerde tutmak hem
    # B-055'in "ikinci bir renk yolu açma" kuralına uyuyor hem de dördünün
    # zamanla ayrışmasını önlüyor.

    def _tab_stili(self) -> str:
        T = self._T
        return (
            f"QTabWidget::pane{{border:1px solid {T['border']};border-radius:4px;}}"
            f"QTabBar::tab{{background:{T['bg']};color:{T['subtext']};padding:6px 18px;"
            f"border:1px solid {T['border']};border-bottom:none;"
            f"border-radius:4px 4px 0 0;}}"
            f"QTabBar::tab:selected{{background:{T['border']};color:{T['text']};}}"
        )

    def _combo_stili(self) -> str:
        T = self._T
        return (
            f"QComboBox{{background:{T['hover']};color:{T['text']};"
            f"border:1px solid {T['border']};"
            f"border-radius:6px;padding:5px 10px;font-size:12px;}}"
            f"QComboBox::drop-down{{border:none;width:20px;}}"
            f"QComboBox QAbstractItemView{{background:{T['hover']};color:{T['text']};"
            f"border:1px solid {T['border']};"
            f"selection-background-color:{T['row_hover']};}}"
        )

    def _bolum_baslik_stili(self) -> str:
        return f"color:{self._T['accent']}; font-size:12px; font-weight:600;"

    def _ipucu_stili(self) -> str:
        return f"color:{self._T['subtext']}; font-size:12px;"

    def _liste_stili(self) -> str:
        T = self._T
        return (
            f"QListWidget{{background:{T['hover']};color:{T['text']};"
            f"border:1px solid {T['border']};"
            f"border-radius:6px;font-size:12px;}}"
            f"QListWidget::item{{padding:4px 8px;}}"
            f"QListWidget::item:selected{{background:{T['row_hover']};}}"
        )

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
        self._btn_blacklist.setStyleSheet(_btn_danger_stil(self._T))
        self._btn_blacklist.setCursor(Qt.PointingHandCursor)
        self._btn_blacklist.setEnabled(False)
        self._btn_blacklist.clicked.connect(self._on_toggle_blacklist)
        bar.addWidget(self._btn_blacklist)

        self._btn_role = QPushButton("Rolü Değiştir")
        self._btn_role.setStyleSheet(_btn_stil(self._T))
        self._btn_role.setCursor(Qt.PointingHandCursor)
        self._btn_role.setEnabled(False)
        self._btn_role.clicked.connect(self._on_change_role)
        bar.addWidget(self._btn_role)

        self._btn_delete = QPushButton("Sil")
        self._btn_delete.setStyleSheet(_btn_danger_stil(self._T))
        self._btn_delete.setCursor(Qt.PointingHandCursor)
        self._btn_delete.setEnabled(False)
        self._btn_delete.clicked.connect(self._on_delete)
        bar.addWidget(self._btn_delete)

        bar.addStretch()

        # B-006: zincir doğrulaması üç yerden çağrılabiliyordu ama hiçbirinin
        # düğmesi yoktu. Kurcalama kanıtı, ancak birileri kanıta
        # BAKABİLİYORSA işe yarar. Yetki kontrolü ayrıca gerekmiyor: bu panel
        # `role != "Yönetici"` ise hiç kurulmuyor (bkz. __init__).
        self._btn_chain = QPushButton("Zinciri Doğrula")
        self._btn_chain.setStyleSheet(_btn_stil(self._T))
        self._btn_chain.setCursor(Qt.PointingHandCursor)
        self._btn_chain.clicked.connect(self._on_verify_chain)
        bar.addWidget(self._btn_chain)

        btn_refresh = QPushButton("Yenile")
        btn_refresh.setStyleSheet(_btn_stil(self._T))
        btn_refresh.setCursor(Qt.PointingHandCursor)
        btn_refresh.clicked.connect(self._load)
        bar.addWidget(btn_refresh)

        return bar

    def _on_verify_chain(self) -> None:
        """
        Denetim zincirini doğrular.

        GÖVDE BURADA DEĞİL: `UI/security_actions.zinciri_dogrula()`.
        Aynı iş Güvenlik sekmesinden de çağrılıyor ve iki ayrı uygulama,
        bu deponun beş kez ürettiği kusur sınıfı olurdu.
        """
        from UI.security_actions import zinciri_dogrula

        zinciri_dogrula(self, self._current_hwid)

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
                hwid_item.setForeground(QColor(self._T["accent"]))
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
                QColor(self._T["red"] if blacklisted else self._T["green"])
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
            self._btn_blacklist.setStyleSheet(_btn_danger_stil(self._T))
            return

        row        = selected[0].row()
        item       = self._table.item(row, 0)
        full_hwid  = item.data(_ROLE_HWID) if item else ""
        blacklisted = bool(item.data(_ROLE_BLACKLISTED)) if item else False
        is_self    = full_hwid == self._current_hwid

        # Kara liste butonu — metin ve stil blacklisted durumuna göre değişir
        if blacklisted:
            self._btn_blacklist.setText("Kara Listeden Çıkar")
            self._btn_blacklist.setStyleSheet(_btn_success_stil(self._T))
        else:
            self._btn_blacklist.setText("Kara Listeye Al")
            self._btn_blacklist.setStyleSheet(_btn_danger_stil(self._T))

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

        if is_admin_role(old_role):
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
        self._btn_approve.setStyleSheet(_btn_success_stil(self._T))
        self._btn_approve.setCursor(Qt.PointingHandCursor)
        self._btn_approve.setEnabled(False)
        self._btn_approve.clicked.connect(self._on_approve)
        bar.addWidget(self._btn_approve)

        self._btn_reject = QPushButton("✕  Reddet")
        self._btn_reject.setStyleSheet(_btn_danger_stil(self._T))
        self._btn_reject.setCursor(Qt.PointingHandCursor)
        self._btn_reject.setEnabled(False)
        self._btn_reject.clicked.connect(self._on_reject)
        bar.addWidget(self._btn_reject)

        btn_new = QPushButton("＋  Yeni Kullanıcı Kaydet")
        btn_new.setStyleSheet(_btn_stil(self._T))
        btn_new.setCursor(Qt.PointingHandCursor)
        btn_new.clicked.connect(self._on_new_user)
        bar.addWidget(btn_new)

        bar.addStretch()

        btn_refresh = QPushButton("Yenile")
        btn_refresh.setStyleSheet(_btn_stil(self._T))
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
            # users satırı + usb_tokens/kasa + per-HWID vault dosyası
            # birlikte silinir (bkz. discard_vault() docstring'i, B-060/061)
            discard_vault(hwid)
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
        header.setStyleSheet(f"color:{self._T['text']}; font-size:13px; font-weight:bold;")
        lay.addWidget(header)

        sep = QLabel()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background:{self._T['border']};")
        lay.addWidget(sep)

        # ── Görünüm modu (Bireysel/Kurumsal) ───────────────────────────────
        mode_lbl = QLabel("Görünüm modu")
        mode_lbl.setStyleSheet(self._bolum_baslik_stili())
        lay.addWidget(mode_lbl)

        mode_row = QHBoxLayout()
        mode_row.setSpacing(10)

        self._mode_combo = QComboBox()
        self._mode_combo.addItem("Kurumsal", KURUMSAL)
        self._mode_combo.addItem("Bireysel", BIREYSEL)
        self._mode_combo.setFixedWidth(110)
        self._mode_combo.setStyleSheet(self._combo_stili())
        mode_row.addWidget(self._mode_combo)

        mode_hint = QLabel(
            "Bireysel: \"Bekleyen Kayıtlar\" sekmesi ve kenar çubuğundaki "
            "\"Yönetici\" başlığı gizlenir. Yetkiler DEĞİŞMEZ — yalnızca "
            "görünüm."
        )
        mode_hint.setWordWrap(True)
        mode_hint.setStyleSheet(self._ipucu_stili())
        mode_row.addWidget(mode_hint, 1)
        lay.addLayout(mode_row)

        ttl_lbl = QLabel("İmha Odası varsayılan TTL süresi")
        ttl_lbl.setStyleSheet(self._bolum_baslik_stili())
        lay.addWidget(ttl_lbl)

        row = QHBoxLayout()
        row.setSpacing(10)

        self._ttl_combo = QComboBox()
        for h in self._TTL_OPTIONS:
            self._ttl_combo.addItem(f"{h} saat", h)
        self._ttl_combo.setFixedWidth(110)
        self._ttl_combo.setStyleSheet(self._combo_stili())
        row.addWidget(self._ttl_combo)

        hint = QLabel("sonra İmha Odası'ndaki dosyalar otomatik silinir")
        hint.setStyleSheet(self._ipucu_stili())
        row.addWidget(hint)
        row.addStretch()
        lay.addLayout(row)

        # ── Hareketsizlik kilidi ──────────────────────────────────────────
        idle_lbl = QLabel("Hareketsizlik kilidi")
        idle_lbl.setStyleSheet(self._bolum_baslik_stili())
        lay.addWidget(idle_lbl)

        idle_row = QHBoxLayout()
        idle_row.setSpacing(10)

        self._idle_combo = QComboBox()
        for m in IDLE_OPTIONS:
            self._idle_combo.addItem("Kapalı" if m == IDLE_DISABLED else f"{m} dakika", m)
        self._idle_combo.setFixedWidth(110)
        self._idle_combo.setStyleSheet(self._combo_stili())
        idle_row.addWidget(self._idle_combo)

        idle_hint = QLabel("hareketsizlikten sonra oturum kilitlenir (USB takılı olsa bile)")
        idle_hint.setStyleSheet(self._ipucu_stili())
        idle_row.addWidget(idle_hint)
        idle_row.addStretch()
        lay.addLayout(idle_row)

        btn_save = QPushButton("Kaydet")
        btn_save.setStyleSheet(_btn_success_stil(self._T))
        btn_save.setCursor(Qt.PointingHandCursor)
        btn_save.setFixedWidth(100)
        btn_save.clicked.connect(self._on_save_settings)
        lay.addWidget(btn_save)

        lay.addWidget(self._tsa_kok_bloku())
        lay.addWidget(self._kurtarma_bloku())
        lay.addStretch()
        return page

    # ── Kurtarma parçası ─────────────────────────────────────────────────────
    #
    # Bugüne kadar yalnızca komut satırından alınabiliyordu
    # (`python CORE/recover_vault.py --export`). Panikleyen bir kullanıcının
    # o komutu bulması beklenemez; rehber de onu "kaybetmeden önce al"
    # diyerek uyarıyor.
    #
    # Buraya konmasının sebebi: AdminPanel zaten yönetici kapısının
    # ARDINDA (`main_window::_on_open_admin_panel`, `is_admin_role`). Ayrı
    # bir rol kontrolü yazmak ikinci bir karar noktası olurdu.

    def _kurtarma_bloku(self) -> QWidget:
        kutu = QWidget()
        lay = QVBoxLayout(kutu)
        lay.setContentsMargins(0, 12, 0, 0)
        lay.setSpacing(8)

        baslik = QLabel("Kurtarma parçası")
        baslik.setStyleSheet(self._bolum_baslik_stili())
        lay.addWidget(baslik)

        ipucu = QLabel(
            "USB ya da anahtar kasası kaybolduğunda kasayı açan üçüncü pay. "
            "Bir kez gösterilir, hiçbir yere kaydedilmez — yazdırıp fiziksel "
            "olarak saklayın."
        )
        ipucu.setWordWrap(True)
        ipucu.setStyleSheet(self._ipucu_stili())
        lay.addWidget(ipucu)

        btn = QPushButton("Kurtarma Parçasını Göster…")
        btn.setObjectName("admin_btn_kurtarma")
        btn.setStyleSheet(_btn_danger_stil(self._T))
        btn.setCursor(Qt.PointingHandCursor)
        btn.setFixedWidth(230)
        btn.clicked.connect(self._on_kurtarma_parcasi)
        lay.addWidget(btn)
        return kutu

    def _on_kurtarma_parcasi(self) -> None:
        """
        Kurtarma parçasını üretir ve modalda gösterir.

        Pay bu metotta da, diyalogda da DİSKE YAZILMIYOR; `build_export`
        yalnızca bellekte yaşayan bir nesne döndürüyor ve blok biterken
        ikisi de bırakılıyor.
        """
        from CORE.recovery_share import build_export
        from UI.RecoveryShareDialog import RecoveryShareDialog

        hwid = self._current_hwid
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

        baslik = QLabel("Güvenilir zaman damgası kökleri")
        baslik.setStyleSheet(self._bolum_baslik_stili())
        lay.addWidget(baslik)

        ipucu = QLabel(
            "Kurumunuzun zaman damgası kökünü ekleyin. Liste boşken damgalar "
            "«geçerli — ama kurum doğrulanmadı» olarak gösterilir."
        )
        ipucu.setWordWrap(True)
        ipucu.setStyleSheet(self._ipucu_stili())
        lay.addWidget(ipucu)

        self._tsa_liste = QListWidget()
        self._tsa_liste.setFixedHeight(96)
        self._tsa_liste.setStyleSheet(self._liste_stili())
        lay.addWidget(self._tsa_liste)

        satir = QHBoxLayout()
        satir.setSpacing(10)
        btn_ekle = QPushButton("Kök Ekle…")
        btn_ekle.setStyleSheet(_btn_success_stil(self._T))
        btn_ekle.setCursor(Qt.PointingHandCursor)
        btn_ekle.setFixedWidth(120)
        btn_ekle.clicked.connect(self._on_tsa_kok_ekle)
        satir.addWidget(btn_ekle)

        self._btn_tsa_sil = QPushButton("Kaldır")
        self._btn_tsa_sil.setStyleSheet(_btn_danger_stil(self._T))
        self._btn_tsa_sil.setCursor(Qt.PointingHandCursor)
        self._btn_tsa_sil.setFixedWidth(100)
        # Başlangıç durumu BURADA verilmiyor: `_tsa_yukle()` her yüklemede
        # zaten kapatıyor ve blok onunla bitiyor. Mutasyon testinde ölçüldü —
        # buradaki `setEnabled(False)` hiçbir testi etkilemiyordu, yani
        # gözlenemeyen bir satırdı.
        self._btn_tsa_sil.clicked.connect(self._on_tsa_kok_sil)
        satir.addWidget(self._btn_tsa_sil)
        satir.addStretch()
        lay.addLayout(satir)

        self._tsa_liste.itemSelectionChanged.connect(
            lambda: self._btn_tsa_sil.setEnabled(
                self._tsa_liste.currentItem() is not None)
        )
        self._tsa_yukle()
        return kutu

    def _kim(self) -> int | None:
        """
        Denetim kaydına yazılacak `users.id` — 262. satırdaki zincir
        doğrulamasıyla AYNI yol (B-011, yan etkisiz `kullanici_bilgisi`).
        """
        from CORE.session_user import kullanici_bilgisi

        try:
            kim = kullanici_bilgisi(DBManager(), self._current_hwid)
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
        self._apply_mode_visibility(mode_current)

    def _apply_mode_visibility(self, mode: str) -> None:
        """Bireysel/Kurumsal seçimine göre bu panelin sekmelerini filtreler.

        YALNIZCA görünürlük: `_pending_tab_index`'teki widget, `_on_approve`/
        `_on_reject` ve altındaki veri hiçbir zaman silinmiyor — yalnızca
        sekme çubuğunda gizleniyor/gösteriliyor.
        """
        self._tabs.setTabVisible(self._pending_tab_index, mode != BIREYSEL)

    def _on_save_settings(self) -> None:
        hours = self._ttl_combo.currentData()
        minutes = self._idle_combo.currentData()
        mode = self._mode_combo.currentData()
        try:
            db = DBManager()
            db.set_setting("imha_ttl_hours", str(hours))
            db.log("setting_changed",
                   detail=f"key=imha_ttl_hours value={hours} hwid={self._current_hwid}")

            # Doğrulama ve denetim kaydı CORE tarafında; kilidi KAPATMAK ayrı
            # bir action ile yazılıyor (bkz. CORE/idle_lock.py).
            set_idle_timeout_minutes(db, minutes, hwid=self._current_hwid)

            # Doğrulama ve denetim kaydı CORE tarafında (bkz. CORE/app_mode.py).
            set_app_mode(db, mode, hwid=self._current_hwid)
            self._apply_mode_visibility(mode)

            # Açık pencereye anında uygula — yeniden başlatma beklenmesin.
            self._apply_idle_timeout_to_main_window()
            self._apply_mode_to_main_window()

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

    def _apply_mode_to_main_window(self) -> None:
        """Ayarı çalışan ana pencereye bildirir — `_apply_idle_timeout_to_main_window`
        ile aynı desen (bulunamazsa sessizce geçilir, bir sonraki açılışta okunur)."""
        parent = self.parent()
        while parent is not None:
            reload_fn = getattr(parent, "reload_app_mode", None)
            if callable(reload_fn):
                reload_fn()
                return
            parent = parent.parent()

    def _apply_idle_timeout_to_main_window(self) -> None:
        """
        Ayarı çalışan ana pencereye bildirir.

        Paneli açan pencere aranıyor; bulunamazsa sessizce geçiliyor —
        ayar zaten kaydedildi ve bir sonraki açılışta okunacak.
        """
        parent = self.parent()
        while parent is not None:
            reload_fn = getattr(parent, "reload_idle_timeout", None)
            if callable(reload_fn):
                reload_fn()
                return
            parent = parent.parent()
