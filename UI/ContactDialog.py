"""HYCLEUS — Destek ve İletişim Diyaloğu"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from CORE.version import surum_etiketi
from DB.db_manager import DBManager

#: Tek kaynak: CORE/version.py. Elle yazmayın — bkz. BACKLOG B-017.
_APP_VERSION = surum_etiketi()

_QSS = """
QDialog  { background: #FFFFFF; }
QWidget  { color: #111827; background: transparent; }
QLabel   { color: #111827; background: transparent; }

QLabel#dlg_title    { font-size: 18px; font-weight: 700; color: #111827; }
QLabel#section_lbl  { font-size: 11px; font-weight: 600; color: #9CA3AF;
                       letter-spacing: 1px; }
QLabel#code_display { font-size: 32px; font-weight: 700; color: #2563EB;
                       background: #EFF6FF; border-radius: 8px;
                       padding: 12px 24px; }
QLabel#mail_body    { color: #374151; font-size: 12px;
                       background: #F9FAFB; border: 1px solid #E5E7EB;
                       border-radius: 6px; padding: 10px; }

QFrame#top_sep  { background: #E5E7EB; max-height: 1px; border: none; }
QFrame#info_box { background: #EFF6FF; border-left: 3px solid #2563EB;
                   border-radius: 4px; }
QFrame#sys_box  { background: #F9FAFB; border: 1px solid #E5E7EB;
                   border-radius: 8px; }

QListWidget { background: #F9FAFB; border: 1px solid #E5E7EB;
              border-radius: 8px; font-size: 13px; color: #111827; outline: none; }
QListWidget::item            { padding: 8px 12px;
                                border-bottom: 1px solid #F3F4F6; }
QListWidget::item:selected   { background: #EFF6FF; color: #2563EB; }

QLineEdit { background: transparent; color: #111827; border: none;
            border-bottom: 2px solid #E5E7EB; font-size: 14px;
            min-height: 40px; padding: 4px 0; }
QLineEdit:focus { border-bottom: 2px solid #2563EB; }

QTextEdit { background: #F9FAFB; color: #111827;
            border: 1px solid #E5E7EB; border-radius: 8px;
            font-size: 13px; padding: 8px; }

QPushButton#btn_primary  { background: #2563EB; color: #FFFFFF; border: none;
                            border-radius: 8px; font-size: 14px; font-weight: 600;
                            min-height: 40px; padding: 0 20px; }
QPushButton#btn_primary:hover    { background: #1D4ED8; }
QPushButton#btn_primary:disabled { background: #BFDBFE; color: #93C5FD; }

QPushButton#btn_secondary { background: transparent; color: #374151;
                             border: 1px solid #D1D5DB; border-radius: 8px;
                             font-size: 14px; min-height: 40px; padding: 0 16px; }
QPushButton#btn_secondary:hover { background: #F3F4F6; }

QPushButton#tab_on  { background: transparent; color: #2563EB; border: none;
                       border-bottom: 2px solid #2563EB; border-radius: 0px;
                       font-size: 14px; font-weight: 600; padding: 10px 20px; }
QPushButton#tab_off { background: transparent; color: #9CA3AF; border: none;
                       border-bottom: 2px solid transparent;
                       font-size: 14px; padding: 10px 20px; }
QPushButton#tab_off:hover { color: #6B7280; }
"""


class ContactDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Destek ve İletişim")
        self.setFixedSize(520, 600)
        self.setStyleSheet(_QSS)
        self._selected_user_id: int | None = None
        self._current_code: str = ""
        self._build_ui()

    # ── UI kurulumu ───────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Başlık
        header = QWidget()
        header.setStyleSheet("background: #FFFFFF;")
        h_lay = QVBoxLayout(header)
        h_lay.setContentsMargins(28, 24, 28, 8)
        title = QLabel("Destek ve İletişim")
        title.setObjectName("dlg_title")
        h_lay.addWidget(title)
        root.addWidget(header)

        # Sekme çubuğu
        tab_bar = QWidget()
        tab_bar.setStyleSheet("background: #FFFFFF;")
        tab_h = QHBoxLayout(tab_bar)
        tab_h.setContentsMargins(20, 0, 20, 0)
        tab_h.setSpacing(0)

        self._tab_auth = QPushButton("Auth Kodu Paylaş")
        self._tab_auth.setObjectName("tab_on")
        self._tab_auth.setCursor(Qt.PointingHandCursor)
        self._tab_auth.clicked.connect(lambda: self._switch_tab(0))
        tab_h.addWidget(self._tab_auth)

        self._tab_info = QPushButton("İletişim")
        self._tab_info.setObjectName("tab_off")
        self._tab_info.setCursor(Qt.PointingHandCursor)
        self._tab_info.clicked.connect(lambda: self._switch_tab(1))
        tab_h.addWidget(self._tab_info)

        tab_h.addStretch()
        root.addWidget(tab_bar)

        sep = QFrame()
        sep.setObjectName("top_sep")
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        root.addWidget(sep)

        # Sayfalar
        self._stack = QStackedWidget()
        self._stack.setStyleSheet("background: #FFFFFF;")
        self._stack.addWidget(self._make_auth_page())
        self._stack.addWidget(self._make_contact_page())
        root.addWidget(self._stack, 1)

    def _switch_tab(self, idx: int) -> None:
        self._tab_auth.setObjectName("tab_on" if idx == 0 else "tab_off")
        self._tab_info.setObjectName("tab_on" if idx == 1 else "tab_off")
        for btn in (self._tab_auth, self._tab_info):
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        self._stack.setCurrentIndex(idx)

    # ── Auth Kodu Paylaş ──────────────────────────────────────────────────────

    def _make_auth_page(self) -> QWidget:
        page = QWidget()
        page.setStyleSheet("background: #FFFFFF;")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(28, 20, 28, 24)
        lay.setSpacing(14)

        # Bilgi kutusu
        info_box = QFrame()
        info_box.setObjectName("info_box")
        info_lay = QHBoxLayout(info_box)
        info_lay.setContentsMargins(14, 10, 14, 10)
        info_lbl = QLabel(
            "Yeni kullanıcıya TOTP kurulumu için auth kodu gönderin.\n"
            "Oluşturulan kod 30 dakika geçerlidir."
        )
        info_lbl.setWordWrap(True)
        info_lbl.setStyleSheet(
            "color: #1D4ED8; font-size: 13px; background: transparent;"
        )
        info_lay.addWidget(info_lbl)
        lay.addWidget(info_box)

        # Kullanıcı listesi
        users_lbl = QLabel("KULLANICILAR")
        users_lbl.setObjectName("section_lbl")
        lay.addWidget(users_lbl)

        self._user_list = QListWidget()
        self._user_list.setFixedHeight(130)
        self._user_list.currentItemChanged.connect(self._on_user_selected)
        lay.addWidget(self._user_list)
        self._load_users()

        # Kod oluştur
        self._btn_gen = QPushButton("Auth Kodu Oluştur")
        self._btn_gen.setObjectName("btn_primary")
        self._btn_gen.setEnabled(False)
        self._btn_gen.setCursor(Qt.PointingHandCursor)
        self._btn_gen.clicked.connect(self._on_generate_code)
        lay.addWidget(self._btn_gen)

        # Kod gösterimi
        self._code_lbl = QLabel("— — — —  — — — —")
        self._code_lbl.setObjectName("code_display")
        self._code_lbl.setAlignment(Qt.AlignCenter)
        self._code_lbl.setVisible(False)
        lay.addWidget(self._code_lbl)

        # Hazır mail metni
        self._mail_lbl = QLabel()
        self._mail_lbl.setObjectName("mail_body")
        self._mail_lbl.setWordWrap(True)
        self._mail_lbl.setVisible(False)
        lay.addWidget(self._mail_lbl)

        # Kopyala
        self._btn_copy = QPushButton("Kopyala")
        self._btn_copy.setObjectName("btn_secondary")
        self._btn_copy.setCursor(Qt.PointingHandCursor)
        self._btn_copy.setVisible(False)
        self._btn_copy.clicked.connect(self._on_copy_code)
        lay.addWidget(self._btn_copy)

        lay.addStretch()
        return page

    def _load_users(self) -> None:
        self._user_list.clear()
        try:
            rows = DBManager().fetchall(
                "SELECT id, username, role FROM users WHERE status = 'approved' ORDER BY username"
            )
        except Exception:
            return
        role_map = {"admin": "Yönetici", "user": "Kullanıcı"}
        for row in rows:
            role_display = role_map.get(row["role"], row["role"])
            item = QListWidgetItem(f"  {row['username']}  —  {role_display}")
            item.setData(Qt.UserRole, row["id"])
            item.setData(Qt.UserRole + 1, row["username"])
            self._user_list.addItem(item)

    def _on_user_selected(self, item) -> None:
        self._selected_user_id = item.data(Qt.UserRole) if item else None
        self._btn_gen.setEnabled(self._selected_user_id is not None)

    def _on_generate_code(self) -> None:
        if self._selected_user_id is None:
            return

        code = f"{secrets.randbelow(100000000):08d}"
        expires_at = (
            datetime.now(timezone.utc) + timedelta(minutes=30)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        try:
            db = DBManager()
            db.execute(
                "UPDATE auth_codes SET used = 1 WHERE user_id = ? AND used = 0",
                (self._selected_user_id,),
            )
            db.execute(
                "INSERT INTO auth_codes (user_id, code, expires_at) VALUES (?, ?, ?)",
                (self._selected_user_id, code, expires_at),
            )
            db.log(
                "auth_code_generated",
                target_type="user",
                target_id=self._selected_user_id,
                detail=f"expires={expires_at}",
            )
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))
            return

        self._current_code = code

        self._code_lbl.setText(f"{code[:4]}  {code[4:]}")
        self._code_lbl.setVisible(True)

        selected_item = self._user_list.currentItem()
        username = selected_item.data(Qt.UserRole + 1) if selected_item else "kullanıcı"
        mail_text = (
            f"Konu: HYCLEUS Erişim Auth Kodu\n\n"
            f"Merhaba {username},\n\n"
            f"HYCLEUS sistemine erişim için auth kodunuz:\n\n"
            f"  {code}\n\n"
            f"Kod 30 dakika geçerlidir.\n"
            f"Kullandıktan sonra otomatik olarak geçersiz hale gelecektir."
        )
        self._mail_lbl.setText(mail_text)
        self._mail_lbl.setVisible(True)
        self._btn_copy.setVisible(True)
        self._btn_copy.setProperty("_mail", mail_text)

    def _on_copy_code(self) -> None:
        text = self._btn_copy.property("_mail") or self._current_code
        QApplication.clipboard().setText(text)
        self._btn_copy.setText("✓ Kopyalandı")
        QTimer.singleShot(2000, lambda: self._btn_copy.setText("Kopyala"))

    # ── İletişim ──────────────────────────────────────────────────────────────

    def _make_contact_page(self) -> QWidget:
        page = QWidget()
        page.setStyleSheet("background: #FFFFFF;")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(28, 20, 28, 24)
        lay.setSpacing(14)

        # Sistem bilgileri
        sys_lbl = QLabel("SİSTEM BİLGİLERİ")
        sys_lbl.setObjectName("section_lbl")
        lay.addWidget(sys_lbl)

        sys_box = QFrame()
        sys_box.setObjectName("sys_box")
        sys_v = QVBoxLayout(sys_box)
        sys_v.setContentsMargins(16, 12, 16, 12)
        sys_v.setSpacing(8)
        sys_v.addWidget(self._info_row("Versiyon", _APP_VERSION))
        sys_v.addWidget(self._info_row("Kurulum Tarihi", self._get_install_date()))
        sys_v.addWidget(self._info_row("Toplam Dosya", str(self._get_file_count())))
        lay.addWidget(sys_box)

        # Sorun bildir
        report_lbl = QLabel("SORUN BİLDİR")
        report_lbl.setObjectName("section_lbl")
        lay.addWidget(report_lbl)

        self._report_title = QLineEdit()
        self._report_title.setPlaceholderText("Sorun başlığı...")
        lay.addWidget(self._report_title)

        self._report_desc = QTextEdit()
        self._report_desc.setPlaceholderText("Sorunu açıklayın...")
        self._report_desc.setFixedHeight(100)
        lay.addWidget(self._report_desc)

        self._btn_copy_report = QPushButton("Mail Metnini Kopyala")
        self._btn_copy_report.setObjectName("btn_secondary")
        self._btn_copy_report.setCursor(Qt.PointingHandCursor)
        self._btn_copy_report.clicked.connect(self._on_copy_report)
        lay.addWidget(self._btn_copy_report)

        hint = QLabel("yunusemre.is@outlook.com adresine yapıştırın")
        hint.setStyleSheet("color: #9CA3AF; font-size: 12px; background: transparent;")
        lay.addWidget(hint)

        lay.addStretch()
        return page

    @staticmethod
    def _info_row(label: str, value: str) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        lbl = QLabel(label)
        lbl.setStyleSheet("color: #6B7280; font-size: 13px; background: transparent;")
        val = QLabel(value)
        val.setStyleSheet(
            "color: #111827; font-size: 13px; font-weight: 600; background: transparent;"
        )
        h.addWidget(lbl)
        h.addStretch()
        h.addWidget(val)
        return w

    @staticmethod
    def _get_install_date() -> str:
        try:
            row = DBManager().fetchone("SELECT MIN(timestamp) AS t FROM audit_log")
            if row and row["t"]:
                return row["t"][:10]
        except Exception:
            pass
        return "Bilinmiyor"

    @staticmethod
    def _get_file_count() -> int:
        try:
            row = DBManager().fetchone("SELECT COUNT(*) AS c FROM files")
            return row["c"] if row else 0
        except Exception:
            return 0

    def _on_copy_report(self) -> None:
        title = self._report_title.text().strip() or "(başlık yok)"
        desc  = self._report_desc.toPlainText().strip() or "(açıklama yok)"
        text = (
            f"Konu: HYCLEUS Sorun Bildirimi — {title}\n"
            f"Alıcı: yunusemre.is@outlook.com\n\n"
            f"Açıklama:\n{desc}\n\n"
            f"--- Sistem Bilgileri ---\n"
            f"Versiyon      : {_APP_VERSION}\n"
            f"Kurulum Tarihi: {self._get_install_date()}\n"
            f"Toplam Dosya  : {self._get_file_count()}\n"
        )
        QApplication.clipboard().setText(text)
        self._btn_copy_report.setText("✓ Kopyalandı")
        QTimer.singleShot(
            2000,
            lambda: self._btn_copy_report.setText("Mail Metnini Kopyala"),
        )
