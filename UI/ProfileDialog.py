"""HYCLEUS — Profil ve İletişim Diyaloğu"""
from __future__ import annotations

from datetime import datetime, timezone

import pyotp
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from CORE.pin_policy import validate_new_pin
from DB.db_manager import DBManager

_QSS = """
QDialog { background: #F9FAFB; color: #111827; }
QFrame#header {
    background: #2563EB;
    border-radius: 0;
}
QLabel#avatar_lbl {
    background: #1D4ED8;
    color: #FFFFFF;
    font-size: 24px;
    font-weight: 700;
    border-radius: 28px;
    min-width: 56px; max-width: 56px;
    min-height: 56px; max-height: 56px;
}
QLabel#user_name {
    color: #FFFFFF;
    font-size: 16px;
    font-weight: 700;
    background: transparent;
}
QLabel#user_role {
    color: #BFDBFE;
    font-size: 12px;
    background: transparent;
}
QFrame#tab_bar { background: #FFFFFF; border-bottom: 1px solid #E5E7EB; }
QPushButton[tab_on="true"] {
    background: transparent;
    color: #2563EB;
    border: none;
    border-bottom: 2px solid #2563EB;
    border-radius: 0;
    font-size: 13px;
    font-weight: 600;
    padding: 10px 20px;
}
QPushButton[tab_on="false"] {
    background: transparent;
    color: #6B7280;
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    font-size: 13px;
    padding: 10px 20px;
}
QPushButton[tab_on="false"]:hover { color: #374151; }
QWidget#page { background: #F9FAFB; }
QLabel#section_lbl {
    color: #6B7280;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1px;
    background: transparent;
}
QLabel#field_key {
    color: #6B7280;
    font-size: 12px;
    background: transparent;
    min-width: 120px;
}
QLabel#field_val {
    color: #111827;
    font-size: 13px;
    font-weight: 500;
    background: transparent;
}
QLabel#warn_lbl {
    color: #D97706;
    font-size: 12px;
    background: #FEF3C7;
    border-radius: 6px;
    padding: 6px 10px;
}
QFrame#sep { background: #E5E7EB; max-height: 1px; border: none; }
QLineEdit {
    background: #FFFFFF;
    color: #111827;
    border: 1px solid #D1D5DB;
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 13px;
}
QLineEdit:focus { border-color: #2563EB; }
QPushButton#btn_primary {
    background: #2563EB;
    color: #FFFFFF;
    border: none;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
    padding: 9px 20px;
}
QPushButton#btn_primary:hover { background: #1D4ED8; }
QPushButton#btn_secondary {
    background: #FFFFFF;
    color: #374151;
    border: 1px solid #D1D5DB;
    border-radius: 8px;
    font-size: 13px;
    padding: 9px 20px;
}
QPushButton#btn_secondary:hover { background: #F3F4F6; }
"""

_ROLE_COLOR = {
    "Yönetici":    ("#DBEAFE", "#2563EB"),
    "Standart":    ("#D1FAE5", "#059669"),
    "Salt Okunur": ("#FEF3C7", "#D97706"),
}


def _sep() -> QFrame:
    f = QFrame()
    f.setObjectName("sep")
    f.setFrameShape(QFrame.HLine)
    return f


class ProfileDialog(QDialog):
    def __init__(self, hwid: str, username: str, role: str, user_id: int, parent=None) -> None:
        super().__init__(parent)
        self._hwid     = hwid
        self._username = username
        self._role     = role
        self._user_id  = user_id

        self.setWindowTitle("HYCLEUS — Profil")
        self.setFixedSize(460, 540)
        self.setStyleSheet(_QSS)
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._make_header())
        root.addWidget(self._make_tab_bar())
        root.addWidget(self._make_pages(), 1)

    def _make_header(self) -> QFrame:
        hdr = QFrame()
        hdr.setObjectName("header")
        hdr.setFixedHeight(96)

        lay = QHBoxLayout(hdr)
        lay.setContentsMargins(24, 0, 24, 0)
        lay.setSpacing(16)

        av = QLabel(self._username[0].upper())
        av.setObjectName("avatar_lbl")
        av.setAlignment(Qt.AlignCenter)
        lay.addWidget(av)

        info = QVBoxLayout()
        info.setSpacing(2)

        name_lbl = QLabel(self._username)
        name_lbl.setObjectName("user_name")
        info.addWidget(name_lbl)

        bg, fg = _ROLE_COLOR.get(self._role, ("#F3F4F6", "#6B7280"))
        role_lbl = QLabel(self._role)
        role_lbl.setObjectName("user_role")
        info.addWidget(role_lbl)

        lay.addLayout(info)
        lay.addStretch()
        return hdr

    def _make_tab_bar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("tab_bar")
        bar.setFixedHeight(42)

        lay = QHBoxLayout(bar)
        lay.setContentsMargins(16, 0, 16, 0)
        lay.setSpacing(0)

        self._tab_profil = QPushButton("Profil")
        self._tab_profil.setCursor(Qt.PointingHandCursor)
        self._tab_profil.clicked.connect(lambda: self._switch_tab(0))

        self._tab_iletisim = QPushButton("İletişim")
        self._tab_iletisim.setCursor(Qt.PointingHandCursor)
        self._tab_iletisim.clicked.connect(lambda: self._switch_tab(1))

        lay.addWidget(self._tab_profil)
        lay.addWidget(self._tab_iletisim)
        lay.addStretch()
        return bar

    def _make_pages(self) -> QWidget:
        from PySide6.QtWidgets import QStackedWidget
        self._stack = QStackedWidget()
        self._stack.addWidget(self._make_profil_page())
        self._stack.addWidget(self._make_iletisim_page())
        self._switch_tab(0)
        return self._stack

    def _switch_tab(self, idx: int) -> None:
        self._stack.setCurrentIndex(idx)
        for i, btn in enumerate([self._tab_profil, self._tab_iletisim]):
            btn.setProperty("tab_on", "true" if i == idx else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    # ── Profil sayfası ────────────────────────────────────────────────────────

    def _make_profil_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("page")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 16, 24, 16)
        lay.setSpacing(8)

        # Kullanıcı bilgileri
        sec1 = QLabel("BİLGİLER")
        sec1.setObjectName("section_lbl")
        lay.addWidget(sec1)

        lay.addWidget(self._info_row("Kullanıcı Adı", self._username))
        lay.addWidget(self._info_row("Rol", self._role))
        lay.addWidget(self._info_row("HWID", self._hwid[:16] + "..."))

        # 6 aylık PIN hatırlatması
        self._pin_warn = QLabel()
        self._pin_warn.setObjectName("warn_lbl")
        self._pin_warn.setWordWrap(True)
        self._pin_warn.setVisible(False)
        self._check_pin_age()
        lay.addWidget(self._pin_warn)

        lay.addWidget(_sep())

        sec2 = QLabel("PIN DEĞİŞTİR")
        sec2.setObjectName("section_lbl")
        lay.addWidget(sec2)

        self._old_pin = QLineEdit()
        self._old_pin.setPlaceholderText("Mevcut PIN")
        self._old_pin.setEchoMode(QLineEdit.Password)
        lay.addWidget(self._old_pin)

        self._new_pin = QLineEdit()
        self._new_pin.setPlaceholderText("Yeni PIN")
        self._new_pin.setEchoMode(QLineEdit.Password)
        lay.addWidget(self._new_pin)

        self._new_pin2 = QLineEdit()
        self._new_pin2.setPlaceholderText("Yeni PIN (tekrar)")
        self._new_pin2.setEchoMode(QLineEdit.Password)
        lay.addWidget(self._new_pin2)

        btn_pin = QPushButton("PIN'i Güncelle")
        btn_pin.setObjectName("btn_primary")
        btn_pin.setCursor(Qt.PointingHandCursor)
        btn_pin.clicked.connect(self._on_change_pin)
        lay.addWidget(btn_pin)

        lay.addStretch()
        return page

    @staticmethod
    def _info_row(key: str, value: str) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 2, 0, 2)
        h.setSpacing(8)
        k = QLabel(key)
        k.setObjectName("field_key")
        v = QLabel(value)
        v.setObjectName("field_val")
        h.addWidget(k)
        h.addWidget(v)
        h.addStretch()
        return w

    def _check_pin_age(self) -> None:
        try:
            row = DBManager().fetchone(
                "SELECT last_pin_changed FROM users WHERE id = ?",
                (self._user_id,),
            )
        except Exception:
            return
        if row is None or not row["last_pin_changed"]:
            self._pin_warn.setText("⚠  PIN değiştirme tarihi bilinmiyor — güvenliğiniz için güncelleyin.")
            self._pin_warn.setVisible(True)
            return
        try:
            changed = datetime.strptime(row["last_pin_changed"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - changed).days
            if age_days >= 180:
                self._pin_warn.setText(
                    f"⚠  PIN'iniz {age_days} gündür değiştirilmedi (son: {row['last_pin_changed'][:10]})."
                    " 6 ayda bir güncellemeniz önerilir."
                )
                self._pin_warn.setVisible(True)
        except ValueError:
            pass

    def _on_change_pin(self) -> None:
        old = self._old_pin.text().strip()
        new = self._new_pin.text().strip()
        rep = self._new_pin2.text().strip()

        if not old or not new or not rep:
            QMessageBox.warning(self, "PIN", "Tüm alanlar doldurulmalıdır.")
            return
        if new != rep:
            QMessageBox.warning(self, "PIN", "Yeni PIN'ler eşleşmiyor.")
            return
        pin_error = validate_new_pin(new)
        if pin_error:
            QMessageBox.warning(self, "PIN", pin_error)
            return

        try:
            from CORE.vault_manager import change_vault_pin
            change_vault_pin(self._hwid, old, new)
        except ValueError as exc:
            QMessageBox.warning(self, "PIN Hatası", str(exc))
            return
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))
            return

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            db = DBManager()
            db.execute(
                "UPDATE users SET last_pin_changed = ? WHERE id = ?",
                (now_str, self._user_id),
            )
            db.log("pin_changed", user_id=self._user_id,
                   detail=f"hwid={self._hwid[:8]}")
        except Exception:
            pass

        self._old_pin.clear()
        self._new_pin.clear()
        self._new_pin2.clear()
        self._pin_warn.setVisible(False)
        QMessageBox.information(self, "PIN", "PIN başarıyla güncellendi.")

    # ── İletişim sayfası ──────────────────────────────────────────────────────

    def _make_iletisim_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("page")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(12)

        lbl = QLabel("Destek ve iletişim için ContactDialog'u açın.")
        lbl.setWordWrap(True)
        lbl.setStyleSheet("color: #374151; font-size: 13px; background: transparent;")
        lay.addWidget(lbl)

        btn = QPushButton("💬  Destek ve İletişim Penceresini Aç")
        btn.setObjectName("btn_primary")
        btn.setCursor(Qt.PointingHandCursor)
        btn.clicked.connect(self._open_contact)
        lay.addWidget(btn)

        lay.addStretch()
        return page

    def _open_contact(self) -> None:
        from UI.ContactDialog import ContactDialog
        ContactDialog(self).exec()
