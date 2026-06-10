"""HYCLEUS — Yeni Kullanıcı Kayıt Diyaloğu

Akış:
  1. Yönetici USB doğrulama  — admin_hwid ile mevcut USB karşılaştırılır.
  2. Yeni USB tespiti         — Tespit Et butonu yeni HWID'i okur.
  3. Kullanıcı bilgileri      — Kullanıcı adı, PIN, PIN tekrar, rol.
  4. Vault oluşturma          — create_vault() + users kaydı (status='pending').
"""
from __future__ import annotations

from pathlib import Path

import pyotp
from argon2 import PasswordHasher
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
)

from CORE.usb_manager import _sanitize_hwid, get_usb_hwid
from CORE.vault_manager import create_vault
from DB.db_manager import DBManager

from CORE.paths import data_dir as _data_dir
_TOTP_FILE   = _data_dir() / "totp_secret.json"
_PIN_MIN_LEN = 4
_PH          = PasswordHasher()

# Yönetici dışındaki roller — Yönetici hesabı yalnızca ilk kurulumda oluşur
_NEW_USER_ROLES = [
    ("Standart",    "Dosya yönetimi, Kritik sekme görünür"),
    ("Salt Okunur", "Sadece görüntüleme, drag-drop devre dışı"),
]

_STYLE = """
QDialog  { background: #1e1e2e; color: #cdd6f4; }
QLabel   { color: #cdd6f4; }
QLabel#title {
    color: #cdd6f4; font-size: 16px; font-weight: bold;
}
QLabel#subtitle { color: #6c7086; font-size: 11px; }
QLabel#section  {
    color: #89b4fa; font-size: 11px; font-weight: bold;
    margin-top: 6px;
}
QLabel#field    { color: #a6adc8; font-size: 12px; margin-top: 2px; }
QLabel#info_ok  { color: #a6e3a1; font-size: 12px; }
QLabel#info_warn { color: #f9e2af; font-size: 12px; }
QLabel#error    { color: #f38ba8; font-size: 11px; }
QFrame#sep { background: #313244; max-height: 1px; }
QLineEdit {
    background: #313244; color: #cdd6f4;
    border: 1px solid #45475a; border-radius: 6px;
    padding: 8px 10px; font-size: 13px;
}
QLineEdit:focus   { border-color: #89b4fa; }
QLineEdit:disabled { color: #45475a; background: #181825; }
QPushButton#primary {
    background: #89b4fa; color: #1e1e2e; border: none;
    border-radius: 6px; padding: 10px;
    font-size: 13px; font-weight: bold; margin-top: 4px;
}
QPushButton#primary:hover   { background: #b4d0ff; }
QPushButton#primary:disabled { background: #313244; color: #45475a; }
QPushButton#secondary {
    background: #313244; color: #cdd6f4; border: none;
    border-radius: 6px; padding: 10px; font-size: 13px;
}
QPushButton#secondary:hover { background: #45475a; }
QPushButton#detect {
    background: #1e1e2e; color: #89b4fa;
    border: 1px solid #89b4fa; border-radius: 6px;
    padding: 6px 14px; font-size: 12px;
}
QPushButton#detect:hover { background: #313244; }
QRadioButton {
    color: #cdd6f4; font-size: 12px; spacing: 6px;
    background: transparent; padding: 2px 0;
}
QRadioButton::indicator {
    width: 14px; height: 14px;
    border: 2px solid #45475a; border-radius: 7px;
    background: #313244;
}
QRadioButton::indicator:checked { background: #89b4fa; border-color: #89b4fa; }
"""


def _sep() -> QFrame:
    f = QFrame()
    f.setObjectName("sep")
    f.setFrameShape(QFrame.HLine)
    return f


class RegisterDialog(QDialog):
    """
    Yeni kullanıcı kayıt diyaloğu.

    Args:
        admin_hwid: Oturum açmış yöneticinin USB HWID'i.
                    Yeni kullanıcının USB'sinin bu değerden farklı olması zorunludur.
    """

    def __init__(self, admin_hwid: str, parent=None) -> None:
        super().__init__(parent)
        self._admin_hwid   = admin_hwid
        self._new_hwid: str | None = None
        self.setWindowTitle("HYCLEUS — Yeni Kullanıcı Kaydı")
        self.setFixedWidth(400)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setStyleSheet(_STYLE)
        self._build_ui()
        self._check_admin_usb()

    # ------------------------------------------------------------------
    # UI kurulumu
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(6)

        # ── Başlık ────────────────────────────────────────────────────
        title = QLabel("Yeni Kullanıcı Kaydı")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        sub = QLabel("Yönetici onayı gerektiren kayıt akışı")
        sub.setObjectName("subtitle")
        sub.setAlignment(Qt.AlignCenter)
        layout.addWidget(sub)

        layout.addSpacing(4)
        layout.addWidget(_sep())
        layout.addSpacing(4)

        # ── Adım 1: Yönetici USB ──────────────────────────────────────
        sec1 = QLabel("1 — YÖNETİCİ DOĞRULAMA")
        sec1.setObjectName("section")
        layout.addWidget(sec1)

        self._admin_status = QLabel("Kontrol ediliyor…")
        self._admin_status.setObjectName("info_warn")
        layout.addWidget(self._admin_status)

        layout.addSpacing(4)
        layout.addWidget(_sep())
        layout.addSpacing(4)

        # ── Adım 2: Yeni USB tespiti ──────────────────────────────────
        sec2 = QLabel("2 — YENİ KULLANICI USB TESPİTİ")
        sec2.setObjectName("section")
        layout.addWidget(sec2)

        usb_hint = QLabel(
            "Yönetici USB'sini çıkarın, yeni kullanıcının USB'sini takın,\n"
            "ardından aşağıdaki butona tıklayın."
        )
        usb_hint.setObjectName("field")
        usb_hint.setWordWrap(True)
        layout.addWidget(usb_hint)

        usb_row = QHBoxLayout()
        self._detect_btn = QPushButton("USB Tespit Et")
        self._detect_btn.setObjectName("detect")
        self._detect_btn.setCursor(Qt.PointingHandCursor)
        self._detect_btn.clicked.connect(self._on_detect)
        usb_row.addWidget(self._detect_btn)

        self._usb_status = QLabel("—")
        self._usb_status.setObjectName("info_warn")
        self._usb_status.setWordWrap(True)
        usb_row.addWidget(self._usb_status, 1)
        layout.addLayout(usb_row)

        layout.addSpacing(4)
        layout.addWidget(_sep())
        layout.addSpacing(4)

        # ── Adım 3: Kullanıcı bilgileri ───────────────────────────────
        sec3 = QLabel("3 — KULLANICI BİLGİLERİ")
        sec3.setObjectName("section")
        layout.addWidget(sec3)

        lbl_user = QLabel("Kullanıcı Adı")
        lbl_user.setObjectName("field")
        layout.addWidget(lbl_user)
        self._username_input = QLineEdit()
        self._username_input.setPlaceholderText("benzersiz bir kullanıcı adı")
        self._username_input.setEnabled(False)
        layout.addWidget(self._username_input)

        lbl_pin = QLabel(f"PIN (en az {_PIN_MIN_LEN} karakter)")
        lbl_pin.setObjectName("field")
        layout.addWidget(lbl_pin)
        self._pin_input = QLineEdit()
        self._pin_input.setEchoMode(QLineEdit.Password)
        self._pin_input.setPlaceholderText("••••")
        self._pin_input.setEnabled(False)
        layout.addWidget(self._pin_input)

        lbl_pin2 = QLabel("PIN Tekrar")
        lbl_pin2.setObjectName("field")
        layout.addWidget(lbl_pin2)
        self._pin2_input = QLineEdit()
        self._pin2_input.setEchoMode(QLineEdit.Password)
        self._pin2_input.setPlaceholderText("••••")
        self._pin2_input.setEnabled(False)
        layout.addWidget(self._pin2_input)

        lbl_role = QLabel("Rol")
        lbl_role.setObjectName("field")
        layout.addWidget(lbl_role)
        self._role_group = QButtonGroup(self)
        for i, (role_name, role_desc) in enumerate(_NEW_USER_ROLES):
            rb = QRadioButton(f"{role_name}  ·  {role_desc}")
            rb.setProperty("role_value", role_name)
            rb.setEnabled(False)
            if i == 0:
                rb.setChecked(True)
            self._role_group.addButton(rb)
            layout.addWidget(rb)

        layout.addSpacing(4)

        self._error_label = QLabel("")
        self._error_label.setObjectName("error")
        self._error_label.setAlignment(Qt.AlignCenter)
        self._error_label.setWordWrap(True)
        self._error_label.hide()
        layout.addWidget(self._error_label)

        # ── Butonlar ──────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        self._save_btn = QPushButton("Kaydet (Onay Bekleyecek)")
        self._save_btn.setObjectName("primary")
        self._save_btn.setEnabled(False)
        self._save_btn.setCursor(Qt.PointingHandCursor)
        self._save_btn.clicked.connect(self._on_save)
        btn_row.addWidget(self._save_btn)

        cancel_btn = QPushButton("İptal")
        cancel_btn.setObjectName("secondary")
        cancel_btn.setCursor(Qt.PointingHandCursor)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        layout.addLayout(btn_row)

    # ------------------------------------------------------------------
    # Adım 1: Yönetici USB kontrolü
    # ------------------------------------------------------------------

    def _check_admin_usb(self) -> None:
        current = get_usb_hwid()
        if current == self._admin_hwid:
            self._admin_status.setText(
                f"Yönetici USB takılı: {self._admin_hwid[:16]}…"
            )
            self._admin_status.setObjectName("info_ok")
            self._admin_status.setStyleSheet("color:#a6e3a1; font-size:12px;")
        else:
            self._admin_status.setText(
                "Yönetici USB tespit edilemedi. Bu pencereyi yönetici\n"
                "oturumundan açtığınızdan emin olun."
            )
            self._admin_status.setObjectName("info_warn")
            self._admin_status.setStyleSheet("color:#f9e2af; font-size:12px;")

    # ------------------------------------------------------------------
    # Adım 2: Yeni USB tespiti
    # ------------------------------------------------------------------

    def _on_detect(self) -> None:
        hwid = get_usb_hwid()

        if hwid is None:
            self._usb_status.setText("USB bulunamadı.")
            self._usb_status.setStyleSheet("color:#f38ba8; font-size:12px;")
            self._set_form_enabled(False)
            return

        # Geçersiz karakter içeriyorsa temizlenmiş hali al, boş kaldıysa reddet
        hwid = _sanitize_hwid(hwid) or ""
        if not hwid:
            self._usb_status.setText(
                "USB seri numarası geçersiz karakter içeriyor.\n"
                "Farklı bir USB deneyiniz."
            )
            self._usb_status.setStyleSheet("color:#f38ba8; font-size:12px;")
            self._set_form_enabled(False)
            return

        if hwid == self._admin_hwid:
            self._usb_status.setText(
                "Bu yönetici USB'si.\nLütfen yeni kullanıcının USB'sini takın."
            )
            self._usb_status.setStyleSheet("color:#f9e2af; font-size:12px;")
            self._set_form_enabled(False)
            return

        # Daha önce kayıtlı mı?
        existing = DBManager().fetchone(
            "SELECT hwid FROM usb_tokens WHERE hwid = ?", (hwid,)
        )
        if existing:
            self._usb_status.setText(
                f"Bu USB zaten kayıtlı:\n{hwid[:24]}…"
            )
            self._usb_status.setStyleSheet("color:#f38ba8; font-size:12px;")
            self._set_form_enabled(False)
            return

        self._new_hwid = hwid
        self._usb_status.setText(f"Tespit edildi: {hwid[:20]}…")
        self._usb_status.setStyleSheet("color:#a6e3a1; font-size:12px;")
        self._set_form_enabled(True)

    def _set_form_enabled(self, enabled: bool) -> None:
        self._username_input.setEnabled(enabled)
        self._pin_input.setEnabled(enabled)
        self._pin2_input.setEnabled(enabled)
        self._save_btn.setEnabled(enabled)
        for btn in self._role_group.buttons():
            btn.setEnabled(enabled)

    # ------------------------------------------------------------------
    # Adım 4: Kayıt
    # ------------------------------------------------------------------

    def _on_save(self) -> None:
        self._error_label.hide()

        username = self._username_input.text().strip()
        pin      = self._pin_input.text()
        pin2     = self._pin2_input.text()

        checked = self._role_group.checkedButton()
        role    = checked.property("role_value") if checked else "Standart"

        # ── Doğrulama ─────────────────────────────────────────────────
        if not username:
            self._show_error("Kullanıcı adı boş olamaz.")
            return
        if len(username) < 3:
            self._show_error("Kullanıcı adı en az 3 karakter olmalı.")
            return
        if len(pin) < _PIN_MIN_LEN:
            self._show_error(f"PIN en az {_PIN_MIN_LEN} karakter olmalı.")
            return
        if pin != pin2:
            self._show_error("PIN'ler eşleşmiyor.")
            return
        if self._new_hwid is None:
            self._show_error("Önce yeni USB'yi tespit edin.")
            return

        db = DBManager()

        # Kullanıcı adı benzersizlik kontrolü
        if db.fetchone("SELECT id FROM users WHERE username = ?", (username,)):
            self._show_error("Bu kullanıcı adı zaten alınmış.")
            return

        # ── Vault oluştur ─────────────────────────────────────────────
        try:
            create_vault(self._new_hwid, pin, role)
        except Exception as exc:
            self._show_error(f"Vault oluşturulamadı: {exc}")
            return

        # ── DB: users kaydı (status='pending') ────────────────────────
        db_role = "admin" if role == "Yönetici" else "user"
        try:
            db.execute(
                """
                INSERT INTO users (username, password_hash, role, status, hwid)
                VALUES (?, ?, ?, 'pending', ?)
                """,
                (username, _PH.hash(pin), db_role, self._new_hwid),
            )
            db.log(
                "user_registered",
                detail=(
                    f"username={username} hwid={self._new_hwid} "
                    f"role={role} registered_by={self._admin_hwid}"
                ),
            )
        except Exception as exc:
            self._show_error(f"Veritabanı hatası: {exc}")
            return

        QMessageBox.information(
            self,
            "Kayıt Başarılı",
            f"'{username}' kullanıcısı kaydedildi.\n\n"
            "Yönetici onayından sonra giriş yapabilecek.\n"
            "Onay için Admin Paneli → Bekleyen Kayıtlar sekmesini kullanın.",
        )
        self.accept()

    # ------------------------------------------------------------------
    # Yardımcı
    # ------------------------------------------------------------------

    def _show_error(self, msg: str) -> None:
        self._error_label.setText(msg)
        self._error_label.show()
