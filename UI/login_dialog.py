import json
from io import BytesIO
from pathlib import Path

import pyotp
import qrcode
import qrcode.constants
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
)

_TOTP_FILE = Path(__file__).parent.parent / "data" / "totp_secret.json"
_PIN_FILE  = Path(__file__).parent.parent / "data" / "pin_hash.json"
_APP_NAME     = "HYCLEUS"
_PIN_MIN_LEN  = 4
_TOTP_LEN     = 6
_MAX_ATTEMPTS = 5

_PH = PasswordHasher()  # Argon2id, varsayılan parametreler

_ROLES = [
    ("Yönetici",    "Tam erişim — tüm özellikler aktif"),
    ("Standart",    "Dosya yönetimi, Kritik sekme görünür"),
    ("Salt Okunur", "Sadece görüntüleme, drag-drop devre dışı"),
]

_STYLE = """
QDialog { background: #1e1e2e; }
QLabel#title {
    color: #cdd6f4; font-size: 18px; font-weight: bold; margin-bottom: 4px;
}
QLabel#subtitle {
    color: #6c7086; font-size: 11px; margin-bottom: 8px;
}
QLabel#section_label {
    color: #89b4fa; font-size: 11px; font-weight: bold;
    margin-top: 8px; margin-bottom: 2px;
}
QLabel#field_label {
    color: #a6adc8; font-size: 12px; margin-top: 4px;
}
QLabel#secret_label {
    color: #585b70; font-size: 10px; font-family: monospace;
}
QLineEdit {
    background: #313244; color: #cdd6f4;
    border: 1px solid #45475a; border-radius: 6px;
    padding: 8px 10px; font-size: 13px;
}
QLineEdit:focus  { border: 1px solid #89b4fa; }
QLineEdit:disabled { color: #45475a; background: #181825; }
QPushButton#action_btn {
    background: #89b4fa; color: #1e1e2e; border: none;
    border-radius: 6px; padding: 10px;
    font-size: 13px; font-weight: bold; margin-top: 8px;
}
QPushButton#action_btn:hover    { background: #b4d0ff; }
QPushButton#action_btn:pressed  { background: #6c9fd8; }
QPushButton#action_btn:disabled { background: #313244; color: #45475a; }
QLabel#error_label  { color: #f38ba8; font-size: 11px; margin-top: 4px; }
QLabel#lockout_label {
    color: #f38ba8; font-size: 12px; font-weight: bold;
    padding: 8px; border: 1px solid #f38ba8; border-radius: 6px;
}
QRadioButton {
    color: #cdd6f4; font-size: 12px; spacing: 6px;
    background: transparent; padding: 2px 0;
}
QRadioButton::indicator {
    width: 14px; height: 14px;
    border: 2px solid #45475a; border-radius: 7px; background: #313244;
}
QRadioButton::indicator:checked { background: #89b4fa; border-color: #89b4fa; }
QRadioButton:hover { color: #b4d0ff; }
"""


# ------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ------------------------------------------------------------------

def _load_pin_data() -> dict | None:
    try:
        return json.loads(_PIN_FILE.read_text())
    except Exception:
        return None


def _load_pin_hash() -> str | None:
    d = _load_pin_data()
    return d["hash"] if d else None


def _load_role() -> str:
    d = _load_pin_data()
    return (d or {}).get("role", "Yönetici")


def _load_secret() -> str | None:
    try:
        return json.loads(_TOTP_FILE.read_text())["secret"]
    except Exception:
        return None


def _save_secret(secret: str) -> None:
    _TOTP_FILE.parent.mkdir(parents=True, exist_ok=True)
    _TOTP_FILE.write_text(json.dumps({"secret": secret}))


def _save_pin_hash(pin: str, role: str) -> None:
    _PIN_FILE.parent.mkdir(parents=True, exist_ok=True)
    _PIN_FILE.write_text(json.dumps({"hash": _PH.hash(pin), "role": role}))


def _verify_pin(pin: str) -> bool:
    stored = _load_pin_hash()
    if not stored:
        return False
    try:
        _PH.verify(stored, pin)
        return True
    except (VerifyMismatchError, InvalidHashError):
        return False


def _make_qr_pixmap(uri: str, size: int = 180) -> QPixmap:
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=4,
        border=2,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    px = QPixmap()
    px.loadFromData(buf.getvalue())
    return px.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)


# ------------------------------------------------------------------
# Dialog
# ------------------------------------------------------------------

class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setStyleSheet(_STYLE)

        self._fail_count  = 0
        self._locked_out  = False
        self._role: str   = "Yönetici"

        secret   = _load_secret()
        pin_hash = _load_pin_hash()
        first_run = secret is None or pin_hash is None

        if first_run:
            self._secret = pyotp.random_base32()
            self._build_setup_ui()
        else:
            self._secret = secret
            self._build_login_ui()

    @property
    def role(self) -> str:
        return self._role

    # ------------------------------------------------------------------
    # İlk kurulum — Rol + PIN + TOTP birlikte ayarla
    # ------------------------------------------------------------------

    def _build_setup_ui(self) -> None:
        self.setWindowTitle("HYCLEUS — Kurulum")
        self.setFixedSize(340, 720)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(4)

        title = QLabel("İlk Kurulum")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Rol, PIN ve Authenticator ayarlarını yapın")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)

        # --- Rol seçimi ---
        role_section = QLabel("ROL")
        role_section.setObjectName("section_label")
        layout.addWidget(role_section)

        self._role_group = QButtonGroup(self)
        for i, (role_name, role_desc) in enumerate(_ROLES):
            rb = QRadioButton(f"{role_name}  ·  {role_desc}")
            rb.setProperty("role_value", role_name)
            if i == 0:
                rb.setChecked(True)
            self._role_group.addButton(rb)
            layout.addWidget(rb)

        # --- PIN bölümü ---
        pin_section = QLabel("PIN")
        pin_section.setObjectName("section_label")
        layout.addWidget(pin_section)

        pin_lbl = QLabel(f"PIN (en az {_PIN_MIN_LEN} karakter)")
        pin_lbl.setObjectName("field_label")
        layout.addWidget(pin_lbl)

        self._pin_input = QLineEdit()
        self._pin_input.setPlaceholderText("••••")
        self._pin_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self._pin_input)

        pin_confirm_lbl = QLabel("PIN tekrar")
        pin_confirm_lbl.setObjectName("field_label")
        layout.addWidget(pin_confirm_lbl)

        self._pin_confirm_input = QLineEdit()
        self._pin_confirm_input.setPlaceholderText("••••")
        self._pin_confirm_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self._pin_confirm_input)

        # --- Authenticator bölümü ---
        auth_section = QLabel("AUTHENTICATOR")
        auth_section.setObjectName("section_label")
        layout.addWidget(auth_section)

        auth_sub = QLabel("Google Authenticator ile QR kodu tarayın")
        auth_sub.setObjectName("field_label")
        auth_sub.setWordWrap(True)
        layout.addWidget(auth_sub)

        totp_obj = pyotp.TOTP(self._secret)
        uri = totp_obj.provisioning_uri(name="admin", issuer_name=_APP_NAME)

        qr_lbl = QLabel()
        qr_lbl.setAlignment(Qt.AlignCenter)
        qr_lbl.setPixmap(_make_qr_pixmap(uri, 180))
        layout.addWidget(qr_lbl)

        secret_lbl = QLabel(f"Manuel: {self._secret}")
        secret_lbl.setObjectName("secret_label")
        secret_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(secret_lbl)

        totp_lbl = QLabel("Doğrulama kodu (tarama sonrası):")
        totp_lbl.setObjectName("field_label")
        layout.addWidget(totp_lbl)

        self._totp_input = QLineEdit()
        self._totp_input.setPlaceholderText("6 haneli kod")
        self._totp_input.setMaxLength(_TOTP_LEN)
        self._totp_input.setAlignment(Qt.AlignCenter)
        self._totp_input.returnPressed.connect(self._on_setup_confirm)
        layout.addWidget(self._totp_input)

        self._error_label = QLabel("")
        self._error_label.setObjectName("error_label")
        self._error_label.setAlignment(Qt.AlignCenter)
        self._error_label.hide()
        layout.addWidget(self._error_label)

        btn = QPushButton("Doğrula ve Kaydet")
        btn.setObjectName("action_btn")
        btn.clicked.connect(self._on_setup_confirm)
        layout.addWidget(btn)

        layout.addStretch()

    # ------------------------------------------------------------------
    # Normal giriş — PIN + TOTP
    # ------------------------------------------------------------------

    def _build_login_ui(self) -> None:
        self.setWindowTitle("HYCLEUS — Giriş")
        self.setFixedSize(340, 340)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(4)

        title = QLabel("HYCLEUS")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Kimlik doğrulama gerekli")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)

        pin_lbl = QLabel("PIN")
        pin_lbl.setObjectName("field_label")
        layout.addWidget(pin_lbl)

        self._pin_input = QLineEdit()
        self._pin_input.setPlaceholderText("En az 4 karakter")
        self._pin_input.setEchoMode(QLineEdit.Password)
        self._pin_input.returnPressed.connect(self._on_login)
        layout.addWidget(self._pin_input)

        totp_lbl = QLabel("Authenticator Kodu")
        totp_lbl.setObjectName("field_label")
        layout.addWidget(totp_lbl)

        self._totp_input = QLineEdit()
        self._totp_input.setPlaceholderText("6 haneli kod")
        self._totp_input.setMaxLength(_TOTP_LEN)
        self._totp_input.returnPressed.connect(self._on_login)
        layout.addWidget(self._totp_input)

        self._error_label = QLabel("")
        self._error_label.setObjectName("error_label")
        self._error_label.setAlignment(Qt.AlignCenter)
        self._error_label.setWordWrap(True)
        self._error_label.hide()
        layout.addWidget(self._error_label)

        self._login_btn = QPushButton("Giriş Yap")
        self._login_btn.setObjectName("action_btn")
        self._login_btn.clicked.connect(self._on_login)
        layout.addWidget(self._login_btn)

        layout.addStretch()

    # ------------------------------------------------------------------
    # İşleyiciler
    # ------------------------------------------------------------------

    def _on_setup_confirm(self) -> None:
        checked = self._role_group.checkedButton()
        if checked is None:
            self._show_error("Lütfen bir rol seçin")
            return

        pin         = self._pin_input.text()
        pin_confirm = self._pin_confirm_input.text()
        code        = self._totp_input.text().strip()

        if len(pin) < _PIN_MIN_LEN:
            self._show_error(f"PIN en az {_PIN_MIN_LEN} karakter olmalı")
            self._pin_input.setFocus()
            return
        if pin != pin_confirm:
            self._show_error("PIN'ler eşleşmiyor")
            self._pin_confirm_input.setFocus()
            return
        if not code.isdigit() or len(code) != _TOTP_LEN:
            self._show_error("6 haneli sayısal kod girin")
            self._totp_input.setFocus()
            return
        if not pyotp.TOTP(self._secret).verify(code, valid_window=1):
            self._show_error("Authenticator kodu geçersiz — tekrar deneyin")
            self._totp_input.setFocus()
            return

        role = checked.property("role_value")
        _save_pin_hash(pin, role)
        _save_secret(self._secret)
        self._role = role
        self.accept()

    def _on_login(self) -> None:
        if self._locked_out:
            return

        pin  = self._pin_input.text()
        code = self._totp_input.text().strip()

        if len(pin) < _PIN_MIN_LEN:
            self._show_error(f"PIN en az {_PIN_MIN_LEN} karakter olmalı")
            self._pin_input.setFocus()
            return
        if not code.isdigit() or len(code) != _TOTP_LEN:
            self._show_error("Authenticator kodu 6 haneli sayı olmalı")
            self._totp_input.setFocus()
            return

        pin_ok  = _verify_pin(pin)
        totp_ok = pyotp.TOTP(self._secret).verify(code, valid_window=1)

        if not pin_ok or not totp_ok:
            self._fail_count += 1
            remaining = _MAX_ATTEMPTS - self._fail_count
            if remaining <= 0:
                self._do_lockout()
                return
            suffix = f" ({remaining} deneme kaldı)" if remaining <= 2 else ""
            self._show_error(f"PIN veya Authenticator kodu hatalı{suffix}")
            return

        self._role = _load_role()
        self.accept()

    def _do_lockout(self) -> None:
        self._locked_out = True
        self._pin_input.setEnabled(False)
        self._totp_input.setEnabled(False)
        self._login_btn.setEnabled(False)
        self._error_label.hide()

        lockout_lbl = QLabel("Çok fazla hatalı deneme\nUygulama kilitlendi — yeniden başlatın")
        lockout_lbl.setObjectName("lockout_label")
        lockout_lbl.setAlignment(Qt.AlignCenter)
        self.layout().insertWidget(self.layout().count() - 1, lockout_lbl)

    def _show_error(self, message: str) -> None:
        self._error_label.setText(message)
        self._error_label.show()
