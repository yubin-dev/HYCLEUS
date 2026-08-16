"""HYCLEUS — Giriş & Kayıt Diyaloğu"""
from __future__ import annotations

import json
import logging
import os
import sys
from io import BytesIO
from pathlib import Path

_log = logging.getLogger("hycleus.login")

import pyotp
import qrcode
import qrcode.constants
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from PySide6.QtCore import QPoint, Qt, QTimer
from PySide6.QtGui import QColor, QPalette, QPixmap
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from CORE.usb_manager import get_usb_hwid
from CORE.vault_manager import (
    USBAuthError,
    VaultTamperedError,
    _read_vault_path,
    create_vault,
    open_vault,
    read_vault_role,
)
from DB.db_manager import DBManager

# ── Paths / constants ─────────────────────────────────────────────────────────

from CORE.paths import data_dir as _data_dir
from CORE import rate_limit
from CORE.pin_policy import LOGIN_MIN_LEN, PIN_MIN_LEN, validate_new_pin
from CORE.rate_limit import LockState
from CORE.secret_store import load_totp_secret, store_totp_secret

_PIN_FILE    = _data_dir() / "pin_hash.json"
_VAULT_PATH  = _data_dir() / ".hcl_vault"
_APP_NAME    = "HYCLEUS"
_TOTP_LEN    = 6
# Deneme sınırı ve kilit süreleri CORE/rate_limit.py'de — sayaç DB'de tutulur

_PH = PasswordHasher()

_SETUP_ROLES = [
    ("Yönetici",    "Tam erişim"),
    ("Standart",    "Dosya yönetimi"),
    ("Salt Okunur", "Sadece görüntüleme"),
]

# ── Shared QSS fragments ───────────────────────────────────────────────────────

# Input: borderless, only bottom rule, min-height 48px
_QSS_INPUT = (
    "QLineEdit {"
    "  background: transparent;"
    "  color: #111827;"
    "  border: none;"
    "  border-bottom: 2px solid #E5E7EB;"
    "  border-radius: 0px;"
    "  padding: 8px 0px;"
    "  font-size: 15px;"
    "  min-height: 48px;"
    "}"
    "QLineEdit:focus {"
    "  border-bottom: 2px solid #2563EB;"
    "}"
    "QLineEdit:disabled {"
    "  color: #9CA3AF;"
    "  border-bottom: 2px solid #F3F4F6;"
    "}"
)

_QSS_COMBO = (
    "QComboBox {"
    "  background: transparent;"
    "  color: #111827;"
    "  border: none;"
    "  border-bottom: 2px solid #E5E7EB;"
    "  border-radius: 0px;"
    "  padding: 8px 0px;"
    "  font-size: 15px;"
    "  min-height: 48px;"
    "}"
    "QComboBox:focus { border-bottom: 2px solid #2563EB; }"
    "QComboBox::drop-down { border: none; width: 28px; }"
    "QComboBox QAbstractItemView {"
    "  background: #FFFFFF;"
    "  color: #111827;"
    "  border: 1px solid #E5E7EB;"
    "  outline: none;"
    "  selection-background-color: #EFF6FF;"
    "  selection-color: #1D4ED8;"
    "}"
)

_QSS_BTN_PRIMARY = (
    "QPushButton {"
    "  background: #2563EB;"
    "  color: #FFFFFF;"
    "  border: none;"
    "  border-radius: 10px;"
    "  font-size: 15px;"
    "  font-weight: 600;"
    "  min-height: 48px;"
    "}"
    "QPushButton:hover   { background: #1D4ED8; }"
    "QPushButton:pressed { background: #1E40AF; }"
    "QPushButton:disabled { background: #BFDBFE; color: #93C5FD; }"
)

_QSS_TAB_ON = (
    "QPushButton {"
    "  background: transparent;"
    "  color: #2563EB;"
    "  border: none;"
    "  border-bottom: 2px solid #2563EB;"
    "  border-radius: 0px;"
    "  font-size: 14px;"
    "  font-weight: 600;"
    "  padding-bottom: 4px;"
    "}"
)
_QSS_TAB_OFF = (
    "QPushButton {"
    "  background: transparent;"
    "  color: #9CA3AF;"
    "  border: none;"
    "  border-bottom: 2px solid transparent;"
    "  border-radius: 0px;"
    "  font-size: 14px;"
    "  padding-bottom: 4px;"
    "}"
    "QPushButton:hover { color: #6B7280; }"
)

_QSS_RADIO = (
    "QRadioButton {"
    "  color: #374151;"
    "  font-size: 13px;"
    "  background: transparent;"
    "  spacing: 6px;"
    "}"
    "QRadioButton::indicator {"
    "  width: 16px; height: 16px;"
    "  border: 2px solid #D1D5DB;"
    "  border-radius: 8px;"
    "  background: #FFFFFF;"
    "}"
    "QRadioButton::indicator:checked {"
    "  background: #2563EB;"
    "  border-color: #2563EB;"
    "}"
)

_PLACEHOLDER_COLOR = QColor("#9CA3AF")


# ── Helper functions ──────────────────────────────────────────────────────────

def _load_pin_data() -> dict | None:
    try:
        return json.loads(_PIN_FILE.read_text())
    except Exception:
        return None


def _load_pin_hash() -> str | None:
    d = _load_pin_data()
    return d["hash"] if d else None


def _load_role() -> str:
    return (_load_pin_data() or {}).get("role", "Yönetici")


def _load_secret() -> str | None:
    """TOTP sırrını anahtar kasasından okur (eskiden data/totp_secret.json)."""
    return load_totp_secret()


def _save_secret(secret: str) -> None:
    """TOTP sırrını anahtar kasasına yazar; geri okuma doğrulaması store() içinde."""
    store_totp_secret(secret)


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


def _make_qr_pixmap(uri: str, size: int = 160) -> QPixmap:
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


def _lbl(text: str, size: int = 12, color: str = "#9CA3AF",
         bold: bool = False) -> QLabel:
    w = QLabel(text)
    weight = "font-weight:600;" if bold else ""
    w.setStyleSheet(
        f"color:{color};font-size:{size}px;{weight}background:transparent;"
    )
    return w


def _make_input(placeholder: str = "", password: bool = False,
                max_len: int = 0) -> QLineEdit:
    """Styled QLineEdit — alt çizgi, 48px, placeholder #9CA3AF."""
    inp = QLineEdit()
    inp.setPlaceholderText(placeholder)
    if password:
        inp.setEchoMode(QLineEdit.Password)
    if max_len:
        inp.setMaxLength(max_len)
    inp.setStyleSheet(_QSS_INPUT)
    inp.setMinimumHeight(48)
    # placeholder rengi: Qt'de QSS ile değil QPalette ile ayarlanır
    pal = inp.palette()
    pal.setColor(QPalette.PlaceholderText, _PLACEHOLDER_COLOR)
    inp.setPalette(pal)
    return inp


def _field(label_text: str, input_widget: QWidget) -> QWidget:
    """
    Container:
      QLabel  (12px, #9CA3AF)      ← label_text
      [6px gap]
      input_widget                  ← herhangi bir QWidget
    Fieldlar arasına addSpacing(20) koyulur; bu fonksiyon iç boşlukla ilgilenmez.
    """
    c = QWidget()
    c.setStyleSheet("background:transparent;")
    v = QVBoxLayout(c)
    v.setContentsMargins(0, 0, 0, 0)
    v.setSpacing(6)                    # label → input arası
    v.addWidget(_lbl(label_text))
    v.addWidget(input_widget)
    return c


def _hsep() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.HLine)
    f.setStyleSheet("QFrame{background:#F3F4F6;max-height:1px;border:none;}")
    return f


# ── Dialog ─────────────────────────────────────────────────────────────────────

class LoginDialog(QDialog):
    def __init__(
        self,
        hwid: str | None = None,
        first_run: bool | None = None,
        use_vault: bool | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        self._hwid          = hwid
        # Başarısız deneme sayacı DB'de (CORE/rate_limit.py) — burada tutulmaz,
        # yoksa uygulamayı yeniden başlatmak sayacı sıfırlar ve kilidi bypass ederdi.
        self._locked_out    = False
        self._lock_timer: QTimer | None = None
        self._role: str     = "Yönetici"
        self.session_key: bytes = b""
        self._drag_pos: QPoint | None = None

        # use_vault: main.py'den gelir (sys.frozen korumalı); yoksa fallback
        if use_vault is not None:
            self._use_vault = use_vault
        else:
            self._use_vault = (
                hwid is not None
                and not hasattr(sys, "frozen")
                and os.getenv("DEV_MODE", "").lower() not in ("1", "true", "yes")
            )

        secret = _load_secret()

        # first_run: main.py'den gelir; yoksa hesapla
        if first_run is not None:
            _first_run = first_run
        elif self._use_vault:
            _vault_path   = _read_vault_path(hwid) if hwid else None
            _vault_exists = _vault_path.exists() if _vault_path else False
            _first_run    = secret is None or not _vault_exists
        else:
            _first_run = secret is None or _load_pin_hash() is None

        if _first_run:
            self._secret = pyotp.random_base32()
            self._init_card(640, 760)
            self._build_setup_ui()
        else:
            # Tip daraltma; güvenlik kontrolü değil (mypy None'ı burada eliyor).
            assert secret is not None  # nosec B101
            self._secret = secret
            self._init_card(640, 720)
            self._build_main_ui()

    @property
    def role(self) -> str:
        return self._role

    # ── Card / window ─────────────────────────────────────────────────────

    def _init_card(self, w: int, h: int) -> None:
        self.setFixedSize(w + 20, h + 20)

        self._card = QFrame(self)
        self._card.setGeometry(10, 10, w, h)
        self._card.setStyleSheet(
            "QFrame{background:#FFFFFF;border:none;border-radius:14px;}"
        )

        eff = QGraphicsDropShadowEffect(self)
        eff.setBlurRadius(28)
        eff.setOffset(0, 6)
        eff.setColor(QColor(0, 0, 0, 30))
        self._card.setGraphicsEffect(eff)

    def mousePressEvent(self, ev) -> None:
        if ev.button() == Qt.LeftButton:
            self._drag_pos = (
                ev.globalPosition().toPoint() - self.frameGeometry().topLeft()
            )

    def mouseMoveEvent(self, ev) -> None:
        if self._drag_pos is not None and ev.buttons() & Qt.LeftButton:
            self.move(ev.globalPosition().toPoint() - self._drag_pos)

    def mouseReleaseEvent(self, ev) -> None:
        self._drag_pos = None

    # ── Main UI (login + register tabs) ──────────────────────────────────

    def _build_main_ui(self) -> None:
        root = QVBoxLayout(self._card)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ──────────────────────────────────────────────────────
        header = QWidget()
        header.setStyleSheet("background:transparent;")
        h_lay = QVBoxLayout(header)
        h_lay.setContentsMargins(48, 44, 48, 0)
        h_lay.setSpacing(0)

        title = _lbl("HYCLEUS", size=30, color="#111827", bold=True)
        title.setAlignment(Qt.AlignCenter)
        h_lay.addWidget(title)

        sub = _lbl("Güvenli Dosya Yönetim Sistemi", size=14, color="#6B7280")
        sub.setAlignment(Qt.AlignCenter)
        sub.setContentsMargins(0, 8, 0, 0)
        h_lay.addWidget(sub)

        h_lay.addSpacing(24)
        h_lay.addWidget(_hsep())
        root.addWidget(header)

        # ── Tab bar ──────────────────────────────────────────────────────
        tab_wrap = QWidget()
        tab_wrap.setStyleSheet("background:transparent;")
        tab_h = QHBoxLayout(tab_wrap)
        tab_h.setContentsMargins(48, 16, 48, 0)
        tab_h.setSpacing(32)

        self._tab_login = QPushButton("Giriş Yap")
        self._tab_login.setFixedHeight(40)
        self._tab_login.setCursor(Qt.PointingHandCursor)
        self._tab_login.clicked.connect(lambda: self._switch_tab(0))

        self._tab_register = QPushButton("Kayıt Ol")
        self._tab_register.setFixedHeight(40)
        self._tab_register.setCursor(Qt.PointingHandCursor)
        self._tab_register.clicked.connect(lambda: self._switch_tab(1))

        tab_h.addWidget(self._tab_login)
        tab_h.addWidget(self._tab_register)
        tab_h.addStretch()
        root.addWidget(tab_wrap)

        # ── Stacked pages ────────────────────────────────────────────────
        self._stack = QStackedWidget()
        self._stack.setStyleSheet("background:transparent;")
        self._stack.addWidget(self._build_login_page())
        self._stack.addWidget(self._build_register_page())
        root.addWidget(self._stack, 1)   # stretch=1 → tüm boş alanı kapla

        self._switch_tab(0)

    def _switch_tab(self, idx: int) -> None:
        self._stack.setCurrentIndex(idx)
        self._tab_login.setStyleSheet(  _QSS_TAB_ON  if idx == 0 else _QSS_TAB_OFF)
        self._tab_register.setStyleSheet(_QSS_TAB_ON if idx == 1 else _QSS_TAB_OFF)

    # ── Login page ────────────────────────────────────────────────────────

    def _build_login_page(self) -> QWidget:
        page = QWidget()
        page.setStyleSheet("background:transparent;")

        lay = QVBoxLayout(page)
        lay.setContentsMargins(48, 32, 48, 40)
        lay.setSpacing(0)

        # USB badge
        usb_row = QHBoxLayout()
        usb_row.setSpacing(6)
        dot = QLabel("●")
        if self._hwid:
            dot.setStyleSheet("color:#16A34A;font-size:14px;background:transparent;")
            usb_txt = _lbl("USB Bağlı",    size=13, color="#16A34A")
        else:
            dot.setStyleSheet("color:#DC2626;font-size:14px;background:transparent;")
            usb_txt = _lbl("USB Gerekli",  size=13, color="#DC2626")
        usb_row.addWidget(dot)
        usb_row.addWidget(usb_txt)
        usb_row.addStretch()
        lay.addLayout(usb_row)
        lay.addSpacing(28)

        # PIN field
        # Giriş ekranı: burada uzunluk ipucu verilmez — yeni politika 6 hane
        # ama eski 4-5 haneli PIN'ler hâlâ geçerli, "en az 6" yazmak yanıltıcı olurdu.
        self._pin_input = _make_input("PIN'inizi girin", password=True)
        self._pin_input.returnPressed.connect(self._on_login)
        lay.addWidget(_field("PIN", self._pin_input))
        lay.addSpacing(20)

        # TOTP field
        self._totp_input = _make_input("6 haneli kod", max_len=_TOTP_LEN)
        self._totp_input.returnPressed.connect(self._on_login)
        lay.addWidget(_field("Authenticator Kodu", self._totp_input))
        lay.addSpacing(32)

        # Error label
        self._error_label = QLabel("")
        self._error_label.setAlignment(Qt.AlignCenter)
        self._error_label.setWordWrap(True)
        self._error_label.setStyleSheet(
            "color:#DC2626;font-size:13px;background:transparent;"
        )
        self._error_label.hide()
        lay.addWidget(self._error_label)
        lay.addSpacing(8)

        # Login button
        self._login_btn = QPushButton("Giriş Yap")
        self._login_btn.setStyleSheet(_QSS_BTN_PRIMARY)
        self._login_btn.setCursor(Qt.PointingHandCursor)
        self._login_btn.clicked.connect(self._on_login)
        lay.addWidget(self._login_btn)

        lay.addStretch()
        return page

    # ── Register page (scroll area) ───────────────────────────────────────

    def _build_register_page(self) -> QWidget:
        # Outer wrapper: scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet(
            "QScrollArea{background:transparent;border:none;}"
            "QScrollBar:vertical{"
            "  background:#F9FAFB;width:6px;border-radius:3px;}"
            "QScrollBar::handle:vertical{"
            "  background:#D1D5DB;border-radius:3px;min-height:24px;}"
            "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}"
        )

        # Inner content widget
        inner = QWidget()
        inner.setStyleSheet("background:transparent;")
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(48, 32, 48, 40)
        lay.setSpacing(0)

        # ── Info box ─────────────────────────────────────────────────────
        info = QFrame()
        info.setStyleSheet(
            "QFrame{"
            "  background:#EFF6FF;"
            "  border:none;"
            "  border-radius:10px;"
            "}"
        )
        info_lay = QVBoxLayout(info)
        info_lay.setContentsMargins(16, 12, 16, 12)
        info_lay.setSpacing(0)
        info_lbl = QLabel("Kayıt için Yönetici USB'si takılı olmalıdır")
        info_lbl.setStyleSheet(
            "color:#1D4ED8;font-size:13px;background:transparent;border:none;"
        )
        info_lbl.setWordWrap(True)
        info_lay.addWidget(info_lbl)
        lay.addWidget(info)
        lay.addSpacing(24)

        # ── Admin USB status field ────────────────────────────────────────
        current = get_usb_hwid()
        if current == self._hwid and self._hwid is not None:
            usb_val = _lbl("● Bağlı",     size=15, color="#16A34A")
        else:
            usb_val  = _lbl("● Bekleniyor", size=15, color="#D97706")
        usb_val.setMinimumHeight(48)
        usb_val.setContentsMargins(0, 10, 0, 0)
        lay.addWidget(_field("Yönetici USB", usb_val))
        lay.addSpacing(20)

        # ── Kullanıcı Adı ─────────────────────────────────────────────────
        self._reg_username = _make_input("benzersiz bir kullanıcı adı")
        lay.addWidget(_field("Kullanıcı Adı", self._reg_username))
        lay.addSpacing(20)

        # ── PIN ───────────────────────────────────────────────────────────
        self._reg_pin = _make_input(f"En az {PIN_MIN_LEN} karakter", password=True)
        lay.addWidget(_field("PIN", self._reg_pin))
        lay.addSpacing(20)

        # ── PIN Tekrar ────────────────────────────────────────────────────
        self._reg_pin2 = _make_input("PIN'i tekrar girin", password=True)
        lay.addWidget(_field("PIN Tekrar", self._reg_pin2))
        lay.addSpacing(20)

        # ── Rol ───────────────────────────────────────────────────────────
        self._reg_role = QComboBox()
        self._reg_role.addItems(["Standart", "Salt Okunur"])
        self._reg_role.setStyleSheet(_QSS_COMBO)
        self._reg_role.setMinimumHeight(48)
        lay.addWidget(_field("Rol", self._reg_role))
        lay.addSpacing(32)

        # ── Error / pending feedback ──────────────────────────────────────
        self._reg_error = QLabel("")
        self._reg_error.setAlignment(Qt.AlignCenter)
        self._reg_error.setWordWrap(True)
        self._reg_error.setStyleSheet(
            "color:#DC2626;font-size:13px;background:transparent;"
        )
        self._reg_error.hide()
        lay.addWidget(self._reg_error)

        self._reg_pending = QLabel("Yönetici onayı bekleniyor...")
        self._reg_pending.setAlignment(Qt.AlignCenter)
        self._reg_pending.setStyleSheet(
            "color:#16A34A;font-size:13px;background:transparent;"
        )
        self._reg_pending.hide()
        lay.addWidget(self._reg_pending)
        lay.addSpacing(8)

        # ── Register button ───────────────────────────────────────────────
        self._reg_btn = QPushButton("Kayıt Ol")
        self._reg_btn.setStyleSheet(_QSS_BTN_PRIMARY)
        self._reg_btn.setCursor(Qt.PointingHandCursor)
        self._reg_btn.clicked.connect(self._on_register)
        lay.addWidget(self._reg_btn)

        lay.addStretch()

        scroll.setWidget(inner)
        return scroll

    # ── Setup UI (first run) ──────────────────────────────────────────────

    def _build_setup_ui(self) -> None:
        root = QVBoxLayout(self._card)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        header = QWidget()
        header.setStyleSheet("background:transparent;")
        h_lay = QVBoxLayout(header)
        h_lay.setContentsMargins(48, 44, 48, 0)
        h_lay.setSpacing(0)

        title_lbl = _lbl("İlk Kurulum", size=30, color="#111827", bold=True)
        title_lbl.setAlignment(Qt.AlignCenter)
        h_lay.addWidget(title_lbl)

        sub = _lbl("Rol, PIN ve Authenticator ayarlarını yapın", size=14, color="#6B7280")
        sub.setAlignment(Qt.AlignCenter)
        sub.setContentsMargins(0, 8, 0, 0)
        h_lay.addWidget(sub)
        h_lay.addSpacing(24)
        h_lay.addWidget(_hsep())
        root.addWidget(header)

        # Scrollable setup content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet(
            "QScrollArea{background:transparent;border:none;}"
            "QScrollBar:vertical{background:#F9FAFB;width:6px;border-radius:3px;}"
            "QScrollBar::handle:vertical{background:#D1D5DB;border-radius:3px;min-height:24px;}"
            "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}"
        )

        inner = QWidget()
        inner.setStyleSheet("background:transparent;")
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(48, 32, 48, 40)
        lay.setSpacing(0)

        # Role selection
        role_lbl = _lbl("Rol", size=12, color="#9CA3AF")
        lay.addWidget(role_lbl)
        lay.addSpacing(10)

        self._role_group = QButtonGroup(self)
        for i, (rname, rdesc) in enumerate(_SETUP_ROLES):
            rb = QRadioButton(f"{rname}  ·  {rdesc}")
            rb.setProperty("role_value", rname)
            rb.setStyleSheet(_QSS_RADIO)
            if i == 0:
                rb.setChecked(True)
            self._role_group.addButton(rb)
            lay.addWidget(rb)
            lay.addSpacing(6)
        lay.addSpacing(14)

        # PIN
        self._pin_input = _make_input("••••", password=True)
        lay.addWidget(_field(f"PIN (en az {PIN_MIN_LEN} karakter)", self._pin_input))
        lay.addSpacing(20)

        # PIN Tekrar
        self._pin_confirm_input = _make_input("••••", password=True)
        lay.addWidget(_field("PIN Tekrar", self._pin_confirm_input))
        lay.addSpacing(28)

        # QR code
        qr_hint = _lbl("Google Authenticator ile QR kodu tarayın",
                        size=13, color="#6B7280")
        qr_hint.setAlignment(Qt.AlignCenter)
        lay.addWidget(qr_hint)
        lay.addSpacing(12)

        uri = pyotp.TOTP(self._secret).provisioning_uri(
            name="admin", issuer_name=_APP_NAME
        )
        qr_lbl = QLabel()
        qr_lbl.setAlignment(Qt.AlignCenter)
        qr_lbl.setPixmap(_make_qr_pixmap(uri, 160))
        qr_lbl.setStyleSheet("background:transparent;")
        lay.addWidget(qr_lbl)

        secret_lbl = QLabel(f"Manuel: {self._secret}")
        secret_lbl.setAlignment(Qt.AlignCenter)
        secret_lbl.setStyleSheet(
            "color:#9CA3AF;font-size:10px;font-family:monospace;background:transparent;"
        )
        lay.addWidget(secret_lbl)
        lay.addSpacing(20)

        # TOTP
        self._totp_input = _make_input("6 haneli kod", max_len=_TOTP_LEN)
        self._totp_input.setAlignment(Qt.AlignCenter)
        self._totp_input.returnPressed.connect(self._on_setup_confirm)
        lay.addWidget(_field("Doğrulama Kodu (tarama sonrası)", self._totp_input))
        lay.addSpacing(32)

        # Error label
        self._error_label = QLabel("")
        self._error_label.setAlignment(Qt.AlignCenter)
        self._error_label.setWordWrap(True)
        self._error_label.setStyleSheet(
            "color:#DC2626;font-size:13px;background:transparent;"
        )
        self._error_label.hide()
        lay.addWidget(self._error_label)
        lay.addSpacing(8)

        # Confirm button
        confirm_btn = QPushButton("Doğrula ve Başla")
        confirm_btn.setStyleSheet(_QSS_BTN_PRIMARY)
        confirm_btn.setCursor(Qt.PointingHandCursor)
        confirm_btn.clicked.connect(self._on_setup_confirm)
        lay.addWidget(confirm_btn)
        lay.addStretch()

        scroll.setWidget(inner)
        root.addWidget(scroll, 1)

    # ── Event handlers (mantık değişmedi) ─────────────────────────────────

    def _on_setup_confirm(self) -> None:
        checked = self._role_group.checkedButton()
        if checked is None:
            self._show_error("Lütfen bir rol seçin")
            return

        pin  = self._pin_input.text()
        pin2 = self._pin_confirm_input.text()
        code = self._totp_input.text().strip()

        pin_error = validate_new_pin(pin)
        if pin_error:
            self._show_error(pin_error)
            self._pin_input.setFocus()
            return
        if pin != pin2:
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
        if self._use_vault and self._hwid is not None:
            try:
                create_vault(self._hwid, pin, role)
            except Exception as exc:
                self._show_error(f"Vault oluşturulamadı: {exc}")
                return
            # Kurulum sonrası vault'u hemen açarak session_key'i al
            try:
                _, self.session_key = open_vault(self._hwid, pin)
            except Exception as exc:
                self._show_error(f"Vault açılamadı: {exc}")
                return
        else:
            _save_pin_hash(pin, role)
        _save_secret(self._secret)
        self._role = role
        self.accept()

    def _on_login(self) -> None:
        # Kilit DB'de tutulur — uygulamayı yeniden başlatmak kilidi kaldırmaz
        lock = rate_limit.check(DBManager(), self._rl_key())
        if lock.locked:
            rate_limit.record_blocked_attempt(DBManager(), self._rl_key(), lock)
            self._apply_lockout(lock)
            return

        if self._locked_out:
            return

        pin  = self._pin_input.text()
        code = self._totp_input.text().strip()

        # DİKKAT: burada PIN_MIN_LEN (6) DEĞİL, LOGIN_MIN_LEN (4) kullanılır.
        # Politika 6'ya çıkarılmadan önce kaydolmuş 4-5 haneli PIN sahipleri
        # aksi hâlde kendi doğru PIN'leriyle giriş yapamazdı.
        if len(pin) < LOGIN_MIN_LEN:
            self._show_error(f"PIN en az {LOGIN_MIN_LEN} karakter olmalı")
            self._pin_input.setFocus()
            return
        if not code.isdigit() or len(code) != _TOTP_LEN:
            self._show_error("Authenticator kodu 6 haneli sayı olmalı")
            self._totp_input.setFocus()
            return

        pin_ok = False
        role   = ""

        if self._use_vault and self._hwid is not None:
            try:
                role, self.session_key = open_vault(self._hwid, pin)
                pin_ok = True
            except VaultTamperedError:
                self._show_error("Vault bütünlüğü bozulmuş — yöneticiye başvurun")
                return
            except USBAuthError as exc:
                # Kara liste: PIN doğru olsa bile açılmaz. Genel "PIN hatalı"
                # mesajına düşürmek yanıltıcı olurdu — kullanıcı doğru PIN'i
                # tekrar tekrar dener ve kendini rate limit'e kilitler.
                self._show_error(str(exc))
                return
            except Exception:
                pass
        else:
            pin_ok = _verify_pin(pin)
            role   = _load_role() if pin_ok else ""

        totp_ok = pyotp.TOTP(self._secret).verify(code, valid_window=1)

        if not pin_ok or not totp_ok:
            reason = f"pin_ok={pin_ok} totp_ok={totp_ok}"
            state = rate_limit.record_failure(DBManager(), self._rl_key(), detail=reason)
            if state.locked:
                self._apply_lockout(state)
                return
            remaining = rate_limit.MAX_ATTEMPTS - state.fail_count
            suffix = f" ({remaining} deneme kaldı)" if remaining <= 2 else ""
            self._show_error(f"PIN veya Authenticator kodu hatalı{suffix}")
            return

        if self._hwid:
            row = DBManager().fetchone(
                "SELECT status FROM users WHERE hwid = ?", (self._hwid,)
            )
            if row is not None and row["status"] == "pending":
                self._show_error("Hesabınız yönetici onayı bekliyor — giriş yapılamaz")
                return

        # Başarılı giriş sayacı sıfırlar ve audit log'a düşer
        rate_limit.record_success(DBManager(), self._rl_key())

        self._role = role
        _log.info(
            "login_result  hwid=%s  role=%s  session_key_len=%d",
            self._hwid, self._role, len(self.session_key) if self.session_key else 0,
        )
        self.accept()

    def _on_register(self) -> None:
        self._reg_error.hide()
        self._reg_pending.hide()

        username = self._reg_username.text().strip()
        pin      = self._reg_pin.text()
        pin2     = self._reg_pin2.text()
        role     = self._reg_role.currentText()

        if not username:
            self._show_reg_error("Kullanıcı adı boş olamaz.")
            return
        if len(username) < 3:
            self._show_reg_error("Kullanıcı adı en az 3 karakter olmalı.")
            return
        pin_error = validate_new_pin(pin)
        if pin_error:
            self._show_reg_error(pin_error)
            return
        if pin != pin2:
            self._show_reg_error("PIN'ler eşleşmiyor.")
            return

        new_hwid = get_usb_hwid()
        if new_hwid is None:
            self._show_reg_error("USB tespit edilemedi.")
            return

        db = DBManager()
        if db.fetchone("SELECT id FROM users WHERE username = ?", (username,)):
            self._show_reg_error("Bu kullanıcı adı zaten alınmış.")
            return

        try:
            create_vault(new_hwid, pin, role)
        except Exception as exc:
            self._show_reg_error(f"Vault oluşturulamadı: {exc}")
            return

        db_role = "admin" if role == "Yönetici" else "user"
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role, status, hwid) "
                "VALUES (?, ?, ?, 'pending', ?)",
                (username, _PH.hash(pin), db_role, new_hwid),
            )
            db.log(
                "user_registered",
                detail=f"username={username} hwid={new_hwid} role={role}",
            )
        except Exception as exc:
            self._show_reg_error(f"Veritabanı hatası: {exc}")
            return

        self._reg_btn.setEnabled(False)
        self._reg_pending.show()

    def _apply_lockout(self, state: LockState) -> None:
        """
        Süreli kilidi uygular: alanları kapatır, kalan süreyi saniye saniye gösterir.

        Eski davranış kalıcı kilitti ("uygulamayı yeniden başlatın") — ama sayaç
        bellekte olduğu için yeniden başlatmak kilidi tamamen kaldırıyordu, yani
        koruma değil sadece rahatsızlıktı. Artık sayaç DB'de ve kilit süreli.
        """
        self._locked_out = True
        self._pin_input.setEnabled(False)
        self._totp_input.setEnabled(False)
        self._login_btn.setEnabled(False)
        self._show_error(state.message())

        if self._lock_timer is None:
            self._lock_timer = QTimer(self)
            self._lock_timer.setInterval(1000)
            self._lock_timer.timeout.connect(self._tick_lockout)
        self._lock_timer.start()

    def _tick_lockout(self) -> None:
        """Her saniye kalan süreyi tazeler; süre dolunca girişi geri açar."""
        state = rate_limit.check(DBManager(), self._rl_key())
        if state.locked:
            self._show_error(state.message())
            return

        if self._lock_timer is not None:
            self._lock_timer.stop()
        self._locked_out = False
        self._pin_input.setEnabled(True)
        self._totp_input.setEnabled(True)
        self._login_btn.setEnabled(True)
        self._show_error("")
        self._pin_input.setFocus()

    def _rl_key(self) -> str:
        """Rate limit anahtarı — giriş ekranı kullanıcı adı değil HWID bazlıdır."""
        return self._hwid or "<no-hwid>"

    def _show_error(self, msg: str) -> None:
        if msg:
            self._error_label.setText(msg)
            self._error_label.show()
        else:
            self._error_label.hide()

    def _show_reg_error(self, msg: str) -> None:
        if msg:
            self._reg_error.setText(msg)
            self._reg_error.show()
        else:
            self._reg_error.hide()
