"""HYCLEUS — Giriş & Kayıt Diyaloğu"""
from __future__ import annotations

import json
import logging
import os
import sys
from io import BytesIO

_log = logging.getLogger("hycleus.login")

import pyotp
import qrcode
import qrcode.constants
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from PySide6.QtCore import QPoint, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPalette, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QComboBox,
    QDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from CORE.app_mode import BIREYSEL, KURUMSAL, get_app_mode, set_app_mode
from CORE.referans_id import generate_referans_id, get_referans_id, set_referans_id
from CORE.registration import (
    HwidAlreadyRegisteredError,
    UsernameTakenError,
    register_new_user,
)
from CORE.usb_manager import get_usb_hwid
from CORE.version import surum_etiketi
from UI.totp_enrollment import show_totp_enrollment_dialog
from CORE.vault_manager import (
    USBAuthError,
    VaultTamperedError,
    create_vault,
    open_vault,
)
from DB.db_manager import DBManager

# ── Paths / constants ─────────────────────────────────────────────────────────

from CORE.paths import data_dir as _data_dir
from CORE import rate_limit
from CORE.pin_policy import LOGIN_MIN_LEN, PIN_MAX_LEN, PIN_MIN_LEN, validate_new_pin
from CORE.pin_rotation import yenileme_gerekli
from CORE.session_user import (
    kullanici_bilgisi,
    sistem_kurulmus_mu,
    tekil_hwid_satiri,
)
from CORE.rate_limit import LockState
from CORE.secret_store import (
    load_totp_secret,
    load_totp_secret_for_hwid,
    store_totp_secret,
    store_totp_secret_for_hwid,
)
from UI.main_window_palette import _ABYSSAL_BLUE as _LT

_PIN_FILE    = _data_dir() / "pin_hash.json"
_VAULT_PATH  = _data_dir() / ".hcl_vault"
_APP_NAME    = "HYCLEUS"
_TOTP_LEN    = 6
# Deneme sınırı ve kilit süreleri CORE/rate_limit.py'de — sayaç DB'de tutulur

# İki-sütunlu düzen (2026-08-26): sol marka paneli sabit genişlik, sağ
# sütun (form) eskisiyle AYNI genişlik (`w` parametresi _init_card'a hâlâ
# bunu taşıyor) — içindeki hiçbir margin/genişlik matematiği değişmedi,
# yalnızca kartın TOPLAM genişliğine bu kadar eklendi.
_SOL_PANEL_W = 380

_PH = PasswordHasher()

_SETUP_ROLES = [
    ("Yönetici",    "Tam erişim"),
    ("Standart",    "Dosya yönetimi"),
    ("Salt Okunur", "Sadece görüntüleme"),
]

# ── Shared QSS fragments ───────────────────────────────────────────────────────
#
# Arayüz güncellemesi (2026-08-26): oturum öncesi bu diyaloğun `self._T`'si
# YOK — HycleusWindow henüz kurulmadı. Mockup'ın donanım-temalı koyu
# görünümüne yaklaştırmak için sabit bir palet seçildi: `_ABYSSAL_BLUE` — icat edilmiş
# yeni bir renk kümesi değil, kayıtlı preset'lerden biri (bkz.
# UI/main_window_palette.py). Kullanıcının oturum-içi tema tercihini OKUMAYA
# ÇALIŞMADI: bu, kapsamın dışında yeni bir özellik (kalıcı tercihin oturum
# öncesine taşınması) olurdu, salt görsel bir renk değişikliği değil.

# Input: borderless, only bottom rule, min-height 48px
_QSS_INPUT = (
    "QLineEdit {"
    "  background: transparent;"
    f"  color: {_LT['text']};"
    "  border: none;"
    f"  border-bottom: 2px solid {_LT['border']};"
    "  border-radius: 0px;"
    "  padding: 8px 0px;"
    "  font-size: 15px;"
    "  min-height: 48px;"
    "}"
    "QLineEdit:focus {"
    f"  border-bottom: 2px solid {_LT['accent']};"
    "}"
    "QLineEdit:disabled {"
    f"  color: {_LT['subtext']};"
    f"  border-bottom: 2px solid {_LT['border']};"
    "}"
)

_QSS_COMBO = (
    "QComboBox {"
    "  background: transparent;"
    f"  color: {_LT['text']};"
    "  border: none;"
    f"  border-bottom: 2px solid {_LT['border']};"
    "  border-radius: 0px;"
    "  padding: 8px 0px;"
    "  font-size: 15px;"
    "  min-height: 48px;"
    "}"
    f"QComboBox:focus {{ border-bottom: 2px solid {_LT['accent']}; }}"
    "QComboBox::drop-down { border: none; width: 28px; }"
    "QComboBox QAbstractItemView {"
    f"  background: {_LT['search_bg']};"
    f"  color: {_LT['text']};"
    f"  border: 1px solid {_LT['border']};"
    "  outline: none;"
    f"  selection-background-color: {_LT['hover']};"
    f"  selection-color: {_LT['accent']};"
    "}"
)

_QSS_BTN_PRIMARY = (
    "QPushButton {"
    f"  background: {_LT['accent']};"
    f"  color: {_LT['on_accent']};"
    "  border: none;"
    "  border-radius: 10px;"
    "  font-size: 15px;"
    "  font-weight: 600;"
    "  min-height: 48px;"
    "}"
    f"QPushButton:hover   {{ background: {_LT['accent_hover']}; }}"
    f"QPushButton:pressed {{ background: {_LT['accent_hover']}; }}"
    f"QPushButton:disabled {{ background: {_LT['hover']}; color: {_LT['subtext']}; }}"
)

_QSS_TAB_ON = (
    "QPushButton {"
    "  background: transparent;"
    f"  color: {_LT['accent']};"
    "  border: none;"
    f"  border-bottom: 2px solid {_LT['accent']};"
    "  border-radius: 0px;"
    "  font-size: 14px;"
    "  font-weight: 600;"
    "  padding-bottom: 4px;"
    "}"
)
_QSS_TAB_OFF = (
    "QPushButton {"
    "  background: transparent;"
    f"  color: {_LT['subtext']};"
    "  border: none;"
    "  border-bottom: 2px solid transparent;"
    "  border-radius: 0px;"
    "  font-size: 14px;"
    "  padding-bottom: 4px;"
    "}"
    f"QPushButton:hover {{ color: {_LT['text']}; }}"
)

_QSS_RADIO = (
    "QRadioButton {"
    f"  color: {_LT['text']};"
    "  font-size: 13px;"
    "  background: transparent;"
    "  spacing: 6px;"
    "}"
    "QRadioButton::indicator {"
    "  width: 16px; height: 16px;"
    f"  border: 2px solid {_LT['border']};"
    "  border-radius: 8px;"
    f"  background: {_LT['search_bg']};"
    "}"
    "QRadioButton::indicator:checked {"
    f"  background: {_LT['accent']};"
    f"  border-color: {_LT['accent']};"
    "}"
)

_PLACEHOLDER_COLOR = QColor(_LT["subtext"])


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


def _lbl(text: str, size: int = 12, color: str = _LT["subtext"],
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
    f.setStyleSheet(f"QFrame{{background:{_LT['border']};max-height:1px;border:none;}}")
    return f


_QSS_PIN_BOX = (
    "QLineEdit {"
    f"  background: {_LT['topbar']};"
    f"  color: {_LT['text']};"
    f"  border: 2px solid {_LT['border']};"
    "  border-radius: 8px;"
    "  font-size: 20px;"
    "}"
    "QLineEdit:focus {"
    f"  border: 2px solid {_LT['accent']};"
    "}"
    "QLineEdit:disabled {"
    f"  color: {_LT['subtext']};"
    f"  border: 2px solid {_LT['border']};"
    "}"
)


class _PinDigitBox(QLineEdit):
    """
    Tek bir PIN kutucuğu. Yapıştırma (paste) ile gelen BİRDEN FAZLA
    karakteri KENDİSİ işlemez — `paste()` (Ctrl+V VE sağ tık bağlam
    menüsündeki "Yapıştır" için ortak Qt kancası — `QLineEdit`'te
    `insertFromMimeData` YOKTUR, o yalnızca `QTextEdit` ailesinde
    vardır) bunu yakalayıp üst widget'a (`_PinBoxInput`) devreder,
    çünkü `maxLength(1)` olan bir kutuya normal yoldan yapıştırma
    yapılırsa Qt sessizce ilk karakter DIŞINDAKİ HER ŞEYİ atar — 6
    haneli bir PIN'in otomatik dağıtılması bu yakalama olmadan mümkün
    değil.
    """

    def __init__(self, ust: "_PinBoxInput", index: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._ust = ust
        self._index = index

    def paste(self) -> None:
        metin = QApplication.clipboard().text().strip()
        if len(metin) > 1:
            self._ust._yapistir(metin)
            return
        super().paste()

    def keyPressEvent(self, event) -> None:  # type: ignore[override]
        if event.key() == Qt.Key_Backspace and not self.text():
            self._ust._onceki_kutuya_gec(self._index)
            return
        super().keyPressEvent(event)


class _PinBoxInput(QWidget):
    """
    Altı kutucuklu PIN girişi (giriş ekranı, mockup'a uygun).

    KRİTİK UYUMLULUK NOTU: `CORE/pin_policy.py` PIN'in tam olarak 6
    hane ya da yalnızca rakam olacağını HİÇBİR ZAMAN garanti etmez —
    `LOGIN_MIN_LEN=4` eski (6 hane politikasından önce kaydolmuş)
    kullanıcıları kasıtlı olarak kabul eder ve rakam-dışı karakterler
    için hiçbir kısıtlama yoktur (yalnızca Authenticator kodu
    `isdigit()` ile denetlenir, PIN değil). Bu yüzden kutucuklar
    karakter sınıfını KISITLAMAZ (harf/sembol içeren eski PIN'ler
    çalışmaya devam eder) ve SONUNCU kutucuk taşabilir: 6. karakterden
    sonrası da oraya yazılır.

    DÜZELTME (B-095 devam): `PIN_MAX_LEN`in "GUI akışlarında hiç
    zorlanmadığı" iddiası bu widget için YANLIŞTIR ve önceki bir turda
    yanlışlıkla belgelenmişti — aşağıdaki satır `CORE.pin_policy.
    PIN_MAX_LEN`i DOĞRUDAN ithal edip son kutunun `setMaxLength()`'ine
    veriyor (ayrı, elle yazılmış bir `32` sabiti YOK — `tests/
    test_pin_giris_kutulari.py::test_son_kutunun_pin_max_len_ile_
    CANLI_baglantisi` bunu monkeypatch ile KANITLIYOR). Sonuç: bu
    widget toplam `5 + PIN_MAX_LEN` (bugün 37) karakterden UZUN bir
    PIN'i FİZİKSEL OLARAK TUTAMAZ — `validate_new_pin()` hâlâ üst sınır
    KONTROL ETMEDİĞİ için, teorik olarak bu sınırdan uzun bir PIN'i
    olan (varsa) bir kullanıcı bu ekrandan giriş YAPAMAZ. Kabul edilen,
    dar bir ödünleşim: `PIN_MIN_LEN=4`ün koruduğu KISA/eski PIN'lerin
    aksine, bu ölçüde UZUN bir PIN'in gerçekte var olması aşırı
    olası değil, ve sınırsız bir metin kutusu tutmak mockup'ın "6 kutu"
    tasarımıyla ZATEN uyumsuz olurdu.

    Yapıştırma davranışı: herhangi bir kutuya birden fazla karakter
    yapıştırılırsa TÜM kutular temizlenir ve yapıştırılan metin BAŞTAN
    (1. kutudan) dağıtılır — kullanıcı "6 haneli PIN'i tek seferde
    yapıştırırsa" tamamının ilk kutudan başlayarak yerleşmesini bekler,
    hangi kutu o an odaktaysa fark etmez.
    """

    textChanged = Signal(str)
    returnPressed = Signal()

    _KUTU_SAYISI = 6

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setStyleSheet("background:transparent;")
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self._kutular: list[_PinDigitBox] = []

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        for i in range(self._KUTU_SAYISI):
            kutu = _PinDigitBox(self, i)
            # Sonuncu kutucuk taşan karakterleri de kabul eder (bkz. sınıf docstring'i).
            kutu.setMaxLength(1 if i < self._KUTU_SAYISI - 1 else PIN_MAX_LEN)
            kutu.setEchoMode(QLineEdit.Password)
            kutu.setAlignment(Qt.AlignCenter)
            kutu.setFixedSize(44, 52)
            kutu.setStyleSheet(_QSS_PIN_BOX)
            kutu.textChanged.connect(lambda _txt, idx=i: self._kutu_degisti(idx))
            kutu.returnPressed.connect(self.returnPressed.emit)
            self._kutular.append(kutu)
            lay.addWidget(kutu)

    def _kutu_degisti(self, index: int) -> None:
        kutu = self._kutular[index]
        if index < self._KUTU_SAYISI - 1 and len(kutu.text()) >= 1:
            self._kutular[index + 1].setFocus()
        self.textChanged.emit(self.text())

    def _onceki_kutuya_gec(self, index: int) -> None:
        if index > 0:
            onceki = self._kutular[index - 1]
            onceki.setFocus()
            onceki.setCursorPosition(len(onceki.text()))

    def _dagit(self, metin: str) -> None:
        """Bir dizeyi kutulara böler — hem yapıştırma hem `setText()` bunu kullanır."""
        for kutu in self._kutular:
            kutu.blockSignals(True)
            kutu.clear()
        for i, kutu in enumerate(self._kutular[:-1]):
            if i < len(metin):
                kutu.setText(metin[i])
        son = self._kutular[-1]
        if len(metin) >= self._KUTU_SAYISI:
            son.setText(metin[self._KUTU_SAYISI - 1:])
        for kutu in self._kutular:
            kutu.blockSignals(False)
        self.textChanged.emit(self.text())

    def _yapistir(self, metin: str) -> None:
        self._dagit(metin)
        odak_index = min(len(metin), self._KUTU_SAYISI - 1)
        odak_kutu = self._kutular[odak_index]
        odak_kutu.setFocus()
        odak_kutu.setCursorPosition(len(odak_kutu.text()))

    def text(self) -> str:
        return "".join(k.text() for k in self._kutular)

    def setText(self, text: str) -> None:  # type: ignore[override]
        """
        Programatik atama (ör. testler, gelecekteki bir otomatik-doldurma).
        Yapıştırmadan FARKLI olarak odağı DEĞİŞTİRMEZ — `QLineEdit.setText()`nin
        de yapmadığı gibi.
        """
        self._dagit(text)

    def setFocus(self) -> None:  # type: ignore[override]
        self._kutular[0].setFocus()

    def clear(self) -> None:
        for kutu in self._kutular:
            kutu.blockSignals(True)
            kutu.clear()
            kutu.blockSignals(False)
        self.textChanged.emit("")


# ── Dialog ─────────────────────────────────────────────────────────────────────

class LoginDialog(QDialog):
    # `_pin_input`in giriş sayfasında `_PinBoxInput` (bu turda eklendi), kurulum
    # sihirbazı sayfasında ise düz `QLineEdit` olması gerekiyor — iki sayfa
    # karşılıklı DIŞLAYICI (bkz. modül docstring'i), ama aynı sınıfın aynı
    # özniteliği olduğundan mypy'nin ikisini de kabul etmesi için açık Union.
    _pin_input: QLineEdit | "_PinBoxInput"

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

        # B-059: TOTP sırrı artık HWID başına (paylaşılan/global DEĞİL).
        # DEV_MODE'un kasa öncesi yolu (`not self._use_vault`) istisna:
        # RBAC/çok-kullanıcı tehdit modelinin parçası değil, tek operatörlü
        # geliştirme senaryosu — orada hâlâ global sır kullanılıyor.
        if self._use_vault and hwid:
            secret = load_totp_secret_for_hwid(hwid)
        else:
            secret = _load_secret()

        # first_run: main.py'den gelir; yoksa hesapla
        #
        # B-058 kök neden düzeltmesi: vault dalı artık "bu HWID'nin vault'u
        # var mı" DEĞİL, "sistemde onaylı en az bir kullanıcı var mı"
        # soruyor (main.py'deki gerçek karar noktasıyla AYNI fonksiyon —
        # `CORE.session_user.sistem_kurulmus_mu`, tek kaynak). Eski soru
        # HWID başınaydı ve daha önce hiç görülmemiş her USB'yi "sistem hiç
        # kurulmamış" sanıp İlk Kurulum sihirbazını (serbest rol seçimi,
        # onaysız doğrudan 'approved' yazımı) yeniden açıyordu.
        if first_run is not None:
            _first_run = first_run
        elif self._use_vault:
            _first_run = not sistem_kurulmus_mu(DBManager())
        else:
            _first_run = secret is None or _load_pin_hash() is None

        if _first_run:
            self._secret = pyotp.random_base32()
            self._init_card(640, 760)
            self._build_setup_ui()
        else:
            if not self._use_vault:
                # Tip daraltma; güvenlik kontrolü değil (mypy None'ı burada eliyor).
                assert secret is not None  # nosec B101
            # Vault yolunda `secret` None OLABİLİR (B-059): bu HWID hiç
            # enroll olmamış -- göç öncesi onaylı bir kullanıcı ya da eski
            # bir kayıt. `_on_login()` bunu ayrı, açık bir mesajla ele alıyor.
            self._secret = secret
            self._init_card(640, 720)
            self._build_main_ui()

    @property
    def role(self) -> str:
        return self._role

    # ── Card / window ─────────────────────────────────────────────────────
    #
    # İki-sütunlu düzen (2026-08-26, mockup): kart artık TEK bir
    # QVBoxLayout değil, yatayda ikiye bölünmüş — sol sabit-genişlik marka
    # paneli (`_sol_panel`, tamamen statik metin) + sağ `_sag_govde`
    # (içine `_build_main_ui`/`_build_setup_ui`'nin AYNI kod yolu
    # yerleşiyor, `self._card` yerine `self._sag_govde`'ye). Bu ayrım
    # yalnızca YERLEŞİM: hiçbir widget adı, sinyal bağlantısı ya da iş
    # mantığı fonksiyonu değişmedi — bkz. B-058/B-060/B-061/B-065/B-067
    # testleri, hepsi bu dosyanın davranışını kilitliyor.
    #
    # Köşe yuvarlaklığı: `self._card` (QFrame) kendi arka planını/
    # border-radius'unu boyuyor; sol panel şeffaf kalıp o rengi olduğu
    # gibi gösteriyor (dosyadaki mevcut kural — header/tab_wrap/stack de
    # hep "background:transparent"). Sağ taraf FARKLI (biraz daha açık)
    # bir yüzey rengi istediği için ayrı bir QFrame — yalnızca SAĞ iki
    # köşesi yuvarlatılmış, sol kenarı kartın içinde, görünmeyen bir
    # dikişte kalıyor.

    def _init_card(self, w: int, h: int) -> None:
        total_w = w + _SOL_PANEL_W
        self.setFixedSize(total_w + 20, h + 20)

        # NOT: seçiciler `QFrame{...}` DEĞİL, `QFrame#adı{...}` — bare
        # tip seçicisi Qt'de QLabel'a (QFrame'in alt sınıfı) KASKAD EDER
        # ve her etikete istenmeyen bir border/border-radius bulaştırır.
        # Nesne-adı seçicisi bu kaskadı keser (yalnızca bu widget'a bağlar).
        self._card = QFrame(self)
        self._card.setObjectName("hycleus_login_card")
        self._card.setGeometry(10, 10, total_w, h)
        self._card.setStyleSheet(
            f"QFrame#hycleus_login_card{{background:{_LT['bg']};"
            f"border:1px solid {_LT['border']};border-radius:14px;}}"
        )

        eff = QGraphicsDropShadowEffect(self)
        eff.setBlurRadius(28)
        eff.setOffset(0, 6)
        eff.setColor(QColor(0, 0, 0, 30))
        self._card.setGraphicsEffect(eff)

        card_lay = QHBoxLayout(self._card)
        card_lay.setContentsMargins(0, 0, 0, 0)
        card_lay.setSpacing(0)
        card_lay.addWidget(self._sol_panel())

        self._sag_govde = QFrame()
        self._sag_govde.setObjectName("hycleus_login_sag")
        self._sag_govde.setStyleSheet(
            f"QFrame#hycleus_login_sag{{background:{_LT['sidebar']};border:none;"
            f"border-top-right-radius:14px;border-bottom-right-radius:14px;}}"
        )
        card_lay.addWidget(self._sag_govde, 1)

    def _sol_panel(self) -> QWidget:
        """Marka/özellik paneli — Giriş/Kayıt Ol/İlk Kurulum'un ortak sol sütunu.

        Tamamen statik metin: hiçbir widget veri bağlamıyor, hiçbir DB
        çağrısı ya da doğrulama mantığı yok. Buradaki üç madde
        (AES-256-GCM, Shamir 2-of-3, HWID kilidi) ve alt bilgi (Argon2id,
        TOTP RFC 6238) uydurulmadı — SECURITY.md'de belgelenen gerçek
        özellikler, mockup'ın metni olduğu gibi buraya taşındı.
        """
        panel = QWidget()
        panel.setFixedWidth(_SOL_PANEL_W)
        panel.setStyleSheet("background:transparent;")
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(40, 40, 32, 32)
        lay.setSpacing(0)

        # Mockup'ın ağ-erişimi-yok rozeti BİLEREK YOK — doğrulanmamış bir
        # mimari iddia, SECURITY.md'yle çelişiyordu (bkz. §M1: zaman damgası
        # otoritesi gibi ağ üzerinden ulaşılan gerçek bir tehdit yüzeyi
        # var). Aynı gerekçe UI/main_window_palette.py'de _AURORA_BOREALIS
        # üstündeki yorumda da kayıtlı — buraya da BİLEREK taşınmadı. (Bu
        # yorumun kendisi de rozetin metnini YAZMAZ — tests/test_login_
        # dogrulanmamis_iddia.py'nin banned-text taraması, açıklarken
        # tekrar sızdırmayı önlemek için tam da bunu kontrol ediyor.)
        rozet = _lbl(surum_etiketi(), size=11, color=_LT["subtext"])
        lay.addWidget(rozet)
        lay.addSpacing(40)

        baslik = QLabel("Donanıma\nbağlı kasa.")
        baslik.setStyleSheet(
            f"color:{_LT['text']};font-size:26px;font-weight:700;background:transparent;"
        )
        lay.addWidget(baslik)
        lay.addSpacing(28)

        for ozellik in (
            "AES-256-GCM Mühürlü",
            "Shamir 2-of-3 Paylaşımı",
            "USB HWID Kilit Mekanizması",
        ):
            satir = QHBoxLayout()
            satir.setSpacing(8)
            tik = QLabel("✓")
            tik.setFixedWidth(16)
            tik.setStyleSheet(
                f"color:{_LT['accent']};font-size:13px;font-weight:700;background:transparent;"
            )
            satir.addWidget(tik)
            satir.addWidget(_lbl(ozellik, size=13, color=_LT["text"]))
            satir.addStretch()
            lay.addLayout(satir)
            lay.addSpacing(10)

        lay.addStretch(1)

        alt_bilgi = _lbl(
            "Argon2id · TOTP RFC 6238 · Yerel Bellek İzolasyonu",
            size=10, color=_LT["subtext"],
        )
        alt_bilgi.setWordWrap(True)
        lay.addWidget(alt_bilgi)

        return panel

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
        root = QVBoxLayout(self._sag_govde)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ──────────────────────────────────────────────────────
        header = QWidget()
        header.setStyleSheet("background:transparent;")
        h_lay = QVBoxLayout(header)
        h_lay.setContentsMargins(48, 44, 48, 0)
        h_lay.setSpacing(0)

        title = _lbl("HYCLEUS", size=30, color=_LT["text"], bold=True)
        title.setAlignment(Qt.AlignCenter)
        h_lay.addWidget(title)

        sub = _lbl("Güvenli Dosya Yönetim Sistemi", size=14, color=_LT["subtext"])
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

        # ── Sürüm etiketi ───────────────────────────────────────────────
        #
        # CORE.version.surum_etiketi()'ten okunuyor — elle yazılmamalı
        # (bkz. B-017, tests/test_version.py). Alt köşede, küçük ve gri:
        # bilgi amaçlı, dikkat çekmemesi gerekiyor.
        self._surum_etiketi = _lbl(surum_etiketi(), size=10, color=_LT["border"])
        self._surum_etiketi.setAlignment(Qt.AlignCenter)
        self._surum_etiketi.setContentsMargins(0, 4, 0, 10)
        root.addWidget(self._surum_etiketi)

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
            dot.setStyleSheet(f"color:{_LT['green']};font-size:14px;background:transparent;")
            usb_txt = _lbl("USB Bağlı",    size=13, color=_LT["green"])
        else:
            dot.setStyleSheet(f"color:{_LT['red']};font-size:14px;background:transparent;")
            usb_txt = _lbl("USB Gerekli",  size=13, color=_LT["red"])
        usb_row.addWidget(dot)
        usb_row.addWidget(usb_txt)
        usb_row.addStretch()
        lay.addLayout(usb_row)
        lay.addSpacing(28)

        # PIN field
        # Giriş ekranı: burada uzunluk ipucu verilmez — yeni politika 6 hane
        # ama eski 4-5 haneli PIN'ler hâlâ geçerli, "en az 6" yazmak yanıltıcı olurdu.
        self._pin_input = _PinBoxInput()
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
            f"color:{_LT['red']};font-size:13px;background:transparent;"
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
            f"  background:{_LT['search_bg']};width:6px;border-radius:3px;}}"
            "QScrollBar::handle:vertical{"
            f"  background:{_LT['border']};border-radius:3px;min-height:24px;}}"
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
            f"  background:{_LT['accent_tint']};"
            "  border:none;"
            "  border-radius:10px;"
            "}"
        )
        info_lay = QVBoxLayout(info)
        info_lay.setContentsMargins(16, 12, 16, 12)
        info_lay.setSpacing(0)
        info_lbl = QLabel("Kayıt için Yönetici USB'si takılı olmalıdır")
        info_lbl.setStyleSheet(
            f"color:{_LT['accent']};font-size:13px;background:transparent;border:none;"
        )
        info_lbl.setWordWrap(True)
        info_lay.addWidget(info_lbl)
        lay.addWidget(info)
        lay.addSpacing(24)

        # ── Admin USB status field ────────────────────────────────────────
        current = get_usb_hwid()
        if current == self._hwid and self._hwid is not None:
            usb_val = _lbl("● Bağlı",     size=15, color=_LT["green"])
        else:
            usb_val  = _lbl("● Bekleniyor", size=15, color=_LT["yellow"])
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

        # ── Talep Edilen Rol ─────────────────────────────────────────────────
        # Etiket 2026-08-29'da "Rol"den değiştirildi (bkz. BACKLOG B-076).
        # Backend zaten TAM olarak bunu yapıyordu — `register_new_user()`
        # bu seçimi `status='pending'` bir satıra yazıyor, GERÇEK yetkiye
        # yönetici `AdminPanel`'in "Bekleyen Kayıtlar" sekmesinden onay
        # verene kadar dönüşmüyor (bkz. CORE/registration.py). Yeni bir
        # `requested_role` sütunu EKLENMEDİ — mevcut `role` sütunu zaten bu
        # semantiği taşıyor, ikinci bir sütun yalnızca aynı bilgiyi iki
        # kopya hâlinde tutup senkronizasyon/kaynak-otorite belirsizliği
        # yaratırdı. Bu yüzden yalnızca etiket değişti, şema değişmedi.
        # `UI/RegisterDialog.py`nin admin-başlatan akışında etiket KASITLI
        # olarak "Rol" kaldı — orada yöneticinin KENDİSİ seçiyor, "talep"
        # kelimesi kafa karıştırırdı.
        self._reg_role = QComboBox()
        self._reg_role.addItems(["Standart", "Salt Okunur"])
        self._reg_role.setStyleSheet(_QSS_COMBO)
        self._reg_role.setMinimumHeight(48)
        lay.addWidget(_field("Talep Edilen Rol", self._reg_role))
        lay.addSpacing(20)

        # ── Referans Kodu — YALNIZCA Kurumsal modda ─────────────────────────
        # Bireysel modda bu alan hiç YOK (widget bile oluşturulmuyor) —
        # `_on_register` bunu `getattr(self, "_reg_referans", None)` ile
        # kontrol ediyor. E-posta/plan-tier alanları EKLENMEDİ — o karar
        # değişmedi (bkz. BACKLOG, 077159e). Bu alan `_on_register`'da
        # `CORE.referans_id.get_referans_id()` ile GERÇEKTEN karşılaştırılır.
        self._reg_referans = None
        if get_app_mode(DBManager()) == KURUMSAL:
            self._reg_referans = _make_input("İlk Kurulum'da üretilen kod (KRM-...)")
            lay.addWidget(_field("Referans Kodu", self._reg_referans))
            lay.addSpacing(12)

        lay.addSpacing(12)

        # ── Error / pending feedback ──────────────────────────────────────
        self._reg_error = QLabel("")
        self._reg_error.setAlignment(Qt.AlignCenter)
        self._reg_error.setWordWrap(True)
        self._reg_error.setStyleSheet(
            f"color:{_LT['red']};font-size:13px;background:transparent;"
        )
        self._reg_error.hide()
        lay.addWidget(self._reg_error)

        self._reg_pending = QLabel("Yönetici onayı bekleniyor...")
        self._reg_pending.setAlignment(Qt.AlignCenter)
        self._reg_pending.setStyleSheet(
            f"color:{_LT['green']};font-size:13px;background:transparent;"
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
        root = QVBoxLayout(self._sag_govde)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        header = QWidget()
        header.setStyleSheet("background:transparent;")
        h_lay = QVBoxLayout(header)
        h_lay.setContentsMargins(48, 44, 48, 0)
        h_lay.setSpacing(0)

        title_lbl = _lbl("İlk Kurulum", size=30, color=_LT["text"], bold=True)
        title_lbl.setAlignment(Qt.AlignCenter)
        h_lay.addWidget(title_lbl)

        sub = _lbl("Rol, PIN ve Authenticator ayarlarını yapın", size=14, color=_LT["subtext"])
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
            f"QScrollBar:vertical{{background:{_LT['search_bg']};width:6px;border-radius:3px;}}"
            f"QScrollBar::handle:vertical{{background:{_LT['border']};border-radius:3px;min-height:24px;}}"
            "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}"
        )

        inner = QWidget()
        inner.setStyleSheet("background:transparent;")
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(48, 32, 48, 40)
        lay.setSpacing(0)

        # ── Görünüm modu (Bireysel/Kurumsal) ────────────────────────────────
        # Mockup'ta bu ekranda yok — bizim kararımız (bkz. CORE/app_mode.py).
        # Mockup'ın kendisinde adım sayaçlı bir sihirbaz görünüyordu ama
        # gerçek kodda öyle bir yapı hiç yok (tek, sürekli kaydırılan form)
        # — bu yüzden yeni bir "adım" değil, formun en başına yeni bir bölüm
        # olarak eklendi: en temel karar, rol seçiminden bile önce gelir.
        mode_lbl = _lbl("Görünüm Modu", size=12, color=_LT["subtext"])
        lay.addWidget(mode_lbl)
        lay.addSpacing(10)

        self._mode_group = QButtonGroup(self)
        _MODE_SECENEKLERI = (
            (KURUMSAL, "Kurumsal", "Birden çok kullanıcı, onay akışı, Referans ID"),
            (BIREYSEL, "Bireysel", "Tek kullanıcı, sade görünüm"),
        )
        for i, (mval, mname, mdesc) in enumerate(_MODE_SECENEKLERI):
            rb = QRadioButton(f"{mname}  ·  {mdesc}")
            rb.setProperty("mode_value", mval)
            rb.setStyleSheet(_QSS_RADIO)
            if i == 0:
                rb.setChecked(True)
            self._mode_group.addButton(rb)
            lay.addWidget(rb)
            lay.addSpacing(6)
        lay.addSpacing(14)

        # Role selection
        role_lbl = _lbl("Rol", size=12, color=_LT["subtext"])
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
                        size=13, color=_LT["subtext"])
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
            f"color:{_LT['subtext']};font-size:10px;font-family:monospace;background:transparent;"
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
            f"color:{_LT['red']};font-size:13px;background:transparent;"
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
        # Savunma derinliği (B-058): bu fonksiyon rolü SERBEST seçtirip
        # doğrudan 'approved' bir kullanıcı üretiyor (`main.py`'nin
        # `dialog.exec()` sonrası çağırdığı `sync_session_user()` ile) —
        # tam olarak kapatılan güvenlik açığının kendisi. `__init__`'teki
        # `_first_run` hesabı bunu zaten engellemeli; burası o hesabın
        # bir yerde atlanması İHTİMALİNE karşı — sessizce ikinci bir
        # onaysız admin üretmek yerine GÖRÜNÜR biçimde patlıyor.
        if self._use_vault and sistem_kurulmus_mu(DBManager()):
            raise RuntimeError(
                "İlk Kurulum sihirbazı, sistemde zaten onaylı bir kullanıcı "
                "varken çağrıldı (B-058) — _first_run hesaplaması bir yerde "
                "bu kontrolü atlamış olmalı. Onaysız ikinci bir 'approved' "
                "kullanıcı ÜRETİLMEDİ."
            )

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

        mode_btn = self._mode_group.checkedButton()
        mode = mode_btn.property("mode_value") if mode_btn is not None else KURUMSAL

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
            # B-059: TOTP sırrı HWID başına saklanır, global DEĞİL.
            try:
                store_totp_secret_for_hwid(self._hwid, self._secret)
            except Exception as exc:
                self._show_error(f"TOTP sırrı kaydedilemedi: {exc}")
                return
            # Görünüm modu + (Kurumsal'sa) Referans ID — settings tablosuna
            # kalıcı, users satırına DEĞİL (bkz. CORE/app_mode.py,
            # CORE/referans_id.py — kurulum-geneli tek değerler).
            try:
                db = DBManager()
                set_app_mode(db, mode, hwid=self._hwid)
                referans_id = None
                if mode == KURUMSAL:
                    referans_id = generate_referans_id()
                    set_referans_id(db, referans_id)
            except Exception as exc:
                self._show_error(f"Kurulum ayarları kaydedilemedi: {exc}")
                return
            if referans_id is not None:
                self._show_referans_id_dialog(referans_id)
        else:
            _save_pin_hash(pin, role)
            _save_secret(self._secret)
        self._role = role
        self.accept()

    def _show_referans_id_dialog(self, referans_id: str) -> None:
        """Kurumsal Referans ID'yi ekranda gösterir — kopyalanabilir.

        Kayıt Ol ekranındaki Referans Kodu alanı bununla GERÇEKTEN
        karşılaştırılacak (bkz. `_on_register`) — bu yüzden yalnızca bir
        kez gösterilip unutulacak bir metin değil, kullanıcı bunu fiilen
        saklamalı.
        """
        kutu = QMessageBox(self)
        kutu.setIcon(QMessageBox.Information)
        kutu.setWindowTitle("Kurumsal Referans ID")
        kutu.setText(
            "Kurulum tamamlandı. Bu Referans ID, ekibinizin \"Kayıt Ol\" "
            "ekranında kullanacağı doğrulama kodudur — güvenli bir yerde "
            "saklayın:\n\n" + referans_id
        )
        for lbl in kutu.findChildren(QLabel):
            lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        kopyala = kutu.addButton("Kopyala", QMessageBox.ActionRole)
        tamam = kutu.addButton("Tamam", QMessageBox.AcceptRole)
        kutu.setDefaultButton(tamam)
        kutu.exec()
        if kutu.clickedButton() is kopyala:
            QApplication.clipboard().setText(referans_id)

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

        # B-059: `self._secret` None olabilir -- bu HWID hiç enroll olmamış
        # (göç öncesi onaylı bir kullanıcı ya da eski bir kayıt). pyotp.TOTP(None)
        # patlar; None'ı "kod hiçbir zaman doğrulanmaz" olarak ele alıyoruz.
        totp_ok = (
            self._secret is not None
            and pyotp.TOTP(self._secret).verify(code, valid_window=1)
        )

        if not pin_ok or not totp_ok:
            reason = f"pin_ok={pin_ok} totp_ok={totp_ok}"
            state = rate_limit.record_failure(DBManager(), self._rl_key(), detail=reason)
            if state.locked:
                self._apply_lockout(state)
                return
            if pin_ok and self._secret is None:
                # Ayrı ve açık mesaj (B-059): PIN doğru olduğu için bu HWID
                # zaten kimliği doğrulanmış -- "kod yanlış" demek yanıltıcı
                # olurdu, gerçek sorun bu USB'nin hiç TOTP kaydı olmaması.
                #
                # BİLİNÇLİ ÖDÜNLEŞİM: bu mesaj dolaylı olarak "PIN doğruydu"
                # bilgisini sızdırıyor (rate limit'e rağmen). Kabul edildi
                # çünkü saldırgan zaten fiziksel USB'ye sahip olmalı (uzaktan
                # saldırılabilir bir yüzey değil) VE bu tek başına GİRİŞ
                # SAĞLAMIYOR (totp_ok hâlâ False, fonksiyon burada dönüyor) —
                # yalnızca "PIN doğru" bilgisini biraz erken açığa çıkarıyor.
                # Karşılığında: bu geçici duruma (B-059 göçü sonrası yeniden
                # enrollment bekleyen meşru bir kullanıcı) düşen gerçek
                # kullanıcı neden giremediğini anlıyor, "kod yanlış" sanıp
                # sonsuza kadar denemiyor.
                self._show_error(
                    "Bu USB için authenticator kaydı bulunamadı — "
                    "yöneticinize başvurun."
                )
                return
            remaining = rate_limit.MAX_ATTEMPTS - state.fail_count
            suffix = f" ({remaining} deneme kaldı)" if remaining <= 2 else ""
            self._show_error(f"PIN veya Authenticator kodu hatalı{suffix}")
            return

        if self._hwid:
            row = tekil_hwid_satiri(DBManager(), self._hwid, "status")
            if row is not None and row["status"] == "pending":
                self._show_error("Hesabınız yönetici onayı bekliyor — giriş yapılamaz")
                return

        # ── B-003: kısa PIN'le girildiyse yenileme ZORUNLU ────────────────
        #
        # Tespit ancak BURADA yapılabiliyor: PIN'in uzunluğu Argon2id
        # hash'inden çıkarılamaz, düz metin yalnızca bu anda elde.
        #
        # ASIL KAPI BU BLOK — diyaloğun kapatılamaz olması bir
        # kullanılabilirlik tercihi. Yenileme başarılı olmadıkça
        # `accept()` çağrılmıyor, yani diyalog dışarıdan kapatılsa bile
        # kullanıcı içeri giremiyor.
        if not self._zorunlu_pin_yenileme(pin):
            return

        # Başarılı giriş sayacı sıfırlar ve audit log'a düşer
        rate_limit.record_success(DBManager(), self._rl_key())

        self._role = role
        _log.info(
            "login_result  hwid=%s  role=%s  session_key_len=%d",
            self._hwid, self._role, len(self.session_key) if self.session_key else 0,
        )
        self.accept()

    def _zorunlu_pin_yenileme(self, pin: str) -> bool:
        """Kısa PIN'i olan kullanıcıyı yenilemeye zorlar (B-003).

        Returns:
            True  — giriş sürebilir (PIN zaten uygun ya da yenilendi)
            False — giriş ENGELLENDİ; kullanıcı giriş ekranında kalıyor

        Kasa kullanılmayan yolda (DEV_MODE ve kasa öncesi kurulumlar)
        yenileme YAPILAMIYOR: `change_vault_pin()` bir kasa dosyası
        istiyor, o yolda ise PIN ayrı bir hash dosyasında duruyor.
        Girişi engellemek orada bir kilitlenme üretirdi — çıkış yolu
        olmayan bir zorunluluk. Durum kayda geçiyor; kalan boşluk
        BACKLOG'a yazıldı.
        """
        if not yenileme_gerekli(pin):
            return True

        if not (self._use_vault and self._hwid):
            _log.warning(
                "pin_rotation_skipped  kasa yok  hwid=%s  uzunluk=%d",
                self._hwid, len(pin),
            )
            return True

        from UI.PinRotationDialog import PinRotationDialog

        db = DBManager()
        # `users.id` girişte henüz eşlenmemiş olabilir
        # (`sync_session_user` main.py'de, bu diyalogdan SONRA çalışıyor).
        # Yan etkisiz arama: bulunursa `last_pin_changed` da güncellenir,
        # bulunmazsa denetim kaydı yine düşer.
        try:
            bilgi = kullanici_bilgisi(db, self._hwid)
        except Exception:
            bilgi = None

        dlg = PinRotationDialog(
            db=db, hwid=self._hwid, mevcut_pin=pin,
            user_id=bilgi[0] if bilgi else None, parent=self,
        )
        dlg.exec()

        if not dlg.rotated:
            # Diyalog kapatılamaz olsa da pencere yöneticisi ya da bir
            # test onu dışarıdan kapatabilir. Karar burada verilir.
            _log.warning("pin_rotation_incomplete  hwid=%s", self._hwid)
            self._show_error("PIN güncellenmeden giriş yapılamaz")
            return False

        _log.info("pin_rotation_done  hwid=%s", self._hwid)
        return True

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

        # Kurumsal modda GERÇEK karşılaştırma — eşleşmezse kayıt REDDEDİLİR,
        # sahte bir "geçerli" onayı hiç verilmez. `register_new_user()`
        # çağrılmadan önce döndüğü için DB'ye hiçbir satır yazılmaz.
        if self._reg_referans is not None:
            girilen_kod = self._reg_referans.text().strip()
            gercek_kod = get_referans_id(DBManager())
            if not girilen_kod:
                self._show_reg_error("Referans Kodu boş olamaz.")
                return
            if gercek_kod is None or girilen_kod != gercek_kod:
                self._show_reg_error("Referans Kodu geçersiz.")
                return

        new_hwid = get_usb_hwid()
        if new_hwid is None:
            self._show_reg_error("USB tespit edilemedi.")
            return

        try:
            sonuc = register_new_user(
                DBManager(), hwid=new_hwid, username=username, pin=pin, role=role,
            )
        except UsernameTakenError:
            self._show_reg_error("Bu kullanıcı adı zaten alınmış.")
            return
        except HwidAlreadyRegisteredError as exc:
            # B-060: bu HWID zaten bir satıra bağlı -- ne pending ne
            # approved fark etmez, create_vault() ÇAĞRILMADI, var olan
            # vault dokunulmadan kaldı.
            if exc.status == "approved":
                self._show_reg_error(
                    "Bu USB zaten kayıtlı ve onaylı bir kullanıcıya ait. "
                    "Aynı USB'yi yeni biri için kullanmak istiyorsanız "
                    "önce bir yönetici Admin Paneli'nden bu kaydı kaldırmalı."
                )
            else:
                self._show_reg_error(
                    "Bu USB için zaten bekleyen bir kayıt var — bir "
                    "yönetici onaylayana ya da reddedene kadar yeniden "
                    "kayıt olunamaz."
                )
            return
        except Exception as exc:
            self._show_reg_error(f"Kayıt oluşturulamadı: {exc}")
            return

        show_totp_enrollment_dialog(self, sonuc.totp_secret, username)
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
