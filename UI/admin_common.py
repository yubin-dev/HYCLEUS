"""HYCLEUS — USB Yönetim Paneli: üç sayfa arasında PAYLAŞILAN kod.

Modal'dan tam sayfaya, tek panelden üç sayfaya
------------------------------------------------
`UI/AdminPanel.py` (kaldırıldı) tek bir `QDialog` içinde üç `QTabWidget`
sekmesi taşıyordu: USB Tokenlar / Bekleyen Kayıtlar / Ayarlar. Artık
`UI/GuvenlikView.py`/`UI/AuditLogView.py`/`UI/ProfileView.py` ile AYNI
desende — `_govde_yigini` (`QStackedWidget`) içinde ÜÇ AYRI sayfa, kenar
çubuğunda üç ayrı giriş noktası (`UI/UsbTokensView.py`,
`UI/PendingRegistrationsView.py`, `UI/AdminSettingsView.py`).

Stil yardımcıları (`_btn_stil` vb.) ve `Qt.UserRole` slot sabitleri
üçünde de AYNI — burada tutulmasının sebebi üçe bölünürken üç kopyaya
ayrışmalarını önlemek, B-055'in "ikinci bir renk yolu açma" ilkesiyle
aynı gerekçe.


Canlı yetki denetimi — NEDEN artık kendi zamanlayıcısı YOK
--------------------------------------------------------------
Eski `AdminPanel`, application-modal bir `QDialog` olduğu için ana
penceredeki `_poll_usb()`/`_lock()`'tan HABERSİZDİ — o yüzden kendi 3
saniyelik `_yetki_timer`'ını ve "USB çıkarıldı/rol düştü" uyarı şeridini
kendi kurmak ZORUNDAYDI (bkz. eski dosyanın B-064/B-066 yorumu).

Bu üç sayfa artık `centralWidget()`'ın İÇİNDE: `_lock()` tetiklendiğinde
`centralWidget().setEnabled(False)` ZATEN tüm sayfaları (bunlar dahil)
kaplıyor — ayrı bir zamanlayıcı + şerit ARTIK GEREKSİZ, ana pencerenin
mevcut `_poll_usb()`'si (B-066) bu sayfalar açıkken de aynı şekilde
çalışıyor.

`yonetici_hala_yetkili()` SİLİNMEDİ — TAMAMLANDI: `centralWidget().
setEnabled(False)` yalnızca FARE/KLAVYE olaylarını engelliyor, Python
düzeyinde `sayfa._on_approve()` gibi DOĞRUDAN bir metot çağrısını
ENGELLEMİYOR (bkz. aşağıdaki fonksiyonun docstring'i). Bu, eski
`AdminPanel._yonetici_hala_yetkili`'nin ASIL garantisiydi ve modal/sayfa
ayrımından BAĞIMSIZ hâlâ geçerli.


`is_admin_role` kontrolü — YENİ, kasıtlı bir sıkılaştırma
---------------------------------------------------------------
Eski `AdminPanel` yalnızca `is_admin_role(role)` DOĞRUYSA kuruluyordu
(`__init__`'in başındaki kapı) — yönetici olmayan bir rol için nesne hiç
VAR OLMUYORDU, dolayısıyla `_yonetici_hala_yetkili`'nin kendisi admin
olup olmadığına hiç bakmıyordu (yalnızca `oturum_yetkisi_gecerli_mi` ile
"rol GİRİŞTEKİYLE aynı mı" diye soruyordu — zaten yönetici olmayan
geçerli bir oturum için bu hep True dönerdi).

Üç sayfa artık `_govde_yigini`'ne KOŞULSUZ ekleniyor (Güvenlik/Denetim
Günlüğü/Profil ile AYNI desen — bkz. `UI/main_window_layout.py::
_make_govde_yigini`), yani yönetici OLMAYAN bir oturumun `pencere`
nesnesinde de `pencere._pending_view` gibi CANLI bir referans duruyor.
Kenar çubuğu düğmesi ve `_on_open_*` giriş noktası rol'e göre
gizli/reddedilir (B-028 tek karar noktası, `CORE.roles.is_admin_role`) —
ama nesne referansının kendisi artık VAR, ki eskiden hiç yoktu. Bu
fonksiyon o yüzden `is_admin_role(pencere._role)`'u KENDİSİ de kontrol
ediyor: giriş noktası atlanıp `pending_view._on_approve()` doğrudan
çağrılsa bile (bir hata ya da programatik erişim), yönetici olmayan bir
oturum için DB yazısı yine de REDDEDİLİR.
"""
from __future__ import annotations

import logging
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox, QWidget

from CORE.roles import is_admin_role
from CORE.session_user import oturum_yetkisi_gecerli_mi
from CORE.usb_manager import get_usb_hwid
from DB.db_manager import DBManager

_log = logging.getLogger("hycleus.admin_panel")

#: Rol değiştirme diyalogunun sunduğu seçenekler — üç sayfa arasında
#: yalnızca USB Tokenlar sayfası kullanıyor, ama tanım burada: `_ROLES`
#: "hangi roller var" sorusunun cevabı, sayfaya özgü bir ayrıntı değil.
ROLES = ["Yönetici", "Standart", "Salt Okunur"]

# Qt.UserRole slots for column-0 items (USB Tokenlar tablosu)
ROLE_HWID = Qt.UserRole              # str  — tam HWID
ROLE_BLACKLISTED = Qt.UserRole + 1   # bool — kara liste durumu


def stil(T: dict[str, str]) -> str:
    """Sayfanın ana stil sayfası — kayıtlı tema token'larından (B-055).

    Sabit bir palet değil; yeni bir token İCAT EDİLMİYOR.
    """
    return f"""
QWidget {{ background: {T['bg']}; color: {T['text']}; }}
QLabel  {{ color: {T['text']}; background: transparent; }}
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


def btn_stil(T: dict[str, str]) -> str:
    return (
        f"QPushButton{{color:{T['text']};background:{T['hover']};border:none;"
        f"border-radius:6px;padding:5px 14px;font-size:12px;}}"
        f"QPushButton:hover{{background:{T['row_hover']};}}"
        f"QPushButton:disabled{{color:{T['gray']};background:{T['bg']};border:none;}}"
    )


def btn_danger_stil(T: dict[str, str]) -> str:
    return (
        f"QPushButton{{color:{T['red']};background:{T['red_tint']};"
        f"border:1px solid {T['red']};"
        f"border-radius:6px;padding:5px 14px;font-size:12px;}}"
        f"QPushButton:hover{{background:{T['red_tint']};}}"
        f"QPushButton:disabled{{color:{T['gray']};background:{T['bg']};"
        f"border:1px solid {T['border']};}}"
    )


def btn_success_stil(T: dict[str, str]) -> str:
    return (
        f"QPushButton{{color:{T['green']};background:{T['green_tint']};"
        f"border:1px solid {T['green']};"
        f"border-radius:6px;padding:5px 14px;font-size:12px;}}"
        f"QPushButton:hover{{background:{T['green_tint']};}}"
        f"QPushButton:disabled{{color:{T['gray']};background:{T['bg']};"
        f"border:1px solid {T['border']};}}"
    )


def combo_stili(T: dict[str, str]) -> str:
    return (
        f"QComboBox{{background:{T['hover']};color:{T['text']};"
        f"border:1px solid {T['border']};"
        f"border-radius:6px;padding:5px 10px;font-size:12px;}}"
        f"QComboBox::drop-down{{border:none;width:20px;}}"
        f"QComboBox QAbstractItemView{{background:{T['hover']};color:{T['text']};"
        f"border:1px solid {T['border']};"
        f"selection-background-color:{T['row_hover']};}}"
    )


def bolum_baslik_stili(T: dict[str, str]) -> str:
    return f"color:{T['accent']}; font-size:12px; font-weight:600;"


def ipucu_stili(T: dict[str, str]) -> str:
    return f"color:{T['subtext']}; font-size:12px;"


def liste_stili(T: dict[str, str]) -> str:
    return (
        f"QListWidget{{background:{T['hover']};color:{T['text']};"
        f"border:1px solid {T['border']};"
        f"border-radius:6px;font-size:12px;}}"
        f"QListWidget::item{{padding:4px 8px;}}"
        f"QListWidget::item:selected{{background:{T['row_hover']};}}"
    )


def yonetici_hala_yetkili(widget: QWidget, pencere: Any) -> bool:
    """Her yetkili admin eyleminden ÖNCE canlı doğrulama (B-064/B-066).

    Üç kontrol, sırayla, İLKİ geçmeden ikincisine BAKILMAZ:

      1. `is_admin_role(pencere._role)` — sayfa yönetici olmayan bir
         oturum için de VAR (yukarıdaki modül docstring'i), giriş
         noktası atlanırsa asıl kapı BURASI.
      2. `get_usb_hwid() == pencere._hwid` — giriş anındaki fiziksel USB
         hâlâ takılı mı.
      3. `oturum_yetkisi_gecerli_mi()` — DB'deki rol/durum hâlâ oturumun
         GİRİŞTEKİ rolüyle uyuşuyor mu (B-066: başka bir yerden düşürülmüş
         olabilir).

    Geçersizse: kullanıcıya nedeni gösterir VE `pencere._lock("revoked")`
    çağırır — eski davranış (`panel.reject()`, modalı kapatmak) artık
    anlamsız (bu bir sayfa, kapatılamaz); doğru karşılığı TÜM pencereyi
    kilitlemek, ki `_poll_usb()` zaten aynı durumda aynı şeyi yapıyor.
    """
    if not is_admin_role(getattr(pencere, "_role", None)):
        gecerli, sebep = False, "Bu işlem için yönetici yetkisi gerekiyor."
    else:
        canli_hwid = get_usb_hwid()
        if canli_hwid != getattr(pencere, "_hwid", None):
            gecerli, sebep = False, "USB çıkarıldı veya değiştirildi."
        else:
            try:
                gecerli, sebep = oturum_yetkisi_gecerli_mi(
                    DBManager(), pencere._hwid, pencere._role
                )
            except Exception as exc:
                # Ana penceredeki _poll_usb ile aynı tavır: DB'ye anlık
                # erişilemedi diye geçerli bir yönetici oturumunu kesme,
                # bir sonraki eylem ya da _poll_usb tik'i yeniden dener.
                _log.warning("admin_yetkisi_dogrulanamadi (tekrar denenecek): %s", exc)
                return True

    if gecerli:
        return True

    QMessageBox.critical(
        widget, "Oturum Geçersiz",
        f"{sebep}\n\nOturum kilitleniyor — yeniden giriş yapmanız gerekiyor.",
    )
    lock = getattr(pencere, "_lock", None)
    if callable(lock):
        lock("revoked")
    return False


__all__ = [
    "ROLES", "ROLE_HWID", "ROLE_BLACKLISTED",
    "stil", "btn_stil", "btn_danger_stil", "btn_success_stil",
    "combo_stili", "bolum_baslik_stili", "ipucu_stili", "liste_stili",
    "yonetici_hala_yetkili",
]
