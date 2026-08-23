"""
HYCLEUS — rapor diyaloglarının ortak tesisatı

`TimestampDialog` ve `BackupVerifyDialog` aynı işi yapıyor: bir doğrulama
sonucunu okunur biçimde göstermek. Yerleşimleri de aynı — renkli bir karar
başlığı, bir özet, kutular hâlinde ayrıntılar, kapalı başlayan bir teknik
blok, kopyala/kapat.

Burada olan şey yalnızca o TESİSAT: stil sayfası, ayraç, satır kaydıran
etiket, kutu. Karar mantığı ve metin YOK — onlar her diyaloğun kendi
alanında, çünkü ikisi farklı şeyler söylüyor.

Neden `Aciklama` ve seviye sabitleri burada DEĞİL
--------------------------------------------------
İlk tasarımda buraya konacaktı. Konmadı: seviye SÖZLÜKLERİ ortak değil.
Damga tarafında "damgasız" diye anlamlı bir durum var ve yedekte
karşılığı yok; yedekte "yarıda kesildi" var ve damgada karşılığı yok.
Ortak bir sabit kümesi, her iki tarafa diğerinin sözcüklerini
taşıtırdı — ve "bu seviye burada kullanılmıyor" istisnaları başlardı.

Paylaşılan şey biçim; anlam paylaşılmıyor.

Neden RAPOR_STILI/VARSAYILAN_GORUNUM artık SABİT DEĞİL (B-055)
----------------------------------------------------------------
Sabit bir Catppuccin-Mocha paletiydi — hangi tema seçili olursa olsun
hep aynı görünüyordu. `main_window_theme.py`'nin preset-registry'si
(75c6ddd) bu üç diyaloğu hiç etkilemiyordu, çünkü ikisi de token değil
literal hex okuyordu. Şimdi ikisi de kayıtlı token sözlüğünü (`self._T`)
parametre olarak alan FONKSİYON — ikinci bir renk yolu açmadan tek
noktadan çözülüyor.

Neden kök seçici `QDialog` değil `QWidget#rapor_disi_govde` (slide-over turu)
------------------------------------------------------------------------------
`TimestampDialog`/`BackupVerifyDialog` artık `QDialog` DEĞİL — ayrı bir
pencere açmak yerine `main_window_layout.py`'nin slide-over paneline
YERLEŞİYORLAR. `QDialog {...}` seçicisi artık hiçbir şeye uymaz ve arka
plan/rengi SESSİZCE uygulanmaz olurdu. İkisi de `__init__`'te
`self.setObjectName("rapor_disi_govde")` çağırıyor; iç kaydırma alanının
`objectName("govde")`'siyle (bkz. `_build_ui`) ÇAKIŞMASIN diye ayrı ad.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget


def rapor_stili(T: dict[str, str]) -> str:
    """Rapor diyaloglarının ortak stil sayfası — kayıtlı tema token'larından.

    `T`, `UI/main_window_palette.py`'deki preset sözlüklerinden biri
    (`self._T`). Yeni bir token İCAT EDİLMEDİ — yalnızca var olanlar
    kullanıldı.
    """
    return f"""
QWidget#rapor_disi_govde {{ background: {T['bg']}; color: {T['text']}; }}
QLabel   {{ color: {T['text']}; background: transparent; }}
QLabel#dosya    {{ color: {T['subtext']}; font-size: 11px; }}
QLabel#simge    {{ font-size: 26px; }}
QLabel#baslik   {{ font-size: 15px; font-weight: bold; }}
QLabel#ozet     {{ color: {T['text']}; font-size: 12px; }}
QLabel#oneri    {{ color: {T['yellow']}; font-size: 12px; }}
QLabel#not_bas  {{ font-size: 12px; font-weight: bold; }}
QLabel#not_gov  {{ color: {T['subtext']}; font-size: 11px; }}
QLabel#alan_ad  {{ color: {T['subtext']}; font-size: 11px; }}
QLabel#alan_dgr {{ color: {T['text']}; font-size: 12px; font-weight: bold; }}
QFrame#sep      {{ background: {T['border']}; max-height: 1px; }}
QFrame#kutu     {{ background: {T['search_bg']}; border: 1px solid {T['border']}; border-radius: 6px; }}
QScrollArea     {{ background: {T['bg']}; border: none; }}
QWidget#govde   {{ background: {T['bg']}; }}
QTextEdit#teknik {{
    background: {T['bg']}; color: {T['subtext']};
    border: 1px solid {T['border']}; border-radius: 6px;
    font-family: Consolas, monospace; font-size: 11px;
}}
QPushButton#primary_btn {{
    background: {T['accent']}; color: {T['on_accent']}; border: none;
    border-radius: 6px; padding: 9px 22px; font-size: 13px; font-weight: bold;
}}
QPushButton#primary_btn:hover {{ background: {T['accent_hover']}; }}
QPushButton#flat_btn {{
    background: {T['hover']}; color: {T['text']}; border: none;
    border-radius: 6px; padding: 7px 14px; font-size: 12px;
}}
QPushButton#flat_btn:hover {{ background: {T['row_hover']}; }}
"""


def varsayilan_gorunum(T: dict[str, str]) -> tuple[str, str]:
    """Seviyesi bilinmeyen bir mesajın görünümü — diyalogların çökmemesi için.

    Eksiksizlik denetimleri erişilmez olmasını sağlıyor.
    """
    return ("•", T["subtext"])


def ayrac() -> QFrame:
    """Yatay ince çizgi."""
    f = QFrame()
    f.setObjectName("sep")
    f.setFrameShape(QFrame.HLine)
    return f


def sarmali(metin: str, nesne_adi: str) -> QLabel:
    """Satır kaydıran, seçilebilir bir etiket.

    `setWordWrap(True)` olmadan uzun açıklamalar pencereyi ekran dışına
    taşırıyor; bu diyalogların metinleri kasten uzun — tek cümlelik bir
    "geçersiz" yetmiyor.

    Metin SEÇİLEBİLİR: kullanıcı bir dosya adını ya da bir hata cümlesini
    yöneticisine iletecekse ekran görüntüsüne mahkûm kalmamalı.
    """
    lbl = QLabel(metin)
    lbl.setObjectName(nesne_adi)
    lbl.setWordWrap(True)
    lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return lbl


def kutu(icerik: list[QWidget]) -> QFrame:
    """İçeriği çerçeveli, koyu bir kutuya alır."""
    cerceve = QFrame()
    cerceve.setObjectName("kutu")
    sutun = QVBoxLayout(cerceve)
    sutun.setContentsMargins(12, 10, 12, 10)
    sutun.setSpacing(3)
    for w in icerik:
        sutun.addWidget(w)
    return cerceve


__all__ = ["rapor_stili", "varsayilan_gorunum", "ayrac", "kutu", "sarmali"]
