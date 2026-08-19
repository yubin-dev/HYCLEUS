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
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

#: Rapor diyaloglarının ortak stil sayfası.
#:
#: Renk paleti `UI/TagDialog.py` ile aynı aileden; uygulamanın diyalogları
#: tek bir görsel dil konuşuyor.
RAPOR_STILI = """
QDialog  { background: #1e1e2e; color: #cdd6f4; }
QLabel   { color: #cdd6f4; background: transparent; }
QLabel#dosya    { color: #a6adc8; font-size: 11px; }
QLabel#simge    { font-size: 26px; }
QLabel#baslik   { font-size: 15px; font-weight: bold; }
QLabel#ozet     { color: #cdd6f4; font-size: 12px; }
QLabel#oneri    { color: #f9e2af; font-size: 12px; }
QLabel#not_bas  { font-size: 12px; font-weight: bold; }
QLabel#not_gov  { color: #a6adc8; font-size: 11px; }
QLabel#alan_ad  { color: #a6adc8; font-size: 11px; }
QLabel#alan_dgr { color: #cdd6f4; font-size: 12px; font-weight: bold; }
QFrame#sep      { background: #313244; max-height: 1px; }
QFrame#kutu     { background: #181825; border: 1px solid #313244; border-radius: 6px; }
QScrollArea     { background: #1e1e2e; border: none; }
QWidget#govde   { background: #1e1e2e; }
QTextEdit#teknik {
    background: #11111b; color: #a6adc8;
    border: 1px solid #313244; border-radius: 6px;
    font-family: Consolas, monospace; font-size: 11px;
}
QPushButton#primary_btn {
    background: #89b4fa; color: #1e1e2e; border: none;
    border-radius: 6px; padding: 9px 22px; font-size: 13px; font-weight: bold;
}
QPushButton#primary_btn:hover { background: #b4d0ff; }
QPushButton#flat_btn {
    background: #313244; color: #cdd6f4; border: none;
    border-radius: 6px; padding: 7px 14px; font-size: 12px;
}
QPushButton#flat_btn:hover { background: #45475a; }
"""

#: Seviyesi bilinmeyen bir mesajın görünümü. Diyalogların çökmemesi için
#: var; eksiksizlik denetimleri erişilmez olmasını sağlıyor.
VARSAYILAN_GORUNUM: tuple[str, str] = ("•", "#a6adc8")


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


__all__ = ["RAPOR_STILI", "VARSAYILAN_GORUNUM", "ayrac", "kutu", "sarmali"]
