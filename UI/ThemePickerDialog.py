"""
HYCLEUS — Tema seçici: görsel kart grid

`ThemeMixin._on_theme_menu()`'un eski hâli (bkz. `UI/main_window_theme.py`
git geçmişi) düz metin bir `QMenu` açıyordu — 11 tema adı üst üste, hiçbir
görsel önizleme yok. Bu diyalog onun yerini alıyor: her kayıtlı tema kendi
kartında, kendi GERÇEK renk paletiyle canlı önizleniyor.

Token kaynağı — yeni renk İCAT EDİLMEDİ
-----------------------------------------
Diyaloğun KENDİ çerçevesi (başlık, arka plan, kart kenarlığı, "Seçili"
etiketi) çağıranın GÜNCEL `self._T`'siyle boyanıyor — tıpkı `ProfileDialog`/
`RecoveryShareDialog` gibi diğer ikincil diyaloglar gibi. Ama her kartın
İÇİNDEKİ önizleme şeridi o kartın TEMSİL ETTİĞİ preset'in KENDİ
token'larından geliyor (`UI/main_window_theme.py::_THEMES[key]["dark"/
"light"]`, kaynağı `UI/main_window_palette.py`) — başka bir deyişle her
kart kendi rengini gösterir, aktif temanın rengini değil. İkisi de zaten
KAYITLI token sözlükleri; hiçbir yeni hex değeri elle yazılmadı.

Koyu-yalnızca preset'ler (`light is None`) için önizleme her zaman KENDİ
koyu paletini gösterir — `dark` parametresinden bağımsız, `ThemeMixin.
_set_theme()`'in aynı preset'i seçtiğinde yaptığı `self._dark = True`
zorlamasıyla TUTARLI (bkz. `_toggle_theme`/`_set_theme`).
"""
from __future__ import annotations

from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

_KOLON = 3
#: Önizleme şeridinde gösterilen renk noktaları — sırayla accent/durum
#: renkleri. `sidebar` ayrı bir blok olarak, bunlardan önce çiziliyor.
_ONIZLEME_RENK_ANAHTARLARI = ("accent", "green", "yellow", "red")


def _stil(T: dict[str, str]) -> str:
    """Diyaloğun KENDİ çerçevesi — çağıranın aktif tema token'larından
    (B-055'in aynı deseni: bkz. `ProfileDialog.py::_stil`)."""
    return f"""
QDialog {{ background: {T['bg']}; color: {T['text']}; }}
QLabel#tema_secici_baslik {{
    color: {T['text']};
    font-size: 16px;
    font-weight: 700;
    background: transparent;
}}
QLabel#tema_secici_aciklama {{
    color: {T['subtext']};
    font-size: 12px;
    background: transparent;
}}
QScrollArea#tema_secici_scroll {{ border: none; background: transparent; }}
QWidget#tema_secici_icerik {{ background: transparent; }}
QLabel#tema_karti_ad {{
    color: {T['text']};
    font-size: 13px;
    font-weight: 600;
    background: transparent;
}}
QLabel#tema_karti_secili_etiket {{
    color: {T['accent']};
    font-size: 11px;
    font-weight: 600;
    background: transparent;
}}
QPushButton#tema_secici_kapat {{
    background: {T['hover']};
    color: {T['text']};
    border: 1px solid {T['border']};
    border-radius: 8px;
    font-size: 13px;
    padding: 8px 20px;
}}
QPushButton#tema_secici_kapat:hover {{ background: {T['row_hover']}; }}
"""


def _onizleme_seridi(preset_T: dict[str, str]) -> QWidget:
    """Bir preset'in KENDİ token'larından küçük bir canlı önizleme —
    kenar çubuğu bloğu + accent/durum renklerinden noktalar, hepsi o
    preset'in `bg`'si üzerinde."""
    serit = QWidget()
    serit.setObjectName("tema_onizleme")
    serit.setFixedHeight(48)
    serit.setStyleSheet(
        f"QWidget#tema_onizleme {{ background: {preset_T['bg']};"
        f" border: 1px solid {preset_T['border']}; border-radius: 6px; }}"
    )
    lay = QHBoxLayout(serit)
    lay.setContentsMargins(8, 8, 8, 8)
    lay.setSpacing(6)

    kenar_cubugu = QFrame()
    kenar_cubugu.setFixedSize(14, 32)
    kenar_cubugu.setStyleSheet(
        f"background: {preset_T['sidebar']}; border-radius: 3px;"
        f" border: 1px solid {preset_T['border']};"
    )
    lay.addWidget(kenar_cubugu)

    for anahtar in _ONIZLEME_RENK_ANAHTARLARI:
        nokta = QFrame()
        nokta.setFixedSize(12, 12)
        nokta.setStyleSheet(f"background: {preset_T[anahtar]}; border-radius: 6px;")
        lay.addWidget(nokta)

    lay.addStretch()
    return serit


def _tema_karti(
    key: str,
    ad: str,
    preset_T: dict[str, str],
    *,
    T: dict[str, str],
    secili: bool,
    on_click: Callable[[str], None],
) -> QFrame:
    """Tek bir tema kartı — tıklanabilir (`mousePressEvent` ataması,
    `UI/main_window_layout.py`'nin avatar/scrim düğmeleriyle AYNI desen:
    ayrı bir sınıf açmak yerine örnek metoda doğrudan atama)."""
    kart = QFrame()
    kart.setObjectName("tema_karti")
    kart.setProperty("theme_key", key)
    kart.setProperty("secili", secili)
    kart.setCursor(Qt.PointingHandCursor)

    kenarlik = T["accent"] if secili else T["border"]
    kalinlik = "2px" if secili else "1px"
    kart.setStyleSheet(
        f"QFrame#tema_karti {{ background: {T['sidebar']};"
        f" border: {kalinlik} solid {kenarlik}; border-radius: 10px; }}"
    )

    v = QVBoxLayout(kart)
    v.setContentsMargins(10, 10, 10, 10)
    v.setSpacing(6)
    v.addWidget(_onizleme_seridi(preset_T))

    ad_etiketi = QLabel(ad)
    ad_etiketi.setObjectName("tema_karti_ad")
    ad_etiketi.setWordWrap(True)
    v.addWidget(ad_etiketi)

    secili_etiketi = QLabel("✓ Seçili")
    secili_etiketi.setObjectName("tema_karti_secili_etiket")
    secili_etiketi.setVisible(secili)
    v.addWidget(secili_etiketi)

    kart.mousePressEvent = lambda _ev, k=key: on_click(k)
    return kart


class ThemePickerDialog(QDialog):
    """Tema seçici — kart grid. Bir kart tıklanınca `on_select(key)`
    çağrılır ve diyalog kapanır (`accept()`)."""

    def __init__(
        self,
        parent=None,
        *,
        T: dict[str, str],
        theme_key: str,
        dark: bool,
        on_select: Callable[[str], None],
    ) -> None:
        super().__init__(parent)
        # Döngüsel içe aktarım (`main_window_theme.py` <-> bu dosya) burada
        # değil, ÇAĞIRANDA (`ThemeMixin._on_theme_menu`) kırılıyor — o da
        # bu ithalatı yerel yapıyor (bkz. o dosyadaki yorum).
        from UI.main_window_theme import _THEMES, available_themes

        self._T = T
        self._on_select = on_select

        self.setWindowTitle("Tema Seç")
        self.setModal(True)
        self.setMinimumSize(560, 420)
        self.setStyleSheet(_stil(T))

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        baslik = QLabel("Tema Seç")
        baslik.setObjectName("tema_secici_baslik")
        root.addWidget(baslik)

        aciklama = QLabel(
            "Her kart kendi renk paletini gösterir — bir karta tıklayın."
        )
        aciklama.setObjectName("tema_secici_aciklama")
        root.addWidget(aciklama)

        scroll = QScrollArea()
        scroll.setObjectName("tema_secici_scroll")
        scroll.setWidgetResizable(True)

        icerik = QWidget()
        icerik.setObjectName("tema_secici_icerik")
        grid = QGridLayout(icerik)
        grid.setSpacing(12)

        for i, (key, ad) in enumerate(available_themes()):
            preset = _THEMES[key]
            # Koyu-yalnızca preset'ler her zaman KENDİ koyu paletini
            # gösterir — `_set_theme()`'in aynı durumda yaptığı gibi.
            varyant = preset["dark"] if (dark or preset["light"] is None) else preset["light"]
            kart = _tema_karti(
                key, ad, varyant,
                T=T, secili=(key == theme_key), on_click=self._sec,
            )
            grid.addWidget(kart, i // _KOLON, i % _KOLON)

        scroll.setWidget(icerik)
        root.addWidget(scroll, 1)

        kapat = QPushButton("Kapat")
        kapat.setObjectName("tema_secici_kapat")
        kapat.setCursor(Qt.PointingHandCursor)
        kapat.clicked.connect(self.reject)
        alt_bar = QHBoxLayout()
        alt_bar.addStretch()
        alt_bar.addWidget(kapat)
        root.addLayout(alt_bar)

    def _sec(self, key: str) -> None:
        self._on_select(key)
        self.accept()
