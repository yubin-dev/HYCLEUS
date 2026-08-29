"""
HYCLEUS — Tema ve stil

UI/main_window.py'den 2.7 refactor'ünde ayrıldı. Metot gövdeleri
kelimesi kelimesine taşındı; davranış değişmedi.

`HycleusWindow` bu mixin'i miras alıyor, dolayısıyla `self` hâlâ
pencerenin kendisi ve çağrı yerleri değişmedi.
"""
import logging
# timedelta modül seviyesinde artık kullanılmıyor: "şimdi + TTL" hesabı
# CORE/expiry.py'ye taşındı. _FileRunnable.run() kendi yerel import'unu
# yapıyor (worker thread'inde çalışıyor, bkz. satır ~218).

_log = logging.getLogger("hycleus.ui")

from PySide6.QtCore import (
    QEvent,
)

# Hareketsizlik sayacını sıfırlayan olaylar. Yalnızca GERÇEK kullanıcı
# etkileşimi: zamanlayıcı tik'leri, boyama ve pencere olayları buraya
# GİRMEZ — girseydi ekranda dönen bir ilerleme çubuğu bile oturumu sonsuza
# kadar açık tutardı.
_ACTIVITY_EVENTS = frozenset({
    QEvent.MouseButtonPress,
    QEvent.MouseButtonRelease,
    QEvent.MouseButtonDblClick,
    QEvent.MouseMove,
    QEvent.KeyPress,
    QEvent.KeyRelease,
    QEvent.Wheel,
    QEvent.TouchBegin,
    QEvent.TouchUpdate,
})



from CORE.roles import normalize_role

from UI.main_window_palette import (
    _DARK,
    _LIGHT,
    _TEAL_GOLD_DARK,
    _TEAL_GOLD_LIGHT,
    _AURORA_BOREALIS,
    _ABYSSAL_BLUE,
    _GRAPHITE_AMBER,
    _CAM,
    _KLASIK,
    _AKRILIK,
    _AURORA_CAM,
    _GUN_BATIMI,
    _GRAFIT_CAM,
    _ROLE_BADGE,
)


# ── Tema preset kaydı ─────────────────────────────────────────────────────────
# `register_theme(key, name, dark, light)` — `light` verilmezse preset yalnızca
# koyu modda çalışır ve tema düğmesindeki Gündüz/Gece geçişi o preset için
# devre dışı kalır (bkz. ThemeMixin._toggle_theme). Sıra, tema menüsünde
# gösterilme sırasıdır.
_THEMES: dict[str, dict] = {}


def register_theme(key: str, name: str, dark: dict[str, str], light: dict[str, str] | None = None) -> None:
    """Bir tema preset'ini kayda ekler."""
    _THEMES[key] = {"name": name, "dark": dark, "light": light}


def available_themes() -> list[tuple[str, str]]:
    """Tema menüsü için (key, ad) listesi, kayıt sırasıyla."""
    return [(key, preset["name"]) for key, preset in _THEMES.items()]


register_theme("mavi", "Mavi (Varsayılan)", _DARK, _LIGHT)
register_theme("teal_gold", "Teal & Gold", _TEAL_GOLD_DARK, _TEAL_GOLD_LIGHT)
register_theme("aurora_borealis", "Aurora Borealis", _AURORA_BOREALIS)
register_theme("abyssal_blue", "Abyssal Blue", _ABYSSAL_BLUE)
register_theme("graphite_amber", "Grafit & Kehribar", _GRAPHITE_AMBER)
# Arayüz güncellemesi (2026-08-26) — mockup'ın 11 temasından eksik 6'sı.
# "Gece"/"Gün" eklenmedi: ölçüldüğünde teal_gold ile birebir aynı çıktı
# (bkz. UI/main_window_palette.py'nin bu bloğun üstündeki yorumu, BACKLOG).
register_theme("cam", "Cam", _CAM)
register_theme("klasik", "Klasik", _KLASIK)
register_theme("akrilik", "Akrilik", _AKRILIK)
register_theme("aurora_cam", "Aurora (Cam)", _AURORA_CAM)
register_theme("gun_batimi", "Gün Batımı", _GUN_BATIMI)
register_theme("grafit_cam", "Grafit (Cam)", _GRAFIT_CAM)


class ThemeMixin:
    """Tema ve stil."""

    # ── Tema ──────────────────────────────────────────────────────────────────

    def _refresh_after_theme_change(self) -> None:
        """`_toggle_theme` ve `_set_theme` sonrası ortak tazeleme adımı."""
        self._apply_theme()
        self._reset_drop_hint_style()
        # Slide-over paneli `central_root`'un DIŞINDA (bkz.
        # `main_window_layout.py::_SlideOverPanel.stil_uygula`) — yukarıdaki
        # `_apply_theme()`'in kaskadı ona ulaşmıyor, elle tazelenmesi gerekiyor.
        if getattr(self, "_slide_over", None) is not None:
            self._slide_over.stil_uygula(self._T)
        # Denetim Günlüğü sayfası HALKA/Uyarı sütunlarını `self._T`'den
        # QColor ile elle boyuyor (QSS cascade'i yakalayamaz — bkz.
        # `UI/AuditLogView.py::_insert_row`); satırlar zaten kurulduysa
        # yeniden yüklenip yeni tema renkleriyle tekrar boyanmalı.
        if getattr(self, "_audit_log_view", None) is not None:
            self._audit_log_view._load()
        if self._current_tag_id is not None:
            self._load_tag_files(self._current_tag_id)
        else:
            self._load_label(self._current_label)

    def _toggle_theme(self) -> None:
        preset = _THEMES[self._theme_key]
        if preset["light"] is None:
            # Koyu-yalnızca preset — Gündüz/Gece geçişinin bu preset'te
            # yapacağı bir şey yok.
            return
        self._dark = not self._dark
        self._T = preset["dark"].copy() if self._dark else preset["light"].copy()
        self._refresh_after_theme_change()

    def _set_theme(self, key: str) -> None:
        preset = _THEMES[key]
        self._theme_key = key
        if preset["light"] is None:
            self._dark = True
        self._T = preset["dark"].copy() if self._dark else preset["light"].copy()
        self._refresh_after_theme_change()

    def _on_theme_menu(self) -> None:
        """Tema seçici — görsel kart grid (bkz. `UI/ThemePickerDialog.py`).

        Eskiden düz metin bir `QMenu` açıyordu (11 tema adı üst üste,
        önizleme yok). Yerel içe aktarım: `ThemePickerDialog` bu mixin'i
        (`_THEMES`/`available_themes`) geri içe aktarıyor — döngüsel
        bağımlılığı modül-seviyesinde DEĞİL, çağrı anında çözüyor. Bu aynı
        zamanda testlerin `UI.ThemePickerDialog.ThemePickerDialog`'u
        monkeypatch edebilmesini sağlıyor (`AdminPanel.py`'nin
        `RecoveryShareDialog`'u içe aktarma deseniyle AYNI, bkz. o
        dosyadaki `_on_kurtarma_parcasi`).
        """
        from UI.ThemePickerDialog import ThemePickerDialog

        dlg = ThemePickerDialog(
            self, T=self._T, theme_key=self._theme_key, dark=self._dark,
            on_select=self._set_theme,
        )
        dlg.exec()

    def _toggle_maximize(self) -> None:
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def _nav_btn_style(self, *, active: bool) -> str:
        T = self._T
        if active:
            return (
                f"QPushButton {{"
                f" background: {T['accent_tint']}; color: {T['accent']};"
                f" border: none; border-left: 3px solid {T['accent']};"
                f" border-radius: 8px; height: 44px;"
                f" padding: 0 20px 0 17px; text-align: left;"
                f" font-size: 14px; font-weight: 600; margin: 2px 12px;"
                f"}}"
                f"QPushButton:hover {{ background: {T['accent_tint_hover']}; }}"
            )
        return (
            f"QPushButton {{"
            f" background: transparent; color: {T['nav_text']};"
            f" border: none; border-left: 3px solid transparent;"
            f" border-radius: 8px; height: 44px;"
            f" padding: 0 20px; text-align: left;"
            f" font-size: 14px; margin: 2px 12px;"
            f"}}"
            f"QPushButton:hover {{ background: {T['hover']}; }}"
        )

    def _tag_btn_style(self, *, color: str, active: bool) -> str:
        T = self._T
        if active:
            return (
                f"QPushButton {{"
                f" background: {T['accent_tint']}; color: {color};"
                f" border: none; border-left: 3px solid {color};"
                f" border-radius: 8px;"
                f" padding: 6px 20px 6px 17px; text-align: left;"
                f" font-size: 13px; font-weight: 600; margin: 1px 12px;"
                f"}}"
                f"QPushButton:hover {{ background: {T['accent_tint_hover']}; }}"
            )
        return (
            f"QPushButton {{"
            f" background: transparent; color: {T['subtext']};"
            f" border: none; border-left: 3px solid transparent;"
            f" border-radius: 8px;"
            f" padding: 6px 20px; text-align: left;"
            f" font-size: 13px; margin: 1px 12px;"
            f"}}"
            f"QPushButton:hover {{ background: {T['hover']}; }}"
        )

    def _apply_tag_theme(self) -> None:
        for btn in self._tag_btns.values():
            color  = btn.property("tag_color") or self._T["accent"]
            active = btn is self._active_tag_btn
            btn.setStyleSheet(self._tag_btn_style(color=color, active=active))

    def _apply_theme(self) -> None:
        T = self._T
        self._theme_btn.setText("☀" if self._dark else "🌙")
        self._avatar.setText(self._username[0].upper() if self._username else "?")

        bg, fg = _ROLE_BADGE.get(normalize_role(self._role), ("#F3F4F6", "#6B7280"))
        self._role_badge.setStyleSheet(
            f"QLabel {{ color: {fg}; background: {bg}; border-radius: 20px;"
            f" font-size: 12px; font-weight: 600; padding: 4px 12px;"
            f" margin: 8px 20px 4px; }}"
        )

        drop_bg = T["sidebar"] if self._dark else "#FAFAFA"

        qss = f"""
            QWidget#central_root, QWidget#body {{ background: {T['bg']}; }}

            QFrame#top_bar {{
                background: {T['topbar']};
                border-bottom: 1px solid {T['border']};
            }}
            QLabel#page_title {{
                color: {T['text']};
                font-size: 18px;
                font-weight: 600;
                background: transparent;
            }}
            QPushButton#theme_btn {{
                background: transparent;
                color: {T['subtext']};
                border: none;
                border-radius: 18px;
                font-size: 16px;
            }}
            QPushButton#theme_btn:hover {{ background: {T['hover']}; }}
            QLabel#avatar {{
                background: {T['accent']};
                color: {T['on_accent']};
                font-size: 13px;
                font-weight: 700;
                border-radius: 16px;
            }}

            QFrame#action_bar {{
                background: {T['topbar']};
                border-bottom: 1px solid {T['border']};
            }}
            QPushButton#btn_primary {{
                background: {T['accent']};
                color: {T['on_accent']};
                border: none;
                border-radius: 8px;
                font-size: 14px;
                padding: 0 16px;
            }}
            QPushButton#btn_primary:hover {{ background: {T['accent_hover']}; }}
            QPushButton#btn_secondary {{
                background: transparent;
                color: {T['nav_text']};
                border: 1px solid {T['border']};
                border-radius: 8px;
                font-size: 14px;
                padding: 0 16px;
                min-width: 36px;
            }}
            QPushButton#btn_secondary:hover {{ background: {T['hover']}; }}

            QFrame#sidebar {{
                background: {T['sidebar']};
                border-right: 1px solid {T['border']};
            }}
            QLabel#sidebar_logo {{
                color: {T['text']};
                font-size: 16px;
                font-weight: 700;
                padding: 24px 20px 16px;
                background: transparent;
            }}
            QFrame#sidebar_sep {{
                background: {T['border']};
                border: none;
                max-height: 1px;
            }}
            QLabel#nav_section_label {{
                color: #9CA3AF;
                font-size: 11px;
                font-weight: 600;
                letter-spacing: 1px;
                padding: 16px 20px 8px;
                background: transparent;
            }}
            QPushButton#admin_btn {{
                color: {T['subtext']};
                background: transparent;
                border: none;
                border-left: 3px solid transparent;
                border-radius: 8px;
                padding: 10px 14px 10px 16px;
                text-align: left;
                font-size: 12px;
            }}
            QPushButton#admin_btn:hover {{ background: {T['hover']}; }}
            QLabel#usb_badge {{
                background: transparent;
                margin: 4px 20px 16px;
                padding: 0;
            }}
            QScrollArea#sidebar_scroll {{
                background: transparent;
                border: none;
            }}
            QWidget#sidebar_scroll_content {{
                background: transparent;
            }}
            QScrollArea#sidebar_scroll QScrollBar:vertical {{
                background: transparent;
                width: 4px;
                margin: 0;
            }}
            QScrollArea#sidebar_scroll QScrollBar::handle:vertical {{
                background: {T['border']};
                border-radius: 2px;
                min-height: 20px;
            }}
            QScrollArea#sidebar_scroll QScrollBar::add-line:vertical,
            QScrollArea#sidebar_scroll QScrollBar::sub-line:vertical {{
                height: 0;
            }}

            QWidget#content {{ background: {T['bg']}; }}
            QWidget#search_container {{ background: {T['search_bg']}; }}
            QLabel#search_icon {{
                color: #9CA3AF;
                font-size: 16px;
                background: transparent;
            }}
            QLineEdit#search_bar {{
                background: transparent;
                color: {T['text']};
                border: none;
                font-size: 14px;
            }}

            QTableWidget {{
                background: {T['bg']};
                color: {T['text']};
                border: none;
                gridline-color: transparent;
                outline: none;
                font-size: 13px;
            }}
            QHeaderView::section {{
                background: {T['bg']};
                color: #9CA3AF;
                border: none;
                border-bottom: 1px solid {T['border']};
                padding: 0 10px;
                font-size: 12px;
                font-weight: 600;
            }}
            QTableWidget::item {{
                padding: 0 10px;
                border-bottom: 1px solid {T['hover']};
                background: {T['bg']};
            }}
            QTableWidget::item:hover {{ background: {T['row_hover']}; }}
            QTableWidget::item:selected {{
                background: {T['accent_tint']};
                color: {T['tint_text']};
            }}
            QLabel#drop_hint {{
                color: #9CA3AF;
                font-size: 13px;
                border: 2px dashed {T['border']};
                border-radius: 8px;
                background: {drop_bg};
                margin: 12px;
            }}
            QLabel#expiry_banner {{
                color: {T['subtext']};
                font-size: 13px;
                background: {T['sidebar']};
                border-radius: 8px;
                padding: 4px 12px;
                margin: 4px 12px 0;
            }}
            QLabel#progress_banner {{
                color: {T['on_accent']};
                font-size: 13px;
                font-weight: 600;
                background: {T['accent']};
                border-radius: 8px;
                padding: 4px 12px;
                margin: 4px 12px 0;
            }}

            /* Güvenlik sekmesi (UI/GuvenlikView.py) — B-055. Bu sayfa hiç
               kendi setStyleSheet() çağırmıyor, tamamı buradan cascade
               ediyor (main_window_table.py/tree.py ile aynı desen). */
            QWidget#guvenlik_view {{ background: {T['bg']}; }}
            QWidget#guvenlik_view QLabel {{ color: {T['text']}; }}
            QLabel#guvenlik_aciklama,
            QLabel#guvenlik_mod_ipucu,
            QLabel#guvenlik_kart_aciklama {{ color: {T['subtext']}; }}
            QFrame#guvenlik_ayrac {{
                background: {T['border']};
                border: none;
                max-height: 1px;
            }}
            QFrame#guvenlik_kart {{
                background: {T['search_bg']};
                border: 1px solid {T['border']};
                border-radius: 8px;
            }}
            QWidget#guvenlik_view QCheckBox {{ color: {T['text']}; }}
            QWidget#guvenlik_view QPushButton {{
                background: {T['hover']};
                color: {T['text']};
                border: none;
                border-radius: 6px;
                padding: 6px 16px;
                font-size: 12px;
            }}
            QWidget#guvenlik_view QPushButton:hover {{ background: {T['row_hover']}; }}

            /* Denetim Günlüğü sayfası (UI/AuditLogView.py) — Güvenlik
               sekmesiyle AYNI desen: kendi setStyleSheet()'ini çağırmıyor,
               tablo/başlık QTableWidget/QHeaderView kuralları YUKARIDAN
               (bu QSS'in üst kısmı) zaten cascade ediyor. Burada yalnızca
               bu sayfaya özgü olan: sekme şeridi, filtre alanları. */
            QWidget#audit_view {{ background: {T['bg']}; }}
            QWidget#audit_view QLabel {{ color: {T['text']}; }}
            QLabel#audit_baslik {{ font-size: 15px; font-weight: bold; }}
            QLabel#audit_aciklama {{ color: {T['subtext']}; font-size: 12px; }}
            QLabel#audit_sayac {{ color: {T['subtext']}; font-size: 11px; }}
            QTabBar#audit_sekmeler::tab {{
                background: {T['hover']};
                color: {T['subtext']};
                padding: 6px 18px;
                margin-right: 4px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-size: 12px;
            }}
            QTabBar#audit_sekmeler::tab:selected {{
                background: {T['accent_tint']};
                color: {T['accent']};
                font-weight: 600;
            }}
            QTabBar#audit_sekmeler::tab:hover {{ background: {T['row_hover']}; }}
            QWidget#audit_view QComboBox {{
                background: {T['search_bg']};
                color: {T['text']};
                border: 1px solid {T['border']};
                border-radius: 4px;
                padding: 4px 8px;
                min-width: 150px;
                font-size: 12px;
            }}
            QWidget#audit_view QComboBox QAbstractItemView {{
                background: {T['search_bg']};
                color: {T['text']};
                selection-background-color: {T['row_hover']};
                border: 1px solid {T['border']};
            }}
            QWidget#audit_view QComboBox::drop-down {{ border: none; width: 20px; }}
            QWidget#audit_view QDateEdit {{
                background: {T['search_bg']};
                color: {T['text']};
                border: 1px solid {T['border']};
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 12px;
            }}
            QWidget#audit_view QDateEdit::drop-down {{ border: none; width: 20px; }}
            QWidget#audit_view QCalendarWidget {{ background: {T['search_bg']}; color: {T['text']}; }}
            QPushButton#audit_btn_filtrele, QPushButton#audit_btn_sifirla {{
                color: {T['text']};
                background: {T['hover']};
                border: none;
                border-radius: 6px;
                padding: 5px 14px;
                font-size: 12px;
            }}
            QPushButton#audit_btn_filtrele:hover, QPushButton#audit_btn_sifirla:hover {{
                background: {T['row_hover']};
            }}
            QPushButton#audit_btn_disa_aktar {{
                color: {T['on_accent']};
                background: {T['accent']};
                border: none;
                border-radius: 6px;
                padding: 5px 14px;
                font-size: 12px;
                font-weight: 600;
            }}
            QPushButton#audit_btn_disa_aktar:hover {{ background: {T['accent_hover']}; }}
        """

        self.centralWidget().setStyleSheet(qss)

        for db_label, btn in self._nav_btns.items():
            btn.setStyleSheet(self._nav_btn_style(active=(db_label == self._current_label)))

        self._refresh_usb_badge()
        self._apply_tag_theme()

    def _folder_btn_style(self, *, active: bool) -> str:
        T = self._T
        if active:
            return (
                f"QPushButton {{"
                f" background: {T['accent_tint']}; color: {T['accent']};"
                f" border: none; border-left: 3px solid {T['accent']};"
                f" border-radius: 6px; height: 34px;"
                f" padding: 0 20px 0 8px; text-align: left;"
                f" font-size: 12px; margin: 1px 12px 1px 24px;"
                f"}}"
                f"QPushButton:hover {{ background: {T['accent_tint_hover']}; }}"
            )
        return (
            f"QPushButton {{"
            f" background: transparent; color: {T['subtext']};"
            f" border: none; border-left: 3px solid transparent;"
            f" border-radius: 6px; height: 34px;"
            f" padding: 0 20px 0 8px; text-align: left;"
            f" font-size: 12px; margin: 1px 12px 1px 24px;"
            f"}}"
            f"QPushButton:hover {{ background: {T['hover']}; }}"
        )

