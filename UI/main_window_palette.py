"""
HYCLEUS — Arayüz sabitleri ve küçük çizim yardımcıları

Renk paletleri, rozet/etiket stil tabloları ve nokta simgesi üreteci.
2.7 refactor'ünde UI/main_window.py'den ayrıldı.

Kendi modülünde olmasının nedeni bu sabitlerin BİRDEN FAZLA mixin
tarafından kullanılması: paletler temada, rozet tabloları tabloda,
kenar çubuğu listesi iskelette, etiket renkleri ağaçta. Herhangi bir
mixin'in içine konsalardı diğerleri ondan import etmek zorunda kalır ve
mixin'ler birbirine bağlanırdı.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QPainter, QPixmap

from CORE.roles import ROL_SALT_OKUNUR, ROL_STANDART, ROL_YONETICI


# ── Renk paletleri ────────────────────────────────────────────────────────────
# Ortak anahtar kümesi (her preset aynı anahtarları taşır — main_window_theme.py
# ve diğer mixin'ler `self._T[...]` ile anahtar adına göre okuyor, preset'e göre
# değil). `accent_hover` dolgulu (Primary) butonun hover rengi, `accent_tint` /
# `accent_tint_hover` aktif/seçili satır arka planı, `on_accent` dolgulu accent
# üzerindeki metin rengi, `tint_text` accent_tint üzerindeki metin rengi.
# `red_tint`/`green_tint` — B-055 turunda eklendi (AdminPanel/RecoveryShareDialog
# uyarı kutuları ve ikincil buton dolguları için): `red`/`green`'in aynı
# mantıkla (accent → accent_tint) türetilmiş yarı saydam yüzey hâli.
_DARK: dict[str, str] = {
    "bg":        "#1C1C1E",
    "sidebar":   "#1C1C1E",
    "topbar":    "#2C2C2E",
    "accent":    "#2563EB",
    "accent_hover":      "#1D4ED8",
    "accent_tint":       "#EFF6FF",
    "accent_tint_hover": "#DBEAFE",
    "on_accent":         "#FFFFFF",
    "tint_text":         "#111827",
    "text":      "#F9FAFB",
    "subtext":   "#9CA3AF",
    "nav_text":  "#D1D5DB",
    "border":    "#3A3A3C",
    "hover":     "#2C2C2E",
    # B-057 (2026-08-25): eskisi #2C2C2E (topbar/hover/row_hover ile aynı
    # tondaydı), accent/search_bg (metin olarak — AdminPanel'in kendi HWID
    # vurgusu) kontrastı 2.70:1 idi (AA eşiği 3.0). En az yan etkili
    # düzeltme: yalnızca bu yüzeyi biraz koyulaştırmak — `accent`'e (birçok
    # başka geçen kontrastın bağlı olduğu token) HİÇ dokunmadan yeter.
    # Sonuç: accent/search_bg 3.07:1. topbar/hover/row_hover kasıtlı olarak
    # DEĞİŞMEDİ — yalnızca search_bg artık onlardan bir tık koyu.
    "search_bg": "#222224",
    "row_hover": "#2C2C2E",
    "green":     "#059669",
    "green_tint": "rgba(5, 150, 105, 0.14)",
    "red":       "#DC2626",
    "red_tint":  "rgba(220, 38, 38, 0.14)",
    "yellow":    "#D97706",
    "gray":      "#6B7280",
    "purple":    "#2563EB",
    "hcl_fg":    "#2563EB",
}


_LIGHT: dict[str, str] = {
    "bg":        "#F9FAFB",
    "sidebar":   "#FFFFFF",
    "topbar":    "#FFFFFF",
    "accent":    "#2563EB",
    "accent_hover":      "#1D4ED8",
    "accent_tint":       "#EFF6FF",
    "accent_tint_hover": "#DBEAFE",
    "on_accent":         "#FFFFFF",
    "tint_text":         "#111827",
    "text":      "#111827",
    # B-054 (2026-08-24): eskisi #9CA3AF, text/bg kontrastı 2.43:1 idi (AA
    # eşiği 3.0). Aynı gri tonun en yakın koyu tonuna çekildi — 3.11:1.
    # accent/bg/text'e dokunulmadı, "mavi" preset tanınabilir kaldı.
    #
    # B-054 takibi (2026-08-25): `subtext` gerçekte NEREDE kullanılıyor
    # diye tarandı (AdminPanel.py, dialog_kit.py, main_window_theme.py,
    # main_window_tree.py, RecoveryShareDialog.py, TimestampDialog.py) —
    # hepsi 11-12px DÜZ etiket metni, WCAG'ın "büyük metin" eşiğine
    # (18pt/24px normal ya da 14pt/18.66px kalın) hiçbiri girmiyor. Yani
    # bunlar normal küçük metin sınıfında ve gerçek eşik 3.0 değil 4.5:1
    # olmalıydı — 3.11:1 (yukarıdaki B-054 düzeltmesi) yetersizdi. `#898F9A`
    # → `#64707C`: aynı soğuk gri-mavi aile, yalnızca daha koyu.
    # accent/bg/text'e yine dokunulmadı.
    #   subtext/bg        : 3.11:1 → 4.84:1  (eşik: 4.5)
    #   subtext/search_bg : 2.95:1 → 4.60:1  (eşik: 4.5 — ayrıca B-057'nin
    #                        iki noktasından biri, bu düzeltmenin YAN ETKİSİ
    #                        olarak da kapandı, search_bg'ye hiç dokunulmadan)
    "subtext":   "#64707C",
    "nav_text":  "#374151",
    "border":    "#E5E7EB",
    "hover":     "#F3F4F6",
    "search_bg": "#F3F4F6",
    "row_hover": "#F0F9FF",
    "green":     "#059669",
    "green_tint": "rgba(5, 150, 105, 0.14)",
    "red":       "#DC2626",
    "red_tint":  "rgba(220, 38, 38, 0.14)",
    "yellow":    "#D97706",
    "gray":      "#6B7280",
    "purple":    "#2563EB",
    "hcl_fg":    "#2563EB",
}


# ── Eklenti preset'leri (Claude Design senkronu, 2026-08-22) ──────────────────
# `hycleus-tasarim-semasi.md`'nin teal/gold kararı — tek preset, hem koyu hem
# açık modu var. "Gold" (ikincil vurgu) ayrı bir token mimarisi açmak yerine
# mevcut `yellow` rolüne eşlendi — bilinçli kapsam daraltması, bkz. BACKLOG.
_TEAL_GOLD_DARK: dict[str, str] = {
    "bg":        "#0a0d12",
    "sidebar":   "#12161d",
    "topbar":    "#171c24",
    "accent":    "#57c8bd",
    "accent_hover":      "#3fada2",
    "accent_tint":       "rgba(87, 200, 189, 0.14)",
    "accent_tint_hover": "rgba(87, 200, 189, 0.24)",
    "on_accent":         "#04231f",
    "tint_text":         "#e7e7e2",
    "text":      "#e7e7e2",
    "subtext":   "#8b958f",
    "nav_text":  "#b9c4c2",
    "border":    "#232a35",
    "hover":     "#1b2129",
    "search_bg": "#171c24",
    "row_hover": "#1b2129",
    "green":     "#059669",
    "green_tint": "rgba(5, 150, 105, 0.14)",
    "red":       "#DC2626",
    "red_tint":  "rgba(220, 38, 38, 0.14)",
    "yellow":    "#e0b45c",
    "gray":      "#6B7280",
    "purple":    "#57c8bd",
    "hcl_fg":    "#57c8bd",
}


_TEAL_GOLD_LIGHT: dict[str, str] = {
    "bg":        "#f6f5f1",
    "sidebar":   "#ffffff",
    "topbar":    "#f0efe9",
    "accent":    "#0f7d6c",
    "accent_hover":      "#0b5c4f",
    "accent_tint":       "rgba(15, 125, 108, 0.06)",
    "accent_tint_hover": "rgba(15, 125, 108, 0.12)",
    "on_accent":         "#FFFFFF",
    "tint_text":         "#1c1f1a",
    "text":      "#1c1f1a",
    # B-063 (2026-08-25): B-054/B-057'nin "mavi"de bulduğu 11-12px küçük-metin
    # gerçeği (gerçek eşik 3.0 değil 4.5:1) bu preset'te de doğrulandı — aynı
    # paylaşılan bileşenler (AdminPanel.py, dialog_kit.py, main_window_theme.py
    # vb.) preset'e bakmaksızın aynı font-size'ı kullanıyor. Eskisi #6b7280,
    # subtext/bg 4.43:1 ve subtext/search_bg 4.20:1 idi — ikisi de 4.5'in
    # altında. Aynı gri-mavi aile, biraz koyulaştırıldı. accent/bg/text'e
    # dokunulmadı. Sonuç: subtext/bg 5.22:1, subtext/search_bg 4.95:1.
    "subtext":   "#606773",
    "nav_text":  "#4b5563",
    "border":    "#e3e1d9",
    "hover":     "#ece9e1",
    "search_bg": "#f0efe9",
    "row_hover": "#ece9e1",
    "green":     "#059669",
    "green_tint": "rgba(5, 150, 105, 0.08)",
    "red":       "#DC2626",
    "red_tint":  "rgba(220, 38, 38, 0.08)",
    "yellow":    "#a8722c",
    "gray":      "#6B7280",
    "purple":    "#0f7d6c",
    "hcl_fg":    "#0f7d6c",
}


# `theme_addons.py`'den (Claude Design projesi) — üç koyu-yalnızca preset.
# LOGIN_BRAND_PANEL'deki "v2.5 / AIR-GAPPED" metni BİLEREK taşınmadı: sürüm
# yanlıştı (gerçek 2.3.0) ve "air-gapped" doğrulanmamış bir güvenlik iddiası,
# SECURITY.md'yle çelişiyordu.
_AURORA_BOREALIS: dict[str, str] = {
    "bg":        "#0F1C1C",
    "sidebar":   "#132525",
    "topbar":    "#0F2020",
    "accent":    "#2DD4BF",
    "accent_hover":      "#5FE3D2",
    "accent_tint":       "rgba(45, 212, 191, 0.14)",
    "accent_tint_hover": "rgba(45, 212, 191, 0.22)",
    "on_accent":         "#04231F",
    "tint_text":         "#F0FDFA",
    "text":      "#F0FDFA",
    "subtext":   "#5F9E94",
    "nav_text":  "#99F6E4",
    "border":    "#1E3A3A",
    "hover":     "#172D2D",
    "search_bg": "#0F2020",
    "row_hover": "#172D2D",
    "green":     "#059669",
    "green_tint": "rgba(5, 150, 105, 0.14)",
    "red":       "#F08A7C",
    "red_tint":  "rgba(240, 138, 124, 0.14)",
    "yellow":    "#E9C46A",
    "gray":      "#6B7280",
    "purple":    "#2DD4BF",
    "hcl_fg":    "#2DD4BF",
}


_ABYSSAL_BLUE: dict[str, str] = {
    "bg":        "#0B132B",
    "sidebar":   "#1C2541",
    "topbar":    "#16203A",
    "accent":    "#48CAE4",
    "accent_hover":      "#00B4D8",
    "accent_tint":       "rgba(72, 202, 228, 0.14)",
    "accent_tint_hover": "rgba(72, 202, 228, 0.22)",
    "on_accent":         "#0B132B",
    "tint_text":         "#F0F8FF",
    "text":      "#F0F8FF",
    # B-063 (2026-08-25): aynı 11-12px küçük-metin denetimi bu preset'te de
    # doğrulandı, gerçek eşik 4.5:1. Eskisi #6A86A6, subtext/bg 4.88:1 idi
    # (geçiyordu) ama subtext/search_bg (AdminPanel/GuvenlikView kartları)
    # 4.28:1'di — search_bg (#16203A) bg'den (#0B132B) daha açık bir yüzey,
    # aynı ton orada yetmiyordu. Karanlık zeminde METİN olduğu için
    # KOYULAŞTIRMAK değil AÇIKLAŞTIRMAK gerekti — aynı mavi-gri aile, biraz
    # daha açık. accent/bg/text'e dokunulmadı. Sonuç: subtext/bg 5.66:1,
    # subtext/search_bg 4.96:1.
    "subtext":   "#7891AE",
    "nav_text":  "#8ECAE6",
    "border":    "#2A3A5E",
    "hover":     "#223056",
    "search_bg": "#16203A",
    "row_hover": "#223056",
    "green":     "#059669",
    "green_tint": "rgba(5, 150, 105, 0.14)",
    "red":       "#FF7A85",
    "red_tint":  "rgba(255, 122, 133, 0.14)",
    "yellow":    "#FFB703",
    "gray":      "#6B7280",
    "purple":    "#48CAE4",
    "hcl_fg":    "#48CAE4",
}


_GRAPHITE_AMBER: dict[str, str] = {
    "bg":        "#121316",
    "sidebar":   "#1A1C20",
    "topbar":    "#15171A",
    "accent":    "#D97706",
    "accent_hover":      "#F59E0B",
    "accent_tint":       "rgba(217, 119, 6, 0.08)",
    "accent_tint_hover": "rgba(217, 119, 6, 0.16)",
    "on_accent":         "#121316",
    "tint_text":         "#F3F4F6",
    "text":      "#F3F4F6",
    # B-063 (2026-08-25): aynı 11-12px küçük-metin denetimi bu preset'te de
    # doğrulandı, gerçek eşik 4.5:1. Eskisi #6B7280, subtext/bg 3.84:1 ve
    # subtext/search_bg 3.71:1 idi — ikisi de belirgin biçimde altındaydı
    # (yalnızca eski 3.0 eşiğini geçiyordu). Aynı nötr gri aile, açıklaştırıldı
    # (koyu zeminde metin). accent/bg/text'e dokunulmadı. Sonuç: subtext/bg
    # 4.93:1, subtext/search_bg 4.77:1.
    "subtext":   "#7C8492",
    "nav_text":  "#9CA3AF",
    "border":    "#2D3139",
    "hover":     "#20232A",
    "search_bg": "#15171A",
    "row_hover": "#20232A",
    "green":     "#059669",
    "green_tint": "rgba(5, 150, 105, 0.14)",
    "red":       "#EF4444",
    "red_tint":  "rgba(239, 68, 68, 0.14)",
    "yellow":    "#F59E0B",
    "gray":      "#6B7280",
    "purple":    "#D97706",
    "hcl_fg":    "#D97706",
}


# ── Arayüz güncellemesi turu (2026-08-26) — mockup'ın 11 temasından eksik 6'sı ──
# Mockup'ta 11 tema var; "Gece"/"Gün" mockup'ta varsayılan gibi görünse de
# ölçüldüğünde `_TEAL_GOLD_DARK`/`_TEAL_GOLD_LIGHT` ile TÜM anahtarlarda birebir
# aynı çıktı (bkz. BACKLOG) — o ikisi BİLEREK eklenmedi, teal_gold'un kopyası
# olurdu. "Aurora"/"Grafit" (mockup'ın yeni yarı saydam/gradyanlı temaları) adı
# zaten var olan `_AURORA_BOREALIS`/`_GRAPHITE_AMBER` (FARKLI renkler) ile
# çakışmasın diye "(Cam)" ekiyle ayırt edildi — menüde ikisi de görünecek.
#
# Mockup yalnızca `wall` (gradyan duvar kağıdı), `panel` (yarı saydam yüzey),
# `tx` (metin) ve `accent` veriyordu bu 4 tema için — QSS gerçek pencere
# saydamlığı desteklemediğinden `wall` şu turda UYGULANMADI (BÖLÜM B'ye
# ertelendi, orada gerçek arka plan widget'ları ele alınacak); `panel` burada
# koyu/açık bir taban rengin üzerine matematiksel olarak bindirilip DÜZ bir
# `sidebar` hex'ine çevrildi. `green`/`red`/`yellow` mockup'ta hiç verilmedi —
# `tests/test_tema_kontrasti.py`'nin WCAG AA eşiklerini (bkz. B-054/B-057/B-063)
# geçene kadar mevcut varsayılan tonlardan yalnızca gerektiği kadar koyultuldu.
_CAM: dict[str, str] = {
    "bg":        "#eef1f6",
    "sidebar":   "#fbfcfe",
    "topbar":    "#e6eaf2",
    "accent":    "#1d6fa5",
    "accent_hover":      "#175984",
    "accent_tint":       "rgba(29, 111, 165, 0.08)",
    "accent_tint_hover": "rgba(29, 111, 165, 0.16)",
    "on_accent":         "#FFFFFF",
    "tint_text":         "#161b22",
    "text":      "#161b22",
    "subtext":   "#626a7a",
    "nav_text":  "#4b5566",
    "border":    "#d7dde8",
    "hover":     "#c3cbda",
    "search_bg": "#e6eaf2",
    "row_hover": "#c3cbda",
    "green":     "#059669",
    "green_tint": "rgba(5, 150, 105, 0.08)",
    "red":       "#DC2626",
    "red_tint":  "rgba(220, 38, 38, 0.08)",
    "yellow":    "#cc7006",
    "gray":      "#6B7280",
    "purple":    "#1d6fa5",
    "hcl_fg":    "#1d6fa5",
}


_KLASIK: dict[str, str] = {
    "bg":        "#c8c6bd",
    "sidebar":   "#dedcd3",
    "topbar":    "#cfcdc4",
    "accent":    "#1c5d54",
    "accent_hover":      "#164a43",
    "accent_tint":       "rgba(28, 93, 84, 0.14)",
    "accent_tint_hover": "rgba(28, 93, 84, 0.24)",
    "on_accent":         "#FFFFFF",
    "tint_text":         "#1b1b18",
    "text":      "#1b1b18",
    "subtext":   "#51514c",
    "nav_text":  "#4a4a44",
    "border":    "#a9a79e",
    "hover":     "#8e8c83",
    "search_bg": "#cfcdc4",
    "row_hover": "#8e8c83",
    # green/red/yellow: mockup vermiyordu, bg orta tonlu (#c8c6bd) olduğu için
    # varsayılan tonlar AA'nın altında kalıyordu — üçü de koyultuldu.
    "green":     "#047653",
    "green_tint": "rgba(4, 118, 83, 0.08)",
    "red":       "#c22121",
    "red_tint":  "rgba(194, 33, 33, 0.08)",
    "yellow":    "#a55a05",
    "gray":      "#6B7280",
    "purple":    "#1c5d54",
    "hcl_fg":    "#1c5d54",
}


_AKRILIK: dict[str, str] = {
    "bg":        "#141a2e",
    "sidebar":   "#151b2c",
    "topbar":    "#111627",
    "accent":    "#7fd8cd",
    "accent_hover":      "#92ded4",
    "accent_tint":       "rgba(127, 216, 205, 0.14)",
    "accent_tint_hover": "rgba(127, 216, 205, 0.24)",
    "on_accent":         "#0b2420",
    "tint_text":         "#eceaf4",
    "text":      "#eceaf4",
    "subtext":   "#9aa0c4",
    "nav_text":  "#c3c8e8",
    "border":    "#3f4452",
    "hover":     "#2c3241",
    "search_bg": "#111627",
    "row_hover": "#2c3241",
    "green":     "#059669",
    "green_tint": "rgba(5, 150, 105, 0.14)",
    "red":       "#DC2626",
    "red_tint":  "rgba(220, 38, 38, 0.14)",
    "yellow":    "#D97706",
    "gray":      "#6B7280",
    "purple":    "#7fd8cd",
    "hcl_fg":    "#7fd8cd",
}


_AURORA_CAM: dict[str, str] = {
    "bg":        "#0b0f1a",
    "sidebar":   "#0b171f",
    "topbar":    "#090c15",
    "accent":    "#68e0c6",
    "accent_hover":      "#7fe5cf",
    "accent_tint":       "rgba(104, 224, 198, 0.14)",
    "accent_tint_hover": "rgba(104, 224, 198, 0.24)",
    "on_accent":         "#04231f",
    "tint_text":         "#e6f5f1",
    "text":      "#e6f5f1",
    "subtext":   "#8fb0a8",
    "nav_text":  "#b3d9cf",
    "border":    "#3c454c",
    "hover":     "#28333a",
    "search_bg": "#090c15",
    "row_hover": "#28333a",
    "green":     "#059669",
    "green_tint": "rgba(5, 150, 105, 0.14)",
    "red":       "#DC2626",
    "red_tint":  "rgba(220, 38, 38, 0.14)",
    "yellow":    "#D97706",
    "gray":      "#6B7280",
    "purple":    "#68e0c6",
    "hcl_fg":    "#68e0c6",
}


_GUN_BATIMI: dict[str, str] = {
    "bg":        "#ffd7b0",
    "sidebar":   "#ffefe0",
    "topbar":    "#ffebd8",
    "accent":    "#0f6f78",
    "accent_hover":      "#0c5960",
    "accent_tint":       "rgba(15, 111, 120, 0.08)",
    "accent_tint_hover": "rgba(15, 111, 120, 0.16)",
    "on_accent":         "#FFFFFF",
    "tint_text":         "#2a1c18",
    "text":      "#2a1c18",
    "subtext":   "#5c4a44",
    "nav_text":  "#4a3a35",
    "border":    "#d9cbbe",
    "hover":     "#ebdcce",
    "search_bg": "#ffebd8",
    "row_hover": "#ebdcce",
    # green: mockup vermiyordu, sıcak/açık bg'de varsayılan AA'nın altındaydı.
    "green":     "#058860",
    "green_tint": "rgba(5, 136, 96, 0.08)",
    "red":       "#DC2626",
    "red_tint":  "rgba(220, 38, 38, 0.08)",
    "yellow":    "#b86505",
    "gray":      "#6B7280",
    "purple":    "#0f6f78",
    "hcl_fg":    "#0f6f78",
}


_GRAFIT_CAM: dict[str, str] = {
    "bg":        "#1d1f22",
    "sidebar":   "#202225",
    "topbar":    "#191a1d",
    "accent":    "#8fd0c4",
    "accent_hover":      "#a0d7cd",
    "accent_tint":       "rgba(143, 208, 196, 0.14)",
    "accent_tint_hover": "rgba(143, 208, 196, 0.24)",
    "on_accent":         "#12211d",
    "tint_text":         "#e9e9e6",
    "text":      "#e9e9e6",
    "subtext":   "#9aa19d",
    "nav_text":  "#c2c7c4",
    "border":    "#484a4c",
    "hover":     "#36383b",
    "search_bg": "#191a1d",
    "row_hover": "#36383b",
    "green":     "#059669",
    "green_tint": "rgba(5, 150, 105, 0.14)",
    "red":       "#DC2626",
    "red_tint":  "rgba(220, 38, 38, 0.14)",
    "yellow":    "#D97706",
    "gray":      "#6B7280",
    "purple":    "#8fd0c4",
    "hcl_fg":    "#8fd0c4",
}


_SIDEBAR_NAV: list[tuple[str, str, str]] = [
    ("📁", "Genel",      "Genel"),
    ("🛡", "Kritik",     "Kritik"),
    ("🕐", "Karantina",  "Karantina"),
    ("🗑", "İmha Odası", "Imha"),
]


#: Anahtarlar KANONİK rol değeri (CORE/roles.py). Eskiden görünen ad
#: ("Yönetici") anahtardı ve kasada ASCII "Yonetici" yazan bir kullanıcı
#: rozetsiz kalıyordu — B-028'in görünür ama zararsız yüzü.
_ROLE_BADGE: dict[str, tuple[str, str]] = {
    ROL_YONETICI:    ("#DBEAFE", "#2563EB"),
    ROL_STANDART:    ("#D1FAE5", "#059669"),
    ROL_SALT_OKUNUR: ("#FEF3C7", "#D97706"),
}


_VERDICT_BADGE: dict[str, tuple[str, str]] = {
    "clean":      ("✓ Temiz",         "#059669"),
    "suspicious": ("⚠ Şüpheli",      "#D97706"),
    "malicious":  ("✗ Zararlı",       "#DC2626"),
    "unknown":    ("—",               "#9CA3AF"),
    "timeout":    ("⏱ Zaman Aşımı", "#D97706"),
}


_LABEL_PILL_STYLE: dict[str, tuple[str, str]] = {
    "Genel":     ("#059669", "#D1FAE5"),
    "Kritik":    ("#DC2626", "#FEE2E2"),
    "Karantina": ("#D97706", "#FEF3C7"),
    "Imha":      ("#6B7280", "#F3F4F6"),
}


_TAG_COLORS = ["#6366F1", "#EC4899", "#F59E0B", "#10B981", "#3B82F6", "#EF4444", "#8B5CF6"]


def _make_dot_pixmap(color: str, size: int = 8) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(QColor(color)))
    p.drawEllipse(0, 0, size, size)
    p.end()
    return pm
