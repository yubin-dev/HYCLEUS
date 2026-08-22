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
    "search_bg": "#2C2C2E",
    "row_hover": "#2C2C2E",
    "green":     "#059669",
    "red":       "#DC2626",
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
    "subtext":   "#9CA3AF",
    "nav_text":  "#374151",
    "border":    "#E5E7EB",
    "hover":     "#F3F4F6",
    "search_bg": "#F3F4F6",
    "row_hover": "#F0F9FF",
    "green":     "#059669",
    "red":       "#DC2626",
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
    "red":       "#DC2626",
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
    "subtext":   "#6b7280",
    "nav_text":  "#4b5563",
    "border":    "#e3e1d9",
    "hover":     "#ece9e1",
    "search_bg": "#f0efe9",
    "row_hover": "#ece9e1",
    "green":     "#059669",
    "red":       "#DC2626",
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
    "red":       "#F08A7C",
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
    "subtext":   "#6A86A6",
    "nav_text":  "#8ECAE6",
    "border":    "#2A3A5E",
    "hover":     "#223056",
    "search_bg": "#16203A",
    "row_hover": "#223056",
    "green":     "#059669",
    "red":       "#FF7A85",
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
    "subtext":   "#6B7280",
    "nav_text":  "#9CA3AF",
    "border":    "#2D3139",
    "hover":     "#20232A",
    "search_bg": "#15171A",
    "row_hover": "#20232A",
    "green":     "#059669",
    "red":       "#EF4444",
    "yellow":    "#F59E0B",
    "gray":      "#6B7280",
    "purple":    "#D97706",
    "hcl_fg":    "#D97706",
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
    "clean":      ("✓ Temiz",    "#059669"),
    "suspicious": ("⚠ Şüpheli", "#D97706"),
    "malicious":  ("✗ Zararlı",  "#DC2626"),
    "unknown":    ("—",          "#9CA3AF"),
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
