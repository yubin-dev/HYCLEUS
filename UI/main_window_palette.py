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
_DARK: dict[str, str] = {
    "bg":        "#1C1C1E",
    "sidebar":   "#1C1C1E",
    "topbar":    "#2C2C2E",
    "accent":    "#2563EB",
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
