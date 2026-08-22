"""HYCLEUS — Tema preset'lerinin WCAG AA kontrastı

`UI/main_window_theme.py`'nin preset-registry'sindeki (`_THEMES`) her tema,
her varyantta (koyu / açık, varsa) okunabilir kalmalı. İki eşik kullanılır:

* 4.5:1 — asıl okunacak metin: gövde metni (`text`), accent dolgu üzerindeki
  metin (`on_accent`), aktif/seçili satır metni (`accent` veya `tint_text`
  kendi tint arka planı üzerinde).
* 3.0:1 — ikincil/loşlaştırılmış metin (`subtext`, `nav_text`) — bunlar
  bilerek düşük vurgulu 11-12px etiketler, WCAG'ın büyük metin / UI bileşeni
  eşiğiyle karşılaştırılır.

`accent_tint` / `accent_tint_hover` bazı preset'lerde yarı saydam
(`rgba(...)`) — gerçek göründüğü yüzeyin (sidebar/bg/topbar) üzerine
bindirilip öyle karşılaştırılır.

Kapsam dışı: AdminPanel/GuvenlikView/RecoveryShareDialog preset sistemine
BAĞLI DEĞİL (`self._T` hiç kullanmıyorlar — bkz. 2026-08-22 tasarım-senkronu
raporu), dolayısıyla preset değişince görünümleri değişmiyor. Bu dosya bu
yüzden onları preset başına test ETMEZ; yalnızca AdminPanel'in kendi
sabit QDialog {background, color} çiftini bir kere doğrular (GuvenlikView ve
RecoveryShareDialog kendi başına bir arka plan bildirmiyor, ortam/varsayılan
Qt paletiyle çiziliyor — statik bir token testiyle anlamlı şekilde
karşılaştırılamaz).
"""
from __future__ import annotations

import pytest

try:
    from UI.main_window_theme import _THEMES
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )


def _hex_to_rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip("#")
    return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))


def _resolve_rgb(color: str, base_hex: str) -> tuple[int, int, int]:
    """`color` düz hex ise direkt, `rgba(...)` ise `base_hex` üzerine bindirip döner."""
    color = color.strip()
    if color.startswith("rgba"):
        r, g, b, a = (float(p) for p in color[color.index("(") + 1 : color.index(")")].split(","))
        br, bg, bb = _hex_to_rgb(base_hex)
        return (
            round(r * a + br * (1 - a)),
            round(g * a + bg * (1 - a)),
            round(b * a + bb * (1 - a)),
        )
    return _hex_to_rgb(color)


def _srgb_channel_to_linear(c: int) -> float:
    c = c / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def _relative_luminance(rgb: tuple[int, int, int]) -> float:
    r, g, b = (_srgb_channel_to_linear(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg: str, bg: str, base_hex: str) -> float:
    """WCAG kontrast oranı. `fg`/`bg` hex ya da rgba(...) olabilir; rgba ise
    `base_hex` üzerine bindirilerek çözümlenir (gerçekte göründüğü gibi)."""
    l1 = _relative_luminance(_resolve_rgb(fg, base_hex))
    l2 = _relative_luminance(_resolve_rgb(bg, base_hex))
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


_AA_TEXT = 4.5
_AA_MUTED = 3.0


def _variant_cases() -> list[tuple[str, str, dict[str, str]]]:
    cases = []
    for key, preset in _THEMES.items():
        cases.append((key, "dark", preset["dark"]))
        if preset["light"] is not None:
            cases.append((key, "light", preset["light"]))
    return cases


@pytest.mark.parametrize("key,variant,T", _variant_cases(), ids=lambda v: v if isinstance(v, str) else "")
def test_govde_metni_okunabilir(key, variant, T):
    assert contrast_ratio(T["text"], T["bg"], T["bg"]) >= _AA_TEXT, f"{key}/{variant}: text/bg"
    assert contrast_ratio(T["text"], T["sidebar"], T["sidebar"]) >= _AA_TEXT, f"{key}/{variant}: text/sidebar"
    assert contrast_ratio(T["text"], T["topbar"], T["topbar"]) >= _AA_TEXT, f"{key}/{variant}: text/topbar"


# "mavi" (mevcut varsayılan) preset'inin `subtext` rengi bu senkrondan ÖNCE
# de #9CA3AF'ti ve açık modda bg'ye karşı zaten 3:1'in altında (2.43) —
# bu görev "mevcut mavi"yi geriye dönük uyumluluk için birebir korumayı
# istiyor, dolayısıyla bilinen/önceden var olan bu durum burada SESSİZCE
# düzeltilmiyor; yalnızca kaydı tutuluyor.
_ONCEDEN_VAR_OLAN_ISTISNALAR = {("mavi", "light", "subtext_bg")}


@pytest.mark.parametrize("key,variant,T", _variant_cases(), ids=lambda v: v if isinstance(v, str) else "")
def test_ikincil_metin_ayirt_edilebilir(key, variant, T):
    if (key, variant, "subtext_bg") not in _ONCEDEN_VAR_OLAN_ISTISNALAR:
        assert contrast_ratio(T["subtext"], T["bg"], T["bg"]) >= _AA_MUTED, f"{key}/{variant}: subtext/bg"
    assert contrast_ratio(T["nav_text"], T["sidebar"], T["sidebar"]) >= _AA_MUTED, f"{key}/{variant}: nav_text/sidebar"


@pytest.mark.parametrize("key,variant,T", _variant_cases(), ids=lambda v: v if isinstance(v, str) else "")
def test_accent_dolgu_uzerindeki_metin_okunabilir(key, variant, T):
    # btn_primary, avatar, progress_banner — hepsi accent dolgu + on_accent metin
    assert contrast_ratio(T["on_accent"], T["accent"], T["accent"]) >= _AA_TEXT, f"{key}/{variant}: on_accent/accent"


@pytest.mark.parametrize("key,variant,T", _variant_cases(), ids=lambda v: v if isinstance(v, str) else "")
def test_aktif_satir_okunabilir(key, variant, T):
    # nav/tag/folder aktif satırı: accent_tint arka plan (sidebar üzerine
    # bindirilir), üzerindeki metin T['accent'] rengiyle yazılır.
    tint_on_sidebar = _resolve_rgb(T["accent_tint"], T["sidebar"])
    accent_rgb = _hex_to_rgb(T["accent"]) if T["accent"].startswith("#") else _resolve_rgb(T["accent"], T["sidebar"])
    ratio = (
        max(_relative_luminance(accent_rgb), _relative_luminance(tint_on_sidebar)) + 0.05
    ) / (min(_relative_luminance(accent_rgb), _relative_luminance(tint_on_sidebar)) + 0.05)
    assert ratio >= _AA_TEXT, f"{key}/{variant}: accent/accent_tint(sidebar)"

    # Tablo seçili satırı: accent_tint arka plan (bg üzerine bindirilir),
    # üzerindeki metin T['tint_text'].
    tint_on_bg = _resolve_rgb(T["accent_tint"], T["bg"])
    text_rgb = _hex_to_rgb(T["tint_text"])
    ratio2 = (
        max(_relative_luminance(text_rgb), _relative_luminance(tint_on_bg)) + 0.05
    ) / (min(_relative_luminance(text_rgb), _relative_luminance(tint_on_bg)) + 0.05)
    assert ratio2 >= _AA_TEXT, f"{key}/{variant}: tint_text/accent_tint(bg)"


@pytest.mark.parametrize("key,variant,T", _variant_cases(), ids=lambda v: v if isinstance(v, str) else "")
def test_durum_renkleri_zeminde_secilebilir(key, variant, T):
    # Dosya tablosunda aciliyet rengi (green/red/yellow) doğrudan T['bg']
    # üzerine metin rengi olarak basılıyor (main_window_table.py).
    for status_key in ("green", "red", "yellow"):
        assert contrast_ratio(T[status_key], T["bg"], T["bg"]) >= _AA_MUTED, (
            f"{key}/{variant}: {status_key}/bg"
        )


def test_admin_panel_sabit_paleti_okunabilir():
    """AdminPanel preset sistemine bağlı değil (kendi QDialog {...} bloğu
    var) — bu, preset seçiminden bağımsız TEK bir sabit doğrulama."""
    assert contrast_ratio("#cdd6f4", "#1e1e2e", "#1e1e2e") >= _AA_TEXT
