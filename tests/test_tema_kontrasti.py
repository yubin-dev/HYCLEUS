"""HYCLEUS — Tema preset'lerinin WCAG AA kontrastı

`UI/main_window_theme.py`'nin preset-registry'sindeki (`_THEMES`) her tema,
her varyantta (koyu / açık, varsa) okunabilir kalmalı. İki eşik kullanılır:

* 4.5:1 — asıl okunacak metin: gövde metni (`text`), accent dolgu üzerindeki
  metin (`on_accent`), aktif/seçili satır metni (`accent` veya `tint_text`
  kendi tint arka planı üzerinde). B-054/B-057/B-063 (2026-08-24/25):
  `subtext` da BURAYA taşındı — kod taraması (`AdminPanel.py`,
  `dialog_kit.py`, `main_window_theme.py`, `main_window_tree.py`,
  `RecoveryShareDialog.py`) gösterdi ki hep 11-12px DÜZ etiket metni,
  WCAG'ın büyük-metin eşiğine hiç girmiyor — "ikincil" olması onu büyük
  metin yapmıyor. 5 preset'in (10 varyant) hepsinde ölçülüp gerektiğinde
  düzeltildi (bkz. `UI/main_window_palette.py`'deki B-054/B-057/B-063
  yorumları).
* 3.0:1 — yalnızca `nav_text` (kenar çubuğu menü metni) — bu da 11-12px
  ama ayrı denetlenmedi, `subtext`'inkiyle aynı varsayımı miras alıyor
  olabilir; kapsam dışı bırakıldı (bkz. BACKLOG).

`accent_tint` / `accent_tint_hover` bazı preset'lerde yarı saydam
(`rgba(...)`) — gerçek göründüğü yüzeyin (sidebar/bg/topbar) üzerine
bindirilip öyle karşılaştırılır.

B-055 (2026-08-22): AdminPanel/GuvenlikView/RecoveryShareDialog artık
`self._T` kullanıyor — bu dosyanın ikinci yarısı üçünü de kapsıyor. İki
katman ölçülüyor:

  1. KONTRAST — gerçek preset değerleriyle WCAG AA (aynı fonksiyonlar).
  2. MUTASYON KANITI — bir ekranın stil fonksiyonu iki FARKLI preset'le
     çağrılıp çıktı karşılaştırılıyor. Biri sabit bir hex'e geri
     dönerse (örn. `background: #1e1e2e` T'siz yazılırsa) çıktı artık
     preset'ten bağımsız hâle gelir ve bu eşitsizlik testi düşer —
     kontrast testleri tek başına bunu YAKALAYAMAZDI, çünkü sabit bir
     rengin KENDİSİ hâlâ AA'yı geçebilir.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from UI.main_window_theme import _THEMES
    from UI import AdminPanel as _AP
    from UI import dialog_kit as _dk
    from UI.main_window_palette import _DARK, _LIGHT, _GRAPHITE_AMBER
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


# Tarihsel not: bu küme bir zamanlar üç istisna taşıyordu (B-054/B-057) —
# "mavi" preset'in birebir korunması istendiği için sessizce atlanıyorlardı,
# yutulmuyor, yalnızca kaydı tutuluyordu:
#
#   subtext/bg           — B-054, 2026-08-24'te DÜZELTİLDİ.
#   subtext/search_bg    — B-057, 2026-08-25'te DÜZELTİLDİ (B-054'ün
#                           takibinde `subtext`'i 4.5:1'e çekmenin YAN
#                           ETKİSİ — bkz. main_window_palette.py).
#   accent/search_bg     — B-057, 2026-08-25'te DÜZELTİLDİ (`search_bg`
#                           koyulaştırıldı, `accent`'e dokunulmadı).
#
# Üçü de kapandı, küme artık BOŞ. Mekanizma (ve `_istisna_disinda`) bir
# sonraki preset/yüzey kombinasyonu AA'nın altında çıkarsa aynı "sessizce
# yutma, kaydını tut" deseni tekrar kullanılabilsin diye kasıtlı olarak
# duruyor — boş bir küme yeniden dolabilir, silinmiyor.
_ONCEDEN_VAR_OLAN_ISTISNALAR: set[tuple[str, str, str]] = set()


def _istisna_disinda(key: str, variant: str, ad: str) -> bool:
    return (key, variant, ad) not in _ONCEDEN_VAR_OLAN_ISTISNALAR


@pytest.mark.parametrize("key,variant,T", _variant_cases(), ids=lambda v: v if isinstance(v, str) else "")
def test_ikincil_metin_ayirt_edilebilir(key, variant, T):
    # B-054/B-057/B-063: subtext'in gerçek eşiği 4.5 (yukarıdaki modül
    # docstring'ine bkz.) — `nav_text` denetlenmedi, 3.0'da bırakıldı.
    if _istisna_disinda(key, variant, "subtext_bg"):
        assert contrast_ratio(T["subtext"], T["bg"], T["bg"]) >= _AA_TEXT, f"{key}/{variant}: subtext/bg"
    assert contrast_ratio(T["nav_text"], T["sidebar"], T["sidebar"]) >= _AA_MUTED, f"{key}/{variant}: nav_text/sidebar"


def test_b054_mavi_acik_subtext_duzeltildi():
    """B-054: "mavi" açık modun subtext/bg kontrastı artık AA'yı (3.0) geçiyor.

    Eski değer (#9CA3AF, 2.43:1) bilerek burada sabit tutuluyor — biri bu
    düzeltmeyi geri alırsa (subtext'i eski griye döndürürse) bu test düşer.
    """
    yeni = _LIGHT["subtext"]
    eski = "#9CA3AF"
    bg = _LIGHT["bg"]

    assert contrast_ratio(yeni, bg, bg) >= _AA_MUTED, (
        f"mavi/light: subtext({yeni})/bg hâlâ AA'nın altında"
    )
    assert contrast_ratio(eski, bg, bg) < _AA_MUTED, (
        "eski subtext değeri artık AA'yı geçiyor gibi görünüyor — "
        "bu testin referans değeri güncel değil"
    )
    assert yeni != eski, "subtext hâlâ eski (düzeltilmemiş) griye eşit"


def test_b054_takibi_subtext_gercekte_kucuk_metin_4_5_esigini_geciyor():
    """B-054 takibi (2026-08-25): `subtext` 3.0 DEĞİL 4.5:1'i karşılamalı.

    Kod taraması: `_LIGHT["subtext"]` (ve `_DARK["subtext"]`, aynı anahtar
    adı tüm preset'lerde okunuyor) şu dosyalarda hep 11-12px DÜZ etiket
    metni olarak kullanılıyor — hiçbiri WCAG'ın büyük-metin eşiğine
    (18pt/24px normal, 14pt/18.66px kalın) girmiyor:

      UI/AdminPanel.py:249            (sekme metni, 12px varsayılan)
      UI/AdminPanel.py:271            font-size:12px
      UI/dialog_kit.py:57,63,64       font-size: 11px
      UI/main_window_tree.py:96       font-size:11px
      UI/RecoveryShareDialog.py:279   font-size:12px

    Yani proje kararı olan "subtext'e 3.0 (büyük metin/UI) eşiği
    uygulanır" varsayımı gerçek kullanımla UYUŞMUYOR — bu normal küçük
    metin, 4.5:1 gerektiriyor. Bu test yalnızca "mavi" (varsayılan)
    preset'i düzeltir; diğer 4 preset'in `subtext`'i denetlenmedi
    (bkz. BACKLOG B-063).
    """
    bg = _LIGHT["bg"]
    search_bg = _LIGHT["search_bg"]
    yeni = _LIGHT["subtext"]
    eski_b054 = "#898F9A"     # B-054'ün ARA değeri — 3.0'ı geçer, 4.5'i geçmez
    eski_orijinal = "#9CA3AF"  # B-054'ten önceki değer

    assert contrast_ratio(yeni, bg, bg) >= _AA_TEXT, (
        f"mavi/light: subtext({yeni})/bg 4.5:1'in altında"
    )
    assert contrast_ratio(yeni, search_bg, search_bg) >= _AA_TEXT, (
        f"mavi/light: subtext({yeni})/search_bg 4.5:1'in altında"
    )
    assert contrast_ratio(eski_b054, bg, bg) < _AA_TEXT, (
        "B-054 ARA değeri artık 4.5:1'i geçiyor gibi görünüyor — "
        "bu testin referans değeri güncel değil"
    )
    assert contrast_ratio(eski_orijinal, bg, bg) < _AA_TEXT, (
        "orijinal değer artık 4.5:1'i geçiyor gibi görünüyor — "
        "bu testin referans değeri güncel değil"
    )
    assert yeni not in (eski_b054, eski_orijinal)


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


@pytest.mark.parametrize("key,variant,T", _variant_cases(), ids=lambda v: v if isinstance(v, str) else "")
def test_search_bg_yuzeyinde_metin_okunabilir(key, variant, T):
    # AdminPanel tablosu, GuvenlikView kartı, RecoveryShareDialog base32
    # kutusu, dialog_kit "kutu" — hepsi search_bg'yi metin taşıyan bir
    # yüzey olarak kullanıyor (B-055).
    assert contrast_ratio(T["text"], T["search_bg"], T["search_bg"]) >= _AA_TEXT, (
        f"{key}/{variant}: text/search_bg"
    )
    if _istisna_disinda(key, variant, "subtext_search_bg"):
        assert contrast_ratio(T["subtext"], T["search_bg"], T["search_bg"]) >= _AA_TEXT, (
            f"{key}/{variant}: subtext/search_bg"
        )


@pytest.mark.parametrize("key,variant,T", _variant_cases(), ids=lambda v: v if isinstance(v, str) else "")
def test_accent_metin_olarak_zeminde_okunabilir(key, variant, T):
    # AdminPanel: tablo başlıkları, bölüm başlıkları, kendi HWID'inin
    # vurgusu — accent burada bir dolgu değil, DOĞRUDAN metin rengi.
    assert contrast_ratio(T["accent"], T["bg"], T["bg"]) >= _AA_MUTED, (
        f"{key}/{variant}: accent/bg (metin)"
    )
    if _istisna_disinda(key, variant, "accent_search_bg"):
        assert contrast_ratio(T["accent"], T["search_bg"], T["search_bg"]) >= _AA_MUTED, (
            f"{key}/{variant}: accent/search_bg (metin)"
        )


def test_b057_mavi_koyu_accent_search_bg_duzeltildi():
    """B-057: "mavi" koyu modun accent/search_bg kontrastı artık AA'yı (3.0) geçiyor.

    `accent`'e HİÇ dokunulmadı (birçok başka geçen kontrast ona bağlı) —
    yalnızca `search_bg` biraz koyulaştırıldı (`#2C2C2E` → `#222224`).
    Eski değer burada bilerek sabit tutuluyor — biri `search_bg`'yi eski
    tona döndürürse bu test düşer.
    """
    accent = _DARK["accent"]
    yeni_search_bg = _DARK["search_bg"]
    eski_search_bg = "#2C2C2E"

    assert contrast_ratio(accent, yeni_search_bg, yeni_search_bg) >= _AA_MUTED, (
        f"mavi/dark: accent/search_bg({yeni_search_bg}) hâlâ AA'nın altında"
    )
    assert contrast_ratio(accent, eski_search_bg, eski_search_bg) < _AA_MUTED, (
        "eski search_bg değeri artık AA'yı geçiyor gibi görünüyor — "
        "bu testin referans değeri güncel değil"
    )
    assert yeni_search_bg != eski_search_bg, "search_bg hâlâ eski (düzeltilmemiş) tona eşit"


@pytest.mark.parametrize("key,variant,T", _variant_cases(), ids=lambda v: v if isinstance(v, str) else "")
def test_renkli_tint_uzerinde_kendi_rengi_okunabilir(key, variant, T):
    # RecoveryShareDialog uyarı kutusu (red/red_tint), AdminPanel
    # tehlike/başarı butonları (red/red_tint, green/green_tint).
    for renk, tint in (("red", "red_tint"), ("green", "green_tint")):
        tint_on_bg = _resolve_rgb(T[tint], T["bg"])
        renk_rgb = _hex_to_rgb(T[renk])
        ratio = (
            max(_relative_luminance(renk_rgb), _relative_luminance(tint_on_bg)) + 0.05
        ) / (min(_relative_luminance(renk_rgb), _relative_luminance(tint_on_bg)) + 0.05)
        assert ratio >= _AA_MUTED, f"{key}/{variant}: {renk}/{tint}(bg)"


# ══════════════════════════════════════════════════════════════════════════════
# Mutasyon kanıtı — AdminPanel/dialog_kit/RecoveryShareDialog/GuvenlikView
# gerçekten T'den okuyor mu (B-055)
# ══════════════════════════════════════════════════════════════════════════════
#
# Her fonksiyon iki BAMBAŞKA preset'le ("mavi" koyu ve "Grafit & Kehribar")
# çağrılıyor ve çıktılar EŞİT OLMAMALI. Biri sabit bir hex'e geri dönerse
# (T parametresi görmezden gelinirse) iki çağrı da AYNI dizeyi üretir ve bu
# eşitlik testi düşürür — kontrast testleri bunu yakalayamaz, çünkü sabit
# bırakılan bir renk hâlâ AA eşiğini geçebilir.

_A, _B = _DARK, _GRAPHITE_AMBER


def test_mutasyon_admin_panel_stil_fonksiyonlari_T_ye_bagli():
    assert _AP._stil(_A) != _AP._stil(_B)
    assert _AP._btn_stil(_A) != _AP._btn_stil(_B)
    assert _AP._btn_danger_stil(_A) != _AP._btn_danger_stil(_B)
    assert _AP._btn_success_stil(_A) != _AP._btn_success_stil(_B)


def test_mutasyon_dialog_kit_T_ye_bagli():
    assert _dk.rapor_stili(_A) != _dk.rapor_stili(_B)
    assert _dk.varsayilan_gorunum(_A) != _dk.varsayilan_gorunum(_B)


def test_mutasyon_admin_panel_ornek_metotlari_T_ye_bagli():
    """Sınıf metotları (`_tab_stili` vb.) yalnızca `self._T` okuyor —
    doğrudan çağırmak için tam bir dialog kurmaya gerek yok, sahte bir
    `self` (yalnızca `_T` taşıyan) yeterli."""
    class _SahteOzben:
        pass

    ozben_a, ozben_b = _SahteOzben(), _SahteOzben()
    ozben_a._T, ozben_b._T = _A, _B

    assert _AP.AdminPanel._tab_stili(ozben_a) != _AP.AdminPanel._tab_stili(ozben_b)
    assert _AP.AdminPanel._combo_stili(ozben_a) != _AP.AdminPanel._combo_stili(ozben_b)
    assert (_AP.AdminPanel._bolum_baslik_stili(ozben_a)
            != _AP.AdminPanel._bolum_baslik_stili(ozben_b))
    assert _AP.AdminPanel._ipucu_stili(ozben_a) != _AP.AdminPanel._ipucu_stili(ozben_b)
    assert _AP.AdminPanel._liste_stili(ozben_a) != _AP.AdminPanel._liste_stili(ozben_b)


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    return app


@pytest.fixture
def isolate_safezone(tmp_path, monkeypatch: pytest.MonkeyPatch):
    from CORE.safezone import SAFEZONE_ENV_VAR

    hedef = tmp_path / "safezone"
    monkeypatch.setenv(SAFEZONE_ENV_VAR, str(hedef))
    return hedef


def test_mutasyon_admin_panel_dialog_gercekten_farkli_boyaniyor(qapp, db):
    """Uçtan uca: iki AYRI preset'le kurulan gerçek `AdminPanel`
    penceresinin kendi stylesheet'i farklı olmalı.

    `db` fixture'ı ZORUNLU: onsuz `_load()` DB'ye erişemez, hata
    `QMessageBox.warning(...)` ile gösterilmeye çalışılır ve bu, başsız
    bir testte tıklayacak kimse olmadığı için SONSUZA KADAR bloklar."""
    a = _AP.AdminPanel(current_hwid="X", role="Yönetici", T=_A)
    b = _AP.AdminPanel(current_hwid="X", role="Yönetici", T=_B)
    try:
        assert a.styleSheet() != b.styleSheet()
        assert a._mode_combo.styleSheet() != b._mode_combo.styleSheet()
    finally:
        a.close()
        b.close()


def test_mutasyon_recovery_share_dialog_gercekten_farkli_boyaniyor(qapp):
    from PySide6.QtWidgets import QLabel
    from CORE.recovery_share import build_export
    from UI.RecoveryShareDialog import RecoveryShareDialog

    disa_aktarim = build_export("3:" + "ab" * 33)
    a = RecoveryShareDialog(disa_aktarim, None, T=_A)
    b = RecoveryShareDialog(disa_aktarim, None, T=_B)
    try:
        assert a.styleSheet() != b.styleSheet()

        uyari_a = a.findChild(QLabel, "kurtarma_uyari")
        uyari_b = b.findChild(QLabel, "kurtarma_uyari")
        assert uyari_a.styleSheet() != uyari_b.styleSheet()

        koruma_a = a.findChild(QLabel, "kurtarma_koruma_durumu")
        koruma_b = b.findChild(QLabel, "kurtarma_koruma_durumu")
        assert koruma_a.styleSheet() != koruma_b.styleSheet()
    finally:
        a.close()
        b.close()


def test_mutasyon_guvenlik_view_qss_T_ye_bagli(qapp, db, isolate_safezone, monkeypatch):
    """GuvenlikView'in kendi widget'ları hiç setStyleSheet() çağırmıyor —
    tamamı `main_window_theme.py`'nin merkezi QSS'inden cascade ediyor
    (bkz. `#guvenlik_*` seçicileri). Bu yüzden mutasyon kanıtı merkezi
    stylesheet üzerinden: iki preset arasında geçince o QSS'in
    guvenlik-özel kısmı değişmeli."""
    from UI import main_window as mw

    monkeypatch.setattr(mw, "get_usb_hwid", lambda: "MUTASYON-HWID")
    window = mw.HycleusWindow(hwid="MUTASYON-HWID", key=b"K" * 32, role="Yönetici")
    try:
        window._set_theme("mavi")
        qss_mavi = window.centralWidget().styleSheet()
        window._set_theme("graphite_amber")
        qss_grafit = window.centralWidget().styleSheet()

        assert "guvenlik_kart" in qss_mavi and "guvenlik_kart" in qss_grafit
        assert qss_mavi != qss_grafit

        def _guvenlik_bolumu(qss: str) -> str:
            return qss[qss.index("guvenlik_view"):]

        assert _guvenlik_bolumu(qss_mavi) != _guvenlik_bolumu(qss_grafit), (
            "Güvenlik sekmesinin QSS bölümü preset değişince aynı kaldı"
        )
    finally:
        for ad in ("_usb_timer", "_expiry_timer", "_idle_timer"):
            getattr(window, ad).stop()
        from PySide6.QtWidgets import QApplication
        QApplication.instance().removeEventFilter(window)
        window.close()
