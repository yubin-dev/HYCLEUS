"""
HYCLEUS — Tema seçici: kart grid (`UI/ThemePickerDialog.py`)

Eski `ThemeMixin._on_theme_menu()` düz metin bir `QMenu` açıyordu; şimdi
`ThemePickerDialog`'u açıyor — her kayıtlı tema kendi kartında, kendi
GERÇEK renk paletiyle canlı önizleniyor. Bu paket dört şeyi ölçüyor:

  1. Kayıt — `_THEMES`'te GERÇEKTEN 11 tema var mı (register_theme()
     kaydı; `UI/main_window_theme.py`'nin kendisi, elle tekrarlanmadan).
  2. Diyalog yapısı — tam 11 kart kuruluyor mu, her biri KENDİ preset'inin
     renklerini mi taşıyor (mutasyon kanıtı: iki farklı kart AYNI
     stylesheet'i üretmemeli).
  3. Seçim — bir karta "tıklamak" (`mousePressEvent` çağrısı, kodun
     kendi atadığı işleyiciyle) doğru anahtarı bildirip diyaloğu kapatıyor
     mu; şu an seçili olan tema doğru işaretleniyor mu.
  4. Uçtan uca — gerçek `HycleusWindow` üzerinde 11 temanın HEPSİ
     seçilebiliyor mu ve her biri `self._T`'ye DOĞRU token setini mi
     yazıyor (preset'in dark/light varyantıyla birebir eşit).
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QFrame, QWidget

    from UI.main_window import HycleusWindow
    from UI.main_window_palette import _DARK
    from UI.main_window_theme import _THEMES, available_themes
    from UI.ThemePickerDialog import ThemePickerDialog
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

_HWID = "TEMA-SECICI-TEST"
_KEY = b"K" * 32

#: Mockup'ın 11 teması — register_theme() kaydının TAM olarak bu kümeyi
#: içermesi gerekiyor. Arayüz güncellemesi (2026-08-26, `4b07486`) ilk 5'e
#: (mavi/teal_gold/aurora_borealis/abyssal_blue/graphite_amber) eksik 6'yı
#: (cam/klasik/akrilik/aurora_cam/gun_batimi/grafit_cam) ekledi.
_BEKLENEN_TEMA_ANAHTARLARI = frozenset({
    "mavi", "teal_gold", "aurora_borealis", "abyssal_blue", "graphite_amber",
    "cam", "klasik", "akrilik", "aurora_cam", "gun_batimi", "grafit_cam",
})


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


@pytest.fixture
def isolate_safezone(tmp_path, monkeypatch: pytest.MonkeyPatch):
    from CORE.safezone import SAFEZONE_ENV_VAR

    hedef = tmp_path / "safezone"
    monkeypatch.setenv(SAFEZONE_ENV_VAR, str(hedef))
    return hedef


@pytest.fixture
def win(qapp, db, isolate_safezone, monkeypatch: pytest.MonkeyPatch):
    """Gerçek `HycleusWindow` — `tests/test_main_window_smoke.py`'nin
    aynı fikstürü (izole DB, sahte USB, teardown'da zamanlayıcı/olay
    filtresi temizliği)."""
    from UI import main_window as mw

    monkeypatch.setattr(mw, "get_usb_hwid", lambda: _HWID)
    window = HycleusWindow(hwid=_HWID, key=_KEY, role="Yönetici")
    try:
        yield window
    finally:
        for ad in ("_usb_timer", "_expiry_timer", "_idle_timer"):
            zamanlayici = getattr(window, ad, None)
            if zamanlayici is not None:
                zamanlayici.stop()
        app = QApplication.instance()
        if app is not None:
            app.removeEventFilter(window)
        window.close()


def _kartlari_bul(dlg: ThemePickerDialog) -> dict[str, QFrame]:
    return {
        k.property("theme_key"): k
        for k in dlg.findChildren(QFrame, "tema_karti")
    }


# ══════════════════════════════════════════════════════════════════════════════
# 1. Kayıt — register_theme() GERÇEKTEN 11 temayı içeriyor mu
# ══════════════════════════════════════════════════════════════════════════════


def test_tam_11_tema_kayitli():
    assert len(_THEMES) == 11, f"beklenen 11, bulunan {len(_THEMES)}: {sorted(_THEMES)}"
    assert set(_THEMES.keys()) == _BEKLENEN_TEMA_ANAHTARLARI


def test_available_themes_THEMES_ile_tutarli():
    """`available_themes()` (menü/diyalog listesi) ile `_THEMES` (asıl
    kayıt) aynı anahtar kümesini, aynı sırada döndürmeli."""
    liste_anahtarlari = [key for key, _ in available_themes()]
    assert liste_anahtarlari == list(_THEMES.keys())


@pytest.mark.parametrize("key", sorted(_BEKLENEN_TEMA_ANAHTARLARI))
def test_her_temanin_dark_varyanti_tam_token_setine_sahip(key: str):
    """Her preset'in `dark` varyantı `_DARK`'la (referans şema) AYNI
    anahtar kümesini taşımalı — eksik bir anahtar `self._T[...]` okuyan
    bir yerde sessiz bir `KeyError`'a yol açardı."""
    preset = _THEMES[key]
    assert set(preset["dark"].keys()) == set(_DARK.keys()), (
        f"{key}: dark varyantının anahtar kümesi referanstan farklı"
    )
    if preset["light"] is not None:
        assert set(preset["light"].keys()) == set(_DARK.keys()), (
            f"{key}: light varyantının anahtar kümesi referanstan farklı"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 2. Diyalog yapısı — 11 kart, her biri KENDİ paletini taşıyor
# ══════════════════════════════════════════════════════════════════════════════


def test_diyalogda_tam_11_kart_var(qapp):
    dlg = ThemePickerDialog(
        None, T=_DARK, theme_key="mavi", dark=True, on_select=lambda k: None,
    )
    try:
        kartlar = _kartlari_bul(dlg)
        assert len(kartlar) == 11
        assert set(kartlar.keys()) == _BEKLENEN_TEMA_ANAHTARLARI
    finally:
        dlg.close()


def test_farkli_kartlarin_onizlemesi_FARKLI_renkte(qapp):
    """Mutasyon kanıtı: iki farklı temanın önizleme şeridi AYNI
    stylesheet'i üretmemeli — üretiyorsa kart kendi preset'i yerine
    (ör. yanlışlıkla) aktif temanın rengini gösteriyor demektir."""
    dlg = ThemePickerDialog(
        None, T=_DARK, theme_key="mavi", dark=True, on_select=lambda k: None,
    )
    try:
        kartlar = _kartlari_bul(dlg)
        onizleme_mavi = kartlar["mavi"].findChild(QWidget, "tema_onizleme")
        onizleme_grafit = kartlar["graphite_amber"].findChild(QWidget, "tema_onizleme")
        assert onizleme_mavi is not None and onizleme_grafit is not None
        assert onizleme_mavi.styleSheet() != onizleme_grafit.styleSheet(), (
            "İki farklı temanın önizlemesi aynı — kart kendi paletini göstermiyor olabilir"
        )
    finally:
        dlg.close()


def test_koyu_yalniz_preset_HER_ZAMAN_kendi_koyu_paletini_gosterir(qapp):
    """`aurora_borealis` (koyu-yalnızca) — diyalog açık modda çağrılsa
    bile (`dark=False`) önizlemesi DEĞİŞMEMELİ, çünkü `_set_theme()`'in
    kendisi de bu preset'i seçince `self._dark`'ı zorla `True` yapıyor
    (bkz. `UI/main_window_theme.py::_set_theme`)."""
    dlg_koyu = ThemePickerDialog(
        None, T=_DARK, theme_key="mavi", dark=True, on_select=lambda k: None,
    )
    dlg_acik = ThemePickerDialog(
        None, T=_DARK, theme_key="mavi", dark=False, on_select=lambda k: None,
    )
    try:
        onizleme_koyu = _kartlari_bul(dlg_koyu)["aurora_borealis"].findChild(
            QWidget, "tema_onizleme"
        )
        onizleme_acik = _kartlari_bul(dlg_acik)["aurora_borealis"].findChild(
            QWidget, "tema_onizleme"
        )
        assert onizleme_koyu.styleSheet() == onizleme_acik.styleSheet()
    finally:
        dlg_koyu.close()
        dlg_acik.close()


# ══════════════════════════════════════════════════════════════════════════════
# 3. Seçim — tıklama doğru anahtarı bildiriyor, mevcut seçim işaretli
# ══════════════════════════════════════════════════════════════════════════════


def test_secili_tema_karti_ISARETLI_digerleri_degil(qapp):
    dlg = ThemePickerDialog(
        None, T=_DARK, theme_key="graphite_amber", dark=True, on_select=lambda k: None,
    )
    try:
        kartlar = _kartlari_bul(dlg)
        assert kartlar["graphite_amber"].property("secili") is True
        for key, kart in kartlar.items():
            if key != "graphite_amber":
                assert kart.property("secili") is False, f"{key} yanlışlıkla seçili işaretli"
    finally:
        dlg.close()


def test_karta_tiklamak_secimi_bildirir_ve_diyalogu_kapatir(qapp):
    from PySide6.QtWidgets import QDialog

    secilenler: list[str] = []
    dlg = ThemePickerDialog(
        None, T=_DARK, theme_key="mavi", dark=True, on_select=secilenler.append,
    )
    try:
        hedef = _kartlari_bul(dlg)["graphite_amber"]
        hedef.mousePressEvent(None)
        assert secilenler == ["graphite_amber"]
        assert dlg.result() == QDialog.Accepted
    finally:
        dlg.close()


def test_kapat_dugmesi_secim_bildirmeden_reddeder(qapp):
    from PySide6.QtWidgets import QDialog, QPushButton

    secilenler: list[str] = []
    dlg = ThemePickerDialog(
        None, T=_DARK, theme_key="mavi", dark=True, on_select=secilenler.append,
    )
    try:
        kapat_dugmesi = dlg.findChild(QPushButton, "tema_secici_kapat")
        assert kapat_dugmesi is not None
        kapat_dugmesi.click()
        assert secilenler == []
        assert dlg.result() == QDialog.Rejected
    finally:
        dlg.close()


# ══════════════════════════════════════════════════════════════════════════════
# 4. Uçtan uca — gerçek HycleusWindow, 11 temanın HEPSİ doğru token setini uyguluyor
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("key", sorted(_BEKLENEN_TEMA_ANAHTARLARI))
def test_gercek_pencerede_her_tema_dogru_token_setini_uyguluyor(win, key: str):
    win._set_theme(key)
    preset = _THEMES[key]
    beklenen = preset["dark"] if win._dark else preset["light"]
    assert win._T == beklenen, f"{key}: uygulanan token seti preset'le eşleşmiyor"
    assert win._theme_key == key


def test_gercek_pencerede_koyu_yalniz_tema_secilince_dark_True_olur(win):
    win._dark = False
    win._set_theme("aurora_borealis")
    assert win._dark is True
    assert win._T == _THEMES["aurora_borealis"]["dark"]


def test_tema_secici_ACILIS_dogru_kwargs_ile_kuruluyor(win, monkeypatch: pytest.MonkeyPatch):
    """`_on_theme_menu()` gerçekten `ThemePickerDialog`'u pencerenin GÜNCEL
    `_T`/`_theme_key`/`_dark`'ıyla kuruyor mu — yerel içe aktarım deseni
    (`from UI.ThemePickerDialog import ThemePickerDialog`) sahte bir
    sınıfla monkeypatch edilerek doğrulanıyor (`.exec()` GERÇEKTEN
    çağrılmadan, başsız bir testte sonsuza kadar bloklamasın diye)."""
    import UI.ThemePickerDialog as tpd

    cagrilar: list[dict] = []

    class _SahteDialog:
        def __init__(self, parent=None, **kwargs):
            cagrilar.append(kwargs)

        def exec(self):
            cagrilar.append({"exec": True})

    monkeypatch.setattr(tpd, "ThemePickerDialog", _SahteDialog)

    win._set_theme("cam")
    win._on_theme_menu()

    assert len(cagrilar) == 2
    kurulum, exec_cagrisi = cagrilar
    assert kurulum["theme_key"] == "cam"
    assert kurulum["dark"] == win._dark
    assert kurulum["T"] == win._T
    assert exec_cagrisi == {"exec": True}


# ══════════════════════════════════════════════════════════════════════════════
# 5. Küçük pencerede taşma — 11 kart hâlâ erişilebilir mi (scroll ile)
# ══════════════════════════════════════════════════════════════════════════════


def test_kucuk_pencerede_TUM_kartlar_scroll_ile_erisilebilir(qapp):
    """Diyalog kendi asgari boyutuna (`setMinimumSize(560, 420)` —
    `ThemePickerDialog.__init__`) küçültülünce 11 kart 3 sütun × 4 satır
    hâlinde bu alana sığmıyor. Otomatik testlerin çoğu bu tür görsel
    taşmayı yakalamaz (widget'lar `assert kartlar` düzeyinde "var" olur,
    ekranda gerçekten görünüp görünmediği ayrı bir soru) — burada GERÇEK
    widget geometrisini (`sizeHint`, `viewport`, scrollbar menzili)
    ölçüyoruz."""
    from PySide6.QtWidgets import QScrollArea

    dlg = ThemePickerDialog(
        None, T=_DARK, theme_key="mavi", dark=True, on_select=lambda k: None,
    )
    try:
        dlg.resize(dlg.minimumSize())
        dlg.show()

        # 1) Tüm 11 kart, görünür viewport'tan bağımsız, hâlâ ağaçta —
        #    layout onları GİZLEMİYOR/YOK ETMİYOR, sadece taşırıyor.
        kartlar = _kartlari_bul(dlg)
        assert len(kartlar) == 11

        scroll = dlg.findChild(QScrollArea, "tema_secici_scroll")
        assert scroll is not None
        icerik = scroll.widget()
        assert icerik is not None

        # 2) İçerik gerçekten viewport'tan uzun mu — asgari boyutta taşma
        #    GERÇEKTEN var mı, yoksa 11 kart zaten sığıyor mu. Test bunu
        #    varsaymıyor, ölçüyor; sığıyorsa aşağıdaki kaydırma iddiaları
        #    anlamsız kalır ve bu assert onu açıkça bildirir.
        assert icerik.sizeHint().height() > scroll.viewport().height(), (
            "içerik viewport'tan uzun değil — bu test asgari boyutta taşma "
            "olduğunu varsayıyordu; artık sığıyorsa kart sayısı/boyutu "
            "değişmiş olabilir, test verisini gözden geçir"
        )

        # 3) Taşma VARSA, dikey kaydırma çubuğunun bunu telafi edecek
        #    menzili olmalı — yani en alttaki kart bile kaydırılarak
        #    erişilebilir, sessizce kaybolmuyor.
        dikey = scroll.verticalScrollBar()
        assert dikey.maximum() > 0, "içerik taşıyor ama kaydırma çubuğunun menzili yok"

        # 4) Her kart hâlâ makul bir geometriye sahip (0 boyuta
        #    sıkıştırılıp fiilen görünmez hâle GETİRİLMEMİŞ).
        for key, kart in kartlar.items():
            assert kart.width() > 0 and kart.height() > 0, f"{key}: kart geometrisi sıfır"
    finally:
        dlg.close()
