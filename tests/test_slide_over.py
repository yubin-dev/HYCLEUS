"""
UI/main_window_layout.py — slide-over paneli.

Tasarım brief'i: "doğrulama ve ayar ekranları slide-over panel veya
inline sekme olarak açılır, yeni pencere açmaz." Bu tur YALNIZCA
`TimestampDialog` ve `BackupVerifyDialog`'u bu mekanizmaya taşıdı.
AdminPanel bilerek dışarıda (kendi turu); `RecoveryShareDialog` bilerek
modal kalıyor (tek gösterimlik, dikkat gerektiren akış).

Üç şey ölçülüyor
----------------
1. YAPISAL (AST) — "iki çağıran, tek gövde" burada da geçerli: her
   diyalog TEK yerden kuruluyor ve o TEK yer aynı fonksiyonda
   `_open_slide_over()`'ı da çağırıyor. Eski `.exec()` yolu geri
   gelmemeli.
2. MEKANİZMA — panel açıkken `centralWidget()` gerçekten devre dışı
   kalıyor mu, kapanınca gerçekten açılıyor mu; kilit mekanizmasıyla
   (`main_window_lock.py`) aynı anahtarı (`centralWidget`) paylaştığı
   için ikisinin birbirinin korumasını YANLIŞLIKLA kaldırmadığı.
3. ESC — panel açıkken kapatıyor, kapalıyken hiçbir şey yapmıyor, olayı
   YUTMUYOR (hareketsizlik sayacı `main_window_lock.py::LockMixin`
   üzerinden Esc'i yine bir etkinlik olarak görebilsin diye).
"""
from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QEvent, Qt, Signal
    from PySide6.QtGui import QKeyEvent
    from PySide6.QtWidgets import QApplication, QMainWindow, QWidget

    from UI.main_window_layout import LayoutMixin
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

KOK = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


class _Pencere(LayoutMixin, QMainWindow):
    """
    Slide-over mekanizmasının dokunduğu asgari yüzey.

    Tam `_build_ui()` KURULMUYOR: o, GuvenlikView/tablo/kenar çubuğu gibi
    bu paketin ölçmediği çok şey ister. Mekanizmanın kendisi yalnızca
    `centralWidget()`, `width()/height()/rect()` ve (varsa) `self._T`'a
    dokunuyor.
    """

    def __init__(self) -> None:
        super().__init__()
        self._locked = False
        self.setCentralWidget(QWidget())
        self.resize(1200, 800)
        # `.isVisible()` ana pencere `.show()` edilmeden GÜVENİLMEZ (offscreen
        # platformda bile) — `_slide_over_acik()` bu yüzden kendi bayrağını
        # tutuyor, ama widget'ın GERÇEKTEN gösterilip gösterilmediğini de
        # ölçebilmek için pencereyi burada gösteriyoruz.
        self.show()


class _Icerik(QWidget):
    """`kapat_istendi` taşıyan asgari içerik — `TimestampDialog` gövdesinin yerine."""

    kapat_istendi = Signal()


@pytest.fixture
def pencere(qapp) -> _Pencere:
    return _Pencere()


def _kaynak(yol: str) -> str:
    return (KOK / yol).read_text(encoding="utf-8")


def _cagri_adlari(kaynak: str, fonksiyon: str | None = None) -> set[str]:
    """Kaynaktaki (ya da tek bir fonksiyondaki) çağrı adları."""
    agac: ast.AST = ast.parse(kaynak)
    if fonksiyon:
        adaylar = [n for n in ast.walk(agac)
                   if isinstance(n, ast.FunctionDef) and n.name == fonksiyon]
        assert adaylar, f"{fonksiyon} bulunamadı"
        agac = adaylar[0]
    return {
        (d.func.attr if isinstance(d.func, ast.Attribute) else
         d.func.id if isinstance(d.func, ast.Name) else "")
        for d in ast.walk(agac) if isinstance(d, ast.Call)
    }


def _kurulum_yerleri(sinif_adi: str, kendi_dosyasi: str) -> list[str]:
    """`sinif_adi(...)` çağrısının UI/*.py içinde HANGİ dosyalarda geçtiği."""
    yerler: list[str] = []
    for yol in sorted((KOK / "UI").glob("*.py")):
        if yol.name == kendi_dosyasi:
            continue
        if sinif_adi in _cagri_adlari(yol.read_text(encoding="utf-8")):
            yerler.append(yol.name)
    return yerler


# ══════════════════════════════════════════════════════════════════════════════
# 1. İki çağıran, tek gövde — yapısal (AST)
# ══════════════════════════════════════════════════════════════════════════════


def test_TimestampDialog_TEK_yerden_kuruluyor() -> None:
    """
    İkinci bir kuruluş yeri, `_open_slide_over()`'ı atlayan ikinci bir
    "aç" yolu demek olurdu — bu deponun beş kez ürettiği kusur
    (B-004/B-008, B-007, B-010, B-011, pay ayrıştırıcı).
    """
    assert _kurulum_yerleri("TimestampDialog", "TimestampDialog.py") == [
        "main_window_files.py"
    ]


def test_BackupVerifyDialog_TEK_yerden_kuruluyor() -> None:
    assert _kurulum_yerleri("BackupVerifyDialog", "BackupVerifyDialog.py") == [
        "main_window_open.py"
    ]


def test_damga_kurulumu_ayni_fonksiyonda_panele_aciliyor() -> None:
    """
    Kuran fonksiyon AYNI fonksiyonda `_open_slide_over(` de çağırmalı —
    kurup sonra eski `.exec()` ile ayrı bir pencere açan yol geri gelmesin.
    """
    cagrilar = _cagri_adlari(
        _kaynak("UI/main_window_files.py"), "_on_ctx_verify_timestamp"
    )
    assert "TimestampDialog" in cagrilar
    assert "_open_slide_over" in cagrilar
    assert "exec" not in cagrilar, "eski .exec() yolu geri gelmiş"


def test_yedek_kurulumu_ayni_fonksiyonda_panele_aciliyor() -> None:
    cagrilar = _cagri_adlari(
        _kaynak("UI/main_window_open.py"), "_on_verify_backup"
    )
    assert "BackupVerifyDialog" in cagrilar
    assert "_open_slide_over" in cagrilar
    assert "exec" not in cagrilar, "eski .exec() yolu geri gelmiş"


def test_RecoveryShareDialog_HALA_modal() -> None:
    """
    Görev bilerek `RecoveryShareDialog`'u dışarıda bıraktı: tek
    gösterimlik, dikkat gerektiren bir akış. Hâlâ `QDialog` ve hâlâ
    `.exec()` ile açılıyor — panele TAŞINMADIĞINI sabitliyor.
    """
    assert "class RecoveryShareDialog(QDialog)" in _kaynak("UI/RecoveryShareDialog.py")
    assert "RecoveryShareDialog" in _cagri_adlari(_kaynak("UI/AdminSettingsView.py"))


def test_eventFilter_olayi_YUTMUYOR() -> None:
    """
    `eventFilter` Esc'i kapatıp `super()`'a devretmeli — YUTMAMALI.
    Yutsaydı `main_window_lock.py::LockMixin.eventFilter`'ın hareketsizlik
    sayacı Esc'i bir ETKİNLİK olarak hiç göremezdi (MRO: LayoutMixin önce,
    bkz. `UI/main_window.py::HycleusWindow`).
    """
    agac = ast.parse(_kaynak("UI/main_window_layout.py"))
    fonksiyon = next(
        n for n in ast.walk(agac)
        if isinstance(n, ast.FunctionDef) and n.name == "eventFilter"
    )
    govde = ast.get_source_segment(_kaynak("UI/main_window_layout.py"), fonksiyon)
    assert "super().eventFilter" in govde


def test_resizeEvent_ana_pencereye_devrediyor() -> None:
    """
    `main_window_table.py::TableMixin.resizeEvent` kilit örtüsünü pencere
    boyutuna göre yeniden konumluyor. `LayoutMixin.resizeEvent` MRO'da
    ondan ÖNCE geliyor — zincirlemezse örtü artık yeniden boyutlanmaz.
    """
    agac = ast.parse(_kaynak("UI/main_window_layout.py"))
    fonksiyon = next(
        n for n in ast.walk(agac)
        if isinstance(n, ast.FunctionDef) and n.name == "resizeEvent"
    )
    govde = ast.get_source_segment(_kaynak("UI/main_window_layout.py"), fonksiyon)
    assert "super().resizeEvent" in govde


# ══════════════════════════════════════════════════════════════════════════════
# 2. Mekanizma — panel açıkken ana pencere etkileşimi
# ══════════════════════════════════════════════════════════════════════════════


def test_acilinca_ayni_govde_panele_yerlesiyor(pencere: _Pencere) -> None:
    icerik = _Icerik()
    pencere._open_slide_over("Test Başlığı", icerik)

    assert pencere._slide_over.isVisible()
    assert pencere._slide_over._icerik is icerik, "panel FARKLI bir gövde gösteriyor"
    assert icerik.parent() is not None


def test_acilinca_ana_pencere_KILITLENIYOR(pencere: _Pencere) -> None:
    assert pencere.centralWidget().isEnabled()
    pencere._open_slide_over("Test", _Icerik())
    assert not pencere.centralWidget().isEnabled(), (
        "panel açıkken ana pencere hâlâ tıklanabilir"
    )


def test_kapaninca_ana_pencere_ACILIYOR(pencere: _Pencere) -> None:
    pencere._open_slide_over("Test", _Icerik())
    pencere._close_slide_over()
    assert not pencere._slide_over.isVisible()
    assert pencere.centralWidget().isEnabled()


def test_kapat_istendi_sinyali_paneli_kapatiyor(pencere: _Pencere) -> None:
    """İçeriğin kendi "Kapat" düğmesi de paneli kapatabilmeli."""
    icerik = _Icerik()
    pencere._open_slide_over("Test", icerik)
    icerik.kapat_istendi.emit()
    assert not pencere._slide_over.isVisible()


def test_kilit_AKTIFKEN_panel_kapansa_bile_ana_pencere_ACILMIYOR(
    pencere: _Pencere,
) -> None:
    """
    `main_window_lock.py::LockMixin._unlock()` ile PAYLAŞILAN durum: USB/
    hareketsizlik kilidi devredeyken panel kapansa bile `centralWidget()`
    açılmamalı — o korumayı yalnızca `LockMixin._unlock()` kaldırabilir.
    """
    pencere._open_slide_over("Test", _Icerik())
    pencere._locked = True  # LockMixin'in gerçek davranışını simüle ediyor
    pencere._close_slide_over()
    assert not pencere._slide_over.isVisible(), "panel yine de kapanmalı"
    assert not pencere.centralWidget().isEnabled(), (
        "kilit aktifken panel central'ı YANLIŞLIKLA açtı"
    )


def test_kilitliyken_panel_ACILMIYOR(pencere: _Pencere) -> None:
    """
    Kilit aktifken zaten central devre dışı olduğu için kullanıcı bu
    metoda giden hiçbir düğmeye (sağ tık menüsü, Güvenlik sekmesi)
    tıklayamaz — yine de tek satırlık bir koruma var (z-sırası yarışına,
    panelin kilit örtüsünün ÜSTÜNE çıkmasına hiç girmesin diye).
    """
    pencere._locked = True
    pencere._open_slide_over("Test", _Icerik())
    assert getattr(pencere, "_slide_over", None) is None


def test_unlock_panel_ACIKKEN_central_i_ACMIYOR(qapp) -> None:
    """
    Ters yönden AYNI yarış: panel açıkken bir USB/hareketsizlik kilidi
    kalkarsa, `LockMixin._unlock()` `centralWidget()`'ı YANLIŞLIKLA
    açmamalı — o korumayı panel yönetiyor.
    """
    from UI.main_window_lock import LockMixin

    class _SahteOrtu:
        def set_message(self, *a, **k):
            pass

        def hide(self):
            pass

    class _KilitliPencere(LockMixin, QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setCentralWidget(QWidget())
            self._lock_reasons: set[str] = {"usb"}
            self._locked = True
            self._overlay = _SahteOrtu()

        def _slide_over_acik(self) -> bool:
            return True  # panel açık gibi davran

    p = _KilitliPencere()
    p.centralWidget().setEnabled(False)
    p._unlock("usb")
    assert not p.centralWidget().isEnabled(), (
        "_unlock() panel açıkken central'ı açtı"
    )


def test_unlock_panel_YOKKEN_normal_calisiyor(qapp) -> None:
    """Karşı taraf: panel mekanizması hiç kurulmamışsa `_unlock()` eskisi
    gibi çalışmalı — yeni `getattr` koruması davranışı DEĞİŞTİRMEMELİ."""
    from UI.main_window_lock import LockMixin

    class _SahteOrtu:
        def set_message(self, *a, **k):
            pass

        def hide(self):
            pass

    class _KilitliPencere(LockMixin, QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setCentralWidget(QWidget())
            self._lock_reasons: set[str] = {"usb"}
            self._locked = True
            self._overlay = _SahteOrtu()

    p = _KilitliPencere()
    p.centralWidget().setEnabled(False)
    p._unlock("usb")
    assert p.centralWidget().isEnabled()


# ══════════════════════════════════════════════════════════════════════════════
# 3. Esc davranışı
# ══════════════════════════════════════════════════════════════════════════════


def _esc_olayi() -> QKeyEvent:
    return QKeyEvent(QEvent.KeyPress, Qt.Key_Escape, Qt.NoModifier)


def test_esc_panel_acikken_kapatiyor(pencere: _Pencere) -> None:
    pencere._open_slide_over("Test", _Icerik())
    pencere.eventFilter(pencere, _esc_olayi())
    assert not pencere._slide_over.isVisible()


def test_esc_panel_KAPALIYKEN_hicbir_sey_yapmiyor(pencere: _Pencere) -> None:
    sonuc = pencere.eventFilter(pencere, _esc_olayi())
    assert sonuc is False  # QMainWindow'un varsayılanına düşüyor
    assert getattr(pencere, "_slide_over", None) is None


def test_baska_tus_panel_acikken_KAPATMIYOR(pencere: _Pencere) -> None:
    pencere._open_slide_over("Test", _Icerik())
    baska_tus = QKeyEvent(QEvent.KeyPress, Qt.Key_A, Qt.NoModifier)
    pencere.eventFilter(pencere, baska_tus)
    assert pencere._slide_over.isVisible()
