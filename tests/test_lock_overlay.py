"""
HYCLEUS — Kilit örtüsü ve kilit-nedeni mantığı testleri (Qt)

Bu paket, hareketsizlik kilidinin Qt tarafından test EDİLEBİLEN kısmını
kapsıyor. Zamanlama kararı CORE'da ve tests/test_idle_lock.py'de sınanıyor;
burada sınanan şey iki tetikleyicinin tek örtüyü nasıl paylaştığı.

Neden bu kısım test ediliyor
----------------------------
Kilit NEDENLERİ kümesi, tasarımın en kolay yanlış yapılabilecek yeri: tek
bir `_locked` bayrağıyla yazılsaydı, hareketsizlik kilidi devredeyken USB
geri takıldığında `_unlock()` her iki kilidi birden kaldırırdı — yani
masasından uzaktaki kullanıcının oturumu, USB'yi takan kişiye açılırdı.
Bu sınıf bir hata değil, bir açık olurdu; dolayısıyla iddia edilmekle
kalmayıp doğrulanması gerekiyor.

QApplication offscreen platformda kuruluyor (ekran gerekmiyor), ama yine de
PySide6 olmayan bir ortamda paket tümüyle atlanıyor.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Qt import'ları TEK bir korumanın altında.
#
# `importorskip("PySide6")` YETMİYOR: paket kurulu olsa bile alt modüller
# sistem kütüphanelerine bağlı (libEGL.so.1, libxkbcommon) ve çıplak bir
# Linux runner'ında `from PySide6.QtGui import ...` ImportError veriyor.
# Modül seviyesinde patlayan bir import, pytest'te ATLAMA değil TOPLAMA
# HATASI olur (çıkış kodu 2) ve CI'ı kırar — nitekim 297327f'te Ubuntu ayağı
# tam olarak böyle kırıldı.
#
# Bu yüzden UI import'u da dahil hepsi aynı blokta ve hata modül seviyesinde
# atlamaya çevriliyor. Windows (asıl hedef platform) tam koşuyor.
try:
    from PySide6.QtCore import QEvent, QPointF, Qt
    from PySide6.QtGui import QMouseEvent
    from PySide6.QtWidgets import QApplication, QWidget

    from UI.main_window import _ACTIVITY_EVENTS, HycleusWindow, _LockOverlay
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def qapp():
    """
    Offscreen QApplication.

    PySide6 kurulu olsa bile QApplication her ortamda AYAĞA KALKMAYABİLİR:
    çıplak bir Linux runner'ında libEGL / libxkbcommon gibi sistem
    kütüphaneleri bulunmaz ve offscreen platform bile yüklenemez. Bu
    durumda paket atlanıyor — asıl hedef platform Windows ve orada
    çalışıyor. Kırmak yerine atlamak, CI'ın Ubuntu ayağını Qt sistem
    kütüphanelerine bağımlı hâle getirmemek için.
    """
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


@pytest.fixture
def overlay(qapp):
    # yield ile: `host` üretici çerçevesinde canlı kalıyor. return edilseydi
    # ebeveyn çöp toplanır ve C++ tarafında çocuk örtü de onunla silinirdi.
    host = QWidget()
    host.resize(800, 600)
    yield _LockOverlay(host)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Örtü
# ══════════════════════════════════════════════════════════════════════════════


def test_overlay_starts_hidden(overlay):
    assert overlay.isHidden()


def test_overlay_defaults_to_the_usb_message(overlay):
    assert "USB" in overlay._title.text()


def test_set_message_switches_both_lines(overlay):
    overlay.set_message("Oturum Kilitlendi", "PIN girin")
    assert overlay._title.text() == "Oturum Kilitlendi"
    assert overlay._sub.text() == "PIN girin"


def test_overlay_emits_clicked_on_mouse_press(overlay):
    tiklandi = []
    overlay.clicked.connect(lambda: tiklandi.append(True))

    olay = QMouseEvent(
        QEvent.MouseButtonPress, QPointF(10, 10), QPointF(10, 10),
        Qt.LeftButton, Qt.LeftButton, Qt.NoModifier,
    )
    overlay.mousePressEvent(olay)
    assert tiklandi == [True]


# ══════════════════════════════════════════════════════════════════════════════
# 2. Kilit nedenleri — iki tetikleyici, tek örtü
# ══════════════════════════════════════════════════════════════════════════════
#
# _lock/_unlock, HycleusWindow'un tam kurulumuna (DB, anahtar, USB) bağlı
# olmayan saf durum mantığı. Bu yüzden gerçek metotlar, aynı alanlara sahip
# hafif bir sahne üzerinde çalıştırılıyor: test edilen KOD gerçek, yalnızca
# etrafındaki pencere kurulumu atlanıyor.


class _Sahne:
    """_lock/_unlock'un dokunduğu asgari yüzey."""

    _LOCK_MESSAGES = HycleusWindow._LOCK_MESSAGES
    _lock = HycleusWindow._lock
    _unlock = HycleusWindow._unlock

    def __init__(self, qapp):
        self._central = QWidget()
        self._central.resize(800, 600)
        self._overlay = _LockOverlay(self._central)
        self._blur = None
        self._locked = False
        self._lock_reasons: set[str] = set()

    # HycleusWindow API'sinin _lock/_unlock tarafından kullanılan kısmı
    def centralWidget(self):
        return self._central

    def size(self):
        return self._central.size()


@pytest.fixture
def sahne(qapp):
    return _Sahne(qapp)


def test_usb_lock_shows_the_usb_message(sahne):
    sahne._lock("usb")
    assert sahne._locked
    assert not sahne._overlay.isHidden()
    assert "USB" in sahne._overlay._title.text()
    assert sahne.centralWidget().isEnabled() is False


def test_idle_lock_shows_the_idle_message(sahne):
    sahne._lock("idle")
    assert "Hareketsizlik" in sahne._overlay._sub.text()
    assert "USB" not in sahne._overlay._title.text()


def test_single_reason_unlocks_normally(sahne):
    sahne._lock("usb")
    sahne._unlock("usb")
    assert sahne._locked is False
    assert sahne._overlay.isHidden()
    assert sahne.centralWidget().isEnabled() is True


def test_usb_unlock_does_not_clear_an_idle_lock(sahne):
    """
    ASIL SENARYO: kullanıcı masasından uzakta (idle kilit), bu arada USB
    çekilip geri takılıyor. Oturum AÇILMAMALI.
    """
    sahne._lock("idle")
    sahne._lock("usb")

    sahne._unlock("usb")          # USB geri takıldı

    assert sahne._locked is True
    assert not sahne._overlay.isHidden()
    assert sahne.centralWidget().isEnabled() is False
    assert sahne._lock_reasons == {"idle"}


def test_remaining_reason_message_is_shown_after_partial_unlock(sahne):
    """Örtü kalkmıyorsa kullanıcı NEDEN kilitli olduğunu görebilmeli."""
    sahne._lock("idle")
    sahne._lock("usb")
    assert "USB" in sahne._overlay._title.text()

    sahne._unlock("usb")
    assert "Hareketsizlik" in sahne._overlay._sub.text()


def test_idle_unlock_does_not_clear_a_usb_lock(sahne):
    """Simetrik durum: PIN girildi ama USB hâlâ çıkık."""
    sahne._lock("usb")
    sahne._lock("idle")

    sahne._unlock("idle")

    assert sahne._locked is True
    assert sahne._lock_reasons == {"usb"}
    assert "USB" in sahne._overlay._title.text()


def test_both_reasons_cleared_unlocks(sahne):
    sahne._lock("usb")
    sahne._lock("idle")
    sahne._unlock("usb")
    sahne._unlock("idle")
    assert sahne._locked is False
    assert sahne._overlay.isHidden()
    assert sahne._lock_reasons == set()


def test_unlocking_an_absent_reason_is_harmless(sahne):
    """_poll_usb, kilitli olmasa da _unlock('usb') çağırabiliyor."""
    sahne._unlock("usb")
    assert sahne._locked is False
    assert sahne._lock_reasons == set()


def test_repeated_lock_with_the_same_reason_is_idempotent(sahne):
    sahne._lock("idle")
    sahne._lock("idle")
    assert sahne._lock_reasons == {"idle"}
    sahne._unlock("idle")
    assert sahne._locked is False


# ══════════════════════════════════════════════════════════════════════════════
# 3. Aktivite olay kümesi
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("olay", [
    QEvent.MouseButtonPress, QEvent.MouseMove, QEvent.KeyPress,
    QEvent.KeyRelease, QEvent.Wheel,
])
def test_real_interaction_counts_as_activity(olay):
    assert olay in _ACTIVITY_EVENTS


@pytest.mark.parametrize("olay", [
    QEvent.Timer, QEvent.Paint, QEvent.UpdateRequest,
    QEvent.WindowActivate, QEvent.Resize, QEvent.Move,
])
def test_non_interaction_events_do_not_count_as_activity(olay):
    """
    Zamanlayıcı ve boyama olayları sayaç sıfırlamamalı.

    Sayılsalardı ekranda dönen bir ilerleme çubuğu, saatlik zamanlayıcı ya
    da yalnızca açık duran bir pencere oturumu sonsuza kadar açık tutardı —
    kilit hiç devreye girmezdi.
    """
    assert olay not in _ACTIVITY_EVENTS
