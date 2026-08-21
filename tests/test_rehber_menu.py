"""
Kullanım rehberinin İKİNCİ erişim yolu: hamburger menüsü.

Bu paket yalnızca DAVRANIŞI ölçüyor — "menüde madde var mı, doğru
işleyiciye bağlı mı" soruları Qt gerektirmiyor ve
`tests/test_rehber_kopyalari.py`'de AST ile yanıtlanıyor. Buradaki soru
şu: madde tıklandığında GERÇEKTEN doğru hedef açılıyor mu.

Ayrım önemli: yapısal denetim doğru fonksiyonun çağrıldığını gösterir ama
yanlış argümanla çağırmayı görmez.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

# QApplication kurulmadan ÖNCE — diğer Qt test dosyalarındaki desen (B-046).
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from CORE import rehber

# Qt ve UI TEK korumanın altında: modül seviyesinde patlayan bir import
# ATLAMA değil TOPLAMA HATASI olur ve paketin tamamını durdurur (B-047).
try:
    from PySide6.QtCore import QUrl
    from PySide6.QtGui import QDesktopServices
    from PySide6.QtWidgets import QApplication, QMessageBox, QWidget

    from UI.main_window import HycleusWindow
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def qapp():  # type: ignore[no-untyped-def]
    uygulama = QApplication.instance() or QApplication([])
    yield uygulama


@pytest.fixture
def acilanlar(monkeypatch: pytest.MonkeyPatch) -> list[QUrl]:
    """`QDesktopServices.openUrl` çağrılarını yakalar; hiçbir şey açılmaz."""
    kayit: list[QUrl] = []

    def _yakala(url: QUrl) -> bool:
        kayit.append(url)
        return True

    monkeypatch.setattr(QDesktopServices, "openUrl", staticmethod(_yakala))
    return kayit


@pytest.fixture
def uyarilar(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    gosterilen: list[str] = []
    monkeypatch.setattr(
        QMessageBox, "warning",
        staticmethod(lambda *a, **k: gosterilen.append(a[2] if len(a) > 2 else "")))
    return gosterilen


@pytest.fixture
def pencere(qapp) -> QWidget:  # type: ignore[no-untyped-def]
    """
    `_on_open_rehber` için yeterli olan en küçük "self".

    Tam `HycleusWindow` kurmak veritabanı, USB ve tema istiyor; bu metot
    yalnızca `self`'i QMessageBox'a ebeveyn olarak veriyor. Metot bağsız
    çağrılıyor — davranışı ölçmek için gerçek pencere gerekmiyor.
    """
    w = QWidget()
    yield w
    w.deleteLater()


def test_PDF_varken_YEREL_dosya_aciliyor(pencere, acilanlar):
    HycleusWindow._on_open_rehber(pencere)
    assert len(acilanlar) == 1, "rehber açılmadı"
    url = acilanlar[0]
    assert url.isLocalFile(), f"yerel dosya beklenirken {url.toString()!r} açıldı"
    assert Path(url.toLocalFile()) == rehber.PDF


def test_PDF_YOKKEN_web_adresine_dusuluyor(pencere, acilanlar,
                                           monkeypatch: pytest.MonkeyPatch,
                                           tmp_path: Path):
    """
    Düşüş sessiz DEĞİL: kullanıcı bir şey görüyor — web sayfası.

    "Tıkladım, hiçbir şey olmadı" en kötü sonuç olurdu.
    """
    monkeypatch.setattr(rehber, "PDF", tmp_path / "yok.pdf")
    HycleusWindow._on_open_rehber(pencere)
    assert len(acilanlar) == 1
    assert acilanlar[0].toString() == rehber.WEB


def test_ACILAMAZSA_kullaniciya_yol_gosteriliyor(pencere, uyarilar,
                                                 monkeypatch: pytest.MonkeyPatch):
    """
    Harici görüntüleyici yoksa kullanıcı çaresiz bırakılmamalı.

    Uyarı metni dosyanın YOLUNU içeriyor: kullanıcı elle açabilsin.
    """
    monkeypatch.setattr(QDesktopServices, "openUrl", staticmethod(lambda u: False))
    HycleusWindow._on_open_rehber(pencere)
    assert len(uyarilar) == 1, "açılamadı ama kullanıcıya hiçbir şey söylenmedi"
    assert str(rehber.PDF) in uyarilar[0]


def test_basarili_acilista_UYARI_yok(pencere, acilanlar, uyarilar):
    """Her açılışta uyarı kutusu çıkarsa madde kullanılamaz hâle gelir."""
    HycleusWindow._on_open_rehber(pencere)
    assert acilanlar and not uyarilar


def test_menu_etiketi_ARAYUZ_sabitinden_geliyor():
    """
    Menüde görünen yazı ile `CORE/rehber.py`'deki tanım aynı nesne olmalı.

    Arayüz etiketi kopyalasaydı, tanım değiştiğinde menü eski yazıyı
    göstermeye devam eder ve rehberdeki "şunu seçin" cümlesi yanıltırdı.
    """
    from UI.main_window import _REHBER_ETIKETI

    assert _REHBER_ETIKETI is rehber.MENU_ETIKETI
