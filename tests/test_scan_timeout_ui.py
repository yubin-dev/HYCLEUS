"""
`UI/main_window_files.py::_on_ctx_scan_done()` — zaman aşımı verdict'i
(2026-08-30).

"🔍 Tara" yalnızca Karantina sekmesinde sunuluyor (bkz. context menu
kurulumu, `main_window_files.py` ~satır 132) — yani bu akışa giren dosya
ZATEN Karantina'da. Burada ölçülen: kullanıcı NET bir mesaj görüyor mu,
rozet doğru mu, dosya YANLIŞLIKLA başka bir etikete taşınmıyor mu (Karantina
zaten doğru yer, taşımaya gerek yok — `malicious` verdict'inin aksine).
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QMessageBox, QTableWidget, QWidget

    from UI.main_window_files import FileActionsMixin
    from UI.main_window_table import TableMixin
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE.scanner_backends import clean_result, malicious_result, timeout_result


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


class _SahteSahne(QWidget):
    """`_on_ctx_scan_done()`'ın ihtiyaç duyduğu minimal yüzey.

    `tests/test_backup_verify_ui.py`'nin zaten kullandığı "gerçek metodu
    çıplak bir sahne nesnesine bağla" deseniyle aynı — tam bir
    `HycleusWindow` kurmak bu testin ölçtüğü şeyle orantısız olurdu.
    """

    _on_ctx_scan_done = FileActionsMixin._on_ctx_scan_done
    _on_ctx_move_label = FileActionsMixin._on_ctx_move_label
    _set_scan_badge = TableMixin._set_scan_badge

    def __init__(self) -> None:
        super().__init__()
        self._table = QTableWidget(1, 5)
        self._hwid = "TEST-HWID"


@pytest.fixture
def sahne(qapp):
    return _SahteSahne()


@pytest.fixture
def mesaj_kutusu_yakala(monkeypatch):
    """`.warning`'i YAKALAR (döndürülen listeye düşer); diğer modal türlerini
    (`.critical`/`.information`/`.question`) SESSİZCE yutar — testin
    ölçmediği bir yolda gerçek bir `.exec()` çağrılırsa (ör. beklenmeyen bir
    hata dalı) offscreen platformda test SONSUZA KADAR asılı kalırdı."""
    mesajlar: list[tuple] = []
    monkeypatch.setattr(
        QMessageBox, "warning",
        staticmethod(lambda *a, **kw: mesajlar.append(a) or 0),
    )
    for ad in ("critical", "information", "question"):
        monkeypatch.setattr(QMessageBox, ad, staticmethod(lambda *a, **kw: 0))
    return mesajlar


def _rozet_metni(sahne: _SahteSahne) -> str:
    item = sahne._table.item(0, 4)
    return item.text() if item is not None else ""


def test_zaman_asimi_net_mesaj_gosteriyor(sahne, mesaj_kutusu_yakala):
    sonuc = timeout_result("x" * 64, "windows_defender")
    sahne._on_ctx_scan_done(0, sonuc, file_id=1)

    assert len(mesaj_kutusu_yakala) == 1, "kullanıcıya hiçbir şey gösterilmedi"
    baslik, metin = mesaj_kutusu_yakala[0][1], mesaj_kutusu_yakala[0][2]
    assert "Zaman Aşımı" in baslik
    assert "zaman aşımına uğradı" in metin
    assert "manuel inceleme" in metin.lower()


def test_zaman_asimi_rozeti_ayirt_edici(sahne, mesaj_kutusu_yakala):
    sonuc = timeout_result("x" * 64, "windows_defender")
    sahne._on_ctx_scan_done(0, sonuc, file_id=1)
    assert "Zaman Aşımı" in _rozet_metni(sahne)


def test_zaman_asimi_dosyayi_TASIMIYOR_zaten_karantinada(sahne, mesaj_kutusu_yakala):
    """
    `malicious`'ın aksine (İmha'ya taşınır), timeout dosyayı OLDUĞU yerde
    bırakmalı — "🔍 Tara" zaten yalnızca Karantina'dan tetiklenebiliyor,
    taşınacak DAHA GÜVENLİ bir yer yok.
    """
    sonuc = timeout_result("x" * 64, "windows_defender")
    sahne._on_ctx_scan_done(0, sonuc, file_id=1)
    # Satır kaldırılmadı — `_on_ctx_move_label` çağrılsaydı `removeRow` çağrılırdı.
    assert sahne._table.rowCount() == 1


def test_zaman_asimi_ile_zararli_AYNI_SEY_DEGIL(sahne, mesaj_kutusu_yakala):
    """Mutasyon kontrastının hızlı bir kanıtı: iki verdict farklı davranmalı."""
    sahne._on_ctx_scan_done(0, malicious_result("x" * 64, "windows_defender"), file_id=1)
    zararli_mesaj = mesaj_kutusu_yakala[0][1]

    mesaj_kutusu_yakala.clear()
    sahne._on_ctx_scan_done(0, timeout_result("x" * 64, "windows_defender"), file_id=1)
    zaman_asimi_mesaj = mesaj_kutusu_yakala[0][1]

    assert zararli_mesaj != zaman_asimi_mesaj


def test_temiz_verdict_mesaj_KUTUSU_ACMIYOR(sahne, mesaj_kutusu_yakala):
    """Karşılaştırma: `clean` hiçbir zaman modal göstermemeliydi (davranış değişmedi)."""
    sonuc = clean_result("x" * 64, "windows_defender")
    sahne._on_ctx_scan_done(0, sonuc, file_id=1)
    assert mesaj_kutusu_yakala == []
    assert "Temiz" in _rozet_metni(sahne)
