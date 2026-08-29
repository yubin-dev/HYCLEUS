"""
2026-08-30 — büyük arşiv dosyalarında MpCmdRun.exe'nin `QThreadPool`
işçi havuzunu kilitlediği durumun testi.

Kök nedenin kendisi (`CORE/scanner_backends.py::run_tool()`'un
`subprocess.run(..., timeout=...)`'ın Windows'taki sınırsız ikinci
`communicate()`'i) `tests/test_scanner_backends.py`'de izole ölçülüyor.
Burada ölçülen FARKLI bir katman: `CORE.scanner.scan_file()` — `UI/
main_window_table.py::_FileRunnable.run()`'ın gerçekten çağırdığı aynı
fonksiyon — bir `QThreadPool` worker'ı İÇİNDE yapay olarak uzun sürerse,
AYNI havuzdaki DİĞER worker'ların bundan etkilenip etkilenmediği; yani
havuzun GERÇEKTEN kilitlenmediği, yalnızca alt seviyedeki `run_tool()`'un
kilitlenmediği değil.

NEDEN `_FileRunnable`'IN KENDİSİ DEĞİL
---------------------------------------
İlk yazımda gerçek `_FileRunnable` (şifreleme + DB yazma + tarama)
kullanıldı. 20 tekrarlı bir koşuda 2 kez şu hatalarla ARALIKLI başarısız
oldu: `"database is locked"` ailesinden `"another row available"` ve
`"cannot commit - no transaction is active"`. Kök neden: `_FileRunnable.
run()` tekil `DBManager()`'ın PAYLAŞILAN `sqlite3.Connection`'ını
(`check_same_thread=False` ile açılmış — bkz. DB/db_manager.py::connect())
BİRDEN FAZLA `QThreadPool` worker thread'inden GERÇEKTEN eşzamanlı
çağırıyor; `check_same_thread=False` yalnızca Python'un thread-affinity
denetimini kapatıyor, bağlantıyı eşzamanlı `execute()`/`commit()` çağrıları
için GÜVENLİ yapmıyor. `CORE/scanner.py::_save_to_db()`'nin kendi
docstring'i tam olarak bu yüzden AYRI bir bağlantı açıyor
("Thread-safe: singleton'ın connection'ını paylaşmak yerine her scan
thread'i kendi bağlantısını açar") — ama `_FileRunnable.run()`'ın kendi
`record_encrypted_file(db, ...)` çağrısı bu deseni TAKİP ETMİYOR.

Bu GERÇEK ve bu turdan BAĞIMSIZ bir yarış durumu — BACKLOG.md'ye ayrı bir
bulgu olarak düşüldü, burada DÜZELTİLMİYOR (kapsam dışı: görev MpCmdRun.exe
zaman aşımı, `_FileRunnable`'ın DB eşzamanlılığı değil). Onu susturmak
yerine test buradan ÇEKİLDİ: yalnızca `scan_file()`'ı gerçek bir
`QThreadPool`'da izole ediyor, şifreleme/DB adımlarına hiç girmiyor — asıl
iddia zaten yalnızca TARAMA adımıyla ilgili.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal
    from PySide6.QtWidgets import QApplication
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE import scanner
from CORE.scanner_backends import clean_result, timeout_result

#: Yapay "yavaş tarama" süresi. Gerçek bir büyük arşivi taklit ediyor —
#: gerçek testte dakikalar yerine saniyeler kullanılıyor.
_YAVAS_TARAMA_SANIYE = 2.0

#: Bütün test için üst sınır — bu aşılırsa havuz GERÇEKTEN kilitlenmiş demektir.
_TEST_UST_SINIR_SANIYE = _YAVAS_TARAMA_SANIYE + 8.0


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


def _bekle(kosul, sinir_saniye: float) -> bool:
    """`kosul()` True olana kadar Qt olay döngüsünü çalıştırır; sinir aşılırsa False."""
    basla = time.monotonic()
    while not kosul():
        if time.monotonic() - basla > sinir_saniye:
            return False
        QApplication.processEvents()
        time.sleep(0.02)
    return True


# ── `_FileRunnable.run()`'ın tarama parçasının minimal izolasyonu ──────────────


class _TaramaSinyalleri(QObject):
    bitti = Signal(str, object)  # (dosya adı, ScanResult)


class _TaramaGorevi(QRunnable):
    """`_FileRunnable.run()`'ın TEK bir adımını yalıtır: `scan_file()` çağrısı.

    `UI/main_window_table.py::_FileRunnable.run()` da tam olarak bunu
    yapıyor — `sr = scan_file(hcl_path, file_id=file_id)` — geri kalanı
    (şifreleme, DB yazma) bu testin konusu DEĞİL (bkz. modül docstring'i).
    """

    def __init__(self, path: Path, sinyaller: _TaramaSinyalleri) -> None:
        super().__init__()
        self.setAutoDelete(True)
        self._path = path
        self._sinyaller = sinyaller

    def run(self) -> None:
        sonuc = scanner.scan_file(self._path)
        self._sinyaller.bitti.emit(self._path.name, sonuc)


def test_bir_dosyanin_yavas_taramasi_havuzdaki_DIGER_worker_lari_ENGELLEMIYOR(
    tmp_path, monkeypatch, qapp,
):
    """
    3 dosya, 2 thread'lik bir havuz: biri (yavas.hcl) taranırken yapay
    olarak `_YAVAS_TARAMA_SANIYE` kadar "asılı" kalıyor (büyük bir arşivin
    MpCmdRun.exe'yi yavaşlatması taklit ediliyor) ve `timeout_result`
    döndürüyor; diğer ikisi anında `clean_result` döndürüyor.

    Asıl iddia: hızlı iki dosyanın sonucu, yavaş dosya HÂLÂ İŞLENİRKEN
    gelir — havuzdaki bir thread yavaş dosyaya kilitlense bile, ikinci
    thread diğerlerini SIRAYLA ve HIZLA bitirir. Hiçbiri
    `_YAVAS_TARAMA_SANIYE`'yi bekleyerek başlamaz.
    """
    zaman_damgalari: dict[str, float] = {}
    sonuclar: dict[str, object] = {}
    baslangic = time.monotonic()

    def sahte_scan_file(path: Path, file_id: int | None = None):
        if path.name.startswith("yavas"):
            time.sleep(_YAVAS_TARAMA_SANIYE)
            return timeout_result("t" * 64, "windows_defender")
        return clean_result("c" * 64, "windows_defender")

    monkeypatch.setattr(scanner, "scan_file", sahte_scan_file)

    def on_bitti(ad: str, sonuc) -> None:
        zaman_damgalari[ad] = time.monotonic() - baslangic
        sonuclar[ad] = sonuc

    sinyaller = _TaramaSinyalleri()
    sinyaller.bitti.connect(on_bitti)

    pool = QThreadPool()
    pool.setMaxThreadCount(2)  # 3 dosya, 2 thread — kasıtlı olarak SIKI

    dosyalar = ["yavas.hcl", "hizli1.hcl", "hizli2.hcl"]
    for ad in dosyalar:
        yol = tmp_path / ad
        yol.write_bytes(f"icerik-{ad}".encode())
        pool.start(_TaramaGorevi(yol, sinyaller))

    tamamlandi = _bekle(
        lambda: len(zaman_damgalari) == len(dosyalar), _TEST_UST_SINIR_SANIYE,
    )
    assert tamamlandi, (
        f"Havuz {_TEST_UST_SINIR_SANIYE}s içinde tamamlanmadı — "
        f"gelenler: {sorted(zaman_damgalari)}"
    )

    # Hızlı ikisi de doğru verdict'le tamamlandı.
    for ad in ("hizli1.hcl", "hizli2.hcl"):
        assert sonuclar[ad].verdict == "clean"

    # ASIL İDDİA: hızlı dosyaların ikisi de yavaş dosya HÂLÂ İŞLENİRKEN
    # (yavaş taramanın toplam süresinden ÖNCE) tamamlandı — havuzun geri
    # kalanı ondan etkilenmedi.
    for ad in ("hizli1.hcl", "hizli2.hcl"):
        assert zaman_damgalari[ad] < _YAVAS_TARAMA_SANIYE, (
            f"{ad} yavaş dosyanın bitmesini BEKLEMİŞ gibi görünüyor "
            f"({zaman_damgalari[ad]:.2f}s >= {_YAVAS_TARAMA_SANIYE}s) — "
            "havuz kilitlenmiş olabilir"
        )

    # Yavaş dosya sonunda tamamlandı VE ayırt edici "timeout" verdict'i taşıyor.
    assert sonuclar["yavas.hcl"].verdict == "timeout"
    assert sonuclar["yavas.hcl"].mock is False
    assert zaman_damgalari["yavas.hcl"] >= _YAVAS_TARAMA_SANIYE

    pool.waitForDone(int(_TEST_UST_SINIR_SANIYE * 1000))
