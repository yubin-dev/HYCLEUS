"""
B-146: "Onayla → Genel'e taşı" artık dosyanın GERÇEKTEN temiz tarandığını
doğruluyor.

`UI/main_window_files.py::_on_ctx_move_label(new_label="Genel")` ve
`UI/main_window_bulk.py::_on_ctx_bulk_approve` — Karantina'dan çıkışın iki
giriş noktası. Eskiden ikisi de yalnızca genel bir "Devam edilsin mi?"
onayı istiyordu; dosyanın hiç taranıp taranmadığına, taranmışsa
verdict'inin ne olduğuna hiç bakmıyordu — "🔍 Tara" ayrı bir eylemdi ve
sonucu "Onayla"yı hiç etkilemiyordu.

Yön BİLEREK asimetrik: "Reddet → İmha Odası'na taşı" burada SINANMIYOR —
o yön zaten daha kısıtlayıcıya gidiyor (bkz. BACKLOG.md B-146).
"""
from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QMessageBox, QTableWidget, QWidget

    from UI.main_window_bulk import BulkActionsMixin
    from UI.main_window_files import FileActionsMixin
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


class _SahteSahne(QWidget):
    """`_on_ctx_move_label`/`_on_ctx_bulk_approve`'un ihtiyaç duyduğu
    minimal yüzey — tam bir `HycleusWindow` kurmak orantısız olurdu
    (bkz. tests/test_scan_timeout_ui.py'nin AYNI deseni)."""

    _on_ctx_move_label = FileActionsMixin._on_ctx_move_label
    _on_ctx_bulk_approve = BulkActionsMixin._on_ctx_bulk_approve

    def __init__(self, satir_sayisi: int = 3) -> None:
        super().__init__()
        self._table = QTableWidget(satir_sayisi, 1)
        self._hwid = "TEST-HWID"
        self.live_counts_refreshed = 0

    def _refresh_live_counts(self) -> None:
        self.live_counts_refreshed += 1


@pytest.fixture
def sahne(qapp):
    return _SahteSahne()


@pytest.fixture
def kutular(monkeypatch: pytest.MonkeyPatch):
    """`.question` her zaman Yes; `.warning`/`.information` YAKALANIR."""
    yakalanan: dict[str, list] = {"warning": [], "information": []}
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.Yes))
    monkeypatch.setattr(
        QMessageBox, "warning",
        staticmethod(lambda *a, **k: yakalanan["warning"].append(a) or 0),
    )
    monkeypatch.setattr(
        QMessageBox, "information",
        staticmethod(lambda *a, **k: yakalanan["information"].append(a) or 0),
    )
    monkeypatch.setattr(QMessageBox, "critical", staticmethod(lambda *a, **k: 0))
    return yakalanan


def _dosya_ekle(db, filename: str, label: str = "Karantina") -> int:
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label) VALUES (?, ?, ?)",
        (filename, f"/vault/{filename}.hcl", label),
    )
    return int(cur.lastrowid)


def _tarama_kaydet(db, file_id: int, verdict: str, *, quarantined_at: str | None = None) -> None:
    """Gerçek `CORE.scanner._save_to_db()`'nin yazdığı AYNI JSON şekli.

    `quarantined_at` verilirse (birden fazla tarama arasındaki SIRAYI
    saniye çözünürlüklü sütunda GERÇEK bir `time.sleep()` olmadan
    ayırt etmek için) elle geçiliyor; verilmezse şema varsayılanı."""
    reason = json.dumps({
        "source": "test", "sha256": "x" * 64, "verdict": verdict,
        "malicious": verdict == "malicious", "suspicious": verdict == "suspicious",
        "engines_total": 1, "mock": False, "threat": None,
    })
    if quarantined_at is not None:
        db.execute(
            "INSERT INTO quarantine (file_id, reason, quarantined_at) VALUES (?, ?, ?)",
            (file_id, reason, quarantined_at),
        )
    else:
        db.execute("INSERT INTO quarantine (file_id, reason) VALUES (?, ?)", (file_id, reason))


def _label(db, file_id: int) -> str:
    return db.fetchone("SELECT label FROM files WHERE id = ?", (file_id,))["label"]


# ══════════════════════════════════════════════════════════════════════════════
# Tekli onay — UI/main_window_files.py::_on_ctx_move_label
# ══════════════════════════════════════════════════════════════════════════════


def test_hic_taranmamis_dosya_onaylanamiyor(sahne, db, kutular) -> None:
    """
    B-146'nın kalbi: hiç taranmamış (quarantine satırı yok) bir dosya
    "Onayla"yla Genel'e GEÇMEMELİ.

    Mutasyon-kanıt: `_on_ctx_move_label()`'daki
    `son_tarama_verdict(...) != "clean"` kontrolü kaldırılırsa bu test
    KIRMIZIYA düşer — dosya Genel'e taşınır.
    """
    fid = _dosya_ekle(db, "hic-taranmamis.pdf")
    sahne._on_ctx_move_label(0, fid, "Genel")

    assert _label(db, fid) == "Karantina", "taranmamış dosya Genel'e taşınmış"
    assert kutular["warning"], "kullanıcıya hiçbir uyarı gösterilmedi"
    assert not kutular["information"], "başarı mesajı gösterildi ama işlem engellendi"


@pytest.mark.parametrize("verdict", ["malicious", "timeout", "unknown", "suspicious"])
def test_temiz_disindaki_verdictli_dosya_onaylanamiyor(sahne, db, kutular, verdict: str) -> None:
    fid = _dosya_ekle(db, f"{verdict}.pdf")
    _tarama_kaydet(db, fid, verdict)
    sahne._on_ctx_move_label(0, fid, "Genel")

    assert _label(db, fid) == "Karantina", f"'{verdict}' verdict'li dosya Genel'e taşınmış"


def test_temiz_taranan_dosya_onaylanabiliyor(sahne, db, kutular) -> None:
    """Gate FALSE-POSITIVE üretmemeli: gerçekten temiz bir dosya
    normal şekilde onaylanabilmeli."""
    fid = _dosya_ekle(db, "temiz.pdf")
    _tarama_kaydet(db, fid, "clean")
    sahne._on_ctx_move_label(0, fid, "Genel")

    assert _label(db, fid) == "Genel"
    assert kutular["information"], "başarı mesajı gösterilmedi"


def test_en_son_tarama_dikkate_aliniyor_ilk_degil(sahne, db, kutular) -> None:
    """İki kez taranmış bir dosyada (ör. önce zararlı çıktı, sonra
    yeniden tarandı ve temiz çıktı) EN SON sonuç geçerli olmalı —
    `quarantine.quarantined_at DESC` sıralaması `CORE/file_queries.py`'nin
    `scan_reason` alt sorgusuyla AYNI."""
    fid = _dosya_ekle(db, "iki-kez-tarandi.pdf")
    _tarama_kaydet(db, fid, "malicious", quarantined_at="2026-01-01T00:00:00Z")
    _tarama_kaydet(db, fid, "clean", quarantined_at="2026-01-01T00:00:05Z")

    sahne._on_ctx_move_label(0, fid, "Genel")
    assert _label(db, fid) == "Genel"


def test_reddet_yonu_tarama_durumuna_bakmiyor_bilerek(sahne, db, kutular) -> None:
    """B-146'nın kapsamı KASITLI olarak yalnızca 'Onayla' — 'Reddet'
    (→ İmha) zaten daha kısıtlayıcıya gidiyor, burada engellenmemeli."""
    fid = _dosya_ekle(db, "hic-taranmamis-2.pdf")
    sahne._on_ctx_move_label(0, fid, "Imha")

    assert _label(db, fid) == "Imha"


# ══════════════════════════════════════════════════════════════════════════════
# Toplu onay — UI/main_window_bulk.py::_on_ctx_bulk_approve
# ══════════════════════════════════════════════════════════════════════════════


def test_bulk_onay_temizi_tasir_digerlerini_atlar(sahne, db, kutular) -> None:
    """
    Toplu onayda: temiz dosya taşınır; taranmamış ve şüpheli olanlar
    ATLANIR — biri diğerinin taşınmasını engellemez (B-145'teki
    engellenen-dosya-diğerlerini-durdurmasın deseniyle TUTARLI).

    Mutasyon-kanıt: `_on_ctx_bulk_approve()`'daki
    `son_tarama_verdict(db, fid) != "clean"` kontrolü kaldırılırsa bu
    test KIRMIZIYA düşer — üç dosya da Genel'e taşınır.
    """
    f_temiz = _dosya_ekle(db, "t1.pdf")
    _tarama_kaydet(db, f_temiz, "clean")
    f_taranmamis = _dosya_ekle(db, "t2.pdf")
    f_supheli = _dosya_ekle(db, "t3.pdf")
    _tarama_kaydet(db, f_supheli, "suspicious")

    sahne._on_ctx_bulk_approve([0, 1, 2], [f_temiz, f_taranmamis, f_supheli])

    assert _label(db, f_temiz) == "Genel"
    assert _label(db, f_taranmamis) == "Karantina"
    assert _label(db, f_supheli) == "Karantina"
    assert sahne.live_counts_refreshed == 1
