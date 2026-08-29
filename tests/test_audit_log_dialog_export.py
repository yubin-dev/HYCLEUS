"""
`UI/AuditLogDialog.py::_export_txt()` — dışa aktarılan dosyanın kendi
İÇİNDE tutarlı olduğu.

2026-08-29'da ÖLÇÜLEN bir tutarsızlık (bkz. BACKLOG.md B-073 devamı):
dışa aktarılan satırlar `self._table`'ın (diyalog açılışından ya da son
"Filtrele"den kalma, BAYAT olabilecek) o anki hâlinden geliyordu, başlıktaki
"Doğrulanan: N kayıt"/"Son kayıt"/"Son hash" ise `zincir_raporu()` ile dışa
aktarım ANINDA TAZE üretiliyordu. Diyalog açıkken arka planda yeni bir
denetim kaydı oluşursa (gerçekçi bir senaryo — denetim kaydı sürekli
yazılıyor), başlık "Doğrulanan: 5 kayıt" derken alttaki liste 4 satırda
kalabiliyor, altyazı da "4 kayıt" yazıyordu — kendi içinde ÇELİŞEN, uyum
kanıtı olarak sunulabilecek bir dosya.

Düzeltme: `_export_txt()` artık dışa aktarımdan HEMEN önce `self._load()`'ı
yeniden çağırıyor — satırlar ve başlık (zincir raporu dahil) ARKA ARKAYA,
aralarına kullanıcı kodu girmeden üretiliyor.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox

    from UI.AuditLogDialog import AuditLogDialog
    from UI.main_window_palette import _DARK
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
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


@pytest.fixture(autouse=True)
def _mesaj_kutusu_engelle(monkeypatch: pytest.MonkeyPatch) -> None:
    """`QMessageBox` gerçekten AÇILMASIN — testin akışını bloklamasın."""
    for ad in ("information", "warning", "critical", "question"):
        monkeypatch.setattr(QMessageBox, ad, staticmethod(lambda *a, **kw: 0))


def _dosya_sec_sabitle(monkeypatch: pytest.MonkeyPatch, yol: Path) -> None:
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName",
        staticmethod(lambda *a, **kw: (str(yol), "")),
    )


def _basligi_ayristir(metin: str) -> dict:
    """Dışa aktarılan TXT'nin başlığından sayıları çıkarır."""
    dogrulanan = re.search(r"Doğrulanan\s*:\s*(\d+) kayıt", metin)
    altyazi = re.search(r"Bu dışa aktarımdaki kayıt sayısı:\s*(\d+)", metin)
    return {
        "dogrulanan": int(dogrulanan.group(1)) if dogrulanan else None,
        "altyazi": int(altyazi.group(1)) if altyazi else None,
    }


def _listelenen_satir_sayisi(metin: str) -> int:
    """Sütun başlığı ile kapanış ayracı arasındaki veri satırlarını sayar."""
    satirlar = metin.splitlines()
    baslik_idx = next(i for i, s in enumerate(satirlar) if s.startswith("Zaman"))
    ayrac = satirlar[baslik_idx + 1]
    kapanis_idx = satirlar.index(ayrac, baslik_idx + 2)
    return kapanis_idx - (baslik_idx + 2)


def test_export_dosyasi_arkaplanda_eklenen_kaydi_HEM_baslikta_HEM_satirlarda_gosterir(
    qapp, db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    KALICI regresyon: diyalog açıldıktan SONRA, tablo yenilenmeden ÖNCE
    arka planda yeni bir denetim kaydı oluşuyor. Dışa aktarılan dosyada
    başlığın "Doğrulanan" sayısı, altyazının "kayıt sayısı" sayısı ve
    fiilen listelenen satır sayısı ÜÇÜ DE birbiriyle VE gerçek DB
    durumuyla eşleşmeli — hiçbiri geride kalmamalı.
    """
    for i in range(3):
        db.log(f"onceki_islem_{i}", detail="baslangic")

    dlg = AuditLogDialog(T=_DARK)
    satir_sayisi_acilista = dlg._table.rowCount()

    # Arka planda yeni bir kayıt — dialog TABLOYU YENİLEMEDEN.
    db.log("arka_planda_olusan_islem", detail="yeni")
    assert dlg._table.rowCount() == satir_sayisi_acilista, (
        "test kurulumu hatalı — tablo beklenmedik biçimde kendiliğinden yenilendi"
    )

    export_path = tmp_path / "export.txt"
    _dosya_sec_sabitle(monkeypatch, export_path)

    dlg._export_txt()

    metin = export_path.read_text(encoding="utf-8")
    gercek_sayi = db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"]

    basliktakiler = _basligi_ayristir(metin)
    listelenen = _listelenen_satir_sayisi(metin)

    assert basliktakiler["dogrulanan"] == gercek_sayi, (
        f"Başlıktaki 'Doğrulanan' sayısı gerçek DB durumuyla uyuşmuyor: "
        f"{basliktakiler}"
    )
    assert basliktakiler["altyazi"] == gercek_sayi, (
        f"Altyazıdaki kayıt sayısı gerçek DB durumuyla uyuşmuyor: {basliktakiler}"
    )
    assert listelenen == gercek_sayi, (
        f"Listelenen satır sayısı ({listelenen}) gerçek DB durumuyla "
        f"({gercek_sayi}) uyuşmuyor"
    )
    assert "arka_planda_olusan_islem" in metin, (
        "arka planda eklenen kayıt dışa aktarılan dosyada HİÇ görünmüyor"
    )


def test_export_tabloyu_da_yeniliyor(
    qapp, db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Yan etki, bilerek kabul edilen bir sonuç: export sonrası ekrandaki
    tablo da güncel — kullanıcı export'tan sonra dosyayla ekranı
    karşılaştırırsa ikisi aynı şeyi gösteriyor."""
    db.log("ilk_kayit", detail="x")
    dlg = AuditLogDialog(T=_DARK)
    onceki = dlg._table.rowCount()

    db.log("ikinci_kayit", detail="y")
    assert dlg._table.rowCount() == onceki

    export_path = tmp_path / "export2.txt"
    _dosya_sec_sabitle(monkeypatch, export_path)
    dlg._export_txt()

    assert dlg._table.rowCount() == onceki + 1


def test_export_iptal_edilirse_tablo_yenilenmiyor(
    qapp, db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`QFileDialog` iptal edilirse (boş yol) `_load()` HİÇ çağrılmamalı —
    kullanıcı vazgeçtiğinde sessiz bir yan etki olmamalı."""
    db.log("ilk_kayit", detail="x")
    dlg = AuditLogDialog(T=_DARK)
    onceki = dlg._table.rowCount()

    db.log("ikinci_kayit", detail="y")
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName", staticmethod(lambda *a, **kw: ("", ""))
    )

    dlg._export_txt()

    assert dlg._table.rowCount() == onceki, (
        "kullanıcı dosya seçimini iptal etti ama tablo yine de yenilendi"
    )
