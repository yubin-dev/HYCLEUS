"""
K1-15 — `UI/main_window_bulk.py::_on_ctx_bulk_download()` gerçekten
`self._locked`'ı dinliyor mu.

`tests/test_export.py` bu turun asıl güvenlik mantığını (`CORE/export.py::
export_to_directory()`'nin `should_continue()`'u `on_progress`'ten HEMEN
sonra yeniden sorması) CORE seviyesinde, `git stash` ile doğrulanmış bir
mutasyon-kontrastıyla kapatıyor — bu dosya onu TEKRARLAMIYOR.

Buradaki tek soru farklı: gerçek UI çağrı yeri (`_on_ctx_bulk_download`)
`should_continue` lambda'sına `self._locked`'ı GERÇEKTEN bağlıyor mu, yoksa
yalnızca "İptal" düğmesini mi dinliyor. Gerçek bir `HycleusWindow`
üzerinden, gerçek şifreleme ile ölçülüyor — `self._locked` doğrudan
`True` yapılmıyor, `_poll_usb()`'un `_lock()`'u tetiklemesinin GERÇEKTE
göründüğü yerden (`QProgressDialog.setValue()` — `_ilerleme()`'nin her
dosyada çağırdığı, `QApplication.processEvents()`'ten hemen önceki
adım) tetikleniyor.
"""
from __future__ import annotations

import os
from pathlib import Path

import pyotp
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import (
        QApplication,
        QFileDialog,
        QInputDialog,
        QMessageBox,
        QProgressDialog,
    )

    from UI import main_window as mw
    from UI.main_window import HycleusWindow
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE import secret_store
from CORE.crypto import encrypt_file

_KEY = b"K" * 32
_HWID = "BULK-LOCK-HWID"


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


@pytest.fixture
def isolate_safezone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from CORE.safezone import SAFEZONE_ENV_VAR

    hedef = tmp_path / "safezone"
    monkeypatch.setenv(SAFEZONE_ENV_VAR, str(hedef))
    return hedef


@pytest.fixture(autouse=True)
def _diyaloglari_engelle(monkeypatch: pytest.MonkeyPatch) -> None:
    """`_on_ctx_bulk_download` içindeki bilgi/hata kutuları testi bloklamasın."""
    for ad in ("information", "warning", "critical", "question"):
        monkeypatch.setattr(QMessageBox, ad, staticmethod(lambda *a, **kw: None))


@pytest.fixture
def pencere(qapp, db, isolate_safezone, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(mw, "get_usb_hwid", lambda: _HWID)
    win = HycleusWindow(hwid=_HWID, key=_KEY, role="Yönetici")
    try:
        yield win
    finally:
        for ad in ("_usb_timer", "_expiry_timer", "_idle_timer"):
            zamanlayici = getattr(win, ad, None)
            if zamanlayici is not None:
                zamanlayici.stop()
        QApplication.instance().removeEventFilter(win)
        win.close()


def _sifreli_dosyalar_ekle(db, tmp_path: Path, adet: int) -> tuple[list[int], list[str]]:
    file_ids: list[int] = []
    filepaths: list[str] = []
    for i in range(adet):
        src = tmp_path / f"gizli_{i}.txt"
        src.write_bytes(f"gizli-icerik-{i}".encode())
        hcl, _sha, aad = encrypt_file(src, _KEY, user_id=1, hwid=_HWID)
        src.unlink()
        cur = db.execute(
            "INSERT INTO files (filename, filepath, label, aad_metadata) "
            "VALUES (?,?,?,?)",
            (f"gizli_{i}.txt", str(hcl), "Genel", aad),
        )
        file_ids.append(int(cur.lastrowid))
        filepaths.append(str(hcl))
    return file_ids, filepaths


def test_kilit_ortasinda_bulk_indirme_gercekten_duruyor(
    pencere, db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    ANA TEST. `_poll_usb()` → `_lock()` etkileşimi TAKLİT EDİLİYOR:
    `QProgressDialog.setValue(3)` (dosya index=3'ün ilerleme güncellemesi
    — gerçek `_ilerleme()` bunu her dosyada çağırıyor) sırasında
    `pencere._locked` `True` yapılıyor. `_on_ctx_bulk_download`'ın gerçek
    `should_continue` bağlaması bunu görüp döngüyü durdurmalı.
    """
    secret = pyotp.random_base32()
    secret_store.store_totp_secret_for_hwid(_HWID, secret)

    file_ids, filepaths = _sifreli_dosyalar_ekle(db, tmp_path, 8)

    dogru_kod = pyotp.TOTP(secret).now()
    monkeypatch.setattr(
        QInputDialog, "getText", staticmethod(lambda *a, **kw: (dogru_kod, True))
    )

    save_dir = tmp_path / "indirilenler"
    save_dir.mkdir()
    monkeypatch.setattr(
        QFileDialog, "getExistingDirectory",
        staticmethod(lambda *a, **kw: str(save_dir)),
    )

    orijinal_set_value = QProgressDialog.setValue

    def _sahte_set_value(self_dialog, deger):
        if deger == 3:
            # Gerçek _poll_usb()'un yaptığı TEK şey: _lock() çağırıp
            # self._locked = True yapmak. Burada doğrudan onu taklit
            # ediyoruz — zamanlayıcı/USB donanımı simüle etmeye gerek yok,
            # ölçülmek istenen `_on_ctx_bulk_download`'ın buna TEPKİSİ.
            pencere._locked = True
        return orijinal_set_value(self_dialog, deger)

    monkeypatch.setattr(QProgressDialog, "setValue", _sahte_set_value)

    pencere._on_ctx_bulk_download(file_ids, filepaths)

    yazilanlar = {p.name for p in save_dir.iterdir()}
    for i in range(3):
        assert f"gizli_{i}.txt" in yazilanlar, (
            f"gizli_{i}.txt kilitten ÖNCE yazılmalıydı"
        )
    for i in range(3, 8):
        assert f"gizli_{i}.txt" not in yazilanlar, (
            f"gizli_{i}.txt kilitten SONRA yazılmış — _on_ctx_bulk_download "
            "self._locked'ı dinlemiyor olabilir"
        )


def test_kilitlenmeden_tum_dosyalar_normal_sekilde_iniyor(
    pencere, db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutasyon kontrastı — kilitlenmezse tüm dosyalar inmeli; yukarıdaki
    testin eksik/hatalı bir sahne kurulumu yüzünden GEÇMEDİĞİNİ değil,
    kilit sinyalinin GERÇEKTEN etkili olduğunu kanıtlar."""
    secret = pyotp.random_base32()
    secret_store.store_totp_secret_for_hwid(_HWID, secret)

    file_ids, filepaths = _sifreli_dosyalar_ekle(db, tmp_path, 4)

    dogru_kod = pyotp.TOTP(secret).now()
    monkeypatch.setattr(
        QInputDialog, "getText", staticmethod(lambda *a, **kw: (dogru_kod, True))
    )

    save_dir = tmp_path / "indirilenler2"
    save_dir.mkdir()
    monkeypatch.setattr(
        QFileDialog, "getExistingDirectory",
        staticmethod(lambda *a, **kw: str(save_dir)),
    )

    pencere._on_ctx_bulk_download(file_ids, filepaths)

    yazilanlar = {p.name for p in save_dir.iterdir()}
    assert yazilanlar == {f"gizli_{i}.txt" for i in range(4)}
