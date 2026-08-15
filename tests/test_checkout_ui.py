"""
Şeffaf erişimin arayüz tarafı — izleyici, yoklama ve kapanış (Qt).

CORE tarafı (`tests/test_checkout.py`) kararların doğruluğunu sınıyor.
Burada sınanan şey BAĞLANTI: doğru anda doğru kararın çağrıldığı.

Özellikle üç katmanlı ağın çalıştığı:
  1. izleyici olayı  → erken yakalar
  2. yoklama         → izleyici kaçırırsa yakalar
  3. kapanış         → ikisi de kaçırsa bile özet karşılaştırması yakalar

Üçüncüsü en önemlisi: Word gibi uygulamalar dosyayı silip yeniden
yazdığında izleyici düşüyor ve olay hiç gelmiyor. Kapanıştaki
karşılaştırma bunu yakalamazsa kullanıcının düzenlemesi kaybolur.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QWidget

    from UI.main_window_open import OpenMixin
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE import crypto, safezone
from CORE.crypto import decrypt_file, encrypt_file, generate_key

_USER = 5
_HWID = "TEST-HWID-UI"
_ILK = b"ilk surum\n" * 50
_YENI = b"duzenlenmis surum\n" * 60


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


@pytest.fixture(autouse=True)
def _izole(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    q = tmp_path / "quarantine"
    q.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", q)
    monkeypatch.setenv(safezone.SAFEZONE_ENV_VAR, str(tmp_path / "safezone"))


@pytest.fixture(autouse=True)
def _acma_engelle(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """
    Varsayılan uygulamayı GERÇEKTEN açmayı engeller.

    Olmasaydı test paketi Not Defteri/Word açardı — CI'da asılı kalır,
    yerelde ekranı doldururdu.
    """
    acilanlar: list[Path] = []
    import UI.main_window_open as mo

    monkeypatch.setattr(mo, "open_with_default_app", acilanlar.append)
    return acilanlar


@pytest.fixture(autouse=True)
def _diyalog_engelle(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """
    Modal diyalogları yakalar — açılmalarına İZİN VERİLMEZ.

    `QMessageBox.warning()` offscreen platformda bile modaldır ve tıklayacak
    kimse olmadığı için SONSUZA KADAR bloklar. Bu fixture olmadan tek bir
    hata yolu testi Windows CI'ını iş zaman aşımına kadar asardı — bu
    paketi yazarken tam olarak bu oldu.

    Döndürülen liste testlerin "uyarı gerçekten gösterildi mi" diye
    bakmasını sağlıyor; yani diyalog yalnızca susturulmuyor, gözleniyor.
    """
    gosterilen: list[tuple[str, str]] = []

    def _yakala(tur: str):
        def _f(_parent, baslik, metin, *a, **kw):
            gosterilen.append((tur, f"{baslik}: {metin}"))
            return 0
        return _f

    from PySide6.QtWidgets import QMessageBox

    for ad in ("warning", "critical", "information", "question"):
        monkeypatch.setattr(QMessageBox, ad, staticmethod(_yakala(ad)))
    return gosterilen


@pytest.fixture
def key() -> bytes:
    return generate_key()


@pytest.fixture
def hcl(tmp_path: Path, key: bytes) -> Path:
    src = tmp_path / "rapor.txt"
    src.write_bytes(_ILK)
    dst, _s, _a = encrypt_file(src, key, _USER, hwid=_HWID)
    src.unlink()
    return dst


class _Sahne(OpenMixin, QWidget):
    """`OpenMixin`'in dokunduğu asgari yüzey."""

    def __init__(self, key: bytes) -> None:
        super().__init__()
        self._key = key
        self._user_id = _USER
        self._hwid = _HWID
        self._role = "Yönetici"
        self._open_files_label = None
        self.tablo_yenilendi = 0
        self._init_checkout()

    def _refresh_table(self) -> None:
        self.tablo_yenilendi += 1


@pytest.fixture
def sahne(qapp, db, key):
    db.execute(
        "INSERT OR IGNORE INTO users (id, username, password_hash, role, status, hwid)"
        " VALUES (5, 't', '', 'admin', 'approved', 'H')")
    return _Sahne(key)


def _kayit(db, hcl: Path, file_id: int = 1) -> None:
    db.execute(
        "INSERT INTO files (id, filename, filepath, label, original_sha256)"
        " VALUES (?, 'rapor.txt', ?, 'Genel', ?)",
        (file_id, str(hcl), hashlib.sha256(_ILK).hexdigest()))


def _duzenle(path: Path, veri: bytes = _YENI) -> None:
    path.write_bytes(veri)


def _eskit(path: Path, saniye: float = 60.0) -> None:
    st = path.stat()
    os.utime(path, (st.st_atime, st.st_mtime - saniye))


# ══════════════════════════════════════════════════════════════════════════════
# 1. Aç
# ══════════════════════════════════════════════════════════════════════════════


def test_open_decrypts_launches_and_watches(sahne, db, hcl, _acma_engelle) -> None:
    _kayit(db, hcl)
    sahne._on_ctx_open(1, str(hcl))

    entry = sahne._checkouts.get(1)
    assert entry is not None
    assert entry.safe_path.read_bytes() == _ILK
    assert _acma_engelle == [entry.safe_path]
    assert str(entry.safe_path) in sahne._watcher.files()
    assert sahne._checkout_timer.isActive()


def test_the_safezone_directory_is_watched_too(sahne, db, hcl) -> None:
    """
    Sil-ve-yeniden-yaz eden uygulamalarda dosya yolu izlemesi düşüyor;
    dizin olayı ise geliyor.
    """
    _kayit(db, hcl)
    sahne._on_ctx_open(1, str(hcl))
    assert str(safezone.safezone_dir()) in sahne._watcher.directories()


def test_opening_twice_does_not_launch_a_second_copy(sahne, db, hcl, _acma_engelle) -> None:
    _kayit(db, hcl)
    sahne._on_ctx_open(1, str(hcl))
    sahne._on_ctx_open(1, str(hcl))

    assert len(sahne._checkouts) == 1
    assert len(safezone.list_leftovers()) == 1
    assert len(set(_acma_engelle)) == 1   # aynı yol iki kez açıldı, kopya yok


def test_opening_is_audited(sahne, db, hcl) -> None:
    _kayit(db, hcl)
    sahne._on_ctx_open(1, str(hcl))
    assert db.fetchone(
        "SELECT action FROM audit_log ORDER BY id DESC LIMIT 1")["action"] == "file_opened"


def test_a_missing_path_warns_and_opens_nothing(sahne, db, _diyalog_engelle) -> None:
    sahne._on_ctx_open(1, None)
    assert len(sahne._checkouts) == 0
    assert _diyalog_engelle and _diyalog_engelle[0][0] == "warning"


def test_an_undecryptable_file_reports_instead_of_crashing(
    sahne, db, tmp_path, _diyalog_engelle
) -> None:
    """Yanlış anahtarla açma: kullanıcıya söylenmeli, kayıt açılmamalı."""
    bozuk = tmp_path / "bozuk.hcl"
    bozuk.write_bytes(b"HYCL" + b"\x02" + b"\x00" * 40)
    db.execute(
        "INSERT INTO files (id, filename, filepath, label)"
        " VALUES (2, 'bozuk', ?, 'Genel')", (str(bozuk),))

    sahne._on_ctx_open(2, str(bozuk))
    assert len(sahne._checkouts) == 0
    assert any(t == "critical" for t, _m in _diyalog_engelle)
    assert safezone.list_leftovers() == []


# ══════════════════════════════════════════════════════════════════════════════
# 2. Yoklama / izleyici — otomatik geri yazma
# ══════════════════════════════════════════════════════════════════════════════


def test_a_settled_edit_is_written_back_by_the_sweep(sahne, db, hcl, key) -> None:
    """İzleyici ya da yoklama tetikleyince değişiklik geri yazılmalı."""
    _kayit(db, hcl)
    sahne._on_ctx_open(1, str(hcl))
    entry = sahne._checkouts.get(1)
    _duzenle(entry.safe_path)
    _eskit(entry.safe_path)

    sahne._sweep_checkouts()

    icerik, _m = decrypt_file(hcl, key, hwid=_HWID)
    assert icerik == _YENI


def test_the_document_stays_open_after_an_autosave(sahne, db, hcl) -> None:
    """
    Ara geri yazma belgeyi KAPATMAMALI: kullanıcı düzenlemeye devam
    ediyor ve geçici kopya silinirse uygulama altından dosyayı kaybeder.
    """
    _kayit(db, hcl)
    sahne._on_ctx_open(1, str(hcl))
    entry = sahne._checkouts.get(1)
    _duzenle(entry.safe_path)
    _eskit(entry.safe_path)

    sahne._sweep_checkouts()

    assert 1 in sahne._checkouts
    assert entry.safe_path.is_file()
    assert entry.writebacks == 1


def test_an_unsettled_edit_is_not_written_yet(sahne, db, hcl, key) -> None:
    """
    Yarısı yazılmış bir dosyayı şifrelemek, BOZUK bir belgeyi orijinalin
    üzerine yazmak olurdu.
    """
    _kayit(db, hcl)
    sahne._on_ctx_open(1, str(hcl))
    _duzenle(sahne._checkouts.get(1).safe_path)   # mtime = şimdi

    sahne._sweep_checkouts()

    icerik, _m = decrypt_file(hcl, key, hwid=_HWID)
    assert icerik == _ILK, "durulmadan yazılmamalı"


def test_the_sweep_does_nothing_when_unchanged(sahne, db, hcl) -> None:
    _kayit(db, hcl)
    onceki = hcl.read_bytes()
    sahne._on_ctx_open(1, str(hcl))
    _eskit(sahne._checkouts.get(1).safe_path)

    sahne._sweep_checkouts()
    assert hcl.read_bytes() == onceki


def test_the_timer_stops_when_nothing_is_open(sahne, db, hcl) -> None:
    _kayit(db, hcl)
    sahne._on_ctx_open(1, str(hcl))
    assert sahne._checkout_timer.isActive()

    sahne._on_ctx_close_file(1)
    sahne._sweep_checkouts()
    assert not sahne._checkout_timer.isActive()


def test_a_dropped_watch_is_re_registered(sahne, db, hcl) -> None:
    """
    ASIL KAÇIRMA SENARYOSU: uygulama dosyayı silip yeniden yazıyor,
    QFileSystemWatcher izlemeyi düşürüyor. Süpürme onu geri takmalı.
    """
    _kayit(db, hcl)
    sahne._on_ctx_open(1, str(hcl))
    entry = sahne._checkouts.get(1)

    sahne._watcher.removePath(str(entry.safe_path))   # izleme düştü
    assert str(entry.safe_path) not in sahne._watcher.files()

    sahne._sweep_checkouts()
    assert str(entry.safe_path) in sahne._watcher.files()


# ══════════════════════════════════════════════════════════════════════════════
# 3. Kapanış ağı — izleyici tamamen kaçırsa bile
# ══════════════════════════════════════════════════════════════════════════════


def test_a_change_missed_by_the_watcher_is_caught_at_shutdown(sahne, db, hcl, key) -> None:
    """
    EN ÖNEMLİ TEST. İzleyici hiç olay üretmiyor (silinip yeniden
    yazılmış dosya). Kapanıştaki özet karşılaştırması yakalamazsa
    kullanıcının düzenlemesi sessizce kaybolurdu.
    """
    _kayit(db, hcl)
    sahne._on_ctx_open(1, str(hcl))
    entry = sahne._checkouts.get(1)

    # Word tarzı kaydetme: sil, yeniden yaz. İzleyiciye hiç dokunmuyoruz.
    entry.safe_path.unlink()
    entry.safe_path.write_bytes(_YENI)

    sahne._close_all_checkouts(reason="shutdown")

    icerik, _m = decrypt_file(hcl, key, hwid=_HWID)
    assert icerik == _YENI


def test_shutdown_shreds_every_temp_copy(sahne, db, tmp_path, key) -> None:
    """Kapanışta SafeZone'da düz metin kalmamalı."""
    for i in range(3):
        s = tmp_path / f"d{i}.txt"
        s.write_bytes(f"icerik {i}".encode())
        h, _sh, _a = encrypt_file(s, key, _USER, hwid=_HWID)
        db.execute(
            "INSERT INTO files (id, filename, filepath, label) VALUES (?, ?, ?, 'Genel')",
            (10 + i, s.name, str(h)))
        sahne._on_ctx_open(10 + i, str(h))

    assert len(safezone.list_leftovers()) == 3
    sahne._close_all_checkouts(reason="shutdown")
    assert safezone.list_leftovers() == []
    assert len(sahne._checkouts) == 0


def test_shutdown_with_nothing_open_is_harmless(sahne) -> None:
    sahne._close_all_checkouts(reason="shutdown")


def test_locking_closes_open_documents(qapp, db, hcl, key, monkeypatch) -> None:
    """
    Oturum kilidi düz metin kopyaları diskte bırakırsa, kilidin koruduğu
    şeyin yanında açık bir kapı kalırdı.
    """
    from UI.main_window_lock import LockMixin

    class _KilitSahne(_Sahne, LockMixin):
        _LOCK_MESSAGES = {"usb": ("USB", "…"), "idle": ("Hareketsizlik", "…")}

        def __init__(self, key: bytes) -> None:
            super().__init__(key)
            self._locked = False
            self._lock_reasons: set[str] = set()
            self._blur = None
            self._central = QWidget()
            self._overlay = type("O", (), {
                "set_message": lambda *a: None, "resize": lambda *a: None,
                "show": lambda *a: None, "raise_": lambda *a: None,
            })()

        def centralWidget(self):
            return self._central

    _kayit(db, hcl)
    sahne = _KilitSahne(key)
    sahne._on_ctx_open(1, str(hcl))
    _duzenle(sahne._checkouts.get(1).safe_path)

    sahne._lock("idle")

    assert len(sahne._checkouts) == 0
    icerik, _m = decrypt_file(hcl, key, hwid=_HWID)
    assert icerik == _YENI, "kilitlenirken düzenleme geri yazılmalı"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Bitir
# ══════════════════════════════════════════════════════════════════════════════


def test_finish_writes_back_and_shreds(sahne, db, hcl, key) -> None:
    _kayit(db, hcl)
    sahne._on_ctx_open(1, str(hcl))
    entry = sahne._checkouts.get(1)
    yol = entry.safe_path
    _duzenle(yol)

    sahne._on_ctx_close_file(1)

    assert not yol.exists()
    assert len(sahne._checkouts) == 0
    icerik, _m = decrypt_file(hcl, key, hwid=_HWID)
    assert icerik == _YENI
    assert sahne.tablo_yenilendi == 1


def test_finish_updates_the_db_row(sahne, db, hcl) -> None:
    _kayit(db, hcl)
    sahne._on_ctx_open(1, str(hcl))
    _duzenle(sahne._checkouts.get(1).safe_path)
    sahne._on_ctx_close_file(1)

    row = db.fetchone("SELECT original_sha256, size_bytes FROM files WHERE id = 1")
    assert row["original_sha256"] == hashlib.sha256(_YENI).hexdigest()
    assert row["size_bytes"] == len(_YENI)


def test_finishing_an_unopened_file_is_harmless(sahne, db, hcl) -> None:
    _kayit(db, hcl)
    sahne._on_ctx_close_file(1)
    assert len(sahne._checkouts) == 0


def test_the_watch_is_removed_on_finish(sahne, db, hcl) -> None:
    _kayit(db, hcl)
    sahne._on_ctx_open(1, str(hcl))
    yol = str(sahne._checkouts.get(1).safe_path)
    sahne._on_ctx_close_file(1)
    assert yol not in sahne._watcher.files()
