"""
HYCLEUS — Genel/Kasa ekranı canlı özetleri (mockup envanteri, B-1xx)

Onaylanan üç madde:
  1. Kenar çubuğu sayı rozetleri (Genel/Kritik/Karantina/İmha odası +
     Doğrulama Merkezi) — GERÇEK DB sorgusuyla, dosya listesini
     değiştiren MEVCUT noktalara bağlı (yeni bir zamanlayıcı YOK).
  2. Dosya adı hücresinin altında soluk, kısaltılmış SHA-256.
  3. İçerik alanının altında durum çubuğu (dosya/kayıt/kasa boyutu +
     bütünlük taraması + hareketsizlik kilidi).

Bu dosya iki katmanı ayrı ayrı test ediyor:
  · CORE tarafı (`count_files_by_label`, `vault_summary`,
    `audit_log_entry_count`, `_gun_once_metni`) — Qt'siz, saf veri.
  · UI tarafı — gerçek `HycleusWindow` + gerçek dosya ekleme/taşıma
    pipeline'ı (aynı `win` fixture deseni `tests/test_main_window_
    smoke.py`'deki gibi).

Mutasyon-kanıtlı doğrulama NOT (bu dosyaya GÖMÜLMEDİ, kalıcı testler
gibi çalıştırılamaz çünkü üretim kodunu geçici bozmayı gerektirir —
depo konvansiyonu, bkz. `tests/test_kayit_kurumsal_referans.py`
docstring'i): `_refresh_nav_counts()`/`_refresh_status_bar()` çağrıları
her çağıran noktadan (batch tamamlandı, tekli/toplu taşıma, süresi dolan
imha temizliği) TEK TEK geçici olarak yorum satırına alınıp ilgili
testin GERÇEKTEN düştüğü, sonra geri alınınca GEÇTİĞİ doğrulandı.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QLabel, QMessageBox

    from UI.main_window import HycleusWindow
    from UI.main_window_layout import _gun_once_metni
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE.audit_chain import audit_log_entry_count
from CORE.file_queries import count_files_by_label, vault_summary

_HWID = "TEST-HWID-DB"
_KEY = b"K" * 32


# ══════════════════════════════════════════════════════════════════════════════
# 1. CORE katmanı — Qt'siz, saf veri
# ══════════════════════════════════════════════════════════════════════════════


def _dosya_ekle(db, label: str, size: int = 100, sha: str = "a" * 64) -> int:
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label, size_bytes, "
        "original_sha256, added_by) VALUES (?, ?, ?, ?, ?, ?)",
        (f"dosya-{label}-{sha[:4]}.hcl", f"/vaults/{sha[:8]}.hcl", label, size, sha, None),
    )
    return int(cur.lastrowid)


def test_count_files_by_label_gercek_sayiyor(db) -> None:
    _dosya_ekle(db, "Genel", sha="1" * 64)
    _dosya_ekle(db, "Genel", sha="2" * 64)
    _dosya_ekle(db, "Kritik", sha="3" * 64)
    assert count_files_by_label(db, "Genel") == 2
    assert count_files_by_label(db, "Kritik") == 1
    assert count_files_by_label(db, "Karantina") == 0


def test_vault_summary_toplam_dosya_ve_bayt(db) -> None:
    _dosya_ekle(db, "Genel", size=1000, sha="4" * 64)
    _dosya_ekle(db, "Kritik", size=2500, sha="5" * 64)
    n, toplam = vault_summary(db)
    assert n == 2
    assert toplam == 3500


def test_vault_summary_mahrem_haric_tutulunca_azaliyor(db) -> None:
    """`include_private=False` — `files_by_label`'ın AYNI filtresi (B-007)."""
    gizli_id = _dosya_ekle(db, "Genel", size=999, sha="6" * 64)
    db.execute("INSERT INTO tags (name, is_private) VALUES ('gizli-etiket', 1)")
    tag_id = db.fetchone("SELECT id FROM tags WHERE name = 'gizli-etiket'")["id"]
    db.execute("INSERT INTO file_tags (file_id, tag_id) VALUES (?, ?)", (gizli_id, tag_id))
    _dosya_ekle(db, "Genel", size=1, sha="7" * 64)

    n_hepsi, _ = vault_summary(db, include_private=True)
    n_gizli_haric, toplam_gizli_haric = vault_summary(db, include_private=False)
    assert n_hepsi == 2
    assert n_gizli_haric == 1
    assert toplam_gizli_haric == 1


def test_audit_log_entry_count(db) -> None:
    baslangic = audit_log_entry_count(db)
    db.log("test_olayi_1")
    db.log("test_olayi_2")
    assert audit_log_entry_count(db) == baslangic + 2


@pytest.mark.parametrize(
    "gecen_gun, beklenen",
    [(0, "bugün"), (1, "1 gün önce"), (5, "5 gün önce")],
)
def test_gun_once_metni_bicimleri(gecen_gun: int, beklenen: str) -> None:
    zaman = datetime.now(timezone.utc) - timedelta(days=gecen_gun, minutes=1 if gecen_gun else 0)
    assert _gun_once_metni(zaman) == beklenen


def test_gun_once_metni_hic_yapilmadi() -> None:
    assert _gun_once_metni(None) == "hiç yapılmadı"


# ══════════════════════════════════════════════════════════════════════════════
# 2. UI katmanı — gerçek HycleusWindow, gerçek dosya pipeline'ı
# ══════════════════════════════════════════════════════════════════════════════


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


def _pump(app: QApplication, cond, timeout_ms: int = 15000) -> bool:
    t0 = time.monotonic()
    while not cond():
        app.processEvents()
        if (time.monotonic() - t0) * 1000 > timeout_ms:
            return False
    return True


@pytest.fixture
def win(qapp, db, isolate_safezone, monkeypatch):
    """Gerçek HycleusWindow — izole DB, sahte USB, gerçek admin kullanıcısı.

    `tests/test_main_window_smoke.py::win` ile AYNI desen — yalnızca
    `user_id` gerçek bir `users` satırına bağlı: bu dosyanın testleri
    dosya EKLİYOR (`files.added_by` FK'si `NULL`-savunmasız değil, gerçek
    bir kullanıcı istiyor).
    """
    from UI import main_window as mw
    from UI import main_window_table as mwt

    monkeypatch.setattr(mw, "get_usb_hwid", lambda: _HWID)
    monkeypatch.setattr(mwt, "get_usb_hwid", lambda: _HWID)
    monkeypatch.setattr(mwt.QMessageBox, "information", lambda *a, **k: None)
    monkeypatch.setattr(mwt.QMessageBox, "question", lambda *a, **k: QMessageBox.Yes)

    cur = db.execute(
        "INSERT INTO users (username, password_hash, hwid, role) VALUES (?, ?, ?, ?)",
        ("ay", "argon2$sahte", _HWID, "admin"),
    )
    uid = int(cur.lastrowid)
    window = HycleusWindow(hwid=_HWID, key=_KEY, role="Yönetici", username="ay", user_id=uid)
    # Bu dosyanın testleri gerçek dosya işleme sırasında `processEvents()`
    # döngüsünde BEKLİYOR (gerçek şifreleme + AV taraması) — `_usb_timer`
    # (3 sn) o sırada GERÇEKTEN ateşleyip `_poll_usb()`'u tetikleyebiliyor,
    # bu da (sahte hwid gerçek bir USB donanımına karşılık gelmediği için)
    # bloklayan bir `QMessageBox.warning()` açıp testi asıyordu. USB
    # yoklaması bu testlerin konusu DEĞİL — baştan durduruluyor.
    window._usb_timer.stop()
    try:
        yield window
    finally:
        for ad in ("_usb_timer", "_expiry_timer", "_idle_timer"):
            timer = getattr(window, ad, None)
            if timer is not None:
                timer.stop()
        app = QApplication.instance()
        if app is not None:
            app.removeEventFilter(window)
        window.close()
        window.deleteLater()


def _gercek_dosya_ekle(win, qapp, tmp_path: Path, ad: str, label: str = "Genel") -> None:
    # `_start_batch()` önceki parti TAMAMLANMIŞSA (`_batch_done >=
    # _batch_total`) sayaçları SIFIRLIYOR (bkz. UI/main_window_table.py) —
    # bu yüzden art arda çağrılarda toplamı BİRİKTİRMEK yerine, HER
    # çağrının kendi partisinin bitmesini ayrı ayrı bekliyoruz.
    f = tmp_path / ad
    f.write_bytes((b"gercek icerik " + ad.encode()) * 20)
    win._handle_dropped_file(f, label=label)
    assert _pump(qapp, lambda: win._batch_total >= 1 and win._batch_done >= win._batch_total), (
        "dosya işleme zaman aşımına uğradı"
    )


def test_genel_rozeti_dosya_eklenince_GERCEKTEN_artiyor(win, qapp, tmp_path) -> None:
    once = win._nav_btns["Genel"].text()
    assert once.rstrip().endswith("0")

    _gercek_dosya_ekle(win, qapp, tmp_path, "sozlesme.docx")

    sonra = win._nav_btns["Genel"].text()
    assert sonra.rstrip().endswith("1"), f"rozet güncellenmedi: {sonra!r}"
    assert sonra != once


def test_kritige_tasima_genel_azaltir_kritik_artirir(win, qapp, tmp_path) -> None:
    _gercek_dosya_ekle(win, qapp, tmp_path, "rapor.xlsx", label="Genel")
    win._on_sidebar_click("Genel", win._nav_btns["Genel"])
    assert win._nav_btns["Genel"].text().rstrip().endswith("1")
    assert win._nav_btns["Kritik"].text().rstrip().endswith("0")

    win._on_ctx_move_to_kritik(0, win._table.item(0, 0).data(Qt.UserRole))

    assert win._nav_btns["Genel"].text().rstrip().endswith("0")
    assert win._nav_btns["Kritik"].text().rstrip().endswith("1")


def test_toplu_imhaya_atma_rozetleri_gunceller(win, qapp, tmp_path) -> None:
    _gercek_dosya_ekle(win, qapp, tmp_path, "arsiv.zip", label="Genel")
    win._on_sidebar_click("Genel", win._nav_btns["Genel"])
    file_id = win._table.item(0, 0).data(Qt.UserRole)
    assert win._nav_btns["Imha"].text().rstrip().endswith("0")

    win._on_ctx_bulk_move_to_imha([0], [file_id])

    assert win._nav_btns["Genel"].text().rstrip().endswith("0")
    assert win._nav_btns["Imha"].text().rstrip().endswith("1")


def test_sha256_alt_satiri_dogru_degeri_gosteriyor(win, qapp, tmp_path) -> None:
    _gercek_dosya_ekle(win, qapp, tmp_path, "gizli-not.txt", label="Genel")
    win._on_sidebar_click("Genel", win._nav_btns["Genel"])

    item = win._table.item(0, 0)
    tam_hash = item.data(Qt.UserRole + 1)
    assert tam_hash and len(tam_hash) == 64

    cw = win._table.cellWidget(0, 0)
    hash_lbl = cw.findChild(QLabel, "file_hash_sublabel")
    assert hash_lbl is not None, "SHA-256 alt satırı bulunamadı"
    assert hash_lbl.text() == f"sha256 {tam_hash[:12]}…"


def test_durum_cubugu_gercek_toplamlari_gosteriyor(win, qapp, tmp_path) -> None:
    _gercek_dosya_ekle(win, qapp, tmp_path, "bir.txt", label="Genel")
    _gercek_dosya_ekle(win, qapp, tmp_path, "iki.txt", label="Kritik")
    win._on_sidebar_click("Genel", win._nav_btns["Genel"])

    from CORE.file_queries import vault_summary
    from CORE.idle_lock import get_idle_timeout_minutes
    from DB.db_manager import DBManager

    n, toplam = vault_summary(DBManager())
    dk = get_idle_timeout_minutes(DBManager())

    metin = win._status_bar.text()
    assert f"{n} dosya" in metin
    assert win._fmt_size(toplam) in metin
    assert f"Hareketsizlik kilidi: {dk} dk" in metin
    assert "Bütünlük taraması:" in metin


def test_tick_expiry_ile_silinen_dosya_rozeti_azaltir(win, qapp, tmp_path, monkeypatch) -> None:
    """Süresi dolan bir imha dosyası `_tick_expiry()` ile GERÇEKTEN silinince
    hem İmha rozeti azalmalı hem durum çubuğundaki toplam dosya sayısı."""
    _gercek_dosya_ekle(win, qapp, tmp_path, "eski.log", label="Genel")
    win._on_sidebar_click("Genel", win._nav_btns["Genel"])
    file_id = win._table.item(0, 0).data(Qt.UserRole)

    gecmis = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    from DB.db_manager import DBManager
    DBManager().execute(
        "UPDATE files SET label = 'Imha', expires_at = ? WHERE id = ?",
        (gecmis, file_id),
    )
    monkeypatch.setattr(
        win, "_purge_expired_file",
        lambda fid, fp: DBManager().execute("DELETE FROM files WHERE id = ?", (fid,)),
    )

    win._on_sidebar_click("Imha", win._nav_btns["Imha"])
    assert win._nav_btns["Imha"].text().rstrip().endswith("1")

    win._tick_expiry()

    assert win._nav_btns["Imha"].text().rstrip().endswith("0")
    assert "1 dosya" not in win._status_bar.text()


def test_guvenlik_rozeti_yedek_ve_kurtarma_sinyallerini_topluyor(win, monkeypatch) -> None:
    import UI.main_window_layout as mwl

    class _SahteDurum:
        def __init__(self, uyari: bool) -> None:
            self.uyarilmali = uyari

    monkeypatch.setattr(mwl, "yedek_durumu", lambda db: _SahteDurum(False))
    monkeypatch.setattr(mwl, "has_recovery_share", lambda hwid: True)
    win._refresh_nav_counts()
    assert win._guvenlik_btn.text().rstrip().endswith("Merkezi")  # rozet YOK (0)

    monkeypatch.setattr(mwl, "yedek_durumu", lambda db: _SahteDurum(True))
    monkeypatch.setattr(mwl, "has_recovery_share", lambda hwid: False)
    win._refresh_nav_counts()
    assert win._guvenlik_btn.text().rstrip().endswith("2")
