"""
HYCLEUS — Genel/Kasa ekranı: 4 kozmetik mockup farkı + B-124 (USB rozeti konumu)

Onaylanan maddeler:
  1. "+ Yeni" tek dropdown ("Dosya Ekle" + "📁 Klasör Ekle" ayrı düğmeleri
     BİRLEŞTİ) — `_on_add_file()`/`_on_add_folder()` DEĞİŞMEDİ, dropdown
     onları çağırıyor.
  2. Arama çubuğu içerik alanının üstünden üst eylem barına taşındı.
  3. Tarama sütunundaki durum metinlerine önüne "●" (nokta) eklendi.
  4. Dosya satırlarına görünür bir "⋯" düğmesi eklendi — sağ tık
     menüsüyle AYNI `_on_context_menu()` gövdesini açıyor.
  B-124. USB durum rozeti kenar çubuğunun altından üst bara taşındı.

Mutasyon-kanıtlı doğrulama NOT (bu dosyaya GÖMÜLMEDİ — depo konvansiyonu,
bkz. `tests/test_kayit_kurumsal_referans.py` docstring'i): her maddenin
üretim kodu geçici bozulup ilgili testin GERÇEKTEN düştüğü, sonra geri
alınınca GEÇTİĞİ doğrulandı.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QLabel

    from UI.main_window import HycleusWindow
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

_HWID = "TEST-HWID-DB"
_KEY = b"K" * 32


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
def sahte_temiz_tarama(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    `CORE.scanner.select_backend()`'i, HER ZAMAN "clean" dönen sahte bir
    arka uçla değiştirir (bkz. `tests/test_scanner_flow.py::arka_uc`'nin
    aynı deseni).

    Bu dosyadaki testler gerçek tarama sonucuna bakmıyor, yalnızca "●"
    öneki + durum metninin doğru biçimlendiğini kontrol ediyor — ama
    `_FileRunnable.run()` GERÇEK `scan_file()`'ı çağırıyor. Motor
    platforma göre değişiyor (Windows → Defender, genelde kurulu; Linux
    CI koşucusu → ClamAV, genelde KURULU DEĞİL) — fixture olmadan aynı
    test paketi geliştirme makinesinde (gerçek "clean" verdict) ve CI'da
    (motor yok → `mock_result()`, `verdict="unknown"`, "●  — (m)") FARKLI
    sonuç veriyordu. Aynı kök neden `tpm_kapali` (conftest.py) için zaten
    belgelenmiş: makineye göre değişen bir paket güven vermiyor.
    """
    from CORE import scanner
    from CORE.scanner_backends import clean_result

    class _SahteArkaUc:
        ad = "test"
        audit_action = "clamav_scan"

        def available(self) -> bool:
            return True

        def scan(self, path: Path, sha256: str):
            return clean_result(sha256, "test")

    monkeypatch.setattr(scanner, "select_backend", lambda: _SahteArkaUc())


def _pump(app: QApplication, cond, timeout_ms: int = 15000) -> bool:
    t0 = time.monotonic()
    while not cond():
        app.processEvents()
        if (time.monotonic() - t0) * 1000 > timeout_ms:
            return False
    return True


@pytest.fixture
def win(qapp, db, isolate_safezone, sahte_usb):
    """Gerçek HycleusWindow — `sahte_usb` TÜM ilgili modülleri (main_window_lock
    dahil) yamalıyor, bu dosyanın USB rozeti testleri için gerekli."""
    from PySide6.QtWidgets import QMessageBox as _MB
    from UI import main_window_table as mwt

    usb = sahte_usb(_HWID)
    mwt.QMessageBox.information = staticmethod(lambda *a, **k: None)
    mwt.QMessageBox.question = staticmethod(lambda *a, **k: _MB.Yes)

    cur = db.execute(
        "INSERT INTO users (username, password_hash, hwid, role) VALUES (?, ?, ?, ?)",
        ("ay", "argon2$sahte", _HWID, "admin"),
    )
    uid = int(cur.lastrowid)
    window = HycleusWindow(hwid=_HWID, key=_KEY, role="Yönetici", username="ay", user_id=uid)
    window._usb_timer.stop()
    window._usb = usb  # testlerin `.tak()`/`.cikar()` çağırması için
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
    f = tmp_path / ad
    f.write_bytes((b"gercek icerik " + ad.encode()) * 20)
    win._handle_dropped_file(f, label=label)
    assert _pump(qapp, lambda: win._batch_total >= 1 and win._batch_done >= win._batch_total), (
        "dosya işleme zaman aşımına uğradı"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. "+ Yeni" dropdown
# ══════════════════════════════════════════════════════════════════════════════


def test_artik_tek_add_new_dugmesi_var_eski_ikisi_yok(win) -> None:
    assert hasattr(win, "_btn_add_new")
    assert not hasattr(win, "_btn_add_file")
    assert not hasattr(win, "_btn_add_folder")


def test_yeni_menu_iki_eylemi_dogru_metotlara_bagliyor() -> None:
    """
    `_on_add_new_menu()` GERÇEK bir `QMenu.exec()` çağırıyor. Denendi:
    `QMenu.exec`'i sınıf seviyesinde monkeypatch'lemek çağrıyı HİÇ
    yakalamıyor — Shiboken/Qt bunu görmezden geliyor, gerçek modal döngü
    açılıp offscreen platformda SONSUZA KADAR bekliyor (bkz. bu paketin
    kendi `pytest.ini` zaman aşımı ayarının bile bunu kesemediği canlı
    deneme). Bu yüzden depo konvansiyonuyla AYNI yola gidildi (bkz.
    `tests/test_backup_reminder.py::test_main_hatirlatmayi_gosteriyor`'un
    "GÖSTERİM, AST ile denetleniyor" gerekçesi): metodun kaynağı
    ayrıştırılıp iki dalın da doğru metoda bağlı olduğu doğrulanıyor,
    gerçek modal HİÇ açılmadan.
    """
    import ast

    kaynak = (Path(__file__).resolve().parent.parent / "UI" / "main_window_layout.py").read_text(
        encoding="utf-8"
    )
    agac = ast.parse(kaynak)
    fn = next(
        n for n in ast.walk(agac)
        if isinstance(n, ast.FunctionDef) and n.name == "_on_add_new_menu"
    )
    cagrilar = {
        n.func.attr for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert "_on_add_file" in cagrilar, "'Dosya Ekle…' seçimi _on_add_file()'a bağlı değil"
    assert "_on_add_folder" in cagrilar, "'Klasör Ekle…' seçimi _on_add_folder()'a bağlı değil"


def test_add_new_dugmesi_rol_kisitlamasina_hala_uyuyor(win) -> None:
    """`_apply_role_restrictions()`'ın tuple'ı `_btn_add_new`'a güncellendi mi.

    `isVisibleTo(win)` kullanılıyor — pencere hiç `.show()` edilmediğinde
    (bu paketin testlerinin çoğunda olduğu gibi) düz `isVisible()` üst
    pencerenin kendisi görünür olmadığı için HER ZAMAN `False` döner;
    `isVisibleTo()` yalnızca `win`'e göreli görünürlüğü, yani `setVisible()`
    ile GERÇEKTEN ne ayarlandığını sorar.
    """
    win._role = "Salt Okunur"
    win._apply_role_restrictions()
    assert win._btn_add_new.isVisibleTo(win) is False
    win._role = "Yönetici"
    win._apply_role_restrictions()
    assert win._btn_add_new.isVisibleTo(win) is True


# ══════════════════════════════════════════════════════════════════════════════
# 2. Arama çubuğu konumu
# ══════════════════════════════════════════════════════════════════════════════


def test_arama_cubugu_action_bara_tasindi(win) -> None:
    assert win._search_bar.parentWidget().objectName() == "search_container"
    ust_ata = win._search_bar.parentWidget().parentWidget()
    assert ust_ata.objectName() == "action_bar"


def test_arama_hala_calisiyor(win, qapp, tmp_path) -> None:
    """Taşıma sonrası `_search_files()` bağlantısı hâlâ canlı."""
    _gercek_dosya_ekle(win, qapp, tmp_path, "bulunacak-dosya.txt")
    win._on_sidebar_click("Genel", win._nav_btns["Genel"])
    assert win._table.rowCount() == 1

    win._search_bar.setText("bulunmayan-terim-xyz")
    assert win._table.rowCount() == 0

    win._search_bar.setText("bulunacak")
    assert win._table.rowCount() == 1


# ══════════════════════════════════════════════════════════════════════════════
# 3. Tarama sütunu — nokta + metin
# ══════════════════════════════════════════════════════════════════════════════


def test_tarama_rozeti_onunde_nokta_var(win, qapp, tmp_path) -> None:
    _gercek_dosya_ekle(win, qapp, tmp_path, "temiz.txt")
    win._on_sidebar_click("Genel", win._nav_btns["Genel"])

    item = win._table.item(0, 4)
    assert item is not None
    assert item.text().startswith("●"), f"nokta öneki yok: {item.text()!r}"
    assert "Temiz" in item.text()


# ══════════════════════════════════════════════════════════════════════════════
# 4. "⋯" satır menüsü
# ══════════════════════════════════════════════════════════════════════════════


def test_satirda_gorunur_more_dugmesi_var(win, qapp, tmp_path) -> None:
    _gercek_dosya_ekle(win, qapp, tmp_path, "belge.pdf")
    win._on_sidebar_click("Genel", win._nav_btns["Genel"])

    assert win._table.columnCount() == 6
    cw = win._table.cellWidget(0, 5)
    assert cw is not None
    dugme = cw.findChild(QLabel, "more_menu_dugmesi")
    assert dugme is not None
    assert dugme.text() == "⋯"


def test_more_dugmesi_ayni_context_menuyu_dogru_satir_icin_aciyor(
    win, qapp, tmp_path, monkeypatch
) -> None:
    _gercek_dosya_ekle(win, qapp, tmp_path, "ilk.txt")
    _gercek_dosya_ekle(win, qapp, tmp_path, "ikinci.txt")
    win._on_sidebar_click("Genel", win._nav_btns["Genel"])
    win.show()
    qapp.processEvents()

    yakalanan: dict = {}
    monkeypatch.setattr(win, "_on_context_menu", lambda pos: yakalanan.setdefault("pos", pos))

    cw_ikinci_satir = win._table.cellWidget(1, 5)
    dugme = cw_ikinci_satir.findChild(QLabel, "more_menu_dugmesi")
    dugme.mousePressEvent(None)

    assert "pos" in yakalanan, "_on_context_menu HİÇ çağrılmadı"
    satir = win._table.rowAt(yakalanan["pos"].y())
    assert satir == 1, f"yanlış satır için açıldı: {satir}"


# ══════════════════════════════════════════════════════════════════════════════
# 5. B-124 — USB rozeti üst barda
# ══════════════════════════════════════════════════════════════════════════════


def test_usb_rozeti_ust_barda_kenar_cubugunda_degil(win) -> None:
    assert win._usb_badge.parentWidget().objectName() == "top_bar"


def test_usb_rozeti_takili_ve_cikarili_durumlari_gercekten_yansitiyor(win) -> None:
    win._usb.tak(_HWID)
    win._refresh_usb_badge()
    assert _HWID[:8] in win._usb_badge.text()
    assert "USB Yok" not in win._usb_badge.text()

    win._usb.cikar()
    win._refresh_usb_badge()
    assert "USB Yok" in win._usb_badge.text()


# ══════════════════════════════════════════════════════════════════════════════
# MC-Kataloğu (2026-09-10) — Toplu yükleme worker hata işleme (MC-M088 ★)
# ══════════════════════════════════════════════════════════════════════════════

def test_sifreleme_hatasi_basarili_olarak_isaretlenmiyor(
    win, qapp, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    MC-Kataloğu M088 ★: `_FileRunnable.run()`'da `encrypt_file()`
    GERÇEKTEN başarısız olursa dosyanın tabloya "başarıyla eklenmiş" gibi
    GİRMEMESİ gerekiyor — `result["ok"]` False kalmalı, `_batch_errors`
    artmalı. Bugüne kadar hiçbir test bu senaryoyu (toplu yükleme
    sırasında gerçek bir şifreleme hatası) simüle etmiyordu.

    Mutasyon-kanıt: `except Exception` bloğunda `ok=True` yapılıp eksik
    alanlar (size_bytes, sha256, file_id, vb.) sahte değerlerle
    doldurularak `file_done` yayınlanınca bu dosyanın (ve tüm test
    paketinin, 155 test) HİÇBİRİ fark etmedi.
    """
    from UI import main_window_table as mwt

    def patlayan_encrypt_file(*a, **k):
        raise OSError("disk dolu (simüle)")

    monkeypatch.setattr(mwt, "encrypt_file", patlayan_encrypt_file)

    f = tmp_path / "basarisiz.txt"
    f.write_bytes(b"icerik")
    win._handle_dropped_file(f, label="Genel")
    assert _pump(qapp, lambda: win._batch_total >= 1 and win._batch_done >= win._batch_total), (
        "dosya işleme zaman aşımına uğradı"
    )

    win._on_sidebar_click("Genel", win._nav_btns["Genel"])
    assert win._table.rowCount() == 0, "şifrelemesi başarısız dosya tabloya eklenmiş"
    assert win._batch_errors == 1
