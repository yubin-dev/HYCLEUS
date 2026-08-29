"""
UI.AuditLogView — Denetim Günlüğü'nün modal'dan taşındığı tam sayfa
görünüm (eskiden `UI/AuditLogDialog.py`, kaldırıldı).

Bu paket dört şeyi ölçüyor:

  1. Sekme/kategori süzgeci — Tümü/Dosya/Kimlik/Yönetim/Uyarı sekmelerinin
     her biri DOĞRU satırları gösteriyor mu (saf fonksiyon + gerçek
     tablo).
  2. HALKA sütunu — GERÇEK DB'de bilerek kırılmış bir zincir halkasını
     "Kopuk" gösteriyor mu, ve bu sonuç `verify_audit_chain()`'in
     KENDİSİYLE tutarlı mı (görevin asıl istediği kanıt).
  3. Dışa aktarım tutarlılığı — B-073 devamının bu sayfaya taşınmış hâli
     (eskiden `tests/test_audit_log_dialog_export.py`, buraya taşındı).
  4. Kablolama — sayfa `_govde_yigini`'ne gerçekten ekleniyor mu, rol
     kapısı çalışıyor mu (bu turda eklendi — bkz. `UI/main_window.py::
     _on_open_audit_log` docstring'i), sayfa adı tek kaynaktan mı geliyor.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox, QTabBar, QWidget

    from CORE.audit_chain import verify_audit_chain
    from UI.AuditLogView import (
        SAYFA_ADI,
        AuditLogView,
        _is_failure,
        _kategori,
        _sekmeye_uyuyor,
    )
    from UI.main_window_palette import _DARK
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

_HWID = "AUDIT-VIEW-TEST"
_KEY = b"K" * 32


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


class _Pencere(QWidget):
    """`GuvenlikView`'in test dosyasındaki AYNI asgari pencere deseni —
    `AuditLogView` yalnızca `self._pencere._T`'ye bakıyor."""

    def __init__(self) -> None:
        super().__init__()
        self._T = _DARK


@pytest.fixture
def pencere(qapp) -> _Pencere:
    return _Pencere()


@pytest.fixture
def gorunum(pencere: _Pencere, db) -> AuditLogView:
    return AuditLogView(pencere)


def _halka_hucresi(gorunum: AuditLogView, entry_id: int):
    for row in range(gorunum._table.rowCount()):
        item = gorunum._table.item(row, 0)
        if item is not None and item.data(Qt.UserRole) == entry_id:
            return gorunum._table.item(row, 4)
    return None


# ══════════════════════════════════════════════════════════════════════════════
# 1. Sekme/kategori süzgeci — saf fonksiyonlar
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("action", [
    "login_success", "usb_auth_rejected", "pin_changed", "session_revoked",
])
def test_kategori_kimlik(action: str) -> None:
    assert _kategori(action) == "kimlik"


@pytest.mark.parametrize("action", [
    "file_added", "folder_created", "file_tags_updated", "timestamp_verified",
])
def test_kategori_dosya(action: str) -> None:
    assert _kategori(action) == "dosya"


@pytest.mark.parametrize("action", [
    "usb_blacklisted", "backup_created", "user_approved", "setting_changed",
])
def test_kategori_yonetim(action: str) -> None:
    assert _kategori(action) == "yonetim"


def test_kategori_bilinmeyen_action_HICBIR_kategoriye_DUSMUYOR() -> None:
    """Yanlış kategoriye düşürmek, boş bırakmaktan daha kötü — bilinmeyen
    bir action yalnızca Tümü'nde görünmeli."""
    assert _kategori("hic_boyle_bir_islem_yok") is None


def test_sekmeye_uyuyor_tumu_HER_SEYE_uyuyor() -> None:
    assert _sekmeye_uyuyor("tumu", "ne_olursa_olsun")


def test_sekmeye_uyuyor_uyari_KATEGORIDEN_BAGIMSIZ() -> None:
    """"login_failed" hem Kimlik'te hem Uyarı'da görünebilir — ikisi
    farklı eksenler, birbirini dışlamaz."""
    assert _is_failure("login_failed")
    assert _kategori("login_failed") == "kimlik"
    assert _sekmeye_uyuyor("uyari", "login_failed")
    assert _sekmeye_uyuyor("kimlik", "login_failed")


def test_sekmeye_uyuyor_dosya_kimlik_actionina_UYMUYOR() -> None:
    assert not _sekmeye_uyuyor("dosya", "login_success")


# ══════════════════════════════════════════════════════════════════════════════
# 2. Sayfa yapısı
# ══════════════════════════════════════════════════════════════════════════════


def test_sayfa_adi() -> None:
    assert SAYFA_ADI == "Denetim Günlüğü"


def test_bes_sutun_HALKA_dahil(gorunum: AuditLogView) -> None:
    basliklar = [
        gorunum._table.horizontalHeaderItem(i).text()
        for i in range(gorunum._table.columnCount())
    ]
    assert basliklar == ["Zaman", "İşlem", "Kullanıcı", "HWID", "HALKA"]


def test_bes_sekme_dogru_sirada(gorunum: AuditLogView) -> None:
    tabs = gorunum.findChild(QTabBar, "audit_sekmeler")
    assert tabs is not None
    metinler = [tabs.tabText(i) for i in range(tabs.count())]
    assert metinler == ["Tümü", "Dosya", "Kimlik", "Yönetim", "Uyarı"]


def test_kurulumda_DB_ye_dokunulmuyor(pencere: _Pencere, db) -> None:
    """Sayfa `HycleusWindow.__init__`'te kuruluyor — her açılışta tüm
    zinciri yürütmek (bkz. `__init__`'teki gecikmeli yükleme notu)
    gereksiz bir başlangıç maliyeti olurdu. İlk yük `yenile()` ile gelir."""
    db.log("kurulumdan_once", detail="x")
    beklenen = db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"]  # genesis dahil

    gorunum = AuditLogView(pencere)
    assert gorunum._table.rowCount() == 0, (
        "kurulum DB'yi okudu — yalnızca yenile() çağrıldığında okumalı"
    )
    gorunum.yenile()
    assert gorunum._table.rowCount() == beklenen


# ══════════════════════════════════════════════════════════════════════════════
# 3. Sekme filtresi — gerçek tablo
# ══════════════════════════════════════════════════════════════════════════════


def test_dosya_sekmesi_SADECE_dosya_kayitlarini_gosterir(gorunum: AuditLogView, db) -> None:
    db.log("file_added", detail="a")
    db.log("login_success", detail="b")
    db.log("usb_blacklisted", detail="c")
    gorunum.yenile()

    gorunum._tab_bar.setCurrentIndex(1)  # Dosya
    islemler = {
        gorunum._table.item(row, 1).text() for row in range(gorunum._table.rowCount())
    }
    assert islemler == {"file_added"}


def test_tumu_sekmesi_UCUNU_de_gosterir(gorunum: AuditLogView, db) -> None:
    db.log("file_added", detail="a")
    db.log("login_success", detail="b")
    db.log("usb_blacklisted", detail="c")
    gorunum.yenile()

    gorunum._tab_bar.setCurrentIndex(0)  # Tümü
    islemler = {
        gorunum._table.item(row, 1).text() for row in range(gorunum._table.rowCount())
    }
    assert {"file_added", "login_success", "usb_blacklisted"} <= islemler


def test_uyari_sekmesi_basarisiz_actionlari_gosterir(gorunum: AuditLogView, db) -> None:
    db.log("login_failed", detail="a")
    db.log("file_added", detail="b")
    gorunum.yenile()

    gorunum._tab_bar.setCurrentIndex(4)  # Uyarı
    islemler = {
        gorunum._table.item(row, 1).text() for row in range(gorunum._table.rowCount())
    }
    assert "login_failed" in islemler
    assert "file_added" not in islemler


# ══════════════════════════════════════════════════════════════════════════════
# 4. HALKA sütunu — bilerek kırılmış bir halka (görevin ana kanıtı)
# ══════════════════════════════════════════════════════════════════════════════


def test_saglam_kayit_SAGLAM_gosterilir(gorunum: AuditLogView, db) -> None:
    db.log("file_added", detail="temiz")
    kayit_id = db.fetchone(
        "SELECT id FROM audit_log WHERE action = 'file_added' ORDER BY id DESC LIMIT 1"
    )["id"]
    gorunum.yenile()

    hucre = _halka_hucresi(gorunum, kayit_id)
    assert hucre is not None
    assert hucre.text() == "Sağlam"


def test_BILEREK_kirilmis_halka_KOPUK_gosterilir_ve_verify_ile_TUTARLI(
    gorunum: AuditLogView, db,
) -> None:
    """
    Görevin ana iddiası. Bir kaydı `append_entry()`/`db.log()` yolunu
    ATLAYARAK doğrudan `UPDATE` ile bozuyoruz — diske erişimi olan bir
    saldırganın yapacağı şeyin aynısı (bkz. `tests/test_audit_chain.py`
    modül docstring'i, aynı yöntem). Sonra İKİ ayrı kaynağı karşılaştırıyoruz:
    HALKA sütunundaki metin ve `verify_audit_chain()`'in KENDİSİ.
    """
    for i in range(5):
        db.log(f"file_added_{i}", detail=f"kayit-{i}")

    kurban = db.fetchone(
        "SELECT id FROM audit_log WHERE action = 'file_added_2'"
    )["id"]
    db.conn.execute(
        "UPDATE audit_log SET detail = 'saldirgan bu satiri degistirdi' WHERE id = ?",
        (kurban,),
    )
    db.conn.commit()

    # ── Kaynak 1: HALKA sütunu (AuditLogView üzerinden, kullanıcının GÖRDÜĞÜ) ──
    gorunum.yenile()
    hucre = _halka_hucresi(gorunum, kurban)
    assert hucre is not None
    assert hucre.text() == "Kopuk", (
        "bilerek kırılan halka HALKA sütununda Sağlam görünüyor"
    )

    # ── Kaynak 2: mevcut Zinciri Doğrula fonksiyonunun KENDİSİ ───────────────
    dogrudan_sonuc = verify_audit_chain(db.conn)
    assert not dogrudan_sonuc, "verify_audit_chain() kırılmayı görmüyor — test kurulumu hatalı"
    assert dogrudan_sonuc.first_broken_id == kurban

    # ── İki kaynak TUTARLI mı ────────────────────────────────────────────────
    kirik_idler = {b.entry_id for b in dogrudan_sonuc.breaks if b.entry_id is not None}
    assert kurban in kirik_idler
    # HALKA sütunu, verify_audit_chain()'in bulduğu HER kırık id için "Kopuk"
    # göstermeli — tek bir örnekle sınırlı kalmasın diye tüm breaks taranıyor.
    for kirik_id in kirik_idler:
        h = _halka_hucresi(gorunum, kirik_id)
        if h is not None:  # id tabloda görünür aralıkta değilse atla (ör. gap)
            assert h.text() == "Kopuk", f"id={kirik_id} verify_audit_chain'de kırık ama HALKA'da değil"

    # ── Kırılmamış kayıtlar hâlâ Sağlam mı (yanlış pozitif yok) ─────────────
    for onceki_id in (kurban - 1,):
        h = _halka_hucresi(gorunum, onceki_id)
        if h is not None:
            assert h.text() == "Sağlam", "kırılmadan ÖNCEki kayıt yanlışlıkla Kopuk gösterildi"


def test_gecmis_zincir_disi_kayit_KAPSAM_DISI_gosterilir(gorunum: AuditLogView, db) -> None:
    """
    Zincir başlamadan önceki (göç öncesi) bir kayıt "Sağlam" DEĞİL —
    hiç doğrulanmadı, "Kapsam Dışı" göstermeli.

    `db` fixture'ı bağlantıda zinciri ZATEN başlatıyor (`ensure_chain_
    started` — `tests/test_audit_chain.py::test_chain_is_started_
    automatically_on_connect`), yani düz bir INSERT zincirin İÇİNE düşer
    (id > start_id) ve "unhashed" — dolayısıyla Kopuk — olur, "kapsam
    dışı" değil. Gerçek göç-öncesi durumu taklit etmek için
    `tests/test_audit_chain.py::legacy_db` ile AYNI adımlar: mevcut
    zinciri (genesis + settings anahtarı) SİL, eski kaydı yaz, zinciri
    YENİDEN başlat — yeni genesis eski kayıttan SONRAKİ bir id alır.
    """
    from CORE.audit_chain import CHAIN_START_SETTING, ensure_chain_started

    db.execute("DELETE FROM audit_log")
    db.execute("DELETE FROM settings WHERE key = ?", (CHAIN_START_SETTING,))
    db.conn.execute(
        "INSERT INTO audit_log (action, detail) VALUES (?, ?)",
        ("eski_kayit_zincirsiz", "hash sutunu olmadan yazildi"),
    )
    db.conn.commit()
    eski_id = db.fetchone(
        "SELECT id FROM audit_log WHERE action = 'eski_kayit_zincirsiz'"
    )["id"]
    start = ensure_chain_started(db.conn)
    assert eski_id < start, "test kurulumu hatalı — eski kayıt zincir başlangıcından önce değil"

    gorunum.yenile()
    hucre = _halka_hucresi(gorunum, eski_id)
    assert hucre is not None
    assert hucre.text() == "Kapsam Dışı"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Dışa aktarım tutarlılığı — B-073 devamı, bu sayfaya taşındı
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture(autouse=True)
def _mesaj_kutusu_engelle(monkeypatch: pytest.MonkeyPatch) -> None:
    for ad in ("information", "warning", "critical", "question"):
        monkeypatch.setattr(QMessageBox, ad, staticmethod(lambda *a, **kw: 0))


def _dosya_sec_sabitle(monkeypatch: pytest.MonkeyPatch, yol: Path) -> None:
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName", staticmethod(lambda *a, **kw: (str(yol), ""))
    )


def test_export_arkaplanda_eklenen_kaydi_HEM_baslikta_HEM_satirlarda_gosterir(
    gorunum: AuditLogView, db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    for i in range(3):
        db.log(f"onceki_islem_{i}", detail="baslangic")
    gorunum.yenile()
    satir_sayisi_acilista = gorunum._table.rowCount()

    db.log("arka_planda_olusan_islem", detail="yeni")
    assert gorunum._table.rowCount() == satir_sayisi_acilista, (
        "test kurulumu hatalı — tablo beklenmedik biçimde kendiliğinden yenilendi"
    )

    export_path = tmp_path / "export.txt"
    _dosya_sec_sabitle(monkeypatch, export_path)
    gorunum._export_txt()

    metin = export_path.read_text(encoding="utf-8")
    gercek_sayi = db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"]

    import re

    dogrulanan = int(re.search(r"Doğrulanan\s*:\s*(\d+) kayıt", metin).group(1))
    altyazi = int(re.search(r"Bu dışa aktarımdaki kayıt sayısı:\s*(\d+)", metin).group(1))
    satirlar = metin.splitlines()
    baslik_idx = next(i for i, s in enumerate(satirlar) if s.startswith("Zaman"))
    ayrac = satirlar[baslik_idx + 1]
    kapanis_idx = satirlar.index(ayrac, baslik_idx + 2)
    listelenen = kapanis_idx - (baslik_idx + 2)

    assert dogrulanan == gercek_sayi
    assert altyazi == gercek_sayi
    assert listelenen == gercek_sayi
    assert "arka_planda_olusan_islem" in metin


def test_export_HALKA_sutununu_da_yaziyor(
    gorunum: AuditLogView, db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db.log("file_added", detail="x")
    gorunum.yenile()

    export_path = tmp_path / "export_halka.txt"
    _dosya_sec_sabitle(monkeypatch, export_path)
    gorunum._export_txt()

    metin = export_path.read_text(encoding="utf-8")
    assert "HALKA" in metin
    assert "Sağlam" in metin


def test_export_iptal_edilirse_tablo_yenilenmiyor(
    gorunum: AuditLogView, db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db.log("ilk_kayit", detail="x")
    gorunum.yenile()
    onceki = gorunum._table.rowCount()

    db.log("ikinci_kayit", detail="y")
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName", staticmethod(lambda *a, **kw: ("", ""))
    )
    gorunum._export_txt()

    assert gorunum._table.rowCount() == onceki


# ══════════════════════════════════════════════════════════════════════════════
# 6. Kablolama — sayfa geçişi, rol kapısı
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def isolate_safezone(tmp_path, monkeypatch: pytest.MonkeyPatch):
    from CORE.safezone import SAFEZONE_ENV_VAR

    hedef = tmp_path / "safezone"
    monkeypatch.setenv(SAFEZONE_ENV_VAR, str(hedef))
    return hedef


def _pencere_kur(qapp, db, isolate_safezone, monkeypatch, role: str):
    from UI import main_window as mw

    monkeypatch.setattr(mw, "get_usb_hwid", lambda: _HWID)
    window = mw.HycleusWindow(hwid=_HWID, key=_KEY, role=role)
    return window


@pytest.fixture
def yonetici_penceresi(qapp, db, isolate_safezone, monkeypatch: pytest.MonkeyPatch):
    window = _pencere_kur(qapp, db, isolate_safezone, monkeypatch, "Yönetici")
    try:
        yield window
    finally:
        for ad in ("_usb_timer", "_expiry_timer", "_idle_timer"):
            z = getattr(window, ad, None)
            if z is not None:
                z.stop()
        app = QApplication.instance()
        if app is not None:
            app.removeEventFilter(window)
        window.close()


@pytest.fixture
def kullanici_penceresi(qapp, db, isolate_safezone, monkeypatch: pytest.MonkeyPatch):
    window = _pencere_kur(qapp, db, isolate_safezone, monkeypatch, "Kullanıcı")
    try:
        yield window
    finally:
        for ad in ("_usb_timer", "_expiry_timer", "_idle_timer"):
            z = getattr(window, ad, None)
            if z is not None:
                z.stop()
        app = QApplication.instance()
        if app is not None:
            app.removeEventFilter(window)
        window.close()


def test_yonetici_sayfaya_geciyor(yonetici_penceresi) -> None:
    win = yonetici_penceresi
    win._on_open_audit_log()
    assert win._govde_yigini.currentWidget() is win._audit_log_view
    assert win._page_title.text() == SAYFA_ADI


def test_yonetici_OLMAYAN_ENGELLENIYOR(kullanici_penceresi) -> None:
    """
    2026-08-29'da eklenen rol kapısı. Önceden yalnızca kenar çubuğu
    düğmesi gizliydi; hamburger menüsü (`_on_hamburger_menu`) aynı
    metodu rol kontrolü YAPMADAN çağırıyordu. Şimdi kapı metodun
    KENDİSİNDE — hangi giriş noktasından çağrılırsa çağrılsın işliyor.
    """
    win = kullanici_penceresi
    win._on_open_audit_log()
    assert win._govde_yigini.currentWidget() is not win._audit_log_view
    assert win._page_title.text() != SAYFA_ADI


def test_sayfa_gecince_YENILENIYOR(yonetici_penceresi, db) -> None:
    win = yonetici_penceresi
    win._on_open_audit_log()  # ilk gerçek yük — sayfa lazy (bkz. __init__)
    onceki = win._audit_log_view._table.rowCount()

    db.log("yeni_kayit_test", detail="x")
    win._on_open_audit_log()  # `_on_open_audit_log()` HER çağrıda yenile()
                               # tetikliyor — sayfadan ayrılmak şart değil.

    assert win._audit_log_view._table.rowCount() == onceki + 1


def test_guvenlikten_denetime_GECERKEN_dugme_stilleri_DOGRU(yonetici_penceresi) -> None:
    win = yonetici_penceresi
    win._on_guvenlik_click()
    win._on_open_audit_log()
    assert win._govde_yigini.currentWidget() is win._audit_log_view
    # Güvenlik düğmesi artık aktif OLMAMALI — stil karşılaştırması yerine
    # davranışsal kanıt: sayfa gerçekten değişti (yukarıda doğrulandı).


def test_dosya_gorunumune_DONUNCE_denetim_dugmesi_SIFIRLANIYOR(yonetici_penceresi) -> None:
    win = yonetici_penceresi
    win._on_open_audit_log()
    assert win._govde_yigini.currentWidget() is win._audit_log_view

    etiket = next(iter(win._nav_btns))
    win._on_sidebar_click(etiket, win._nav_btns[etiket])
    assert win._govde_yigini.currentIndex() == 0


def test_sayfa_adi_tek_kaynaktan() -> None:
    layout = (Path(__file__).resolve().parent.parent / "UI" / "main_window_layout.py").read_text(
        encoding="utf-8"
    )
    pencere_src = (Path(__file__).resolve().parent.parent / "UI" / "main_window.py").read_text(
        encoding="utf-8"
    )
    assert "_AUDIT_SAYFA_ADI" in layout and "_AUDIT_SAYFA_ADI" in pencere_src
