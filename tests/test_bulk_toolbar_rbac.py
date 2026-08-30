"""
HYCLEUS — Toplu işlem araç çubuğu (kutucuklar) — K1-14 rol denetimi (B-094)

Görev: "Her toplu işlem ... en kritik nokta: K1-14'te kurduğun DB seviyesi
rol denetiminin toplu işlemlerde de aynı şekilde çalıştığından emin ol
(salt-okunur bir kullanıcı toplu imha/taşıma yapamamalı)."

Bu dosya YENİ bir RBAC mekanizması KURMUYOR. `DBManager.execute()`'un
`_yazma_yetkisini_dogrula()`'sı (K1-14/B-074, `DB/db_manager.py`) ZATEN
var ve `files` tablosunu koruyor; `UI/main_window_bulk.py`'nin sağ tık
menüsü de bu korumanın ALTINDAN geçiyor, çünkü ikisi de AYNI `db.execute()`
döngüsünü çağırıyor. Ölçülen şey: kutucuk + araç çubuğu GİRİŞ NOKTASININ
(`_on_bulk_toolbar_*`, `UI/GuvenlikView.py`'dekiyle AYNI "iki giriş
noktası, tek gövde" ilkesiyle eklendi) bu KORUMAYA GERÇEKTEN ULAŞTIĞI —
bu, önceden HİÇ ölçülmemişti çünkü giriş noktasının kendisi bu turda yeni.

Kurulum sırası ÖNEMLİ
----------------------
`_dosya_ekle()` dosyaları HİÇBİR pencere kurulmadan ÖNCE ekliyor —
o an `DBManager._role` hâlâ `None` ve `_yazma_yetkisini_dogrula()` bu
durumda hiç ÇALIŞMIYOR (fonksiyonun kendi ilk satırı), yani INSERT'ler
rol ne olacaksa OLSUN her zaman geçer. `HycleusWindow.__init__()` ZATEN
`_on_sidebar_click("Genel", ...)` ile bu dosyaları tabloya OTOMATİK
yüklüyor — `_insert_row()`'u BİR KEZ DAHA elle çağırmak (ilk taslakta
yapılmıştı) satırları İKİLERdi; bkz. `_satir_bul()`.

`_apply_role_restrictions()` `__init__` içinde ÇAĞRILMIYOR — üretimde
`main.py`'nin `.show()` SONRASI tetiklediği ayrı bir adım (`tests/
test_app_mode_ui.py`'nin AYNI notu). `pencere_kur()` bunu ELLE çağırıyor;
çağırmasaydı `DBManager()._role` `None` kalır ve K1-14 rolü HİÇ KONTROL
ETMEDEN geçerdi — testin asıl ölçmek istediği reddi hiç TETİKLEMEZDİ.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QMessageBox

    from UI import main_window as mw
    from UI.main_window import HycleusWindow
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

_KEY = b"K" * 32
_HWID = "BULK-TOOLBAR-RBAC-HWID"


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


@pytest.fixture(autouse=True)
def _diyaloglari_engelle(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Onay/bilgi/hata kutularını engeller — testin akışını bloklamasınlar.

    `question` HER ZAMAN `Yes` dönüyor: `_on_ctx_bulk_move_to_kritik`/
    `_move_to_imha` işleme geçmeden ÖNCE bunu bekliyor — engellenmeseydi
    (ya da hep `No` dönseydi) testler yetkili roldeki işlemi bile hiç
    TETİKLEMEMİŞ olurdu.
    """
    monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **kw: None))
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **kw: None))
    monkeypatch.setattr(QMessageBox, "critical", staticmethod(lambda *a, **kw: None))
    monkeypatch.setattr(QMessageBox, "question",
                        staticmethod(lambda *a, **kw: QMessageBox.Yes))


@pytest.fixture
def pencere_kur(qapp, db, monkeypatch: pytest.MonkeyPatch):
    """Fabrika: `pencere_kur(role)` gerçek bir `HycleusWindow` kurar."""
    monkeypatch.setattr(mw, "get_usb_hwid", lambda: _HWID)
    pencereler: list[HycleusWindow] = []

    def _kur(role: str) -> HycleusWindow:
        win = HycleusWindow(hwid=_HWID, key=_KEY, role=role)
        win._apply_role_restrictions()  # bkz. modül docstring'i
        pencereler.append(win)
        return win

    yield _kur

    for win in pencereler:
        for ad in ("_usb_timer", "_expiry_timer", "_idle_timer"):
            zamanlayici = getattr(win, ad, None)
            if zamanlayici is not None:
                zamanlayici.stop()
        QApplication.instance().removeEventFilter(win)
        win.close()


def _dosya_ekle(db, filename: str, label: str = "Genel") -> int:
    """`files` tablosuna bir satır ekler — bkz. modül docstring'i, "Kurulum
    sırası ÖNEMLİ"."""
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label) VALUES (?, ?, ?)",
        (filename, f"/tmp/{filename}", label),
    )
    return int(cur.lastrowid)


def _satir_bul(win: HycleusWindow, file_id: int) -> int:
    """`file_id`'nin tablodaki satır indeksi — bkz. modül docstring'i."""
    for r in range(win._table.rowCount()):
        item = win._table.item(r, 0)
        if item is not None and item.data(Qt.UserRole) == file_id:
            return r
    raise AssertionError(f"file_id={file_id} tabloda bulunamadı")


def _isaretle(win: HycleusWindow, file_id: int) -> None:
    win._table.item(_satir_bul(win, file_id), 0).setCheckState(Qt.Checked)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Salt Okunur — toplu kutucuk seçimiyle bile KRİTİK işlem YAPAMIYOR
# ══════════════════════════════════════════════════════════════════════════════


def test_salt_okunur_toplu_kritike_tasima_REDDEDILIYOR(pencere_kur, db) -> None:
    f1 = _dosya_ekle(db, "a.txt")
    f2 = _dosya_ekle(db, "b.txt")

    win = pencere_kur("Salt Okunur")
    _isaretle(win, f1)
    _isaretle(win, f2)

    win._on_bulk_toolbar_kritik()  # İSTİSNA SIZMAMALI — kendi try/except'i var

    for fid in (f1, f2):
        satir = db.fetchone("SELECT label FROM files WHERE id = ?", (fid,))
        assert satir["label"] == "Genel", (
            f"file_id={fid}: salt okunur rol dosyayı Kritik'e taşıyabildi"
        )

    # İşlem başarısız oldu — satırlar tablodan KALDIRILMAMALI.
    assert win._table.rowCount() == 2

    kayit = db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'rbac_write_rejected'"
        " ORDER BY id DESC LIMIT 1"
    )
    assert kayit is not None, "ret denetim kaydına düşmedi"
    assert "Salt Okunur" in kayit["detail"]
    assert "files" in kayit["detail"]


def test_salt_okunur_toplu_imha_REDDEDILIYOR(pencere_kur, db) -> None:
    """Görevin AÇIKÇA adlandırdığı ikinci senaryo — "toplu imha... yapamamalı"."""
    f1 = _dosya_ekle(db, "c.txt")
    f2 = _dosya_ekle(db, "d.txt")

    win = pencere_kur("Salt Okunur")
    _isaretle(win, f1)
    _isaretle(win, f2)

    win._on_bulk_toolbar_imha()

    for fid in (f1, f2):
        satir = db.fetchone("SELECT label, expires_at FROM files WHERE id = ?", (fid,))
        assert satir["label"] == "Genel", (
            f"file_id={fid}: salt okunur rol dosyayı İmha'ya taşıyabildi"
        )
        assert satir["expires_at"] is None

    assert win._table.rowCount() == 2

    kayit = db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'rbac_write_rejected'"
        " ORDER BY id DESC LIMIT 1"
    )
    assert kayit is not None
    assert "Salt Okunur" in kayit["detail"]


def test_salt_okunur_toplu_islem_pencereyi_KILITLEMIYOR(pencere_kur, db) -> None:
    """
    Ret bir AuthenticationError/kilit değil — yalnızca bu YAZMA reddedildi.
    `_lock()` çağrılmadığını doğrulamak, RBAC reddinin B-064/B-066'nın
    canlı-yetki kilitlemesiyle KARIŞTIRILMADIĞINI gösteriyor — ikisi ayrı
    mekanizma, ayrı tepki.
    """
    f1 = _dosya_ekle(db, "e.txt")
    win = pencere_kur("Salt Okunur")
    _isaretle(win, f1)

    win._on_bulk_toolbar_imha()

    assert win._locked is False


# ══════════════════════════════════════════════════════════════════════════════
# 2. Yetkili rol — toplu işlem TÜM seçili dosyalara, YALNIZCA onlara uygulanıyor
# ══════════════════════════════════════════════════════════════════════════════


def test_yonetici_toplu_imha_TUM_secilenlere_dogru_uygulaniyor(pencere_kur, db) -> None:
    f1 = _dosya_ekle(db, "f.txt")
    f2 = _dosya_ekle(db, "g.txt")
    f3 = _dosya_ekle(db, "h.txt")  # İŞARETLENMEYECEK — kontrol grubu

    win = pencere_kur("Yönetici")
    _isaretle(win, f1)
    _isaretle(win, f2)
    # h.txt İŞARETLENMEDİ.

    win._on_bulk_toolbar_imha()

    for fid in (f1, f2):
        satir = db.fetchone("SELECT label FROM files WHERE id = ?", (fid,))
        assert satir["label"] == "Imha", f"file_id={fid} imhaya taşınmadı"

    kontrol = db.fetchone("SELECT label FROM files WHERE id = ?", (f3,))
    assert kontrol["label"] == "Genel", (
        "İŞARETLENMEYEN dosya da imhaya taşınmış — seçim kutucuktan değil "
        "başka bir kaynaktan (ör. tüm satırlar) okunuyor olabilir"
    )

    # İşaretli iki satır kaldırılmalı, işaretsiz KALMALI.
    assert win._table.rowCount() == 1
    kalan_fid = win._table.item(0, 0).data(Qt.UserRole)
    assert kalan_fid == f3

    # Araç çubuğu artık işaretli dosya kalmadığı için GİZLENMELİ.
    assert win._bulk_toolbar.isHidden()


def test_standart_rol_de_toplu_kritike_tasiyabiliyor(pencere_kur, db) -> None:
    """Yetki yalnızca Yönetici'ye özel değil — `can_write()` Standart'ı da
    kapsıyor, sağ tık menüsünün ZATEN kapsadığı AYNI küme."""
    f1 = _dosya_ekle(db, "i.txt")
    f2 = _dosya_ekle(db, "j.txt")

    win = pencere_kur("Standart")
    _isaretle(win, f1)
    _isaretle(win, f2)

    win._on_bulk_toolbar_kritik()

    for fid in (f1, f2):
        satir = db.fetchone("SELECT label FROM files WHERE id = ?", (fid,))
        assert satir["label"] == "Kritik"
    assert win._table.rowCount() == 0
    assert win._bulk_toolbar.isHidden()


def test_denetim_kaydi_dosya_basina_dogru_bilgiyle_dusuyor(pencere_kur, db) -> None:
    """Toplu işlemin denetim izi TEKİL işlemle AYNI ayrıntıda olmalı —
    `bulk=True` işaretiyle, ama `target_id` dosya BAŞINA doğru."""
    f1 = _dosya_ekle(db, "k.txt")
    win = pencere_kur("Yönetici")
    _isaretle(win, f1)

    win._on_bulk_toolbar_imha()

    kayit = db.fetchone(
        "SELECT target_id, detail FROM audit_log"
        " WHERE action = 'file_moved_to_imha' ORDER BY id DESC LIMIT 1"
    )
    assert kayit is not None
    assert kayit["target_id"] == f1
    assert "bulk=True" in kayit["detail"]


# ══════════════════════════════════════════════════════════════════════════════
# 3. Kutucuk durumu, satır SEÇİMİNDEN (native highlight) BAĞIMSIZ okunuyor
# ══════════════════════════════════════════════════════════════════════════════


def test_secili_ama_ISARETLENMEMIS_satirlar_toplu_islemi_TETIKLEMIYOR(
    pencere_kur, db,
) -> None:
    """
    `_checked_selection()` KUTUCUK durumunu okuyor, `QTableWidget`'ın
    native satır SEÇİMİNİ (mavi vurgu, Ctrl/Shift-tık) DEĞİL — ikisi
    karıştırılsaydı, bir kullanıcı yalnızca bir satırı TIKLAYIP (seçip)
    kutucuğu hiç işaretlemeden toplu bir işlemi kazayla tetikleyebilirdi.
    """
    f1 = _dosya_ekle(db, "l.txt")
    win = pencere_kur("Yönetici")
    win._table.selectRow(_satir_bul(win, f1))  # native seçim — kutucuk İŞARETLENMEDİ

    rows, file_ids, _, _ = win._checked_selection()
    assert rows == [] and file_ids == []
    assert win._bulk_toolbar.isHidden()
