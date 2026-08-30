"""
HYCLEUS — Bekleyen Kayıtlar: tablodan kart listesine geçiş (B-089).

Görev: "Bekleyen Kayıtlar tablosunu mockup'taki gibi kart listesine
çevir (isim + rol + HWID + kayıt tarihi, Onayla/Reddet butonları).
Kozmetik bir değişiklik, veri/mantığa dokunma." SQL sorgusu, onay/red
diyalog metinleri, DB yazıları ve denetim kaydı `detail=` biçimi TEK
KARAKTER değişmedi (bkz. `UI/PendingRegistrationsView.py`'nin Git
geçmişi) — değişen tek şey satır → kart eşlemesi ve "seçili satır"
kavramının kalkıp her kartın kendi "Onayla"/"Reddet" düğmesini
taşıması.

Bu paket üç şeyi ölçüyor:

  1. Kart İÇERİĞİ doğru mu (isim/rol/HWID/kayıt tarihi, HWID kırpması).
  2. Onaylama/reddetme akışı GERÇEK düğme tıklamasıyla (yalnızca
     `_on_approve(hwid, username)`'ı doğrudan çağırmak değil —
     `functools.partial` bağlamasının GERÇEKTEN doğru hwid/username'i
     taşıdığını da kanıtlamak için) doğru kullanıcıyı, birden fazla
     kart varken bile, ETKİLİYOR.
  3. Onay/redde giden DB yazısı ve denetim kaydı — mevcut testlerin
     (`tests/test_admin_pages_construction_guard.py`,
     `tests/test_authz_invariants.py`) zaten ölçtüğü guard/yetki
     davranışının TEKRARI DEĞİL, buradaki asıl iddia: "kart görünümünde
     de doğru çalışıyor" — yani içerik + doğru-hedef + DB/denetim
     sonucu.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QLabel, QMessageBox, QPushButton

    from UI.main_window import HycleusWindow
    from UI.PendingRegistrationsView import PendingRegistrationsView
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

_KEY = b"K" * 32
_ADMIN_HWID = "PENDING-KART-ADMIN-HWID"


@pytest.fixture
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


@pytest.fixture
def kasa_dizini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """`_on_reject()`'in `discard_vault()` çağrısı gerçek dosya sistemine
    gitmesin diye — `tests/test_profile_view.py`'nin AYNI fixture'ı."""
    from CORE import vault_manager
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / "legacy.hclv")
    return tmp_path


@pytest.fixture(autouse=True)
def _diyalog_onayla(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """QMessageBox çağrılarını yakalar; `question()` varsayılan olarak
    Yes döner — onay/red akışları testte İLERLESİN."""
    gosterilen: list[tuple[str, str]] = []

    def _yakala(sonuc):
        def _f(_parent, baslik, metin, *a, **kw):
            gosterilen.append((baslik, str(metin)))
            return sonuc
        return _f

    monkeypatch.setattr(QMessageBox, "warning", staticmethod(_yakala(0)))
    monkeypatch.setattr(QMessageBox, "critical", staticmethod(_yakala(0)))
    monkeypatch.setattr(QMessageBox, "information", staticmethod(_yakala(0)))
    monkeypatch.setattr(QMessageBox, "question", staticmethod(_yakala(QMessageBox.Yes)))
    return gosterilen


def _pencere(db, sahte_usb, *, role: str = "Yönetici") -> HycleusWindow:
    sahte_usb(_ADMIN_HWID)
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, 'admin', 'approved', ?)",
        ("kart.testi.admin", "x", _ADMIN_HWID),
    )
    return HycleusWindow(
        hwid=_ADMIN_HWID, key=_KEY, role=role, username="kart.testi.admin", user_id=1,
    )


def _pencereyi_kapat(window: HycleusWindow) -> None:
    for ad in ("_usb_timer", "_expiry_timer", "_idle_timer"):
        t = getattr(window, ad, None)
        if t is not None:
            t.stop()
    QApplication.instance().removeEventFilter(window)
    window.close()


def _bekleyen_ekle(db, hwid: str, username: str, role: str = "user",
                    created_at: str = "2026-08-30T10:00:00Z") -> None:
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid, created_at)"
        " VALUES (?, ?, ?, 'pending', ?, ?)",
        (username, "x", role, hwid, created_at),
    )


def _kart_for_hwid(sayfa: PendingRegistrationsView, hwid: str):
    for kart in sayfa._kart_widgetleri:
        if kart.property("hwid") == hwid:
            return kart
    raise AssertionError(f"{hwid!r} için kart bulunamadı — kartlar: "
                          f"{[k.property('hwid') for k in sayfa._kart_widgetleri]}")


def _kart_metinleri(kart) -> tuple[str, str]:
    isim = kart.findChild(QLabel, "pending_kart_isim")
    detay = kart.findChild(QLabel, "pending_kart_detay")
    assert isim is not None and detay is not None, (
        "kart beklenen etiketleri taşımıyor"
    )
    return isim.text(), detay.text()


def _kart_dugmesine_bas(kart, ad: str) -> None:
    btn = kart.findChild(QPushButton, ad)
    assert btn is not None, f"kartta {ad!r} düğmesi bulunamadı"
    btn.click()


# ══════════════════════════════════════════════════════════════════════════════
# 1 — Kart içeriği: isim + rol + HWID (+ kırpma) + kayıt tarihi
# ══════════════════════════════════════════════════════════════════════════════


def test_kart_isim_rol_hwid_tarih_dogru_gosteriyor(qapp, db, sahte_usb):
    _bekleyen_ekle(db, "KART-ICERIK-HWID", "ayse.demir", role="user",
                    created_at="2026-08-30T14:30:00Z")

    window = _pencere(db, sahte_usb)
    try:
        sayfa = window._pending_view
        sayfa._load_pending()
        assert len(sayfa._kart_widgetleri) == 1

        kart = sayfa._kart_widgetleri[0]
        isim, detay = _kart_metinleri(kart)
        assert isim == "ayse.demir"
        assert "user" in detay
        assert "KART-ICERIK-HWID" in detay
        assert "2026-08-30 14:30:00" in detay
    finally:
        _pencereyi_kapat(window)


def test_kart_uzun_hwid_kirpiliyor(qapp, db, sahte_usb):
    """28 karakterden uzun HWID kartta "…" ile kırpılıyor — eski
    `_pending_table`'ın AYNI 28-karakter sınırı (bkz. `UI/
    PendingRegistrationsView.py`'nin Git geçmişindeki `_load_pending()`)."""
    uzun_hwid = "H" * 40
    _bekleyen_ekle(db, uzun_hwid, "uzun.hwid.testi")

    window = _pencere(db, sahte_usb)
    try:
        sayfa = window._pending_view
        sayfa._load_pending()
        _, detay = _kart_metinleri(sayfa._kart_widgetleri[0])
        assert uzun_hwid[:28] + "…" in detay
        assert uzun_hwid not in detay, "HWID TAM hâliyle gösterilmiş — kırpılmamış"
    finally:
        _pencereyi_kapat(window)


def test_kart_kisa_hwid_kirpilmiyor(qapp, db, sahte_usb):
    kisa_hwid = "KISA-HWID"
    _bekleyen_ekle(db, kisa_hwid, "kisa.hwid.testi")

    window = _pencere(db, sahte_usb)
    try:
        sayfa = window._pending_view
        sayfa._load_pending()
        _, detay = _kart_metinleri(sayfa._kart_widgetleri[0])
        assert kisa_hwid in detay
        assert "…" not in detay
    finally:
        _pencereyi_kapat(window)


def test_bos_durumda_bos_mesaji_gosteriliyor_dolunca_gizleniyor(qapp, db, sahte_usb):
    window = _pencere(db, sahte_usb)
    try:
        sayfa = window._pending_view
        sayfa._load_pending()
        assert len(sayfa._kart_widgetleri) == 0
        assert sayfa._bos_etiketi.isHidden() is False

        _bekleyen_ekle(db, "DOLU-HWID", "dolu.testi")
        sayfa._load_pending()
        assert len(sayfa._kart_widgetleri) == 1
        assert sayfa._bos_etiketi.isHidden() is True
    finally:
        _pencereyi_kapat(window)


# ══════════════════════════════════════════════════════════════════════════════
# 2 — Onaylama/reddetme akışı: GERÇEK düğme tıklamasıyla, birden fazla
#     kart arasında DOĞRU hedefi vuruyor mu.
# ══════════════════════════════════════════════════════════════════════════════


def test_bir_kartin_onayla_dugmesi_SADECE_o_kullaniciyi_onayliyor(qapp, db, sahte_usb):
    """
    Asıl iddia: iki bekleyen kayıt varken, BİRİNCİ kartın "Onayla"
    düğmesine tıklamak yalnızca O kullanıcıyı onaylıyor — ikincisi
    ETKİLENMİYOR. `functools.partial(self._on_approve, hwid, username)`
    bağlamasının GERÇEKTEN doğru hwid'i taşıdığının kanıtı — yalnızca
    tek bir bekleyen kayıtla test edilseydi, hwid'in YANLIŞ bağlanmış
    olması bile (ör. hep SON satırınki) fark edilmezdi.
    """
    _bekleyen_ekle(db, "COKLU-HWID-1", "kullanici.bir")
    _bekleyen_ekle(db, "COKLU-HWID-2", "kullanici.iki")

    window = _pencere(db, sahte_usb)
    try:
        sayfa = window._pending_view
        sayfa._load_pending()
        assert len(sayfa._kart_widgetleri) == 2

        kart_bir = _kart_for_hwid(sayfa, "COKLU-HWID-1")
        _kart_dugmesine_bas(kart_bir, "pending_kart_btn_onayla")

        satir_bir = db.fetchone(
            "SELECT status FROM users WHERE hwid = ?", ("COKLU-HWID-1",)
        )
        satir_iki = db.fetchone(
            "SELECT status FROM users WHERE hwid = ?", ("COKLU-HWID-2",)
        )
        assert satir_bir["status"] == "approved"
        assert satir_iki["status"] == "pending", (
            "İKİNCİ kullanıcı, BİRİNCİ kartın düğmesine basılınca "
            "YANLIŞLIKLA etkilendi"
        )

        # Onaylanan kart listeden düşmeli, diğeri kalmalı.
        assert len(sayfa._kart_widgetleri) == 1
        assert sayfa._kart_widgetleri[0].property("hwid") == "COKLU-HWID-2"
    finally:
        _pencereyi_kapat(window)


def test_bir_kartin_reddet_dugmesi_SADECE_o_kullaniciyi_reddediyor(
    qapp, db, sahte_usb, kasa_dizini,
):
    _bekleyen_ekle(db, "COKLU-RED-HWID-1", "reddedilecek")
    _bekleyen_ekle(db, "COKLU-RED-HWID-2", "kalacak")

    window = _pencere(db, sahte_usb)
    try:
        sayfa = window._pending_view
        sayfa._load_pending()

        kart = _kart_for_hwid(sayfa, "COKLU-RED-HWID-1")
        _kart_dugmesine_bas(kart, "pending_kart_btn_reddet")

        assert db.fetchone(
            "SELECT id FROM users WHERE hwid = ?", ("COKLU-RED-HWID-1",)
        ) is None, "reddedilen kullanıcı satırı hâlâ DB'de"
        assert db.fetchone(
            "SELECT status FROM users WHERE hwid = ?", ("COKLU-RED-HWID-2",)
        )["status"] == "pending", "İLGİSİZ kullanıcı yanlışlıkla etkilendi"

        assert len(sayfa._kart_widgetleri) == 1
        assert sayfa._kart_widgetleri[0].property("hwid") == "COKLU-RED-HWID-2"
    finally:
        _pencereyi_kapat(window)


def test_onaylama_denetim_kaydina_dogru_yaziyor(qapp, db, sahte_usb):
    _bekleyen_ekle(db, "DENETIM-ONAY-HWID", "denetim.onay.testi")

    window = _pencere(db, sahte_usb)
    try:
        sayfa = window._pending_view
        sayfa._load_pending()
        kart = _kart_for_hwid(sayfa, "DENETIM-ONAY-HWID")
        _kart_dugmesine_bas(kart, "pending_kart_btn_onayla")

        kayit = db.fetchone(
            "SELECT detail FROM audit_log WHERE action = 'user_approved'"
            " ORDER BY id DESC LIMIT 1"
        )
        assert kayit is not None
        assert "hwid=DENETIM-ONAY-HWID" in kayit["detail"]
        assert "username=denetim.onay.testi" in kayit["detail"]
        assert f"approved_by={_ADMIN_HWID}" in kayit["detail"]
    finally:
        _pencereyi_kapat(window)


def test_reddetme_denetim_kaydina_dogru_yaziyor(qapp, db, sahte_usb, kasa_dizini):
    _bekleyen_ekle(db, "DENETIM-RED-HWID", "denetim.red.testi")

    window = _pencere(db, sahte_usb)
    try:
        sayfa = window._pending_view
        sayfa._load_pending()
        kart = _kart_for_hwid(sayfa, "DENETIM-RED-HWID")
        _kart_dugmesine_bas(kart, "pending_kart_btn_reddet")

        kayit = db.fetchone(
            "SELECT detail FROM audit_log WHERE action = 'user_rejected'"
            " ORDER BY id DESC LIMIT 1"
        )
        assert kayit is not None
        assert "hwid=DENETIM-RED-HWID" in kayit["detail"]
        assert "username=denetim.red.testi" in kayit["detail"]
        assert f"rejected_by={_ADMIN_HWID}" in kayit["detail"]
    finally:
        _pencereyi_kapat(window)


def test_onayla_ONAY_verilmezse_durum_degismiyor(
    qapp, db, sahte_usb, monkeypatch: pytest.MonkeyPatch,
):
    """Onay diyaloğu "Hayır" dönerse — kart tıklamasının KENDİSİ
    doğrudan DB'ye yazmıyor, mevcut onay adımından GEÇMESİ gerekiyor."""
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.No))

    _bekleyen_ekle(db, "IPTAL-HWID", "iptal.testi")

    window = _pencere(db, sahte_usb)
    try:
        sayfa = window._pending_view
        sayfa._load_pending()
        kart = _kart_for_hwid(sayfa, "IPTAL-HWID")
        _kart_dugmesine_bas(kart, "pending_kart_btn_onayla")

        row = db.fetchone("SELECT status FROM users WHERE hwid = ?", ("IPTAL-HWID",))
        assert row["status"] == "pending"
    finally:
        _pencereyi_kapat(window)
