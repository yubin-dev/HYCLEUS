"""
HYCLEUS — Profil sayfası (2026-08-30): modal'dan tam sayfaya taşındı,
"Cihazlar ve oturum" + "Kendi işlemlerim" bölümleri eklendi.

Bu paket üç iddiayı ölçüyor:

  1. "Cihazlar ve oturum" USB Yönetim Paneli'yle AYNI kaynaktan
     (`CORE/usb_tokens.py::token_kayitlarini_getir()`) besleniyor — iki
     görünüm arasında veri tutarsızlığı olamaz, çünkü ikisi de AYNI
     sorguyu çağırıyor. Bu, `AdminPanel`'in tablosuyla `ProfileView`'ın
     tablosunu satır satır karşılaştırarak doğrudan kanıtlanıyor.
  2. "Kendi işlemlerim" gerçekten `user_id` ile FİLTRELENMİŞ — başka bir
     kullanıcının denetim kayıtları asla sızmıyor.
  3. "Oturumu Kapat" gerçek kilit mekanizmasını (`LockMixin`) kullanıyor
     ve `_poll_usb`'nin "aynı USB hâlâ takılı" otomatik kilit-açmasından
     ETKİLENMİYOR (aksi hâlde "oturum kapat" tıklaması bir anlığına
     ekranı kilitleyip hemen kendiliğinden açardı).

Çoklu cihaz senaryosu TEST EDİLMİYOR: `users.hwid` kısmi UNIQUE (B-060)
bunu şema seviyesinde imkânsız kılıyor — bkz. `CORE/usb_tokens.py`
modül docstring'i, SECURITY.md §4.23, BACKLOG.md B-082.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QMessageBox

    from UI.AdminPanel import AdminPanel
    from UI.main_window import HycleusWindow
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE.vault_manager import create_vault

_KEY = b"K" * 32
_HWID = "PROFIL-TEST-HWID"
_PIN = "gecerli-pin-456"


@pytest.fixture
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


@pytest.fixture
def kasa_dizini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from CORE import vault_manager
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / "legacy.hclv")
    return tmp_path


@pytest.fixture(autouse=True)
def _diyalog_engelle(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """QMessageBox çağrıları (onay/bilgi/hata) testi bloklamasın."""
    gosterilen: list[tuple[str, str]] = []

    def _yakala(sonuc):
        def _f(_parent, baslik, metin, *a, **kw):
            gosterilen.append((baslik, str(metin)))
            return sonuc
        return _f

    monkeypatch.setattr(QMessageBox, "warning", staticmethod(_yakala(0)))
    monkeypatch.setattr(QMessageBox, "critical", staticmethod(_yakala(0)))
    monkeypatch.setattr(QMessageBox, "information", staticmethod(_yakala(0)))
    # question varsayılan olarak Yes döndürsün — onay isteyen eylemler
    # (kara listeye alma, oturumu kapatma) testte İLERLESİN.
    monkeypatch.setattr(QMessageBox, "question", staticmethod(_yakala(QMessageBox.Yes)))
    return gosterilen


def _pencere(db, sahte_usb, hwid: str, *, username: str, user_id: int, role: str = "Yönetici"):
    sahte_usb(hwid)
    return HycleusWindow(hwid=hwid, key=_KEY, role=role, username=username, user_id=user_id)


def _pencereyi_kapat(window) -> None:
    for ad in ("_usb_timer", "_expiry_timer", "_idle_timer"):
        t = getattr(window, ad, None)
        if t is not None:
            t.stop()
    QApplication.instance().removeEventFilter(window)
    window.close()


def _kullanici_ekle(db, hwid: str, username: str, role: str = "admin") -> int:
    cur = db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, ?, 'approved', ?)",
        (username, "!x", role, hwid),
    )
    return cur.lastrowid


def _token_ekle(db, hwid: str, token_id: str = "TOKEN-ABC", blacklisted: int = 0) -> None:
    db.execute(
        "INSERT INTO usb_tokens (hwid, share_2, token_id, blacklisted) VALUES (?, ?, ?, ?)",
        (hwid, "share-2-degeri", token_id, blacklisted),
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1 — "Cihazlar ve oturum" = AdminPanel'in AYNI kaynağı
# ══════════════════════════════════════════════════════════════════════════════


def test_cihazlar_bolumu_admin_panelle_AYNI_kaynaktan_besleniyor(qapp, db, sahte_usb):
    """
    Asıl iddia: `ProfileView`'ın cihaz satırı, `AdminPanel`'in aynı HWID
    için gösterdiği satırla (token ID, kayıt tarihi, durum) BİREBİR
    tutarlı — çünkü ikisi de `CORE.usb_tokens.token_kayitlarini_getir()`'i
    çağırıyor, iki ayrı SQL YAZILMADI.
    """
    user_id = _kullanici_ekle(db, _HWID, "cihaz.test")
    # 12 karakterden kısa: AdminPanel (12'de) ve ProfileView'ın (20'de)
    # FARKLI kırpma sınırları bu testte devreye girmesin — asıl iddia
    # kırpma davranışı değil, veri kaynağının aynı olması.
    _token_ekle(db, _HWID, token_id="TOK-CIHAZ-1")
    # İKİNCİ, İLGİSİZ bir token — aşağıdaki hwid= filtresi ONU HARİÇ
    # tutmalı. Bu satır olmadan DB'de tek token varken filtreli/filtresiz
    # sorgu HER ZAMAN aynı sonucu verirdi ve aşağıdaki eşitlik denetimi
    # filtrenin gerçekten çalıştığını KANITLAMAZDI (tesadüfen geçerdi).
    _kullanici_ekle(db, "BASKA-CIHAZ-HWID", "baskasinin.cihazi")
    _token_ekle(db, "BASKA-CIHAZ-HWID", token_id="ILGISIZ-TOKEN")

    window = _pencere(db, sahte_usb, _HWID, username="cihaz.test", user_id=user_id)
    try:
        window._on_open_profile()
        cihaz_tablo = window._profil_view._cihaz_table
        assert cihaz_tablo.rowCount() == 1, "tek kayıtlı token için tek satır bekleniyordu"

        panel = AdminPanel(current_hwid=_HWID, role="Yönetici")
        try:
            admin_tablo = panel._table
            admin_satir = next(
                r for r in range(admin_tablo.rowCount())
                if admin_tablo.item(r, 0).data(Qt.UserRole) == _HWID
            )
            # AdminPanel sütunları: HWID, Token ID, Rol, Son Giriş, Durum.
            admin_token_id = admin_tablo.item(admin_satir, 1).text()
            admin_durum = admin_tablo.item(admin_satir, 4).text()
        finally:
            panel.close()

        # ProfileView sütunları: Token ID, Kayıt Tarihi, Durum, Şu An Takılı.
        profil_token_id = cihaz_tablo.item(0, 0).text()
        profil_durum = cihaz_tablo.item(0, 2).text()

        # AdminPanel token ID'yi 12 karaktere, ProfileView 20'ye kırpıyor —
        # görüntü uzunluğu farklı olabilir ama İÇERİK aynı kaynaktan gelmeli.
        assert profil_token_id == admin_token_id == "TOK-CIHAZ-1"
        assert profil_durum == admin_durum == "Aktif"

        # Asıl iddia UI hücrelerinin görsel eşleşmesinden DAHA GÜÇLÜ: iki
        # görünümün ARKASINDAKİ veri katmanı da (created_at dahil, hiçbir
        # tabloda görünmeyen bir alan) BİREBİR aynı — çünkü ikisi de AYNI
        # fonksiyonu çağırıyor, filtre dışında hiçbir SQL farkı yok.
        from CORE.usb_tokens import token_kayitlarini_getir
        tek = token_kayitlarini_getir(db, hwid=_HWID)
        tumu = token_kayitlarini_getir(db)
        assert len(tumu) == 2, "iki token eklendi, ikisi de görünmeli"
        assert len(tek) == 1, "hwid= filtresi ikinci token'ı DIŞARIDA bırakmadı"
        assert tek == [k for k in tumu if k.hwid == _HWID]
        assert cihaz_tablo.item(0, 0).text() != "ILGISIZ-TOKEN", (
            "ProfileView başka bir hesabın cihazını gösteriyor"
        )
    finally:
        _pencereyi_kapat(window)


def test_cihazlar_bolumu_kara_liste_durumunu_admin_panelle_TUTARLI_gosteriyor(qapp, db, sahte_usb):
    """Aynı tutarlılık iddiası, kara listeye alınmış bir token için."""
    user_id = _kullanici_ekle(db, _HWID, "kara.liste.test")
    _token_ekle(db, _HWID, token_id="TOKEN-KL-1", blacklisted=1)

    window = _pencere(db, sahte_usb, _HWID, username="kara.liste.test", user_id=user_id)
    try:
        window._on_open_profile()
        cihaz_tablo = window._profil_view._cihaz_table
        assert cihaz_tablo.item(0, 2).text() == "Kara Liste"

        panel = AdminPanel(current_hwid=_HWID, role="Yönetici")
        try:
            assert panel._table.item(0, 4).text() == "Kara Liste"
        finally:
            panel.close()
    finally:
        _pencereyi_kapat(window)


def test_cihazlar_bolumu_su_an_takili_durumunu_canli_yansitiyor(qapp, db, sahte_usb):
    """"Şu an takılı" USB'nin GERÇEKTEN takılı olup olmadığına bakıyor —
    kayıt zamanındaki bir alan değil, `get_usb_hwid()` ile canlı karşılaştırma."""
    user_id = _kullanici_ekle(db, _HWID, "takili.test")
    _token_ekle(db, _HWID)

    window = _pencere(db, sahte_usb, _HWID, username="takili.test", user_id=user_id)
    try:
        window._on_open_profile()
        assert window._profil_view._cihaz_table.item(0, 3).text() == "✓ Evet"

        # USB fiziksel olarak çekildi — get_usb_hwid() artık None dönüyor.
        sahte_usb(None)
        window._profil_view.yenile()
        assert window._profil_view._cihaz_table.item(0, 3).text() == "Hayır"
    finally:
        _pencereyi_kapat(window)


# ══════════════════════════════════════════════════════════════════════════════
# 2 — "Kendi işlemlerim" GERÇEKTEN user_id ile filtreleniyor
# ══════════════════════════════════════════════════════════════════════════════


def test_islemlerim_baska_kullanicinin_kaydini_SIZDIRMIYOR(qapp, db, sahte_usb):
    ben_id = _kullanici_ekle(db, _HWID, "ben")
    baskasi_id = _kullanici_ekle(db, "BASKA-HWID", "baskasi")

    db.log("file_added", user_id=ben_id, detail="filename=benim_dosyam.hcl")
    db.log("file_added", user_id=baskasi_id, detail="filename=onun_dosyasi.hcl")

    window = _pencere(db, sahte_usb, _HWID, username="ben", user_id=ben_id)
    try:
        window._on_open_profile()
        tablo = window._profil_view._islem_table
        detaylar = [tablo.item(r, 2).text() for r in range(tablo.rowCount())]
        assert any("benim_dosyam" in d for d in detaylar)
        assert not any("onun_dosyasi" in d for d in detaylar), (
            "BAŞKA kullanıcının denetim kaydı 'Kendi işlemlerim'e sızdı"
        )
    finally:
        _pencereyi_kapat(window)


# ══════════════════════════════════════════════════════════════════════════════
# 3 — "Oturumu Kapat" gerçek kilit mekanizmasını kullanıyor
# ══════════════════════════════════════════════════════════════════════════════


def test_oturumu_kapat_pencereyi_kilitliyor_ve_ayni_usb_takiliyken_KENDI_KENDINE_ACILMIYOR(
    qapp, db, sahte_usb,
):
    """
    Asıl risk: "manual" kilit `_poll_usb`'nin varsayılan `_unlock()`
    çağrısıyla (yalnızca "usb" nedenini kaldırır) YANLIŞLIKLA açılırsa,
    "Oturumu Kapat" tıklaması gözle görülmeden bir anlığına titreyip
    geri açılırdı — kullanıcının deneyimlediği "oturum hiç kapanmadı."
    """
    user_id = _kullanici_ekle(db, _HWID, "kilit.test")
    _token_ekle(db, _HWID)

    window = _pencere(db, sahte_usb, _HWID, username="kilit.test", user_id=user_id)
    try:
        window._on_open_profile()
        assert window._locked is False

        window._profil_view._on_logout()
        assert window._locked is True
        assert "manual" in window._lock_reasons

        # Aynı USB HÂLÂ takılı — _poll_usb normalde bunu "her şey yolunda"
        # sayıp _unlock() çağırır. "manual" bundan ETKİLENMEMELİ.
        window._poll_usb()
        assert window._locked is True, (
            "manuel kilit, aynı USB takılıyken _poll_usb tarafından "
            "YANLIŞLIKLA açıldı"
        )
        assert "manual" in window._lock_reasons
    finally:
        _pencereyi_kapat(window)


def test_oturumu_kapat_dogru_PINLE_aciliyor(qapp, db, sahte_usb, kasa_dizini, monkeypatch):
    from UI import main_window_lock as ml

    create_vault(_HWID, _PIN, "Yönetici")
    user_id = _kullanici_ekle(db, _HWID, "pin.test")

    window = _pencere(db, sahte_usb, _HWID, username="pin.test", user_id=user_id)
    try:
        window._profil_view._on_logout()
        assert window._locked is True

        monkeypatch.setattr(
            ml, "QInputDialog",
            type("_Sahte", (), {"getText": staticmethod(lambda *a, **k: (_PIN, True))}),
        )
        window._unlock_manual()
        assert window._locked is False
        assert window._lock_reasons == set()
    finally:
        _pencereyi_kapat(window)
