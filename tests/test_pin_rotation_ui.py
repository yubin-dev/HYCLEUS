"""
Zorunlu PIN yenilemenin ARAYÜZ tarafı (B-003).

`tests/test_pin_rotation.py` yenilemenin DOĞRU olduğunu sınıyor. Burada
sınanan şey KAPI: kısa PIN'li kullanıcı gerçekten durduruluyor mu, ve
6+ haneli kullanıcı bu akışa hiç girmiyor mu.

En önemli test `test_yenileme_yapilmazsa_GIRIS_ENGELLENIYOR`. Diyaloğun
kapatılamaz olması bir kullanılabilirlik tercihi; güvenlik kararını veren
yer `_on_login()`. Bir pencere yöneticisi ya da bir test diyaloğu
dışarıdan kapatabilir — o durumda bile kullanıcı içeri GİREMEMELİ.

Giriş akışı Qt diyaloğunun içinde olduğu için testler `LoginDialog`'u
gerçekten kuruyor; yalnızca kasa dizini ve modal `exec()` çağrıları
yönlendiriliyor.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QKeyEvent
    from PySide6.QtWidgets import QApplication

    from UI.login_dialog import LoginDialog
    from UI.PinRotationDialog import PinRotationDialog
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE import vault_manager
from CORE.pin_rotation import EYLEM_ZORUNLU
from CORE.vault_manager import create_vault, open_vault

_HWID = "USB-PINROT-UI"
_KISA = "1234"
_UZUN = "eskiPIN123"
_YENI = "yeniPIN456"
_ROLE = "Yönetici"
_TOTP = "000000"


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


@pytest.fixture
def kasa_dizini(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    return tmp_path


@pytest.fixture
def totp_gecerli(monkeypatch):
    """TOTP doğrulamasını sabitler — sınanan şey PIN akışı.

    Sır da sabitleniyor: `use_vault=True` yolunda `LoginDialog` artık
    HWID başına bir TOTP sırrı bekliyor (B-059) ve başsız koşucuda kasada
    hiç kayıt yok — `self._secret None` kalırdı ve yeni None-koruması
    `_on_login()`'de `totp_ok`'u hiç `pyotp.TOTP` çağırmadan `False`'a
    sabitlerdi. `load_totp_secret_for_hwid` de bu yüzden sabitleniyor.
    """
    import UI.login_dialog as ld

    class _SahteTOTP:
        def __init__(self, *a, **kw) -> None: ...
        def verify(self, *a, **kw) -> bool: return True

    monkeypatch.setattr(ld.pyotp, "TOTP", _SahteTOTP)
    monkeypatch.setattr(ld, "_load_secret", lambda: "A" * 32)
    monkeypatch.setattr(ld, "load_totp_secret_for_hwid", lambda hwid: "A" * 32)


@pytest.fixture
def acilan_diyaloglar(monkeypatch) -> list[PinRotationDialog]:
    """
    `exec()` yakalanıyor — offscreen'de bile modal ve tıklayacak kimse
    olmadığı için test asılırdı. Diyaloğun KURULMASINA izin var:
    kurulumda düşen bir hata ancak böyle yakalanır.

    Varsayılan davranış "kullanıcı hiçbir şey yapmadı" — yani
    `rotated` False kalıyor. Yenileyen testler bunu kendileri
    değiştiriyor.
    """
    acilanlar: list[PinRotationDialog] = []

    def _exec(self):
        acilanlar.append(self)
        return 0

    monkeypatch.setattr(PinRotationDialog, "exec", _exec)
    return acilanlar


def _giris(qapp, hwid: str, pin: str) -> LoginDialog:
    dlg = LoginDialog(hwid=hwid, first_run=False, use_vault=True)
    dlg._pin_input.setText(pin)
    dlg._totp_input.setText(_TOTP)
    return dlg


@pytest.fixture
def kisa_pinli(db, kasa_dizini, totp_gecerli, qapp):
    create_vault(_HWID, _KISA, _ROLE)
    db.execute(
        "INSERT INTO users (id, username, password_hash, role, status, hwid)"
        " VALUES (9, 'eski', '', 'admin', 'approved', ?)", (_HWID,))
    return _HWID


@pytest.fixture
def uzun_pinli(db, kasa_dizini, totp_gecerli, qapp):
    create_vault(_HWID, _UZUN, _ROLE)
    db.execute(
        "INSERT INTO users (id, username, password_hash, role, status, hwid)"
        " VALUES (9, 'yeni', '', 'admin', 'approved', ?)", (_HWID,))
    return _HWID


# ══════════════════════════════════════════════════════════════════════════════
# 1. Yönlendirme — kim akışa giriyor
# ══════════════════════════════════════════════════════════════════════════════


def test_kisa_PINLI_kullanici_YONLENDIRILIYOR(qapp, kisa_pinli, acilan_diyaloglar):
    dlg = _giris(qapp, kisa_pinli, _KISA)
    dlg._on_login()
    assert len(acilan_diyaloglar) == 1, "kısa PIN'li kullanıcı akışa girmedi"


def test_UZUN_PINLI_kullanici_akisa_HIC_girmiyor(qapp, uzun_pinli, acilan_diyaloglar):
    """
    En kolay yapılacak hata: herkesi akışa sokmak. Politikaya uyan
    kullanıcı bu ekranı hiç görmemeli.
    """
    dlg = _giris(qapp, uzun_pinli, _UZUN)
    dlg._on_login()
    assert acilan_diyaloglar == [], "politikaya uyan kullanıcı akışa sokuldu"
    assert dlg.result() == LoginDialog.Accepted, "normal giriş engellendi"


def test_yanlis_PIN_akisa_girmiyor(qapp, kisa_pinli, acilan_diyaloglar):
    """
    Tespit doğrulamadan SONRA yapılıyor. Aksi hâlde kimliği
    doğrulanmamış biri, kısa bir dize yazarak PIN değiştirme ekranını
    açabilirdi.
    """
    dlg = _giris(qapp, kisa_pinli, "9999")
    dlg._on_login()
    assert acilan_diyaloglar == []
    assert dlg.result() != LoginDialog.Accepted


# ══════════════════════════════════════════════════════════════════════════════
# 2. Kapı — yenileme olmadan giriş yok
# ══════════════════════════════════════════════════════════════════════════════


def test_yenileme_yapilmazsa_GIRIS_ENGELLENIYOR(qapp, kisa_pinli, acilan_diyaloglar):
    """
    Bu paketin ana iddiası.

    Diyaloğun kapatılamazlığı bir kullanılabilirlik tercihi — pencere
    yöneticisi onu dışarıdan kapatabilir. Güvenlik kararı `_on_login()`'de:
    `rotated` False ise `accept()` HİÇ çağrılmıyor.
    """
    dlg = _giris(qapp, kisa_pinli, _KISA)
    dlg._on_login()
    assert len(acilan_diyaloglar) == 1
    assert not acilan_diyaloglar[0].rotated
    assert dlg.result() != LoginDialog.Accepted, (
        "PIN yenilenmeden giriş kabul edildi — kapı açık"
    )


def test_yenileme_yapilirsa_giris_SURUYOR(qapp, kisa_pinli, monkeypatch):
    """Zorunluluk bir çıkmaz sokak değil: yenileyen kullanıcı içeri girer."""
    def _exec(self):
        self._yeni.setText(_YENI)
        self._yeni2.setText(_YENI)
        self._on_kaydet()
        return 1

    monkeypatch.setattr(PinRotationDialog, "exec", _exec)

    dlg = _giris(qapp, kisa_pinli, _KISA)
    dlg._on_login()
    assert dlg.result() == LoginDialog.Accepted, "yenileme sonrası giriş engellendi"
    assert open_vault(kisa_pinli, _YENI)[0] == _ROLE


def test_yenileme_sonrasi_oturum_anahtari_GECERLI(qapp, kisa_pinli, monkeypatch):
    """
    PIN değişimi master key'i KORUYOR. Değiştirseydi giriş anında alınan
    `session_key` bir anda yanlış anahtar olurdu ve kullanıcının bütün
    dosyaları o oturumda açılamazdı.
    """
    def _exec(self):
        self._yeni.setText(_YENI)
        self._yeni2.setText(_YENI)
        self._on_kaydet()
        return 1

    monkeypatch.setattr(PinRotationDialog, "exec", _exec)

    dlg = _giris(qapp, kisa_pinli, _KISA)
    dlg._on_login()
    _rol, gercek = open_vault(kisa_pinli, _YENI)
    assert dlg.session_key == gercek


def test_engellenen_giriste_denetim_kaydi_var(qapp, kisa_pinli, acilan_diyaloglar, db):
    """Yenilemeyi reddeden bir oturum, "hiç olmamış" gibi görünmemeli."""
    dlg = _giris(qapp, kisa_pinli, _KISA)
    dlg._on_login()
    # Başarılı giriş kaydı DÜŞMEMELİ — giriş tamamlanmadı.
    assert dlg.result() != LoginDialog.Accepted


# ══════════════════════════════════════════════════════════════════════════════
# 3. Diyalog davranışı
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def diyalog(qapp, db, kasa_dizini) -> PinRotationDialog:
    create_vault(_HWID, _KISA, _ROLE)
    # `users` satırı ŞART: `audit_log.user_id` yabancı anahtarla bu tabloya
    # bağlı. Satır olmadan denetim kaydı FK hatasıyla düşer ve
    # `rotate_pin()` onu yutar — yani test, kayıt yazılmadığını
    # göremeden geçerdi.
    db.execute(
        "INSERT INTO users (id, username, password_hash, role, status, hwid)"
        " VALUES (9, 'eski', '', 'admin', 'approved', ?)", (_HWID,))
    return PinRotationDialog(db=db, hwid=_HWID, mevcut_pin=_KISA, user_id=9)


def test_iptal_dugmesi_YOK(diyalog):
    from PySide6.QtWidgets import QPushButton

    metinler = [b.text() for b in diyalog.findChildren(QPushButton)]
    assert len(metinler) == 1, f"Beklenen tek düğme, bulunan: {metinler}"
    for yasak in ("İptal", "Iptal", "Vazgeç", "Kapat", "Daha sonra"):
        assert not any(yasak in m for m in metinler), f"{yasak!r} düğmesi var"


def test_ESC_diyalogu_kapatmiyor(qapp, diyalog):
    """
    GERÇEK bir tuş olayı gönderiliyor, işleyici doğrudan çağrılmıyor:
    sınanan şey "Esc basınca ne olur", "`keyPressEvent` ne yapar" değil.
    Qt Esc'i `reject()`'e yönlendiriyor ve kapıyı orası tutuyor.
    """
    diyalog.show()
    try:
        assert diyalog.isVisible()
        olay = QKeyEvent(QKeyEvent.KeyPress, Qt.Key_Escape, Qt.NoModifier)
        qapp.sendEvent(diyalog, olay)
        assert diyalog.isVisible(), "Esc diyaloğu kapattı"
        assert not diyalog.rotated
    finally:
        diyalog.hide()


def test_reject_yok_sayiliyor(diyalog):
    """
    `result()` YETMEZ: `QDialog.Rejected == 0` ve başlangıç değeri de 0,
    yani gerçekten reddedilmiş bir diyalog hiç dokunulmamış olandan
    ayırt edilemiyor. Mutasyon testinde bu boşluk ortaya çıktı —
    `reject()`'i `super().reject()`'e çeviren mutasyon HAYATTA KALDI.

    Ayırt eden şey GÖRÜNÜRLÜK: gerçek bir `reject()` diyaloğu gizler.
    """
    diyalog.show()
    try:
        assert diyalog.isVisible()
        diyalog.reject()
        assert diyalog.isVisible(), "reject() diyaloğu kapattı"
        assert not diyalog.rotated
    finally:
        diyalog.hide()


def test_pencere_kapatma_yok_sayiliyor(diyalog):
    from PySide6.QtGui import QCloseEvent

    olay = QCloseEvent()
    diyalog.closeEvent(olay)
    assert not olay.isAccepted(), "kapatma olayı kabul edildi"
    assert not diyalog.rotated


def test_yenileme_sonrasi_kapatma_SERBEST(diyalog):
    """Kilit yalnızca yenilemeye kadar; sonrasında pencere normal davranmalı."""
    from PySide6.QtGui import QCloseEvent

    diyalog._yeni.setText(_YENI)
    diyalog._yeni2.setText(_YENI)
    diyalog._on_kaydet()
    assert diyalog.rotated

    olay = QCloseEvent()
    diyalog.closeEvent(olay)
    assert olay.isAccepted()


def test_eslesmeyen_PINLER_reddediliyor(diyalog):
    diyalog._yeni.setText(_YENI)
    diyalog._yeni2.setText(_YENI + "x")
    diyalog._on_kaydet()
    assert not diyalog.rotated
    assert "eşleşmiyor" in diyalog._hata.text()


def test_hala_kisa_PIN_diyalogda_reddediliyor(diyalog):
    """
    Hata GÖRÜNÜR olmalı, yalnızca metni ayarlanmış değil.

    `isVisible()` gösterilmemiş bir pencerenin çocuğunda her zaman False
    döner — Qt'nin bir davranışı, ürünün değil. Bu yüzden diyalog
    gerçekten gösteriliyor; aksi hâlde "hata etiketi hiç görünmüyor"
    kusuru testten kaçardı.
    """
    diyalog.show()
    try:
        assert not diyalog._hata.isVisible(), "hata etiketi baştan görünür"
        diyalog._yeni.setText("123")
        diyalog._yeni2.setText("123")
        diyalog._on_kaydet()
        assert not diyalog.rotated
        assert diyalog._hata.isVisible(), "hata kullanıcıya gösterilmiyor"
        assert "6" in diyalog._hata.text()
    finally:
        diyalog.hide()


def test_basarili_yenilemede_alanlar_TEMIZLENIYOR(diyalog):
    """
    Düz metin PIN, diyalog kapanana kadar widget denetimi ve ekran
    görüntüsü yüzeyinde açık kalırdı.
    """
    diyalog._yeni.setText(_YENI)
    diyalog._yeni2.setText(_YENI)
    diyalog._on_kaydet()
    assert diyalog._yeni.text() == ""
    assert diyalog._yeni2.text() == ""
    assert diyalog._mevcut_pin == ""


def test_diyalog_denetim_kaydini_ZORUNLU_olarak_yaziyor(diyalog, db):
    diyalog._yeni.setText(_YENI)
    diyalog._yeni2.setText(_YENI)
    diyalog._on_kaydet()
    assert db.fetchone("SELECT 1 FROM audit_log WHERE action = ?", (EYLEM_ZORUNLU,))
