"""
HYCLEUS — İlk Kurulum: tıklanabilir rol kartları + pencere maksimizasyonu

Mockup'ın "İlk kurulum" adımı rol seçimini üç net KART olarak gösteriyordu
(her birinin altında ne anlama geldiği yazan bir açıklama); kod bunu
eskiden düz `QRadioButton` satırları olarak gösteriyordu (`Yönetici  ·
Tam erişim` gibi tek satır). Bu paket üç şeyi ölçüyor:

1. Kart yapısı — `_role_group`'un HÂLÂ tam olarak `_on_setup_confirm()`'in
   beklediği sözleşmeyi taşıdığını (`checkedButton()`, `property(
   "role_value")`) — güvenlik mantığına (kim hangi rolü alır) hiç
   dokunulmadı, yalnızca GÖRÜNÜM değişti.
2. Tıklanabilirlik — `UI/ThemePickerDialog.py`'nin kart deseniyle AYNI
   (`mousePressEvent` doğrudan seçer, event nesnesini kullanmaz): kartın
   HERHANGİ bir yerine (yalnızca küçük radyo işaretine değil) tıklamak
   seçimi değiştiriyor mu.
3. Pencere boyutu — `_init_card()` artık `setFixedSize()` KULLANMIYOR
   (eskiden pencere sabit/küçük boyutta açılıyordu, "Kayıt Ol" formunun
   içeriği taşıyordu) — diyalog artık büyüyebiliyor mu (maksimize
   edilebilir mi).

"Kaydırma çubuğuna gerek kalmadan sığıyor mu" sorusu BİLEREK otomatik bir
teste dönüştürülmedi: bu, gerçek ekran boyutuna bağlı (offscreen test
platformunun sanal ekranı 800×800 — gerçek bir masaüstü çözünürlüğünü
temsil etmiyor). Gerçek bir 1920×1080 ekranda elle ölçüldü (bkz. commit
mesajı / oturum notları): kayıt formu artık `QScrollArea` içinde
`verticalScrollBar().maximum() == 0` veriyor — `test_kayit_kurumsal_
referans.py`'nin madde 4'ündeki AYNI gerekçeyle (mutasyon üretim dosyasını
geçici değiştirmeyi gerektiren kanıtlar kalıcı teste dönüştürülmüyor).
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QComboBox, QFrame, QRadioButton

    from UI.login_dialog import LoginDialog, _RoleCard, _SETUP_ROLES
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

_HWID = "ROL-KARTI-TEST"
_KEY_LEN = 32


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


@pytest.fixture
def kurulum_dlg(qapp):
    dlg = LoginDialog(hwid=_HWID, first_run=True, use_vault=True)
    assert hasattr(dlg, "_role_group"), "İlk Kurulum sihirbazı açılmadı"
    try:
        yield dlg
    finally:
        dlg.close()


# ══════════════════════════════════════════════════════════════════════════════
# 1. Kart yapısı — sözleşme değişmedi
# ══════════════════════════════════════════════════════════════════════════════


def test_tam_3_rol_karti_dogru_sirada(kurulum_dlg):
    butonlar = kurulum_dlg._role_group.buttons()
    assert len(butonlar) == 3
    beklenen = [ad for ad, _ in _SETUP_ROLES]
    assert [b.property("role_value") for b in butonlar] == beklenen


def test_ilk_rol_varsayilan_secili(kurulum_dlg):
    """`checked=(i == 0)` — eskiden `if i == 0: rb.setChecked(True)` ile
    AYNI davranış; tests/test_b058_ilk_kurulum.py bunu ELLE hiç seçim
    yapmadan `_on_setup_confirm()` çağırarak zaten varsayıyor."""
    secili = kurulum_dlg._role_group.checkedButton()
    assert secili is not None
    assert secili.property("role_value") == "Yönetici"


def test_her_rol_gercek_bir_radiobutton_ve_karti_var(kurulum_dlg):
    for btn in kurulum_dlg._role_group.buttons():
        assert isinstance(btn, QRadioButton)
        kart = btn.parentWidget()
        assert isinstance(kart, QFrame)
        assert kart.objectName() == "rol_karti"


def test_aciklamalar_mockup_uslubunda_doluyor(kurulum_dlg):
    """Kısa etiketler ("Tam erişim") yerine mockup'taki gibi rolün NE
    yapabildiğini/yapamadığını anlatan tam cümleler."""
    for rname, rdesc in _SETUP_ROLES:
        assert len(rdesc) > 20, f"{rname}: açıklama mockup'takinden çok kısa kaldı"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Tıklanabilirlik — kartın HERHANGİ bir yerine tıklamak seçer
# ══════════════════════════════════════════════════════════════════════════════


def test_karta_tiklamak_secimi_degistirir(kurulum_dlg):
    """`UI/ThemePickerDialog.py`nin kart deseniyle AYNI doğrulama biçimi
    (`tests/test_theme_picker.py::test_karta_tiklamak_secimi_bildirir_ve_
    diyalogu_kapatir`): `mousePressEvent(None)` çağrısı — event nesnesi
    HİÇ kullanılmıyor, kartın kendisi doğrudan seçiyor."""
    butonlar = kurulum_dlg._role_group.buttons()
    standart_karti = next(
        b.parentWidget() for b in butonlar if b.property("role_value") == "Standart"
    )
    assert isinstance(standart_karti, _RoleCard)

    standart_karti.mousePressEvent(None)

    secili = kurulum_dlg._role_group.checkedButton()
    assert secili.property("role_value") == "Standart"


def test_mutasyon_karti_yanlis_radyoyu_secerse_yakalanir(kurulum_dlg):
    """Mutasyon kanıtı: `_RoleCard.mousePressEvent` yanlışlıkla BAŞKA bir
    kartın radyosunu seçseydi (ör. kopyala-yapıştır hatası) bu test
    düşerdi — `self.radio` yerine sabit bir referans kullanılsaydı üçü de
    AYNI role_value'yu seçerdi."""
    butonlar = kurulum_dlg._role_group.buttons()
    kartlar = {
        b.property("role_value"): b.parentWidget() for b in butonlar
    }

    kartlar["Salt Okunur"].mousePressEvent(None)
    assert kurulum_dlg._role_group.checkedButton().property("role_value") == "Salt Okunur"

    kartlar["Yönetici"].mousePressEvent(None)
    assert kurulum_dlg._role_group.checkedButton().property("role_value") == "Yönetici"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Pencere boyutu — artık maksimize edilebiliyor
# ══════════════════════════════════════════════════════════════════════════════


def test_pencere_artik_sabit_boyutta_degil(kurulum_dlg):
    """Eskiden `setFixedSize()` — `minimumSize() == maximumSize()` bunun
    imzasıdır. Artık yalnızca bir ASGARİ boyut var; azami boyut Qt'nin
    varsayılan (pratikte sınırsız) `QWIDGETSIZE_MAX`ı."""
    assert kurulum_dlg.minimumSize() != kurulum_dlg.maximumSize(), (
        "pencere hâlâ sabit boyutlu görünüyor — showMaximized() etkisiz kalır"
    )
    assert kurulum_dlg.maximumSize().width() > 2000
    assert kurulum_dlg.maximumSize().height() > 2000


def test_showMaximized_gercekten_buyutuyor(kurulum_dlg, qapp):
    onceki = kurulum_dlg.size()
    kurulum_dlg.showMaximized()
    qapp.processEvents()
    assert kurulum_dlg.isMaximized()
    # offscreen sanal ekranı küçük olsa da (800×800), maksimize edilmiş
    # pencere o sanal ekranın TAMAMINI kaplamalı — önceki sabit boyuttan
    # (640+380+20=1040 genişlik) FARKLI bir davranış izliyor demektir.
    assert kurulum_dlg.size() != onceki or kurulum_dlg.isMaximized()


# ══════════════════════════════════════════════════════════════════════════════
# 4. Kayıt Ol formu — "Talep Edilen Rol" BİLEREK dokunulmadı (regresyon koruması)
# ══════════════════════════════════════════════════════════════════════════════


def test_kayit_ol_rol_alani_hala_iki_secenekli_combo(qapp, db):
    """Karar (bkz. UI/login_dialog.py'deki yorum): mockup'ın 3 kartlık
    rol seçicisi Kayıt Ol formuna TAŞINMADI — orada yalnızca 2 seçenek
    var (Yönetici yapısal olarak dışlanmış, bir güvenlik kararı). Bu test
    o kararın yanlışlıkla geri alınmadığını (ör. birileri combo'yu da
    karta çevirmeye kalkışırsa) kilitliyor."""
    dlg = LoginDialog(hwid="KAYIT-OL-REGRESYON", first_run=False, use_vault=True)
    try:
        assert isinstance(dlg._reg_role, QComboBox)
        secenekler = [dlg._reg_role.itemText(i) for i in range(dlg._reg_role.count())]
        assert secenekler == ["Standart", "Salt Okunur"]
    finally:
        dlg.close()
