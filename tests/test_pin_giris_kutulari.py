"""
B-095 — Giriş ekranındaki tek PIN kutusu, mockup'a uygun 6 ayrı kutucuğa
(`UI.login_dialog._PinBoxInput`) dönüştürüldü.

UYUMLULUK GEREKÇESİ (bkz. `CORE/pin_policy.py`): PIN politikası PIN'in
tam 6 hane ya da yalnızca rakam olacağını HİÇBİR ZAMAN garanti etmez —
`LOGIN_MIN_LEN=4` eski kullanıcıları kasıtlı kabul eder, `PIN_MAX_LEN`
GUI'de zorlanmaz, karakter sınıfı hiç kısıtlanmamıştır. Bu yüzden
kutucuklar rakam-dışı karakterleri REDDETMEZ ve 6. kutucuk taşabilir.
Bu dosya hem YENİ 6-kutu UX'ini (tek tek yazma + yapıştırma otomatik
dağıtım) hem de bu GERİYE UYUMLULUK garantisini doğrular.

Karar ve tam gerekçe: `BACKLOG.md` **B-095**.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication

    from UI.login_dialog import LoginDialog, _PinBoxInput
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE import vault_manager
from CORE.pin_policy import PIN_MAX_LEN


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


@pytest.fixture
def kutu(qapp) -> _PinBoxInput:
    # `qWaitForWindowExposed` bilerek KULLANILMIYOR: bu depodaki hiçbir
    # UI testi onu kullanmıyor (yalnızca `.show()` + odak yeterli) ve
    # tüm paket art arda çalıştırıldığında (binlerce testten sonra) o
    # çağrı offscreen platform'da bir access-violation çökmesine yol
    # açtı — tekil/az sayıda dosya çalıştırıldığında hiç görülmedi.
    w = _PinBoxInput()
    w.show()
    qapp.processEvents()
    yield w
    w.deleteLater()


def test_tek_tek_yazma_kutulari_dolduruyor_ve_odak_ilerliyor(kutu: _PinBoxInput) -> None:
    """Her karakter kendi kutusuna gider; dolan kutu odağı bir sonrakine devrediyor."""
    rakamlar = "123456"
    for i, ch in enumerate(rakamlar):
        kutu._kutular[i].setFocus()
        QTest.keyClicks(kutu._kutular[i], ch)
        if i < 5:
            assert kutu._kutular[i + 1].hasFocus(), (
                f"{i}. kutu dolunca odak {i + 1}. kutuya geçmedi"
            )

    assert kutu.text() == rakamlar
    for i, ch in enumerate(rakamlar):
        assert kutu._kutular[i].text() == ch


def test_backspace_bos_kutuda_onceki_kutuya_donuyor(kutu: _PinBoxInput) -> None:
    kutu._kutular[0].setFocus()
    QTest.keyClicks(kutu._kutular[0], "1")
    assert kutu._kutular[1].hasFocus()

    QTest.keyClick(kutu._kutular[1], Qt.Key_Backspace)
    assert kutu._kutular[0].hasFocus(), "boş kutuda backspace önceki kutuya dönmedi"


def test_yapistirma_tam_6_haneyi_otomatik_dagitiyor(kutu: _PinBoxInput) -> None:
    """Kullanıcı 6 haneli PIN'i tek seferde yapıştırırsa tüm kutulara dağılmalı."""
    QApplication.clipboard().setText("482913")
    kutu._kutular[0].setFocus()
    kutu._kutular[0].paste()

    assert kutu.text() == "482913"
    for i, ch in enumerate("482913"):
        assert kutu._kutular[i].text() == ch


def test_yapistirma_odaktaki_kutu_farketmeksizin_bastan_dagitiyor(kutu: _PinBoxInput) -> None:
    """Yapıştırma, hangi kutu odaktaysa fark etmeksizin 1. kutudan başlar."""
    QApplication.clipboard().setText("135790")
    kutu._kutular[3].setFocus()
    kutu._kutular[3].paste()

    assert kutu.text() == "135790"


def test_yapistirma_kisa_pin_eski_kullanicilari_bozmuyor(kutu: _PinBoxInput) -> None:
    """LOGIN_MIN_LEN=4: 6 haneden kısa eski PIN'ler yapıştırmada da kabul edilmeli."""
    QApplication.clipboard().setText("7331")
    kutu._kutular[0].setFocus()
    kutu._kutular[0].paste()

    assert kutu.text() == "7331"
    assert kutu._kutular[4].text() == ""
    assert kutu._kutular[5].text() == ""


def test_yapistirma_uzun_pin_son_kutuda_tasiyor(kutu: _PinBoxInput) -> None:
    """PIN_MAX_LEN GUI'de zorlanmaz: 6'dan uzun PIN'ler son kutuda taşarak kabul edilir."""
    uzun_pin = "1234567890"  # 10 karakter
    QApplication.clipboard().setText(uzun_pin)
    kutu._kutular[0].setFocus()
    kutu._kutular[0].paste()

    assert kutu.text() == uzun_pin
    assert kutu._kutular[5].text() == "67890"


def test_rakam_disi_karakterler_reddedilmiyor(kutu: _PinBoxInput) -> None:
    """PIN politikası karakter sınıfını hiç kısıtlamaz — harf/sembol PIN'ler çalışmalı."""
    kutu._kutular[0].setFocus()
    QTest.keyClicks(kutu._kutular[0], "S")
    assert kutu._kutular[0].text() == "S"
    assert kutu._kutular[1].hasFocus()


def test_clear_tum_kutulari_bosaltiyor(kutu: _PinBoxInput) -> None:
    QApplication.clipboard().setText("999999")
    kutu._kutular[0].setFocus()
    kutu._kutular[0].paste()
    assert kutu.text() == "999999"

    kutu.clear()
    assert kutu.text() == ""
    for k in kutu._kutular:
        assert k.text() == ""


@pytest.mark.parametrize(
    "pin",
    [
        pytest.param("123456", id="tam-6-hane"),
        pytest.param("1234", id="kisa-4-hane-legacy"),
        pytest.param("12345", id="5-hane"),
        pytest.param("12345678901234", id="uzun-14-karakter"),
        pytest.param("AbC-12!xZ", id="rakam-disi-karakterler"),
    ],
)
def test_setText_text_round_trip_karakter_kaybi_olmadan(kutu: _PinBoxInput, pin: str) -> None:
    """setText(pin) ile ayarlanan PIN, .text() ile BİREBİR (kayıpsız, sırasız değil) geri okunmalı."""
    kutu.setText(pin)
    assert kutu.text() == pin


def test_son_kutunun_gercek_bir_maxLength_siniri_var(kutu: _PinBoxInput) -> None:
    """
    Son kutucuk SINIRSIZ değil: `PIN_MAX_LEN` (`CORE/pin_policy.py`) ile
    sınırlı — bkz. `UI/login_dialog.py::_PinBoxInput.__init__`,
    `kutu.setMaxLength(1 if i < 5 else PIN_MAX_LEN)`. İlk 5 kutu ise
    gerçekten 1 karakterle sınırlı (dağıtımın çalışması bunu gerektiriyor).
    """
    son_kutu = kutu._kutular[-1]
    assert son_kutu.maxLength() == PIN_MAX_LEN
    for onceki in kutu._kutular[:-1]:
        assert onceki.maxLength() == 1


def test_uzun_pin_setText_ile_tasan_karakterleri_kesmiyor(kutu: _PinBoxInput) -> None:
    """
    15+ karakterlik bir PIN'in son kutuya taşan kısmı (yalnızca ~9-10
    karakter) `PIN_MAX_LEN`'in (32) ÇOK altında kalır — setText() yolunda
    hiçbir karakter sessizce kesilmemeli.
    """
    uzun_pin = "AB123456789012"  # 14 karakter; tasan kisim (6. kutudan sonrasi) 9 karakter
    kutu.setText(uzun_pin)
    assert kutu.text() == uzun_pin
    assert kutu._kutular[-1].text() == uzun_pin[5:]


def test_uzun_pin_yapistirma_ile_tasan_karakterleri_kesmiyor(kutu: _PinBoxInput) -> None:
    """Aynı doğrulama, paste() yolunda — kullanıcı 15+ karakterlik PIN'i yapıştırırsa."""
    uzun_pin = "ZZ987654321098"  # 14 karakter
    QApplication.clipboard().setText(uzun_pin)
    kutu._kutular[0].setFocus()
    kutu._kutular[0].paste()

    assert kutu.text() == uzun_pin
    assert kutu._kutular[-1].text() == uzun_pin[5:]


def test_pin_max_len_asilinca_son_kutu_gercekten_kesiyor(kutu: _PinBoxInput) -> None:
    """
    Sınırın YALNIZCA `maxLength()` değeriyle değil GERÇEK DAVRANIŞLA var
    olduğunu kanıtlar: toplam uzunluk 5 + PIN_MAX_LEN'i (37) aşınca, son
    kutunun kendi `QLineEdit.maxLength()`'i devreye girer ve fazlalığı
    SESSİZCE keser (Qt, `setText()`'te verilen metni `maxLength` karaktere
    kısaltır — ilk N karakter tutulur, gerisi atılır; boş `QLineEdit` ile
    doğrulandı). Bu senaryoda `.text()` ARTIK orijinal PIN'le eşleşmiyor.

    DÜZELTME (B-095 devam): bu sınır "Qt'nin kendi keyfi sınırı, politikayla
    ilgisi yok" DEĞİLDİR — `UI/login_dialog.py::_PinBoxInput.__init__`
    `CORE.pin_policy.PIN_MAX_LEN`i DOĞRUDAN ithal edip kullanıyor (bkz.
    `test_son_kutunun_pin_max_len_ile_CANLI_baglantisi`, aşağıda). Önceki
    bir turda burada yanlışlıkla "politika sınırı üst katmanda hiç yok"
    yazılmıştı — YANLIŞTI, düzeltildi.
    """
    tasma_miktari = 8
    cok_uzun_pin = "1" * 5 + "2" * (PIN_MAX_LEN + tasma_miktari)  # toplam 5+40=45 karakter
    kutu.setText(cok_uzun_pin)

    beklenen = cok_uzun_pin[: 5 + PIN_MAX_LEN]  # ilk 37 karakter hayatta kalıyor
    assert kutu.text() == beklenen
    assert kutu.text() != cok_uzun_pin
    assert len(kutu.text()) == 5 + PIN_MAX_LEN


def test_son_kutunun_pin_max_len_ile_CANLI_baglantisi(qapp) -> None:
    """
    Son kutunun `setMaxLength()`'inin AYRI, elle yazılmış bir `32` sabiti
    DEĞİL, `CORE.pin_policy.PIN_MAX_LEN`in KENDİSİ olduğunu KANITLAR —
    statik bir `== PIN_MAX_LEN` eşitliği (bkz.
    `test_son_kutunun_gercek_bir_maxLength_siniri_var`) yalnızca BUGÜNKÜ
    değerlerin TESADÜFEN aynı olduğunu gösterir; bu test `PIN_MAX_LEN`i
    FARKLI bir değere değiştirip widget'ın YENİ değeri yansıttığını
    göstererek gerçek (canlı) tekil-kaynaklılığı doğruluyor.

    NEDEN `CORE.pin_policy.PIN_MAX_LEN` DEĞİL `UI.login_dialog.PIN_MAX_LEN`
    yamanıyor: `UI/login_dialog.py`'deki `from CORE.pin_policy import
    PIN_MAX_LEN` satırı, ithal ANINDA `login_dialog` modülünün KENDİ
    ad alanına o değerin bir KOPYASINI bağlıyor (Python'un `from X import
    Y` semantiği) — `CORE.pin_policy.PIN_MAX_LEN`i sonradan değiştirmek bu
    kopyayı GÜNCELLEMEZ (ampirik olarak doğrulandı: `pp.PIN_MAX_LEN = 999`
    sonrası `ld.PIN_MAX_LEN` hâlâ 32 kaldı). Widget'ın GERÇEKTE okuduğu
    isim `UI.login_dialog.PIN_MAX_LEN` olduğu için doğru yama hedefi de
    odur — `_PinBoxInput.__init__` her çağrıldığında bu ismi KENDİ modül
    ad alanından tazeleyerek okuyor, bu yüzden yama SONRASI construct
    edilen bir widget yeni değeri GERÇEKTEN yansıtıyor.
    """
    import UI.login_dialog as ld

    orijinal = ld.PIN_MAX_LEN
    try:
        ld.PIN_MAX_LEN = 20
        w = ld._PinBoxInput()
        try:
            assert w._kutular[-1].maxLength() == 20, (
                "son kutu PIN_MAX_LEN değişikliğini yansıtmadı — ayrı, "
                "senkron-dışı bir sabitten okunuyor olabilir"
            )
        finally:
            w.deleteLater()
    finally:
        ld.PIN_MAX_LEN = orijinal


@pytest.fixture
def kasa_dizini(tmp_path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    return tmp_path


@pytest.fixture
def totp_gecerli(monkeypatch: pytest.MonkeyPatch) -> None:
    import UI.login_dialog as ld

    monkeypatch.setattr(ld, "_load_secret", lambda: "A" * 32)


def test_giris_ekrani_pin_alani_6_kutulu_widget(
    qapp, db, kasa_dizini, totp_gecerli: None,
) -> None:
    """
    Bütünleşme kontrolü: gerçek `LoginDialog`'un giriş sayfasındaki
    `_pin_input`, `_on_login()`'in okuduğu değeri hâlâ `.text()` ile
    üreten bir `_PinBoxInput` — tek metin kutusuna GERİ DÖNÜLMEMİŞ.
    """
    dlg = LoginDialog(hwid="PIN-KUTU-TEST", first_run=False, use_vault=True)
    try:
        assert isinstance(dlg._pin_input, _PinBoxInput)

        QApplication.clipboard().setText("246810")
        dlg._pin_input._kutular[0].setFocus()
        dlg._pin_input._kutular[0].paste()

        assert dlg._pin_input.text() == "246810"
    finally:
        dlg.deleteLater()
