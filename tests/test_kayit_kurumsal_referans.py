"""
HYCLEUS — Kurumsal Referans ID: uçtan uca (İlk Kurulum → Kayıt Ol)

Arayüz güncellemesi turu (2026-08-26): İlk Kurulum sihirbazına Bireysel/
Kurumsal seçimi eklendi (bkz. `UI/login_dialog.py::_build_setup_ui`,
mockup'ta yoktu — bizim kararımız). Kurumsal seçilirse gerçek bir
Referans ID üretilip `settings` tablosuna kalıcı yazılıyor
(`CORE/referans_id.py`); Kayıt Ol ekranındaki Referans Kodu alanı bu
değerle GERÇEKTEN karşılaştırılıyor — sahte bir "geçerli" onayı asla
verilmiyor.

Bu paket beş şeyi ölçüyor
---------------------------
1. İlk Kurulum'da Kurumsal seçilince Referans ID gerçekten üretilip
   kaydediliyor; Bireysel seçilince HİÇ üretilmiyor.
2. Kayıt Ol'da doğru kod geçer, yanlış/boş kod REDDEDİLİR — reddedilince
   `register_new_user()` hiç ÇAĞRILMAZ, DB'ye hiçbir satır yazılmaz.
3. Bireysel modda Referans Kodu alanı hiç OLUŞTURULMAZ (widget `None`) ve
   `users` satırına hiçbir referans/kurum sütunu sızmaz.
4. Mutasyon kanıtı: `_on_register()`'daki karşılaştırma bloğu geçici
   olarak kaldırıldığında yanlış-kod testi GERÇEKTEN düşüyor mu — ayrı
   bir betikle elle doğrulandı (bkz. commit mesajı / oturum notları),
   burada kalıcı bir test olarak DEĞİL çünkü mutasyon üretim dosyasını
   geçici değiştirmeyi gerektiriyor.
5. Hız sınırı (bu tur, kaba kuvvete karşı): art arda yanlış kod
   denemesi `CORE/rate_limit.py`'yi (giriş ekranının ZATEN kullandığı
   AYNI mekanizma, `login_attempts` tablosu) devreye sokuyor — KİLİTLİYKEN
   doğru kod BİLE reddediliyor; doğru kod İLK denemede gecikme OLMADAN
   geçiyor (yanlış pozitif yok); ve referans sayacı giriş ekranının PIN/
   TOTP sayacıyla KARIŞMIYOR (ayrı anahtar uzayı, `_referans_rl_key()`).
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pyotp
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication

    from UI.login_dialog import LoginDialog
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE import rate_limit, vault_manager
from CORE.app_mode import BIREYSEL, KURUMSAL, get_app_mode, set_app_mode
from CORE.rate_limit import MAX_ATTEMPTS
from CORE.referans_id import get_referans_id, set_referans_id

_HWID_KURULUM = "USB-REFID-KURULUM"
_HWID_KAYIT = "USB-REFID-KAYIT"
_PIN_KURULUM = "kurulumPIN123"
_PIN_KAYIT = "kayitPIN123"
_BICIM = re.compile(r"^KRM-[A-Z2-9]{8}$")


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


@pytest.fixture
def kasa_dizini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    return tmp_path


def _ilk_kurulumu_tamamla(qapp, hwid: str, pin: str, mod: str) -> LoginDialog:
    dlg = LoginDialog(hwid=hwid, first_run=True, use_vault=True)
    assert hasattr(dlg, "_mode_group"), "Görünüm Modu bölümü sihirbazda yok"

    for btn in dlg._mode_group.buttons():
        if btn.property("mode_value") == mod:
            btn.setChecked(True)
            break
    else:
        raise AssertionError(f"mod seçeneği bulunamadı: {mod}")

    kod = pyotp.TOTP(dlg._secret).now()
    dlg._pin_input.setText(pin)
    dlg._pin_confirm_input.setText(pin)
    dlg._totp_input.setText(kod)
    dlg._on_setup_confirm()
    return dlg


# ══════════════════════════════════════════════════════════════════════════════
# 1. İlk Kurulum — mod seçimi Referans ID üretimini gerçekten kontrol ediyor
# ══════════════════════════════════════════════════════════════════════════════


def test_ilk_kurulumda_KURUMSAL_secilirse_referans_id_uretilip_kaydediliyor(
    qapp, db, kasa_dizini, monkeypatch: pytest.MonkeyPatch,
) -> None:
    gosterilen = []
    monkeypatch.setattr(
        LoginDialog, "_show_referans_id_dialog",
        lambda self, rid: gosterilen.append(rid),
    )

    assert get_referans_id(db) is None, "ön koşul: henüz üretilmemiş olmalı"

    dlg = _ilk_kurulumu_tamamla(qapp, _HWID_KURULUM, _PIN_KURULUM, KURUMSAL)
    assert dlg.result() == LoginDialog.Accepted

    assert get_app_mode(db) == KURUMSAL
    kayitli = get_referans_id(db)
    assert kayitli is not None, "Kurumsal seçilince Referans ID hiç üretilmedi"
    assert _BICIM.match(kayitli), f"beklenmeyen biçim: {kayitli}"

    # Kullanıcıya GERÇEKTEN gösterildi (kopyalanabilir diyalog) — sessizce
    # üretilip saklanmadı.
    assert gosterilen == [kayitli]


def test_ilk_kurulumda_BIREYSEL_secilirse_referans_id_HIC_uretilmiyor(
    qapp, db, kasa_dizini, monkeypatch: pytest.MonkeyPatch,
) -> None:
    cagrildi = []
    monkeypatch.setattr(
        LoginDialog, "_show_referans_id_dialog",
        lambda self, rid: cagrildi.append(rid),
    )

    dlg = _ilk_kurulumu_tamamla(qapp, _HWID_KURULUM, _PIN_KURULUM, BIREYSEL)
    assert dlg.result() == LoginDialog.Accepted

    assert get_app_mode(db) == BIREYSEL
    assert get_referans_id(db) is None, (
        "Bireysel seçilmesine rağmen bir Referans ID üretilip kaydedilmiş"
    )
    assert cagrildi == [], "Bireysel modda Referans ID diyaloğu hiç açılmamalı"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Kayıt Ol — Kurumsal modda GERÇEK karşılaştırma
# ══════════════════════════════════════════════════════════════════════════════


def _kayit_ekrani_kurulu(qapp, monkeypatch: pytest.MonkeyPatch, hwid: str) -> LoginDialog:
    import UI.login_dialog as ld

    monkeypatch.setattr(ld, "get_usb_hwid", lambda: hwid)
    monkeypatch.setattr(ld, "show_totp_enrollment_dialog", lambda *a, **k: None)
    return LoginDialog(hwid="ADMIN-HWID-IGNORED", first_run=False, use_vault=True)


def test_kurumsal_kayitta_DOGRU_referans_kodu_ile_GECIYOR(
    qapp, db, kasa_dizini, monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_app_mode(db, KURUMSAL)
    gercek_kod = "KRM-ABCD1234"
    set_referans_id(db, gercek_kod)

    dlg = _kayit_ekrani_kurulu(qapp, monkeypatch, _HWID_KAYIT)
    assert dlg._reg_referans is not None

    dlg._reg_username.setText("kurumsal_dogru")
    dlg._reg_pin.setText(_PIN_KAYIT)
    dlg._reg_pin2.setText(_PIN_KAYIT)
    dlg._reg_role.setCurrentText("Standart")
    dlg._reg_referans.setText(gercek_kod)
    dlg._on_register()

    assert dlg._reg_error.isHidden(), f"beklenmedik ret: {dlg._reg_error.text()}"
    satir = db.fetchone("SELECT * FROM users WHERE username = ?", ("kurumsal_dogru",))
    assert satir is not None, "doğru kod girildiği hâlde kullanıcı DB'ye yazılmadı"


def test_kurumsal_kayitta_YANLIS_referans_kodu_REDDEDILIYOR(
    qapp, db, kasa_dizini, monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_app_mode(db, KURUMSAL)
    set_referans_id(db, "KRM-DOGRUKOD1")

    dlg = _kayit_ekrani_kurulu(qapp, monkeypatch, _HWID_KAYIT)
    dlg._reg_username.setText("kurumsal_yanlis")
    dlg._reg_pin.setText(_PIN_KAYIT)
    dlg._reg_pin2.setText(_PIN_KAYIT)
    dlg._reg_role.setCurrentText("Standart")
    dlg._reg_referans.setText("KRM-YANLISKOD")
    dlg._on_register()

    assert not dlg._reg_error.isHidden(), "yanlış kodla kayıt SESSİZCE geçti"
    assert "Referans" in dlg._reg_error.text()
    satir = db.fetchone("SELECT * FROM users WHERE username = ?", ("kurumsal_yanlis",))
    assert satir is None, (
        "REGRESYON: yanlış Referans Kodu ile bile kullanıcı DB'ye yazılmış"
    )


def test_kurumsal_kayitta_BOS_referans_kodu_REDDEDILIYOR(
    qapp, db, kasa_dizini, monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_app_mode(db, KURUMSAL)
    set_referans_id(db, "KRM-DOGRUKOD2")

    dlg = _kayit_ekrani_kurulu(qapp, monkeypatch, _HWID_KAYIT)
    dlg._reg_username.setText("kurumsal_bos")
    dlg._reg_pin.setText(_PIN_KAYIT)
    dlg._reg_pin2.setText(_PIN_KAYIT)
    dlg._reg_role.setCurrentText("Standart")
    # dlg._reg_referans hiç doldurulmadı — boş.
    dlg._on_register()

    assert not dlg._reg_error.isHidden()
    satir = db.fetchone("SELECT * FROM users WHERE username = ?", ("kurumsal_bos",))
    assert satir is None


# ══════════════════════════════════════════════════════════════════════════════
# 3. Bireysel modda alan hiç yok, DB'ye hiç yazmıyor
# ══════════════════════════════════════════════════════════════════════════════


def test_bireysel_kayitta_referans_alani_hic_YOK_ve_DBye_hic_YAZMIYOR(
    qapp, db, kasa_dizini, monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_app_mode(db, BIREYSEL)

    dlg = _kayit_ekrani_kurulu(qapp, monkeypatch, _HWID_KAYIT)
    assert dlg._reg_referans is None, (
        "Bireysel modda Referans Kodu widget'ı OLUŞTURULMAMALI"
    )

    dlg._reg_username.setText("bireysel_kayit")
    dlg._reg_pin.setText(_PIN_KAYIT)
    dlg._reg_pin2.setText(_PIN_KAYIT)
    dlg._reg_role.setCurrentText("Standart")
    dlg._on_register()

    assert dlg._reg_error.isHidden(), f"beklenmedik ret: {dlg._reg_error.text()}"
    satir = db.fetchone("SELECT * FROM users WHERE username = ?", ("bireysel_kayit",))
    assert satir is not None
    for k in satir.keys():
        assert "referans" not in k.lower() and "kurum" not in k.lower(), (
            f"users tablosunda beklenmeyen sütun: {k}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 4. Hız sınırı — kaba kuvvete karşı (CORE/rate_limit.py'nin giriş ekranındaki
#    AYNI mekanizması, yalnızca ayrı bir anahtar uzayıyla)
# ══════════════════════════════════════════════════════════════════════════════


def _yanlis_dene(dlg: LoginDialog, username: str) -> None:
    """`_on_register()`'ı YANLIŞ bir kodla bir kez çalıştırır."""
    dlg._reg_error.hide()
    dlg._reg_username.setText(username)
    dlg._reg_pin.setText(_PIN_KAYIT)
    dlg._reg_pin2.setText(_PIN_KAYIT)
    dlg._reg_role.setCurrentText("Standart")
    dlg._reg_referans.setText("KRM-YANLISYX")
    dlg._on_register()


def test_kurumsal_kayitta_ART_ARDA_yanlis_kod_HIZ_SINIRINA_TAKILIYOR(
    qapp, db, kasa_dizini, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Asıl istenen davranış: `MAX_ATTEMPTS` yanlış denemeden sonra sıradaki
    deneme — DOĞRU kod verilse BİLE — reddediliyor. `CORE/rate_limit.py`'nin
    `check()`'i karşılaştırmadan ÖNCE çalışıyor (`_on_login()` ile AYNI
    sıra), yani kilitliyken doğru kodu bilmek bile işe yaramıyor.
    """
    gercek_kod = "KRM-DOGRUKOD3"
    set_app_mode(db, KURUMSAL)
    set_referans_id(db, gercek_kod)
    dlg = _kayit_ekrani_kurulu(qapp, monkeypatch, _HWID_KAYIT)

    for i in range(MAX_ATTEMPTS):
        _yanlis_dene(dlg, f"art_arda_{i}")
        assert not dlg._reg_error.isHidden()
        satir = db.fetchone(
            "SELECT * FROM users WHERE username = ?", (f"art_arda_{i}",)
        )
        assert satir is None

    # Eşik aşıldı — şimdi DOĞRU kodla dene.
    dlg._reg_error.hide()
    dlg._reg_username.setText("art_arda_dogru_ama_gec")
    dlg._reg_pin.setText(_PIN_KAYIT)
    dlg._reg_pin2.setText(_PIN_KAYIT)
    dlg._reg_role.setCurrentText("Standart")
    dlg._reg_referans.setText(gercek_kod)
    dlg._on_register()

    assert not dlg._reg_error.isHidden(), (
        "MUTASYON: hız sınırı aşıldıktan sonra DOĞRU kod bile geçti"
    )
    assert "fazla" in dlg._reg_error.text() or "deneme" in dlg._reg_error.text()
    satir = db.fetchone(
        "SELECT * FROM users WHERE username = ?", ("art_arda_dogru_ama_gec",)
    )
    assert satir is None, "kilitliyken doğru kodla bile kullanıcı DB'ye yazılmış"


def test_kurumsal_kayitta_DOGRU_kod_ILK_denemede_GECIKME_OLMADAN_geciyor(
    qapp, db, kasa_dizini, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Yanlış pozitif yok: hiç yanlış deneme yapılmamış bir HWID için doğru
    kod hiçbir gecikmeye uğramadan, ilk denemede geçiyor."""
    gercek_kod = "KRM-DOGRUKOD4"
    set_app_mode(db, KURUMSAL)
    set_referans_id(db, gercek_kod)
    dlg = _kayit_ekrani_kurulu(qapp, monkeypatch, _HWID_KAYIT)

    assert rate_limit.check(db, dlg._referans_rl_key()).locked is False, (
        "ön koşul: taze bir HWID'in referans sayacı kilitli olmamalı"
    )

    dlg._reg_username.setText("hemen_dogru")
    dlg._reg_pin.setText(_PIN_KAYIT)
    dlg._reg_pin2.setText(_PIN_KAYIT)
    dlg._reg_role.setCurrentText("Standart")
    dlg._reg_referans.setText(gercek_kod)
    dlg._on_register()

    assert dlg._reg_error.isHidden(), f"beklenmedik ret: {dlg._reg_error.text()}"
    satir = db.fetchone("SELECT * FROM users WHERE username = ?", ("hemen_dogru",))
    assert satir is not None


def test_kurumsal_kayitta_referans_sayaci_GIRIS_sayaciyla_KARISMIYOR(
    qapp, db, kasa_dizini, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Referans Kodu denemeleri AYRI bir anahtar uzayında (`referans:` öneki).
    Aynı HWID için referans sayacı kilitlense bile, GİRİŞ ekranının PIN/
    TOTP sayacı (`_rl_key()`) ETKİLENMEMELİ — aksi hâlde bir kullanıcının
    kayıt sırasında kod yazım hataları, o USB'nin giriş ekranını da
    kilitlerdi (iki ayrı olay, iki ayrı kovaya düşmeli).
    """
    set_app_mode(db, KURUMSAL)
    set_referans_id(db, "KRM-DOGRUKOD5")
    dlg = _kayit_ekrani_kurulu(qapp, monkeypatch, _HWID_KAYIT)

    for i in range(MAX_ATTEMPTS):
        _yanlis_dene(dlg, f"karisma_{i}")

    assert rate_limit.check(db, dlg._referans_rl_key()).locked is True, (
        "test kurulumu hatalı — referans sayacı kilitlenmedi"
    )
    assert rate_limit.check(db, dlg._rl_key()).locked is False, (
        "REGRESYON: referans kodu denemeleri giriş ekranının PIN/TOTP "
        "sayacını da kilitlemiş"
    )


def test_kurumsal_kayitta_BOS_kod_denemeleri_SAYACI_ARTIRMIYOR(
    qapp, db, kasa_dizini, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Boş gönderim bir TAHMİN değil — sayaca işlenmemeli, aksi hâlde
    "Kayıt Ol"a boş alanla art arda basmak bile kilitlenmeye yol açardı."""
    gercek_kod = "KRM-DOGRUKOD6"
    set_app_mode(db, KURUMSAL)
    set_referans_id(db, gercek_kod)
    dlg = _kayit_ekrani_kurulu(qapp, monkeypatch, _HWID_KAYIT)

    for _ in range(MAX_ATTEMPTS * 2):
        dlg._reg_error.hide()
        dlg._reg_username.setText("bos_kod_denemesi")
        dlg._reg_pin.setText(_PIN_KAYIT)
        dlg._reg_pin2.setText(_PIN_KAYIT)
        dlg._reg_role.setCurrentText("Standart")
        dlg._reg_referans.setText("")
        dlg._on_register()

    assert rate_limit.check(db, dlg._referans_rl_key()).locked is False, (
        "boş kod denemeleri referans hız sınırını tetiklemiş"
    )

    # Doğru kod hâlâ gecikmeden geçiyor.
    dlg._reg_error.hide()
    dlg._reg_username.setText("bos_sonra_dogru")
    dlg._reg_pin.setText(_PIN_KAYIT)
    dlg._reg_pin2.setText(_PIN_KAYIT)
    dlg._reg_role.setCurrentText("Standart")
    dlg._reg_referans.setText(gercek_kod)
    dlg._on_register()

    assert dlg._reg_error.isHidden()
    satir = db.fetchone("SELECT * FROM users WHERE username = ?", ("bos_sonra_dogru",))
    assert satir is not None
