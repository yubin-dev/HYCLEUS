"""
Kayıt ekranı — tasarım mockup'ının kurumsal alanları ve mod ayrımı.

Tarihçe: `077159e` (2026-08-23) mockup'taki ÜÇ alanın (kurum e-postası,
referans kodu, plan/tier chip) hiçbirinin backend karşılığı olmadığını
tespit edip hiçbirini eklemedi ("seçenek a"). Arayüz güncellemesi turunda
(2026-08-26) bunlardan YALNIZCA Referans Kodu için gerçek bir backend
kuruldu (bkz. `CORE/referans_id.py`) — bu yüzden bu dosya güncellendi:
Referans Kodu artık KURUMSAL modda GERÇEKTEN var ve gerçekten doğrulanıyor.
Kurum e-postası ve plan/tier chip kararı DEĞİŞMEDİ — ikisi de hâlâ hiçbir
modda yok, hâlâ backend karşılığı yok.

Sonuç: kayıt ekranı BİREYSEL modda bugünkü gerçek akışın (Kullanıcı Adı +
PIN + PIN Tekrar + Rol) aynısı; KURUMSAL modda buna GERÇEK bir Referans
Kodu doğrulaması ekleniyor (yanlış/boş kod → kayıt reddedilir, DB'ye hiçbir
satır yazılmaz). `UI/login_dialog.py`'nin "Kayıt Ol" sekmesi hedef alındı:
`UI/AdminPanel.py` → `RegisterDialog.py` yolu zaten `_apply_mode_visibility()`
ile Bireysel modda TAMAMEN gizli (bkz. `UI/AdminPanel.py:1233`, "Bekleyen
Kayıtlar" sekmesi) — yani mockup'ın betimlediği, her modda erişilebilir
kalan tek kayıt ekranı budur.

Bu paket şunları ölçüyor
-------------------------
1. YAPISAL (metin/regex) — kurum e-postası ve plan/tier chip HİÇBİR
   dosyada YOK; `INSERT INTO users` sütun listesi tam olarak gerçek beş
   sütun (Referans Kodu `users`'a hiç YAZILMIYOR — settings'te tek bir
   kurulum-geneli değer, bkz. `CORE/referans_id.py`).
2. DAVRANIŞSAL — Bireysel modda kayıt akışı eskisi gibi; Kurumsal modda
   doğru Referans Kodu ile geçiyor, yanlış/boş kodla GERÇEKTEN reddediliyor
   (mutasyon kanıtı: `tests/test_kayit_kurumsal_referans.py`). İki modda
   üretilen `users` satırının ŞEKLİ (sütun kümesi) hâlâ birebir aynı.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

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

from CORE import vault_manager
from CORE.app_mode import BIREYSEL, KURUMSAL, set_app_mode
from CORE.referans_id import generate_referans_id, set_referans_id

KOK = Path(__file__).resolve().parent.parent

_HWID_BASE = "USB-KAYIT-TEST"
_PIN = "yeniPIN123"
_ROLE = "Standart"

#: Backend karşılığı hâlâ olmayan mockup alanları — hiçbir dosyada, hiçbir
#: modda görünmemeli. Referans Kodu buradan ÇIKARILDI (artık gerçek bir
#: backend'i var, bkz. modül docstring'i) — "KRM-" ve "Referans" metinleri
#: artık login_dialog.py'de KURUMSAL modda MEŞRU olarak bulunuyor.
#: "plan"/"tier" gibi çıplak sözcükler DIŞARIDA bırakıldı: Türkçe metinde
#: ("planlanan", vb.) yanlış pozitif üretirdi. Somut etiket/objectName'ler
#: kontrol ediliyor.
_YASAKLI_METINLER = (
    "Kurum e-posta",
    "kurum_email",
    "company_email",
    "plan_chip",
    "tier_chip",
    "plan_badge",
    "tier_badge",
)

_KAYIT_DOSYALARI = ("UI/login_dialog.py", "UI/RegisterDialog.py")

#: Gerçek `users` tablosuna yazılan tek sütun kümesi (bkz. `DB/db_manager.py`
#: şeması + `hwid`/`status` göçleri). Kurum/referans/plan sütunu YOK.
_GERCEK_KOLONLAR = frozenset({"username", "password_hash", "role", "status", "hwid"})

#: B-060/061 sonrası `INSERT INTO users` TEK yerde — iki kayıt ekranı da
#: buraya bağlanıyor (bkz. aşağıdaki testler).
_REGISTRATION_MODULE = "CORE/registration.py"


def _kaynak(yol: str) -> str:
    return (KOK / yol).read_text(encoding="utf-8")


def _insert_users_kolonlari(kaynak: str) -> frozenset[str]:
    """`INSERT INTO users (...)` sütun listesini ayrıştırır."""
    eslesme = re.search(r"INSERT INTO users\s*\(([^)]+)\)", kaynak)
    assert eslesme, "kaynakta 'INSERT INTO users (...)' bulunamadı"
    return frozenset(ad.strip() for ad in eslesme.group(1).split(","))


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


@pytest.fixture
def totp_gecerli(monkeypatch: pytest.MonkeyPatch) -> None:
    """`LoginDialog(first_run=False)` bir TOTP sırrı bekliyor — sabitleniyor."""
    import UI.login_dialog as ld

    monkeypatch.setattr(ld, "_load_secret", lambda: "A" * 32)


def _kayit_ekrani(qapp) -> LoginDialog:
    return LoginDialog(hwid="ADMIN-HWID-IGNORED", first_run=False, use_vault=True)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Mockup'ın kurumsal alanları — hiçbir dosyada, hiçbir modda YOK
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("dosya", _KAYIT_DOSYALARI)
def test_kurumsal_alanlar_HICBIR_KAYIT_DOSYASINDA_YOK(dosya: str) -> None:
    kaynak = _kaynak(dosya)
    bulunan = [m for m in _YASAKLI_METINLER if m in kaynak]
    assert not bulunan, f"{dosya}: mockup'ın kurumsal alanı eklenmiş: {bulunan}"


def test_INSERT_users_TAM_gercek_kolonlari_yaziyor() -> None:
    """
    Kurum/referans/plan gibi bir alan UI'a hiç eklenmese bile, birinin
    "madem ekranda değil, DB'ye kaydını tutayım" diyerek satır içine
    sızdırmasını da kapatıyor: sütun listesi TAM olarak gerçek beşli.

    B-060/061 sonrası `INSERT INTO users` iki kayıt ekranında ayrı ayrı
    DEĞİL, `CORE/registration.py::register_new_user()`'da TEK yerde —
    bkz. `test_kayit_dosyalari_KENDI_INSERT_ini_YAZMIYOR`.
    """
    kolonlar = _insert_users_kolonlari(_kaynak(_REGISTRATION_MODULE))
    assert kolonlar == _GERCEK_KOLONLAR, (
        f"{_REGISTRATION_MODULE}: INSERT INTO users beklenmeyen sütun(lar) "
        f"içeriyor: {kolonlar - _GERCEK_KOLONLAR}"
    )


@pytest.mark.parametrize("dosya", _KAYIT_DOSYALARI)
def test_kayit_dosyalari_KENDI_INSERT_ini_YAZMIYOR(dosya: str) -> None:
    """
    B-060/061: iki kayıt ekranı aynı iki hatayı (HWID çakışma kontrolü
    yok + create_vault()/INSERT atomik değil) BAĞIMSIZ olarak
    tekrarlıyordu — ikisi de kendi `INSERT INTO users`'ını yazıyordu.
    Düzeltme sonrası ikisi de `CORE.registration.register_new_user()`
    üzerinden geçiyor ("iki çağıran, tek gövde"); bu test o ayrışmanın
    geri gelmediğini doğruluyor.
    """
    kaynak = _kaynak(dosya)
    assert "INSERT INTO users" not in kaynak, (
        f"{dosya} kendi 'INSERT INTO users'ını yeniden yazmış — "
        "CORE.registration.register_new_user() kullanılmalı (B-060/061)"
    )
    assert "register_new_user" in kaynak, (
        f"{dosya} register_new_user() çağırmıyor gibi görünüyor"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2. Davranışsal — kayıt akışı her iki modda BİREBİR aynı
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("mod", [KURUMSAL, BIREYSEL])
def test_kayit_akisi_HER_IKI_MODDA_da_tamamlaniyor(
    qapp, db, kasa_dizini, totp_gecerli, monkeypatch: pytest.MonkeyPatch, mod: str,
) -> None:
    set_app_mode(db, mod)

    import UI.login_dialog as ld
    hwid = f"{_HWID_BASE}-{mod}"
    monkeypatch.setattr(ld, "get_usb_hwid", lambda: hwid)
    # B-059: kayıt artık kendi TOTP sırrını üretip bir QR/mesaj kutusu
    # gösteriyor (`show_totp_enrollment_dialog`, modal `.exec()`) —
    # testte bu bloklamasın diye susturuluyor.
    monkeypatch.setattr(ld, "show_totp_enrollment_dialog", lambda *a, **k: None)

    dlg = _kayit_ekrani(qapp)
    kullanici_adi = f"kayit_{mod}"
    dlg._reg_username.setText(kullanici_adi)
    dlg._reg_pin.setText(_PIN)
    dlg._reg_pin2.setText(_PIN)
    dlg._reg_role.setCurrentText(_ROLE)

    # KURUMSAL modda artık GERÇEK bir Referans Kodu alanı var — doğru
    # değer olmadan `_on_register()` reddeder (bkz. test_kayit_kurumsal_
    # referans.py'deki ret/mutasyon testleri). Bireysel modda alan hiç
    # oluşturulmuyor (`dlg._reg_referans is None`).
    if mod == KURUMSAL:
        rid = generate_referans_id()
        set_referans_id(db, rid)
        assert dlg._reg_referans is not None
        dlg._reg_referans.setText(rid)
    else:
        assert dlg._reg_referans is None

    dlg._on_register()

    # `.isVisible()` DEĞİL: `dlg` hiç `.show()` edilmedi, bu yüzden ana
    # pencere gösterilmeden `.isVisible()` her zaman `False` döner (bkz.
    # `tests/test_slide_over.py`'deki aynı tuzak). `.isHidden()` widget'ın
    # KENDİ `.show()`/`.hide()` çağrılarını yansıtıyor.
    assert dlg._reg_error.isHidden(), (
        f"{mod}: kayıt hata verdi: {dlg._reg_error.text()}"
    )
    satir = db.fetchone(
        "SELECT * FROM users WHERE username = ?", (kullanici_adi,)
    )
    assert satir is not None, f"{mod}: kullanıcı DB'ye yazılmadı"
    assert satir["status"] == "pending"
    assert satir["hwid"] == hwid
    assert satir["role"] == "user"  # db_role("Standart")

    # Şemanın kendisi kurum/referans/plan sütunu taşımıyor — satırın
    # anahtarları da bunu doğruluyor (parametrized: KURUMSAL ve BİREYSEL
    # AYNI kolon kümesini üretiyor, mod satırın ŞEKLİNİ değiştirmiyor).
    assert set(satir.keys()) >= _GERCEK_KOLONLAR
    for yasakli_alt_dize in ("email", "kurum", "referans", "plan", "tier"):
        assert not any(yasakli_alt_dize in k.lower() for k in satir.keys()), (
            f"{mod}: users tablosunda beklenmeyen bir sütun var: {list(satir.keys())}"
        )


def test_iki_mod_SONUC_SATIRININ_SEKLI_AYNI_kaliyor(
    qapp, db, kasa_dizini, totp_gecerli, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Arayüz güncellemesi turundan ÖNCE bu test "iki mod BİREBİR aynı
    davranıyor" diyordu — artık doğru değil: Kurumsal modda GERÇEK bir
    Referans Kodu adımı var (bkz. modül docstring'i). Hâlâ doğru olan ve
    burada kanıtlanan şey: SÜREÇ farklı olsa da, sonuçta `users`'a yazılan
    satırın ŞEKLİ (hangi sütunlar, hangi tipte) iki modda birebir aynı —
    Referans Kodu satıra hiç YAZILMIYOR, yalnızca doğrulama için kullanılıp
    atılıyor.
    """
    import UI.login_dialog as ld
    monkeypatch.setattr(ld, "show_totp_enrollment_dialog", lambda *a, **k: None)

    sonuclar = {}
    for mod in (KURUMSAL, BIREYSEL):
        set_app_mode(db, mod)
        hwid = f"{_HWID_BASE}-esit-{mod}"
        monkeypatch.setattr(ld, "get_usb_hwid", lambda hwid=hwid: hwid)

        dlg = _kayit_ekrani(qapp)
        kullanici_adi = f"esit_{mod}"
        dlg._reg_username.setText(kullanici_adi)
        dlg._reg_pin.setText(_PIN)
        dlg._reg_pin2.setText(_PIN)
        dlg._reg_role.setCurrentText(_ROLE)
        if mod == KURUMSAL:
            rid = generate_referans_id()
            set_referans_id(db, rid)
            dlg._reg_referans.setText(rid)
        dlg._on_register()

        satir = db.fetchone("SELECT * FROM users WHERE username = ?", (kullanici_adi,))
        assert satir is not None, f"{mod}: kayıt hata verdi: {dlg._reg_error.text()}"
        # `password_hash` argon2'nin kendi rastgele tuzu yüzünden aynı PIN'de
        # bile HER kayıtta farklı çıkar — karşılaştırma dışında tutuluyor,
        # yoksa bu test hiçbir zaman geçmezdi (mod farkından değil, tuzdan).
        sonuclar[mod] = {k: v for k, v in dict(satir).items()
                         if k not in ("id", "username", "hwid", "created_at", "password_hash")}

    assert sonuclar[KURUMSAL] == sonuclar[BIREYSEL], (
        "iki modda üretilen satırın ŞEKLİ farklılaştı — Referans Kodu "
        "users tablosuna SIZMIŞ olabilir"
    )
    for k in sonuclar[KURUMSAL]:
        assert "referans" not in k.lower() and "kurum" not in k.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 3. Sürüm etiketi — CORE/version.py'den okunuyor, elle yazılı DEĞİL (B-017)
# ══════════════════════════════════════════════════════════════════════════════


def test_giris_ekraninda_surum_etiketi_versiyon_py_ile_birebir_eslesiyor(
    qapp, db, kasa_dizini, totp_gecerli, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Mutasyonla kanıt: `CORE.version.__version__` değiştirilince ekranda
    GÖRÜNEN metin de değişmeli — sabit bir dize kopyalanmış olsaydı bu
    ikinci kontrol düşerdi, yalnızca ilk eşitlik geçerdi.
    """
    import UI.login_dialog as ld
    from CORE import version as version_modulu

    monkeypatch.setattr(ld, "get_usb_hwid", lambda: f"{_HWID_BASE}-surum")

    dlg = _kayit_ekrani(qapp)
    assert dlg._surum_etiketi.text() == version_modulu.surum_etiketi()

    onceki = dlg._surum_etiketi.text()
    monkeypatch.setattr(version_modulu, "__version__", "9.9.9-mutasyon")
    dlg_mutasyonlu = _kayit_ekrani(qapp)
    assert dlg_mutasyonlu._surum_etiketi.text() == "HYCLEUS v9.9.9-mutasyon"
    assert dlg_mutasyonlu._surum_etiketi.text() != onceki
