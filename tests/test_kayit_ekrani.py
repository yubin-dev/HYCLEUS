"""
Kayıt ekranı — tasarım mockup'ının kurumsal alanları (kurum e-postası,
referans kodu, plan/tier chip) ve mod ayrımı.

Karar (bu paket bunu SABİTLİYOR): mockup'taki üç alanın hiçbirinin
backend karşılığı yok — `users` tablosunda kurum/referans/plan sütunu
YOK, HYCLEUS'ta çok kiracılı (tenant) ya da davetiye-kodu kavramı hiç
yok. Bu yüzden alanlar HİÇBİR MODDA eklenmedi (seçenek a — "alanları
şimdilik hiç ekleme"), "isteğe bağlı" etiketiyle bile: bir güvenlik
kasası kaydında kullanıcı bir form alanına bir şey yazdığında onun bir
yere gittiğini varsayar; etiket bu varsayımı tam olarak silmiyor.
Plan/tier chip'i zaten hiçbir yerde yoktu — kaldırılacak bir şey
bulunamadı.

Sonuç: kayıt ekranı HER İKİ modda da bugünkü gerçek akışın (Kullanıcı
Adı + PIN + PIN Tekrar + Rol) aynısı — mod, bu ekranı hiç ETKİLEMİYOR.
`UI/login_dialog.py`'nin "Kayıt Ol" sekmesi hedef alındı: `UI/AdminPanel.py`
→ `RegisterDialog.py` yolu zaten `_apply_mode_visibility()` ile Bireysel
modda TAMAMEN gizli (bkz. `UI/AdminPanel.py:1233`, "Bekleyen Kayıtlar"
sekmesi) — yani mockup'ın betimlediği, her modda erişilebilir kalan tek
kayıt ekranı budur.

Bu paket iki şeyi ölçüyor
--------------------------
1. YAPISAL (metin/regex) — mockup'ın kurumsal alanları ve plan/tier
   chip'i HİÇBİR dosyada YOK; `INSERT INTO users` sütun listesi tam
   olarak gerçek beş sütun. Biri "isteğe bağlı" etiketiyle bile bu
   alanları geri getirirse test düşer.
2. DAVRANIŞSAL — kayıt akışı BİREYSEL ve KURUMSAL modda BİREBİR aynı
   şekilde tamamlanıyor; mod DB'ye yazılan satırı hiç ETKİLEMİYOR.
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

KOK = Path(__file__).resolve().parent.parent

_HWID_BASE = "USB-KAYIT-TEST"
_PIN = "yeniPIN123"
_ROLE = "Standart"

#: Mockup'ın kurumsal alanları — hiçbir dosyada, hiçbir modda görünmemeli.
#: "plan"/"tier" gibi çıplak sözcükler DIŞARIDA bırakıldı: Türkçe metinde
#: ("planlanan", vb.) yanlış pozitif üretirdi. Somut etiket/objectName'ler
#: kontrol ediliyor.
_YASAKLI_METINLER = (
    "Kurum e-posta",
    "kurum_email",
    "company_email",
    "Referans kod",
    "referans_kod",
    "reference_code",
    "KRM-",
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

    dlg = _kayit_ekrani(qapp)
    kullanici_adi = f"kayit_{mod}"
    dlg._reg_username.setText(kullanici_adi)
    dlg._reg_pin.setText(_PIN)
    dlg._reg_pin2.setText(_PIN)
    dlg._reg_role.setCurrentText(_ROLE)

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


def test_iki_mod_AYNI_sekilde_davraniyor(
    qapp, db, kasa_dizini, totp_gecerli, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Mod farkı YOK denemesinin doğrudan kanıtı: aynı girdiyle iki ayrı
    kullanıcı adı altında iki moda da kaydolunca satırlar (kullanıcı adı
    ve hwid dışında) BİREBİR aynı şekle sahip olmalı.
    """
    import UI.login_dialog as ld

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
        dlg._on_register()

        satir = db.fetchone("SELECT * FROM users WHERE username = ?", (kullanici_adi,))
        assert satir is not None
        # `password_hash` argon2'nin kendi rastgele tuzu yüzünden aynı PIN'de
        # bile HER kayıtta farklı çıkar — karşılaştırma dışında tutuluyor,
        # yoksa bu test hiçbir zaman geçmezdi (mod farkından değil, tuzdan).
        sonuclar[mod] = {k: v for k, v in dict(satir).items()
                         if k not in ("id", "username", "hwid", "created_at", "password_hash")}

    assert sonuclar[KURUMSAL] == sonuclar[BIREYSEL], (
        "kayıt sonucu moda göre farklılaşıyor — mod bu ekranı ETKİLEMEMELİ"
    )
