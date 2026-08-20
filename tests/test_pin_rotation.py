"""
CORE.pin_rotation — zorunlu PIN yenileme (B-003).

Politika 4 haneden 6'ya çıkarıldığında mevcut hesaplar olduğu yerde
bırakılmıştı: Argon2id doğrulaması uzunluktan bağımsız, yani 4-5 haneli
eski PIN'ler geçerli kalmaya devam etti. Politikanın koruduğu şey — kısa
PIN'e karşı kaba kuvvet direnci — tam olarak en eski ve büyük ihtimalle
en yetkili hesaplarda geçerli değildi.

Testler GERÇEK kasa kullanıyor (Argon2id dahil); yalnızca kasa dizini
`tmp_path`'e yönlendiriliyor. Sahte bir kasayla "PIN değişti" demek,
değişmediğini fark etmemek demek olurdu — bu paketin en önemli iddiası
zaten eski PIN'in ARTIK ÇALIŞMAMASI.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from CORE import vault_manager
from CORE.pin_policy import LOGIN_MIN_LEN, PIN_MIN_LEN
from CORE.pin_rotation import (
    EYLEM_ISTEGE_BAGLI,
    EYLEM_ZORUNLU,
    PinRotationError,
    rotate_pin,
    yenileme_gerekli,
)
from CORE.vault_manager import create_vault, open_vault

KOK = Path(__file__).resolve().parent.parent

_HWID = "USB-PINROT-TEST"
_ESKI_PIN = "1234"          # politika öncesi, 4 hane
_YENI_PIN = "123456"        # politikaya uygun
_ROLE = "Yönetici"


@pytest.fixture
def kasa(db, tmp_path: Path, monkeypatch) -> str:
    """`tmp_path` içinde 4 haneli PIN'li GERÇEK bir kasa."""
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    create_vault(_HWID, _ESKI_PIN, _ROLE)
    db.execute(
        "INSERT INTO users (id, username, password_hash, role, status, hwid)"
        " VALUES (7, 'eski', '', 'admin', 'approved', ?)", (_HWID,))
    return _HWID


# ══════════════════════════════════════════════════════════════════════════════
# 1. Tespit — kimin yenilemesi gerekiyor
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("pin", ["", "1", "12", "123", "1234", "12345"])
def test_kisa_PIN_yenileme_gerektiriyor(pin: str) -> None:
    assert yenileme_gerekli(pin), f"{len(pin)} haneli PIN yenileme istemiyor"


@pytest.mark.parametrize("pin", ["123456", "1234567", "a" * 32, "uzun parola cumlesi"])
def test_politikaya_uyan_PIN_yenileme_GEREKTIRMIYOR(pin: str) -> None:
    """
    En kolay yapılacak hata: herkesi akışa sokmak. 6+ haneli kullanıcı bu
    ekranı HİÇ görmemeli.
    """
    assert not yenileme_gerekli(pin)


def test_sinir_tam_olarak_politika_esiginde() -> None:
    assert yenileme_gerekli("1" * (PIN_MIN_LEN - 1))
    assert not yenileme_gerekli("1" * PIN_MIN_LEN)


def test_kopru_araligindaki_PINLER_kapsanıyor() -> None:
    """
    `LOGIN_MIN_LEN` (4) ile `PIN_MIN_LEN` (6) arasındaki her uzunluk —
    yani köprünün var olma sebebi olan tam küme — yenilemeye giriyor.
    """
    for n in range(LOGIN_MIN_LEN, PIN_MIN_LEN):
        assert yenileme_gerekli("1" * n), f"{n} haneli PIN kapsam dışı"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Yenileme GERÇEKTEN oluyor mu
# ══════════════════════════════════════════════════════════════════════════════


def test_yeni_PIN_kasayi_aciyor(kasa, db) -> None:
    rotate_pin(db, kasa, _ESKI_PIN, _YENI_PIN, user_id=7, zorunlu=True)
    rol, anahtar = open_vault(kasa, _YENI_PIN)
    assert rol == _ROLE and len(anahtar) == 32


def test_ESKI_PIN_artik_calismiyor(kasa, db) -> None:
    """
    Bu paketin ana iddiası. Yenileme "yapıldı" deyip eski PIN'i geçerli
    bırakırsa politika boşluğu hiç kapanmamış olur — üstelik kapandığı
    sanılır.
    """
    rotate_pin(db, kasa, _ESKI_PIN, _YENI_PIN, user_id=7, zorunlu=True)
    with pytest.raises(Exception):
        open_vault(kasa, _ESKI_PIN)


def test_master_key_KORUNUYOR(kasa, db) -> None:
    """
    PIN değişimi yalnızca sarmalayan anahtarı yeniliyor. Master key
    değişseydi kullanıcının bütün `.hcl` dosyaları açılamaz hâle
    gelirdi — yani "PIN güncelle" düğmesi bir veri kaybı düğmesi olurdu.
    """
    _rol, once = open_vault(kasa, _ESKI_PIN)
    rotate_pin(db, kasa, _ESKI_PIN, _YENI_PIN, user_id=7, zorunlu=True)
    _rol2, sonra = open_vault(kasa, _YENI_PIN)
    assert once == sonra


def test_rol_KORUNUYOR(kasa, db) -> None:
    rotate_pin(db, kasa, _ESKI_PIN, _YENI_PIN, user_id=7, zorunlu=True)
    assert open_vault(kasa, _YENI_PIN)[0] == _ROLE


# ══════════════════════════════════════════════════════════════════════════════
# 3. Reddedilen girdiler
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("yeni", ["", "1", "12345"])
def test_hala_kisa_bir_PIN_reddediliyor(kasa, db, yeni: str) -> None:
    """
    Akışın anlamı bu: yenileme, politikaya UYAN bir PIN üretmeli.
    Kısa bir PIN kabul edilseydi kullanıcı ekrandan çıkar ve hiçbir şey
    değişmemiş olurdu.
    """
    with pytest.raises(PinRotationError):
        rotate_pin(db, kasa, _ESKI_PIN, yeni, user_id=7, zorunlu=True)
    # Kasa DOKUNULMAMIŞ olmalı — eski PIN hâlâ açıyor.
    assert open_vault(kasa, _ESKI_PIN)[0] == _ROLE


def test_yanlis_eski_PIN_reddediliyor(kasa, db) -> None:
    with pytest.raises(PinRotationError):
        rotate_pin(db, kasa, "9999", _YENI_PIN, user_id=7, zorunlu=True)
    assert open_vault(kasa, _ESKI_PIN)[0] == _ROLE


def test_ayni_PIN_reddediliyor(kasa, db) -> None:
    """
    Kasa yeniden şifrelenir, hiçbir şey değişmez ve denetim kaydı
    "yenilendi" diye yalan söyler.
    """
    rotate_pin(db, kasa, _ESKI_PIN, _YENI_PIN, user_id=7, zorunlu=True)
    with pytest.raises(PinRotationError, match="aynı"):
        rotate_pin(db, kasa, _YENI_PIN, _YENI_PIN, user_id=7)


def test_reddedilen_denemede_denetim_kaydi_YOK(kasa, db) -> None:
    """Olmayan bir değişikliği kaydetmek, kaydı güvenilmez yapar."""
    with pytest.raises(PinRotationError):
        rotate_pin(db, kasa, _ESKI_PIN, "12", user_id=7, zorunlu=True)
    satir = db.fetchone(
        "SELECT COUNT(*) AS n FROM audit_log WHERE action LIKE 'pin_%'")
    assert satir["n"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# 4. Denetim kaydı
# ══════════════════════════════════════════════════════════════════════════════


def test_zorunlu_yenileme_denetime_gecıyor(kasa, db) -> None:
    rotate_pin(db, kasa, _ESKI_PIN, _YENI_PIN, user_id=7, zorunlu=True)
    satir = db.fetchone(
        "SELECT action, user_id, detail FROM audit_log WHERE action = ?",
        (EYLEM_ZORUNLU,))
    assert satir is not None, "zorunlu yenileme denetim kaydına düşmedi"
    assert satir["user_id"] == 7
    assert "eski_uzunluk=4" in satir["detail"]


def test_istege_bagli_degisim_AYRI_eylem_adiyla(kasa, db) -> None:
    """
    İki akış ayırt edilebilmeli: "kullanıcı kendi istedi" ile "sistem
    zorladı" farklı olaylar ve göçün ne kadar ilerlediği ancak böyle
    sayılabilir.
    """
    rotate_pin(db, kasa, _ESKI_PIN, _YENI_PIN, user_id=7, zorunlu=False)
    assert db.fetchone(
        "SELECT 1 FROM audit_log WHERE action = ?", (EYLEM_ISTEGE_BAGLI,))
    assert db.fetchone(
        "SELECT 1 FROM audit_log WHERE action = ?", (EYLEM_ZORUNLU,)) is None


def test_denetim_kaydi_PIN_DEGERINI_tasimiyor(kasa, db) -> None:
    """Kayda giren tek şey uzunluk; değerin kendisi hiçbir yere yazılmıyor."""
    rotate_pin(db, kasa, _ESKI_PIN, _YENI_PIN, user_id=7, zorunlu=True)
    for satir in db.fetchall("SELECT detail FROM audit_log"):
        detay = satir["detail"] or ""
        assert _ESKI_PIN not in detay
        assert _YENI_PIN not in detay


def test_last_pin_changed_guncelleniyor(kasa, db) -> None:
    rotate_pin(db, kasa, _ESKI_PIN, _YENI_PIN, user_id=7, zorunlu=True)
    satir = db.fetchone("SELECT last_pin_changed FROM users WHERE id = 7")
    assert satir["last_pin_changed"], "PIN yaşı sayacı güncellenmedi"


def test_user_id_bilinmese_bile_yenileme_CALISIYOR(kasa, db) -> None:
    """
    Giriş anında `users.id` henüz eşlenmemiş olabilir
    (`sync_session_user` main.py'de, bu akıştan SONRA çalışıyor).
    Kayıt eksikliği yenilemeyi engellememeli.
    """
    rotate_pin(db, kasa, _ESKI_PIN, _YENI_PIN, user_id=None, zorunlu=True)
    assert open_vault(kasa, _YENI_PIN)[0] == _ROLE
    assert db.fetchone("SELECT 1 FROM audit_log WHERE action = ?", (EYLEM_ZORUNLU,))


def test_denetim_kaydi_dusse_bile_PIN_DEGISIYOR(kasa, monkeypatch) -> None:
    """
    Sıra kritik: kasa önce yeniden şifreleniyor. Kayıt adımı hata
    fırlatırsa işlemi "başarısız" saymak, çalışan bir değişikliği
    başarısız diye bildirip kullanıcıyı ESKİ PIN'ini denemeye iterdi —
    gerçek bir kilitlenme.
    """
    class _KirikDB:
        def execute(self, *a, **kw):
            raise RuntimeError("db kilitli")

        def log(self, *a, **kw):
            raise RuntimeError("db kilitli")

    rotate_pin(_KirikDB(), kasa, _ESKI_PIN, _YENI_PIN, user_id=7, zorunlu=True)
    assert open_vault(kasa, _YENI_PIN)[0] == _ROLE


# ══════════════════════════════════════════════════════════════════════════════
# 5. Tek karar noktası — ikinci bir uygulama geri gelmesin
# ══════════════════════════════════════════════════════════════════════════════


def _cagiranlar(ad: str, kok: Path) -> list[str]:
    """`ad(...)` çağrısı yapan dosyalar — AST ile.

    Metin araması bu dosyaların YORUMLARINA da eşleşirdi; bu depoda o
    hata dört kez yaşandı (sonuncusu B-024).
    """
    bulunan = []
    for yol in sorted(kok.rglob("*.py")):
        agac = ast.parse(yol.read_text(encoding="utf-8"))
        for dugum in ast.walk(agac):
            if (isinstance(dugum, ast.Call)
                    and isinstance(dugum.func, ast.Name)
                    and dugum.func.id == ad):
                bulunan.append(yol.name)
                break
    return bulunan


def test_change_vault_pin_UI_katmanindan_dogrudan_cagrilmiyor() -> None:
    """
    `UI/ProfileDialog.py` PIN değiştirmeyi zaten uyguluyordu; zorunlu akış
    için ikinci bir kopya yazmak bu deponun beş kez ürettiği kusurun
    altıncısı olurdu (B-004/B-008, B-007, B-010, B-011, pay ayrıştırıcı).

    Somut risk: PIN değişimine bir gün yeni bir adım eklenir ve yalnızca
    bir kopyaya eklenir; iki yoldan biri sessizce eksik kalır.
    """
    ihlal = _cagiranlar("change_vault_pin", KOK / "UI")
    assert not ihlal, (
        f"Bu dosyalar `change_vault_pin()`'i doğrudan çağırıyor: {ihlal}. "
        "PIN değişimi `CORE.pin_rotation.rotate_pin()` üzerinden geçmeli."
    )


def test_denetim_gercekten_cagri_buluyor() -> None:
    """
    Boş liste dönen bir tarayıcı yukarıdaki testi kendiliğinden
    geçirirdi. `rotate_pin` en az iki yerden çağrılıyor olmalı: zorunlu
    akış ve ProfileDialog.
    """
    cagiranlar = _cagiranlar("rotate_pin", KOK / "UI")
    assert "PinRotationDialog.py" in cagiranlar
    assert "ProfileDialog.py" in cagiranlar


def test_rotate_pin_change_vault_pin_i_GERCEKTEN_cagiriyor() -> None:
    """
    Ters yön: tek karar noktası, kararı gerçekten VERİYOR olmalı. Boş bir
    `rotate_pin`, yukarıdaki iki testten de geçerdi.
    """
    assert _cagiranlar("change_vault_pin", KOK / "CORE") == ["pin_rotation.py"]
