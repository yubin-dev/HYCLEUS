"""
HYCLEUS — kayıt/kimlik katmanının yetkilendirme DEĞİŞMEZLERİ (B-060/061)

B-058 sınıfı bir tarama (BACKLOG B-060/B-061) şunu buldu: kayıt akışı
"bu HWID zaten var mı" sorusunu hiç sormuyordu ve `create_vault()` ile
`users` INSERT'i atomik değildi. İkisi de aynı sonuca çıkıyordu: hiç
onaylanmamış bir kullanıcı `status='approved'` ile sisteme giriyordu.

Bu dosya o düzeltmenin dört DEĞİŞMEZİNİ (invariant) sabitliyor. İlk üçü
bu turda düzeltildi ve YEŞİL olmalı. Dördüncüsü (TOTP kullanıcı başına)
B-059'a bağlı, henüz uygulanmadı — `xfail(strict=True)` ile işaretli;
bu turun "yeşil" sayımına dahil değil, B-059 kapanınca kendiliğinden
yeşile dönecek.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from CORE import vault_manager
from CORE.registration import (
    HwidAlreadyRegisteredError,
    UsernameTakenError,
    register_new_user,
)
from DB import migrations as M

_PIN = "gecerli-pin-123"


@pytest.fixture
def kasa_dizini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / "legacy.hclv")
    return tmp_path


# ══════════════════════════════════════════════════════════════════════════════
# Değişmez 1 — HWID → en fazla BİR (herhangi durumdaki) users satırı
# ══════════════════════════════════════════════════════════════════════════════


def test_hwid_en_fazla_bir_kullaniciya_bagli(db, kasa_dizini) -> None:
    hwid = "USB-INV-001"
    register_new_user(db, hwid=hwid, username="ilk", pin=_PIN, role="Standart")

    with pytest.raises(HwidAlreadyRegisteredError):
        register_new_user(
            db, hwid=hwid, username="ikinci", pin="baska-pin-456", role="Standart",
        )

    satirlar = db.fetchall("SELECT id FROM users WHERE hwid = ?", (hwid,))
    assert len(satirlar) == 1, "ikinci kayıt reddedilmedi mi, yoksa iki satır mı var"


def test_UNIQUE_kisit_uygulama_katmanini_bypass_eden_INSERTi_de_reddediyor(
    db,
) -> None:
    """
    `register_new_user()`'ın ön kontrolü TOCTOU'ya karşı savunmasız
    olsaydı bile, `users.hwid` üzerindeki UNIQUE indeksin kendisi son
    çare olarak ikinci satırı reddetmeli.
    """
    hwid = "USB-INV-002"
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid) "
        "VALUES ('a', '!x', 'user', 'approved', ?)",
        (hwid,),
    )
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO users (username, password_hash, role, status, hwid) "
            "VALUES ('b', '!y', 'user', 'pending', ?)",
            (hwid,),
        )


# ══════════════════════════════════════════════════════════════════════════════
# Değişmez 2 — yeni kayıt HER ZAMAN pending, asla doğrudan approved/admin
# ══════════════════════════════════════════════════════════════════════════════


def test_yeni_kayit_daima_pending_asla_dogrudan_approved(db, kasa_dizini) -> None:
    uid = register_new_user(
        db, hwid="USB-INV-003", username="yeni", pin=_PIN, role="Standart",
    )
    row = db.fetchone("SELECT status, role FROM users WHERE id = ?", (uid,))
    assert row["status"] == "pending"
    assert row["role"] != "admin"


def test_kullanici_adi_cakismasi_ayri_hatayla_bildiriliyor(db, kasa_dizini) -> None:
    """
    Kullanıcı adı çakışması HWID çakışmasından AYRI bir hata sınıfı
    olmalı -- çağıran taraf ikisi için farklı, doğru mesaj göstermeli.
    """
    register_new_user(
        db, hwid="USB-INV-006", username="ayni-ad", pin=_PIN, role="Standart",
    )
    with pytest.raises(UsernameTakenError):
        register_new_user(
            db, hwid="USB-INV-007", username="ayni-ad", pin=_PIN, role="Standart",
        )
    # İkinci HWID'in kendisi kirlenmemiş olmalı -- reddedilen kullanıcı
    # adı yüzünden create_vault() hiç çağrılmamalı.
    assert db.fetchone(
        "SELECT id FROM users WHERE hwid = ?", ("USB-INV-007",)
    ) is None


def test_kayit_akisindan_asla_admin_uretilemez(db, kasa_dizini) -> None:
    hwid = "USB-INV-004"
    with pytest.raises(RuntimeError):
        register_new_user(
            db, hwid=hwid, username="sozde-admin", pin=_PIN, role="Yönetici",
        )
    assert db.fetchone("SELECT id FROM users WHERE hwid = ?", (hwid,)) is None


# ══════════════════════════════════════════════════════════════════════════════
# Değişmez 3 — vault + users atomik (kesinti simülasyonu)
# ══════════════════════════════════════════════════════════════════════════════


def test_kesinti_sonrasi_ne_approved_satir_ne_yarim_vault_kaliyor(
    db, kasa_dizini, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    B-061'in tam kanıtı: `users` INSERT'i başarısız olduğunda az önce
    yazılan vault geri alınmalı. Geri alınmazsa bir SONRAKİ "giriş"
    `sync_session_user()`'ın "satır yok -> approved yaz" dalını
    tetikleyip onaysız bir hesap üretir (B-058'in kök nedeniyle aynı
    sonuç, farklı tetikleyici).
    """
    hwid = "USB-INV-005"
    orijinal_execute = db.execute

    def _kesintiye_ugrayan_execute(sql, params=()):
        if "INSERT INTO users" in sql:
            raise sqlite3.OperationalError("simüle edilen kesinti (B-061)")
        return orijinal_execute(sql, params)

    monkeypatch.setattr(db, "execute", _kesintiye_ugrayan_execute)

    with pytest.raises(sqlite3.OperationalError):
        register_new_user(
            db, hwid=hwid, username="kesintili", pin=_PIN, role="Standart",
        )

    # Kesinti sonrası ne bir users satırı...
    assert db.fetchone("SELECT * FROM users WHERE hwid = ?", (hwid,)) is None
    # ...ne bir usb_tokens kaydı...
    assert db.fetchone("SELECT * FROM usb_tokens WHERE hwid = ?", (hwid,)) is None
    # ...ne de diskte bir vault dosyası kalmalı.
    vault_yolu = vault_manager._VAULT_DIR / f"{hwid}.hclv"
    assert not vault_yolu.exists(), "geri alma vault dosyasını silmedi"

    # Vault gerçekten yok: açmaya çalışmak FileNotFoundError vermeli,
    # "PIN yanlış" gibi yanıltıcı bir hataya düşmemeli.
    with pytest.raises(FileNotFoundError):
        vault_manager.open_vault(hwid, _PIN)


# ══════════════════════════════════════════════════════════════════════════════
# B-060'ın eski PoC'u — artık başarısız olmalı
# ══════════════════════════════════════════════════════════════════════════════


def test_b060_eski_hesap_devralma_poc_artik_basarisiz(db, kasa_dizini) -> None:
    """
    Eski senaryo (BACKLOG B-060): kurbanın USB'sine PIN'i bilmeden
    fiziksel erişimle "Kayıt Ol"dan yeniden kayıt olup vault'u ele
    geçirmek. Düzeltme sonrası: reddedilmeli, kurbanın PIN'i ve durumu
    DEĞİŞMEDEN kalmalı.
    """
    hwid = "VICTIM-HWID-INV"
    kurban_pin = "kurbanin-gercek-pini-99"
    register_new_user(db, hwid=hwid, username="kurban", pin=kurban_pin, role="Standart")
    db.execute("UPDATE users SET status = 'approved' WHERE hwid = ?", (hwid,))

    saldirgan_pin = "saldirganin-sectigi-pin"
    with pytest.raises(HwidAlreadyRegisteredError) as bilgi:
        register_new_user(
            db, hwid=hwid, username="saldirgan", pin=saldirgan_pin, role="Standart",
        )
    assert bilgi.value.status == "approved"

    # Vault'a HİÇ dokunulmadı: kurbanın PIN'i hâlâ çalışıyor.
    role, _ = vault_manager.open_vault(hwid, kurban_pin)
    assert role == "Standart"

    # Saldırganın PIN'i vault'u AÇMIYOR.
    with pytest.raises(ValueError):
        vault_manager.open_vault(hwid, saldirgan_pin)

    # DB'de hâlâ tek satır var ve hâlâ kurbana ait.
    satirlar = db.fetchall(
        "SELECT username, status FROM users WHERE hwid = ?", (hwid,)
    )
    assert len(satirlar) == 1
    assert satirlar[0]["username"] == "kurban"
    assert satirlar[0]["status"] == "approved"


# ══════════════════════════════════════════════════════════════════════════════
# Migration: çakışan HWID varsa sessizce atlamıyor, raporluyor
# ══════════════════════════════════════════════════════════════════════════════


def test_migration_cakisan_hwid_varsa_sessizce_atlamiyor_raporluyor() -> None:
    """
    `_m23_users_hwid_unique` çakışan bir kurulumda RuntimeError fırlatmalı
    (hangi HWID olduğunu adıyla söyleyerek) ve indeksi OLUŞTURMAMALI —
    B-060'ın canlı bir kurbanını sessizce "çözülmüş" göstermemeli.
    """
    conn = sqlite3.connect(":memory:")
    try:
        for goc in M.MIGRATIONS:
            if goc.numara <= 22:
                goc.uygula(conn)

        conn.execute(
            "INSERT INTO users (username, password_hash, role, status, hwid) "
            "VALUES ('a', '!x', 'user', 'approved', 'CAKISAN-HWID')"
        )
        conn.execute(
            "INSERT INTO users (username, password_hash, role, status, hwid) "
            "VALUES ('b', '!y', 'user', 'pending', 'CAKISAN-HWID')"
        )

        with pytest.raises(RuntimeError, match="CAKISAN-HWID"):
            M._m23_users_hwid_unique(conn)

        indeksler = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        assert "idx_users_hwid_unique" not in indeksler, (
            "çakışma varken indeks yine de oluşmuş — sessizce atlanmış olabilir"
        )
    finally:
        conn.close()


def test_migration_cakisma_YOKSA_temiz_kuruluyor() -> None:
    """Mutasyon kontrastı: çakışma yokken aynı göç sorunsuz uygulanmalı."""
    conn = sqlite3.connect(":memory:")
    try:
        for goc in M.MIGRATIONS:
            if goc.numara <= 22:
                goc.uygula(conn)

        conn.execute(
            "INSERT INTO users (username, password_hash, role, status, hwid) "
            "VALUES ('a', '!x', 'user', 'approved', 'TEMIZ-HWID-1')"
        )
        conn.execute(
            "INSERT INTO users (username, password_hash, role, status, hwid) "
            "VALUES ('b', '!y', 'user', 'pending', 'TEMIZ-HWID-2')"
        )

        M._m23_users_hwid_unique(conn)  # patlamamalı

        indeksler = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        assert "idx_users_hwid_unique" in indeksler
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# Değişmez 4 — TOTP kullanıcı başına (B-059'a bağlı, henüz uygulanmadı)
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.xfail(
    reason=(
        "B-059: TOTP sirri sistem genelinde TEK ve GLOBAL "
        "(CORE.secret_store.TOTP_USERNAME) -- kullanici basina ayri sir "
        "altyapisi henuz yok. B-059 kapanip her onayli kullanicinin KENDI "
        "TOTP sirri olunca bu test kendiliginden yesile donmeli; "
        "strict=True oldugu icin o an bu xfail isaretinin kaldirilip "
        "testin gercek bagimsizligi dogrulayacak sekilde genisletilmesi "
        "gerektigi ACIKCA gorulur (beklenmedik PASS, FAIL sayilir)."
    ),
    strict=True,
)
def test_totp_sirri_kullanici_basina_bagimsiz(db, kasa_dizini) -> None:
    import CORE.session_user as su

    register_new_user(db, hwid="USB-INV-A", username="a", pin=_PIN, role="Standart")
    register_new_user(db, hwid="USB-INV-B", username="b", pin=_PIN, role="Standart")
    db.execute(
        "UPDATE users SET status = 'approved' WHERE hwid IN ('USB-INV-A', 'USB-INV-B')"
    )

    # B-059 kapanınca beklenen: her onaylı kullanıcının KENDİ TOTP sırrını
    # okuyabilen bir API. Bugün böyle bir kavram yok — tek global
    # load_totp_secret() var, iki kullanıcının "kendi" sırrını ayırt
    # edemiyor.
    assert hasattr(su, "totp_secret_for_user"), (
        "B-059 kapandığında kullanıcı başına TOTP sırrı okuyacak bir API "
        "(örn. CORE.session_user.totp_secret_for_user) eklenmiş olmalı; "
        "bu test o zaman iki kullanıcının sırlarının GERÇEKTEN farklı "
        "olduğunu doğrulayacak şekilde genişletilmeli."
    )
