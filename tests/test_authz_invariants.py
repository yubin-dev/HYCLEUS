"""
HYCLEUS — kayıt/kimlik katmanının yetkilendirme DEĞİŞMEZLERİ (B-060/061)

B-058 sınıfı bir tarama (BACKLOG B-060/B-061) şunu buldu: kayıt akışı
"bu HWID zaten var mı" sorusunu hiç sormuyordu ve `create_vault()` ile
`users` INSERT'i atomik değildi. İkisi de aynı sonuca çıkıyordu: hiç
onaylanmamış bir kullanıcı `status='approved'` ile sisteme giriyordu.

B-059 (ayrı bir tarama turunda bulundu): TOTP sırrı paylaşılan/global bir
keyring kaydıydı — herhangi bir kullanıcı başka bir kullanıcının 2FA
kodunu üretebiliyordu. Bu dosya o düzeltmenin de değişmezini sabitliyor:
her HWID kendi TOTP sırrına sahip, göç eski global sırrı sessizce
kaybetmiyor.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pyotp
import pytest

from CORE import secret_migration, secret_store, vault_manager
from CORE.registration import (
    HwidAlreadyRegisteredError,
    UsernameTakenError,
    register_new_user,
)
from CORE.session_user import kullanici_bilgisi, sync_session_user
from CORE.vault_manager import create_vault
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
    sonuc = register_new_user(
        db, hwid="USB-INV-003", username="yeni", pin=_PIN, role="Standart",
    )
    row = db.fetchone("SELECT status, role FROM users WHERE id = ?", (sonuc.user_id,))
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
# Değişmez 4 — TOTP HWID başına, göç eski sırrı sessizce kaybetmiyor (B-059)
# ══════════════════════════════════════════════════════════════════════════════


def test_totp_sirri_iki_kullanici_arasinda_bagimsiz(db, kasa_dizini) -> None:
    """
    B-059'un tam kanıtı: iki farklı kayıt, iki farklı TOTP sırrı alıyor
    ve biri diğerinin kodunu DOĞRULAYAMIYOR.
    """
    sonuc_a = register_new_user(
        db, hwid="USB-INV-A", username="a", pin=_PIN, role="Standart",
    )
    sonuc_b = register_new_user(
        db, hwid="USB-INV-B", username="b", pin=_PIN, role="Standart",
    )

    assert sonuc_a.totp_secret != sonuc_b.totp_secret

    kod_a = pyotp.TOTP(sonuc_a.totp_secret).now()
    assert pyotp.TOTP(sonuc_a.totp_secret).verify(kod_a, valid_window=1)
    # A'nın kodu B'nin sırrıyla DOĞRULANMIYOR -- eskiden (global sır)
    # bu satır AssertionError verirdi, çünkü ikisi de AYNI sırra sahipti.
    assert not pyotp.TOTP(sonuc_b.totp_secret).verify(kod_a, valid_window=1)

    # Kasadan okunan da tutarlı ve birbirinden bağımsız.
    assert secret_store.load_totp_secret_for_hwid("USB-INV-A") == sonuc_a.totp_secret
    assert secret_store.load_totp_secret_for_hwid("USB-INV-B") == sonuc_b.totp_secret


def test_migration_eski_global_sir_ilk_onayli_kullaniciya_devrediyor(
    db, kasa_dizini,
) -> None:
    """
    Göç sonrası var olan (ilk/en eski) onaylı kullanıcı HÂLÂ giriş
    yapabiliyor mu: eski global sırrı devralan HWID'in TOTP kodu hâlâ
    doğrulanabiliyor olmalı — authenticator uygulamasını yeniden
    taramasına gerek yok.
    """
    create_vault("USB-MIG-ILK", _PIN, "Standart")
    create_vault("USB-MIG-IKINCI", _PIN, "Standart")
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid) "
        "VALUES ('ilk_admin', '!x', 'admin', 'approved', 'USB-MIG-ILK')"
    )
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid) "
        "VALUES ('ikinci_kullanici', '!y', 'user', 'approved', 'USB-MIG-IKINCI')"
    )

    eski_global_sir = pyotp.random_base32()
    secret_store.store_totp_secret(eski_global_sir)
    secret_migration.set_schema_version(db, secret_migration.SCHEMA_TOTP)

    rapor = secret_migration.run_migrations(db)

    assert rapor.ran
    assert rapor.to_version == secret_migration.CURRENT_SCHEMA_VERSION
    assert rapor.totp_per_hwid_migrated_to == "USB-MIG-ILK"

    # İlk onaylı kullanıcı KESİNTİSİZ çalışmaya devam ediyor: eski kodu
    # hâlâ doğrulanıyor.
    eski_kod = pyotp.TOTP(eski_global_sir).now()
    devralinan_sir = secret_store.load_totp_secret_for_hwid("USB-MIG-ILK")
    assert devralinan_sir == eski_global_sir
    assert pyotp.TOTP(devralinan_sir).verify(eski_kod, valid_window=1)

    # Global kayıt artık YOK -- ikinci bir sızıntı/kafa karışıklığı yok.
    assert secret_store.load_totp_secret() is None


def test_migration_digerleri_yeniden_enrollment_gerektiriyor_sessizce_degil(
    db, kasa_dizini,
) -> None:
    """
    İlk onaylı kullanıcı DIŞINDAKİLER göç sonrası kendi TOTP kaydına sahip
    DEĞİL — ama bu SESSİZCE olmuyor: rapor kimin etkilendiğini söylüyor.
    """
    create_vault("USB-MIG-ILK-2", _PIN, "Standart")
    create_vault("USB-MIG-DIGER", _PIN, "Standart")
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid) "
        "VALUES ('ilk_admin', '!x', 'admin', 'approved', 'USB-MIG-ILK-2')"
    )
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid) "
        "VALUES ('digeri', '!y', 'user', 'approved', 'USB-MIG-DIGER')"
    )
    secret_store.store_totp_secret(pyotp.random_base32())
    secret_migration.set_schema_version(db, secret_migration.SCHEMA_TOTP)

    rapor = secret_migration.run_migrations(db)

    # "digeri" kendi TOTP kaydına sahip DEĞİL -- yeniden enrollment gerekiyor.
    assert secret_store.load_totp_secret_for_hwid("USB-MIG-DIGER") is None
    # Bu durum rapora (ve main.py üzerinden audit_log'a) SESSİZCE geçmiyor.
    assert any("digeri" in not_ for not_ in rapor.notes), rapor.notes


def test_migration_onayli_kullanici_yokken_sir_kimseye_devredilmeden_silinir(
    db, kasa_dizini,
) -> None:
    """
    Mutasyon kontrastı: onaylı hiç kullanıcı yoksa (teorik olarak olmamalı
    ama savunma derinliği) göç sessizce takılıp kalmıyor, sırrı silip
    uyarıyor.
    """
    secret_store.store_totp_secret(pyotp.random_base32())
    secret_migration.set_schema_version(db, secret_migration.SCHEMA_TOTP)

    rapor = secret_migration.run_migrations(db)

    assert rapor.totp_per_hwid_migrated_to is None
    assert secret_store.load_totp_secret() is None
    assert any("kimseye devredilemedi" in n for n in rapor.notes)


def test_migration_global_sir_YOKSA_hicbir_sey_yapmiyor(db, kasa_dizini) -> None:
    """Mutasyon kontrastı: taşınacak eski sır yoksa göç sorunsuz geçmeli."""
    secret_migration.set_schema_version(db, secret_migration.SCHEMA_TOTP)

    rapor = secret_migration.run_migrations(db)

    assert rapor.to_version == secret_migration.CURRENT_SCHEMA_VERSION
    assert rapor.totp_per_hwid_migrated_to is None


# ══════════════════════════════════════════════════════════════════════════════
# Değişmez 5 — açık oturum DB'deki GERÇEK yetkiyle uyumsuz kalamaz (B-064/B-066)
# ══════════════════════════════════════════════════════════════════════════════
#
# B-064: `AdminPanel` application-modal bir QDialog (`.exec()`) — ana
# penceredeki `_lock()` yalnızca `centralWidget()`'ı etkiliyor, paneli
# HABERSİZ bırakıyor. USB Yönetimi paneli AÇIKKEN yönetici USB'si fiziksel
# olarak çekilirse, eskiden panel hiçbir kontrol yapmadan yetkili DB
# yazılarına (onayla/reddet/rol değiştir/sil/kara listeye al/...) devam
# ediyordu.
#
# B-066: `_poll_usb()` yalnızca "HWID DEĞİŞTİ mi" sorusunu soruyordu. Aynı
# fiziksel USB takılı kaldığı sürece (fiziksel olarak hiç çıkarılmadıysa),
# DB'de rol/durum/kara-liste değişse bile açık oturum ESKİ yetkiyle
# çalışmaya devam ediyordu.
#
# İkisi de aynı kök nedenin (oturum, gerçek zamanlı DB yetkisini hiç
# yeniden doğrulamıyor) iki yüzü — düzeltme tek ortak fonksiyonda:
# `CORE.session_user.oturum_yetkisi_gecerli_mi()`.
#
# Bu iki test PoC scriptleriyle (scratchpad) DEĞİL, gerçek `AdminPanel` /
# `HycleusWindow` sınıflarıyla çalışıyor ve ikisi de mutasyonla doğrulandı:
# ilgili `_yonetici_hala_yetkili()` / `oturum_yetkisi_gecerli_mi()` çağrısı
# geçici olarak devre dışı bırakılıp testin GERÇEKTEN düştüğü görüldü,
# sonra geri getirildi.


def test_b064_admin_paneli_usb_cikinca_onayi_reddediyor(
    db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Panel AÇIKKEN USB fiziksel olarak çekiliyor (aynı süreç, main_window
    kilidinden habersiz bir modal). `_on_approve()` artık DB'ye hiç
    dokunmamalı ve paneli kendisi kapatmalı — düğmenin devre dışı kalması
    değil, handler'ın kendisi son çare.
    """
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

        import UI.AdminPanel as ap
    except ImportError as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"Qt katmanı bu ortamda yüklenemedi ({exc})")

    try:
        QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")

    admin_hwid = "B064-ADMIN-HWID"
    pending_hwid = "B064-PENDING-HWID"
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, 'admin', 'approved', ?)",
        ("panel-admin", "x", admin_hwid),
    )
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, 'user', 'pending', ?)",
        ("bekleyen.kullanici", "x", pending_hwid),
    )

    for ad in ("question", "information", "warning", "critical"):
        monkeypatch.setattr(
            QMessageBox, ad, staticmethod(lambda *a, **k: QMessageBox.Yes)
        )

    # Panel USB HÂLÂ TAKILIYKEN açılıyor.
    monkeypatch.setattr(ap, "get_usb_hwid", lambda: admin_hwid)
    panel = ap.AdminPanel(current_hwid=admin_hwid, role="Yönetici")
    panel._load_pending()
    panel._pending_table.selectRow(0)

    # USB fiziksel olarak çekiliyor. Panel modal olduğu için ana
    # penceredeki _lock() ondan HABERSİZ — hiçbir şey paneli kapatmaz.
    monkeypatch.setattr(ap, "get_usb_hwid", lambda: None)

    panel._on_approve()

    row = db.fetchone("SELECT status FROM users WHERE hwid = ?", (pending_hwid,))
    assert row["status"] == "pending", (
        "B-064 REGRESYONU: USB çekiliyken AdminPanel yetkili bir DB "
        "yazısını (onayla) yine de tamamladı"
    )
    assert panel.result() == QDialog.Rejected, (
        "B-064 REGRESYONU: panel, USB çekilince kendini kapatmadı"
    )
    panel._yetki_timer.stop()
    panel.close()


def test_b064_guard_kaldirilirsa_test_gercekten_dusuyor(
    db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Mutasyon kontrastı — yukarıdaki testin gerçekten bir şey ölçtüğünü
    kanıtlar: `_yonetici_hala_yetkili()` devre dışı bırakılırsa (eski,
    savunmasız davranış simüle edilirse) aynı senaryo GERÇEKTEN onaylanır.
    """
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox

        import UI.AdminPanel as ap
    except ImportError as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"Qt katmanı bu ortamda yüklenemedi ({exc})")

    try:
        QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")

    admin_hwid = "B064-MUTASYON-ADMIN-HWID"
    pending_hwid = "B064-MUTASYON-PENDING-HWID"
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, 'admin', 'approved', ?)",
        ("panel-admin-2", "x", admin_hwid),
    )
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, 'user', 'pending', ?)",
        ("bekleyen.kullanici.2", "x", pending_hwid),
    )

    for ad in ("question", "information", "warning", "critical"):
        monkeypatch.setattr(
            QMessageBox, ad, staticmethod(lambda *a, **k: QMessageBox.Yes)
        )

    monkeypatch.setattr(ap, "get_usb_hwid", lambda: admin_hwid)
    panel = ap.AdminPanel(current_hwid=admin_hwid, role="Yönetici")
    panel._load_pending()
    panel._pending_table.selectRow(0)

    # Eski (savunmasız) davranışı simüle et: guard'ı devre dışı bırak.
    monkeypatch.setattr(panel, "_yonetici_hala_yetkili", lambda: True)
    monkeypatch.setattr(ap, "get_usb_hwid", lambda: None)

    panel._on_approve()

    row = db.fetchone("SELECT status FROM users WHERE hwid = ?", (pending_hwid,))
    assert row["status"] == "approved", (
        "guard devre dışıyken bile onay engellendi — bu test B-064'ü "
        "gerçekten ölçmüyor olabilir"
    )
    panel._yetki_timer.stop()
    panel.close()


def test_b066_rol_dusurulunce_ayni_usb_takiliyken_oturum_kilitleniyor(
    db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    USB HİÇ ÇIKARILMIYOR (fiziksel olarak aynı cihaz takılı kalıyor). DB'de
    rol admin'den user'a düşürülünce `_poll_usb()` (gerçek 3 sn'lik
    zamanlayıcı kodu) oturumu kilitlemeli — HWID hâlâ aynı diye sessiz
    kalmamalı.
    """
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication, QWidget

        import UI.main_window_lock as main_window_lock
        from UI.main_window import HycleusWindow
        from UI.main_window_lock import _LockOverlay
    except ImportError as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"Qt katmanı bu ortamda yüklenemedi ({exc})")

    try:
        QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")

    hwid = "B066-STALE-ROLE-HWID"
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, 'admin', 'approved', ?)",
        ("dusurulen.admin", "x", hwid),
    )

    monkeypatch.setattr(main_window_lock, "get_usb_hwid", lambda: hwid)

    class _Sahne:
        _LOCK_MESSAGES = HycleusWindow._LOCK_MESSAGES
        _lock = HycleusWindow._lock
        _unlock = HycleusWindow._unlock
        _poll_usb = HycleusWindow._poll_usb
        _refresh_usb_badge = HycleusWindow._refresh_usb_badge

        def __init__(self) -> None:
            self._central = QWidget()
            self._central.resize(800, 600)
            self._overlay = _LockOverlay(self._central)
            self._blur = None
            self._locked = False
            self._lock_reasons: set[str] = set()
            self._authenticating = False
            self._hwid = hwid
            self._role = "admin"
            self._usb_badge = QWidget()
            self._usb_badge.setText = lambda *a, **k: None
            self._checkouts = None

        def centralWidget(self):
            return self._central

        def size(self):
            return self._central.size()

    sahne = _Sahne()
    sahne._poll_usb()
    assert sahne._locked is False, "USB hâlâ takılı ve rol henüz düşmedi"

    # Başka bir yerden (ör. ikinci bir AdminPanel) rol DB'de düşürülüyor.
    # USB HİÇ ÇIKARILMIYOR — aynı fiziksel cihaz.
    db.execute("UPDATE users SET role = 'user' WHERE hwid = ?", (hwid,))

    sahne._poll_usb()

    assert sahne._locked is True, (
        "B-066 REGRESYONU: DB'de rol düştüğü hâlde, aynı fiziksel USB "
        "takılıyken açık oturum kilitlenmedi"
    )
    assert "revoked" in sahne._lock_reasons


def test_b066_guard_kaldirilirsa_test_gercekten_dusuyor(
    db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Mutasyon kontrastı — `oturum_yetkisi_gecerli_mi()` çağrısı `_poll_usb`
    içinde devre dışı bırakılırsa (eski davranış: yalnızca HWID eşitliği)
    aynı senaryoda oturum GERÇEKTEN kilitlenmeden kalır.
    """
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication, QWidget

        import UI.main_window_lock as main_window_lock
        from UI.main_window import HycleusWindow
        from UI.main_window_lock import _LockOverlay
    except ImportError as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"Qt katmanı bu ortamda yüklenemedi ({exc})")

    try:
        QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")

    hwid = "B066-MUTASYON-HWID"
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, 'admin', 'approved', ?)",
        ("dusurulen.admin.2", "x", hwid),
    )

    monkeypatch.setattr(main_window_lock, "get_usb_hwid", lambda: hwid)
    # Eski (savunmasız) davranışı simüle et: DB'yi hiç yeniden okuma.
    monkeypatch.setattr(
        main_window_lock, "oturum_yetkisi_gecerli_mi", lambda *a, **k: (True, "")
    )

    class _Sahne:
        _LOCK_MESSAGES = HycleusWindow._LOCK_MESSAGES
        _lock = HycleusWindow._lock
        _unlock = HycleusWindow._unlock
        _poll_usb = HycleusWindow._poll_usb
        _refresh_usb_badge = HycleusWindow._refresh_usb_badge

        def __init__(self) -> None:
            self._central = QWidget()
            self._central.resize(800, 600)
            self._overlay = _LockOverlay(self._central)
            self._blur = None
            self._locked = False
            self._lock_reasons: set[str] = set()
            self._authenticating = False
            self._hwid = hwid
            self._role = "admin"
            self._usb_badge = QWidget()
            self._usb_badge.setText = lambda *a, **k: None
            self._checkouts = None

        def centralWidget(self):
            return self._central

        def size(self):
            return self._central.size()

    sahne = _Sahne()
    sahne._poll_usb()
    db.execute("UPDATE users SET role = 'user' WHERE hwid = ?", (hwid,))

    sahne._poll_usb()

    assert sahne._locked is False, (
        "guard devre dışıyken bile oturum kilitlendi — bu test B-066'yı "
        "gerçekten ölçmüyor olabilir"
    )


# ══════════════════════════════════════════════════════════════════════════════
# Değişmez 6 — ekrandaki "kullanıcı adı" gerçek doğrulanmış kullanıcıyı
# yansıtıyor (B-065)
# ══════════════════════════════════════════════════════════════════════════════
#
# main.py, HycleusWindow'u açarken `username=` hiç geçmiyordu — sabit
# varsayılan "Kullanıcı" her oturumda kalıyordu, gerçek DB adı ne olursa
# olsun. `_trigger_usb_reauth()` (main_window_lock.py) de farklı bir USB
# ile yeniden giriş yapılınca `_hwid`/`_role`'ü güncelliyordu ama
# `_username`/`_user_id`'e hiç dokunmuyordu — reauth sonrası Profil ekranı
# ve avatar ESKİ kullanıcıyı göstermeye devam ediyordu.
#
# main.py ve `_trigger_usb_reauth()` artık AYNI iki fonksiyonu kullanıyor
# (`sync_session_user()` + `kullanici_bilgisi()`) — ikinci bir okuma yolu
# İCAT EDİLMEDİ.

_KEY_B065 = b"K" * 32


@pytest.fixture
def isolate_safezone_b065(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from CORE.safezone import SAFEZONE_ENV_VAR

    hedef = tmp_path / "safezone"
    monkeypatch.setenv(SAFEZONE_ENV_VAR, str(hedef))
    return hedef


def _b065_kullanici_kur(
    db, kasa_dizini, hwid: str, username: str, role: str,
) -> tuple[int, str]:
    """
    main.py'nin YENİ mantığını birebir uygular: `sync_session_user()` +
    `kullanici_bilgisi()`. Test main.py'yi (tam GUI akışı — LoginDialog
    vb.) ÇALIŞTIRMIYOR, ama main.py'nin kullanıcı adını DB'den türettiği
    İKİ fonksiyonu birebir kullanıyor — yani gerçek kod yolu ölçülüyor.
    """
    from CORE.roles import db_role

    create_vault(hwid, _PIN, role)
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, ?, 'approved', ?)",
        (username, "!x", db_role(role), hwid),
    )
    user_id = sync_session_user(db, hwid=hwid, role=role)
    bilgi = kullanici_bilgisi(db, hwid)
    assert bilgi is not None
    return user_id, bilgi[1]


def test_b065_profil_ve_avatar_iki_farkli_kullanicida_gercek_db_adini_gosteriyor(
    db, kasa_dizini, isolate_safezone_b065, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    İki farklı kullanıcı sırayla "giriş yapıyor" (main.py'nin yeni
    türetme mantığıyla): her ikisinde de Profil ekranı ve avatar baş
    harfi KENDİ gerçek DB adını göstermeli — sabit bir varsayılana
    düşmemeli, birinin adı diğerinde kalmamalı.
    """
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication, QLabel

        import UI.main_window as mw
        from UI.main_window import HycleusWindow
        from UI.ProfileView import ProfileView
    except ImportError as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"Qt katmanı bu ortamda yüklenemedi ({exc})")
    try:
        QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")

    kullanicilar = (
        ("B065-HWID-A", "ayse.yilmaz", "Yönetici"),
        ("B065-HWID-B", "mehmet.demir", "Standart"),
    )

    for hwid, ad, rol in kullanicilar:
        user_id, gercek_ad = _b065_kullanici_kur(db, kasa_dizini, hwid, ad, rol)
        assert gercek_ad == ad  # kurulumun kendisi doğru mu

        monkeypatch.setattr(mw, "get_usb_hwid", lambda h=hwid: h)
        window = HycleusWindow(
            hwid=hwid, key=_KEY_B065, role=rol, username=gercek_ad, user_id=user_id,
        )
        try:
            assert window._avatar.text() == ad[0].upper(), (
                f"B-065 REGRESYONU: avatar '{ad}' yerine "
                f"{window._avatar.text()!r} gösteriyor"
            )

            profil = ProfileView(window)
            try:
                ad_etiketi = profil.findChild(QLabel, "user_name")
                avatar_etiketi = profil.findChild(QLabel, "avatar_lbl")
                assert ad_etiketi.text() == ad, (
                    f"B-065 REGRESYONU: Profil sayfası '{ad}' yerine "
                    f"{ad_etiketi.text()!r} gösteriyor"
                )
                assert avatar_etiketi.text() == ad[0].upper()
            finally:
                profil.close()
        finally:
            for zamanlayici in ("_usb_timer", "_expiry_timer", "_idle_timer"):
                t = getattr(window, zamanlayici, None)
                if t is not None:
                    t.stop()
            QApplication.instance().removeEventFilter(window)
            window.close()


def test_b065_reauth_sonrasi_kullanici_adi_ve_avatar_guncelleniyor(
    db, kasa_dizini, isolate_safezone_b065, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Aynı süreçte, farklı bir USB ile yeniden giriş (`_trigger_usb_reauth`)
    yapılınca `_username`/`_user_id` YENİ kullanıcıya güncellenmeli —
    ve bu, ekrandaki avatar widget'ına da (üretim kodundaki
    `_apply_theme()` çağrısı üzerinden) otomatik yansımalı; ayrıca
    dokunmaya gerek olmamalı.
    """
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import (
            QApplication, QInputDialog, QMessageBox,
        )

        import UI.main_window as mw
        from UI.main_window import HycleusWindow
    except ImportError as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"Qt katmanı bu ortamda yüklenemedi ({exc})")
    try:
        QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")

    hwid_a, ad_a = "B065-REAUTH-HWID-A", "kadir.oz"
    hwid_b, ad_b = "B065-REAUTH-HWID-B", "elif.kaya"

    user_id_a, gercek_ad_a = _b065_kullanici_kur(db, kasa_dizini, hwid_a, ad_a, "Yönetici")
    user_id_b, gercek_ad_b = _b065_kullanici_kur(db, kasa_dizini, hwid_b, ad_b, "Standart")

    monkeypatch.setattr(mw, "get_usb_hwid", lambda: hwid_a)
    window = HycleusWindow(
        hwid=hwid_a, key=_KEY_B065, role="Yönetici",
        username=gercek_ad_a, user_id=user_id_a,
    )
    try:
        assert window._username == gercek_ad_a
        assert window._avatar.text() == gercek_ad_a[0].upper()

        monkeypatch.setattr(
            QInputDialog, "getText", staticmethod(lambda *a, **k: (_PIN, True))
        )
        for ad_metodu in ("information", "warning", "critical"):
            monkeypatch.setattr(
                QMessageBox, ad_metodu, staticmethod(lambda *a, **k: None)
            )

        window._trigger_usb_reauth(hwid_b)

        assert window._hwid == hwid_b, "reauth HWID'i güncellemedi"
        assert not window._locked, "reauth başarılı oldu ama oturum kilitli kaldı"
        assert window._username == gercek_ad_b, (
            "B-065 REGRESYONU: reauth sonrası _username ESKİ kullanıcıda kaldı"
        )
        assert window._user_id == user_id_b, (
            "B-065 REGRESYONU: reauth sonrası _user_id ESKİ kullanıcıda kaldı"
        )
        assert window._avatar.text() == gercek_ad_b[0].upper(), (
            "B-065 REGRESYONU: reauth sonrası avatar widget'ı güncellenmedi"
        )
    finally:
        for zamanlayici in ("_usb_timer", "_expiry_timer", "_idle_timer"):
            t = getattr(window, zamanlayici, None)
            if t is not None:
                t.stop()
        QApplication.instance().removeEventFilter(window)
        window.close()
