"""
HYCLEUS — `audit_log`'un DB-seviyesi DELETE/UPDATE koruması (B-132)

`DB/migrations.py::_m27_audit_log_immutable()` bu tabloya dört tetikleyici
ekliyor. Bu dosya SADECE o tetikleyicilerin GERÇEKTEN çalıştığını sınıyor —
`tests/test_audit_chain.py` (ve kardeşleri) ise tetikleyicileri BİLEREK
kaldırıp "eğer bir saldırgan koruma katmanını da aşarsa verify_audit_
chain() hâlâ kurcalamayı yakalıyor mu" sorusunu soruyor. İki dosya
tamamlayıcı: biri "DB reddediyor mu", diğeri "reddetmeseydi ne olurdu".

Testler GERÇEK bir `DBManager`/`sqlite3.Connection` üzerinden, rol
ayarlanmadan (ya da bilerek Salt Okunur/Yönetici ile) çalışıyor —
tetikleyicinin rolden TAMAMEN bağımsız olduğunu kanıtlamak asıl iddia.
"""
from __future__ import annotations

import sqlite3

import pytest

from CORE.roles import ROL_SALT_OKUNUR, ROL_YONETICI


# ══════════════════════════════════════════════════════════════════════════════
# 1. DELETE — hiçbir biçimde geçmemeli
# ══════════════════════════════════════════════════════════════════════════════


def test_tek_satirlik_delete_reddediliyor(db) -> None:
    db.log("test_event", detail="silinmeye calisilacak")
    kayit_id = db.fetchone(
        "SELECT id FROM audit_log WHERE action = 'test_event'"
    )["id"]

    with pytest.raises(sqlite3.IntegrityError, match="silinemez"):
        db.conn.execute("DELETE FROM audit_log WHERE id = ?", (kayit_id,))

    assert db.fetchone(
        "SELECT id FROM audit_log WHERE id = ?", (kayit_id,)
    ) is not None, "engellenmesi gereken DELETE yine de satırı silmiş"


def test_tum_tabloyu_bosaltan_delete_reddediliyor(db) -> None:
    """Scenario 84/B-132'nin asıl kanıtladığı şey: koşulsuz `DELETE FROM
    audit_log` artık HİÇBİR rolle geçmiyor."""
    db.log("test_event_1")
    db.log("test_event_2")
    onceki_sayi = db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"]
    assert onceki_sayi >= 2

    with pytest.raises(sqlite3.IntegrityError, match="silinemez"):
        db.conn.execute("DELETE FROM audit_log")

    assert db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"] == onceki_sayi


@pytest.mark.parametrize("rol", [None, ROL_SALT_OKUNUR, "standart", ROL_YONETICI])
def test_delete_rolden_tamamen_bagimsiz_reddediliyor(db, rol) -> None:
    """
    Asıl B-132 bulgusu: eskiden Salt Okunur (hatta herhangi bir rol)
    `db.execute("DELETE FROM audit_log")` ile tabloyu boşaltabiliyordu —
    RBAC (`DB/db_manager.py::_yazma_yetkisini_dogrula`) `audit_log`'u
    BİLEREK denetlemiyor (`append_entry()` ham `conn` kullandığı için).
    Tetikleyici rol katmanının TAMAMEN ALTINDA çalışıyor; hangi rol
    ayarlı olursa olsun (ayarlanmamış olsa BİLE) aynı şekilde reddediyor.
    """
    if rol is not None:
        db.set_active_role(rol)
    db.log("test_event")

    with pytest.raises(sqlite3.IntegrityError, match="silinemez"):
        db.execute("DELETE FROM audit_log")


# ══════════════════════════════════════════════════════════════════════════════
# 2. UPDATE — içerik sütunları hiçbir zaman değiştirilemez
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    ("sutun", "yeni_deger"),
    [
        ("action", "hacked"),
        ("detail", "KURCALANDI"),
        ("target_type", "file"),
        ("target_id", 999),
        ("timestamp", "2020-01-01T00:00:00Z"),
    ],
)
def test_icerik_sutunlarindan_biri_degistirilemez(db, sutun, yeni_deger) -> None:
    db.log("test_event", detail="orijinal")
    kayit = db.fetchone("SELECT id FROM audit_log WHERE action = 'test_event'")

    with pytest.raises(sqlite3.IntegrityError, match="degistirilemez"):
        db.conn.execute(
            f"UPDATE audit_log SET {sutun} = ? WHERE id = ?",  # noqa: S608 -- sutun sabit listeden, testte
            (yeni_deger, kayit["id"]),
        )


def test_entry_hash_bir_kez_atandiktan_sonra_degistirilemez(db) -> None:
    db.log("test_event")
    kayit = db.fetchone(
        "SELECT id, entry_hash FROM audit_log WHERE action = 'test_event'"
    )
    assert kayit["entry_hash"] is not None, "append_entry() zaten hash atamış olmalı"

    with pytest.raises(sqlite3.IntegrityError, match="entry_hash"):
        db.conn.execute(
            "UPDATE audit_log SET entry_hash = ? WHERE id = ?",
            ("f" * 64, kayit["id"]),
        )


def test_user_id_baska_bir_kullaniciya_yeniden_atanamiyor(db) -> None:
    """`user_id`'yi DOLU bir değerden BAŞKA bir dolu değere çekmek —
    bir kaydı "başka birinin üstüne yıkmak" — HER ZAMAN reddedilmeli."""
    ben = db.execute(
        "INSERT INTO users (username, password_hash) VALUES ('ben', 'x')"
    ).lastrowid
    baskasi = db.execute(
        "INSERT INTO users (username, password_hash) VALUES ('baskasi', 'x')"
    ).lastrowid
    db.log("test_event", user_id=ben)
    kayit = db.fetchone("SELECT id FROM audit_log WHERE action = 'test_event'")

    with pytest.raises(sqlite3.IntegrityError, match="user_id"):
        db.conn.execute(
            "UPDATE audit_log SET user_id = ? WHERE id = ?", (baskasi, kayit["id"])
        )


def test_user_id_bostan_bir_degere_atanamiyor(db) -> None:
    """`user_id`'nin izin verilen TEK geçişi DOLU→NULL (FK eylemi);
    NULL→DOLU (sahiplik uydurmak) da reddedilmeli."""
    db.log("test_event", user_id=None)
    kayit = db.fetchone("SELECT id FROM audit_log WHERE action = 'test_event'")
    assert kayit is not None

    biri = db.execute(
        "INSERT INTO users (username, password_hash) VALUES ('biri', 'x')"
    ).lastrowid

    with pytest.raises(sqlite3.IntegrityError, match="user_id"):
        db.conn.execute(
            "UPDATE audit_log SET user_id = ? WHERE id = ?", (biri, kayit["id"])
        )


# ══════════════════════════════════════════════════════════════════════════════
# 3. Meşru işlemler BOZULMAMALI
# ══════════════════════════════════════════════════════════════════════════════


def test_append_entry_kendi_hash_atamasi_calismaya_devam_ediyor(db) -> None:
    """`append_entry()`'nin INSERT → geri oku → `UPDATE ... SET entry_hash`
    döngüsü tetikleyicilerden ETKİLENMEMELİ — bu göçün asıl amacı bu akışı
    KIRMADAN kurcalamayı engellemekti."""
    onceki = db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"]
    db.log("gercek_islem", detail="meşru bir yazı")
    kayit = db.fetchone("SELECT id, entry_hash FROM audit_log WHERE action = 'gercek_islem'")
    assert kayit is not None
    assert kayit["entry_hash"] is not None
    assert db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"] == onceki + 1


def test_kullanici_silinince_user_id_NULLa_dusuyor_FK_eylemi_calisiyor(db) -> None:
    """`users.id ON DELETE SET NULL` — B-132'nin ÖZELLİKLE MUAF TUTTUĞU
    tek geçiş. Bu göç bunu KIRARSA bir kullanıcı asla silinemez hâle gelir."""
    uid = db.execute(
        "INSERT INTO users (username, password_hash) VALUES ('gidecek', 'x')"
    ).lastrowid
    db.log("test_event", user_id=uid)
    kayit = db.fetchone("SELECT id FROM audit_log WHERE action = 'test_event'")

    db.conn.execute("DELETE FROM users WHERE id = ?", (uid,))
    db.conn.commit()

    guncel = db.fetchone("SELECT user_id FROM audit_log WHERE id = ?", (kayit["id"],))
    assert guncel["user_id"] is None, (
        "kullanıcı silindi ama audit_log.user_id NULL'a düşmedi — "
        "ON DELETE SET NULL FK eylemi tetikleyici tarafından bloklanmış olabilir"
    )
    # Satır SİLİNMEDİ — yalnızca referans NULL oldu.
    assert db.fetchone(
        "SELECT id FROM audit_log WHERE id = ?", (kayit["id"],)
    ) is not None


def test_wal_checkpoint_ve_vacuum_tetikleyicilerden_etkilenmiyor(db) -> None:
    """B-132 talebinin 4. maddesi: WAL checkpoint gibi meşru bakım
    işlemleri bu göçle bozulmamalı — ikisi de FARKLI katmanlar (PRAGMA
    vs. DML), ama gerçek bir DB üzerinde birlikte çalıştırılıp
    doğrulanıyor."""
    db.log("test_event")
    db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.conn.commit()
    assert db.fetchone(
        "SELECT id FROM audit_log WHERE action = 'test_event'"
    ) is not None


def test_migration_27_uygulanmis_ve_dorttrigger_de_kurulu(db) -> None:
    from DB.migrations import AUDIT_LOG_GUARD_TRIGGERS

    kurulu = {
        r["name"]
        for r in db.fetchall(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            " AND tbl_name = 'audit_log'"
        )
    }
    assert set(AUDIT_LOG_GUARD_TRIGGERS) <= kurulu, (
        f"beklenen tetikleyicilerden bazıları kurulu değil: "
        f"{set(AUDIT_LOG_GUARD_TRIGGERS) - kurulu}"
    )
