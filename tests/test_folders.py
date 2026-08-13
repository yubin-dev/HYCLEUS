"""
HYCLEUS — Klasör işlemleri testleri

Bu mantık `UI/main_window.py` içinde satır içi yazılıydı ve Qt olmadan
çalıştırılamadığı için test edilmemişti.

Denetim kaydı detaylarının ALAN SIRASI da sınanıyor: kayıtlar geriye dönük
ayrıştırılabilir olmalı, dolayısıyla biçim taşıma sırasında değişmemeli.
"""
from __future__ import annotations

import pytest

from CORE.audit_chain import verify_audit_chain
from CORE.expiry import parse_expires_at
from CORE.folders import (
    FolderInfo,
    assign_file_to_folder,
    create_folder,
    delete_folder,
    ensure_owner_exists,
    list_folders,
    move_folder_to_imha,
)

_HWID = "TEST-HWID"


def _add_user(db, user_id: int = 1) -> int:
    db.execute(
        "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
        (user_id, f"kullanici{user_id}", "argon2$sahte"),
    )
    return user_id


def _add_file(db, name: str, *, folder_id: int | None = None, label: str = "Genel") -> int:
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label, folder_id) VALUES (?,?,?,?)",
        (name, f"/vault/{name}.hcl", label, folder_id),
    )
    return int(cur.lastrowid)


def _detail(db, action: str) -> str:
    return db.fetchone(
        "SELECT detail FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1",
        (action,),
    )["detail"]


# ══════════════════════════════════════════════════════════════════════════════
# 1. Oluşturma
# ══════════════════════════════════════════════════════════════════════════════


def test_create_returns_the_new_id(db):
    uid = _add_user(db)
    fid = create_folder(db, "Sozlesmeler", owner_id=uid, hwid=_HWID)
    row = db.fetchone("SELECT name, owner_id FROM folders WHERE id = ?", (fid,))
    assert row["name"] == "Sozlesmeler"
    assert row["owner_id"] == uid


def test_create_strips_the_name(db):
    uid = _add_user(db)
    fid = create_folder(db, "   Bosluklu   ", owner_id=uid)
    assert db.fetchone("SELECT name FROM folders WHERE id = ?", (fid,))["name"] == "Bosluklu"


def test_create_is_audited(db):
    uid = _add_user(db)
    create_folder(db, "Yeni", owner_id=uid, hwid=_HWID)
    detail = _detail(db, "folder_created")
    assert "name=Yeni" in detail
    assert f"hwid={_HWID}" in detail


def test_create_writes_a_placeholder_user_when_missing(db):
    """
    KORUNAN DAVRANIŞ — eksik `users` satırı uydurulup yazılıyor.

    folders.owner_id yabancı anahtarı yüzünden, DEV_MODE'da ya da users
    satırı hiç yazılmamış bir oturumda klasör oluşturma FK hatasıyla
    düşerdi. Mevcut kaçamak olduğu gibi taşındı — bkz. BACKLOG B-011.
    """
    assert db.fetchone("SELECT id FROM users WHERE id = 7") is None
    create_folder(db, "Klasor", owner_id=7, hwid=_HWID)

    row = db.fetchone("SELECT username, role, password_hash FROM users WHERE id = 7")
    assert row is not None
    assert row["username"] == "yonetici"
    assert row["role"] == "admin"
    assert row["password_hash"] == "", "boş parola hash'i — B-011"


def test_ensure_owner_does_not_touch_an_existing_user(db):
    _add_user(db, 3)
    db.execute("UPDATE users SET username = 'gercek' WHERE id = 3")
    ensure_owner_exists(db, 3)
    assert db.fetchone("SELECT username FROM users WHERE id = 3")["username"] == "gercek"


def test_create_allows_duplicate_names(db):
    """Klasör adı UNIQUE değil — mevcut şema davranışı."""
    uid = _add_user(db)
    a = create_folder(db, "Ayni", owner_id=uid)
    b = create_folder(db, "Ayni", owner_id=uid)
    assert a != b


# ══════════════════════════════════════════════════════════════════════════════
# 2. Listeleme
# ══════════════════════════════════════════════════════════════════════════════


def test_list_is_sorted_by_name(db):
    uid = _add_user(db)
    for ad in ("Zeta", "Alfa", "Mu"):
        create_folder(db, ad, owner_id=uid)
    assert [f.name for f in list_folders(db)] == ["Alfa", "Mu", "Zeta"]


def test_list_counts_files_per_folder(db):
    uid = _add_user(db)
    a = create_folder(db, "A", owner_id=uid)
    b = create_folder(db, "B", owner_id=uid)
    for i in range(3):
        _add_file(db, f"a{i}.pdf", folder_id=a)
    _add_file(db, "b0.pdf", folder_id=b)
    _add_file(db, "koksuz.pdf")

    sayilar = {f.name: f.file_count for f in list_folders(db)}
    assert sayilar == {"A": 3, "B": 1}


def test_list_is_empty_without_folders(db):
    assert list_folders(db) == []


def test_folder_info_is_a_value_object(db):
    uid = _add_user(db)
    create_folder(db, "A", owner_id=uid)
    assert list_folders(db)[0] == FolderInfo(id=1, name="A", file_count=0)


# ══════════════════════════════════════════════════════════════════════════════
# 3. Silme — dosyalar KALIR
# ══════════════════════════════════════════════════════════════════════════════


def test_delete_removes_the_folder_but_keeps_the_files(db):
    """
    Onay metni "Dosyalar klasörden çıkarılır ama silinmez" diyor —
    davranış bunu tutmalı.
    """
    uid = _add_user(db)
    fid = create_folder(db, "Silinecek", owner_id=uid)
    a = _add_file(db, "a.pdf", folder_id=fid)
    b = _add_file(db, "b.pdf", folder_id=fid)

    tasinan = delete_folder(db, fid, "Silinecek")

    assert tasinan == 2
    assert db.fetchone("SELECT id FROM folders WHERE id = ?", (fid,)) is None
    for file_id in (a, b):
        row = db.fetchone("SELECT folder_id FROM files WHERE id = ?", (file_id,))
        assert row is not None, "dosya silinmemeli"
        assert row["folder_id"] is None, "dosya kök seviyesine çıkmalı"


def test_delete_of_an_empty_folder_reports_zero(db):
    uid = _add_user(db)
    fid = create_folder(db, "Bos", owner_id=uid)
    assert delete_folder(db, fid, "Bos") == 0


def test_delete_is_audited_with_the_folder_as_target(db):
    uid = _add_user(db)
    fid = create_folder(db, "Silinecek", owner_id=uid)
    delete_folder(db, fid, "Silinecek")
    row = db.fetchone(
        "SELECT target_type, target_id, detail FROM audit_log"
        " WHERE action = 'folder_deleted'"
    )
    assert row["target_type"] == "folder"
    assert row["target_id"] == fid
    assert "name=Silinecek" in row["detail"]


def test_delete_does_not_touch_other_folders(db):
    uid = _add_user(db)
    a = create_folder(db, "A", owner_id=uid)
    b = create_folder(db, "B", owner_id=uid)
    kalan = _add_file(db, "b.pdf", folder_id=b)
    delete_folder(db, a, "A")
    assert db.fetchone("SELECT folder_id FROM files WHERE id = ?", (kalan,))["folder_id"] == b


# ══════════════════════════════════════════════════════════════════════════════
# 4. İmha Odası'na taşıma
# ══════════════════════════════════════════════════════════════════════════════


def test_move_to_imha_relabels_every_file_and_sets_the_timer(db):
    uid = _add_user(db)
    fid = create_folder(db, "Imhalik", owner_id=uid)
    ids = [_add_file(db, f"d{i}.pdf", folder_id=fid) for i in range(3)]

    tasinan = move_folder_to_imha(db, fid, hwid=_HWID)

    assert tasinan == 3
    for file_id in ids:
        row = db.fetchone(
            "SELECT label, expires_at FROM files WHERE id = ?", (file_id,)
        )
        assert row["label"] == "Imha"
        assert parse_expires_at(row["expires_at"]) is not None


def test_move_to_imha_honours_the_configured_ttl(db):
    from datetime import timedelta

    uid = _add_user(db)
    db.set_setting("imha_ttl_hours", "6")
    fid = create_folder(db, "A", owner_id=uid)
    file_id = _add_file(db, "a.pdf", folder_id=fid)

    move_folder_to_imha(db, fid)

    expires = parse_expires_at(
        db.fetchone("SELECT expires_at FROM files WHERE id = ?", (file_id,))["expires_at"]
    )
    from datetime import datetime, timezone
    kalan = expires - datetime.now(timezone.utc)
    assert timedelta(hours=5, minutes=55) < kalan <= timedelta(hours=6)


def test_move_to_imha_writes_one_audit_entry_per_file(db):
    """
    Dosya başına AYRI kayıt — mevcut davranış.

    Tek özet kayıt daha derli toplu olurdu ama hangi dosyanın ne zaman
    imhaya gittiğini `target_id` ile sorgulanabilir olmaktan çıkarırdı.
    """
    uid = _add_user(db)
    fid = create_folder(db, "A", owner_id=uid)
    ids = [_add_file(db, f"d{i}.pdf", folder_id=fid) for i in range(3)]

    move_folder_to_imha(db, fid, hwid=_HWID)

    rows = db.fetchall(
        "SELECT target_id, detail FROM audit_log WHERE action = 'file_moved_to_imha'"
        " ORDER BY id"
    )
    assert [r["target_id"] for r in rows] == ids
    assert "via=folder" in rows[0]["detail"]
    assert f"folder_id={fid}" in rows[0]["detail"]


def test_move_to_imha_on_an_empty_folder_is_a_noop(db):
    uid = _add_user(db)
    fid = create_folder(db, "Bos", owner_id=uid)
    assert move_folder_to_imha(db, fid) == 0
    assert db.fetchall("SELECT id FROM audit_log WHERE action='file_moved_to_imha'") == []


def test_move_to_imha_leaves_other_folders_alone(db):
    uid = _add_user(db)
    a = create_folder(db, "A", owner_id=uid)
    b = create_folder(db, "B", owner_id=uid)
    _add_file(db, "a.pdf", folder_id=a)
    korunan = _add_file(db, "b.pdf", folder_id=b)

    move_folder_to_imha(db, a)

    assert db.fetchone("SELECT label FROM files WHERE id = ?", (korunan,))["label"] == "Genel"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Dosya atama
# ══════════════════════════════════════════════════════════════════════════════


def test_assign_moves_a_file_into_a_folder(db):
    uid = _add_user(db)
    fid = create_folder(db, "Hedef", owner_id=uid)
    file_id = _add_file(db, "a.pdf")

    assign_file_to_folder(db, file_id, fid, hwid=_HWID)

    assert db.fetchone("SELECT folder_id FROM files WHERE id=?", (file_id,))["folder_id"] == fid


def test_assign_none_removes_a_file_from_its_folder(db):
    uid = _add_user(db)
    fid = create_folder(db, "Kaynak", owner_id=uid)
    file_id = _add_file(db, "a.pdf", folder_id=fid)

    assign_file_to_folder(db, file_id, None)

    assert db.fetchone("SELECT folder_id FROM files WHERE id=?", (file_id,))["folder_id"] is None


def test_assign_audit_detail_keeps_its_field_order(db):
    """
    Alan sırası `folder_id=... hwid=...` — taşıma sırasında değişmemeli.

    Denetim kaydı geriye dönük ayrıştırılabilir olmalı; sırayı değiştirmek
    mevcut kayıtlarla yeni kayıtları farklı biçimlere ayırırdı.
    """
    uid = _add_user(db)
    fid = create_folder(db, "Hedef", owner_id=uid)
    file_id = _add_file(db, "a.pdf")

    assign_file_to_folder(db, file_id, fid, hwid=_HWID)

    assert _detail(db, "file_moved_to_folder") == f"folder_id={fid} hwid={_HWID}"


# ══════════════════════════════════════════════════════════════════════════════
# 6. Denetim zinciri
# ══════════════════════════════════════════════════════════════════════════════


def test_every_folder_operation_stays_in_the_hash_chain(db):
    uid = _add_user(db)
    fid = create_folder(db, "A", owner_id=uid, hwid=_HWID)
    file_id = _add_file(db, "a.pdf")
    assign_file_to_folder(db, file_id, fid, hwid=_HWID)
    move_folder_to_imha(db, fid, hwid=_HWID)
    delete_folder(db, fid, "A")

    sonuc = verify_audit_chain(db.conn)
    assert sonuc.ok is True
    hashsiz = db.fetchone(
        "SELECT COUNT(*) AS n FROM audit_log WHERE entry_hash IS NULL"
    )["n"]
    assert hashsiz == 0
