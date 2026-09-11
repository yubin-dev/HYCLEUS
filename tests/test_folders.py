"""
HYCLEUS — Klasör işlemleri testleri

Bu mantık `UI/main_window.py` içinde satır içi yazılıydı ve Qt olmadan
çalıştırılamadığı için test edilmemişti.

Denetim kaydı detaylarının ALAN SIRASI da sınanıyor: kayıtlar geriye dönük
ayrıştırılabilir olmalı, dolayısıyla biçim taşıma sırasında değişmemeli.
"""
from __future__ import annotations

import sqlite3

import pytest

from CORE.audit_chain import verify_audit_chain
from CORE.expiry import parse_expires_at
from CORE.folders import (
    FolderInfo,
    assign_file_to_folder,
    create_folder,
    delete_folder,
    folder_subtree_summary,
    is_descendant,
    list_folders,
    move_folder,
    move_folder_to_imha,
)
from CORE.retention import START_UPLOAD, UNIT_YEAR, assign_profile, create_profile

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


def test_create_does_not_invent_a_user_anymore(db):
    """
    DAVRANIŞ DEĞİŞİKLİĞİ (B-011) — eksik sahip artık UYDURULMUYOR.

    Bu test, adı `test_create_writes_a_placeholder_user_when_missing`
    olan sabitleme testinin yerini aldı. Eskisi kaçamağı KORUYORDU:
    `owner_id` yoksa "yonetici" adlı, boş parola hash'li, `admin` rollü
    bir satır yazılıyordu ve test bunu doğruluyordu.

    Artık FK hatası yükseliyor. Gerekçe: oturum kullanıcısı girişte
    `CORE.session_user.sync_session_user()` ile yazılıyor, dolayısıyla
    buraya var olmayan bir `owner_id` gelmesi bir programlama hatası —
    susturulması değil görünmesi gerekiyor.
    """
    assert db.fetchone("SELECT id FROM users WHERE id = 7") is None

    with pytest.raises(sqlite3.IntegrityError):
        create_folder(db, "Klasor", owner_id=7, hwid=_HWID)

    assert db.fetchone("SELECT id FROM users WHERE id = 7") is None, (
        "kaçamak geri gelmiş — users satırı hâlâ uyduruluyor"
    )


def test_ensure_owner_exists_artik_yok(db):
    """
    Kaçamağın fonksiyonu tümüyle KALDIRILDI, susturulmadı.

    Boş bir gövdeye indirgenip bırakılsaydı çağrı yerleri sessizce
    çalışmaya devam eder ve bir sonraki kişi onu yeniden doldurabilirdi.
    """
    import CORE.folders as folders_modulu

    assert not hasattr(folders_modulu, "ensure_owner_exists")


def test_create_folder_audit_extra_alan_sirasini_koruyor(db):
    """
    Sürükle-bırak akışının denetim detayı birebir korunmalı.

    O akış eskiden kendi INSERT'ünü yapıp kendi kaydını yazıyordu
    (kaçamağın İKİNCİ kopyası oradaydı). Tek uygulamada birleşirken
    `via=drag_drop files=N` bilgisi kaybolabilirdi; `audit_extra`
    parametresi tam olarak bunu taşıyor ve alan sırası değişmiyor —
    denetim kayıtları geriye dönük ayrıştırılabilir kalmalı.
    """
    uid = _add_user(db)
    create_folder(
        db, "Surukle", owner_id=uid, hwid=_HWID,
        audit_extra="via=drag_drop files=12",
    )
    assert _detail(db, "folder_created") == (
        f"name=Surukle hwid={_HWID} via=drag_drop files=12"
    )


def test_create_folder_audit_extra_verilmezse_bicim_degismiyor(db):
    """`audit_extra` yoksa detay eski biçimiyle aynı kalmalı."""
    uid = _add_user(db)
    create_folder(db, "Duz", owner_id=uid, hwid=_HWID)
    assert _detail(db, "folder_created") == f"name=Duz hwid={_HWID}"


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
    assert list_folders(db)[0] == FolderInfo(id=1, name="A", file_count=0, parent_id=None)


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
# 4b. B-145 — move_folder_to_imha() artık move_to_imha()'yı çağırıyor,
#     erken-silme onay kapısını UYGULUYOR (ham SQL DEĞİL)
# ══════════════════════════════════════════════════════════════════════════════


def _add_protected_file(db, name: str, *, folder_id: int | None) -> int:
    """Saklama süresi HENÜZ dolmamış (10 yıl, bugün yüklendi), koruma
    AÇIK (erken silme yönetici onayı ister) bir dosya."""
    fid = _add_file(db, name, folder_id=folder_id)
    pid = create_profile(
        db, name=f"korumali-{name}", duration_value=10, duration_unit=UNIT_YEAR,
        start_type=START_UPLOAD, early_delete_protection=True,
    )
    assign_profile(db, fid, pid)
    return fid


def test_move_folder_to_imha_erken_silme_korumali_dosyayi_yonetici_olmayan_onayla_ATLAR(db):
    """
    B-145: `move_folder_to_imha()` artık her dosya için `move_to_imha()`
    çağırıyor — bu da `check_disposal()`/`_require_approval()`'ı devreye
    sokuyor. Saklama süresi dolmamış, koruma AÇIK bir dosya, yönetici
    OLMAYAN bir `approved_by` ile ATLANMALI; aynı klasördeki korumasız
    dosya yine de taşınmalı (bir dosyanın engellenmesi diğerlerini
    durdurmamalı).

    Mutasyon-kanıt: `move_folder_to_imha()` eski ham
    `UPDATE files SET label = 'Imha' ...` SQL'ine dönerse (ya da
    `EarlyDeletionBlocked` yutulup `continue` yerine dosya yine de
    taşınırsa) bu test KIRMIZIYA düşer — korumalı dosya da "Imha"
    etiketine geçer ve `tasinan == 2` olur.
    """
    uid = _add_user(db)  # varsayılan rol 'user' — YÖNETİCİ DEĞİL
    fid_folder = create_folder(db, "Karisik", owner_id=uid)
    korumali_id = _add_protected_file(db, "korumali.pdf", folder_id=fid_folder)
    serbest_id = _add_file(db, "serbest.pdf", folder_id=fid_folder)

    tasinan = move_folder_to_imha(
        db, fid_folder, user_id=uid, user_confirmed=True, approved_by=uid,
    )

    assert tasinan == 1, "yalnızca korumasız dosya taşınmalıydı"
    assert db.fetchone(
        "SELECT label FROM files WHERE id = ?", (korumali_id,)
    )["label"] == "Genel", "erken-silme korumalı dosya YİNE DE İmha'ya taşınmış"
    assert db.fetchone(
        "SELECT label FROM files WHERE id = ?", (serbest_id,)
    )["label"] == "Imha"


def test_move_folder_to_imha_yonetici_onayiyla_korumali_dosyayi_da_tasir(db):
    """Aynı senaryo, ama `approved_by` GERÇEKTEN yönetici — korumalı
    dosya da taşınmalı. Kapının kendisini değil, sadece yetkiyi sınıyor."""
    admin_cur = db.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
        ("yonetici", "x"),
    )
    admin_id = int(admin_cur.lastrowid)
    fid_folder = create_folder(db, "Korumali", owner_id=admin_id)
    korumali_id = _add_protected_file(db, "korumali2.pdf", folder_id=fid_folder)

    tasinan = move_folder_to_imha(
        db, fid_folder, user_id=admin_id, user_confirmed=True, approved_by=admin_id,
    )

    assert tasinan == 1
    assert db.fetchone(
        "SELECT label FROM files WHERE id = ?", (korumali_id,)
    )["label"] == "Imha"


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


# ══════════════════════════════════════════════════════════════════════════════
# 7. Hiyerarşi — alt klasör oluşturma, taşıma, döngü koruması (B-123)
# ══════════════════════════════════════════════════════════════════════════════


def test_create_folder_with_parent_id_nests_it(db):
    uid = _add_user(db)
    ust = create_folder(db, "Ust", owner_id=uid)
    alt = create_folder(db, "Alt", owner_id=uid, parent_id=ust)
    assert db.fetchone("SELECT parent_id FROM folders WHERE id = ?", (alt,))["parent_id"] == ust


def test_create_folder_without_parent_id_is_still_root(db):
    """Varsayılan davranış DEĞİŞMEDİ — mevcut TÜM çağıranlar kök üretmeye devam ediyor."""
    uid = _add_user(db)
    fid = create_folder(db, "Kok", owner_id=uid)
    assert db.fetchone("SELECT parent_id FROM folders WHERE id = ?", (fid,))["parent_id"] is None


def test_create_folder_parent_id_denetim_kaydina_yaziliyor(db):
    uid = _add_user(db)
    ust = create_folder(db, "Ust", owner_id=uid)
    create_folder(db, "Alt", owner_id=uid, hwid=_HWID, parent_id=ust)
    assert _detail(db, "folder_created") == f"name=Alt hwid={_HWID} parent_id={ust}"


def test_create_folder_gecersiz_parent_id_FK_hatasi_verir(db):
    uid = _add_user(db)
    with pytest.raises(sqlite3.IntegrityError):
        create_folder(db, "Yetim", owner_id=uid, parent_id=9999)


def test_list_folders_parent_id_alanini_dondurur(db):
    uid = _add_user(db)
    ust = create_folder(db, "Ust", owner_id=uid)
    create_folder(db, "Alt", owner_id=uid, parent_id=ust)
    eslesme = {f.name: f.parent_id for f in list_folders(db)}
    assert eslesme == {"Ust": None, "Alt": ust}


# ── is_descendant() — döngü koruması ─────────────────────────────────────────


def test_is_descendant_kendisi_icin_true(db):
    uid = _add_user(db)
    fid = create_folder(db, "A", owner_id=uid)
    assert is_descendant(db, fid, fid) is True


def test_is_descendant_dogrudan_cocuk_icin_true(db):
    uid = _add_user(db)
    ust = create_folder(db, "Ust", owner_id=uid)
    alt = create_folder(db, "Alt", owner_id=uid, parent_id=ust)
    assert is_descendant(db, alt, ust) is True


def test_is_descendant_torun_icin_true(db):
    """İki seviye atlayarak da (torun) yakalanmalı — sadece bir seviye değil."""
    uid = _add_user(db)
    a = create_folder(db, "A", owner_id=uid)
    b = create_folder(db, "B", owner_id=uid, parent_id=a)
    c = create_folder(db, "C", owner_id=uid, parent_id=b)
    assert is_descendant(db, c, a) is True


def test_is_descendant_alakasiz_klasorler_icin_false(db):
    uid = _add_user(db)
    a = create_folder(db, "A", owner_id=uid)
    b = create_folder(db, "B", owner_id=uid)
    assert is_descendant(db, b, a) is False


def test_is_descendant_ebeveyn_kendi_cocugunun_alt_agacinda_degil(db):
    """Yön önemli: üst klasör, kendi alt klasörünün alt ağacında SAYILMAZ."""
    uid = _add_user(db)
    ust = create_folder(db, "Ust", owner_id=uid)
    alt = create_folder(db, "Alt", owner_id=uid, parent_id=ust)
    assert is_descendant(db, ust, alt) is False


@pytest.mark.timeout(3)
def test_is_descendant_elle_bozulmus_dongude_sonsuz_donguye_girmiyor(db):
    """
    `move_folder()`'ın kendi döngü koruması sağlamken `parent_id` zinciri
    bozulamaz — ama `gorulen` kümesi tam olarak BUNUN İÇİN var: elle DB
    düzenlemesiyle (ya da başka bir hatayla) oluşmuş, uygulamanın kendi
    guard'ını hiç görmeden yazılmış bir döngüye karşı savunma.
    Bu senaryo normal akışta hiç oluşmuyor, o yüzden `gorulen` kümesi
    kaldırılsa bile mevcut hiçbir test bunu YAKALAMAZ — burada `parent_id`
    zincirini `move_folder()`'ı BYPASS edip doğrudan SQL ile bozarak
    kanıtlıyoruz: fonksiyon sonsuz döngüye girmeden (zaman aşımı olmadan)
    dönüyor.
    """
    uid = _add_user(db)
    a = create_folder(db, "A", owner_id=uid)
    b = create_folder(db, "B", owner_id=uid, parent_id=a)
    diger = create_folder(db, "Alakasiz", owner_id=uid)
    # Guard'ı bypass edip A→B→A döngüsü kuruyoruz (move_folder() bunu
    # asla üretmez, ama bir veri bozulmasını simüle ediyoruz).
    db.execute("UPDATE folders SET parent_id = ? WHERE id = ?", (b, a))

    assert is_descendant(db, a, diger) is False


# ── move_folder() — döngü koruması GERÇEKTEN reddediyor mu ───────────────────


def test_move_folder_kok_klasorlerden_birine_tasir(db):
    uid = _add_user(db)
    a = create_folder(db, "A", owner_id=uid)
    b = create_folder(db, "B", owner_id=uid)
    move_folder(db, a, b, hwid=_HWID)
    assert db.fetchone("SELECT parent_id FROM folders WHERE id = ?", (a,))["parent_id"] == b


def test_move_folder_koke_tasir(db):
    uid = _add_user(db)
    ust = create_folder(db, "Ust", owner_id=uid)
    alt = create_folder(db, "Alt", owner_id=uid, parent_id=ust)
    move_folder(db, alt, None)
    assert db.fetchone("SELECT parent_id FROM folders WHERE id = ?", (alt,))["parent_id"] is None


def test_move_folder_kendine_tasima_REDDEDILIYOR(db):
    """Görevin özel olarak istediği durum: hedef_id == tasinan_id."""
    uid = _add_user(db)
    fid = create_folder(db, "A", owner_id=uid)
    with pytest.raises(ValueError):
        move_folder(db, fid, fid)
    assert db.fetchone("SELECT parent_id FROM folders WHERE id = ?", (fid,))["parent_id"] is None


def test_move_folder_kendi_dogrudan_cocuguna_tasima_REDDEDILIYOR(db):
    uid = _add_user(db)
    ust = create_folder(db, "Ust", owner_id=uid)
    alt = create_folder(db, "Alt", owner_id=uid, parent_id=ust)
    with pytest.raises(ValueError):
        move_folder(db, ust, alt)
    # DB GERÇEKTEN değişmedi mi — reddin yalnızca görünürde olmadığını kanıtla.
    assert db.fetchone("SELECT parent_id FROM folders WHERE id = ?", (ust,))["parent_id"] is None


def test_move_folder_kendi_torununa_tasima_REDDEDILIYOR(db):
    """İki seviye atlayarak döngü kurmaya çalışma da yakalanmalı."""
    uid = _add_user(db)
    a = create_folder(db, "A", owner_id=uid)
    b = create_folder(db, "B", owner_id=uid, parent_id=a)
    c = create_folder(db, "C", owner_id=uid, parent_id=b)
    with pytest.raises(ValueError):
        move_folder(db, a, c)
    assert db.fetchone("SELECT parent_id FROM folders WHERE id = ?", (a,))["parent_id"] is None


def test_move_folder_torundan_uste_tasima_SERBEST(db):
    """Yön önemli: bir alt klasörü kendi üstünün YANINA taşımak döngü DEĞİL."""
    uid = _add_user(db)
    a = create_folder(db, "A", owner_id=uid)
    b = create_folder(db, "B", owner_id=uid, parent_id=a)
    c = create_folder(db, "C", owner_id=uid, parent_id=b)
    move_folder(db, c, a)  # C artık A'nın DOĞRUDAN altında, B'nin değil
    assert db.fetchone("SELECT parent_id FROM folders WHERE id = ?", (c,))["parent_id"] == a


def test_move_folder_denetim_kaydina_yaziliyor(db):
    uid = _add_user(db)
    a = create_folder(db, "A", owner_id=uid)
    b = create_folder(db, "B", owner_id=uid)
    move_folder(db, a, b, hwid=_HWID)
    assert _detail(db, "folder_moved") == f"yeni_parent_id={b} hwid={_HWID}"


# ── folder_subtree_summary() + çok seviyeli silme ────────────────────────────


def test_folder_subtree_summary_tek_klasor_dosya_sayar(db):
    uid = _add_user(db)
    fid = create_folder(db, "A", owner_id=uid)
    _add_file(db, "a.pdf", folder_id=fid)
    _add_file(db, "b.pdf", folder_id=fid)
    id_listesi, dosya_sayisi = folder_subtree_summary(db, fid)
    assert id_listesi == [fid]
    assert dosya_sayisi == 2


def test_folder_subtree_summary_alt_agaci_topluyor(db):
    uid = _add_user(db)
    ust = create_folder(db, "Ust", owner_id=uid)
    alt = create_folder(db, "Alt", owner_id=uid, parent_id=ust)
    torun = create_folder(db, "Torun", owner_id=uid, parent_id=alt)
    _add_file(db, "u.pdf", folder_id=ust)
    _add_file(db, "a1.pdf", folder_id=alt)
    _add_file(db, "a2.pdf", folder_id=alt)
    _add_file(db, "t.pdf", folder_id=torun)
    _add_file(db, "koksuz.pdf")  # sayılmamalı

    id_listesi, dosya_sayisi = folder_subtree_summary(db, ust)

    assert set(id_listesi) == {ust, alt, torun}
    assert dosya_sayisi == 4


def test_delete_folder_alt_agaci_da_GERCEKTEN_siliyor(db):
    """
    Canlı doğrulanmış SQLite gerçeği: `ON DELETE CASCADE` tek seviyede
    KALMIYOR — üç seviye derinlikte bile TÜM alt ağaç gidiyor.
    """
    uid = _add_user(db)
    ust = create_folder(db, "Ust", owner_id=uid)
    alt = create_folder(db, "Alt", owner_id=uid, parent_id=ust)
    torun = create_folder(db, "Torun", owner_id=uid, parent_id=alt)

    delete_folder(db, ust, "Ust")

    for fid in (ust, alt, torun):
        assert db.fetchone("SELECT id FROM folders WHERE id = ?", (fid,)) is None


def test_delete_folder_alt_agactaki_dosyalari_da_kok_seviyesine_cikarir(db):
    uid = _add_user(db)
    ust = create_folder(db, "Ust", owner_id=uid)
    alt = create_folder(db, "Alt", owner_id=uid, parent_id=ust)
    torun_dosya = _add_file(db, "derinde.pdf", folder_id=alt)

    tasinan = delete_folder(db, ust, "Ust")

    assert tasinan == 1
    row = db.fetchone("SELECT folder_id FROM files WHERE id = ?", (torun_dosya,))
    assert row is not None, "dosya silinmemeli"
    assert row["folder_id"] is None, "alt ağaçtaki dosya da köke çıkmalı"
