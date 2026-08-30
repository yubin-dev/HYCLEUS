"""
HYCLEUS — Denetim kaydı hash zinciri testleri

Testlerin çoğu zinciri KIRMAYA çalışır: kayıt değiştirmek, kayıt silmek,
zinciri atlayarak INSERT etmek, kuyruğu kesmek. Sağlam zincirin doğrulanması
kolay kısım; asıl soru kırılmanın DOĞRU NOKTADA raporlanıp raporlanmadığı.

Kurcalama her yerde `db.conn.execute()` ile, yani `append_entry()` yolunu
atlayarak yapılıyor — diske erişimi olan bir saldırganın yapacağı şeyin
birebir aynısı.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from CORE.audit_chain import (
    CHAIN_START_SETTING,
    FIELD_ORDER,
    GENESIS_ACTION,
    GENESIS_HASH,
    LINK_BROKEN,
    LINK_INTACT,
    LINK_OUT_OF_SCOPE,
    SERIALIZATION_VERSION,
    ChainVerification,
    anchor_path,
    append_entry,
    canonical_bytes,
    chain_start_id,
    compute_entry_hash,
    ensure_chain_started,
    link_status,
    link_statuses,
    maybe_write_daily_anchor,
    read_anchors,
    usb_anchor_path,
    verify_against_anchor,
    verify_anchor_file,
    verify_anchor_replicas,
    verify_audit_chain,
    write_anchor,
)


# ── Yardımcılar ───────────────────────────────────────────────────────────────


def _seed_users(db) -> list[int]:
    """
    İki gerçek kullanıcı satırı sağlar.

    audit_log.user_id → users(id) foreign key'i açık (PRAGMA foreign_keys=ON),
    dolayısıyla uydurma bir user_id ile denetim kaydı yazılamaz.
    """
    mevcut = db.fetchall("SELECT id FROM users ORDER BY id")
    if mevcut:
        return [row["id"] for row in mevcut]
    ids: list[int] = []
    for ad in ("test_user_a", "test_user_b"):
        cur = db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)", (ad, "argon2$sahte")
        )
        ids.append(int(cur.lastrowid))
    return ids


def _log_many(db, count: int, prefix: str = "test_action") -> list[int]:
    """count adet denetim kaydı yazar ve id'lerini döndürür."""
    kullanicilar = _seed_users(db)
    ids: list[int] = []
    for index in range(count):
        ids.append(
            append_entry(
                db.conn,
                f"{prefix}_{index}",
                user_id=kullanicilar[index % 2] if index % 3 else None,
                target_type="file" if index % 2 else None,
                target_id=index * 10 if index % 2 else None,
                detail=f"detay #{index} — ünicode: ğüşiöç",
            )
        )
    return ids


def _chained_rows(db) -> list[sqlite3.Row]:
    return db.fetchall(
        "SELECT id, action, entry_hash FROM audit_log"
        " WHERE entry_hash IS NOT NULL ORDER BY id"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. Kanonik serileştirme
# ══════════════════════════════════════════════════════════════════════════════


def _entry(**overrides) -> dict:
    base = {
        "id": 7,
        "timestamp": "2026-08-13T10:00:00Z",
        "user_id": 3,
        "action": "login_success",
        "target_type": None,
        "target_id": None,
        "detail": "hwid=ABC123",
    }
    base.update(overrides)
    return base


def test_canonical_form_is_deterministic():
    assert canonical_bytes(_entry()) == canonical_bytes(_entry())


def test_canonical_form_starts_with_version_header():
    assert canonical_bytes(_entry()).startswith(SERIALIZATION_VERSION.encode() + b"\n")


def test_canonical_form_distinguishes_null_from_empty_string():
    """detail IS NULL ile detail = '' farklı hash üretmeli."""
    assert canonical_bytes(_entry(detail=None)) != canonical_bytes(_entry(detail=""))


def test_canonical_form_resists_field_injection():
    """
    Uzunluk öneki olmasaydı bu iki kayıt aynı byte dizisine çökebilirdi.

    Saldırgan `detail` içine ayraç + alan adı yazarak başka bir kaydın
    temsilini taklit etmeye çalışıyor.
    """
    kurban = _entry(detail="normal", target_type="file")
    saldiri = _entry(detail="normal\ntarget_type=4:file", target_type=None)
    assert canonical_bytes(kurban) != canonical_bytes(saldiri)


def test_canonical_form_requires_every_field():
    eksik = _entry()
    del eksik["detail"]
    with pytest.raises(KeyError):
        canonical_bytes(eksik)


def test_field_order_is_the_full_row_minus_hash():
    """entry_hash dışındaki her audit_log sütunu hash'e girmeli."""
    assert set(FIELD_ORDER) == {
        "id", "timestamp", "user_id", "action", "target_type", "target_id", "detail",
    }


def test_compute_entry_hash_uses_raw_bytes_of_prev_hash():
    """Önceki hash hex metin olarak değil, 32 ham byte olarak karışmalı."""
    import hashlib

    beklenen = hashlib.sha256(
        bytes.fromhex(GENESIS_HASH) + canonical_bytes(_entry())
    ).hexdigest()
    assert compute_entry_hash(GENESIS_HASH, _entry()) == beklenen


def test_compute_entry_hash_rejects_malformed_prev():
    with pytest.raises(ValueError):
        compute_entry_hash("kısa", _entry())
    with pytest.raises(ValueError):
        compute_entry_hash("z" * 64, _entry())


def test_changing_any_single_field_changes_the_hash():
    temel = compute_entry_hash(GENESIS_HASH, _entry())
    degisimler = {
        "id": 8,
        "timestamp": "2026-08-13T10:00:01Z",
        "user_id": 4,
        "action": "login_failed",
        "target_type": "file",
        "target_id": 1,
        "detail": "hwid=ABC124",
    }
    for alan, yeni in degisimler.items():
        assert compute_entry_hash(GENESIS_HASH, _entry(**{alan: yeni})) != temel, alan


# ══════════════════════════════════════════════════════════════════════════════
# 2. Zincir kurulumu ve genesis işaretleyicisi
# ══════════════════════════════════════════════════════════════════════════════


def test_chain_is_started_automatically_on_connect(db):
    """DBManager.connect() zinciri kurar — ayrıca bir çağrı gerekmez."""
    start = chain_start_id(db.conn)
    assert start is not None
    row = db.fetchone("SELECT action, entry_hash FROM audit_log WHERE id = ?", (start,))
    assert row["action"] == GENESIS_ACTION
    assert row["entry_hash"] is not None


def test_genesis_entry_hashes_from_the_genesis_constant(db):
    """İlk halka gerçekten 64 sıfırdan türemeli."""
    start = chain_start_id(db.conn)
    row = db.fetchone(
        f"SELECT {', '.join(FIELD_ORDER)}, entry_hash FROM audit_log WHERE id = ?",
        (start,),
    )
    entry = {alan: row[alan] for alan in FIELD_ORDER}
    assert compute_entry_hash(GENESIS_HASH, entry) == row["entry_hash"]


def test_genesis_entry_records_the_migration_boundary(db):
    start = chain_start_id(db.conn)
    detail = db.fetchone("SELECT detail FROM audit_log WHERE id = ?", (start,))["detail"]
    assert f"serialization={SERIALIZATION_VERSION}" in detail
    assert "unchained_before=" in detail
    assert "last_unchained_id=" in detail


def test_chain_start_is_recorded_in_settings(db):
    start = chain_start_id(db.conn)
    assert db.get_setting(CHAIN_START_SETTING) == str(start)


def test_ensure_chain_started_is_idempotent(db):
    start = chain_start_id(db.conn)
    onceki = db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"]
    assert ensure_chain_started(db.conn) == start
    assert ensure_chain_started(db.conn) == start
    assert db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"] == onceki


def test_chain_start_survives_settings_key_deletion(db):
    """settings satırı silinse bile genesis kaydının kendisi sınırı gösterir."""
    start = chain_start_id(db.conn)
    db.execute("DELETE FROM settings WHERE key = ?", (CHAIN_START_SETTING,))
    assert chain_start_id(db.conn) == start


# ══════════════════════════════════════════════════════════════════════════════
# 3. Sağlam zincir
# ══════════════════════════════════════════════════════════════════════════════


def test_chain_verifies_after_many_entries(db):
    _log_many(db, 25)
    sonuc = verify_audit_chain(db.conn)
    assert sonuc is not None
    assert bool(sonuc) is True
    assert sonuc.ok is True
    assert sonuc.breaks == []
    assert sonuc.checked == 26  # 25 kayıt + genesis
    assert sonuc.unchained_before == 0


def test_db_manager_exposes_verify(db):
    db.log("via_db_manager", detail="x")
    assert db.verify_audit_chain()


def test_db_log_writes_a_hashed_entry(db):
    db.log("hashed_action", user_id=None, detail="detay")
    row = db.fetchone("SELECT entry_hash FROM audit_log WHERE action = 'hashed_action'")
    assert row["entry_hash"] is not None
    assert len(row["entry_hash"]) == 64


def test_each_entry_hash_is_unique_even_for_identical_content(db):
    """Aynı içerikli iki kayıt bile farklı hash almalı — id ve zincir farklı."""
    for _ in range(5):
        db.log("ayni_islem", detail="ayni detay")
    hashes = [r["entry_hash"] for r in _chained_rows(db)]
    assert len(set(hashes)) == len(hashes)


def test_verification_reports_the_last_hash(db):
    _log_many(db, 3)
    sonuc = verify_audit_chain(db.conn)
    son = _chained_rows(db)[-1]
    assert sonuc.last_hash == son["entry_hash"]
    assert sonuc.last_id == son["id"]


def test_summary_is_readable_when_intact(db):
    _log_many(db, 2)
    metin = verify_audit_chain(db.conn).summary()
    assert "sağlam" in metin


# ══════════════════════════════════════════════════════════════════════════════
# 4. Kurcalama — kayıt değiştirme
# ══════════════════════════════════════════════════════════════════════════════


def test_modified_record_is_caught_at_the_right_id(db):
    ids = _log_many(db, 10)
    kurban = ids[4]

    db.conn.execute(
        "UPDATE audit_log SET detail = ? WHERE id = ?",
        ("saldirgan bu satiri degistirdi", kurban),
    )
    db.conn.commit()

    sonuc = verify_audit_chain(db.conn)
    assert not sonuc
    assert sonuc.first_broken_id == kurban
    assert [b.kind for b in sonuc.breaks] == ["modified"]
    assert [b.entry_id for b in sonuc.breaks] == [kurban]


def test_modifying_a_record_does_not_cascade_to_later_records(db):
    """
    Tek satır değiştirildiğinde rapor TEK bir nokta göstermeli.

    Doğrulayıcı kırılmadan sonra saklanan hash'ten devam ediyor; aksi hâlde
    "kırılma nerede başladı" sorusu gürültüye boğulurdu.
    """
    ids = _log_many(db, 12)
    db.conn.execute("UPDATE audit_log SET action = 'sahte' WHERE id = ?", (ids[2],))
    db.conn.commit()

    sonuc = verify_audit_chain(db.conn)
    assert len(sonuc.breaks) == 1
    assert sonuc.breaks[0].entry_id == ids[2]


def test_two_separate_modifications_are_both_reported(db):
    ids = _log_many(db, 12)
    for kurban in (ids[1], ids[8]):
        db.conn.execute(
            "UPDATE audit_log SET detail = 'degisti' WHERE id = ?", (kurban,)
        )
    db.conn.commit()

    sonuc = verify_audit_chain(db.conn)
    assert [b.entry_id for b in sonuc.breaks] == [ids[1], ids[8]]
    assert sonuc.first_broken_id == ids[1]


def test_modifying_the_genesis_record_is_caught(db):
    start = chain_start_id(db.conn)
    _log_many(db, 3)
    db.conn.execute(
        "UPDATE audit_log SET detail = 'zincir buradan baslamadi' WHERE id = ?", (start,)
    )
    db.conn.commit()

    sonuc = verify_audit_chain(db.conn)
    assert not sonuc
    assert sonuc.first_broken_id == start


def test_rewriting_only_the_hash_is_caught(db):
    """Saldırgan içeriği değil hash'i değiştirse de yakalanmalı."""
    ids = _log_many(db, 5)
    db.conn.execute("UPDATE audit_log SET entry_hash = ? WHERE id = ?", ("a" * 64, ids[3]))
    db.conn.commit()

    sonuc = verify_audit_chain(db.conn)
    assert not sonuc
    assert sonuc.first_broken_id == ids[3]


def test_timestamp_backdating_is_caught(db):
    """
    Zaman damgasını geriye çekmek — izleri "eskitmenin" klasik yolu.

    timestamp hash'e dahil olduğu için bu da sıradan bir modification.
    """
    ids = _log_many(db, 4)
    db.conn.execute(
        "UPDATE audit_log SET timestamp = '2020-01-01T00:00:00Z' WHERE id = ?", (ids[2],)
    )
    db.conn.commit()
    assert verify_audit_chain(db.conn).first_broken_id == ids[2]


def test_reassigning_a_record_to_another_user_is_caught(db):
    """Bir işlemi başkasının üstüne yıkmak — user_id de hash'e dahil."""
    ids = _log_many(db, 4)
    kullanicilar = _seed_users(db)
    kurban = ids[1]
    onceki = db.fetchone("SELECT user_id FROM audit_log WHERE id = ?", (kurban,))["user_id"]
    baskasi = next(u for u in kullanicilar if u != onceki)

    db.conn.execute("UPDATE audit_log SET user_id = ? WHERE id = ?", (baskasi, kurban))
    db.conn.commit()
    assert verify_audit_chain(db.conn).first_broken_id == kurban


# ══════════════════════════════════════════════════════════════════════════════
# 5. Kurcalama — kayıt silme
# ══════════════════════════════════════════════════════════════════════════════


def test_deleted_middle_record_is_caught_as_gap_and_break(db):
    """
    Aradan bir kayıt silmek iki iz bırakır: id boşluğu ve sonraki kaydın
    hash uyuşmazlığı. İkisi de aynı noktayı göstermeli.
    """
    ids = _log_many(db, 10)
    silinen = ids[5]

    db.conn.execute("DELETE FROM audit_log WHERE id = ?", (silinen,))
    db.conn.commit()

    sonuc = verify_audit_chain(db.conn)
    assert not sonuc
    assert sonuc.first_broken_id == silinen

    turler = {b.kind: b for b in sonuc.breaks}
    assert "gap" in turler
    assert turler["gap"].entry_id == silinen
    assert str(silinen) in turler["gap"].detail

    assert "modified" in turler
    assert turler["modified"].entry_id == ids[6]  # boşluktan sonraki kayıt


def test_deleting_a_contiguous_block_reports_every_missing_id(db):
    ids = _log_many(db, 12)
    silinenler = ids[3:7]
    db.conn.executemany(
        "DELETE FROM audit_log WHERE id = ?", [(i,) for i in silinenler]
    )
    db.conn.commit()

    sonuc = verify_audit_chain(db.conn)
    bosluk = next(b for b in sonuc.breaks if b.kind == "gap")
    assert bosluk.entry_id == silinenler[0]
    for eksik in silinenler:
        assert str(eksik) in bosluk.detail


def test_deleting_the_genesis_record_is_caught(db):
    start = chain_start_id(db.conn)
    _log_many(db, 4)
    db.conn.execute("DELETE FROM audit_log WHERE id = ?", (start,))
    db.conn.commit()

    sonuc = verify_audit_chain(db.conn)
    assert not sonuc
    assert sonuc.first_broken_id == start


def test_tail_truncation_is_NOT_caught_by_the_chain_alone(db):
    """
    Bilinen ve belgelenmiş sınır: kuyruktan silmek zincirde iz bırakmaz.

    Bu test bir zafiyeti "onaylamıyor" — sınırın yerini sabitliyor. Sınır
    değişirse (ör. biri kuyruk tespiti eklerse) test kırılır ve SECURITY.md
    §4.6 ile birlikte güncellenmesi gerektiği görülür. Bu senaryonun
    karşılığı çıpadır: bir sonraki test onu gösteriyor.
    """
    ids = _log_many(db, 8)
    db.conn.executemany("DELETE FROM audit_log WHERE id = ?", [(i,) for i in ids[-3:]])
    db.conn.commit()

    assert verify_audit_chain(db.conn).ok is True


def test_tail_truncation_IS_caught_by_the_anchor(db, tmp_path: Path):
    capa = tmp_path / "anchor.log"
    ids = _log_many(db, 8)
    write_anchor(db.conn, "test", path=capa)

    db.conn.executemany("DELETE FROM audit_log WHERE id = ?", [(i,) for i in ids[-3:]])
    db.conn.commit()

    # Zincir hâlâ "sağlam" görünüyor…
    assert verify_audit_chain(db.conn).ok is True
    # …ama çıpa aksini söylüyor.
    kontrol = verify_against_anchor(db.conn, path=capa)
    assert not kontrol
    assert any(str(ids[-1]) in p for p in kontrol.problems)


# ══════════════════════════════════════════════════════════════════════════════
# 6. Zinciri atlayan yazma
# ══════════════════════════════════════════════════════════════════════════════


def test_direct_insert_is_reported_as_unhashed(db):
    _log_many(db, 3)
    db.conn.execute(
        "INSERT INTO audit_log (action, detail) VALUES (?, ?)",
        ("zinciri_atlayan_kayit", "append_entry cagrilmadi"),
    )
    db.conn.commit()

    sonuc = verify_audit_chain(db.conn)
    assert not sonuc
    assert [b.kind for b in sonuc.breaks] == ["unhashed"]


def test_unhashed_row_does_not_break_the_links_around_it(db):
    """
    Hash'siz satır kapsam dışıdır ama halkayı KOPARMAZ.

    Yazar (`_previous_hash`) hash'siz satırları atlıyor; doğrulayıcı da
    atlamalı. Aksi hâlde tek bir doğrudan INSERT'ten sonraki her kayıt
    kırık görünür ve rapor işe yaramaz hâle gelirdi.
    """
    _log_many(db, 3)
    db.conn.execute(
        "INSERT INTO audit_log (action) VALUES ('zinciri_atlayan')"
    )
    db.conn.commit()
    sonrakiler = _log_many(db, 3, prefix="sonraki")

    sonuc = verify_audit_chain(db.conn)
    assert len(sonuc.breaks) == 1
    assert sonuc.breaks[0].kind == "unhashed"
    assert sonuc.last_id == sonrakiler[-1]


# ══════════════════════════════════════════════════════════════════════════════
# 7. Zincir öncesi (eski) kayıtlar
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def legacy_db(db):
    """
    Yükseltme öncesi durumu taklit eder: hash'siz eski kayıtlar, zincir yok.

    Genesis satırı ve settings anahtarı silinip yerine düz INSERT'lerle eski
    kayıtlar konuyor — güncellemenin bulduğu tablo tam olarak budur.
    """
    db.execute("DELETE FROM audit_log")
    db.execute("DELETE FROM settings WHERE key = ?", (CHAIN_START_SETTING,))
    for index in range(4):
        db.conn.execute(
            "INSERT INTO audit_log (action, detail) VALUES (?, ?)",
            (f"eski_kayit_{index}", "hash sutunu eklenmeden once yazildi"),
        )
    db.conn.commit()
    return db


def test_legacy_rows_have_no_hash(legacy_db):
    rows = legacy_db.fetchall("SELECT entry_hash FROM audit_log")
    assert len(rows) == 4
    assert all(r["entry_hash"] is None for r in rows)


def test_unstarted_chain_is_reported_not_silently_accepted(legacy_db):
    """Zincir yoksa doğrulama 'sağlam' DEMEZ — açıkça no_chain der."""
    sonuc = verify_audit_chain(legacy_db.conn)
    assert not sonuc
    assert [b.kind for b in sonuc.breaks] == ["no_chain"]
    assert sonuc.unchained_before == 4
    assert sonuc.checked == 0


def test_starting_the_chain_leaves_legacy_rows_out_of_scope(legacy_db):
    start = ensure_chain_started(legacy_db.conn)
    _log_many(legacy_db, 5)

    sonuc = verify_audit_chain(legacy_db.conn)
    assert sonuc.ok is True
    assert sonuc.start_id == start
    assert sonuc.unchained_before == 4   # eski kayıtlar kapsam dışı
    assert sonuc.checked == 6            # genesis + 5 yeni kayıt
    assert "4 eski kayıt kapsam dışı" in sonuc.summary()


def test_genesis_detail_names_the_boundary_it_found(legacy_db):
    start = ensure_chain_started(legacy_db.conn)
    detail = legacy_db.fetchone(
        "SELECT detail FROM audit_log WHERE id = ?", (start,)
    )["detail"]
    assert "unchained_before=4" in detail
    assert f"last_unchained_id={start - 1}" in detail


def test_tampering_with_a_legacy_row_is_not_reported(legacy_db):
    """
    Kapsam dışı, gerçekten kapsam dışı.

    Eski kayıtları korunuyormuş gibi göstermek, korumamaktan daha kötü
    olurdu — bu test o sınırın sessizce kaymadığını garanti eder.
    """
    ensure_chain_started(legacy_db.conn)
    _log_many(legacy_db, 3)
    legacy_db.conn.execute("UPDATE audit_log SET detail = 'silindi' WHERE id = 1")
    legacy_db.conn.commit()
    assert verify_audit_chain(legacy_db.conn).ok is True


# ══════════════════════════════════════════════════════════════════════════════
# 8. Anchor
# ══════════════════════════════════════════════════════════════════════════════


def test_anchor_path_honours_the_env_override(isolate_audit_anchor: Path):
    assert anchor_path() == isolate_audit_anchor


def test_anchor_records_the_current_chain_head(db, tmp_path: Path):
    capa = tmp_path / "anchor.log"
    _log_many(db, 5)

    kayit = write_anchor(db.conn, "test", path=capa)
    son = _chained_rows(db)[-1]

    assert kayit is not None
    assert kayit["last_id"] == son["id"]
    assert kayit["last_hash"] == son["entry_hash"]
    assert kayit["entry_count"] == 6      # genesis + 5
    assert kayit["reason"] == "test"
    assert kayit["seq"] == 1
    assert kayit["prev_anchor_hash"] == GENESIS_HASH
    assert kayit["chain_start_id"] == chain_start_id(db.conn)


def test_anchor_file_is_append_only_in_practice(db, tmp_path: Path):
    """Her çıpa yeni bir satır — öncekiler yerinde kalmalı."""
    capa = tmp_path / "anchor.log"
    write_anchor(db.conn, "birinci", path=capa)
    _log_many(db, 2)
    write_anchor(db.conn, "ikinci", path=capa)
    _log_many(db, 2)
    write_anchor(db.conn, "ucuncu", path=capa)

    kayitlar = read_anchors(capa)
    assert [k["reason"] for k in kayitlar] == ["birinci", "ikinci", "ucuncu"]
    assert [k["seq"] for k in kayitlar] == [1, 2, 3]
    # last_id monoton artmalı — zincirin ucu ilerliyor
    assert [k["last_id"] for k in kayitlar] == sorted(k["last_id"] for k in kayitlar)


def test_anchor_updates_as_the_chain_grows(db, tmp_path: Path):
    capa = tmp_path / "anchor.log"
    write_anchor(db.conn, "once", path=capa)
    onceki = read_anchors(capa)[-1]

    _log_many(db, 4)
    write_anchor(db.conn, "sonra", path=capa)
    sonraki = read_anchors(capa)[-1]

    assert sonraki["last_id"] > onceki["last_id"]
    assert sonraki["last_hash"] != onceki["last_hash"]
    assert sonraki["entry_count"] == onceki["entry_count"] + 4


def test_anchor_matches_an_untouched_database(db, tmp_path: Path):
    capa = tmp_path / "anchor.log"
    _log_many(db, 6)
    write_anchor(db.conn, "test", path=capa)

    kontrol = verify_against_anchor(db.conn, path=capa)
    assert kontrol
    assert kontrol.anchors_checked == 1
    assert kontrol.problems == []


def test_anchor_detects_a_rewritten_chain(db, tmp_path: Path):
    """
    Zincirin baştan yeniden hesaplanması — zincirin tek gerçek zafiyeti.

    Saldırgan bir kaydı değiştirip sonraki bütün hash'leri yeniden yazıyor;
    verify_audit_chain() buna "sağlam" diyor. Çıpa demiyor.
    """
    capa = tmp_path / "anchor.log"
    ids = _log_many(db, 6)
    write_anchor(db.conn, "test", path=capa)

    # Saldırı: kaydı değiştir, sonra tüm zinciri baştan yeniden kur.
    db.conn.execute("UPDATE audit_log SET detail = 'temizlendi' WHERE id = ?", (ids[2],))
    db.conn.commit()
    _rebuild_chain(db)

    assert verify_audit_chain(db.conn).ok is True      # zincir kendi içinde tutarlı
    kontrol = verify_against_anchor(db.conn, path=capa)
    assert not kontrol
    assert any("yeniden yazılmış" in p for p in kontrol.problems)


def _rebuild_chain(db) -> None:
    """Saldırganın yapacağı şey: bütün hash'leri baştan yeniden hesapla."""
    start = chain_start_id(db.conn)
    prev = GENESIS_HASH
    rows = db.fetchall(
        f"SELECT {', '.join(FIELD_ORDER)} FROM audit_log WHERE id >= ? ORDER BY id",
        (start,),
    )
    for row in rows:
        entry = {alan: row[alan] for alan in FIELD_ORDER}
        prev = compute_entry_hash(prev, entry)
        db.conn.execute(
            "UPDATE audit_log SET entry_hash = ? WHERE id = ?", (prev, row["id"])
        )
    db.conn.commit()


def test_verify_against_anchor_is_neutral_when_no_anchor_exists(db, tmp_path: Path):
    kontrol = verify_against_anchor(db.conn, path=tmp_path / "yok.log")
    assert kontrol.anchors_checked == 0
    assert "yok" in kontrol.summary()


def test_daily_anchor_writes_once_per_day(db, tmp_path: Path, monkeypatch):
    from datetime import datetime, timezone

    from CORE import audit_chain

    capa = tmp_path / "anchor.log"
    gun1 = datetime(2026, 8, 13, 9, 0, tzinfo=timezone.utc)
    gun2 = datetime(2026, 8, 14, 9, 0, tzinfo=timezone.utc)

    monkeypatch.setattr(audit_chain, "_utcnow", lambda: gun1)
    assert maybe_write_daily_anchor(db.conn, path=capa) is not None
    assert maybe_write_daily_anchor(db.conn, path=capa) is None  # aynı gün → yazma
    _log_many(db, 2)
    assert maybe_write_daily_anchor(db.conn, path=capa) is None  # hâlâ aynı gün

    monkeypatch.setattr(audit_chain, "_utcnow", lambda: gun2)
    assert maybe_write_daily_anchor(db.conn, path=capa) is not None

    kayitlar = read_anchors(capa)
    assert len(kayitlar) == 2
    assert kayitlar[0]["anchored_at"].startswith("2026-08-13")
    assert kayitlar[1]["anchored_at"].startswith("2026-08-14")


def test_shutdown_anchor_is_written_even_on_the_same_day(db, tmp_path: Path, monkeypatch):
    """Günlük çıpa varken bile kapanış çıpası yazılmalı — write_anchor koşulsuzdur."""
    from datetime import datetime, timezone

    from CORE import audit_chain

    capa = tmp_path / "anchor.log"
    monkeypatch.setattr(
        audit_chain, "_utcnow", lambda: datetime(2026, 8, 13, 9, 0, tzinfo=timezone.utc)
    )
    maybe_write_daily_anchor(db.conn, path=capa)
    write_anchor(db.conn, "shutdown", path=capa)

    assert [k["reason"] for k in read_anchors(capa)] == ["daily", "shutdown"]


def test_anchor_file_has_its_own_verifiable_chain(db, tmp_path: Path):
    capa = tmp_path / "anchor.log"
    for tur in ("startup", "daily", "shutdown"):
        _log_many(db, 2)
        write_anchor(db.conn, tur, path=capa)

    kontrol = verify_anchor_file(capa)
    assert kontrol
    assert kontrol.anchors_checked == 3


def test_editing_an_anchor_line_breaks_the_anchor_file_chain(db, tmp_path: Path):
    capa = tmp_path / "anchor.log"
    for tur in ("startup", "daily", "shutdown"):
        _log_many(db, 2)
        write_anchor(db.conn, tur, path=capa)

    # Ortadaki satırı, sanki daha az kayıt varmış gibi düzenle.
    satirlar = capa.read_text(encoding="utf-8").splitlines()
    kayit = json.loads(satirlar[1])
    kayit["last_id"] = 1
    satirlar[1] = json.dumps(kayit, sort_keys=True, separators=(",", ":"))
    capa.write_text("\n".join(satirlar) + "\n", encoding="utf-8")

    kontrol = verify_anchor_file(capa)
    assert not kontrol
    assert any("Satır 3" in p for p in kontrol.problems)  # sonraki satırın prev'i tutmaz


def test_write_anchor_returns_none_on_an_empty_chain(db, tmp_path: Path):
    db.execute("DELETE FROM audit_log")
    assert write_anchor(db.conn, "test", path=tmp_path / "anchor.log") is None


# ══════════════════════════════════════════════════════════════════════════════
# 9. Yazma yolunun bütünlüğü
# ══════════════════════════════════════════════════════════════════════════════


def test_append_entry_hashes_the_stored_row_not_the_arguments(db):
    """
    id ve timestamp'i veritabanı üretiyor; hash SAKLANAN satırdan hesaplanmalı.

    Bu testin koruduğu şey: biri bir gün hash'i INSERT öncesi Python
    değerlerinden hesaplamaya kalkarsa, id/timestamp uyuşmadığı için
    doğrulama anında kırılır.
    """
    yeni_id = append_entry(db.conn, "kontrol", detail="detay")
    row = db.fetchone(
        f"SELECT {', '.join(FIELD_ORDER)}, entry_hash FROM audit_log WHERE id = ?",
        (yeni_id,),
    )
    entry = {alan: row[alan] for alan in FIELD_ORDER}
    onceki = db.fetchone(
        "SELECT entry_hash FROM audit_log"
        " WHERE id < ? AND entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1",
        (yeni_id,),
    )
    prev = onceki["entry_hash"] if onceki else GENESIS_HASH
    assert compute_entry_hash(prev, entry) == row["entry_hash"]


def test_append_entry_leaves_no_transaction_open(db):
    append_entry(db.conn, "kontrol")
    assert db.conn.in_transaction is False


def test_append_entry_rolls_back_on_failure(db):
    """Hash yazılamazsa kayıt da kalmamalı — hash'siz yarım satır bırakılmaz."""
    onceki = db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"]
    with pytest.raises(sqlite3.IntegrityError):
        append_entry(db.conn, None)  # action NOT NULL
    assert db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"] == onceki
    assert db.conn.in_transaction is False
    assert verify_audit_chain(db.conn).ok is True


def test_chain_survives_a_reopened_database(tmp_path: Path):
    """Zincir bağlantı ömrünü aşmalı — kalıcılık testi."""
    from DB.db_manager import DBManager

    yol = tmp_path / "kalici.db"

    DBManager._instance = None
    ilk = DBManager(yol)
    ilk.connect(hwid="TEST-HWID")
    _log_many(ilk, 3)
    ilk_son = verify_audit_chain(ilk.conn).last_hash
    ilk.close()
    DBManager._instance = None

    ikinci = DBManager(yol)
    ikinci.connect(hwid="TEST-HWID")
    try:
        _log_many(ikinci, 3, prefix="ikinci_oturum")
        sonuc = verify_audit_chain(ikinci.conn)
        assert sonuc.ok is True
        assert sonuc.checked == 7          # genesis + 3 + 3
        assert sonuc.last_hash != ilk_son  # zincir ilerledi
    finally:
        ikinci.close()
        DBManager._instance = None


def test_verification_result_is_falsy_when_broken(db):
    ids = _log_many(db, 3)
    db.conn.execute("DELETE FROM audit_log WHERE id = ?", (ids[0],))
    db.conn.commit()
    sonuc = verify_audit_chain(db.conn)
    assert isinstance(sonuc, ChainVerification)
    assert not sonuc
    assert "KIRIK" in sonuc.summary()


# ══════════════════════════════════════════════════════════════════════════════
# 9. link_status / link_statuses — HALKA sütunu (UI/AuditLogView.py)
# ══════════════════════════════════════════════════════════════════════════════
#
# Bu bölüm YENİ bir hash hesaplaması SINAMIYOR — `link_status()` hiçbiri
# hesaplamıyor, yalnızca `verify_audit_chain()`'in ZATEN ürettiği
# `ChainVerification`'ı satır bazında okuyor. Sınanan şey bu OKUMANIN
# doğruluğu: yukarıdaki bölümlerin tamamının kanıtladığı zincir davranışı
# (modified kırılmadan SONRAKİ kayıtların etkilenmemesi, gap'in bir
# SONRAKİ kaydın modified'ına dönüşmesi) burada satır-durumuna doğru
# yansıyor mu.


def test_saglam_zincirde_TUM_kayitlar_intact(db):
    ids = _log_many(db, 5)
    sonuc = verify_audit_chain(db.conn)
    durumlar = link_statuses(sonuc, ids)
    assert set(durumlar.values()) == {LINK_INTACT}


def test_degistirilen_kayit_BROKEN_ondan_SONRAKILER_INTACT(db):
    """
    `test_modifying_a_record_does_not_cascade_to_later_records`'ın satır
    durumuna yansıması: yalnızca değiştirilen kayıt kırık, ne öncekiler
    ne SONRAKİLER — zincir kırılmadan sonra saklanan hash'ten devam
    ediyor (bkz. `verify_audit_chain()` docstring'i).
    """
    ids = _log_many(db, 8)
    kurban = ids[3]
    db.conn.execute("UPDATE audit_log SET detail = 'degisti' WHERE id = ?", (kurban,))
    db.conn.commit()

    sonuc = verify_audit_chain(db.conn)
    durumlar = link_statuses(sonuc, ids)

    assert durumlar[kurban] == LINK_BROKEN
    for entry_id in ids:
        if entry_id != kurban:
            assert durumlar[entry_id] == LINK_INTACT, (
                f"id={entry_id} kırık gösterildi ama kendi hash'i doğru"
            )


def test_gap_SONRAKI_kayit_BROKEN_gosteriliyor(db):
    """`test_deleted_middle_record_is_caught_as_gap_and_break`'in HALKA
    karşılığı: silinen kaydın kendisi görünür bile değil, ama boşluktan
    sonraki ilk kayıt kırık işaretlenmeli."""
    ids = _log_many(db, 8)
    silinen = ids[4]
    sonraki = ids[5]
    db.conn.execute("DELETE FROM audit_log WHERE id = ?", (silinen,))
    db.conn.commit()

    sonuc = verify_audit_chain(db.conn)
    kalanlar = [i for i in ids if i != silinen]
    durumlar = link_statuses(sonuc, kalanlar)

    assert durumlar[sonraki] == LINK_BROKEN
    assert durumlar[ids[3]] == LINK_INTACT, "boşluktan ÖNCEki kayıt etkilenmemeli"


def test_zincir_baslangicindan_ONCEKI_kayitlar_OUT_OF_SCOPE(legacy_db):
    """Zincir başlamadan önce yazılmış (göç öncesi) kayıtlar ne sağlam ne
    kırık — hiç DOĞRULANMADI. `LINK_INTACT` demek yanlış güven verirdi."""
    eski_id = legacy_db.fetchone("SELECT MIN(id) AS id FROM audit_log")["id"]
    start = ensure_chain_started(legacy_db.conn)
    assert eski_id < start, "test verisi zincir öncesi bir kayıt varsaymıyor"

    sonuc = verify_audit_chain(legacy_db.conn)
    assert link_status(sonuc, eski_id) == LINK_OUT_OF_SCOPE


def test_zincir_HIC_baslamamissa_HER_SEY_OUT_OF_SCOPE(db):
    """`start_id is None` (no_chain) durumunda tek bilinen şey "hiç
    doğrulanmadı" — kırık DEĞİL, kapsam dışı."""
    ids = _log_many(db, 3)
    # audit_log_start_id ayarını ve genesis kaydını KALDIR — zincir hiç
    # başlamamış gibi davran.
    db.conn.execute("DELETE FROM settings WHERE key = ?", (CHAIN_START_SETTING,))
    db.conn.execute("DELETE FROM audit_log WHERE action = ?", (GENESIS_ACTION,))
    db.conn.commit()

    sonuc = verify_audit_chain(db.conn)
    assert sonuc.start_id is None
    for entry_id in ids:
        assert link_status(sonuc, entry_id) == LINK_OUT_OF_SCOPE


def test_link_statuses_bos_id_listesiyle_bos_donuyor(db):
    sonuc = verify_audit_chain(db.conn)
    assert link_statuses(sonuc, []) == {}


def test_link_status_YENI_hash_hesaplamiyor_SADECE_breaks_i_okuyor(db, monkeypatch):
    """
    Yapısal kanıt: `link_status()` `compute_entry_hash()`'i HİÇ
    çağırmamalı — kendi hash'ini üretmiyor, `verify_audit_chain()`'in
    zaten ürettiği sonucu okuyor. Çağırsaydı iki ayrı yerde aynı mantığın
    tekrarlanması (ve zamanla ayrışması) riski doğardı.
    """
    import CORE.audit_chain as modul

    cagrildi = False
    gercek = modul.compute_entry_hash

    def _casus(*a, **k):
        nonlocal cagrildi
        cagrildi = True
        return gercek(*a, **k)

    ids = _log_many(db, 4)
    sonuc = verify_audit_chain(db.conn)  # hash hesaplaması BURADA biter

    monkeypatch.setattr(modul, "compute_entry_hash", _casus)
    link_statuses(sonuc, ids)
    assert not cagrildi, "link_statuses() kendi hash hesaplamasını yapıyor"


# ══════════════════════════════════════════════════════════════════════════════
# 10. USB ikinci kopyası — çıpanın GERÇEK izolasyonu (B-090)
# ══════════════════════════════════════════════════════════════════════════════
#
# `isolate_usb_anchor` (tests/conftest.py, autouse) varsayılan olarak
# `CORE.usb_manager.get_usb_mount_root()`'u None'a SABİTLİYOR — bu dosyanın
# dışındaki HİÇBİR testin gerçek bir WMI sorgusu tetiklememesi (ve GERÇEK
# takılı bir USB'ye sessizce dosya yazmaması) için. Bu bölümdeki testler
# "USB takılı" durumunu SİMÜLE ETMEK üzere `sahte_usb_anchor` fixture'ıyla
# o fonksiyonu kendi içinde AYRICA monkeypatch'liyor — gerçek donanıma
# hiçbir testte dokunulmuyor. `get_usb_mount_root()`'un KENDİ WMI ayrıştırma
# mantığı `tests/test_usb_mount_root.py`'de ayrı ayrı kanıtlanıyor; burada
# ölçülen şey `CORE/audit_chain.py`'nin o fonksiyonu NASIL KULLANDIĞI.


#: `sahte_usb_anchor`'ın simüle ettiği USB'nin hwid'i — hem fixture'da hem
#: onu kullanan testlerde (session-hwid KARŞILAŞTIRMASI için) tek yerden.
SAHTE_USB_HWID = "SAHTE-USB-HWID"


@pytest.fixture
def sahte_usb_anchor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, db) -> Path:
    """
    "USB takılı" durumunu simüle eder: `get_usb_hwid()` sabit bir hwid,
    `get_usb_mount_root()` `tmp_path` altında sahte bir bağlama kökü
    döndürür. Döner değer o sahte bağlama kökü — testler USB anchor
    dosyasının GERÇEKTEN `<kök>/HYCLEUS/audit_anchor.log`'da durduğunu
    buradan doğrulayabilir.

    `usb_tokens` tablosuna da KAYITLI, KARA LİSTEYE ALINMAMIŞ bir satır
    ekler: `write_anchor()`'ın B-090 takip çapraz-doğrulaması artık
    (`_usb_hwid_dogrulanmis_mi()`) `source` ham bir `sqlite3.Connection`
    olduğunda (bu dosyadaki testlerin EZİCİ çoğunluğu `write_anchor(db.conn,
    ...)` kullanıyor — DBManager'ın KENDİSİNİ değil) tam olarak bu tabloya
    bakıyor. Bu satır OLMADAN, bu fixture'ı kullanan HER test USB yazımının
    (haklı olarak) ATLANDIĞINI görürdü — DOĞRULANMAMIŞ bir hwid için.
    """
    from CORE import usb_manager

    kok = tmp_path / "sahte_usb_koku"
    kok.mkdir()
    monkeypatch.setattr(usb_manager, "get_usb_hwid", lambda: SAHTE_USB_HWID)
    monkeypatch.setattr(usb_manager, "get_usb_mount_root", lambda hwid: kok)
    db.execute(
        "INSERT INTO usb_tokens (hwid, share_2) VALUES (?, ?)",
        (SAHTE_USB_HWID, "sahte-share-2-degeri"),
    )
    return kok


def _usb_capa_yolu(kok: Path) -> Path:
    return kok / "HYCLEUS" / "audit_anchor.log"


def test_usb_anchor_path_none_when_no_usb_present(db) -> None:
    """Varsayılan (autouse) durumda — USB simüle edilmemiş — None döner."""
    assert usb_anchor_path() is None
    assert usb_anchor_path(hwid="HERHANGI-BIR-HWID") is None


def test_usb_anchor_path_resolves_under_the_mount_root(sahte_usb_anchor: Path) -> None:
    assert usb_anchor_path() == _usb_capa_yolu(sahte_usb_anchor)


def test_usb_anchor_path_explicit_hwid_skips_get_usb_hwid(
    monkeypatch: pytest.MonkeyPatch, sahte_usb_anchor: Path
) -> None:
    """`hwid=` verilince `get_usb_hwid()`'in HİÇ çağrılmaması gerekiyor —
    çağrılırsa test patlar."""
    from CORE import usb_manager

    def _patlar():
        raise AssertionError("get_usb_hwid() çağrılmamalıydı — hwid zaten verildi")

    monkeypatch.setattr(usb_manager, "get_usb_hwid", _patlar)
    assert usb_anchor_path(hwid="ELLE-VERILEN-HWID") == _usb_capa_yolu(sahte_usb_anchor)


def test_write_anchor_writes_an_identical_second_copy_to_usb(
    db, tmp_path: Path, sahte_usb_anchor: Path
) -> None:
    """
    B-090'ın çekirdek iddiası: USB takılıyken `write_anchor()` YEREL diske
    yazdığı kaydın AYNI DB-türetilmiş içeriğini (last_id/last_hash/
    entry_count/chain_start_id/reason/anchored_at) USB'ye de yazar.
    """
    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 5)

    yerel_kayit = write_anchor(db.conn, "test", path=yerel_capa)
    assert yerel_kayit is not None

    usb_kayitlari = read_anchors(_usb_capa_yolu(sahte_usb_anchor))
    assert len(usb_kayitlari) == 1
    usb_kayit = usb_kayitlari[0]

    for alan in (
        "last_id", "last_hash", "entry_count", "chain_start_id", "reason", "anchored_at",
    ):
        assert usb_kayit[alan] == yerel_kayit[alan], f"{alan} iki kopyada farklı"

    # Her dosya kendi seq/prev_anchor_hash zincirine sahip — ikisi de İLK
    # satır olduğu için burada seq=1/GENESIS PAYLAŞILIYOR ama bu bir
    # tesadüf: aşağıdaki test dosyaların BAĞIMSIZ zincirlere sahip
    # olduğunu (farklı seq'lerle) kanıtlıyor.
    assert usb_kayit["seq"] == 1
    assert usb_kayit["prev_anchor_hash"] == GENESIS_HASH


def test_write_anchor_usb_and_local_keep_independent_seq_chains(
    db, tmp_path: Path, sahte_usb_anchor: Path
) -> None:
    """
    USB, İKİNCİ yazımda takılı DEĞİLSE (best-effort — bkz. write_anchor()
    docstring'i) yerel dosya 2 satıra, USB dosyası 1 satırda kalır; SONRAKİ
    bir yazımda USB tekrar takılıyken o dosyanın `seq`'i KENDİ satır
    sayısından devam eder (2 değil, 2 — çünkü 1 satırı vardı), yerelinkinden
    BAĞIMSIZ.
    """
    from CORE import usb_manager

    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 2)
    write_anchor(db.conn, "birinci", path=yerel_capa)  # USB takılı

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(usb_manager, "get_usb_mount_root", lambda hwid: None)
        _log_many(db, 2)
        write_anchor(db.conn, "ikinci", path=yerel_capa)  # USB TAKILI DEĞİL
    finally:
        monkeypatch.undo()

    _log_many(db, 2)
    write_anchor(db.conn, "ucuncu", path=yerel_capa)  # USB tekrar takılı

    yerel_kayitlar = read_anchors(yerel_capa)
    usb_kayitlar = read_anchors(_usb_capa_yolu(sahte_usb_anchor))

    assert [k["reason"] for k in yerel_kayitlar] == ["birinci", "ikinci", "ucuncu"]
    assert [k["seq"] for k in yerel_kayitlar] == [1, 2, 3]

    # USB'de yalnızca "ikinci" atlanmış İKİ kayıt var, ama KENDİ seq'i 1, 2.
    assert [k["reason"] for k in usb_kayitlar] == ["birinci", "ucuncu"]
    assert [k["seq"] for k in usb_kayitlar] == [1, 2]


def test_write_anchor_usb_absent_does_not_block_local_write(db, tmp_path: Path) -> None:
    """USB hiç simüle edilmemiş (autouse fixture None'a sabitliyor) —
    yerel yazım yine de başarılı olmalı, hiçbir USB dosyası oluşmamalı."""
    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 3)

    kayit = write_anchor(db.conn, "test", path=yerel_capa)
    assert kayit is not None
    assert yerel_capa.exists()
    # Testin kendi tmp_path'i dışında hiçbir yere yazılmadığını dolaylı
    # doğrulamanın bir yolu yok — ama en azından "HYCLEUS" adlı bir alt
    # klasör tmp_path altında OLUŞMAMALI (usb_anchor_path() None döndüğü
    # için hiç denenmedi).
    assert not any(tmp_path.rglob("HYCLEUS"))


def test_write_anchor_usb_write_failure_does_not_break_local_write(
    monkeypatch: pytest.MonkeyPatch, db, tmp_path: Path
) -> None:
    """
    USB'ye yazma HERHANGİ bir nedenle patlarsa (burada: bağlama kökü
    olarak verilen yol aslında bir DOSYA, dizin değil — `mkdir()` bu
    yüzden `NotADirectoryError`/`OSError` fırlatır) yerel kopya YİNE DE
    yazılmalı ve `write_anchor()` hiçbir istisna FIRLATMAMALI.

    hwid'i BİLEREK `usb_tokens`'a KAYITLI ediyor: kayıtlı OLMASAYDI bu
    senaryo B-090 takibinin çapraz-doğrulaması (`_usb_hwid_dogrulanmis_mi()`)
    tarafından dosya yoluna hiç ULAŞMADAN atlanırdı — o zaman bu test asıl
    ölçmek istediği şeyi (yazma HATASININ yerel kopyayı etkilememesi) değil,
    doğrulama reddini ölçerdi.
    """
    from CORE import usb_manager

    bozuk_kok = tmp_path / "bozuk_usb_koku"
    bozuk_kok.write_text("ben bir dosyayım, dizin değilim", encoding="utf-8")
    monkeypatch.setattr(usb_manager, "get_usb_hwid", lambda: "X")
    monkeypatch.setattr(usb_manager, "get_usb_mount_root", lambda hwid: bozuk_kok)
    db.execute("INSERT INTO usb_tokens (hwid, share_2) VALUES ('X', 's')")

    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 3)

    kayit = write_anchor(db.conn, "test", path=yerel_capa)  # İSTİSNA FIRLATMAMALI

    assert kayit is not None
    assert len(read_anchors(yerel_capa)) == 1


def test_write_usb_false_skips_usb_copy_even_if_available(
    db, tmp_path: Path, sahte_usb_anchor: Path
) -> None:
    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 2)

    write_anchor(db.conn, "test", path=yerel_capa, write_usb=False)

    assert not _usb_capa_yolu(sahte_usb_anchor).exists()


# ── verify_anchor_replicas() — iki kopyayı KARŞILAŞTIRMAK ─────────────────────


def test_verify_anchor_replicas_ok_when_both_copies_match(
    db, tmp_path: Path, sahte_usb_anchor: Path
) -> None:
    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 4)
    write_anchor(db.conn, "startup", path=yerel_capa)
    _log_many(db, 2)
    write_anchor(db.conn, "shutdown", path=yerel_capa)

    sonuc = verify_anchor_replicas(
        local_path=yerel_capa, usb_path=_usb_capa_yolu(sahte_usb_anchor)
    )
    assert sonuc
    assert sonuc.anchors_checked == 2
    assert sonuc.problems == []


def test_verify_anchor_replicas_neutral_when_usb_copy_missing(db, tmp_path: Path) -> None:
    """USB kopyası hiç yoksa — 'tutarlı' DEĞİL 'ölçülmedi': ok=True ama
    anchors_checked=0, `verify_against_anchor()`'ın aynı ayrımıyla TUTARLI."""
    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 3)
    write_anchor(db.conn, "test", path=yerel_capa)

    sonuc = verify_anchor_replicas(
        local_path=yerel_capa, usb_path=tmp_path / "yok" / "audit_anchor.log"
    )
    assert sonuc.anchors_checked == 0
    assert sonuc.ok is True
    assert "bulunamadı" in sonuc.summary() or "yok" in sonuc.summary()


def test_verify_anchor_replicas_neutral_when_local_copy_missing(
    db, tmp_path: Path, sahte_usb_anchor: Path
) -> None:
    """Simetrik durum: yerel kopya yoksa da aynı şekilde 'ölçülmedi'."""
    _log_many(db, 3)
    write_anchor(db.conn, "test", path=tmp_path / "yerel.log", usb_path=_usb_capa_yolu(sahte_usb_anchor))

    sonuc = verify_anchor_replicas(
        local_path=tmp_path / "hic_yazilmadi.log", usb_path=_usb_capa_yolu(sahte_usb_anchor)
    )
    assert sonuc.anchors_checked == 0
    assert sonuc.ok is True


def test_verify_anchor_replicas_different_lengths_still_ok_on_overlap(
    db, tmp_path: Path, sahte_usb_anchor: Path
) -> None:
    """
    USB, en SON yazımda takılı DEĞİLDİ (best-effort) — yerel dosyada 3,
    USB dosyasında 2 kayıt var. Bu SAYI farkı TEK BAŞINA bir tutarsızlık
    DEĞİL: karşılaştırma yalnızca ORTAK ÖNEĞE bakmalı ve orada hiçbir
    fark bulmamalı.
    """
    from CORE import usb_manager

    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 2)
    write_anchor(db.conn, "birinci", path=yerel_capa)
    _log_many(db, 2)
    write_anchor(db.conn, "ikinci", path=yerel_capa)

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(usb_manager, "get_usb_mount_root", lambda hwid: None)
        _log_many(db, 2)
        write_anchor(db.conn, "ucuncu", path=yerel_capa)  # USB TAKILI DEĞİL
    finally:
        monkeypatch.undo()

    sonuc = verify_anchor_replicas(
        local_path=yerel_capa, usb_path=_usb_capa_yolu(sahte_usb_anchor)
    )
    assert sonuc
    assert sonuc.anchors_checked == 2  # yalnızca ortak önek
    assert sonuc.problems == []


def _usb_capa_satirini_degistir(usb_capa: Path, index: int, **degisiklikler) -> None:
    """USB anchor dosyasının `index`'inci (0-tabanlı) JSON satırını,
    saldırganın dosyaya doğrudan erişimini simüle ederek değiştirir."""
    satirlar = usb_capa.read_text(encoding="utf-8").splitlines()
    kayit = json.loads(satirlar[index])
    kayit.update(degisiklikler)
    satirlar[index] = json.dumps(kayit, sort_keys=True, separators=(",", ":"))
    usb_capa.write_text("\n".join(satirlar) + "\n", encoding="utf-8")


def test_verify_anchor_replicas_catches_usb_copy_tampered(
    db, tmp_path: Path, sahte_usb_anchor: Path
) -> None:
    """
    B-090'ın asıl kanıtı: USB kopyası TEK BAŞINA (yereldeki dosyaya hiç
    dokunmadan) değiştirilirse, iki dosyanın kendi iç zinciri
    (`verify_anchor_file()`) hâlâ SAĞLAM görünür — saldırgan yalnızca o
    TEK dosyanın içeriğini değiştirdi, o dosyanın kendi seq/
    prev_anchor_hash zinciri bozulmadı. Bunu yakalayan TEK şey yerelle
    KARŞILAŞTIRMAKTIR.
    """
    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 4)
    write_anchor(db.conn, "test", path=yerel_capa)
    usb_capa = _usb_capa_yolu(sahte_usb_anchor)

    # USB'nin kendi iç zinciri hâlâ sağlam — sahte bir last_hash yazıldı.
    _usb_capa_satirini_degistir(usb_capa, 0, last_hash="0" * 64)

    assert verify_anchor_file(usb_capa), "tamponlama testi hatalı kuruldu — bu SAĞLAM olmalıydı"

    sonuc = verify_anchor_replicas(local_path=yerel_capa, usb_path=usb_capa)
    assert not sonuc
    assert sonuc.anchors_checked == 1
    assert any("last_hash" in p and "Satır 1" in p for p in sonuc.problems)


def test_verify_anchor_replicas_catches_local_copy_tampered(
    db, tmp_path: Path, sahte_usb_anchor: Path
) -> None:
    """Simetrik durum: bu sefer YEREL kopya tek başına değiştiriliyor —
    karşılaştırma hangi tarafın değiştiğine bakmaksızın farkı yakalamalı."""
    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 4)
    write_anchor(db.conn, "test", path=yerel_capa)

    satirlar = yerel_capa.read_text(encoding="utf-8").splitlines()
    kayit = json.loads(satirlar[0])
    kayit["entry_count"] = 999
    satirlar[0] = json.dumps(kayit, sort_keys=True, separators=(",", ":"))
    yerel_capa.write_text("\n".join(satirlar) + "\n", encoding="utf-8")

    assert verify_anchor_file(yerel_capa), "tamponlama testi hatalı kuruldu — bu SAĞLAM olmalıydı"

    sonuc = verify_anchor_replicas(
        local_path=yerel_capa, usb_path=_usb_capa_yolu(sahte_usb_anchor)
    )
    assert not sonuc
    assert any("entry_count" in p and "Satır 1" in p for p in sonuc.problems)


def test_verify_anchor_replicas_multiple_rows_only_tampered_one_flagged(
    db, tmp_path: Path, sahte_usb_anchor: Path
) -> None:
    """Birden fazla satır varken yalnızca DEĞİŞEN satır raporlanmalı —
    dokunulmayanlar hakkında YANLIŞ bir şikayet üretilmemeli."""
    yerel_capa = tmp_path / "yerel.log"
    for tur in ("birinci", "ikinci", "ucuncu"):
        _log_many(db, 2)
        write_anchor(db.conn, tur, path=yerel_capa)
    usb_capa = _usb_capa_yolu(sahte_usb_anchor)

    _usb_capa_satirini_degistir(usb_capa, 1, last_id=1)  # yalnızca ORTADAKİ satır

    sonuc = verify_anchor_replicas(local_path=yerel_capa, usb_path=usb_capa)
    assert not sonuc
    assert sonuc.anchors_checked == 3
    assert len(sonuc.problems) == 1
    assert "Satır 2" in sonuc.problems[0]


# ══════════════════════════════════════════════════════════════════════════════
# 11. USB hwid çapraz-doğrulaması — çoklu-USB / yanlış-eşleşme koruması
#     (B-090 takibi)
# ══════════════════════════════════════════════════════════════════════════════
#
# `get_usb_mount_root(hwid)`'in KENDİSİ — VERİLEN bir hwid'i doğru sürücüye
# eşleştirmesi — `tests/test_usb_mount_root.py::
# test_birden_fazla_usb_dogru_olani_seciyor`'da ZATEN kanıtlanmış: iki USB
# takılıyken her hwid KENDİ sürücü harfine eşleşiyor, çapraz eşleşme yok.
#
# Ama bu, `write_anchor()`'ın `get_usb_hwid()`'DEN aldığı hwid'in DOĞRU
# hwid olduğunu KANITLAMIYOR. `get_usb_hwid()` o an takılı USB'lerin WMI
# numaralandırma SIRASINDAKİ İLKİNİ döndürüyor — bu OTURUMUN kendi token'ı
# olduğu GARANTİ değil. Aynı anda BİRDEN FAZLA kayıtlı USB takılıysa (iki
# yönetici token'ı, ya da bu oturumun token'ı çıkarılıp BAŞKA bir kayıtlı
# token takılmışsa) `get_usb_hwid()` BAŞKA bir kullanıcının hwid'ini
# döndürebilir ve `get_usb_mount_root()` o zaman "doğru" ama YANLIŞ bir
# sürücüye KUSURSUZ biçimde eşleşir — ÇAPRAZ-KONTAMİNASYON: bu oturumun
# denetim çıpası BAŞKA BİR KULLANICININ USB'sine yazılır. Bu bölüm, o
# ikinci — çağıran-seviyesi — boşluğu kapatan `_usb_hwid_dogrulanmis_mi()`
# çapraz-kontrolünü ölçüyor.


class _SahteDBManager:
    """`._hwid` taşıyan asgari bir DBManager sahtesi — `.conn`'u GERÇEK
    bir bağlantıya (fixture'ın `db.conn`'una) devrediyor, yalnızca
    `_usb_hwid_dogrulanmis_mi()`'nin `getattr(source, "_hwid", None)`
    okuduğu GÜÇLÜ katmanı izole test edebilmek için."""

    def __init__(self, conn: sqlite3.Connection, hwid: str | None) -> None:
        self.conn = conn
        self._hwid = hwid


def test_usb_hwid_dogrulanmis_mi_guclu_katman_eslesirse_true(db) -> None:
    from CORE.audit_chain import _usb_hwid_dogrulanmis_mi

    kaynak = _SahteDBManager(db.conn, hwid="OTURUM-HWID")
    assert _usb_hwid_dogrulanmis_mi(db.conn, "OTURUM-HWID", kaynak) is True


def test_usb_hwid_dogrulanmis_mi_guclu_katman_BASKA_kayitli_hwid_bile_olsa_false(
    db,
) -> None:
    """
    ÇEKİRDEK iddia: oturumun KENDİ hwid'i biliniyorsa, `usb_tokens`da
    KAYITLI olması bile BAŞKA bir hwid'i kurtarmaz. Güçlü katman zayıf
    katmandan (tablo üyeliği) ÖNCELİKLİ — "kayıtlı bir USB" ile "BU
    oturumun USB'si" AYNI ŞEY DEĞİL.
    """
    from CORE.audit_chain import _usb_hwid_dogrulanmis_mi

    db.execute("INSERT INTO usb_tokens (hwid, share_2) VALUES ('BASKA-HWID', 's')")
    kaynak = _SahteDBManager(db.conn, hwid="OTURUM-HWID")
    assert _usb_hwid_dogrulanmis_mi(db.conn, "BASKA-HWID", kaynak) is False


def test_usb_hwid_dogrulanmis_mi_zayif_katman_kayitliysa_true(db) -> None:
    """`source`'un hwid'i bilinmiyorsa (ham `sqlite3.Connection`) —
    `usb_tokens`da kayıtlı ve kara listede DEĞİLSE doğrulanır."""
    from CORE.audit_chain import _usb_hwid_dogrulanmis_mi

    db.execute("INSERT INTO usb_tokens (hwid, share_2) VALUES ('KAYITLI-HWID', 's')")
    assert _usb_hwid_dogrulanmis_mi(db.conn, "KAYITLI-HWID", db.conn) is True


def test_usb_hwid_dogrulanmis_mi_zayif_katman_kayitsizsa_false(db) -> None:
    from CORE.audit_chain import _usb_hwid_dogrulanmis_mi

    assert _usb_hwid_dogrulanmis_mi(db.conn, "HIC-KAYITLI-DEGIL", db.conn) is False


def test_usb_hwid_dogrulanmis_mi_zayif_katman_kara_listedeyse_false(db) -> None:
    from CORE.audit_chain import _usb_hwid_dogrulanmis_mi

    db.execute(
        "INSERT INTO usb_tokens (hwid, share_2, blacklisted) VALUES ('KARA-LISTE', 's', 1)"
    )
    assert _usb_hwid_dogrulanmis_mi(db.conn, "KARA-LISTE", db.conn) is False


# ── write_anchor() ile UÇTAN UCA — B-090 takip görevinin 2. ve 4b maddesi ─────


def test_write_anchor_usb_skipped_when_hwid_unregistered(
    monkeypatch: pytest.MonkeyPatch, db, tmp_path: Path
) -> None:
    """
    Zayıf katman (ham bağlantı, hwid tabloda YOK) — USB kopyası ATLANMALI,
    yerel kopya ETKİLENMEMELİ. Bu, görevin 2. maddesindeki "sessizce
    başarısız olma" riskinin (a) — çıpanın hiç yazılmaması — GÜVENLİ
    tarafta kaldığını kanıtlıyor: fark edilmez ama en azından YANLIŞ bir
    cihaza da yazılmaz.
    """
    from CORE import usb_manager

    kok = tmp_path / "kayitsiz_usb"
    kok.mkdir()
    monkeypatch.setattr(usb_manager, "get_usb_hwid", lambda: "KAYITSIZ-HWID")
    monkeypatch.setattr(usb_manager, "get_usb_mount_root", lambda hwid: kok)

    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 3)
    kayit = write_anchor(db.conn, "test", path=yerel_capa)

    assert kayit is not None
    assert len(read_anchors(yerel_capa)) == 1
    assert not (kok / "HYCLEUS" / "audit_anchor.log").exists()


def test_write_anchor_usb_skipped_when_hwid_blacklisted(
    monkeypatch: pytest.MonkeyPatch, db, tmp_path: Path
) -> None:
    from CORE import usb_manager

    db.execute(
        "INSERT INTO usb_tokens (hwid, share_2, blacklisted) VALUES ('KARALISTE', 's', 1)"
    )
    kok = tmp_path / "karalisteli_usb"
    kok.mkdir()
    monkeypatch.setattr(usb_manager, "get_usb_hwid", lambda: "KARALISTE")
    monkeypatch.setattr(usb_manager, "get_usb_mount_root", lambda hwid: kok)

    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 3)
    kayit = write_anchor(db.conn, "test", path=yerel_capa)

    assert kayit is not None
    assert not (kok / "HYCLEUS" / "audit_anchor.log").exists()


def test_write_anchor_usb_written_when_session_hwid_matches(
    monkeypatch: pytest.MonkeyPatch, db, tmp_path: Path
) -> None:
    """Güçlü katman POZİTİF: `write_anchor(db, ...)` — `db`'nin KENDİSİ
    (ham `.conn`'u değil) geçirilince, o an takılı USB'nin hwid'i
    `db._hwid`'le eşleşiyorsa `usb_tokens`da KAYITLI olması bile GEREKMEZ."""
    from CORE import usb_manager

    kok = tmp_path / "kendi_usbm"
    kok.mkdir()
    monkeypatch.setattr(usb_manager, "get_usb_hwid", lambda: db._hwid)
    monkeypatch.setattr(usb_manager, "get_usb_mount_root", lambda hwid: kok)

    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 3)
    write_anchor(db, "test", path=yerel_capa)

    assert (kok / "HYCLEUS" / "audit_anchor.log").exists()


def test_write_anchor_usb_skipped_cross_user_even_if_registered(
    monkeypatch: pytest.MonkeyPatch, db, tmp_path: Path
) -> None:
    """
    B-090 takibinin ÇEKİRDEK senaryosu — görevin 2. maddesindeki (b) riski:
    "başka bir kullanıcının/oturumun USB'sine yazma."

    Kurulum: BU oturumun kendi hwid'i `db._hwid`'dir (fixture'da
    "TEST-HWID-DB" olarak sabit). AYRICA, `usb_tokens`da BAŞKA bir
    kullanıcının GERÇEKTEN kayıtlı, kara listede OLMAYAN bir hwid'i var —
    yani zayıf katman TEK BAŞINA bunu geçerdi. O an takılı USB — ne
    olursa olsun `get_usb_hwid()`'in bulduğu — bu OTURUMUN kendi token'ı
    DEĞİL, o BAŞKA kullanıcının token'ı (ör. token'lar fiziksel olarak
    karışmış, ya da iki kayıtlı USB aynı anda takılıyken WMI sırası
    bunu ilk buldu).

    `write_anchor(db, ...)` — `db`'nin KENDİSİ geçirildiği için güçlü
    katman devrede — USB yazımını REDDETMELİ, `usb_tokens` kaydı
    "geçerli" görünse bile. Reddetmezse: bu oturumun denetim çıpası
    BAŞKA BİR KULLANICININ fiziksel USB'sine yazılırdı.
    """
    from CORE import usb_manager

    hwid_baskasi = "BASKA-KULLANICININ-HWIDI"
    db.execute(
        "INSERT INTO usb_tokens (hwid, share_2) VALUES (?, 's')", (hwid_baskasi,)
    )

    baskasinin_usbsi = tmp_path / "baskasinin_usbsi"
    baskasinin_usbsi.mkdir()
    monkeypatch.setattr(usb_manager, "get_usb_hwid", lambda: hwid_baskasi)
    monkeypatch.setattr(usb_manager, "get_usb_mount_root", lambda hwid: baskasinin_usbsi)

    yerel_capa = tmp_path / "yerel.log"
    _log_many(db, 3)

    kayit = write_anchor(db, "test", path=yerel_capa)  # db KENDİSİ

    assert kayit is not None
    assert len(read_anchors(yerel_capa)) == 1  # yerel kopya ETKİLENMEDİ
    assert not (baskasinin_usbsi / "HYCLEUS" / "audit_anchor.log").exists(), (
        "BAŞKA KULLANICININ USB'sine yazıldı — çapraz-kontaminasyon YAKALANMADI"
    )
