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
    SERIALIZATION_VERSION,
    ChainVerification,
    anchor_path,
    append_entry,
    canonical_bytes,
    chain_start_id,
    compute_entry_hash,
    ensure_chain_started,
    maybe_write_daily_anchor,
    read_anchors,
    verify_against_anchor,
    verify_anchor_file,
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
