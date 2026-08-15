"""
CORE.duplicates — tekrar tespiti testleri.

Kapsam kararlarının hepsi ayrı ayrı sınanıyor, çünkü her biri bir TASARIM
KARARI ve hiçbiri "doğal" değil: İmha Odası hariç, Karantina dâhil, mahrem
etiketliler yönetici olmayana görünmez.

En kritik test grubu 4. bölüm: tekrar tespitinin bir SORGULAMA ARACINA
dönüşmediğini kanıtlıyor. O filtre olmasa, yükleme ekranı listeleme
ekranının sakladığı bilgiyi sızdıran bir kanal olurdu.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from CORE.duplicates import (
    EXCLUDED_LABEL,
    DuplicateMatch,
    find_duplicates_by_hash,
    find_duplicates_for_file,
    format_duplicate_warning,
    log_duplicate_decision,
    sha256_of_file,
)

_ICERIK = b"Yonetim Kurulu Karari 2026/14\n" * 40
_SHA = hashlib.sha256(_ICERIK).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# Yardımcılar
# ══════════════════════════════════════════════════════════════════════════════


def _dosya(db, ad: str, sha: str | None = _SHA, *, label: str = "Genel",
           folder_id: int | None = None) -> int:
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label, original_sha256, folder_id)"
        " VALUES (?, ?, ?, ?, ?)",
        (ad, f"/kasa/{ad}.hcl", label, sha, folder_id),
    )
    return int(cur.lastrowid)


def _klasor(db, ad: str) -> int:
    db.execute(
        "INSERT OR IGNORE INTO users (id, username, password_hash, role, status, hwid)"
        " VALUES (1, 'test', '', 'admin', 'approved', 'H')"
    )
    cur = db.execute("INSERT INTO folders (name, owner_id) VALUES (?, 1)", (ad,))
    return int(cur.lastrowid)


def _etiketle(db, file_id: int, ad: str, *, private: bool = False) -> None:
    cur = db.execute(
        "INSERT INTO tags (name, color, is_private) VALUES (?, '#fff', ?)",
        (ad, 1 if private else 0),
    )
    db.execute(
        "INSERT INTO file_tags (file_id, tag_id) VALUES (?, ?)",
        (file_id, cur.lastrowid),
    )


@pytest.fixture
def belge(tmp_path: Path) -> Path:
    p = tmp_path / "karar.docx"
    p.write_bytes(_ICERIK)
    return p


# ══════════════════════════════════════════════════════════════════════════════
# 1. Özet hesabı
# ══════════════════════════════════════════════════════════════════════════════


def test_the_hash_matches_what_encrypt_file_records(tmp_path: Path, belge: Path) -> None:
    """
    ASIL BAĞ: bu modülün ürettiği özet, `encrypt_file()`'ın AAD'ye ve
    `files.original_sha256`'ya yazdığıyla AYNI olmalı. Farklı olsalardı
    tekrar tespiti hiçbir zaman eşleşme bulamazdı.
    """
    from CORE import crypto
    from CORE.crypto import encrypt_file, generate_key

    cikti = tmp_path / "q"
    cikti.mkdir()
    crypto._QUARANTINE_DIR = cikti
    try:
        _hcl, kaydedilen, _aad = encrypt_file(belge, generate_key(), 1, hwid="H")
    finally:
        crypto._QUARANTINE_DIR = Path(__file__).parent.parent / "data" / "quarantine"

    assert sha256_of_file(belge) == kaydedilen == _SHA


def test_the_hash_is_of_the_plaintext_not_the_path(tmp_path: Path) -> None:
    """Aynı içerik, farklı ad → aynı özet. Tekrar tespitinin tüm dayanağı bu."""
    a = tmp_path / "karar.docx"
    b = tmp_path / "KARAR-kopya (2).docx"
    a.write_bytes(_ICERIK)
    b.write_bytes(_ICERIK)
    assert sha256_of_file(a) == sha256_of_file(b)


def test_a_single_byte_difference_changes_the_hash(tmp_path: Path) -> None:
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(_ICERIK)
    b.write_bytes(_ICERIK[:-1] + b"X")
    assert sha256_of_file(a) != sha256_of_file(b)


def test_hashing_handles_files_larger_than_one_chunk(tmp_path: Path) -> None:
    """64 KB blok sınırını aşan dosyada blok döngüsü doğru çalışmalı."""
    p = tmp_path / "buyuk.bin"
    veri = bytes(range(256)) * 2000  # 512 000 B
    p.write_bytes(veri)
    assert sha256_of_file(p) == hashlib.sha256(veri).hexdigest()


def test_an_empty_file_hashes_to_the_empty_digest(tmp_path: Path) -> None:
    p = tmp_path / "bos.txt"
    p.write_bytes(b"")
    assert sha256_of_file(p) == hashlib.sha256(b"").hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# 2. Eşleşme / eşleşmeme
# ══════════════════════════════════════════════════════════════════════════════


def test_identical_content_is_matched(db) -> None:
    _dosya(db, "karar")
    (esl,) = find_duplicates_by_hash(db, _SHA)
    assert esl.filename == "karar"


def test_different_content_is_not_matched(db) -> None:
    _dosya(db, "karar")
    baska = hashlib.sha256(b"tamamen baska bir belge").hexdigest()
    assert find_duplicates_by_hash(db, baska) == []


def test_an_empty_vault_matches_nothing(db) -> None:
    assert find_duplicates_by_hash(db, _SHA) == []


def test_all_copies_are_returned_not_just_one(db) -> None:
    """
    Aynı belge birden fazla yerde olabilir; kullanıcıya HEPSİ gösterilmeli.
    Tek eşleşme döndürmek "başka nerede var" sorusunu yanıtsız bırakırdı —
    fonksiyonun çoğul adlandırılmasının sebebi bu.
    """
    _dosya(db, "karar-genel")
    _dosya(db, "karar-arsiv")
    _dosya(db, "karar-yedek")
    assert len(find_duplicates_by_hash(db, _SHA)) == 3


def test_records_without_a_hash_never_match(db) -> None:
    """
    `original_sha256` eski kayıtlarda NULL. NULL bir özetle eşleşmemeli,
    yoksa özeti olmayan tüm eski dosyalar birbirinin tekrarı sayılırdı.
    """
    _dosya(db, "eski", sha=None)
    _dosya(db, "eski2", sha=None)
    assert find_duplicates_by_hash(db, _SHA) == []


def test_an_empty_hash_argument_returns_nothing(db) -> None:
    _dosya(db, "karar", sha="")
    assert find_duplicates_by_hash(db, "") == []


def test_find_for_file_hashes_and_searches(db, belge: Path) -> None:
    _dosya(db, "karar")
    sha, esl = find_duplicates_for_file(db, belge)
    assert sha == _SHA
    assert len(esl) == 1


# ══════════════════════════════════════════════════════════════════════════════
# 3. Kapsam kararları — hangi dosyalar sayılıyor
# ══════════════════════════════════════════════════════════════════════════════


def test_files_in_the_destruction_room_are_excluded(db) -> None:
    """
    KARAR: imhaya gönderilmiş bir belge "zaten kayıtlı" saymıyor.

    Kullanıcı belgeyi bilerek imhaya göndermiş ve şimdi yeniden ekliyor
    olabilir — yani tam olarak yapmak İSTEDİĞİ şeyi yapıyor. Uyarı, doğru
    eylemi sorgulatırdı.
    """
    _dosya(db, "imha-edilen", label=EXCLUDED_LABEL)
    assert find_duplicates_by_hash(db, _SHA) == []


def test_only_the_destruction_copy_is_excluded(db) -> None:
    """İmhadaki kopya elenirken kasadaki sağlam kopya görünmeye devam etmeli."""
    _dosya(db, "imhadaki", label="Imha")
    _dosya(db, "duran", label="Genel")
    (esl,) = find_duplicates_by_hash(db, _SHA)
    assert esl.filename == "duran"


def test_quarantined_files_are_included(db) -> None:
    """
    KARAR: karantinadaki dosya DÂHİL — hatta en değerli uyarı bu.

    "Bu içerik zaten karantinada" bilgisi, Defender'ın işaretlediği bir
    belgenin farkında olmadan yeniden yüklenmesini engelliyor.
    """
    _dosya(db, "supheli", label="Karantina")
    (esl,) = find_duplicates_by_hash(db, _SHA)
    assert esl.label == "Karantina"


@pytest.mark.parametrize("label", ["Genel", "Kritik", "Karantina"])
def test_every_live_label_is_included(db, label: str) -> None:
    _dosya(db, f"dosya-{label}", label=label)
    assert len(find_duplicates_by_hash(db, _SHA)) == 1


# ══════════════════════════════════════════════════════════════════════════════
# 4. Mahrem etiket — tekrar tespiti bir sorgulama aracı OLMAMALI
# ══════════════════════════════════════════════════════════════════════════════


def test_a_private_match_is_hidden_from_non_admins(db) -> None:
    """
    ASIL GÜVENLİK TESTİ.

    Yönetici olmayan biri, eline geçirdiği bir belgeyi sürükleyip "bu belge
    zaten 'Yönetim Kurulu' klasöründe kayıtlı" uyarısını görebilseydi,
    görme yetkisi olmayan bir belgenin VARLIĞINI ve YERİNİ öğrenirdi.
    Elindeki her adayı deneyerek kasayı haritalayabilirdi.
    """
    fid = _dosya(db, "gizli-karar")
    _etiketle(db, fid, "Yönetim", private=True)

    assert find_duplicates_by_hash(db, _SHA, include_private=False) == []


def test_an_admin_still_sees_the_private_match(db) -> None:
    fid = _dosya(db, "gizli-karar")
    _etiketle(db, fid, "Yönetim", private=True)

    (esl,) = find_duplicates_by_hash(db, _SHA, include_private=True)
    assert esl.filename == "gizli-karar"


def test_the_default_hides_private_matches(db) -> None:
    """
    Varsayılan GÜVENLİ taraf olmalı: parametreyi geçmeyi unutan bir çağrı
    yeri sızdırmasın.
    """
    fid = _dosya(db, "gizli")
    _etiketle(db, fid, "Mahrem", private=True)
    assert find_duplicates_by_hash(db, _SHA) == []


def test_a_non_private_tag_does_not_hide_anything(db) -> None:
    fid = _dosya(db, "acik-belge")
    _etiketle(db, fid, "Muhasebe", private=False)
    assert len(find_duplicates_by_hash(db, _SHA)) == 1


def test_a_public_copy_still_warns_when_a_private_copy_exists(db) -> None:
    """
    Aynı içerik hem mahrem hem açık bir kopyada duruyorsa, yönetici olmayan
    kullanıcı AÇIK olanı görmeli — gizlenen tek şey mahrem kopya.
    """
    gizli = _dosya(db, "gizli-kopya")
    _etiketle(db, gizli, "Yönetim", private=True)
    _dosya(db, "acik-kopya")

    esl = find_duplicates_by_hash(db, _SHA, include_private=False)
    assert [m.filename for m in esl] == ["acik-kopya"]


# ══════════════════════════════════════════════════════════════════════════════
# 5. Uyarı içeriği — "nerede kayıtlı" sorusunun cevabı
# ══════════════════════════════════════════════════════════════════════════════


def test_the_folder_name_is_reported(db) -> None:
    fid = _klasor(db, "2026 Kararlar")
    _dosya(db, "karar", folder_id=fid)
    (esl,) = find_duplicates_by_hash(db, _SHA)
    assert esl.folder_name == "2026 Kararlar"
    assert "2026 Kararlar" in esl.location()


def test_the_tags_are_reported(db) -> None:
    fid = _dosya(db, "karar")
    _etiketle(db, fid, "Muhasebe")
    _etiketle(db, fid, "Onaylı")
    (esl,) = find_duplicates_by_hash(db, _SHA)
    assert set(esl.tags) == {"Muhasebe", "Onaylı"}
    assert "Muhasebe" in esl.location()


def test_a_file_with_neither_folder_nor_tag_falls_back_to_its_label(db) -> None:
    """Konum bilgisi her zaman olmalı — hiçbiri yoksa sekme adı kalıyor."""
    _dosya(db, "karar", label="Kritik")
    (esl,) = find_duplicates_by_hash(db, _SHA)
    assert esl.folder_name is None
    assert esl.tags == ()
    assert "Kritik" in esl.location()


def test_newest_matches_come_first(db) -> None:
    db.execute(
        "INSERT INTO files (filename, filepath, label, original_sha256, added_at)"
        " VALUES ('eski', '/a.hcl', 'Genel', ?, '2020-01-01T00:00:00Z')", (_SHA,))
    db.execute(
        "INSERT INTO files (filename, filepath, label, original_sha256, added_at)"
        " VALUES ('yeni', '/b.hcl', 'Genel', ?, '2026-01-01T00:00:00Z')", (_SHA,))
    assert [m.filename for m in find_duplicates_by_hash(db, _SHA)] == ["yeni", "eski"]


def test_the_warning_text_names_the_file_and_the_location() -> None:
    metin = format_duplicate_warning("karar.docx", [
        DuplicateMatch(1, "karar", "Genel", "2026 Kararlar", ("Muhasebe",), "2026-01-01"),
    ])
    assert "karar.docx" in metin
    assert "2026 Kararlar" in metin
    assert "Muhasebe" in metin


def test_the_warning_text_counts_multiple_matches() -> None:
    metin = format_duplicate_warning("k.docx", [
        DuplicateMatch(1, "a", "Genel", None, (), "2026-01-01"),
        DuplicateMatch(2, "b", "Genel", None, (), "2026-01-02"),
    ])
    assert "2 belge" in metin


def test_no_matches_produces_no_warning() -> None:
    assert format_duplicate_warning("k.docx", []) == ""


# ══════════════════════════════════════════════════════════════════════════════
# 6. Uyarı ENGELLEYİCİ DEĞİL
# ══════════════════════════════════════════════════════════════════════════════


def test_finding_a_duplicate_does_not_prevent_adding_it(db, belge: Path) -> None:
    """
    ASIL DAVRANIŞ: tespit bir UYARI, bir kilit değil.

    CORE tarafında bunun anlamı şu: `find_duplicates_by_hash()` yalnızca
    bilgi döndürüyor — istisna fırlatmıyor, hiçbir şeyi engellemiyor ve
    kaydı yazan `record_encrypted_file()` ondan haberdar bile değil.
    Mükerrer kayıt yazılabiliyor ve İKİ kayıt birden duruyor.
    """
    from CORE.file_records import record_encrypted_file

    _dosya(db, "ilk-kopya")
    assert len(find_duplicates_by_hash(db, _SHA)) == 1

    ikinci = record_encrypted_file(
        db, filename="ikinci-kopya", filepath="/kasa/ikinci.hcl",
        label="Genel", original_sha256=_SHA,
    )
    assert ikinci > 0

    esl = find_duplicates_by_hash(db, _SHA)
    assert len(esl) == 2
    assert {m.filename for m in esl} == {"ilk-kopya", "ikinci-kopya"}


def test_the_core_function_never_raises_on_a_duplicate(db) -> None:
    """Tespit bir hata değil; istisna fırlatmak akışı kilitlerdi."""
    _dosya(db, "kopya")
    find_duplicates_by_hash(db, _SHA)  # istisna yok


# ══════════════════════════════════════════════════════════════════════════════
# 7. Denetim kaydı
# ══════════════════════════════════════════════════════════════════════════════


def test_adding_anyway_is_audited(db) -> None:
    """
    "Bu belge neden iki kez var" sorusunun cevabı bir yerde durmalı: kayıt,
    kullanıcının uyarıyı GÖRÜP bilerek devam ettiğini gösteriyor.
    """
    _dosya(db, "kopya")
    esl = find_duplicates_by_hash(db, _SHA)
    log_duplicate_decision(db, filename="karar.docx", sha256=_SHA,
                           matches=esl, added_anyway=True)

    row = db.fetchone(
        "SELECT action, detail FROM audit_log ORDER BY id DESC LIMIT 1")
    assert row["action"] == "duplicate_added_anyway"
    assert "karar.docx" in row["detail"]


def test_skipping_is_audited_differently(db) -> None:
    _dosya(db, "kopya")
    log_duplicate_decision(db, filename="k.docx", sha256=_SHA,
                           matches=find_duplicates_by_hash(db, _SHA),
                           added_anyway=False)
    row = db.fetchone("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1")
    assert row["action"] == "duplicate_skipped"


def test_the_audit_entry_joins_the_hash_chain(db) -> None:
    """
    Denetim kaydı `db.log()` üzerinden gidiyor, yani hash zincirine
    giriyor — doğrudan INSERT edilseydi zincir dışı kalırdı.
    """
    log_duplicate_decision(db, filename="k.docx", sha256=_SHA,
                           matches=[], added_anyway=True)
    row = db.fetchone(
        "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    assert row["entry_hash"]


def test_the_full_hash_is_not_written_to_the_audit_log(db) -> None:
    """
    Kayda özetin yalnızca ilk 16 hanesi giriyor. Denetim kaydı şifresiz bir
    tabloda duruyor (SECURITY.md §3) ve tam SHA-256, bir belgeyi çözmeden
    DOĞRULAMAYA yarıyor — yani düz metin özeti orada gereğinden fazla bilgi.
    Kısaltılmış hâli iki kaydı ilişkilendirmeye yetiyor.
    """
    log_duplicate_decision(db, filename="k.docx", sha256=_SHA,
                           matches=[], added_anyway=True)
    detail = db.fetchone(
        "SELECT detail FROM audit_log ORDER BY id DESC LIMIT 1")["detail"]
    assert _SHA not in detail
    assert _SHA[:16] in detail


# ══════════════════════════════════════════════════════════════════════════════
# 8. İndeks
# ══════════════════════════════════════════════════════════════════════════════


def test_the_hash_column_is_indexed(db) -> None:
    """
    Tekrar tespiti her yüklemede bu sütunu sorguluyor; indekssiz her dosya
    tam tablo taraması demek olurdu.
    """
    adlar = {r["name"] for r in db.fetchall("PRAGMA index_list(files)")}
    assert "idx_files_sha256" in adlar


def test_the_query_actually_uses_the_index(db) -> None:
    """
    İndeksin VAR olması yetmez, sorgunun onu KULLANMASI gerekir. Sorgu
    plana bakılarak doğrulanıyor — `WHERE` koşulu bir fonksiyona sarılsa
    ya da sütun tipi değişse indeks sessizce devre dışı kalırdı.
    """
    for i in range(50):
        _dosya(db, f"d{i}", sha=hashlib.sha256(f"{i}".encode()).hexdigest())
    plan = " ".join(
        r["detail"] for r in db.fetchall(
            "EXPLAIN QUERY PLAN SELECT id FROM files"
            " WHERE original_sha256 = ? AND label <> 'Imha'", (_SHA,))
    )
    # İki ayrı iddia. Yalnızca ada bakmak yetmiyor: adı aynı önekle
    # başlayan BAŞKA bir indeks ("idx_files_sha256_x" gibi) alt dize
    # kontrolünü geçerdi. "SCAN files" tam tablo taraması demek — asıl
    # kaçınılan şey o.
    assert "idx_files_sha256" in plan, plan
    assert "SCAN files" not in plan, f"tam tablo taraması yapılıyor: {plan}"
