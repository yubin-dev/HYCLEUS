"""
CORE.backup — şifreli yedekleme ve doğrulanabilir geri yükleme testleri.

Dört tasarım kararının her biri ayrı ayrı sınanıyor:

  1. `.hcl` dosyaları OLDUĞU GİBİ kopyalanıyor (bayt-bayt aynı)
  2. Veritabanı ŞİFRELENİYOR — yedekte hiçbir yerde düz metin tablo yok
  3. Anahtar kasası (`.hclv`) yedeğe GİRMİYOR
  4. `verify_backup()` bozulmayı GERİ YÜKLEMEDEN yakalıyor

En sıkı grup 3. bölüm: yedeğin içinde düz metin sızıntısı OLMADIĞINI
kanıtlıyor. Bu iddia bir docstring cümlesi olarak kalamaz — yedek harici
bir diske yazılıyor ve harici disk tam olarak kaybolan şey.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from CORE import crypto
from CORE.backup import (
    EXCLUDED_TABLES,
    FORMAT,
    MANIFEST_NAME,
    METADATA_NAME,
    REFERENCE_TABLES,
    RESTORABLE_TABLES,
    BackupError,
    apply_metadata,
    create_backup,
    default_backup_name,
    latest_backup,
    read_manifest,
    restore_backup,
    verify_backup,
)
from CORE.crypto import encrypt_file, generate_key

_USER = 3
_HWID = "TEST-HWID-BK"

#: Yedekte ARANMAYACAK sızıntı işaretleri — hepsi gerçek verilerin içine
#: bilerek gömülüyor, sonra bütün yedek baytlarında aranıyor.
_GIZLI_AD = "COK-GIZLI-SOZLESME"
_GIZLI_ETIKET = "MAHREM-ETIKET-XYZ"
_GIZLI_KLASOR = "YONETIM-KURULU-KLASORU"
_GIZLI_DENETIM = "DENETIM-IZI-GIZLI-DETAY"

#: `.hcl` adı → DÜZ METİN SHA-256. `vault` fixture'ı dolduruyor.
#: Ciphertext özetiyle karıştırılmamalı: manifesto ciphertext'inkini
#: taşıyor, düz metninki manifestoda ARANMAYAN değer.
_PLAINTEXT_SHA: dict[str, str] = {}


@pytest.fixture
def key() -> bytes:
    return generate_key()


@pytest.fixture
def vault(tmp_path: Path, key: bytes, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Üç `.hcl` dosyası içeren bir kasa dizini."""
    q = tmp_path / "quarantine"
    q.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", q)
    _PLAINTEXT_SHA.clear()

    for ad, icerik in (
        (f"{_GIZLI_AD}.txt", b"birinci belge icerigi\n" * 30),
        ("rapor.txt", b"ikinci belge\n" * 20),
        ("notlar.txt", b"ucuncu belge\n" * 10),
    ):
        src = tmp_path / ad
        src.write_bytes(icerik)
        hcl, sha, _aad = encrypt_file(src, key, _USER, hwid=_HWID)
        _PLAINTEXT_SHA[hcl.name] = sha
        src.unlink()
    return q


@pytest.fixture
def dolu_db(db, vault: Path):
    """Yedeklenecek metadata'yı taşıyan veritabanı."""
    db.execute(
        "INSERT INTO users (id, username, password_hash, role, status, hwid)"
        " VALUES (3, 'gizli_kullanici', 'ARGON2-HASH-GIZLI', 'admin', 'approved', ?)",
        (_HWID,))
    db.execute("INSERT INTO folders (id, name, owner_id) VALUES (1, ?, 3)",
               (_GIZLI_KLASOR,))
    db.execute("INSERT INTO tags (id, name, color, is_private) VALUES (1, ?, '#f00', 1)",
               (_GIZLI_ETIKET,))
    for i, p in enumerate(sorted(vault.glob("*.hcl")), start=1):
        db.execute(
            "INSERT INTO files (id, filename, filepath, label, original_sha256,"
            " size_bytes, folder_id) VALUES (?, ?, ?, 'Genel', ?, ?, 1)",
            (i, p.stem, str(p), _PLAINTEXT_SHA[p.name], p.stat().st_size))
    db.execute("INSERT INTO file_tags (file_id, tag_id) VALUES (1, 1)")
    db.execute(
        "INSERT INTO retention_profiles (name, duration_value, duration_unit,"
        " start_type, legal_basis) VALUES ('KVKK-5yil', 5, 'yil', 'yukleme_tarihi', 'KVKK')")
    db.log("test_event", user_id=3, detail=_GIZLI_DENETIM)
    return db


def _yedek(dolu_db, vault: Path, tmp_path: Path, key: bytes, **kw):
    return create_backup(
        dolu_db, tmp_path / "yedek", key, vault_dir=vault,
        user_id=_USER, hwid=_HWID, **kw)


def _tum_baytlar(root: Path) -> bytes:
    """Yedekteki HER dosyanın baytları — sızıntı taraması için."""
    parcalar = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            parcalar.append(p.name.encode("utf-8"))
            parcalar.append(p.read_bytes())
    return b"\n".join(parcalar)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Yedek alma
# ══════════════════════════════════════════════════════════════════════════════


def test_backup_copies_every_hcl(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)

    assert rapor.file_count == 3
    assert rapor.skipped == []
    kopyalar = sorted(p.name for p in (rapor.path / "files").glob("*.hcl"))
    assert kopyalar == sorted(p.name for p in vault.glob("*.hcl"))


def test_the_copies_are_byte_identical(dolu_db, vault, tmp_path, key) -> None:
    """
    KARAR 1: sarmalama şifrelemesi YOK. Kopyalar kaynağın aynısı olmalı;
    farklı olsalardı ya yeniden şifreleniyor ya bozuluyorlardı.
    """
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    for src in vault.glob("*.hcl"):
        assert (rapor.path / "files" / src.name).read_bytes() == src.read_bytes()


def test_the_manifest_describes_the_backup(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    manifest = read_manifest(rapor.path)

    assert manifest["format"] == FORMAT
    assert manifest["file_count"] == 3
    assert manifest["total_bytes"] == rapor.total_bytes
    assert len(manifest["entries"]) == 3
    assert manifest["metadata"]["name"] == METADATA_NAME


def test_manifest_hashes_are_of_the_ciphertext(dolu_db, vault, tmp_path, key) -> None:
    """
    Manifestodaki özet ŞİFRELİ dosyanın özeti; düz metnin DEĞİL.

    Düz metin özeti bir belgeyi çözmeden doğrulamaya yarıyor; onu düz
    metin bir manifestoya yazmak SECURITY.md §3'teki maruziyeti gereksiz
    yere çoğaltırdı.
    """
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    manifest = read_manifest(rapor.path)

    for girdi in manifest["entries"]:
        sifreli = (rapor.path / "files" / girdi["name"]).read_bytes()
        assert girdi["sha256"] == hashlib.sha256(sifreli).hexdigest()

    # Düz metin özetleri DB'de var; manifestoda olmamalı.
    ham = (rapor.path / MANIFEST_NAME).read_text(encoding="utf-8")
    for row in dolu_db.fetchall("SELECT original_sha256 FROM files"):
        assert row["original_sha256"] not in ham


def test_a_locked_file_is_skipped_not_fatal(dolu_db, vault, tmp_path, key,
                                            monkeypatch) -> None:
    """
    Eksik bir yedek, hiç yedek olmamasından iyidir — yeter ki EKSİK
    OLDUĞU görünsün. Atlanan dosya manifestoya da girmemeli, yoksa
    doğrulama her seferinde "eksik" derdi.
    """
    gercek = __import__("shutil").copy2

    def _bazen_patla(src, dst, *a, **kw):
        if "rapor" in str(src):
            raise OSError("dosya kilitli")
        return gercek(src, dst, *a, **kw)

    import CORE.backup as bk
    monkeypatch.setattr(bk.shutil, "copy2", _bazen_patla)

    rapor = _yedek(dolu_db, vault, tmp_path, key)
    assert len(rapor.skipped) == 1
    assert rapor.file_count == 2
    assert len(read_manifest(rapor.path)["entries"]) == 2
    assert verify_backup(rapor.path, key=key, hwid=_HWID).ok


def test_the_backup_is_audited(dolu_db, vault, tmp_path, key) -> None:
    _yedek(dolu_db, vault, tmp_path, key)
    row = dolu_db.fetchone("SELECT action, entry_hash FROM audit_log"
                           " ORDER BY id DESC LIMIT 1")
    assert row["action"] == "backup_created"
    assert row["entry_hash"], "denetim kaydı zincire girmeli"


def test_default_names_are_sortable() -> None:
    from datetime import datetime, timezone
    a = default_backup_name(now=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    b = default_backup_name(now=datetime(2026, 1, 2, 3, 4, 6, tzinfo=timezone.utc))
    assert a < b


def test_latest_backup_finds_the_newest(dolu_db, vault, tmp_path, key) -> None:
    kok = tmp_path / "hedef"
    for ad in ("hycleus-backup-1", "hycleus-backup-2"):
        create_backup(dolu_db, kok / ad, key, vault_dir=vault, hwid=_HWID)
    assert latest_backup(kok) is not None
    assert latest_backup(tmp_path / "yok") is None


# ══════════════════════════════════════════════════════════════════════════════
# 2. Metadata şifreleniyor
# ══════════════════════════════════════════════════════════════════════════════


def test_the_metadata_file_is_a_real_hcl(dolu_db, vault, tmp_path, key) -> None:
    from CORE.crypto import verify_file

    rapor = _yedek(dolu_db, vault, tmp_path, key)
    meta = rapor.path / METADATA_NAME
    assert meta.read_bytes()[:4] == b"HYCL"
    verify_file(meta, key, hwid=_HWID)   # GCM doğrulaması geçmeli


def test_the_metadata_carries_the_restorable_tables(dolu_db, vault, tmp_path, key) -> None:
    from CORE.backup import _read_metadata

    rapor = _yedek(dolu_db, vault, tmp_path, key)
    icerik = _read_metadata(rapor.path / METADATA_NAME, key, hwid=_HWID)

    assert set(icerik["tables"]) == set(RESTORABLE_TABLES)
    assert len(icerik["tables"]["files"]) == 3
    assert icerik["tables"]["folders"][0]["name"] == _GIZLI_KLASOR


def test_the_audit_log_is_backed_up_as_reference(dolu_db, vault, tmp_path, key) -> None:
    """Uyumluluk için saklanıyor ama geri yüklenebilir tablolar arasında değil."""
    from CORE.backup import _read_metadata

    rapor = _yedek(dolu_db, vault, tmp_path, key)
    icerik = _read_metadata(rapor.path / METADATA_NAME, key, hwid=_HWID)

    assert set(icerik["reference"]) == set(REFERENCE_TABLES)
    assert any(_GIZLI_DENETIM in (r.get("detail") or "")
               for r in icerik["reference"]["audit_log"])
    assert "audit_log" not in icerik["tables"]


def test_no_temporary_plaintext_dump_is_left(dolu_db, vault, tmp_path, key) -> None:
    """Geçici döküm güvenli silinmeli — içinde bütün envanter var."""
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    assert not (rapor.path / "_metadata.json").exists()
    assert sorted(p.name for p in rapor.path.iterdir()) == sorted(
        [MANIFEST_NAME, METADATA_NAME, "files"])


# ══════════════════════════════════════════════════════════════════════════════
# 3. SIZINTI TARAMASI — yedekte düz metin olmamalı
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("gizli", [
    _GIZLI_ETIKET, _GIZLI_KLASOR, _GIZLI_DENETIM,
    "ARGON2-HASH-GIZLI", "gizli_kullanici",
])
def test_database_contents_never_appear_in_the_backup(
    dolu_db, vault, tmp_path, key, gizli: str
) -> None:
    """
    ASIL GÜVENLİK TESTİ — KARAR 2.

    Veritabanı düz metin kopyalansaydı bu dizeler yedekte AÇIKÇA
    bulunurdu. Yedek harici bir diske yazılıyor ve harici disk tam olarak
    kaybolan şey; iddia bir docstring cümlesi olarak kalamaz.
    """
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    assert gizli.encode("utf-8") not in _tum_baytlar(rapor.path)


def test_the_sqlite_file_itself_is_not_copied(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    adlar = [p.name for p in rapor.path.rglob("*")]
    assert not any(a.endswith((".db", ".db-wal", ".db-shm")) for a in adlar)


def test_the_vault_key_file_is_not_backed_up(dolu_db, vault, tmp_path, key) -> None:
    """
    KARAR 3: `.hclv` yedeğe GİRMİYOR.

    İçinde Argon2id ile korunan `share_1` var; harici medyaya konsaydı
    onu ele geçiren biri çevrimdışı kaba kuvvet için hazır bir hedef
    bulurdu. Anahtar kaybı 2.1'in (Shamir) işi.
    """
    (vault.parent / "vaults").mkdir(exist_ok=True)
    (vault.parent / "vaults" / f"{_HWID}.hclv").write_bytes(b"SHARE1-GIZLI-VERI")

    rapor = _yedek(dolu_db, vault, tmp_path, key)
    assert not any(p.suffix == ".hclv" for p in rapor.path.rglob("*"))
    assert b"SHARE1-GIZLI-VERI" not in _tum_baytlar(rapor.path)


def test_excluded_tables_are_documented_and_absent(dolu_db, vault, tmp_path, key) -> None:
    from CORE.backup import _read_metadata

    rapor = _yedek(dolu_db, vault, tmp_path, key)
    icerik = _read_metadata(rapor.path / METADATA_NAME, key, hwid=_HWID)
    icinde = set(icerik["tables"]) | set(icerik["reference"])
    assert icinde.isdisjoint(EXCLUDED_TABLES)


def test_the_filenames_leak_exactly_what_the_vault_already_leaks(
    dolu_db, vault, tmp_path, key
) -> None:
    """
    KABUL EDİLEN SINIR — bir iddia değil, kayda geçirilen davranış.

    `.hcl` dosya adları kasadaki adların aynısı, yani belge adı yedekte
    de görünüyor. Bu YENİ bir sızıntı değil: aynı ad `.hcl` başlığındaki
    AAD'de de duruyor (SECURITY.md §3). Düzeltilecekse bu bir format
    değişikliği olur; o gün geldiğinde bu test bilinçli olarak güncellenir.
    """
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    adlar = [p.name for p in (rapor.path / "files").glob("*.hcl")]
    assert any(_GIZLI_AD in a for a in adlar)


# ══════════════════════════════════════════════════════════════════════════════
# 4. Doğrulama — GERİ YÜKLEMEDEN
# ══════════════════════════════════════════════════════════════════════════════


def test_a_healthy_backup_verifies_without_a_key(dolu_db, vault, tmp_path, key) -> None:
    """
    Anahtarsız çalışması önemli: yedeğin sağlamlığını kontrol etmek için
    kasayı açmak gerekmemeli (zamanlanmış bir betikten çağrılabilsin).
    """
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    sonuc = verify_backup(rapor.path)
    assert sonuc.ok and sonuc.checked == 3 and sonuc.deep is False


def test_a_healthy_backup_verifies_with_the_key(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    sonuc = verify_backup(rapor.path, key=key, hwid=_HWID)
    assert sonuc.ok and sonuc.deep is True


def test_a_missing_file_is_caught(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    kurban = next((rapor.path / "files").glob("*.hcl"))
    kurban.unlink()

    sonuc = verify_backup(rapor.path)
    assert not sonuc.ok
    assert sonuc.missing == [kurban.name]


def test_a_truncated_file_is_caught_without_a_key(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    kurban = next((rapor.path / "files").glob("*.hcl"))
    kurban.write_bytes(kurban.read_bytes()[:-50])

    sonuc = verify_backup(rapor.path)
    assert not sonuc.ok and sonuc.corrupt == [kurban.name]


def test_a_flipped_byte_is_caught_without_a_key(dolu_db, vault, tmp_path, key) -> None:
    """Boyut aynı kalıyor; yakalayan şey özet."""
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    kurban = next((rapor.path / "files").glob("*.hcl"))
    ham = bytearray(kurban.read_bytes())
    ham[len(ham) // 2] ^= 0xFF
    kurban.write_bytes(bytes(ham))

    sonuc = verify_backup(rapor.path)
    assert not sonuc.ok and sonuc.corrupt == [kurban.name]


def test_a_swapped_file_passes_hash_but_fails_gcm(dolu_db, vault, tmp_path, key) -> None:
    """
    Manifestoyla birlikte değiştirilen bir dosya özet kontrolünü GEÇER —
    anahtarsız doğrulamanın sınırı bu. GCM doğrulaması yakalıyor.
    """
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    kurban = next((rapor.path / "files").glob("*.hcl"))
    sahte = bytearray(kurban.read_bytes())
    sahte[-1] ^= 0xFF                       # GCM tag'i boz
    kurban.write_bytes(bytes(sahte))

    manifest = read_manifest(rapor.path)
    for g in manifest["entries"]:
        if g["name"] == kurban.name:
            g["sha256"] = hashlib.sha256(bytes(sahte)).hexdigest()
    (rapor.path / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")

    assert verify_backup(rapor.path).ok is True          # özet uyduruldu
    derin = verify_backup(rapor.path, key=key, hwid=_HWID)
    assert not derin.ok
    assert derin.auth_failed == [kurban.name]


def test_a_tampered_manifest_is_detected_with_the_key(dolu_db, vault, tmp_path, key) -> None:
    """
    Düz metin manifesto değiştirilebilir; şifreli kopya karşılaştırması
    bunu yakalıyor.
    """
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    manifest = read_manifest(rapor.path)
    manifest["entries"] = manifest["entries"][:1]   # iki girdi silindi
    (rapor.path / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")

    assert verify_backup(rapor.path).ok is True      # anahtarsız fark edemiyor
    derin = verify_backup(rapor.path, key=key, hwid=_HWID)
    assert derin.manifest_mismatch is True
    assert not derin.ok


def test_a_missing_metadata_file_is_caught(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    (rapor.path / METADATA_NAME).unlink()
    sonuc = verify_backup(rapor.path)
    assert not sonuc.ok and METADATA_NAME in sonuc.missing


def test_a_wrong_key_fails_deep_verification(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    sonuc = verify_backup(rapor.path, key=generate_key(), hwid=_HWID)
    assert not sonuc.ok
    assert len(sonuc.auth_failed) == 4      # 3 dosya + metadata


def test_a_missing_manifest_reports_cleanly(tmp_path) -> None:
    bos = tmp_path / "bos"
    bos.mkdir()
    sonuc = verify_backup(bos)
    assert not sonuc.ok and "Manifesto bulunamadı" in (sonuc.error or "")


def test_an_unknown_format_is_refused(tmp_path) -> None:
    d = tmp_path / "gelecek"
    d.mkdir()
    (d / MANIFEST_NAME).write_text('{"format": "HYCLEUS-BACKUP-V9"}', encoding="utf-8")
    sonuc = verify_backup(d)
    assert not sonuc.ok and "Desteklenmeyen yedek biçimi" in (sonuc.error or "")


# ══════════════════════════════════════════════════════════════════════════════
# 1b. B-097 — bozuk/kötü niyetli manifesto GÜVENLE reddediliyor, ÇÖKMÜYOR
# ══════════════════════════════════════════════════════════════════════════════
#
# `read_manifest()` yalnızca `json.loads()` + "format" alanı kontrolü
# yapıyordu — üst seviye nesnenin dict OLDUĞUNU, `entries`'in liste
# OLDUĞUNU ya da her girdinin gerekli alanları TAŞIDIĞINI hiç
# doğrulamıyordu. Aşağıdaki her senaryo, düzeltmeden ÖNCE
# `verify_backup()`'ı gerçek bir istisnayla (KeyError/TypeError/
# AttributeError) ÇÖKERTİYORDU — bu bölüm o çökmelerin artık temiz bir
# `BackupError`/`rapor.ok=False`'a döndüğünü kanıtlıyor. TAM bir JSON
# şeması DEĞİL (bkz. `CORE/backup.py::_manifest_sekli_gecersiz_mi`
# docstring'i) — riskin çoğunu ucuza kapatan basit bir boyut/tip kapısı.


def test_a_json_array_manifest_is_refused_not_crashed(tmp_path) -> None:
    """Üst seviye nesne dict değil (liste) — eskiden AttributeError'la çöküyordu."""
    d = tmp_path / "kotu1"
    d.mkdir()
    (d / MANIFEST_NAME).write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    sonuc = verify_backup(d)
    assert not sonuc.ok
    assert "Manifesto biçimi geçersiz" in (sonuc.error or "")


def test_entries_that_is_not_a_list_is_refused_not_crashed(tmp_path) -> None:
    """`entries` bir liste değil, bir string — eskiden TypeError'la çöküyordu."""
    d = tmp_path / "kotu2"
    d.mkdir()
    (d / MANIFEST_NAME).write_text(
        json.dumps({"format": FORMAT, "entries": "BEN-BIR-STRINGIM"}), encoding="utf-8")
    sonuc = verify_backup(d)
    assert not sonuc.ok
    assert "Manifesto biçimi geçersiz" in (sonuc.error or "")


def test_an_entry_that_is_not_an_object_is_refused_not_crashed(tmp_path) -> None:
    """`entries` içindeki bir öğe dict değil (sayı) — eskiden TypeError'la çöküyordu."""
    d = tmp_path / "kotu3"
    d.mkdir()
    (d / "files").mkdir()
    (d / MANIFEST_NAME).write_text(
        json.dumps({"format": FORMAT, "entries": [12345]}), encoding="utf-8")
    sonuc = verify_backup(d)
    assert not sonuc.ok
    assert "Manifesto biçimi geçersiz" in (sonuc.error or "")


def test_an_entry_missing_a_required_field_is_refused_not_crashed(tmp_path) -> None:
    """
    `size`/`sha256` eksik — dosya GERÇEKTEN var olduğu için eskiden
    `girdi["size"]` erişiminde KeyError'la çöküyordu (dosya yoksa
    `missing` listesine düşüp döngü erkenden `continue` ediyordu, yani
    bu çökme yalnızca GERÇEKTEN VAR olan bir dosyayla tetikleniyordu).
    """
    d = tmp_path / "kotu4"
    d.mkdir()
    (d / "files").mkdir()
    (d / "files" / "x.hcl").write_bytes(b"veri")
    (d / MANIFEST_NAME).write_text(
        json.dumps({"format": FORMAT, "entries": [{"name": "x.hcl"}]}), encoding="utf-8")
    sonuc = verify_backup(d)
    assert not sonuc.ok
    assert "Manifesto biçimi geçersiz" in (sonuc.error or "")


def test_an_entry_with_an_unexpected_field_type_is_refused_not_crashed(tmp_path) -> None:
    """`size` bir tam sayı değil, beklenmedik bir tipte (string) — güvenle reddedilmeli."""
    d = tmp_path / "kotu5"
    d.mkdir()
    (d / "files").mkdir()
    (d / "files" / "x.hcl").write_bytes(b"veri")
    (d / MANIFEST_NAME).write_text(
        json.dumps({
            "format": FORMAT,
            "entries": [{"name": "x.hcl", "size": "COK-BUYUK-BIR-DEGER", "sha256": "a" * 64}],
        }), encoding="utf-8")
    sonuc = verify_backup(d)
    assert not sonuc.ok
    assert "Manifesto biçimi geçersiz" in (sonuc.error or "")


def test_an_oversized_manifest_file_is_refused_without_being_fully_read(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Aşırı büyük bir manifesto dosyası — bozuk ya da kötü niyetli (JSON
    bombası) olabilir. Boyut, `json.loads()`'a HİÇ verilmeden reddediliyor.

    Gerçek üretim sınırı (10 MB) kadar bir dosya YAZMIYOR — bunun yerine
    sınırı küçük bir değere (100 bayt) indirip birkaç KB'lık, tamamen
    zararsız bir dosyayla aşıyor. Bu hem testi hızlı/güvenli tutuyor hem
    de sınırın KENDİ DEĞERİNDEN bağımsız olarak KARŞILAŞTIRMA MANTIĞININ
    (`boyut > _MANIFEST_MAX_BYTES`) çalıştığını kanıtlıyor.
    """
    import CORE.backup as bk

    monkeypatch.setattr(bk, "_MANIFEST_MAX_BYTES", 100)

    d = tmp_path / "kotu6"
    d.mkdir()
    # Geçerli JSON olması ŞART DEĞİL: boyut kontrolü ayrıştırmadan ÖNCE.
    (d / MANIFEST_NAME).write_bytes(b"1," * 200)  # 400 bayt > yamalı 100 bayt
    sonuc = verify_backup(d)
    assert not sonuc.ok
    assert "Manifesto çok büyük" in (sonuc.error or "")


def test_a_valid_manifest_still_passes_the_shape_check(dolu_db, vault, tmp_path, key) -> None:
    """Sağlamlaştırma gerçek/sağlıklı bir yedeği YANLIŞLIKLA reddetmiyor."""
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    manifest = read_manifest(rapor.path)  # istisna fırlatmamalı
    assert manifest["format"] == FORMAT
    sonuc = verify_backup(rapor.path)
    assert sonuc.ok is True


def test_extra_files_are_reported_but_not_an_error(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    (rapor.path / "files" / "yabanci.hcl").write_bytes(b"x")
    sonuc = verify_backup(rapor.path)
    assert sonuc.ok is True
    assert sonuc.extra == ["yabanci.hcl"]


def test_verification_writes_nothing(dolu_db, vault, tmp_path, key) -> None:
    """Doğrulama hiçbir şeye DOKUNMAMALI."""
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    once = {p: p.stat().st_mtime_ns for p in sorted(rapor.path.rglob("*")) if p.is_file()}
    verify_backup(rapor.path, key=key, hwid=_HWID)
    sonra = {p: p.stat().st_mtime_ns for p in sorted(rapor.path.rglob("*")) if p.is_file()}
    assert once == sonra


# ══════════════════════════════════════════════════════════════════════════════
# 4b. İlerleme ve iptal
# ══════════════════════════════════════════════════════════════════════════════
#
# Doğrulama her baytı okuyor (derin modda iki kez) ve yedeğin doğal yeri
# harici disk. Ölçüldü: işlemci tarafında ~1,3 GB/s, ama 120 MB/s bir
# diskte 50 GB'lık bir yedek on dakikaları buluyor. Durdurulamayan on
# dakikalık bir kontrol, çalıştırılmayan bir kontrole dönüşür.


def test_progress_reports_every_file_in_order(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    adimlar: list[tuple[int, int, str]] = []
    verify_backup(rapor.path, on_progress=lambda i, n, ad: adimlar.append((i, n, ad)))

    assert [i for i, _n, _ad in adimlar] == [1, 2, 3]
    assert {n for _i, n, _ad in adimlar} == {3}


def test_cancelling_stops_the_scan(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    gorulen: list[str] = []

    sonuc = verify_backup(
        rapor.path,
        on_progress=lambda i, n, ad: gorulen.append(ad),
        should_continue=lambda: len(gorulen) < 2,
    )
    assert sonuc.cancelled
    assert len(gorulen) == 2, "İptalden sonra dosya okunmaya devam etti."


def test_a_cancelled_scan_is_NOT_reported_as_healthy(
    dolu_db, vault, tmp_path, key,
) -> None:
    """
    En tehlikeli yanlış cevap bu olurdu.

    Yedek gerçekten sağlam; tarama ilk dosyada kesiliyor. `ok=True`
    dönseydi kullanıcı 500 dosyalık bir yedeği 1 dosyaya bakarak
    onaylamış olurdu ve rapordan bunu ayırt edemezdi.
    """
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    assert verify_backup(rapor.path).ok, "Yedek zaten sağlam olmalı."

    sonuc = verify_backup(rapor.path, should_continue=lambda: False)
    assert sonuc.cancelled is True
    assert sonuc.ok is False
    assert sonuc.checked == 0
    assert "YARIDA KESİLDİ" in sonuc.summary()


def test_total_says_how_much_was_NOT_looked_at(dolu_db, vault, tmp_path, key) -> None:
    """`checked` tek başına eksik: neyin dışında kaldığı bilinmeli."""
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    gorulen: list[str] = []
    sonuc = verify_backup(
        rapor.path,
        on_progress=lambda i, n, ad: gorulen.append(ad),
        should_continue=lambda: len(gorulen) < 1,
    )
    assert (sonuc.checked, sonuc.total) == (1, 3)


def test_total_is_filled_on_a_complete_scan_too(dolu_db, vault, tmp_path, key) -> None:
    sonuc = verify_backup(_yedek(dolu_db, vault, tmp_path, key).path)
    assert sonuc.total == sonuc.checked == 3


def test_verification_without_callbacks_behaves_as_before(
    dolu_db, vault, tmp_path, key,
) -> None:
    """
    Geriye dönük uyumluluk: CLI ve zamanlanmış çağrılar iki yeni
    parametreyi geçmiyor.
    """
    sonuc = verify_backup(_yedek(dolu_db, vault, tmp_path, key).path)
    assert sonuc.ok and not sonuc.cancelled


# ══════════════════════════════════════════════════════════════════════════════
# 5. Geri yükleme
# ══════════════════════════════════════════════════════════════════════════════


def test_restore_round_trips_byte_for_byte(dolu_db, vault, tmp_path, key) -> None:
    """ANA TEST: geri yüklenen dosyalar orijinalle bayt-bayt aynı olmalı."""
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    hedef = tmp_path / "geri"

    sonuc = restore_backup(rapor.path, hedef, key, hwid=_HWID)

    assert sonuc.restored == 3
    for src in vault.glob("*.hcl"):
        assert (hedef / "files" / src.name).read_bytes() == src.read_bytes()


def test_restored_files_still_decrypt(dolu_db, vault, tmp_path, key) -> None:
    """Bayt eşitliği yetmez — dosyalar hâlâ AÇILABİLMELİ."""
    from CORE.crypto import decrypt_file

    rapor = _yedek(dolu_db, vault, tmp_path, key)
    hedef = tmp_path / "geri"
    restore_backup(rapor.path, hedef, key, hwid=_HWID)

    for p in (hedef / "files").glob("*.hcl"):
        # B-092/B-099: original_sha256 artık AAD'de yok (meta bunu
        # taşımıyor) — asıl iddia zaten decrypt_file()'ın istisnasız
        # dönmesi ve içeriğin BOŞ olmaması.
        icerik, _meta = decrypt_file(p, key, hwid=_HWID)
        assert icerik


def test_restore_refuses_a_corrupt_backup(dolu_db, vault, tmp_path, key) -> None:
    """
    Doğrulama geri yüklemenin ÖNKOŞULU — bozuk bir yedeği açmaya
    çalışmak, geri dönülemez bir işlemi kusurlu veriyle yapmak olurdu.
    """
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    next((rapor.path / "files").glob("*.hcl")).unlink()
    hedef = tmp_path / "geri"

    with pytest.raises(BackupError, match="doğrulanamadı"):
        restore_backup(rapor.path, hedef, key, hwid=_HWID)
    assert not hedef.exists(), "başarısız geri yükleme hedefe dokunmamalı"


def test_restore_refuses_a_non_empty_destination(dolu_db, vault, tmp_path, key) -> None:
    """
    Geri yükleme geri alınamaz ve çoğu zaman panikle yapılıyor. Dolu bir
    dizine yazmak açık onay istiyor.
    """
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    hedef = tmp_path / "dolu"
    hedef.mkdir()
    (hedef / "onemli.txt").write_bytes(b"kaybolmamali")

    with pytest.raises(BackupError, match="boş değil"):
        restore_backup(rapor.path, hedef, key, hwid=_HWID)
    assert (hedef / "onemli.txt").read_bytes() == b"kaybolmamali"


def test_overwrite_is_explicit(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    hedef = tmp_path / "dolu"
    hedef.mkdir()
    (hedef / "eski.txt").write_bytes(b"x")

    sonuc = restore_backup(rapor.path, hedef, key, hwid=_HWID, overwrite=True)
    assert sonuc.restored == 3


def test_restore_never_touches_the_live_vault(dolu_db, vault, tmp_path, key) -> None:
    """Canlı kasa geri yüklemeden ETKİLENMEMELİ."""
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    once = {p.name: p.read_bytes() for p in vault.glob("*.hcl")}

    restore_backup(rapor.path, tmp_path / "geri", key, hwid=_HWID)

    assert {p.name: p.read_bytes() for p in vault.glob("*.hcl")} == once


def test_restore_never_touches_the_live_database(dolu_db, vault, tmp_path, key) -> None:
    """
    Metadata dosyaya yazılıyor, veritabanına DEĞİL. İkisini birleştirmek
    kullanıcının yedeği inceleme fırsatını elinden alırdı.
    """
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    once = dolu_db.fetchone("SELECT COUNT(*) AS n FROM files")["n"]

    restore_backup(rapor.path, tmp_path / "geri", key, hwid=_HWID)

    assert dolu_db.fetchone("SELECT COUNT(*) AS n FROM files")["n"] == once


def test_restore_writes_readable_metadata(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    hedef = tmp_path / "geri"
    sonuc = restore_backup(rapor.path, hedef, key, hwid=_HWID)

    tablolar = json.loads((hedef / "metadata.json").read_text(encoding="utf-8"))
    assert len(tablolar["files"]) == 3
    assert sonuc.metadata_tables["files"] == 3


def test_the_audit_log_is_written_separately(dolu_db, vault, tmp_path, key) -> None:
    """Okunabilir ama canlı zincire karışmıyor."""
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    hedef = tmp_path / "geri"
    sonuc = restore_backup(rapor.path, hedef, key, hwid=_HWID)

    assert "audit_log.json" in sonuc.reference_written
    kayitlar = json.loads((hedef / "audit_log.json").read_text(encoding="utf-8"))
    assert any(_GIZLI_DENETIM in (r.get("detail") or "") for r in kayitlar)
    assert "audit_log" not in json.loads(
        (hedef / "metadata.json").read_text(encoding="utf-8"))


# ══════════════════════════════════════════════════════════════════════════════
# 6. Metadata'yı canlı veritabanına uygulama
# ══════════════════════════════════════════════════════════════════════════════


def test_apply_metadata_restores_the_rows(dolu_db, vault, tmp_path, key, db) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    hedef = tmp_path / "geri"
    restore_backup(rapor.path, hedef, key, hwid=_HWID)
    tablolar = json.loads((hedef / "metadata.json").read_text(encoding="utf-8"))

    dolu_db.execute("DELETE FROM file_tags")
    dolu_db.execute("DELETE FROM files")
    assert dolu_db.fetchone("SELECT COUNT(*) AS n FROM files")["n"] == 0

    yazilan = apply_metadata(dolu_db, tablolar, user_id=_USER)

    assert yazilan["files"] == 3
    assert dolu_db.fetchone("SELECT COUNT(*) AS n FROM files")["n"] == 3


def test_apply_metadata_is_audited(dolu_db, vault, tmp_path, key) -> None:
    rapor = _yedek(dolu_db, vault, tmp_path, key)
    hedef = tmp_path / "geri"
    restore_backup(rapor.path, hedef, key, hwid=_HWID)
    tablolar = json.loads((hedef / "metadata.json").read_text(encoding="utf-8"))

    apply_metadata(dolu_db, tablolar, user_id=_USER)
    assert dolu_db.fetchone(
        "SELECT action FROM audit_log ORDER BY id DESC LIMIT 1"
    )["action"] == "backup_metadata_applied"


def test_apply_metadata_never_writes_excluded_tables(dolu_db, vault, tmp_path, key) -> None:
    """
    Yedekte olmayan bir tabloyu elle eklemek bile yazılmamalı — yazılacak
    tablo listesi sabit.
    """
    kotu = {"users": [{"id": 99, "username": "sizan", "password_hash": "",
                       "role": "admin", "status": "approved", "hwid": "X"}]}
    apply_metadata(dolu_db, kotu, user_id=_USER)
    assert dolu_db.fetchone("SELECT id FROM users WHERE id = 99") is None


# ══════════════════════════════════════════════════════════════════════════════
# 7. Eşzamanlı yazma altında tutarlılık — TÜM tablolar TEK bir anlık görüntü
# ══════════════════════════════════════════════════════════════════════════════
#
# `_dump_tables()` her tabloyu AYRI bir SELECT ile okuyor. `create_backup()`
# bunu `RESTORABLE_TABLES` (`files` `quarantine`'den ÖNCE, `quarantine` SON
# eleman) için `BEGIN`...`COMMIT` ile sarmalıyor — WAL modunun anlık-görüntü
# izolasyonunu tüm okuma dizisine yayarak. Bu sarmalayıcı OLMASAYDI: `files`
# dump'ı bir yazmadan ÖNCEKİ hâlini, `quarantine` dump'ı (döngüde SONRA
# okunuyor) AYNI yazmadan SONRAKİ hâlini gösterebilirdi — iki tablo arasında
# ZAMANDA YIRTIK bir görüntü. Somut sonucu: `quarantine`'de, dump'a hiç
# girmemiş bir `files` satırına (id=99) işaret eden bir satır — restore
# edildiğinde YETİM bir referans.

_ESZAMANLI_DOSYA = "ESZAMANLI-EKLENEN-DOSYA"


def _dolu_db_yolu(dolu_db) -> Path:
    return dolu_db._db_path


def _ayri_baglantiyla_yeni_dosya_ve_karantina_yaz(db_path: Path) -> None:
    """`dolu_db`'nin bağlantısından TAMAMEN AYRI, ikinci bir bağlantıyla —
    gerçek bir "başka bir thread/pencere eşzamanlı yazıyor" senaryosunu
    taklit ediyor. `files`'a YENİ bir satır (id=99), `quarantine`'e ona
    işaret eden bir satır ekleyip COMMIT ediyor."""
    yazan = sqlite3.connect(str(db_path))
    try:
        yazan.execute(
            "INSERT INTO files (id, filename, filepath) VALUES (99, ?, ?)",
            (_ESZAMANLI_DOSYA, f"{_ESZAMANLI_DOSYA}-yol"),
        )
        yazan.execute(
            "INSERT INTO quarantine (file_id, reason) VALUES (99, 'test')"
        )
        yazan.commit()
    finally:
        yazan.close()


def test_dump_tables_building_block_is_torn_by_a_concurrent_write_if_unwrapped(
    dolu_db,
) -> None:
    """
    KALICI regresyon kilidi: `_dump_tables()`'ın KENDİSİ tek bir tutarlı
    anlık görüntü GARANTİ ETMİYOR. `create_backup()`'taki `BEGIN`...
    `COMMIT` sarmalayıcısı yanlışlıkla kaldırılırsa, bu test hemen kırılır
    ve NEDEN gerektiğini gösterir — `_dump_tables()`'ı sarmalamadan iki kez
    çağırmak (tıpkı düzeltmeden ÖNCEki `create_backup()` gibi) burada
    KASITLI olarak tekrarlanıyor.
    """
    from CORE.backup import _dump_tables

    ilk = _dump_tables(dolu_db, ("files",))
    assert len(ilk["files"]) == 3, "yazmadan önce 3 dosya olmalı (vault fixture'ı)"

    # "Eşzamanlı" yazma — files ZATEN okundu, quarantine HENÜZ okunmadı.
    _ayri_baglantiyla_yeni_dosya_ve_karantina_yaz(_dolu_db_yolu(dolu_db))

    son = _dump_tables(dolu_db, ("quarantine",))

    # YIRTIK: files eski hâlini (99 YOK) gösterdi, ama quarantine YENİ
    # satırı (99'a işaret eden) gösteriyor — iki tablo aynı ana ait değil.
    assert not any(f["id"] == 99 for f in ilk["files"])
    assert any(q["file_id"] == 99 for q in son["quarantine"]), (
        "beklenen: sarmalanmamış çağrı yırtık bir görüntü üretir "
        "(quarantine yeni satırı görüyor, files görmüyor)"
    )


def test_create_backup_dump_is_a_single_consistent_snapshot(
    dolu_db, vault, tmp_path, key, monkeypatch,
) -> None:
    """
    ANA TEST: gerçek `create_backup()` çağrısı, `_dump_tables()` çağrıları
    ARASINDA gelen bir eşzamanlı yazmaya rağmen TEK bir tutarlı anlık
    görüntü üretmeli — `files` VE `quarantine` AYNI ana (yazmadan ÖNCEye)
    ait olmalı, biri eski biri yeni bir karışım DEĞİL.

    Yazma, `quarantine` (RESTORABLE_TABLES'ın SON elemanı) okunmak ÜZEREYKEN
    tetikleniyor — `files` o ana kadar ÇOKTAN okunmuş oluyor; bu da tam
    olarak yırtığın oluşabileceği en geniş pencere.
    """
    from CORE.backup import METADATA_NAME, _read_metadata

    orijinal_fetchall = dolu_db.fetchall
    tetiklendi = {"yazildi": False}

    def _quarantine_okunurken_araya_gir(sql, params=()):
        if "FROM quarantine" in sql and not tetiklendi["yazildi"]:
            tetiklendi["yazildi"] = True
            _ayri_baglantiyla_yeni_dosya_ve_karantina_yaz(_dolu_db_yolu(dolu_db))
        return orijinal_fetchall(sql, params)

    monkeypatch.setattr(dolu_db, "fetchall", _quarantine_okunurken_araya_gir)

    rapor = _yedek(dolu_db, vault, tmp_path, key)
    assert tetiklendi["yazildi"], "test kurulumu hatalı — araya girme hiç tetiklenmedi"

    icerik = _read_metadata(rapor.path / METADATA_NAME, key, hwid=_HWID)

    # Tutarlı = TAMAMEN eski (yazmadan ÖNCEki) hâl: id=99 NE files'ta NE
    # quarantine'de. (Yazma dump BAŞLADIKTAN sonra geldiği için "tamamen
    # yeni" bir sonuç beklenmiyor — snapshot dump'ın başındaki ana sabit.)
    assert not any(f["id"] == 99 for f in icerik["tables"]["files"]), (
        "files dump'ı beklenmedik biçimde eşzamanlı yazmayı görüyor"
    )
    assert not any(q["file_id"] == 99 for q in icerik["tables"]["quarantine"]), (
        "quarantine dump'ı eşzamanlı yazmayı görüyor — YIRTIK anlık görüntü "
        "(BEGIN...COMMIT sarmalayıcısı çalışmıyor demektir)"
    )
    assert len(icerik["tables"]["files"]) == 3
    assert icerik["tables"]["quarantine"] == []


def test_restored_backup_has_no_orphaned_quarantine_reference(
    dolu_db, vault, tmp_path, key, monkeypatch,
) -> None:
    """
    ROUND-TRIP: yukarıdaki tutarlı yedeği GERÇEKTEN geri yükleyip
    (`apply_metadata` ile TEMİZ bir veritabanına yazıp), `quarantine.
    file_id`'nin restore SONRASI hâlâ `files.id`'de karşılığı olduğunu
    doğruluyor. Tutarsız (yırtık) bir yedek bunu KIRARDI: yeni `files`
    satırı (id=99) OLMADAN yalnızca ona işaret eden bir `quarantine`
    satırı restore edilebilirdi — yetim bir referans.

    Restore hedefi `dolu_db`'den TAMAMEN AYRI bir veritabanı olmak ZORUNDA
    — `DBManager` bir singleton olduğu için (`dolu_db` fixture'ı da onu
    kullanıyor) burada ELLE yeni bir örneğe geçiliyor, tıpkı
    `conftest.py`'deki `db` fixture'ının yaptığı gibi. `db` fixture'ını
    doğrudan parametre almak İŞE YARAMAZ: `dolu_db(db, vault)` onu zaten
    sarmaladığı için ikisi AYNI singleton örneğine, dolayısıyla eşzamanlı
    yazmanın da ZATEN girdiği AYNI canlı veritabanına işaret eder — bu
    yanlış kurulum bu testin ilk taslağında yakalandı (bkz. BACKLOG.md).
    """
    from CORE.backup import METADATA_NAME, _read_metadata
    from DB.db_manager import DBManager

    orijinal_fetchall = dolu_db.fetchall
    tetiklendi = {"yazildi": False}

    def _quarantine_okunurken_araya_gir(sql, params=()):
        if "FROM quarantine" in sql and not tetiklendi["yazildi"]:
            tetiklendi["yazildi"] = True
            _ayri_baglantiyla_yeni_dosya_ve_karantina_yaz(_dolu_db_yolu(dolu_db))
        return orijinal_fetchall(sql, params)

    monkeypatch.setattr(dolu_db, "fetchall", _quarantine_okunurken_araya_gir)

    rapor = _yedek(dolu_db, vault, tmp_path, key)
    icerik = _read_metadata(rapor.path / METADATA_NAME, key, hwid=_HWID)

    onceki_instance = DBManager._instance
    DBManager._instance = None
    hedef_db = DBManager(tmp_path / "restore_hedefi.db")
    hedef_db.connect(hwid="RESTORE-HEDEFI-HWID")
    try:
        # `users` KASITLI olarak yedeklenmiyor (bkz. modül docstring'i) —
        # `apply_metadata()`'nın gerçek ön koşulu, hedefte kullanıcıların
        # ZATEN var olması (aynı `dolu_db` fixture'ının kendi üzerine
        # geri yükleyen `test_apply_metadata_restores_the_rows` testinde
        # olduğu gibi), TAMAMEN BOŞ bir kurulum değil. `folders.owner_id`/
        # `files.added_by`/`quarantine.quarantined_by` bu kullanıcıya
        # işaret ettiği için FK'nın karşılığı burada da sağlanıyor.
        hedef_db.execute(
            "INSERT INTO users (id, username, password_hash, role, status, hwid)"
            " VALUES (3, 'gizli_kullanici', 'ARGON2-HASH-GIZLI', 'admin',"
            " 'approved', ?)", (_HWID,))
        apply_metadata(hedef_db, icerik["tables"], user_id=_USER)
        dosya_idleri = {r["id"] for r in hedef_db.fetchall("SELECT id FROM files")}
        karantina_dosya_idleri = {
            r["file_id"] for r in hedef_db.fetchall("SELECT file_id FROM quarantine")
        }
    finally:
        hedef_db.close()
        DBManager._instance = onceki_instance

    yetimler = karantina_dosya_idleri - dosya_idleri
    assert yetimler == set(), (
        f"quarantine, restore sonrası files'ta karşılığı olmayan "
        f"file_id'lere işaret ediyor: {yetimler}"
    )
    assert dosya_idleri == {1, 2, 3}, "yalnızca yazmadan ÖNCEki 3 dosya restore edilmeli"
    assert karantina_dosya_idleri == set(), "quarantine boş kalmalı (yazmadan önce boştu)"


# ══════════════════════════════════════════════════════════════════════════════
# 8. Hata dayanıklılığı — transaction, dump SIRASINDA patlarsa da kapanmalı
# ══════════════════════════════════════════════════════════════════════════════
#
# `_dump_tables()`'ın KENDİSİ tablo başına bir `try/except Exception` taşıyor
# (bkz. `CORE/backup.py`) — yani `db.fetchall()`'ın attığı bir hata ZATEN
# İÇERİDE yutulup boş listeye çevriliyor, `create_backup()`'ın dış
# `try/finally`'sine hiç ULAŞMIYOR. O yüzden dış sarmalayıcıyı GERÇEKTEN
# sınamak için hata, `_dump_tables()`'ın try/except'inin KAPSAMADIĞI bir
# noktadan (fonksiyonun kendisinin ÇAĞRILMASINDAN) enjekte ediliyor.


def test_create_backup_transaction_closes_even_if_the_dump_raises(
    dolu_db, vault, tmp_path, key, monkeypatch,
) -> None:
    """
    Yapay bir exception, `REFERENCE_TABLES` dump'ı (transaction zaten
    `BEGIN` edilmişken, ikinci `_dump_tables()` çağrısında) sırasında
    fırlatılıyor. `create_backup()`'ın hatayı YUTMAMASI (çağırana
    YANSIMASI) VE buna rağmen transaction'ı `finally` ile KAPATMIŞ OLMASI
    gerekiyor — açık kalan bir transaction sonraki bir checkpoint/WAL
    kısaltmasını bloklayabilir.
    """
    import CORE.backup as backup_modulu

    orijinal_dump_tables = backup_modulu._dump_tables

    def _referans_dump_edilirken_patla(db, tables):
        if tables == backup_modulu.REFERENCE_TABLES:
            raise RuntimeError("yapay hata — dump sırasında")
        return orijinal_dump_tables(db, tables)

    monkeypatch.setattr(backup_modulu, "_dump_tables", _referans_dump_edilirken_patla)

    assert dolu_db.conn.in_transaction is False, "test öncesi zaten açık bir transaction var"

    with pytest.raises(RuntimeError, match="yapay hata"):
        _yedek(dolu_db, vault, tmp_path, key)

    assert dolu_db.conn.in_transaction is False, (
        "transaction ASILI/AÇIK kaldı — finally'deki COMMIT çalışmamış "
        "olabilir, bu sonraki bir checkpoint/WAL kısaltmasını bloklardı"
    )

    # Bağlantı hâlâ KULLANILABİLİR olmalı — açık kalan bir transaction ya
    # da bozuk bir bağlantı durumu SONRAKİ sorguları da etkilerdi.
    assert dolu_db.fetchone("SELECT COUNT(*) AS n FROM files")["n"] == 3


def test_create_backup_transaction_closes_normally_when_nothing_raises(
    dolu_db, vault, tmp_path, key,
) -> None:
    """Karşılaştırma kaydı: normal (hatasız) bir yedeklemeden SONRA da
    transaction açık kalmamalı — yukarıdaki testin yalnızca hata yolunu
    değil, `finally`'nin HER İKİ yolda da çalıştığını doğrulamak için."""
    assert dolu_db.conn.in_transaction is False
    _yedek(dolu_db, vault, tmp_path, key)
    assert dolu_db.conn.in_transaction is False
