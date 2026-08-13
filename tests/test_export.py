"""
HYCLEUS — Toplu dışa aktarma testleri

Gerçek şifreleme kullanılıyor: dosyalar `encrypt_file()` ile üretiliyor,
`export_*` onları gerçekten çözüyor ve çıktı diskte doğrulanıyor. Mock yok —
bu akışın asıl riski "çözülmüş içerik doğru yere doğru adla yazılıyor mu",
ve onu ancak gerçek byte'larla sınayabiliriz.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from CORE import crypto
from CORE.crypto import encrypt_file
from CORE.export import (
    ExportResult,
    aad_hwid_of,
    export_to_directory,
    export_to_zip,
    format_errors,
    unique_path,
)

_KEY = b"K" * 32
_HWID = "TEST-HWID-DB"


@pytest.fixture(autouse=True)
def isolate_quarantine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    hedef = tmp_path / "quarantine"
    hedef.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", hedef)
    return hedef


def _add_encrypted(db, tmp_path: Path, name: str, icerik: bytes, *,
                   hwid: str | None = _HWID) -> tuple[int, Path]:
    src = tmp_path / name
    src.write_bytes(icerik)
    hcl, _sha, aad = encrypt_file(src, _KEY, user_id=1, hwid=hwid)
    src.unlink()
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label, aad_metadata) VALUES (?,?,?,?)",
        (name, str(hcl), "Genel", aad),
    )
    return int(cur.lastrowid), hcl


def _rows(db) -> list:
    return db.fetchall(
        "SELECT id, filename, filepath, aad_metadata FROM files ORDER BY id"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. Yardımcılar
# ══════════════════════════════════════════════════════════════════════════════


def test_aad_hwid_extracted():
    assert aad_hwid_of('{"hwid": "ABC", "filename": "a.pdf"}') == "ABC"


@pytest.mark.parametrize("deger", [None, "", "{bozuk", '{"filename":"a"}'])
def test_aad_hwid_missing_or_broken_is_none(deger):
    assert aad_hwid_of(deger) is None


def test_unique_path_returns_the_plain_name_when_free(tmp_path: Path):
    assert unique_path(tmp_path, "a.pdf") == tmp_path / "a.pdf"


def test_unique_path_never_overwrites(tmp_path: Path):
    """
    Kullanıcının kendi dizinindeki bir dosyayı sessizce ezmek kabul edilemez.
    """
    (tmp_path / "a.pdf").write_bytes(b"mevcut")
    assert unique_path(tmp_path, "a.pdf") == tmp_path / "a_1.pdf"
    (tmp_path / "a_1.pdf").write_bytes(b"x")
    assert unique_path(tmp_path, "a.pdf") == tmp_path / "a_2.pdf"


def test_unique_path_keeps_the_extension(tmp_path: Path):
    (tmp_path / "rapor.tar.gz").write_bytes(b"x")
    assert unique_path(tmp_path, "rapor.tar.gz").name == "rapor.tar_1.gz"


def test_format_errors_truncates_long_lists():
    hatalar = [f"dosya{i}.pdf (hata)" for i in range(25)]
    metin = format_errors(hatalar)
    assert "dosya0.pdf" in metin
    assert "dosya9.pdf" in metin
    assert "dosya10.pdf" not in metin
    assert "… ve 15 daha" in metin


def test_format_errors_empty_is_empty():
    assert format_errors([]) == ""


# ══════════════════════════════════════════════════════════════════════════════
# 2. ZIP dışa aktarımı
# ══════════════════════════════════════════════════════════════════════════════


def test_zip_contains_the_decrypted_originals(db, tmp_path: Path):
    _add_encrypted(db, tmp_path, "a.txt", b"birinci belge")
    _add_encrypted(db, tmp_path, "b.txt", b"ikinci belge")
    hedef = tmp_path / "cikti.zip"

    sonuc = export_to_zip(db, _rows(db), _KEY, hedef, hwid_fallback=_HWID)

    assert sonuc.saved == 2
    assert sonuc.clean
    with zipfile.ZipFile(hedef) as zf:
        assert sorted(zf.namelist()) == ["a.txt", "b.txt"]
        assert zf.read("a.txt") == b"birinci belge"
        assert zf.read("b.txt") == b"ikinci belge"


def test_zip_uses_the_original_name_from_the_aad(db, tmp_path: Path):
    """Arşivdeki ad AAD'daki orijinal ad olmalı, .hcl yolu değil."""
    _add_encrypted(db, tmp_path, "orijinal_ad.pdf", b"x")
    hedef = tmp_path / "c.zip"
    export_to_zip(db, _rows(db), _KEY, hedef, hwid_fallback=_HWID)
    with zipfile.ZipFile(hedef) as zf:
        assert zf.namelist() == ["orijinal_ad.pdf"]


def test_zip_skips_a_corrupt_file_but_keeps_going(db, tmp_path: Path):
    """
    Tek bozuk dosya arşivi iptal ETMEMELİ.

    Etseydi, tek bir bozuk dosya yüzünden kullanıcı hiçbir şey indiremezdi.
    """
    _add_encrypted(db, tmp_path, "saglam1.txt", b"bir")
    _fid, bozuk = _add_encrypted(db, tmp_path, "bozuk.txt", b"iki")
    _add_encrypted(db, tmp_path, "saglam2.txt", b"uc")

    raw = bytearray(bozuk.read_bytes())
    raw[-1] ^= 0xFF
    bozuk.write_bytes(raw)

    sonuc = export_to_zip(db, _rows(db), _KEY, tmp_path / "c.zip", hwid_fallback=_HWID)

    assert sonuc.saved == 2
    assert sonuc.errors == ["bozuk.txt (bütünlük hatası)"]
    with zipfile.ZipFile(tmp_path / "c.zip") as zf:
        assert sorted(zf.namelist()) == ["saglam1.txt", "saglam2.txt"]


def test_zip_reports_a_missing_file_as_an_error(db, tmp_path: Path):
    _fid, yol = _add_encrypted(db, tmp_path, "silinmis.txt", b"x")
    yol.unlink()
    sonuc = export_to_zip(db, _rows(db), _KEY, tmp_path / "c.zip", hwid_fallback=_HWID)
    assert sonuc.saved == 0
    assert len(sonuc.errors) == 1
    assert "silinmis.txt" in sonuc.errors[0]


def test_zip_of_an_empty_selection_produces_an_empty_archive(db, tmp_path: Path):
    sonuc = export_to_zip(db, [], _KEY, tmp_path / "bos.zip")
    assert sonuc.saved == 0 and sonuc.clean
    with zipfile.ZipFile(tmp_path / "bos.zip") as zf:
        assert zf.namelist() == []


def test_zip_wrong_key_fails_every_file(db, tmp_path: Path):
    _add_encrypted(db, tmp_path, "a.txt", b"x")
    sonuc = export_to_zip(db, _rows(db), b"Y" * 32, tmp_path / "c.zip", hwid_fallback=_HWID)
    assert sonuc.saved == 0
    assert "bütünlük hatası" in sonuc.errors[0]


# ══════════════════════════════════════════════════════════════════════════════
# 3. Dizine dışa aktarım
# ══════════════════════════════════════════════════════════════════════════════


def test_directory_export_writes_the_decrypted_files(db, tmp_path: Path):
    fid_a, yol_a = _add_encrypted(db, tmp_path, "a.txt", b"birinci")
    fid_b, yol_b = _add_encrypted(db, tmp_path, "b.txt", b"ikinci")
    hedef = tmp_path / "cikti"
    hedef.mkdir()

    sonuc = export_to_directory(
        db, [(fid_a, str(yol_a)), (fid_b, str(yol_b))], _KEY, hedef, session_hwid=_HWID
    )

    assert sonuc.saved == 2 and sonuc.clean
    assert (hedef / "a.txt").read_bytes() == b"birinci"
    assert (hedef / "b.txt").read_bytes() == b"ikinci"


def test_directory_export_does_not_overwrite_existing_files(db, tmp_path: Path):
    fid, yol = _add_encrypted(db, tmp_path, "a.txt", b"yeni")
    hedef = tmp_path / "cikti"
    hedef.mkdir()
    (hedef / "a.txt").write_bytes(b"onceden burada olan")

    export_to_directory(db, [(fid, str(yol))], _KEY, hedef, session_hwid=_HWID)

    assert (hedef / "a.txt").read_bytes() == b"onceden burada olan"
    assert (hedef / "a_1.txt").read_bytes() == b"yeni"


def test_directory_export_logs_each_saved_file(db, tmp_path: Path):
    fid, yol = _add_encrypted(db, tmp_path, "a.txt", b"x")
    hedef = tmp_path / "cikti"
    hedef.mkdir()

    export_to_directory(db, [(fid, str(yol))], _KEY, hedef, session_hwid=_HWID)

    row = db.fetchone(
        "SELECT target_id, detail FROM audit_log WHERE action = 'file_downloaded'"
    )
    assert row["target_id"] == fid
    assert "bulk=True" in row["detail"]
    assert f"hwid={_HWID}" in row["detail"]


def test_directory_export_audit_entries_join_the_hash_chain(db, tmp_path: Path):
    from CORE.audit_chain import verify_audit_chain

    fid, yol = _add_encrypted(db, tmp_path, "a.txt", b"x")
    hedef = tmp_path / "cikti"
    hedef.mkdir()
    export_to_directory(db, [(fid, str(yol))], _KEY, hedef, session_hwid=_HWID)
    assert verify_audit_chain(db.conn).ok is True


def test_directory_export_reports_a_missing_path(db, tmp_path: Path):
    hedef = tmp_path / "cikti"
    hedef.mkdir()
    sonuc = export_to_directory(db, [(42, None)], _KEY, hedef)
    assert sonuc.saved == 0
    assert sonuc.errors == ["#42 (dosya yolu yok)"]


def test_directory_export_continues_after_a_failure(db, tmp_path: Path):
    fid_a, yol_a = _add_encrypted(db, tmp_path, "saglam.txt", b"bir")
    fid_b, yol_b = _add_encrypted(db, tmp_path, "bozuk.txt", b"iki")
    raw = bytearray(yol_b.read_bytes())
    raw[-1] ^= 0xFF
    yol_b.write_bytes(raw)
    hedef = tmp_path / "cikti"
    hedef.mkdir()

    sonuc = export_to_directory(
        db, [(fid_b, str(yol_b)), (fid_a, str(yol_a))], _KEY, hedef, session_hwid=_HWID
    )

    assert sonuc.saved == 1
    assert len(sonuc.errors) == 1
    assert (hedef / "saglam.txt").exists()


def test_directory_export_reports_progress(db, tmp_path: Path):
    fid_a, yol_a = _add_encrypted(db, tmp_path, "a.txt", b"x")
    fid_b, yol_b = _add_encrypted(db, tmp_path, "b.txt", b"y")
    hedef = tmp_path / "cikti"
    hedef.mkdir()
    izlenen: list[tuple[int, str]] = []

    export_to_directory(
        db, [(fid_a, str(yol_a)), (fid_b, str(yol_b))], _KEY, hedef,
        on_progress=lambda i, ad: izlenen.append((i, ad)),
    )

    assert [i for i, _ in izlenen] == [0, 1]
    assert izlenen[0][1].endswith(".hcl")


def test_directory_export_can_be_cancelled(db, tmp_path: Path):
    ogeler = []
    for i in range(5):
        fid, yol = _add_encrypted(db, tmp_path, f"d{i}.txt", b"x")
        ogeler.append((fid, str(yol)))
    hedef = tmp_path / "cikti"
    hedef.mkdir()

    sayac = {"n": 0}

    def devam():
        sayac["n"] += 1
        return sayac["n"] <= 2

    sonuc = export_to_directory(db, ogeler, _KEY, hedef, should_continue=devam)

    assert sonuc.cancelled is True
    assert sonuc.saved == 2
    assert not sonuc.clean


# ══════════════════════════════════════════════════════════════════════════════
# 4. KORUNAN FARK — hwid geri dönüşü
# ══════════════════════════════════════════════════════════════════════════════


def test_zip_falls_back_to_the_session_hwid(db, tmp_path: Path):
    """
    AAD'da hwid yoksa ZIP akışı OTURUM hwid'iyle doğruluyor.

    Dosya başka bir hwid ile şifrelenmişse bu doğrulama düşer ve dosya
    atlanır — mevcut davranış.
    """
    _add_encrypted(db, tmp_path, "baska.txt", b"x", hwid="BASKA-CIHAZ")
    # aad_metadata'yı boşalt: AAD'da hwid okunamasın
    db.execute("UPDATE files SET aad_metadata = NULL")

    sonuc = export_to_zip(db, _rows(db), _KEY, tmp_path / "c.zip", hwid_fallback=_HWID)
    assert sonuc.saved == 0
    assert "bütünlük hatası" in sonuc.errors[0]


def test_directory_export_does_NOT_fall_back_by_default(db, tmp_path: Path):
    """
    BİLİNEN FARK — mevcut davranış, bilerek korundu.

    Aynı dosya, aynı anahtar: ZIP akışı reddediyor (yukarıdaki test), toplu
    indirme kabul ediyor. Çünkü toplu indirme AAD'da hwid yoksa
    doğrulamayı hiç yapmıyor (hwid=None geçiyor).

    Bu test bir onay değil, bir SABİTLEME — bkz. CORE/export.py
    docstring'i, "KORUNAN FARK".
    """
    fid, yol = _add_encrypted(db, tmp_path, "baska.txt", b"icerik", hwid="BASKA-CIHAZ")
    db.execute("UPDATE files SET aad_metadata = NULL")
    hedef = tmp_path / "cikti"
    hedef.mkdir()

    sonuc = export_to_directory(db, [(fid, str(yol))], _KEY, hedef, session_hwid=_HWID)

    assert sonuc.saved == 1, "toplu indirme hwid doğrulaması yapmıyor — mevcut davranış"
    assert (hedef / "baska.txt").read_bytes() == b"icerik"


def test_directory_export_honours_an_explicit_fallback(db, tmp_path: Path):
    """Parametre verilirse toplu indirme de ZIP gibi davranabiliyor."""
    fid, yol = _add_encrypted(db, tmp_path, "baska.txt", b"x", hwid="BASKA-CIHAZ")
    db.execute("UPDATE files SET aad_metadata = NULL")
    hedef = tmp_path / "cikti"
    hedef.mkdir()

    sonuc = export_to_directory(
        db, [(fid, str(yol))], _KEY, hedef, hwid_fallback=_HWID
    )
    assert sonuc.saved == 0


def test_export_result_defaults_are_clean():
    assert ExportResult().clean is True
