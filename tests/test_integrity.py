"""
HYCLEUS — Bütünlük taraması testleri

İki ayrı katman sınanıyor:

  · `CORE.crypto.verify_file()` — dar doğrulama ilkeli. Buradaki asıl soru
    tag'i doğru kontrol edip etmediği DEĞİL (o zaten decrypt_file ile aynı
    kod yolu), düz metni sızdırıp sızdırmadığı.
  · `CORE.integrity.sweep_integrity()` — sınıflandırma, DB işaretleme ve
    denetim kaydı.

Bozma işlemleri gerçek: dosyanın byte'ları diskte değiştiriliyor, mock
kullanılmıyor.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from CORE import crypto
from CORE.audit_chain import verify_audit_chain
from CORE.crypto import AuthenticationError, decrypt_file, encrypt_file, verify_file
from CORE.integrity import (
    LAST_SWEEP_SETTING,
    SWEEP_INTERVAL_DAYS,
    FileVerdict,
    IntegrityStatus,
    last_sweep_at,
    maybe_run_weekly_sweep,
    sweep_due,
    sweep_integrity,
)

_KEY = b"K" * 32
_PLAINTEXT = b"HYCLEUS gizli belge icerigi - BENZERSIZ_IMZA_9d4f2a - " + b"dolgu " * 500


# ── Yardımcılar ───────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def isolate_quarantine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """encrypt_file() sabit bir data/quarantine dizinine yazıyor — izole et."""
    hedef = tmp_path / "quarantine"
    hedef.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", hedef)
    return hedef


def _make_hcl(tmp_path: Path, name: str = "belge.txt", data: bytes = _PLAINTEXT) -> Path:
    """Gerçek bir .hcl üretir ve yolunu döndürür."""
    src = tmp_path / name
    src.write_bytes(data)
    hcl, _sha, _aad = encrypt_file(src, _KEY, user_id=1, hwid="TEST-HWID-DB")
    src.unlink()
    return hcl


def _register(db, hcl: Path, *, label: str = "Genel") -> int:
    """.hcl dosyasını files tablosuna kaydeder ve id döndürür."""
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label, size_bytes) VALUES (?, ?, ?, ?)",
        (hcl.name, str(hcl), label, hcl.stat().st_size),
    )
    return int(cur.lastrowid)


def _corrupt_tag(hcl: Path) -> None:
    """Son 16 byte GCM tag'i — son byte'ı çevir."""
    raw = bytearray(hcl.read_bytes())
    raw[-1] ^= 0xFF
    hcl.write_bytes(raw)


def _corrupt_ciphertext(hcl: Path) -> None:
    """Gövdenin ortasından bir byte çevir — tag aynı kalır."""
    raw = bytearray(hcl.read_bytes())
    raw[len(raw) // 2] ^= 0xFF
    hcl.write_bytes(raw)


def _statuses(db, file_id: int) -> tuple[str | None, str | None]:
    row = db.fetchone(
        "SELECT integrity_status, integrity_checked_at FROM files WHERE id = ?",
        (file_id,),
    )
    return row["integrity_status"], row["integrity_checked_at"]


def _actions(db) -> list[str]:
    return [r["action"] for r in db.fetchall("SELECT action FROM audit_log ORDER BY id")]


# ══════════════════════════════════════════════════════════════════════════════
# 1. verify_file() — dar doğrulama ilkeli
# ══════════════════════════════════════════════════════════════════════════════


def test_verify_file_accepts_an_intact_file(tmp_path: Path):
    hcl = _make_hcl(tmp_path)
    meta = verify_file(hcl, _KEY)
    assert meta["filename"] == "belge.txt"


def test_verify_file_does_not_return_plaintext(tmp_path: Path):
    """
    İmza sözleşmesi: dönen şey AAD metadata'sı, düz metin değil.

    decrypt_file() (bytes, dict) döndürüyor; verify_file yalnızca dict.
    """
    hcl = _make_hcl(tmp_path)
    sonuc = verify_file(hcl, _KEY)

    assert isinstance(sonuc, dict)
    assert not isinstance(sonuc, tuple)
    # AAD alanlarının hiçbiri düz metni taşımıyor
    for deger in sonuc.values():
        assert _PLAINTEXT not in str(deger).encode()
        assert b"BENZERSIZ_IMZA_9d4f2a" not in str(deger).encode()


def test_verify_file_returns_the_same_metadata_as_decrypt_file(tmp_path: Path):
    """Dar yol, geniş yolla aynı AAD'ı görmeli — format yorumu ayrışmasın."""
    hcl = _make_hcl(tmp_path)
    icerik, meta_full = decrypt_file(hcl, _KEY)
    try:
        assert verify_file(hcl, _KEY) == meta_full
    finally:
        del icerik


def test_verify_file_detects_a_flipped_tag(tmp_path: Path):
    hcl = _make_hcl(tmp_path)
    _corrupt_tag(hcl)
    with pytest.raises(AuthenticationError):
        verify_file(hcl, _KEY)


def test_verify_file_detects_a_flipped_ciphertext_byte(tmp_path: Path):
    hcl = _make_hcl(tmp_path)
    _corrupt_ciphertext(hcl)
    with pytest.raises(AuthenticationError):
        verify_file(hcl, _KEY)


def test_verify_file_detects_edited_aad(tmp_path: Path):
    """AAD şifresiz duruyor ama GCM tarafından doğrulanıyor."""
    hcl = _make_hcl(tmp_path)
    raw = hcl.read_bytes()
    # json.dumps varsayılan ayraçlarla yazıyor: '"filename": "belge.txt"'
    bozuk = raw.replace(b'"filename": "belge.txt"', b'"filename": "baska.txt"')
    assert bozuk != raw, "AAD içinde beklenen dize bulunamadı"
    hcl.write_bytes(bozuk)
    with pytest.raises(AuthenticationError):
        verify_file(hcl, _KEY)


def test_verify_file_rejects_a_wrong_key(tmp_path: Path):
    hcl = _make_hcl(tmp_path)
    with pytest.raises(AuthenticationError):
        verify_file(hcl, b"X" * 32)


def test_verify_file_rejects_a_bad_magic(tmp_path: Path):
    hcl = _make_hcl(tmp_path)
    raw = bytearray(hcl.read_bytes())
    raw[0:4] = b"XXXX"
    hcl.write_bytes(raw)
    with pytest.raises(ValueError):
        verify_file(hcl, _KEY)


def test_verify_file_rejects_an_unsupported_version(tmp_path: Path):
    hcl = _make_hcl(tmp_path)
    raw = bytearray(hcl.read_bytes())
    raw[4] = 99
    hcl.write_bytes(raw)
    with pytest.raises(ValueError, match="Desteklenmeyen versiyon"):
        verify_file(hcl, _KEY)


def test_verify_file_rejects_a_truncated_file(tmp_path: Path):
    hcl = _make_hcl(tmp_path)
    raw = hcl.read_bytes()
    hcl.write_bytes(raw[:20])
    with pytest.raises(ValueError):
        verify_file(hcl, _KEY)


def test_verify_file_rejects_a_short_key(tmp_path: Path):
    hcl = _make_hcl(tmp_path)
    with pytest.raises(ValueError, match="32 byte"):
        verify_file(hcl, b"kisa")


def test_verify_file_checks_hwid_when_asked(tmp_path: Path):
    hcl = _make_hcl(tmp_path)
    verify_file(hcl, _KEY, hwid="TEST-HWID-DB")          # eşleşiyor
    with pytest.raises(AuthenticationError, match="HWID"):
        verify_file(hcl, _KEY, hwid="BASKA-CIHAZ")


def test_verify_file_raises_oserror_for_a_missing_file(tmp_path: Path):
    with pytest.raises(OSError):
        verify_file(tmp_path / "yok.hcl", _KEY)


def test_verify_file_handles_an_empty_payload(tmp_path: Path):
    """Sıfır byte'lık bir dosya da geçerli şekilde şifrelenip doğrulanabilmeli."""
    hcl = _make_hcl(tmp_path, name="bos.txt", data=b"")
    assert verify_file(hcl, _KEY)["filename"] == "bos.txt"


def test_verify_file_handles_a_multichunk_file(tmp_path: Path):
    """64 KB'lık blok sınırının ötesi — update_into döngüsü doğru ilerlemeli."""
    buyuk = os.urandom(64 * 1024 * 3 + 1234)
    hcl = _make_hcl(tmp_path, name="buyuk.bin", data=buyuk)
    assert verify_file(hcl, _KEY)["filename"] == "buyuk.bin"
    _corrupt_ciphertext(hcl)
    with pytest.raises(AuthenticationError):
        verify_file(hcl, _KEY)


def test_verify_file_never_writes_to_disk(tmp_path: Path):
    """Doğrulama bir okuma işlemi — hiçbir dosya oluşturmamalı/değiştirmemeli."""
    hcl = _make_hcl(tmp_path)
    onceki = {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*") if p.is_file()}
    onceki_boyut = hcl.stat().st_size

    verify_file(hcl, _KEY)

    sonraki = {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*") if p.is_file()}
    assert set(sonraki) == set(onceki), "doğrulama yeni dosya oluşturdu"
    assert hcl.stat().st_size == onceki_boyut


def test_verify_file_does_not_leak_plaintext_into_its_scratch_buffer(
    tmp_path: Path, monkeypatch
):
    """
    Geçici tampon çıkışta gerçekten sıfırlanıyor mu?

    `bytearray`i yakalayıp verify_file döndükten SONRA içeriğine bakıyoruz.
    İddia "düz metin hiç oluşmaz" değil (GCM akışında oluşur, bkz.
    crypto.verify_file docstring'i) — "çıkışta tamponda kalmaz".
    """
    yakalanan: list[bytearray] = []
    gercek = bytearray

    def izleyen_bytearray(*args, **kwargs):
        buf = gercek(*args, **kwargs)
        yakalanan.append(buf)
        return buf

    monkeypatch.setattr(crypto, "bytearray", izleyen_bytearray, raising=False)
    hcl = _make_hcl(tmp_path)
    verify_file(hcl, _KEY)
    monkeypatch.undo()

    assert yakalanan, "scratch tamponu yakalanamadı — test kendi varsayımını yitirmiş"
    for buf in yakalanan:
        assert bytes(buf) == b"\x00" * len(buf), "tampon sıfırlanmamış"
        assert b"BENZERSIZ_IMZA_9d4f2a" not in bytes(buf)


def test_verify_file_buffer_is_zeroed_even_when_the_tag_fails(tmp_path: Path, monkeypatch):
    """Hata yolunda da temizlik yapılmalı — finally bloğu."""
    yakalanan: list[bytearray] = []
    gercek = bytearray

    def izleyen_bytearray(*args, **kwargs):
        buf = gercek(*args, **kwargs)
        yakalanan.append(buf)
        return buf

    hcl = _make_hcl(tmp_path)
    _corrupt_tag(hcl)
    monkeypatch.setattr(crypto, "bytearray", izleyen_bytearray, raising=False)
    with pytest.raises(AuthenticationError):
        verify_file(hcl, _KEY)
    monkeypatch.undo()

    assert yakalanan
    for buf in yakalanan:
        assert bytes(buf) == b"\x00" * len(buf)


def test_verify_file_memory_is_constant_regardless_of_size(tmp_path: Path):
    """
    Doğrulamanın bellek maliyeti dosya boyutundan BAĞIMSIZ olmalı.

    decrypt_file() tüm düz metni biriktirdiği için bu testi geçemezdi;
    verify_file() sabit tamponla akıyor. Ölçüm tracemalloc'un tepe değeriyle:
    dosya 8 katına çıkarken tepe bellek dosya boyutuyla ölçeklenmemeli.
    """
    import tracemalloc

    def tepe_bellek(boyut: int) -> int:
        hcl = _make_hcl(tmp_path, name=f"olcum_{boyut}.bin", data=os.urandom(boyut))
        tracemalloc.start()
        try:
            verify_file(hcl, _KEY)
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
            hcl.unlink()

    kucuk = tepe_bellek(128 * 1024)
    buyuk = tepe_bellek(1024 * 1024)

    # Sabit tamponla akarken fark gürültü seviyesinde kalmalı. Eşik bilerek
    # gevşek: amaç "512 KB'lık artış belleğe yansımadı"yı göstermek.
    assert buyuk < kucuk + 256 * 1024, (
        f"bellek dosya boyutuyla ölçekleniyor: {kucuk} -> {buyuk}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2. Sınıflandırma
# ══════════════════════════════════════════════════════════════════════════════


def test_intact_file_is_marked_ok(db, tmp_path: Path):
    hcl = _make_hcl(tmp_path)
    fid = _register(db, hcl)

    rapor = sweep_integrity(db, _KEY)

    assert rapor.checked == 1
    assert rapor.ok == 1
    assert rapor.corrupt == 0
    assert rapor.clean
    assert _statuses(db, fid)[0] == IntegrityStatus.OK
    assert _statuses(db, fid)[1] is not None


def test_tampered_tag_is_caught_as_tag_mismatch(db, tmp_path: Path):
    saglam = _make_hcl(tmp_path, name="saglam.txt")
    bozuk = _make_hcl(tmp_path, name="bozuk.txt")
    id_saglam = _register(db, saglam)
    id_bozuk = _register(db, bozuk)
    _corrupt_tag(bozuk)

    rapor = sweep_integrity(db, _KEY)

    assert rapor.ok == 1
    assert rapor.corrupt == 1
    assert not rapor.clean
    assert _statuses(db, id_saglam)[0] == IntegrityStatus.OK
    assert _statuses(db, id_bozuk)[0] == IntegrityStatus.TAG_MISMATCH


def test_missing_file_is_classified_as_missing(db, tmp_path: Path):
    hcl = _make_hcl(tmp_path)
    fid = _register(db, hcl)
    hcl.unlink()

    rapor = sweep_integrity(db, _KEY)

    assert rapor.corrupt == 1
    assert _statuses(db, fid)[0] == IntegrityStatus.MISSING
    verdict = rapor.corrupt_verdicts()[0]
    assert verdict.status is IntegrityStatus.MISSING
    assert "diskte yok" in verdict.reason


def test_malformed_header_is_classified_separately(db, tmp_path: Path):
    """Bozuk başlık, tag hatasından AYRI raporlanmalı — farklı arıza türü."""
    hcl = _make_hcl(tmp_path)
    fid = _register(db, hcl)
    raw = bytearray(hcl.read_bytes())
    raw[0:4] = b"NOPE"
    hcl.write_bytes(raw)

    sweep_integrity(db, _KEY)
    assert _statuses(db, fid)[0] == IntegrityStatus.MALFORMED


def test_truncated_file_is_malformed_not_tag_mismatch(db, tmp_path: Path):
    hcl = _make_hcl(tmp_path)
    fid = _register(db, hcl)
    hcl.write_bytes(hcl.read_bytes()[:30])

    sweep_integrity(db, _KEY)
    assert _statuses(db, fid)[0] == IntegrityStatus.MALFORMED


def test_unreadable_file_is_classified_as_unreadable(db, tmp_path: Path, monkeypatch):
    """
    İzin/GÇ hatası ayrı bir sınıf — dosya bozuk değil, ERİŞİLEMİYOR.

    Windows'ta chmod güvenilir değil, bu yüzden open() OSError fırlatacak
    şekilde sarmalanıyor; sınıflandırılan davranış aynı.
    """
    import builtins

    hcl = _make_hcl(tmp_path)
    fid = _register(db, hcl)

    gercek_open = builtins.open

    def patlayan_open(path, *a, **k):
        if str(path) == str(hcl):
            raise PermissionError(13, "Erisim engellendi")
        return gercek_open(path, *a, **k)

    # Modül globali builtins'ten önce bakılır — crypto içindeki open() bunu görür.

    monkeypatch.setattr(crypto, "open", patlayan_open, raising=False)
    sweep_integrity(db, _KEY)
    monkeypatch.undo()

    assert _statuses(db, fid)[0] == IntegrityStatus.UNREADABLE


def test_hwid_mismatch_is_not_counted_as_corruption(db, tmp_path: Path):
    """
    Başka cihazda şifrelenmiş dosya bozuk DEĞİL — ayrı bulgu.

    Bozuk saymak, USB değiştiren bir kullanıcının tüm kasasını "bozuk"
    göstermek olurdu; dosyaların kendisi sapasağlam.
    """
    hcl = _make_hcl(tmp_path)
    fid = _register(db, hcl)

    rapor = sweep_integrity(db, _KEY, hwid="BASKA-CIHAZ")

    assert _statuses(db, fid)[0] == IntegrityStatus.HWID_MISMATCH
    assert rapor.corrupt == 0
    verdict = rapor.verdicts[0]
    assert not verdict.corrupt and not verdict.ok


def test_mixed_vault_classifies_each_file_independently(db, tmp_path: Path):
    saglam = _make_hcl(tmp_path, name="a.txt")
    tag_bozuk = _make_hcl(tmp_path, name="b.txt")
    eksik = _make_hcl(tmp_path, name="c.txt")
    format_bozuk = _make_hcl(tmp_path, name="d.txt")

    ids = {ad: _register(db, p) for ad, p in
           (("a", saglam), ("b", tag_bozuk), ("c", eksik), ("d", format_bozuk))}

    _corrupt_tag(tag_bozuk)
    eksik.unlink()
    format_bozuk.write_bytes(b"COKKISA")

    rapor = sweep_integrity(db, _KEY)

    assert rapor.checked == 4
    assert rapor.ok == 1
    assert rapor.corrupt == 3
    assert _statuses(db, ids["a"])[0] == IntegrityStatus.OK
    assert _statuses(db, ids["b"])[0] == IntegrityStatus.TAG_MISMATCH
    assert _statuses(db, ids["c"])[0] == IntegrityStatus.MISSING
    assert _statuses(db, ids["d"])[0] == IntegrityStatus.MALFORMED


def test_empty_vault_sweeps_cleanly(db):
    rapor = sweep_integrity(db, _KEY)
    assert rapor.total == 0 and rapor.checked == 0 and rapor.clean


def test_sweep_rejects_a_bad_key_length(db):
    with pytest.raises(ValueError, match="32 byte"):
        sweep_integrity(db, b"kisa")


# ══════════════════════════════════════════════════════════════════════════════
# 3. Denetim kaydı — hash zincirinden geçerek
# ══════════════════════════════════════════════════════════════════════════════


def test_sweep_logs_start_and_finish(db, tmp_path: Path):
    _register(db, _make_hcl(tmp_path))
    sweep_integrity(db, _KEY)

    actions = _actions(db)
    assert "integrity_sweep_started" in actions
    assert "integrity_sweep_finished" in actions

    detail = db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'integrity_sweep_finished'"
    )["detail"]
    assert "total=1" in detail and "ok=1" in detail and "corrupt=0" in detail


def test_sweep_logs_each_corrupt_file_with_its_target(db, tmp_path: Path):
    bozuk = _make_hcl(tmp_path, name="bozuk.txt")
    fid = _register(db, bozuk)
    _corrupt_tag(bozuk)

    sweep_integrity(db, _KEY)

    row = db.fetchone(
        "SELECT target_type, target_id, detail FROM audit_log"
        " WHERE action = 'integrity_check_failed'"
    )
    assert row["target_type"] == "file"
    assert row["target_id"] == fid
    assert "status=tag_mismatch" in row["detail"]
    assert "bozuk.txt" in row["detail"]


def test_sweep_does_not_log_healthy_files_individually(db, tmp_path: Path):
    """
    Sağlam dosyalar tek tek yazılmamalı — haftalık tarama denetim kaydını
    boğardı. Sonuç zaten files.integrity_status içinde duruyor.
    """
    for i in range(5):
        _register(db, _make_hcl(tmp_path, name=f"dosya{i}.txt"))

    sweep_integrity(db, _KEY)

    assert _actions(db).count("integrity_check_failed") == 0
    # yalnızca başlangıç + bitiş
    assert _actions(db).count("integrity_sweep_started") == 1
    assert _actions(db).count("integrity_sweep_finished") == 1


def test_sweep_entries_are_part_of_the_hash_chain(db, tmp_path: Path):
    """Bu turun asıl bağlantısı: tarama kayıtları zincire dahil olmalı."""
    bozuk = _make_hcl(tmp_path, name="bozuk.txt")
    _register(db, bozuk)
    _register(db, _make_hcl(tmp_path, name="saglam.txt"))
    _corrupt_tag(bozuk)

    onceki = verify_audit_chain(db.conn).checked
    sweep_integrity(db, _KEY)

    sonuc = verify_audit_chain(db.conn)
    assert sonuc.ok is True
    assert sonuc.checked == onceki + 3   # started + failed + finished

    hashsiz = db.fetchone(
        "SELECT COUNT(*) AS n FROM audit_log"
        " WHERE action LIKE 'integrity%' AND entry_hash IS NULL"
    )["n"]
    assert hashsiz == 0


def test_tampering_with_a_sweep_entry_breaks_the_chain(db, tmp_path: Path):
    """Tarama bulgusunu silmeye kalkmak zincirde iz bırakmalı."""
    bozuk = _make_hcl(tmp_path)
    _register(db, bozuk)
    _corrupt_tag(bozuk)
    sweep_integrity(db, _KEY)

    kayit = db.fetchone(
        "SELECT id FROM audit_log WHERE action = 'integrity_check_failed'"
    )
    db.conn.execute("DELETE FROM audit_log WHERE id = ?", (kayit["id"],))
    db.conn.commit()

    sonuc = verify_audit_chain(db.conn)
    assert not sonuc
    assert sonuc.first_broken_id == kayit["id"]


# ══════════════════════════════════════════════════════════════════════════════
# 4. Yanlış anahtar koruması
# ══════════════════════════════════════════════════════════════════════════════


def test_wrong_key_does_not_mark_the_whole_vault_corrupt(db, tmp_path: Path):
    ids = [_register(db, _make_hcl(tmp_path, name=f"d{i}.txt")) for i in range(4)]

    rapor = sweep_integrity(db, b"Y" * 32)

    assert rapor.suspected_wrong_key
    assert rapor.corrupt == 0
    assert not rapor.clean
    for fid in ids:
        assert _statuses(db, fid)[0] is None, "yanlış anahtarda işaretleme yapılmamalı"

    actions = _actions(db)
    assert "integrity_sweep_aborted" in actions
    assert "integrity_sweep_finished" not in actions
    assert actions.count("integrity_check_failed") == 0


def test_wrong_key_guard_does_not_hide_a_genuine_single_failure(db, tmp_path: Path):
    """Bir dosya bozuk, diğerleri sağlamsa koruma DEVREYE GİRMEMELİ."""
    bozuk = _make_hcl(tmp_path, name="bozuk.txt")
    fid = _register(db, bozuk)
    for i in range(3):
        _register(db, _make_hcl(tmp_path, name=f"saglam{i}.txt"))
    _corrupt_tag(bozuk)

    rapor = sweep_integrity(db, _KEY)

    assert not rapor.suspected_wrong_key
    assert rapor.corrupt == 1
    assert _statuses(db, fid)[0] == IntegrityStatus.TAG_MISMATCH


def test_wrong_key_guard_needs_a_minimum_sample(db, tmp_path: Path):
    """
    İki dosyada "hepsi bozuk" bir örüntü değil — koruma devreye girmemeli,
    yoksa gerçekten iki dosyası bozulmuş bir kasa sessiz kalırdı.
    """
    for i in range(2):
        _register(db, _make_hcl(tmp_path, name=f"d{i}.txt"))

    for row in db.fetchall("SELECT filepath FROM files"):
        _corrupt_tag(Path(row["filepath"]))

    rapor = sweep_integrity(db, _KEY)
    assert not rapor.suspected_wrong_key
    assert rapor.corrupt == 2


def test_missing_files_do_not_trigger_the_wrong_key_guard(db, tmp_path: Path):
    """Koruma yalnızca TAG hatalarına bakar; eksik dosya anahtarla ilgisiz."""
    for i in range(4):
        hcl = _make_hcl(tmp_path, name=f"d{i}.txt")
        _register(db, hcl)
        hcl.unlink()

    rapor = sweep_integrity(db, _KEY)
    assert not rapor.suspected_wrong_key
    assert rapor.corrupt == 4


# ══════════════════════════════════════════════════════════════════════════════
# 5. Yarıda durdurma
# ══════════════════════════════════════════════════════════════════════════════


def test_sweep_stops_cleanly_when_asked(db, tmp_path: Path):
    for i in range(6):
        _register(db, _make_hcl(tmp_path, name=f"d{i}.txt"))

    sayac = {"n": 0}

    def devam_et() -> bool:
        sayac["n"] += 1
        return sayac["n"] <= 3

    rapor = sweep_integrity(db, _KEY, should_continue=devam_et)

    assert rapor.aborted
    assert rapor.checked == 3
    assert rapor.total == 6
    assert "YARIDA DURDURULDU" in rapor.summary()


def test_aborted_sweep_still_records_what_it_checked(db, tmp_path: Path):
    ids = [_register(db, _make_hcl(tmp_path, name=f"d{i}.txt")) for i in range(4)]
    sayac = {"n": 0}

    def devam_et() -> bool:
        sayac["n"] += 1
        return sayac["n"] <= 2

    sweep_integrity(db, _KEY, should_continue=devam_et)

    assert _statuses(db, ids[0])[0] == IntegrityStatus.OK
    assert _statuses(db, ids[1])[0] == IntegrityStatus.OK
    assert _statuses(db, ids[3])[0] is None, "kontrol edilmeyen dosya işaretlenmemeli"


# ══════════════════════════════════════════════════════════════════════════════
# 6. Haftalık kapı
# ══════════════════════════════════════════════════════════════════════════════


def test_first_run_is_always_due(db):
    assert last_sweep_at(db) is None
    assert sweep_due(db) is True


def test_sweep_is_not_repeated_within_the_week(db, tmp_path: Path, monkeypatch):
    from CORE import integrity

    _register(db, _make_hcl(tmp_path))
    simdi = datetime(2026, 8, 13, 10, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(integrity, "_utcnow", lambda: simdi)

    assert maybe_run_weekly_sweep(db, _KEY) is not None
    assert maybe_run_weekly_sweep(db, _KEY) is None

    monkeypatch.setattr(
        integrity, "_utcnow", lambda: simdi + timedelta(days=SWEEP_INTERVAL_DAYS - 1)
    )
    assert maybe_run_weekly_sweep(db, _KEY) is None

    monkeypatch.setattr(
        integrity, "_utcnow", lambda: simdi + timedelta(days=SWEEP_INTERVAL_DAYS)
    )
    assert maybe_run_weekly_sweep(db, _KEY) is not None


def test_aborted_sweep_does_not_advance_the_weekly_gate(db, tmp_path: Path):
    """
    Yarıda kesilen tur sayacı ilerletmemeli.

    İlerletseydi kapanış sırasında kesilen bir tarama, bir hafta boyunca
    yeniden denenmezdi.
    """
    _register(db, _make_hcl(tmp_path))
    rapor = maybe_run_weekly_sweep(db, _KEY, should_continue=lambda: False)

    assert rapor is not None and rapor.aborted
    assert db.get_setting(LAST_SWEEP_SETTING, "") == ""
    assert sweep_due(db) is True


def test_wrong_key_run_does_not_advance_the_weekly_gate(db, tmp_path: Path):
    for i in range(4):
        _register(db, _make_hcl(tmp_path, name=f"d{i}.txt"))

    rapor = maybe_run_weekly_sweep(db, b"Z" * 32)
    assert rapor is not None and rapor.suspected_wrong_key
    assert sweep_due(db) is True


def test_completed_sweep_records_its_timestamp(db, tmp_path: Path):
    _register(db, _make_hcl(tmp_path))
    rapor = maybe_run_weekly_sweep(db, _KEY)
    assert rapor is not None
    assert db.get_setting(LAST_SWEEP_SETTING, "") == rapor.finished_at
    assert last_sweep_at(db) is not None


def test_corrupt_last_sweep_setting_is_treated_as_never_run(db):
    db.set_setting(LAST_SWEEP_SETTING, "bozuk-zaman-damgasi")
    assert last_sweep_at(db) is None
    assert sweep_due(db) is True


# ══════════════════════════════════════════════════════════════════════════════
# 7. Rapor ve zamanlayıcı entegrasyonu
# ══════════════════════════════════════════════════════════════════════════════


def test_report_summary_is_readable(db, tmp_path: Path):
    bozuk = _make_hcl(tmp_path, name="bozuk.txt")
    _register(db, bozuk)
    _register(db, _make_hcl(tmp_path, name="saglam.txt"))
    _corrupt_tag(bozuk)

    metin = sweep_integrity(db, _KEY).summary()
    assert "2/2 dosya kontrol edildi" in metin
    assert "1 sağlam" in metin and "1 bozuk" in metin


def test_verdict_str_names_the_file_and_status(db, tmp_path: Path):
    v = FileVerdict(
        file_id=1, filename="a.txt", filepath="/x/a.txt",
        status=IntegrityStatus.TAG_MISMATCH, reason="tag tutmadi",
    )
    assert "tag_mismatch" in str(v) and "a.txt" in str(v)


def test_integrity_job_is_registered_with_the_scheduler(monkeypatch):
    from CORE import scheduler

    kayitli: list[str] = []

    class SahteScheduler:
        def __init__(self, *a, **k) -> None:
            pass

        def add_job(self, func, **kwargs):
            kayitli.append(kwargs["id"])

        def start(self) -> None:
            pass

        def shutdown(self, **kwargs) -> None:
            pass

    monkeypatch.setattr(scheduler, "BackgroundScheduler", SahteScheduler)
    monkeypatch.setattr(scheduler, "_scheduler", None)
    try:
        scheduler.start_scheduler()
        assert "integrity_sweep" in kayitli
    finally:
        monkeypatch.setattr(scheduler, "_scheduler", None)


def test_integrity_job_skips_silently_without_a_key(monkeypatch):
    """Anahtar yoksa tarama patlamamalı, sessizce atlamalı."""
    from CORE import scheduler

    monkeypatch.setattr(scheduler, "_key_provider", None)
    scheduler._integrity_sweep()          # istisna fırlatmamalı

    monkeypatch.setattr(scheduler, "_key_provider", lambda: None)
    scheduler._integrity_sweep()


def test_stop_scheduler_sets_the_cancellation_flag():
    from CORE import scheduler

    scheduler._stop_event.clear()
    scheduler.stop_scheduler()
    assert scheduler._stop_event.is_set()
    scheduler._stop_event.clear()
