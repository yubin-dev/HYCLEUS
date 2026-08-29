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
    aad_map,
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
# K1-15 — USB çekilince (kilit) bulk indirme de gerçekten duruyor
# ══════════════════════════════════════════════════════════════════════════════
#
# Sorgu (2026-08-29): "USB çekilince kilitlenir" iddiası UI/main_window_lock.py
# ::_lock() için doğru (açık checkout'ları senkron kapatıyor), ama
# export_to_directory()'nin ARKA PLANDA sürmesi mümkün — `on_progress`
# (`UI/main_window_bulk.py::_ilerleme`) her turda `QApplication.
# processEvents()` çağırıyor, yani bu döngü Qt olay döngüsüne yeniden
# giriş yapabiliyor. USB tam bu processEvents() sırasında çekilirse
# `_poll_usb()` → `_lock()` çalışır ve `self._locked = True` olur — ama
# eski `should_continue=lambda: not prog.wasCanceled()` bunu HİÇ
# görmüyordu, döngü kalan dosyaları çözüp yazmaya devam ederdi.
#
# Aşağıdaki test bunu doğrudan, gerçek şifreleme ile ölçüyor:
# `on_progress`'in KENDİSİ belirli bir dosyada kilidi tetikliyor (gerçek
# `_poll_usb`/`_lock()` etkileşiminin taklidi) ve döngünün O ANDAN
# SONRA hiçbir dosya çözüp yazmadığı doğrulanıyor.


def test_lock_ortasinda_daha_fazla_dosya_yazilmiyor(db, tmp_path: Path):
    """
    ANA TEST (K1-15). `git stash` ile düzeltmeden ÖNCEki
    `CORE/export.py`'ye karşı çalıştırıldığında bu test BAŞARISIZ olur:
    kilit `on_progress(index=3, ...)` sırasında tetiklendiği hâlde
    dosya_3.txt yine de diske yazılır (`saved=4`, beklenen `saved=3`) —
    manuel canlı tekrarla TAM eşleşen sonuç.
    """
    ogeler = []
    for i in range(8):
        fid, yol = _add_encrypted(db, tmp_path, f"dosya_{i}.txt", f"gizli-{i}".encode())
        ogeler.append((fid, str(yol)))
    hedef = tmp_path / "indirilenler"
    hedef.mkdir()

    sahne = {"locked": False}

    def _ilerleme(index: int, kisa_ad: str) -> None:
        # `_poll_usb()` → `_lock()` taklidi: USB tam bu dosyanın
        # `on_progress` çağrısı sırasında çekiliyor.
        if index == 3:
            sahne["locked"] = True

    sonuc = export_to_directory(
        db, ogeler, _KEY, hedef,
        on_progress=_ilerleme,
        should_continue=lambda: not sahne["locked"],
    )

    assert sonuc.cancelled is True
    assert sonuc.saved == 3, (
        f"kilit index=3'te tetiklendi, saved 3 olmalıydı: {sonuc.saved}"
    )

    yazilanlar = {p.name for p in hedef.iterdir()}
    for i in range(3):
        assert f"dosya_{i}.txt" in yazilanlar, f"dosya_{i}.txt kilitten ÖNCE yazılmalıydı"
    for i in range(3, 8):
        assert f"dosya_{i}.txt" not in yazilanlar, (
            f"dosya_{i}.txt kilitten SONRA yazılmış — yarım kalan/gecikmiş "
            "düz metin"
        )


def test_lock_on_progress_YOKSA_ikinci_kontrol_devreye_girmiyor(db, tmp_path: Path):
    """
    Mutasyon kontrastı — negatif yön: `on_progress` HİÇ verilmezse Qt
    olay döngüsüne yeniden giriş fırsatı da yok, yani ikinci kontrol
    gereksiz. Bu test `should_continue`'un tam olarak ESKİ (tek) sayıda
    çağrıldığını doğruluyor — `test_directory_export_can_be_cancelled`'ın
    dayandığı çağrı-sayacı varsayımı hâlâ geçerli, K1-15 onu SESSİZCE
    bozmadı.
    """
    ogeler = []
    for i in range(4):
        fid, yol = _add_encrypted(db, tmp_path, f"d{i}.txt", b"x")
        ogeler.append((fid, str(yol)))
    hedef = tmp_path / "cikti"
    hedef.mkdir()

    cagri_sayisi = {"n": 0}

    def devam():
        cagri_sayisi["n"] += 1
        return True

    export_to_directory(db, ogeler, _KEY, hedef, should_continue=devam)

    assert cagri_sayisi["n"] == len(ogeler), (
        "on_progress verilmediği hâlde should_continue() beklenenden "
        "fazla/az çağrıldı"
    )


def test_lock_sirasinda_zeroizable_tampon_gercekten_sifirlaniyor(
    db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Zeroize kısmı: `export_to_directory()` artık `decrypt_file(...,
    zeroizable=True)` kullanıyor ve yazdıktan hemen sonra
    `zero_bytearray()` çağırıyor. `zero_bytearray()`'i CASUS bir
    sarmalayıcıyla değiştirip GERÇEKTEN, her dosya için TAM OLARAK bir
    kez çağrıldığını ve argümanının o dosyanın düz metin uzunluğunda bir
    `bytearray` olduğunu ölçüyoruz — yalnızca varlığını değil.
    """
    from CORE import export as export_mod

    cagrilar: list[bytes] = []
    orijinal = export_mod.zero_bytearray

    def _casus(buf: bytearray) -> None:
        cagrilar.append(bytes(buf))  # sıfırlanmadan ÖNCEki hâli kopyala
        orijinal(buf)
        assert all(b == 0 for b in buf), "zero_bytearray sonrası içerik sıfır DEĞİL"

    monkeypatch.setattr(export_mod, "zero_bytearray", _casus)

    icerikler = [b"birinci-dosyanin-gizli-verisi", b"ikinci-kisa"]
    ogeler = []
    for i, icerik in enumerate(icerikler):
        fid, yol = _add_encrypted(db, tmp_path, f"z{i}.txt", icerik)
        ogeler.append((fid, str(yol)))
    hedef = tmp_path / "cikti"
    hedef.mkdir()

    export_to_directory(db, ogeler, _KEY, hedef)

    assert len(cagrilar) == len(icerikler), (
        f"zero_bytearray() {len(icerikler)} kez çağrılmalıydı, "
        f"{len(cagrilar)} kez çağrıldı"
    )
    assert set(cagrilar) == set(icerikler), (
        "zero_bytearray()'e geçen tampon(lar) beklenen düz metinle "
        "eşleşmiyor"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 4. GİDERİLEN FARK — hwid geri dönüşü (B-010)
# ══════════════════════════════════════════════════════════════════════════════


def test_zip_falls_back_to_the_session_hwid(db, tmp_path: Path):
    """
    DB sütununda hwid yoksa ZIP akışı OTURUM hwid'iyle doğruluyor.

    Dosya başka bir hwid ile şifrelenmişse bu doğrulama düşer ve dosya
    atlanır. B-010'da bu davranış DOĞRU olan seçildi.
    """
    _add_encrypted(db, tmp_path, "baska.txt", b"x", hwid="BASKA-CIHAZ")
    # aad_metadata'yı boşalt: DB sütunundan hwid okunamasın
    db.execute("UPDATE files SET aad_metadata = NULL")

    sonuc = export_to_zip(db, _rows(db), _KEY, tmp_path / "c.zip", hwid_fallback=_HWID)
    assert sonuc.saved == 0
    assert "bütünlük hatası" in sonuc.errors[0]


def test_directory_export_falls_back_like_zip(db, tmp_path: Path):
    """
    B-010 DÜZELTMESİ — bu testin adı ve iddiası BİLEREK tersine çevrildi.

    Eski hâli `test_directory_export_does_NOT_fall_back_by_default` idi ve
    farkı SABİTLİYORDU: aynı dosyayı ZIP akışı reddederken toplu indirme
    kabul ediyordu, çünkü çağıran `hwid_fallback` geçmediği için
    `decrypt_file`'a `hwid=None` gidiyor ve kontrol hiç çalışmıyordu.

    Artık iki akış aynı kararı veriyor.
    """
    fid, yol = _add_encrypted(db, tmp_path, "baska.txt", b"icerik", hwid="BASKA-CIHAZ")
    db.execute("UPDATE files SET aad_metadata = NULL")
    hedef = tmp_path / "cikti"
    hedef.mkdir()

    sonuc = export_to_directory(
        db, [(fid, str(yol))], _KEY, hedef,
        session_hwid=_HWID, hwid_fallback=_HWID,
    )

    assert sonuc.saved == 0
    assert "bütünlük hatası" in sonuc.errors[0]
    assert not (hedef / "baska.txt").exists()


def test_iki_akis_ayni_dosyada_ayni_karari_veriyor(db, tmp_path: Path):
    """
    B-010'UN ÖZÜ: bulgu "toplu indirme doğrulamıyor" değil, İKİSİNİN
    AYRIŞMASIYDI. İkisini tek testte yan yana koymak, ileride biri
    değişirse bunu tek kırılmayla gösterir.
    """
    fid, yol = _add_encrypted(db, tmp_path, "baska.txt", b"icerik", hwid="BASKA-CIHAZ")
    db.execute("UPDATE files SET aad_metadata = NULL")
    hedef = tmp_path / "cikti"
    hedef.mkdir()

    zip_sonuc = export_to_zip(
        db, _rows(db), _KEY, tmp_path / "c.zip", hwid_fallback=_HWID
    )
    dizin_sonuc = export_to_directory(
        db, [(fid, str(yol))], _KEY, hedef, hwid_fallback=_HWID
    )
    assert zip_sonuc.saved == dizin_sonuc.saved
    assert bool(zip_sonuc.errors) == bool(dizin_sonuc.errors)


def test_dogru_cihazda_iki_akis_da_calisiyor(db, tmp_path: Path):
    """
    Düzeltme yalnızca YANLIŞ cihazı reddetmeli.

    Bu test olmadan "her şeyi reddet" mutasyonu da geçerdi.
    """
    fid, yol = _add_encrypted(db, tmp_path, "bizim.txt", b"icerik", hwid=_HWID)
    db.execute("UPDATE files SET aad_metadata = NULL")
    hedef = tmp_path / "cikti"
    hedef.mkdir()

    assert export_to_zip(
        db, _rows(db), _KEY, tmp_path / "c.zip", hwid_fallback=_HWID
    ).saved == 1
    assert export_to_directory(
        db, [(fid, str(yol))], _KEY, hedef, hwid_fallback=_HWID
    ).saved == 1


def test_bulk_cagri_yeri_hwid_fallback_geciyor():
    """
    ASIL KORUMA — `hwid_fallback` varsayılanı None olduğu için, çağrı
    yerinden düşerse hiçbir şey patlamaz: doğrulama sessizce kapanır.
    B-010'un ilk hâli tam olarak buydu.
    """
    import ast
    from pathlib import Path as _P

    kaynak = (_P(__file__).resolve().parent.parent / "UI" / "main_window_bulk.py")
    cagrilar = [
        d
        for d in ast.walk(ast.parse(kaynak.read_text(encoding="utf-8")))
        if isinstance(d, ast.Call)
        and isinstance(d.func, ast.Name)
        and d.func.id == "export_to_directory"
    ]
    assert cagrilar, "toplu indirme artık export_to_directory çağırmıyor"
    for cagri in cagrilar:
        assert "hwid_fallback" in {k.arg for k in cagri.keywords}, (
            "hwid_fallback geçilmiyor — hwid doğrulaması sessizce kapanır"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 5. N+1 sorgu (B-009)
# ══════════════════════════════════════════════════════════════════════════════


class _SayanDB:
    """`fetchall`/`fetchone` çağrılarını sayan ince sarmalayıcı."""

    def __init__(self, gercek):
        self._gercek = gercek
        self.fetchall_sayisi = 0
        self.fetchone_sayisi = 0
        #: Her `fetchall` çağrısına bağlanan parametre sayısı.
        self.bagli_parametreler: list[int] = []

    def fetchall(self, *a, **k):
        self.fetchall_sayisi += 1
        self.bagli_parametreler.append(len(a[1]) if len(a) > 1 else 0)
        return self._gercek.fetchall(*a, **k)

    def fetchone(self, *a, **k):
        self.fetchone_sayisi += 1
        return self._gercek.fetchone(*a, **k)

    def __getattr__(self, ad):
        return getattr(self._gercek, ad)


def test_toplu_indirme_dosya_basina_sorgu_atmiyor(db, tmp_path: Path):
    """
    B-009 DÜZELTMESİ — sorgu sayısı dosya sayısıyla ARTMAMALI.

    Ölçüm sayıya bakıyor, kodun şekline değil: `WHERE id IN (...)` tekrar
    döngüye girerse bu test söyler.
    """
    hedef = tmp_path / "cikti"
    hedef.mkdir()
    items = [
        _add_encrypted(db, tmp_path, f"d{i}.txt", b"x", hwid=_HWID)
        for i in range(8)
    ]
    sayan = _SayanDB(db)

    sonuc = export_to_directory(
        sayan, [(fid, str(yol)) for fid, yol in items], _KEY, hedef,
        hwid_fallback=_HWID,
    )

    assert sonuc.saved == 8
    assert sayan.fetchone_sayisi == 0, "döngü içi fetchone geri gelmiş"
    assert sayan.fetchall_sayisi == 1, (
        f"8 dosya için {sayan.fetchall_sayisi} sorgu — N+1 geri gelmiş"
    )


def test_aad_map_bulunamayan_idyi_atliyor(db, tmp_path: Path):
    """Olmayan id sözlükte yer almamalı; çağıran `.get()` ile None'a düşer."""
    fid, _yol = _add_encrypted(db, tmp_path, "var.txt", b"x", hwid=_HWID)
    harita = aad_map(db, [fid, 9999])
    assert fid in harita
    assert 9999 not in harita
    assert harita.get(9999) is None


def test_aad_map_tekrarli_idleri_bir_kez_soruyor(db, tmp_path: Path):
    """
    Aynı id birden çok kez verilirse sorguya BİR KEZ bağlanmalı.

    İlk yazılışında bu test yalnızca sonuç sözlüğüne ve sorgu sayısına
    bakıyordu — ikisi de tekilleştirme olmadan da doğru çıkıyor, yani
    test hiçbir şey kanıtlamıyordu (mutasyon hayatta kaldı). Asıl ölçüm
    BAĞLANAN PARAMETRE SAYISI: tekilleştirme olmazsa 2000 tekrarlı id
    parça sınırını gereksiz yere aşar.
    """
    fid, _yol = _add_encrypted(db, tmp_path, "var.txt", b"x", hwid=_HWID)
    sayan = _SayanDB(db)

    harita = aad_map(sayan, [fid, fid, fid])

    assert list(harita) == [fid]
    assert sayan.fetchall_sayisi == 1
    assert sayan.bagli_parametreler == [1], (
        f"tekilleştirme yok — {sayan.bagli_parametreler[0]} parametre bağlandı"
    )


def test_aad_map_tekilleştirme_parcalamayi_da_etkiliyor(db):
    """
    Tekilleştirmenin neden yalnızca süs olmadığı: 2000 tekrarlı id,
    tekilleştirilmezse 3 sorguya bölünür; tekilleştirilince 1 sorgu.
    """
    sayan = _SayanDB(db)
    aad_map(sayan, [7] * 2000)
    assert sayan.fetchall_sayisi == 1
    assert sayan.bagli_parametreler == [1]


def test_aad_map_bos_liste_sorgu_atmiyor(db):
    sayan = _SayanDB(db)
    assert aad_map(sayan, []) == {}
    assert sayan.fetchall_sayisi == 0


def test_aad_map_parametre_sinirinin_uzerinde_parcaliyor(db):
    """
    SQLite'ın `SQLITE_MAX_VARIABLE_NUMBER` sınırı (eski varsayılan 999).

    Parçalama olmasaydı büyük bir toplu indirme `OperationalError` ile
    düşerdi — N+1'i düzeltirken kolayca eklenebilecek bir gerileme.

    İd sayısı SABİT (2000), `_IN_CHUNK`'tan TÜRETİLMİYOR. İlk yazılışında
    türetiliyordu ve sabiti büyüten bir mutasyon testin kendisine iki
    milyarlık liste ayırttı — testi askıda bıraktı. Sabiti sınayan bir
    test, boyutunu o sabitten almamalı.
    """
    from CORE.export import _IN_CHUNK

    assert _IN_CHUNK <= 999, "SQLite'ın eski parametre sınırının üstünde"

    sayan = _SayanDB(db)
    harita = aad_map(sayan, list(range(1, 2001)))   # takılırsa fırlar
    assert harita == {}                              # hiçbiri gerçek değil
    assert sayan.fetchall_sayisi == 3                # ceil(2000 / 900)


def test_export_result_defaults_are_clean():
    assert ExportResult().clean is True
