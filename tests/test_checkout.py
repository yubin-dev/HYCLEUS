"""
CORE.checkout — şeffaf erişim (çöz → düzenle → geri şifrele) testleri.

Qt yok: kayıt defteri, değişiklik tespiti, atomik geri yazma ve güvenli
silme başsız koşuyor. İzleyici ve uygulama başlatma arayüz tarafında
(tests/test_checkout_ui.py).

Bu paketin sınadığı dört tasarım kararı:
  1. Değişmemiş dosya GERİ YAZILMIYOR (gereksiz nonce/şifreleme yok)
  2. Aynı belge iki kez açılınca İKİNCİ KOPYA ÜRETİLMİYOR
  3. Geri yazma yarıda kesilirse orijinal `.hcl` BOZULMUYOR
  4. Geçici kopya `shred_file()` ile siliniyor — düz unlink değil
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from CORE import crypto, safezone
from CORE.checkout import (
    CheckedOutFile,
    CheckoutError,
    CheckoutRegistry,
    apply_checkin,
    check_in,
    check_in_all,
    check_out,
    discard,
    has_changed,
    is_settled,
    log_checkout,
    rewrite_encrypted,
    sha256_of,
    stale_safezone_files,
)
from CORE.crypto import AuthenticationError, decrypt_file, encrypt_file, generate_key

_USER = 5
_HWID = "TEST-HWID-CO"
_ILK = b"Sozlesme metni, ilk surum.\n" * 50
_YENI = b"Sozlesme metni, DUZENLENMIS surum.\n" * 60


@pytest.fixture(autouse=True)
def _izole(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Karantina ve SafeZone test başına ayrı dizinlere."""
    q = tmp_path / "quarantine"
    q.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", q)
    monkeypatch.setenv(safezone.SAFEZONE_ENV_VAR, str(tmp_path / "safezone"))


@pytest.fixture
def key() -> bytes:
    return generate_key()


@pytest.fixture
def reg() -> CheckoutRegistry:
    return CheckoutRegistry()


@pytest.fixture
def hcl(tmp_path: Path, key: bytes) -> Path:
    src = tmp_path / "sozlesme.txt"
    src.write_bytes(_ILK)
    dst, _sha, _aad = encrypt_file(src, key, _USER, hwid=_HWID)
    src.unlink()  # gerçek akışta kaynak kasada değil
    return dst


def _duzenle(entry: CheckedOutFile, veri: bytes = _YENI) -> None:
    entry.safe_path.write_bytes(veri)


def _eskit(entry: CheckedOutFile, saniye: float = 60.0) -> None:
    """mtime'ı geriye alır — `is_settled()` beklemek zorunda kalmasın."""
    st = entry.safe_path.stat()
    os.utime(entry.safe_path, (st.st_atime, st.st_mtime - saniye))


# ══════════════════════════════════════════════════════════════════════════════
# 1. Aç
# ══════════════════════════════════════════════════════════════════════════════


def test_checkout_writes_the_plaintext_to_safezone(reg, hcl, key) -> None:
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)

    assert entry.safe_path.read_bytes() == _ILK
    assert entry.safe_path.parent == safezone.safezone_dir()
    assert entry.original_name == "sozlesme.txt"
    assert len(reg) == 1


def test_the_temp_name_does_not_leak_the_document_name(reg, hcl, key) -> None:
    """
    SafeZone'daki ad rastgele: dizin listesi bile "şu belge açıldı"
    bilgisini sızdırır ve bu, dosya imha edildikten sonra da dizin
    girdisinde kalabilir.
    """
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    assert "sozlesme" not in entry.safe_path.name


def test_the_extension_is_preserved(reg, hcl, key) -> None:
    """Varsayılan uygulamayı seçen şey uzantı — kaybolursa dosya açılmaz."""
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    assert entry.safe_path.suffix == ".txt"


def test_the_baseline_is_the_current_content(reg, hcl, key) -> None:
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    assert entry.baseline_sha256 == hashlib.sha256(_ILK).hexdigest()
    assert has_changed(entry) is False


def test_a_wrong_key_does_not_create_a_safezone_file(reg, hcl) -> None:
    """Çözülemeyen dosya için SafeZone'da artık kalmamalı."""
    with pytest.raises(CheckoutError):
        check_out(reg, file_id=1, hcl_path=hcl, key=generate_key())
    assert safezone.list_leftovers() == []
    assert len(reg) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 2. Aynı belge iki kez açılırsa
# ══════════════════════════════════════════════════════════════════════════════


def test_opening_twice_reuses_the_same_copy(reg, hcl, key) -> None:
    """
    ASIL TEST. İki kopya olsaydı kullanıcı ikisini de düzenler, son geri
    yazan diğerinin işini silerdi.
    """
    ilk = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    ikinci = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)

    assert ikinci is ilk
    assert ikinci.reopened is True
    assert len(reg) == 1
    assert len(safezone.list_leftovers()) == 1


def test_reopening_does_not_discard_unsaved_edits(reg, hcl, key) -> None:
    """İkinci açma, düzenlenmiş kopyanın üzerine ORİJİNALİ yazmamalı."""
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)

    yeniden = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    assert yeniden.safe_path.read_bytes() == _YENI


def test_two_different_files_get_two_copies(reg, tmp_path, key) -> None:
    a = tmp_path / "a.txt"
    a.write_bytes(b"AAA")
    b = tmp_path / "b.txt"
    b.write_bytes(b"BBB")
    ha, _s, _d = encrypt_file(a, key, _USER, hwid=_HWID)
    hb, _s, _d = encrypt_file(b, key, _USER, hwid=_HWID)

    e1 = check_out(reg, file_id=1, hcl_path=ha, key=key, aad_hwid=_HWID)
    e2 = check_out(reg, file_id=2, hcl_path=hb, key=key, aad_hwid=_HWID)
    assert e1.safe_path != e2.safe_path
    assert len(reg) == 2


def test_a_vanished_copy_is_re_decrypted(reg, hcl, key) -> None:
    """
    Kayıt var ama dosya yok (kullanıcı sildi / temizlik geçti): yeniden
    çözülmeli, yoksa "Aç" hiçbir şey yapmazdı.
    """
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    entry.safe_path.unlink()

    yeniden = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    assert yeniden.safe_path.is_file()
    assert yeniden.safe_path.read_bytes() == _ILK


# ══════════════════════════════════════════════════════════════════════════════
# 3. Değişiklik tespiti
# ══════════════════════════════════════════════════════════════════════════════


def test_an_edit_is_detected(reg, hcl, key) -> None:
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)
    assert has_changed(entry) is True


def test_a_rewrite_with_identical_content_is_not_a_change(reg, hcl, key) -> None:
    """
    Bazı uygulamalar kaydederken içeriği değiştirmeden dosyayı yeniden
    yazıyor. Özete bakmanın sebebi bu — `mtime` "değişti" derdi.
    """
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry, _ILK)  # aynı içerik, yeni mtime
    assert has_changed(entry) is False


def test_a_touched_file_is_not_a_change(reg, hcl, key) -> None:
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    st = entry.safe_path.stat()
    os.utime(entry.safe_path, (st.st_atime + 1000, st.st_mtime + 1000))
    assert has_changed(entry) is False


def test_a_deleted_copy_is_not_a_change(reg, hcl, key) -> None:
    """"Silinmiş" ile "değişmiş" aynı şey değil — şifrelenecek içerik yok."""
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    entry.safe_path.unlink()
    assert has_changed(entry) is False


def test_settling_waits_for_writes_to_stop(reg, hcl, key) -> None:
    """
    Yarısı yazılmış bir dosyayı şifrelemek, BOZUK bir belgeyi orijinalin
    üzerine yazmak olurdu.
    """
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)
    assert is_settled(entry) is False       # az önce yazıldı
    _eskit(entry)
    assert is_settled(entry) is True


# ══════════════════════════════════════════════════════════════════════════════
# 4. Geri yazma
# ══════════════════════════════════════════════════════════════════════════════


def test_the_full_cycle_re_encrypts_the_edit(reg, hcl, key) -> None:
    """ANA AKIŞ: aç → değiştir → kapat → `.hcl` yeni içeriği taşıyor."""
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)

    sonuc = check_in(reg, 1, key, user_id=_USER, hwid=_HWID)
    assert sonuc.rewritten is True

    icerik, meta = decrypt_file(hcl, key, hwid=_HWID)
    assert icerik == _YENI
    assert meta["filename"] == "sozlesme.txt"
    assert meta["original_sha256"] == hashlib.sha256(_YENI).hexdigest()


def test_an_unchanged_file_is_not_re_encrypted(reg, hcl, key) -> None:
    """
    İSTENEN DAVRANIŞ: değişmemiş dosya geri yazılmamalı.

    Yazılsaydı `.hcl` her açılışta değişir (yeni nonce), yedekleme
    araçları her belgeyi "değişmiş" görür ve zaman damgası doğrulaması
    (3.1b) her seferinde yeniden yapılması gerekirdi.
    """
    onceki = hcl.read_bytes()
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)

    sonuc = check_in(reg, 1, key, user_id=_USER, hwid=_HWID)
    assert sonuc.rewritten is False
    assert hcl.read_bytes() == onceki   # tek byte bile değişmedi


def test_the_nonce_changes_on_every_rewrite(reg, hcl, key) -> None:
    """
    Aynı anahtarla aynı nonce'u tekrar kullanmak GCM'i kırardı ve bu akış
    tam da aynı anahtarla aynı dosyayı defalarca şifreliyor.
    """
    nonce = lambda p: p.read_bytes()[5:17]  # noqa: E731
    ilk_nonce = nonce(hcl)

    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)
    rewrite_encrypted(entry, key, user_id=_USER, hwid=_HWID)
    ikinci = nonce(hcl)

    _duzenle(entry, b"ucuncu surum")
    rewrite_encrypted(entry, key, user_id=_USER, hwid=_HWID)
    ucuncu = nonce(hcl)

    assert len({ilk_nonce, ikinci, ucuncu}) == 3


def test_the_baseline_moves_after_a_writeback(reg, hcl, key) -> None:
    """Geri yazdıktan sonra aynı içerik artık "değişmiş" sayılmamalı."""
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)
    rewrite_encrypted(entry, key, user_id=_USER, hwid=_HWID)

    assert has_changed(entry) is False
    assert entry.writebacks == 1


def test_the_original_filename_survives_the_rewrite(reg, hcl, key) -> None:
    """
    Kaynak, SafeZone'daki RASTGELE adlı kopya. `src.name` kullanılsaydı
    belgenin gerçek adı o rastgele adla kalıcı olarak değişirdi.
    """
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)
    check_in(reg, 1, key, user_id=_USER, hwid=_HWID)

    _icerik, meta = decrypt_file(hcl, key, hwid=_HWID)
    assert meta["filename"] == "sozlesme.txt"
    assert "hycleus_" not in meta["filename"]


def test_the_rewritten_file_still_verifies(reg, hcl, key) -> None:
    """Geri yazılan dosya bütünlük taramasından geçmeli."""
    from CORE.crypto import verify_file

    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)
    check_in(reg, 1, key, user_id=_USER, hwid=_HWID)

    assert verify_file(hcl, key, hwid=_HWID)["filename"] == "sozlesme.txt"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Kesinti — orijinal BOZULMAMALI
# ══════════════════════════════════════════════════════════════════════════════


def test_an_interrupted_rewrite_leaves_the_original_intact(
    reg, hcl, key, monkeypatch
) -> None:
    """
    ATOMİKLİĞİN TESTİ. Son adım (`os.replace`) patlatılıyor.

    Doğrudan `.hcl` üzerine yazılsaydı bu senaryo dosyayı yarım şifreli
    bırakırdı: GCM doğrulaması düşer, haftalık bütünlük taraması sağlam
    sanılan bir belgeyi "bozuk" gösterir ve orijinal içerik geri
    getirilemezdi.
    """
    onceki = hcl.read_bytes()
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)

    import CORE.checkout as co
    monkeypatch.setattr(co.os, "replace",
                        lambda s, d: (_ for _ in ()).throw(OSError("disk dolu")))

    with pytest.raises(CheckoutError, match="Yeniden şifreleme"):
        rewrite_encrypted(entry, key, user_id=_USER, hwid=_HWID)

    assert hcl.read_bytes() == onceki
    icerik, _m = decrypt_file(hcl, key, hwid=_HWID)
    assert icerik == _ILK


def test_an_interrupted_rewrite_leaves_no_temp_file(reg, hcl, key, monkeypatch) -> None:
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)

    import CORE.checkout as co
    monkeypatch.setattr(co.os, "replace",
                        lambda s, d: (_ for _ in ()).throw(OSError("kesildi")))
    with pytest.raises(CheckoutError):
        rewrite_encrypted(entry, key, user_id=_USER, hwid=_HWID)

    assert list(hcl.parent.glob("*-rewrite-tmp*")) == []


def test_the_edit_survives_a_failed_rewrite(reg, hcl, key, monkeypatch) -> None:
    """
    Geri yazma başarısız olursa geçici kopya SİLİNMEMELİ: kullanıcının
    düzenlemesi tek nüsha hâlinde orada duruyor.
    """
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)

    import CORE.checkout as co
    monkeypatch.setattr(co.os, "replace",
                        lambda s, d: (_ for _ in ()).throw(OSError("kesildi")))
    with pytest.raises(CheckoutError):
        check_in(reg, 1, key, user_id=_USER, hwid=_HWID)

    assert entry.safe_path.read_bytes() == _YENI
    assert 1 in reg, "kayıt düşürülmemeli — düzenleme hâlâ açık"


def test_a_batch_checkin_continues_after_one_failure(reg, tmp_path, key, monkeypatch) -> None:
    """
    Kapanışta yarıda kalmak, geri kalan belgelerin düz metin kopyalarını
    diskte bırakmak demek olurdu.
    """
    yollar = []
    for i in range(3):
        s = tmp_path / f"d{i}.txt"
        s.write_bytes(f"icerik {i}".encode())
        yollar.append(encrypt_file(s, key, _USER, hwid=_HWID)[0])

    girdiler = [
        check_out(reg, file_id=i, hcl_path=p, key=key, aad_hwid=_HWID)
        for i, p in enumerate(yollar)
    ]
    for e in girdiler:
        _duzenle(e, b"degistirildi")

    gercek = os.replace
    cagri = {"n": 0}

    def _bazen_patla(s, d):
        cagri["n"] += 1
        if cagri["n"] == 2:
            raise OSError("ikinci dosyada hata")
        return gercek(s, d)

    import CORE.checkout as co
    monkeypatch.setattr(co.os, "replace", _bazen_patla)

    sonuclar = check_in_all(reg, key, user_id=_USER, hwid=_HWID)
    assert len(sonuclar) == 3
    assert sum(1 for s in sonuclar if s.rewritten) == 2


# ══════════════════════════════════════════════════════════════════════════════
# 6. Güvenli silme
# ══════════════════════════════════════════════════════════════════════════════


def test_the_temp_copy_is_shredded_on_checkin(reg, hcl, key) -> None:
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    yol = entry.safe_path
    _duzenle(entry)

    sonuc = check_in(reg, 1, key, user_id=_USER, hwid=_HWID)
    assert sonuc.shredded is True
    assert not yol.exists()
    assert len(reg) == 0


def test_shredding_overwrites_before_unlinking(reg, hcl, key, monkeypatch) -> None:
    """
    Düz `unlink` YETMEZ — içerik diskte kalırdı. `shred_file()` önce
    üzerine yazıyor; sıranın doğru olduğu gözlemleniyor.
    """
    olaylar: list[str] = []
    gercek_open = open

    def _izle(path, mode="r", *a, **kw):
        if "b" in mode and "+" in mode and safezone.SAFEZONE_DIRNAME in str(path):
            olaylar.append("overwrite")
        return gercek_open(path, mode, *a, **kw)

    import CORE.secure_erase as se
    monkeypatch.setattr(se, "open", _izle, raising=False)
    gercek_unlink = Path.unlink

    def _unlink(self, *a, **kw):
        if safezone.SAFEZONE_DIRNAME in str(self):
            olaylar.append("unlink")
        return gercek_unlink(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", _unlink)

    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    check_in(reg, 1, key, user_id=_USER, hwid=_HWID)

    assert olaylar == ["overwrite", "unlink"]


def test_discard_shreds_without_writing_back(reg, hcl, key) -> None:
    """"Kaydetmeden çık": değişiklik ATILIYOR, orijinal dokunulmamış."""
    onceki = hcl.read_bytes()
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    yol = entry.safe_path
    _duzenle(entry)

    assert discard(reg, 1) is True
    assert not yol.exists()
    assert hcl.read_bytes() == onceki
    assert len(reg) == 0


def test_a_failed_shred_does_not_raise(reg, hcl, key, monkeypatch) -> None:
    """
    Dosya hâlâ kilitli olabilir. Açılıştaki artık temizliği
    (`purge_orphans`) bunu yakalıyor — akış durmamalı.
    """
    import CORE.checkout as co
    monkeypatch.setattr(co, "shred_file",
                        lambda p: (_ for _ in ()).throw(OSError("kilitli")))

    check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    sonuc = check_in(reg, 1, key, user_id=_USER, hwid=_HWID)
    assert sonuc.shredded is False


def test_safezone_is_empty_after_a_full_cycle(reg, hcl, key) -> None:
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)
    check_in(reg, 1, key, user_id=_USER, hwid=_HWID)
    assert safezone.list_leftovers() == []


# ══════════════════════════════════════════════════════════════════════════════
# 7. Kayıt defteri ve artıklar
# ══════════════════════════════════════════════════════════════════════════════


def test_lookup_by_safe_path(reg, hcl, key) -> None:
    """İzleyici yol veriyor; kayıt ondan bulunabilmeli."""
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    assert reg.by_safe_path(entry.safe_path) is entry
    assert reg.by_safe_path("/olmayan/yol") is None


def test_checking_in_an_unknown_file_raises(reg, key) -> None:
    with pytest.raises(CheckoutError, match="Açık kayıt yok"):
        check_in(reg, 99, key, user_id=_USER)


def test_stale_files_are_reported(reg, hcl, key) -> None:
    """Hiçbir açık kayda ait olmayan SafeZone dosyaları görünür olmalı."""
    check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    artik = safezone.allocate(suffix=".tmp")
    artik.write_bytes(b"onceki oturumdan kalma")

    assert [p.name for p in stale_safezone_files(reg)] == [artik.name]


# ══════════════════════════════════════════════════════════════════════════════
# 8. Veritabanı ve denetim kaydı
# ══════════════════════════════════════════════════════════════════════════════


def _kullanici(db) -> None:
    db.execute(
        "INSERT OR IGNORE INTO users (id, username, password_hash, role, status, hwid)"
        " VALUES (5, 't', '', 'admin', 'approved', 'H')")


def test_the_db_row_is_updated_after_a_writeback(db, reg, hcl, key) -> None:
    """
    `original_sha256` güncellenmezse tekrar tespiti ESKİ özete bakar ve
    zaman damgası doğrulaması damgayı geçersiz gösterirdi.
    """
    _kullanici(db)
    db.execute(
        "INSERT INTO files (id, filename, filepath, label, original_sha256, size_bytes)"
        " VALUES (1, 'sozlesme.txt', ?, 'Genel', ?, ?)",
        (str(hcl), hashlib.sha256(_ILK).hexdigest(), len(_ILK)))

    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)
    sonuc = check_in(reg, 1, key, user_id=_USER, hwid=_HWID)
    apply_checkin(db, sonuc, user_id=_USER, hwid=_HWID)

    row = db.fetchone("SELECT original_sha256, size_bytes FROM files WHERE id = 1")
    assert row["original_sha256"] == hashlib.sha256(_YENI).hexdigest()
    assert row["size_bytes"] == len(_YENI)


def test_an_unchanged_checkin_leaves_the_row_alone(db, reg, hcl, key) -> None:
    _kullanici(db)
    eski = hashlib.sha256(_ILK).hexdigest()
    db.execute(
        "INSERT INTO files (id, filename, filepath, label, original_sha256)"
        " VALUES (1, 'sozlesme.txt', ?, 'Genel', ?)", (str(hcl), eski))

    check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    apply_checkin(db, check_in(reg, 1, key, user_id=_USER), user_id=_USER)

    assert db.fetchone(
        "SELECT original_sha256 FROM files WHERE id = 1")["original_sha256"] == eski


def test_opening_and_closing_are_audited(db, reg, hcl, key) -> None:
    """
    Açma kaydı önemli: düz metin bir kopyanın diske indiği AN burası.
    """
    _kullanici(db)
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    log_checkout(db, entry, user_id=_USER, hwid=_HWID)
    _duzenle(entry)
    apply_checkin(db, check_in(reg, 1, key, user_id=_USER), user_id=_USER)

    eylemler = [r["action"] for r in db.fetchall(
        "SELECT action FROM audit_log ORDER BY id")]
    assert "file_opened" in eylemler
    assert "file_checked_in" in eylemler


def test_an_unchanged_close_is_audited_differently(db, reg, hcl, key) -> None:
    _kullanici(db)
    check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    apply_checkin(db, check_in(reg, 1, key, user_id=_USER), user_id=_USER)

    assert db.fetchone(
        "SELECT action FROM audit_log ORDER BY id DESC LIMIT 1"
    )["action"] == "file_closed_unchanged"


def test_audit_entries_join_the_hash_chain(db, reg, hcl, key) -> None:
    _kullanici(db)
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    log_checkout(db, entry, user_id=_USER, hwid=_HWID)

    assert db.fetchone(
        "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")["entry_hash"]


# ══════════════════════════════════════════════════════════════════════════════
# 9. HWID
# ══════════════════════════════════════════════════════════════════════════════


def test_a_foreign_hwid_blocks_the_checkout(reg, hcl, key) -> None:
    """Başka cihazda şifrelenmiş dosya açılamamalı — GCM AAD kontrolü."""
    with pytest.raises(CheckoutError):
        check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid="BASKA-HWID")


def test_the_rewrite_rebinds_to_the_editing_device(reg, hcl, key) -> None:
    """
    Geri yazma bu cihazda yapıldı; AAD'deki hwid de bu cihazı göstermeli.
    Aksi hâlde AAD, dosyanın gerçekte nerede üretildiğini yanlış anlatırdı.
    """
    entry = check_out(reg, file_id=1, hcl_path=hcl, key=key, aad_hwid=_HWID)
    _duzenle(entry)
    rewrite_encrypted(entry, key, user_id=_USER, hwid="YENI-CIHAZ")

    _i, meta = decrypt_file(hcl, key, hwid="YENI-CIHAZ")
    assert meta["hwid"] == "YENI-CIHAZ"
    with pytest.raises(AuthenticationError):
        decrypt_file(hcl, key, hwid=_HWID)


def test_sha256_of_matches_hashlib(tmp_path: Path) -> None:
    p = tmp_path / "x.bin"
    veri = os.urandom(200_000)
    p.write_bytes(veri)
    assert sha256_of(p) == hashlib.sha256(veri).hexdigest()
