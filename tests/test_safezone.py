"""
HYCLEUS — SafeZone testleri

Asıl soru "dosya silindi mi" değil — `unlink` de siler. Soru şu: içerik
silinmeden ÖNCE üzerine yazıldı mı? Bu yüzden testlerin bir kısmı ham disk
byte'larına bakıyor: `shred_file`'ın açtığı dosya tanıtıcısı yakalanıp
gerçekten rastgele veri yazıldığı doğrulanıyor.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from CORE import safezone
from CORE.audit_chain import verify_audit_chain
from CORE.safezone import (
    SAFEZONE_DIRNAME,
    SAFEZONE_ENV_VAR,
    allocate,
    list_leftovers,
    purge,
    purge_on_exit,
    purge_orphans,
    safezone_dir,
    safezone_file,
)

_GIZLI = b"COZULMUS_BELGE_ICERIGI_c7f21a" + b"dolgu" * 200


def _actions(db) -> list[str]:
    return [r["action"] for r in db.fetchall("SELECT action FROM audit_log ORDER BY id")]


@pytest.fixture(autouse=True)
def isolate_safezone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """
    SafeZone'u her test için tmp_path'e taşır.

    autouse — varsayılan konum data/safezone; testlerin kullanıcının gerçek
    çalışma alanını süpürmesi kabul edilemez.
    """
    hedef = tmp_path / "safezone"
    monkeypatch.setenv(SAFEZONE_ENV_VAR, str(hedef))
    return hedef


def _yaz(icerik: bytes = _GIZLI, suffix: str = ".tmp") -> Path:
    p = allocate(suffix=suffix)
    p.write_bytes(icerik)
    return p


# ══════════════════════════════════════════════════════════════════════════════
# 1. Konum — sistem TEMP'i DEĞİL
# ══════════════════════════════════════════════════════════════════════════════


def test_safezone_is_not_the_system_temp(isolate_safezone: Path, monkeypatch):
    """
    Asıl gereksinim: SafeZone sistem TEMP'inin altında OLMAMALI.

    Ortam değişkeni kaldırılıp gerçek varsayılan konum sınanıyor.
    """
    import tempfile

    from CORE.paths import data_dir

    monkeypatch.delenv(SAFEZONE_ENV_VAR, raising=False)
    varsayilan = safezone_dir(create=False)

    assert varsayilan == data_dir() / SAFEZONE_DIRNAME
    sistem_temp = Path(tempfile.gettempdir()).resolve()
    assert sistem_temp not in varsayilan.resolve().parents
    assert varsayilan.resolve() != sistem_temp


def test_safezone_sits_next_to_the_vault_data(monkeypatch):
    """data/ ile aynı birimde olmalı — shred'in varsayımı orada geçerli."""
    from CORE.paths import data_dir

    monkeypatch.delenv(SAFEZONE_ENV_VAR, raising=False)
    assert safezone_dir(create=False).parent == data_dir()


def test_env_override_is_honoured(isolate_safezone: Path):
    assert safezone_dir(create=False) == isolate_safezone


def test_directory_is_created_on_demand(isolate_safezone: Path):
    assert not isolate_safezone.exists()
    safezone_dir()
    assert isolate_safezone.is_dir()


@pytest.mark.skipif(os.name == "nt", reason="Windows ACL devralır, mode yok sayılır")
def test_directory_is_owner_only_on_posix(isolate_safezone: Path):
    safezone_dir()
    assert (isolate_safezone.stat().st_mode & 0o777) == 0o700


# ══════════════════════════════════════════════════════════════════════════════
# 2. Dosya ayırma
# ══════════════════════════════════════════════════════════════════════════════


def test_allocate_returns_a_path_inside_the_safezone(isolate_safezone: Path):
    p = allocate(suffix=".pdf")
    assert p.parent == isolate_safezone
    assert p.suffix == ".pdf"


def test_allocate_does_not_create_the_file(isolate_safezone: Path):
    assert not allocate().exists()


def test_allocated_names_are_unique(isolate_safezone: Path):
    adlar = {allocate().name for _ in range(200)}
    assert len(adlar) == 200


def test_allocated_names_do_not_leak_the_original_filename(isolate_safezone: Path):
    """
    Dizin girdisi bile "şu belge açıldı" bilgisini sızdırmamalı.

    Ad rastgele; çağıran orijinal adı geçirse bile (suffix dışında)
    dosya adına girmiyor.
    """
    p = allocate(suffix=".pdf")
    assert "gizli" not in p.name.lower()
    assert p.stem.startswith("hycleus_")
    assert len(p.stem) > 20   # rastgele bileşen


# ══════════════════════════════════════════════════════════════════════════════
# 3. Güvenli silme — üzerine yazma DOĞRULANIYOR
# ══════════════════════════════════════════════════════════════════════════════


def test_purge_removes_the_file(isolate_safezone: Path):
    p = _yaz()
    assert p.exists()

    rapor = purge()

    assert not p.exists()
    assert rapor.shredded == 1
    assert rapor.clean


def test_purge_overwrites_before_deleting(isolate_safezone: Path, monkeypatch):
    """
    Silmeden ÖNCE üzerine yazılmalı — testin asıl konusu bu.

    secure_erase.shred_file'ın yazdığı byte'lar yakalanıyor: dosyaya
    yazılan içerikte orijinal düz metin OLMAMALI ve yazma unlink'ten önce
    gerçekleşmeli.
    """
    from CORE import secure_erase

    yazilanlar: list[bytes] = []
    silinenler: list[str] = []
    gercek_open = open

    class _Izleyen:
        def __init__(self, fh):
            self._fh = fh

        def write(self, data):
            yazilanlar.append(bytes(data))
            return self._fh.write(data)

        def __getattr__(self, ad):
            return getattr(self._fh, ad)

        def __enter__(self):
            self._fh.__enter__()
            return self

        def __exit__(self, *a):
            return self._fh.__exit__(*a)

    def izleyen_open(path, *a, **k):
        return _Izleyen(gercek_open(path, *a, **k))

    gercek_unlink = Path.unlink

    def izleyen_unlink(self, *a, **k):
        silinenler.append(self.name)
        # unlink anında yazma ZATEN olmuş olmalı
        assert yazilanlar, "unlink, üzerine yazmadan önce çağrıldı"
        return gercek_unlink(self, *a, **k)

    p = _yaz()
    monkeypatch.setattr(secure_erase, "open", izleyen_open, raising=False)
    monkeypatch.setattr(Path, "unlink", izleyen_unlink)
    purge()
    monkeypatch.undo()

    assert silinenler == [p.name]
    assert yazilanlar, "hiç üzerine yazma yapılmadı"
    for blok in yazilanlar:
        assert b"COZULMUS_BELGE_ICERIGI_c7f21a" not in blok
    # Yazılan toplam en az dosya boyutu kadar olmalı (3 tur bekleniyor)
    assert sum(len(b) for b in yazilanlar) >= len(_GIZLI)


def test_purge_handles_many_files(isolate_safezone: Path):
    yollar = [_yaz(suffix=f".{i}") for i in range(25)]
    rapor = purge()
    assert rapor.shredded == 25
    assert not any(p.exists() for p in yollar)


def test_purge_clears_nested_directories(isolate_safezone: Path):
    alt = safezone_dir() / "alt" / "daha_alt"
    alt.mkdir(parents=True)
    (alt / "gizli.tmp").write_bytes(_GIZLI)

    rapor = purge()

    assert rapor.shredded == 1
    assert not (alt / "gizli.tmp").exists()
    assert not alt.exists(), "boşalan alt dizin kaldırılmalı"
    assert safezone_dir(create=False).exists(), "SafeZone kökü kalmalı"


def test_purge_on_empty_safezone_is_a_noop(isolate_safezone: Path):
    rapor = purge()
    assert rapor.shredded == 0
    assert not rapor.had_leftovers
    assert "temiz" in rapor.summary()


def test_purge_continues_after_a_failure(isolate_safezone: Path, monkeypatch):
    """
    Bir dosya silinemezse diğerleri YİNE DE silinmeli.

    Erken çıkmak, silinebilecek düz metin kopyalarını diskte bırakırdı.
    """
    from CORE import safezone as sz

    sorunlu = _yaz(suffix=".kilitli")
    digerleri = [_yaz(suffix=f".{i}") for i in range(3)]

    gercek_shred = sz.shred_file

    def secici_shred(path: Path, *a, **k):
        if path.name == sorunlu.name:
            raise PermissionError(13, "Dosya kilitli")
        return gercek_shred(path, *a, **k)

    monkeypatch.setattr(sz, "shred_file", secici_shred)
    rapor = purge()
    monkeypatch.undo()

    assert rapor.shredded == 3
    assert rapor.failed == 1
    assert not rapor.clean
    assert not any(p.exists() for p in digerleri)
    assert rapor.errors[0][0] == sorunlu.name
    assert "SİLİNEMEDİ" in rapor.summary()


# ══════════════════════════════════════════════════════════════════════════════
# 4. Bağlam yöneticisi
# ══════════════════════════════════════════════════════════════════════════════


def test_context_manager_shreds_on_exit(isolate_safezone: Path):
    with safezone_file(suffix=".pdf") as tmp:
        tmp.write_bytes(_GIZLI)
        assert tmp.exists()
        yol = tmp
    assert not yol.exists()


def test_context_manager_shreds_even_when_the_block_raises(isolate_safezone: Path):
    """İstisna çıksa da düz metin kopyası kalmamalı."""
    yol: Path | None = None
    with pytest.raises(RuntimeError):
        with safezone_file() as tmp:
            tmp.write_bytes(_GIZLI)
            yol = tmp
            raise RuntimeError("akış patladı")
    assert yol is not None and not yol.exists()


def test_context_manager_tolerates_an_unused_file(isolate_safezone: Path):
    """Dosya hiç yazılmadıysa çıkış patlamamalı."""
    with safezone_file() as tmp:
        pass
    assert not tmp.exists()


def test_context_manager_leaves_the_safezone_empty(isolate_safezone: Path):
    with safezone_file() as tmp:
        tmp.write_bytes(_GIZLI)
    assert list_leftovers() == []


# ══════════════════════════════════════════════════════════════════════════════
# 5. Artakalan senaryosu — çökme sonrası açılış
# ══════════════════════════════════════════════════════════════════════════════


def test_leftovers_are_detected(isolate_safezone: Path):
    """Çökme simülasyonu: dosya SafeZone'da, temizlik hiç çalışmamış."""
    p = _yaz()
    kalanlar = list_leftovers()
    assert [k.name for k in kalanlar] == [p.name]


def test_startup_purges_leftovers_from_a_crashed_session(isolate_safezone: Path, db):
    # Önceki oturum çökmüş gibi: iki dosya ortada kalmış
    kalanlar = [_yaz(suffix=".a"), _yaz(suffix=".b")]

    rapor = purge_orphans(db)

    assert rapor.shredded == 2
    assert rapor.had_leftovers
    assert not any(p.exists() for p in kalanlar)
    assert list_leftovers() == []


def test_startup_on_a_clean_safezone_logs_nothing(isolate_safezone: Path, db):
    """Normal açılışta denetim kaydı kirletilmemeli."""
    onceki = len(_actions(db))
    rapor = purge_orphans(db)

    assert not rapor.had_leftovers
    assert len(_actions(db)) == onceki


def test_startup_purge_is_audited(isolate_safezone: Path, db):
    _yaz(suffix=".a")
    purge_orphans(db)

    row = db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'safezone_orphans_purged'"
    )
    assert row is not None
    assert "shredded=1" in row["detail"]
    assert "reason=startup_orphans" in row["detail"]


def test_shutdown_purge_is_audited_with_its_own_action(isolate_safezone: Path, db):
    """
    Açılış ve kapanış temizliği AYRI action — anlamları farklı.

    Kapanış rutin; açılışta bulunan artık bir ÇÖKME kanıtıdır ve denetim
    kaydında öyle ayırt edilebilmeli.
    """
    _yaz()
    purge_on_exit(db)

    actions = _actions(db)
    assert "safezone_purged" in actions
    assert "safezone_orphans_purged" not in actions


def test_purge_audit_entry_is_in_the_hash_chain(isolate_safezone: Path, db):
    _yaz()
    onceki = verify_audit_chain(db.conn).checked

    purge_orphans(db)

    sonuc = verify_audit_chain(db.conn)
    assert sonuc.ok is True
    assert sonuc.checked == onceki + 1


def test_purge_audit_lists_the_file_names(isolate_safezone: Path, db):
    p = _yaz()
    purge_orphans(db)
    detail = db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'safezone_orphans_purged'"
    )["detail"]
    assert p.name in detail


def test_purge_audit_truncates_a_long_file_list(isolate_safezone: Path, db):
    """15 dosyanın tamamı detail'e yazılmamalı — denetim kaydı okunabilir kalsın."""
    for i in range(15):
        _yaz(suffix=f".{i}")
    purge_orphans(db)

    detail = db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'safezone_orphans_purged'"
    )["detail"]
    assert "shredded=15" in detail
    assert "(+5)" in detail


def test_purge_works_without_a_database(isolate_safezone: Path):
    """DB yoksa temizlik yine de yapılmalı — denetim ikincil."""
    p = _yaz()
    rapor = purge_orphans(None)
    assert rapor.shredded == 1
    assert not p.exists()


def test_audit_failure_does_not_abort_the_purge(isolate_safezone: Path, monkeypatch):
    """Denetime yazılamasa bile dosya İMHA EDİLMİŞ olmalı."""
    class PatlayanDB:
        def log(self, *a, **k):
            raise RuntimeError("denetim yazılamadı")

    p = _yaz()
    rapor = purge_orphans(PatlayanDB())
    assert rapor.shredded == 1
    assert not p.exists()


def test_full_lifecycle_leaves_nothing_behind(isolate_safezone: Path, db):
    """Açılış → kullanım → kapanış: hiçbir aşamada düz metin kalmıyor."""
    purge_orphans(db)

    with safezone_file(suffix=".pdf") as tmp:
        tmp.write_bytes(_GIZLI)
    assert list_leftovers() == []

    rapor = purge_on_exit(db)
    assert not rapor.had_leftovers
    assert list_leftovers() == []
