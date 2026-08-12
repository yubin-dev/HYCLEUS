"""
CORE.recovery_share + vault_manager kurtarma akışı.

Gerçek vault oluşturulur, gerçek Argon2id/GCM kullanılır; yalnızca vault
dizini tmp_path'e yönlendirilir.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from CORE import recovery_share, vault_manager
from CORE.recovery_share import (
    RecoveryShareError,
    build_export,
    decode_share,
    encode_share,
)
from CORE.vault_manager import (
    create_vault,
    export_recovery_share,
    has_recovery_share,
    open_vault,
    recover_master_key,
)

_HWID = "USB-REC-TEST"
_PIN = "kurtarma-pin-1"
_ROLE = "Yönetici"


@pytest.fixture
def vault(db, tmp_path: Path, monkeypatch) -> str:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    create_vault(_HWID, _PIN, _ROLE)
    return _HWID


# ── Kodlama / çözme ───────────────────────────────────────────────────────────

def test_encode_decode_round_trip() -> None:
    _s1, _s2, share_3 = vault_manager._sss_split(b"\xab" * 32)

    text = encode_share(share_3)
    assert text.startswith("HYCLEUS-R3-")
    assert decode_share(text) == share_3


def test_encoded_text_is_transcription_friendly() -> None:
    """
    Base32 gövdesi yalnızca A-Z ve 2-7 içermeli.

    0, 1, 8, 9 rakamlarının alfabede olmaması O/0 ve I/L/1 karışmasını
    yapısal olarak engeller — elle kâğıttan girilecek bir metin için önemli.
    """
    _s1, _s2, share_3 = vault_manager._sss_split(b"\x11" * 32)
    text = encode_share(share_3)

    govde = text.replace("HYCLEUS-R3-", "").replace("-", "")
    assert govde.isupper()
    assert set(govde) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    for rakam in "0189":
        assert rakam not in govde, f"{rakam!r} base32 gövdesinde olmamalı"


@pytest.mark.parametrize(
    "bozuk",
    ["", "   ", "rastgele metin", "HYCLEUS-R3-!!!!", "3:" + "ab" * 33],
)
def test_decode_rejects_malformed_text(bozuk: str) -> None:
    with pytest.raises(RecoveryShareError):
        decode_share(bozuk)


def test_decode_tolerates_user_typing_variations() -> None:
    """Elle girilirken boşluk, satır sonu, küçük harf ve tire farkları tolere edilmeli."""
    _s1, _s2, share_3 = vault_manager._sss_split(b"\x5c" * 32)
    text = encode_share(share_3)

    for varyant in (
        text.lower(),
        text.replace("-", " "),
        text.replace("-", ""),
        f"  {text}\n",
        text.replace("-", "\n"),
    ):
        assert decode_share(varyant) == share_3


def test_truncated_share_is_rejected() -> None:
    """Eksik yazılmış parça sessizce yanlış anahtar üretmemeli."""
    _s1, _s2, share_3 = vault_manager._sss_split(b"\x77" * 32)
    text = encode_share(share_3)

    with pytest.raises(RecoveryShareError, match="byte olmalı|çözümlenemedi"):
        decode_share(text[:-8])


def test_encode_rejects_non_recovery_share() -> None:
    """Yanlışlıkla share_1 veya share_2 dışa aktarılmamalı."""
    share_1, share_2, _s3 = vault_manager._sss_split(b"\x01" * 32)
    for yanlis in (share_1, share_2):
        with pytest.raises(RecoveryShareError, match="3 indisli"):
            encode_share(yanlis)


# ── Dışa aktarım paketi ───────────────────────────────────────────────────────

def test_build_export_contains_warning_and_both_formats() -> None:
    _s1, _s2, share_3 = vault_manager._sss_split(b"\x2f" * 32)

    export = build_export(share_3)

    assert export.base32_text.startswith("HYCLEUS-R3-")
    assert export.qr_svg is not None and "<svg" in export.qr_svg
    assert decode_share(export.base32_text) == share_3

    # Uyarı metni fiziksel saklamayı söylemeli, dijitali yasaklamalı.
    # Türkçe büyük İ'nin lower() davranışı sorunlu olduğu için metin
    # olduğu gibi (büyük harfli hâliyle) aranıyor.
    uyari = export.warning
    assert "FİZİKSEL" in uyari
    assert "DİJİTAL OLARAK SAKLAMAYIN" in uyari
    assert "kasa" in uyari
    assert "ekran görüntüsü almayın" in uyari
    assert uyari in export.printable()


def test_qr_encodes_exactly_the_base32_text() -> None:
    """QR ile metin aynı payı taşımalı — ikisi de tek başına yeterli."""
    _s1, _s2, share_3 = vault_manager._sss_split(b"\x9d" * 32)
    export = build_export(share_3)

    assert export.qr_svg is not None
    # Aynı girdi aynı QR'ı üretmeli (deterministik) ve QR tam olarak
    # base32 metninden üretilmiş olmalı
    assert recovery_share.render_qr_svg(export.base32_text) == export.qr_svg
    assert recovery_share.render_qr_svg("baska-metin") != export.qr_svg
    assert decode_share(export.base32_text) == share_3


def test_export_without_qr_still_works() -> None:
    """qrcode yoksa base32 tek başına yeterli olmalı."""
    _s1, _s2, share_3 = vault_manager._sss_split(b"\x44" * 32)
    export = build_export(share_3, with_qr=False)
    assert export.qr_svg is None
    assert decode_share(export.base32_text) == share_3


# ── Kalıcı iz bırakmama ───────────────────────────────────────────────────────

def _tum_db_baytlari(db) -> bytes:
    blob = b""
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(db._db_path) + suffix)
        if p.exists():
            blob += p.read_bytes()
    return blob


def test_exported_share_leaves_no_trace_on_disk(vault, db, tmp_path: Path) -> None:
    """
    ASIL GÜVENLİK TESTİ: kurtarma parçası hiçbir yere yazılmamalı.

    DB (WAL dahil), vault dosyaları ve tmp_path altındaki her şey taranır;
    ne ham pay, ne base32 metni, ne QR içeriği bulunmalı.
    """
    share_3 = export_recovery_share(vault, _PIN)
    export = build_export(share_3)

    ham = share_3.split(":", 1)[1].encode()
    metin = export.base32_text.encode()
    govde = export.base32_text.replace("HYCLEUS-R3-", "").replace("-", "").encode()

    db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db_baytlari = _tum_db_baytlari(db)
    for aranan, ad in ((ham, "ham hex"), (metin, "base32 metin"), (govde, "base32 gövde")):
        assert aranan not in db_baytlari, f"kurtarma parçası DB'de bulundu ({ad})"

    # Vault dosyaları ve tmp_path altındaki her şey
    for dosya in tmp_path.rglob("*"):
        if not dosya.is_file() or dosya.name.startswith("hycleus_test.db"):
            continue
        icerik = dosya.read_bytes()
        for aranan, ad in ((ham, "ham hex"), (metin, "base32 metin")):
            assert aranan not in icerik, f"kurtarma parçası {dosya} içinde ({ad})"


def test_only_timestamp_is_recorded_not_the_share(vault, db) -> None:
    """DB'ye yalnızca 'dışa aktarıldı' zamanı yazılmalı."""
    assert has_recovery_share(vault) is False

    share_3 = export_recovery_share(vault, _PIN)

    assert has_recovery_share(vault) is True
    row = db.fetchone("SELECT * FROM usb_tokens WHERE hwid = ?", (vault,))
    assert row["recovery_issued_at"]
    for deger in tuple(row):
        if isinstance(deger, str):
            assert share_3 not in deger
            assert share_3.split(":", 1)[1] not in deger


def test_export_is_audited(vault, db) -> None:
    export_recovery_share(vault, _PIN)
    kayitlar = db.fetchall(
        "SELECT detail FROM audit_log WHERE action = 'recovery_share_exported'"
    )
    assert len(kayitlar) == 1
    # Audit log'a da parça yazılmamalı
    assert "3:" not in kayitlar[0]["detail"]


def test_repeated_export_yields_the_same_share(vault, db) -> None:
    """
    Kurtarma parçası deterministiktir — kaybedilirse yeniden üretilebilir.

    Aynı polinomdan türetildiği için her seferinde aynı değer çıkar; bu,
    "yeniden üret" akışının vault'u yeniden anahtarlamadığını gösterir.
    """
    ilk = export_recovery_share(vault, _PIN)
    ikinci = export_recovery_share(vault, _PIN)
    assert ilk == ikinci


def test_export_requires_correct_pin(vault, db) -> None:
    with pytest.raises(ValueError):
        export_recovery_share(vault, "yanlis-pin-123")
    assert has_recovery_share(vault) is False, "başarısız denemede zaman damgası yazılmamalı"


# ── Kurtarma akışı ────────────────────────────────────────────────────────────

def test_recover_with_share_1_and_recovery_share(vault, db) -> None:
    """share_2 kayıp senaryosu: vault (PIN) + kurtarma parçası."""
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)

    kurtarilan = recover_master_key(vault, recovery_share=share_3, pin=_PIN)
    assert kurtarilan == beklenen


def test_recover_with_share_2_and_recovery_share(vault, db) -> None:
    """share_1 kayıp senaryosu: anahtar kasası + kurtarma parçası, PIN gerekmez."""
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)

    kurtarilan = recover_master_key(vault, recovery_share=share_3, pin=None)
    assert kurtarilan == beklenen


def test_recovery_still_works_after_vault_file_is_deleted(vault, db, tmp_path) -> None:
    """Vault dosyası tamamen silinse bile share_2 + kurtarma parçası yeterli."""
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)

    vault_dosyasi = vault_manager._read_vault_path(vault)
    vault_manager._clear_readonly(vault_dosyasi)
    vault_dosyasi.unlink()
    assert not vault_dosyasi.exists()

    assert recover_master_key(vault, recovery_share=share_3, pin=None) == beklenen


def test_recovery_rejects_wrong_share(vault, db) -> None:
    """Başka bir vault'un kurtarma parçası doğru anahtarı vermemeli."""
    _role, beklenen = open_vault(vault, _PIN)
    _b1, _b2, baska_share_3 = vault_manager._sss_split(b"\xee" * 32)

    try:
        kurtarilan = recover_master_key(vault, recovery_share=baska_share_3, pin=_PIN)
    except (ValueError, OverflowError):
        return  # hata da kabul edilebilir sonuç
    assert kurtarilan != beklenen, "yanlış parça doğru anahtarı verdi"


def test_recovery_rejects_malformed_share(vault, db) -> None:
    with pytest.raises(ValueError):
        recover_master_key(vault, recovery_share="tamamen-bozuk", pin=_PIN)


def test_decoded_text_share_recovers_the_key(vault, db) -> None:
    """Uçtan uca: base32 metin → çöz → kurtar."""
    _role, beklenen = open_vault(vault, _PIN)
    export = build_export(export_recovery_share(vault, _PIN))

    # Kullanıcının kâğıttan okuyup girdiği hâli taklit et
    elle_girilen = export.base32_text.lower().replace("-", " ")
    share_3 = decode_share(elle_girilen)

    assert recover_master_key(vault, recovery_share=share_3, pin=None) == beklenen


# ── Geriye dönük uyumluluk ────────────────────────────────────────────────────

def test_legacy_2of2_vault_can_be_upgraded_without_rekeying(vault, db) -> None:
    """
    2-of-2 döneminde oluşturulmuş vault senaryosu.

    O dönemde recovery_issued_at sütunu yoktu ve yalnızca iki pay vardı.
    Yükseltme, share_1/share_2'ye HİÇ dokunmadan çalışmalı ve master_key
    değişmemeli — aksi hâlde mevcut .hcl dosyaları açılamaz hâle gelirdi.
    """
    _role, master_key_once = open_vault(vault, _PIN)
    share_2_once = vault_manager._load_share_2(vault)

    # Eski hâli taklit et: kurtarma parçası hiç alınmamış
    db.execute("UPDATE usb_tokens SET recovery_issued_at = NULL WHERE hwid = ?", (vault,))
    assert has_recovery_share(vault) is False

    share_3 = export_recovery_share(vault, _PIN)

    _role2, master_key_sonra = open_vault(vault, _PIN)
    assert master_key_sonra == master_key_once, "yükseltme master_key'i değiştirdi"
    assert vault_manager._load_share_2(vault) == share_2_once, "share_2 değişti"
    assert recover_master_key(vault, recovery_share=share_3, pin=None) == master_key_once


def test_missing_recovery_column_is_migrated(tmp_path: Path) -> None:
    """
    recovery_issued_at sütunu olmayan eski bir DB açıldığında eklenmeli.

    Sütun eklenmezse has_recovery_share() OperationalError ile patlardı.
    """
    from DB.db_manager import DBManager

    db_path = tmp_path / "eski.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE usb_tokens (id INTEGER PRIMARY KEY, hwid TEXT UNIQUE, "
        "share_2 TEXT NOT NULL, token_id TEXT NOT NULL DEFAULT '')"
    )
    conn.execute(
        "INSERT INTO usb_tokens (hwid, share_2, token_id) VALUES ('ESKI', '', 'tok')"
    )
    conn.commit()
    conn.close()

    DBManager._instance = None
    manager = DBManager(db_path)
    manager.connect(hwid="ESKI")
    try:
        kolonlar = {r["name"] for r in manager.fetchall("PRAGMA table_info(usb_tokens)")}
        assert "recovery_issued_at" in kolonlar
        assert has_recovery_share("ESKI") is False
    finally:
        manager.close()
        DBManager._instance = None
