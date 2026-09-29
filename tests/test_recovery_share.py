"""
CORE.recovery_share + vault_manager kurtarma akışı.

Gerçek vault oluşturulur, gerçek Argon2id/GCM kullanılır; yalnızca vault
dizini tmp_path'e yönlendirilir.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from CORE import recovery_share, secret_store, vault_manager
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
    reprovision_vault,
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


@pytest.mark.parametrize("gecersiz_karakter", ["0", "1", "8", "9"])
def test_decode_gecersiz_base32_rakamini_SESSIZCE_duzeltmiyor(gecersiz_karakter: str) -> None:
    """
    B-126 senaryo 90: RFC 4648 base32 alfabesinde 0/1/8/9 rakamları HİÇ
    yok (yalnızca A-Z + 2-7) — bu yüzden gövdede bu rakamlardan biri
    görülürse ya AÇIKÇA reddedilmeli, ya da (bu test asıl bunu sınıyor)
    "muhtemelen O/I/B/g demek istedi" diye SESSİZCE bir başka karaktere
    ÇEVRİLİP kabul EDİLMEMELİ — böyle bir "yardımsever" düzeltme, gerçekte
    farklı bir karakteri kastetmiş bir yazım hatasını sessizce YANLIŞ bir
    değere çözebilir (bkz. B-021'in aynı sınıftan riski).

    Mutasyon-kanıt: `decode_share()`'e `str.maketrans("018", "OIB")` ile
    böyle bir "yardımsever" ön-çeviri eklenince test_recovery_share.py'nin
    (26 test) HİÇBİRİ fark etmedi — gövdede zaten bu rakamlar hiç
    kullanılmadığı için (encode_share() onları hiç üretmiyor) round-trip
    testleri etkilenmiyordu.
    """
    _s1, _s2, share_3 = vault_manager._sss_split(b"\x7a" * 32)
    text = encode_share(share_3)
    govde = text.replace("HYCLEUS-R3-", "").replace("-", "")
    bozuk_govde = gecersiz_karakter + govde[1:]

    with pytest.raises(RecoveryShareError):
        decode_share(f"HYCLEUS-R3-{bozuk_govde}")


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
    """
    Başka bir vault'un kurtarma parçası İSTİSNA vermeli.

    Eski hâli "hata da kabul edilebilir, yanlış anahtar da" diyordu. Yanlış
    anahtarı kabul etmek B-160'ın tam kendisi: çağıran (reprovision_vault,
    takeover_usb) onu doğru sanıp kasayı onunla yeniden kuruyor.
    """
    _b1, _b2, baska_share_3 = vault_manager._sss_split(b"\xee" * 32)

    with pytest.raises(ValueError):
        recover_master_key(vault, recovery_share=baska_share_3, pin=_PIN)


@pytest.mark.parametrize("pin_yolu", [True, False], ids=["share_1+share_3", "share_2+share_3"])
def test_TEK_HARFI_yanlis_parca_recover_yolunda_reddedilir_kasa_DOKUNULMAZ(
    vault, db, tek_harf_boz, pin_yolu
) -> None:
    """
    B-160, `recover_vault.py --recover` yolu: aynı hwid,
    `recover_master_key()` ardından `reprovision_vault()`.

    Bugünkü davranış (2026-09-29'da ölçüldü, BACKLOG B-160 "ADIM 1
    gözlemi"): yanlış parça hata vermiyor, vault dosyası yanlış anahtarla
    yeniden yazılıyor; PIN yolunda kasadaki share_2 de değişiyor. Ayakta
    kalan payın DEĞERİ korunuyor, ama denetim "kurtarıldı" diyor ve kasa
    yanlış anahtarla açılıyor.
    """
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)
    bozuk = tek_harf_boz(share_3)
    vault_yolu = vault_manager._read_vault_path(vault)
    vault_once = vault_yolu.read_bytes()
    share_2_once = secret_store.load(secret_store.share_2_username(vault))

    with pytest.raises(ValueError):
        anahtar = recover_master_key(
            vault, recovery_share=bozuk, pin=_PIN if pin_yolu else None
        )
        # recover_vault.py --recover'ın bir sonraki adımı.
        reprovision_vault(
            vault, "yeniPIN-987654", _ROLE, master_key=anahtar, recovery_share=bozuk
        )

    assert vault_yolu.read_bytes() == vault_once, "vault dosyası yeniden yazıldı"
    assert secret_store.load(secret_store.share_2_username(vault)) == share_2_once
    _role, anahtar_sonra = open_vault(vault, _PIN)
    assert anahtar_sonra == beklenen
    eylemler = {r["action"] for r in db.fetchall("SELECT action FROM audit_log")}
    assert "vault_recovery_rejected" in eylemler
    assert "vault_recovered" not in eylemler
    assert "vault_reprovisioned" not in eylemler


# ── B-160 — kurtarılan anahtarın doğrulanması ────────────────────────────────


def _kcv_sil(db, hwid: str) -> None:
    """Göç 29'dan önce kurulmuş, o günden beri açılmamış kasayı taklit eder."""
    db.execute("UPDATE usb_tokens SET kcv = NULL WHERE hwid = ?", (hwid,))


def _hcl_ekle(
    db, tmp_path: Path, anahtar: bytes, *, hwid: str = _HWID, ad: str = "belge",
    added_at: str = "2026-09-01T10:00:00Z",
) -> Path:
    """`anahtar` ile şifrelenmiş gerçek bir .hcl yazar ve files'a kaydeder."""
    from CORE.crypto import encrypt_file

    kaynak = tmp_path / f"{ad}.txt"
    kaynak.write_bytes(f"gizli icerik {ad}".encode())
    (tmp_path / "hcl").mkdir(exist_ok=True)
    yol, _sha, aad = encrypt_file(
        kaynak, anahtar, 1, hwid=hwid, dst=tmp_path / "hcl" / f"{ad}.hcl"
    )
    db.execute(
        "INSERT INTO files (filename, filepath, aad_metadata, added_at) VALUES (?, ?, ?, ?)",
        (f"{ad}.txt", str(yol), aad, added_at),
    )
    return yol


def _son_kurtarma_detayi(db) -> str:
    return db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'vault_recovered' ORDER BY id DESC LIMIT 1"
    )["detail"]


def test_dogru_parca_KCV_ile_dogrulaniyor(vault, db) -> None:
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)

    kurtarilan = recover_master_key(vault, recovery_share=share_3, pin=None)

    assert kurtarilan == beklenen
    assert kurtarilan.dogrulama == vault_manager.DOGRULAMA_KCV
    assert _son_kurtarma_detayi(db).endswith("dogrulama=kcv")


def test_yanlis_parca_SABIT_mesaj_parcanin_hicbir_kismini_icermiyor(
    vault, db, tek_harf_boz
) -> None:
    share_3 = export_recovery_share(vault, _PIN)
    bozuk = tek_harf_boz(share_3)

    with pytest.raises(ValueError) as exc:
        recover_master_key(vault, recovery_share=bozuk, pin=_PIN)

    mesaj = str(exc.value)
    assert mesaj == vault_manager.YANLIS_PARCA_MESAJI
    govde = bozuk.split(":", 1)[1]
    for i in range(0, len(govde) - 8, 4):
        assert govde[i : i + 8] not in mesaj.lower()


def test_KCVsiz_eski_kasa_DOGRU_parcayi_hcl_ile_dogruluyor(vault, db, tmp_path) -> None:
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)
    _kcv_sil(db, vault)
    _hcl_ekle(db, tmp_path, beklenen)

    kurtarilan = recover_master_key(vault, recovery_share=share_3, pin=None)

    assert kurtarilan == beklenen
    assert kurtarilan.dogrulama == vault_manager.DOGRULAMA_HCL


def test_KCVsiz_eski_kasa_YANLIS_parcayi_hcl_ile_REDDEDIYOR(
    vault, db, tmp_path, tek_harf_boz
) -> None:
    """ESKİ KASA TESTİ (B-160 ADIM 3, mutasyon 2): KCV yok, tek kanıt .hcl."""
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)
    _kcv_sil(db, vault)
    _hcl_ekle(db, tmp_path, beklenen)

    with pytest.raises(ValueError, match="bu kasaya ait değil"):
        recover_master_key(vault, recovery_share=tek_harf_boz(share_3), pin=None)

    eylemler = {r["action"] for r in db.fetchall("SELECT action FROM audit_log")}
    assert "vault_recovery_rejected" in eylemler
    assert "vault_recovered" not in eylemler


def test_hcl_adaylarindan_BIRI_yeter_eski_anahtarli_dosya_reddettirmiyor(
    vault, db, tmp_path
) -> None:
    """
    Aynı hwid'in anahtarı bir kez değişmişse (yeniden kayıt, --reset)
    ESKİ anahtarla şifrelenmiş dosyalar da aday olur. En yeni aday eski
    anahtarlı olsa bile, daha eski ama DOĞRU anahtarlı bir aday yeter.
    """
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)
    _kcv_sil(db, vault)
    _hcl_ekle(db, tmp_path, beklenen, ad="dogru", added_at="2026-09-01T10:00:00Z")
    _hcl_ekle(db, tmp_path, b"\x5a" * 16 + b"\xa5" * 16, ad="eski-anahtar",
              added_at="2026-09-20T10:00:00Z")

    kurtarilan = recover_master_key(vault, recovery_share=share_3, pin=None)

    assert kurtarilan == beklenen
    assert kurtarilan.dogrulama == vault_manager.DOGRULAMA_HCL


def test_hcl_diskte_olmayan_ya_da_baska_hwidin_dosyasi_aday_sayilmaz(
    vault, db, tmp_path
) -> None:
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)
    _kcv_sil(db, vault)
    silinecek = _hcl_ekle(db, tmp_path, beklenen, ad="silinmis")
    silinecek.unlink()
    _hcl_ekle(db, tmp_path, b"\x5a" * 16 + b"\xa5" * 16, hwid="BASKA-USB", ad="baska")

    kurtarilan = recover_master_key(vault, recovery_share=share_3, pin=None)

    assert kurtarilan.dogrulama == vault_manager.DOGRULAMA_YAPILAMADI


def test_KCV_ve_dosya_yoksa_DOGRULANAMADI_denetime_yaziliyor_KCV_YAZILMIYOR(
    vault, db
) -> None:
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)
    _kcv_sil(db, vault)

    kurtarilan = recover_master_key(vault, recovery_share=share_3, pin=None)

    assert kurtarilan == beklenen
    assert kurtarilan.dogrulama == vault_manager.DOGRULAMA_YAPILAMADI
    assert _son_kurtarma_detayi(db).endswith("dogrulama=yapilamadi")
    kcv = db.fetchone("SELECT kcv FROM usb_tokens WHERE hwid = ?", (vault,))["kcv"]
    assert kcv is None, "doğrulanamamış bir anahtarın KCV'si yazılmamalı"


def test_yarim_kalan_dogrulanamayan_kurtarma_DOGRU_parcayi_KILITLEMIYOR(
    vault, db, tek_harf_boz
) -> None:
    """
    Doğrulanamayan durumda recover_master_key KCV yazsaydı: tek harfi
    yanlış parça kabul edilir, kullanıcı "yeniden kurulsun mu?" → Hayır
    der, yanlış anahtarın KCV'si kalır ve DOĞRU parça reddedilirdi.
    """
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)
    _kcv_sil(db, vault)

    ilk = recover_master_key(vault, recovery_share=tek_harf_boz(share_3), pin=None)
    assert ilk != beklenen  # doğrulanamadığı için yanlış anahtar kabul edildi
    # ... kullanıcı yeniden kurmadan vazgeçti. Doğru parçayla tekrar:
    ikinci = recover_master_key(vault, recovery_share=share_3, pin=None)

    assert ikinci == beklenen


def test_dogrulanamayan_kurtarmadan_sonra_yeniden_kurulum_KCV_yaziyor(vault, db) -> None:
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)
    _kcv_sil(db, vault)

    anahtar = recover_master_key(vault, recovery_share=share_3, pin=None)
    reprovision_vault(vault, "yeniPIN-24680", _ROLE, master_key=anahtar, recovery_share=share_3)

    kcv = db.fetchone("SELECT kcv FROM usb_tokens WHERE hwid = ?", (vault,))["kcv"]
    assert kcv == vault_manager._kcv_hesapla(beklenen).hex()


# ── B-160 (h) — --recover yolu: yan yazım, doğrulama, atomik yer değiştirme ──


def _anlik(vault: str) -> tuple[bytes, str | None]:
    return (
        vault_manager._read_vault_path(vault).read_bytes(),
        secret_store.load(secret_store.share_2_username(vault)),
    )


def _yan_dosya_yok(vault: str) -> None:
    assert list(vault_manager._read_vault_path(vault).parent.glob("*.yeni")) == []


def test_yeniden_kurulum_YAN_dosya_dogrulamasi_duserse_eski_kasa_ve_share2_DOKUNULMAZ(
    vault, db, monkeypatch
) -> None:
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)
    once = _anlik(vault)
    anahtar = recover_master_key(vault, recovery_share=share_3, pin=None)

    def _patla(*_a, **_k):
        raise ValueError("yan dosya açılamadı (test)")

    monkeypatch.setattr(vault_manager, "_hazirlanan_kasayi_dogrula", _patla)
    with pytest.raises(ValueError, match="test"):
        reprovision_vault(vault, "yeniPIN-13579", _ROLE, master_key=anahtar, recovery_share=share_3)

    assert _anlik(vault) == once
    _yan_dosya_yok(vault)
    assert open_vault(vault, _PIN)[1] == beklenen


@pytest.mark.parametrize("share_2_kasada", [True, False], ids=["share_2-var", "share_2-kayip"])
def test_yeniden_kurulum_yer_degistirmeden_SONRA_duserse_eski_durum_GERI_YUKLENIR(
    vault, db, monkeypatch, share_2_kasada
) -> None:
    """
    Yeni vault yerine kondu, share_2 kasaya yazıldı, SONRA DB yazması
    düştü: vault dosyası ve share_2 eski hâline dönmeli. `share_2-kayip`:
    PIN yolunun asıl senaryosu (kasada share_2 yok) — geri yükleme yeni
    yazılanı SİLMELİ, eski bir değer uydurmamalı.
    """
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)
    if not share_2_kasada:
        secret_store.erase(secret_store.share_2_username(vault))
    once = _anlik(vault)
    anahtar = recover_master_key(
        vault, recovery_share=share_3, pin=None if share_2_kasada else _PIN
    )

    def _yarim_yaz(hwid, share_2, _token_id_hex, *, kcv_hex=None):
        secret_store.store(secret_store.share_2_username(hwid), share_2)
        raise RuntimeError("DB yazılamadı (test)")

    monkeypatch.setattr(vault_manager, "_save_usb_token", _yarim_yaz)
    with pytest.raises(RuntimeError, match="test"):
        reprovision_vault(vault, "yeniPIN-13579", _ROLE, master_key=anahtar, recovery_share=share_3)

    assert _anlik(vault) == once
    _yan_dosya_yok(vault)
    if share_2_kasada:
        assert open_vault(vault, _PIN)[1] == beklenen


def test_yeniden_kurulum_basarili_yan_dosya_BIRAKMAZ_yeni_PIN_ayni_anahtari_verir(
    vault, db
) -> None:
    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)
    anahtar = recover_master_key(vault, recovery_share=share_3, pin=None)

    reprovision_vault(vault, "yeniPIN-13579", _ROLE, master_key=anahtar, recovery_share=share_3)

    _yan_dosya_yok(vault)
    assert open_vault(vault, "yeniPIN-13579")[1] == beklenen


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
