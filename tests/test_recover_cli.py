"""
CORE.recover_vault — kurtarma CLI akışı.

CLI fonksiyonları gerçek vault üzerinde, girdi/parola istemleri
monkeypatch'lenerek çalıştırılır.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from CORE import recover_vault, vault_manager
from CORE.recovery_share import decode_share
from CORE.vault_manager import create_vault, export_recovery_share, open_vault

_HWID = "USB-CLI-TEST"
_PIN = "cli-pin-4567"
_ROLE = "Yönetici"


@pytest.fixture
def vault(db, tmp_path: Path, monkeypatch) -> str:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    monkeypatch.setattr(recover_vault, "get_usb_hwid", lambda: _HWID)
    create_vault(_HWID, _PIN, _ROLE)
    return _HWID


def _args(**kw):
    return type("Args", (), {"qr_out": None, **kw})()


# ── --status ──────────────────────────────────────────────────────────────────

def test_status_warns_when_recovery_share_missing(vault, db, capsys) -> None:
    """Kurtarma parçası alınmamışsa açıkça uyarmalı — sessiz 2-of-2 olmaz."""
    recover_vault._cmd_status(_args())

    cikti = capsys.readouterr().out
    assert "ALINMAMIS" in cikti
    assert "2-of-2" in cikti
    assert "recover_vault.py --export" in cikti


def test_status_reports_when_share_was_issued(vault, db, capsys) -> None:
    export_recovery_share(vault, _PIN)

    recover_vault._cmd_status(_args())

    cikti = capsys.readouterr().out
    assert "ALINMIS" in cikti
    assert "2-of-2" not in cikti


# ── --export ──────────────────────────────────────────────────────────────────

def test_export_shows_warning_and_share(vault, db, capsys, monkeypatch) -> None:
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: _PIN)

    recover_vault._cmd_export(_args())

    cikti = capsys.readouterr().out
    assert "HYCLEUS-R3-" in cikti
    assert "FİZİKSEL" in cikti
    assert "DİJİTAL OLARAK SAKLAMAYIN" in cikti
    # Gösterilen metin gerçekten geçerli bir pay olmalı
    satir = next(s for s in cikti.splitlines() if "HYCLEUS-R3-" in s and ":" not in s)
    assert decode_share(satir.strip()).startswith("3:")


def test_export_writes_nothing_by_default(vault, db, capsys, monkeypatch, tmp_path) -> None:
    """
    Varsayılan davranış hiçbir şeyi diske yazmamak.

    QR yalnızca kullanıcı --qr-out ile açıkça istediğinde yazılır.
    """
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: _PIN)
    onceki = {p for p in tmp_path.rglob("*") if p.is_file()}

    recover_vault._cmd_export(_args())

    yeni = {p for p in tmp_path.rglob("*") if p.is_file()} - onceki
    assert not yeni, f"beklenmeyen dosya yazıldı: {yeni}"
    assert "--qr-out" in capsys.readouterr().out


def test_export_writes_qr_only_when_asked(vault, db, capsys, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: _PIN)
    hedef = tmp_path / "kurtarma_qr.svg"

    recover_vault._cmd_export(_args(qr_out=str(hedef)))

    assert hedef.exists()
    assert "<svg" in hedef.read_text(encoding="utf-8")
    # Kullanıcıya dosyayı silmesi söylenmeli
    assert "silin" in capsys.readouterr().out


def test_export_aborts_on_wrong_pin(vault, db, monkeypatch) -> None:
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: "yanlis-pin")

    with pytest.raises(SystemExit):
        recover_vault._cmd_export(_args())


def test_export_declining_reexport_confirmation_shows_nothing(
    vault, db, capsys, monkeypatch
) -> None:
    """
    Parça daha önce alınmışsa yeniden gösterme onayı isteniyor.
    "H" (Hayır) cevabı GERÇEKTEN durdurmalı — PIN hiç sorulmamalı, parça
    hiç ekrana basılmamalı.
    """
    from CORE.recover_vault import has_recovery_share

    export_recovery_share(vault, _PIN)
    assert has_recovery_share(vault)

    pin_cagrildi = []
    monkeypatch.setattr(
        recover_vault, "_prompt_pin",
        lambda *_a, **_k: pin_cagrildi.append(1) or _PIN,
    )
    monkeypatch.setattr("builtins.input", lambda *_a: "H")

    recover_vault._cmd_export(_args())

    cikti = capsys.readouterr().out
    assert "Iptal edildi" in cikti
    assert "HYCLEUS-R3-" not in cikti
    assert not pin_cagrildi, "onay reddedildiği hâlde PIN yine de soruldu"


# ── --recover ─────────────────────────────────────────────────────────────────

def test_recover_with_vault_and_pin(vault, db, capsys, monkeypatch) -> None:
    """Seçenek 1: vault duruyor, PIN biliniyor (share_2 kayıp)."""
    import hashlib

    from CORE.recovery_share import encode_share

    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)

    yanitlar = iter([encode_share(share_3), _PIN])
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: next(yanitlar))
    monkeypatch.setattr("builtins.input", lambda *_a: "1")

    recover_vault._cmd_recover(_args())

    cikti = capsys.readouterr().out
    assert "MASTER KEY KURTARILDI" in cikti
    # Anahtarın kendisi değil yalnızca özeti gösterilmeli
    assert beklenen.hex() not in cikti
    assert hashlib.sha256(beklenen).hexdigest() in cikti


def test_recover_reprovisions_vault_with_canonical_role(
    vault, db, capsys, monkeypatch
) -> None:
    """
    Uçtan uca yeniden kurulum yolu (B-028): önceki iki test `input()`'u hep
    "1"/"2" ile yamalıyor — bu SEÇENEK sorusuna cevap, ama "Vault yeniden
    kurulsun mu? [e/H]" sorusuna da AYNI "1" cevabı gidiyor, ki bu ("e",
    "evet") kümesinde OLMADIĞI için akış hep "Atlandı" dalına düşüyor.
    Yani `role = display_role(ham_rol)` satırı (B-028'in asıl düzeltmesi)
    hiçbir testte GERÇEKTEN çalışmıyordu. Burada "e" cevabıyla akışın
    SONUNA kadar gidiyoruz ve ASCII (Türkçe karaktersiz) "yonetici"
    girdisinin kanonik "Yönetici"ye normalize edildiğini, ham hâliyle
    KASAYA YAZILMADIĞINI doğruluyoruz.
    """
    from CORE.recovery_share import encode_share

    share_3 = export_recovery_share(vault, _PIN)

    girdiler = iter([encode_share(share_3), _PIN, "yeni-pin-98765", "yeni-pin-98765"])
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: next(girdiler))
    cevaplar = iter(["1", "e", "yonetici"])
    monkeypatch.setattr("builtins.input", lambda *_a: next(cevaplar))

    recover_vault._cmd_recover(_args())

    cikti = capsys.readouterr().out
    assert "VAULT YENIDEN KURULDU" in cikti

    role, _key = open_vault(vault, "yeni-pin-98765")
    assert role == "Yönetici", (
        f"rol kanonik hâle getirilmemiş: {role!r} — B-028 regresyonu geri gelmiş olabilir"
    )


def test_recover_without_pin_uses_keyring_share(vault, db, capsys, monkeypatch) -> None:
    """Seçenek 2: vault dosyası yok, share_2 kasadan okunur."""
    import hashlib

    _role, beklenen = open_vault(vault, _PIN)
    share_3 = export_recovery_share(vault, _PIN)

    from CORE.recovery_share import encode_share

    vault_dosyasi = vault_manager._read_vault_path(vault)
    vault_manager._clear_readonly(vault_dosyasi)
    vault_dosyasi.unlink()

    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: encode_share(share_3))
    monkeypatch.setattr("builtins.input", lambda *_a: "2")

    recover_vault._cmd_recover(_args())

    assert hashlib.sha256(beklenen).hexdigest() in capsys.readouterr().out


def test_recover_aborts_on_malformed_share(vault, db, monkeypatch) -> None:
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: "tamamen-bozuk")

    with pytest.raises(SystemExit):
        recover_vault._cmd_recover(_args())


def test_recover_aborts_on_foreign_share(vault, db, capsys, monkeypatch) -> None:
    """Başka bir vault'un parçası ya reddedilmeli ya da doğru anahtarı vermemeli."""
    import hashlib

    from CORE.recovery_share import encode_share

    _role, beklenen = open_vault(vault, _PIN)
    _b1, _b2, yabanci = vault_manager._sss_split(b"\x3c" * 32)

    yanitlar = iter([encode_share(yabanci), _PIN])
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: next(yanitlar))
    monkeypatch.setattr("builtins.input", lambda *_a: "1")

    try:
        recover_vault._cmd_recover(_args())
    except SystemExit:
        return  # net hata — kabul edilebilir sonuç

    # Hata vermediyse en azından DOĞRU anahtarı üretmemiş olmalı
    cikti = capsys.readouterr().out
    assert hashlib.sha256(beklenen).hexdigest() not in cikti, (
        "yabancı kurtarma parçası doğru master_key'i üretti"
    )


# ── B-037: başarısız kurtarma denemeleri denetim kaydına "reddedildi"
#    yazılıyor — payın/PIN'in KENDİSİ asla yazılmıyor (negatif kanıt) ────────
#
# `vault_manager.recover_master_key()` doğrudan çağrılıyor (CLI katmanı
# DEĞİL) — üç senaryo da (yanlış PIN, bozuk pay, eşik dışı indisli pay)
# doğrudan o fonksiyonun kendi `except Exception` sarmalayıcısını sınıyor.
# `_cmd_recover()` zaten bu üçünü de yukarıdaki testlerde CLI seviyesinde
# kapsıyor; burada odak DENETİM KAYDI.


def test_recover_yanlis_pin_denetim_kaydina_reddedildi_yaziyor(vault, db) -> None:
    """Yanlış PIN → `_decrypt_vault`'un GCM hatası (`ValueError`) →
    "vault_recovery_rejected" yazılmalı — PIN'in KENDİSİ hiçbir `detail`
    alanında olmamalı."""
    share_3 = export_recovery_share(vault, _PIN)
    yanlis_pin = "YANLIS-PIN-000-ASLA-YAZILMAMALI"

    with pytest.raises(ValueError):
        vault_manager.recover_master_key(vault, recovery_share=share_3, pin=yanlis_pin)

    satir = db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'vault_recovery_rejected' "
        "ORDER BY id DESC LIMIT 1"
    )
    assert satir is not None, "reddedilen kurtarma denemesi denetime yazılmadı"
    assert "ValueError" in satir["detail"]
    assert yanlis_pin not in satir["detail"]

    # NEGATİF KANIT: audit_log'un HİÇBİR satırının detail'inde PIN yok —
    # yalnızca son satır değil, TÜMÜ tarandı.
    tum_detaylar = " ".join(
        r["detail"] or "" for r in db.fetchall("SELECT detail FROM audit_log")
    )
    assert yanlis_pin not in tum_detaylar
    assert _PIN not in tum_detaylar


def test_recover_bozuk_pay_denetim_kaydina_reddedildi_yaziyor(vault, db) -> None:
    """Biçimi bozuk bir kurtarma payı → `_parse_share`'in `ValueError`'ı →
    "vault_recovery_rejected" yazılmalı; payın KENDİSİ — ya da bir PARÇASI,
    `_parse_share` hata mesajına payın İLK 16 KARAKTERİNİ gömüyor — hiçbir
    detail alanında olmamalı."""
    bozuk_pay = "BU-TAMAMEN-GECERSIZ-BIR-KURTARMA-PAYI-DEGERI-ASLA-YAZILMAMALI"

    with pytest.raises(ValueError):
        vault_manager.recover_master_key(vault, recovery_share=bozuk_pay, pin=_PIN)

    satir = db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'vault_recovery_rejected' "
        "ORDER BY id DESC LIMIT 1"
    )
    assert satir is not None
    assert "ValueError" in satir["detail"]
    assert bozuk_pay not in satir["detail"]
    assert bozuk_pay[:16] not in satir["detail"], (
        "_parse_share'in hata mesajına gömdüğü pay parçası denetime sızmış"
    )

    tum_detaylar = " ".join(
        r["detail"] or "" for r in db.fetchall("SELECT detail FROM audit_log")
    )
    assert bozuk_pay[:16] not in tum_detaylar


def test_recover_esik_disi_indisli_pay_denetim_kaydina_reddedildi_yaziyor(
    vault, db,
) -> None:
    """`recovery_share` olarak share_1/share_2 verilmesi (indis kontrolü,
    bkz. `tests/test_vault_manager.py::
    test_recover_master_key_yalnizca_3_indisli_parcayi_kabul_ediyor`) de
    AYNI "vault_recovery_rejected" yolundan geçmeli."""
    s1, _s2, _s3 = vault_manager._sss_split(b"\x77" * 32)

    with pytest.raises(ValueError, match="3 indisli olmalı"):
        vault_manager.recover_master_key(vault, recovery_share=s1, pin=_PIN)

    satir = db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'vault_recovery_rejected' "
        "ORDER BY id DESC LIMIT 1"
    )
    assert satir is not None
    assert "ValueError" in satir["detail"]


def test_recover_basarili_denemede_reddedildi_YAZILMIYOR(vault, db) -> None:
    """Kontrast: başarılı bir kurtarma "vault_recovery_rejected" DEĞİL
    yalnızca "vault_recovered" yazmalı — iki olay birbirine karışmamalı."""
    share_3 = export_recovery_share(vault, _PIN)

    vault_manager.recover_master_key(vault, recovery_share=share_3, pin=_PIN)

    assert db.fetchone(
        "SELECT 1 FROM audit_log WHERE action = 'vault_recovery_rejected'"
    ) is None
    assert db.fetchone(
        "SELECT 1 FROM audit_log WHERE action = 'vault_recovered'"
    ) is not None


# ── --takeover (B-11X, Madde 2) ─────────────────────────────────────────────
#
# `--recover`'dan FARKLI senaryo: `vault` fixture'ının HWID'i (_HWID) burada
# "eski/kayıp" USB'yi temsil ediyor; test içinde `get_usb_hwid()` GENUİNELY
# farklı bir değere (_HWID_YENI) monkeypatch'lenerek "yeni USB takılı" hâli
# simüle ediliyor — `--recover`'ın aksine burada iki hwid GERÇEKTEN farklı.

_HWID_YENI = "USB-CLI-DEVIR-YENI"
_YENI_PIN = "yeniCliPIN123"


@pytest.fixture
def admin_kaydi(vault, db) -> str:
    """`vault` fixture'ının HWID'ine bağlı GERÇEK bir `users` satırı —
    `_cmd_takeover`'ın kullanıcı adından hwid'e çözümlemesi için gerekli."""
    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid) "
        "VALUES ('admin_cli', 'x', 'admin', 'approved', ?)",
        (vault,),
    )
    return "admin_cli"


def test_takeover_happy_path_users_tablosu_guncelleniyor(
    admin_kaydi, vault, db, capsys, monkeypatch,
) -> None:
    from CORE.recovery_share import encode_share
    from CORE.secret_store import load_totp_secret_for_hwid, store_totp_secret_for_hwid

    store_totp_secret_for_hwid(vault, "CLITOTPSECRET")
    share_3 = export_recovery_share(vault, _PIN)

    monkeypatch.setattr(recover_vault, "get_usb_hwid", lambda: _HWID_YENI)
    girdiler = iter(["admin_cli", "1", "e"])
    monkeypatch.setattr("builtins.input", lambda *_a: next(girdiler))
    pinler = iter([encode_share(share_3), _PIN, _YENI_PIN, _YENI_PIN])
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: next(pinler))

    recover_vault._cmd_takeover(_args())

    cikti = capsys.readouterr().out
    assert "USB DEVRALINDI" in cikti

    satirlar = db.fetchall("SELECT username, hwid FROM users")
    assert len(satirlar) == 1, f"beklenen 1 satır: {[dict(r) for r in satirlar]}"
    assert satirlar[0]["hwid"] == _HWID_YENI
    assert satirlar[0]["username"] == "admin_cli"

    role, _key = open_vault(_HWID_YENI, _YENI_PIN)
    assert role == "Yönetici"
    assert load_totp_secret_for_hwid(_HWID_YENI) == "CLITOTPSECRET"

    with pytest.raises(FileNotFoundError):
        open_vault(vault, _PIN)


def test_takeover_iptal_edilirse_HICBIR_SEY_degismez(
    admin_kaydi, vault, db, capsys, monkeypatch,
) -> None:
    from CORE.recovery_share import encode_share

    share_3 = export_recovery_share(vault, _PIN)

    monkeypatch.setattr(recover_vault, "get_usb_hwid", lambda: _HWID_YENI)
    girdiler = iter(["admin_cli", "1", "H"])  # son soruda "Hayır"
    monkeypatch.setattr("builtins.input", lambda *_a: next(girdiler))
    pinler = iter([encode_share(share_3), _PIN, _YENI_PIN, _YENI_PIN])
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: next(pinler))

    recover_vault._cmd_takeover(_args())

    assert "Iptal edildi" in capsys.readouterr().out
    satirlar = db.fetchall("SELECT username, hwid FROM users")
    assert satirlar[0]["hwid"] == vault, "iptal edilmesine rağmen hwid değişmiş"

    # Eski USB HÂLÂ çalışıyor olmalı — iptal gerçekten hiçbir şeyi bozmadı.
    role, _key = open_vault(vault, _PIN)
    assert role == "Yönetici"


def test_takeover_olmayan_kullanici_adi_reddedilir(vault, db, monkeypatch) -> None:
    monkeypatch.setattr(recover_vault, "get_usb_hwid", lambda: _HWID_YENI)
    monkeypatch.setattr("builtins.input", lambda *_a: "hic-yok-boyle-biri")

    with pytest.raises(SystemExit):
        recover_vault._cmd_takeover(_args())


def test_takeover_yanlis_kurtarma_parcasi_reddedilir_DB_DEGISMEZ(
    admin_kaydi, vault, db, monkeypatch,
) -> None:
    monkeypatch.setattr(recover_vault, "get_usb_hwid", lambda: _HWID_YENI)
    girdiler = iter(["admin_cli", "1"])
    monkeypatch.setattr("builtins.input", lambda *_a: next(girdiler))
    pinler = iter(["yanlis-parca-tamamen-bozuk"])
    monkeypatch.setattr(recover_vault, "_prompt_pin", lambda *_a, **_k: next(pinler))

    with pytest.raises(SystemExit):
        recover_vault._cmd_takeover(_args())

    assert db.fetchone("SELECT hwid FROM users WHERE username = 'admin_cli'")["hwid"] == vault
