"""
CORE.usb_manager / CORE.vault_manager — seri numarası okunamayan USB'ler
için "zayıf bağlama" durumu artık SESSİZ değil (BACKLOG B-025).

Önceki davranış: `_sanitize_hwid()` seri numarası boş/'0'/kontrol
karakteriyse `usb_ids.json`'da saklı bir UUID'ye sessizce düşüyordu. Kimlik
o andan itibaren DONANIMDAN değil bir dosyadan geliyordu ama hiçbir yerde
bu belirtilmiyordu — "donanıma bağlı kasa" iddiası bu cihaz sınıfı için
sessizce yanlış hâle geliyordu.

Bu dosya iki şeyi doğruluyor:
  1. `CORE.usb_manager.is_uuid_fallback_hwid()` — durumu SAPTAYAN, saf
     fonksiyon; canlı USB probu gerektirmiyor.
  2. `CORE.vault_manager`'ın kritik işlemleri (vault açma, USB kaydı,
     PIN/rol değişikliği, USB yeniden kimlik doğrulama) bu durumdaki bir
     hwid için REDDEDİYOR — kapalı hataya (fail-closed) çevrilmiş.
     Kurtarma (recover_master_key / reprovision_vault) BİLEREK muaf —
     zayıf bağlı bir cihazın tek çıkış yolu bu.

Gerçek dosya sistemi (tmp_path'e yönlendirilmiş usb_ids.json ve vault
dizini) ve gerçek bellek-içi keyring (fake_keyring, autouse) kullanılır.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from CORE import usb_manager, vault_manager
from CORE.usb_manager import is_uuid_fallback_hwid
from CORE.vault_manager import (
    USBAuthError,
    change_vault_pin,
    change_vault_role,
    create_vault,
    export_recovery_share,
    open_vault,
    read_vault_role,
    recover_master_key,
    reprovision_vault,
    verify_vault,
)

_PIN = "gizli-pin-654"
_ROLE = "Standart"


@pytest.fixture
def vault_dizini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / "legacy.hclv")
    monkeypatch.setattr(usb_manager, "_USB_IDS_FILE", tmp_path / "usb_ids.json")
    return tmp_path


def _zayif_hwid_isaretle(vault_dizini: Path, hwid: str, raw: str = "\x00\x00") -> None:
    """
    hwid'i, sanki `_get_or_create_uuid(raw)` üretmiş gibi usb_ids.json'a yazar.

    `create_vault()` artık YENİ bir zayıf hwid'in kaydını reddettiği için,
    "zaten kayıtlı bir vault'un hwid'i SONRADAN zayıf çıkarsa ne olur"
    senaryosunu (pre-fix kayıt, ya da tesadüfi çakışma) test etmek için
    vault ÖNCE güçlü bir kimlikle oluşturuluyor, SONRA bu yardımcı onu
    zayıf olarak işaretliyor.
    """
    dosya = usb_manager._USB_IDS_FILE
    mapping: dict[str, str] = {}
    if dosya.exists():
        mapping = json.loads(dosya.read_text(encoding="utf-8"))
    mapping[raw] = hwid
    dosya.parent.mkdir(parents=True, exist_ok=True)
    dosya.write_text(json.dumps(mapping), encoding="utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# 1. usb_manager.is_uuid_fallback_hwid() — saf saptama
# ══════════════════════════════════════════════════════════════════════════════


def test_is_uuid_fallback_hwid_dosya_yoksa_false(vault_dizini) -> None:
    assert is_uuid_fallback_hwid("HERHANGI-BIR-HWID") is False


def test_is_uuid_fallback_hwid_gercek_seriyi_yanlis_isaretlemiyor(vault_dizini) -> None:
    """Gerçek bir donanım serisi (dosyada hiç geçmeyen) zayıf sayılmamalı."""
    _zayif_hwid_isaretle(vault_dizini, "UUID-DEGERI-ABC")
    assert is_uuid_fallback_hwid("4C53XXXXXXXXXXXXXXXX") is False


def test_is_uuid_fallback_hwid_yedek_degeri_dogru_taniyor(vault_dizini) -> None:
    _zayif_hwid_isaretle(vault_dizini, "UUID-DEGERI-ABC")
    assert is_uuid_fallback_hwid("UUID-DEGERI-ABC") is True


def test_is_uuid_fallback_hwid_bozuk_json_false_doner(vault_dizini) -> None:
    usb_manager._USB_IDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    usb_manager._USB_IDS_FILE.write_text("{bozuk json", encoding="utf-8")
    assert is_uuid_fallback_hwid("HERHANGI-BIR-HWID") is False


def test_get_or_create_uuid_ilk_uretimde_uyari_logluyor(
    vault_dizini, caplog: pytest.LogCaptureFixture,
) -> None:
    """
    B-025'in şikayet ettiği tam nokta: ilk düşüş artık SESSİZ değil.
    """
    with caplog.at_level(logging.WARNING, logger="hycleus.usb"):
        uretilen = usb_manager._get_or_create_uuid("\x01\x02")

    assert is_uuid_fallback_hwid(uretilen) is True
    uyarilar = [k for k in caplog.records if k.levelno >= logging.WARNING]
    assert any("okunamadı" in k.message for k in uyarilar), (
        "ilk UUID üretimi log'a düşmedi — B-025'in sessizliği hâlâ sürüyor"
    )


def test_get_or_create_uuid_ikinci_cagrida_tekrar_uyarmiyor(
    vault_dizini, caplog: pytest.LogCaptureFixture,
) -> None:
    """Aynı fiziksel cihazın HER takılışında uyarı basmak gürültü olurdu."""
    usb_manager._get_or_create_uuid("\x03\x04")
    caplog.clear()  # caplog.records TÜM testi kapsıyor, yalnızca aşağıki bloğu değil
    with caplog.at_level(logging.WARNING, logger="hycleus.usb"):
        usb_manager._get_or_create_uuid("\x03\x04")
    assert caplog.records == []


def test_sanitize_hwid_bos_ve_sifir_zayif_uretir(vault_dizini) -> None:
    assert is_uuid_fallback_hwid(usb_manager._sanitize_hwid("")) is True
    assert is_uuid_fallback_hwid(usb_manager._sanitize_hwid("0")) is True


def test_sanitize_hwid_gercek_seri_zayif_DEGIL(vault_dizini) -> None:
    temiz = usb_manager._sanitize_hwid("4C53AB12CD34EF56")
    assert is_uuid_fallback_hwid(temiz) is False


# ══════════════════════════════════════════════════════════════════════════════
# 2. Kritik işlemler — kapalı hata (fail-closed)
# ══════════════════════════════════════════════════════════════════════════════


def test_create_vault_yeni_zayif_hwid_reddedilir(vault_dizini, db) -> None:
    """
    ASIL DÜZELTME (USB kaydı): seri okunamayan bir cihaz için YENİ vault
    oluşturulamaz.
    """
    zayif = "ZAYIF-HWID-YENI"
    _zayif_hwid_isaretle(vault_dizini, zayif)

    with pytest.raises(USBAuthError, match="donanım seri numarası okunamıyor"):
        create_vault(zayif, _PIN, _ROLE)

    assert not (vault_dizini / "vaults" / f"{zayif}.hclv").exists(), (
        "reddedilen kayıt yine de dosya bırakmış"
    )


def test_create_vault_reddi_denetim_kaydina_dusuyor(vault_dizini, db) -> None:
    zayif = "ZAYIF-HWID-AUDIT"
    _zayif_hwid_isaretle(vault_dizini, zayif)

    with pytest.raises(USBAuthError):
        create_vault(zayif, _PIN, _ROLE)

    kayitlar = db.fetchall(
        "SELECT detail FROM audit_log WHERE action = 'weak_hwid_binding_rejected'"
    )
    assert len(kayitlar) == 1
    assert f"hwid={zayif}" in kayitlar[0]["detail"]
    assert "USB kaydı" in kayitlar[0]["detail"]


@pytest.fixture
def zayif_vault(vault_dizini, db) -> str:
    """
    ÖNCEDEN KAYITLI bir vault'u SONRADAN zayıf hâle getirir.

    Gerçek dünya karşılığı: bu düzeltmeden önce kaydolmuş bir kullanıcı,
    ya da hwid'i tesadüfen bir UUID yedeğiyle çakışan biri. create_vault()
    burada GÜÇLÜ bir kimlikle çağrılıyor (yoksa reddedilirdi) — zayıflık
    SONRADAN, usb_ids.json'a yazılarak ekleniyor.
    """
    hwid = "USB-ONCEDEN-KAYITLI"
    create_vault(hwid, _PIN, _ROLE)
    _zayif_hwid_isaretle(vault_dizini, hwid, raw="\x05\x06")
    assert is_uuid_fallback_hwid(hwid) is True  # ön koşul
    return hwid


def test_open_vault_zayif_hwid_icin_reddedilir(zayif_vault, db) -> None:
    with pytest.raises(USBAuthError, match="donanım seri numarası okunamıyor"):
        open_vault(zayif_vault, _PIN)


def test_read_vault_role_zayif_hwid_icin_reddedilir(zayif_vault, db) -> None:
    with pytest.raises(USBAuthError):
        read_vault_role(zayif_vault, _PIN)


def test_change_vault_role_zayif_hwid_icin_reddedilir(zayif_vault, db) -> None:
    with pytest.raises(USBAuthError):
        change_vault_role(zayif_vault, _PIN, "Yönetici")


def test_change_vault_pin_zayif_hwid_icin_reddedilir(zayif_vault, db) -> None:
    with pytest.raises(USBAuthError):
        change_vault_pin(zayif_vault, _PIN, "yeni-pin-999")


def test_authenticate_usb_zayif_hwid_icin_reddedilir(zayif_vault, db) -> None:
    with pytest.raises(USBAuthError, match="donanım seri numarası okunamıyor"):
        vault_manager.authenticate_usb(zayif_vault)


def test_kritik_islem_reddi_ac_kapali_HEPSI_denetim_kaydina_dusuyor(zayif_vault, db) -> None:
    """Beş reddin hepsi ayrı ayrı denetim kaydına düşmeli — sessiz olan yok."""
    for cagri in (
        lambda: open_vault(zayif_vault, _PIN),
        lambda: read_vault_role(zayif_vault, _PIN),
        lambda: change_vault_role(zayif_vault, _PIN, "Yönetici"),
        lambda: change_vault_pin(zayif_vault, _PIN, "yeni-pin-999"),
        lambda: vault_manager.authenticate_usb(zayif_vault),
    ):
        with pytest.raises(USBAuthError):
            cagri()

    kayitlar = db.fetchall(
        "SELECT detail FROM audit_log WHERE action = 'weak_hwid_binding_rejected'"
    )
    assert len(kayitlar) == 5


def test_verify_vault_zayif_hwid_icin_ENGELLENMIYOR(zayif_vault, db) -> None:
    """
    Tanı/bütünlük denetimi (verify_vault, haftalık taramanın kullandığı)
    engellenmemeli — zayıf bağlı bir vault'un bozulup bozulmadığını hâlâ
    bilmek isteriz. Yalnızca TRUST veren işlemler reddediliyor.
    """
    verify_vault(zayif_vault)  # istisna atmamalı


def test_kurtarma_zayif_hwid_icin_MUAF(zayif_vault, db) -> None:
    """
    Kurtarma akışı BİLEREK muaf: zayıf bağlı bir cihazın tek çıkış yolu bu.
    Onu da kapatmak kullanıcıyı kalıcı olarak kilitlerdi.
    """
    parca = export_recovery_share(zayif_vault, _PIN)  # istisna atmamalı
    kurtarilan = recover_master_key(zayif_vault, recovery_share=parca, pin=_PIN)
    assert len(kurtarilan) == 32

    # reprovision_vault (create_vault'un anchor_share'li çağrısı) de muaf —
    # aynı (zayıf) hwid'e yeniden kurulum başarıyla tamamlanmalı.
    yeni_yol = reprovision_vault(
        zayif_vault, "yeni-pin-777", _ROLE,
        master_key=kurtarilan, recovery_share=parca,
    )
    assert yeni_yol.exists()
    verify_vault(zayif_vault)  # yeniden kurulan vault geçerli imzayla duruyor
