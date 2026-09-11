"""
CORE.vault_manager — kara liste kontrolü.

Gerçek vault oluşturulup gerçek open_vault() ile açılır (Argon2id dahil);
yalnızca vault dizini tmp_path'e yönlendirilir.

Geçmiş: kara liste yalnızca authenticate_usb() içinde kontrol ediliyordu,
oysa giriş ekranı open_vault()'u doğrudan çağırıyor — kara listedeki bir USB
geçerli PIN'le vault'u açabiliyordu (SECURITY.md §4.1). Bu testler iki giriş
yolunun da aynı kontrolden geçtiğini garanti eder.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from CORE import vault_manager
from CORE.vault_manager import (
    USBAuthError,
    blacklist_usb,
    change_vault_pin,
    change_vault_role,
    create_vault,
    open_vault,
    read_vault_role,
)

_HWID = "USB-BL-TEST"
_PIN = "gizli-pin-123"
_ROLE = "Yönetici"


@pytest.fixture
def vault(db, tmp_path: Path, monkeypatch) -> str:
    """tmp_path içinde gerçek bir vault oluşturur ve HWID'i döndürür."""
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    create_vault(_HWID, _PIN, _ROLE)
    return _HWID


def _unblacklist(db, hwid: str) -> None:
    """AdminPanel'in 'Kara Listeden Çıkar' işlemiyle aynı SQL."""
    db.execute("UPDATE usb_tokens SET blacklisted = 0 WHERE hwid = ?", (hwid,))


# ── Temel davranış ────────────────────────────────────────────────────────────

def test_vault_opens_normally_before_blacklisting(vault, db) -> None:
    """Ön koşul: kara listeye alınmadan önce açılabiliyor olmalı."""
    role, master_key = open_vault(vault, _PIN)
    assert role == _ROLE
    assert len(master_key) == 32


def test_blacklisted_usb_cannot_open_vault(vault, db) -> None:
    """
    ASIL DÜZELTME: kara listedeki USB, DOĞRU PIN ile bile açamamalı.

    Bu test düzeltmeden önce başarısız olurdu — open_vault kara listeye
    hiç bakmıyordu.
    """
    blacklist_usb(vault)

    with pytest.raises(USBAuthError, match="kara listede"):
        open_vault(vault, _PIN)


def test_blacklist_is_checked_before_pin_work(vault, db) -> None:
    """
    Kara liste kontrolü PIN'den ÖNCE gelmeli.

    Yanlış PIN'le bile USBAuthError gelmeli (ValueError değil): kontrol
    Argon2id maliyetine girmeden, en başta çalışıyor demektir.
    """
    blacklist_usb(vault)

    with pytest.raises(USBAuthError):
        open_vault(vault, "tamamen-yanlis-pin")


def test_unblacklisted_usb_can_open_again(vault, db) -> None:
    """Kara listeden çıkarılan USB tekrar açabilmeli."""
    blacklist_usb(vault)
    with pytest.raises(USBAuthError):
        open_vault(vault, _PIN)

    _unblacklist(db, vault)

    role, master_key = open_vault(vault, _PIN)
    assert role == _ROLE
    assert len(master_key) == 32


def test_master_key_is_identical_after_unblacklist(vault, db) -> None:
    """
    Kara liste bir İPTAL değil — paylar geçerliliğini korur.

    Çıkarıldıktan sonra kurtarılan master_key, kara listeye alınmadan
    öncekiyle birebir aynı olmalı. Bu, SECURITY.md §4.1'deki "idari işaret,
    iptal mekanizması değil" ifadesini koda bağlar.
    """
    _, before = open_vault(vault, _PIN)

    blacklist_usb(vault)
    _unblacklist(db, vault)

    _, after = open_vault(vault, _PIN)
    assert after == before, "paylar değişmiş — kara liste iptal gibi davranmış"


# ── İki giriş yolu da aynı kontrolden geçiyor ─────────────────────────────────

def test_both_entry_paths_reject_blacklisted_device(vault, db) -> None:
    """
    authenticate_usb (USB yeniden takma) ve open_vault (PIN girişi)
    aynı kontrolden geçmeli — biri açık kalırsa bypass geri gelir.
    """
    blacklist_usb(vault)

    with pytest.raises(USBAuthError, match="kara listede"):
        vault_manager.authenticate_usb(vault)

    with pytest.raises(USBAuthError, match="kara listede"):
        open_vault(vault, _PIN)


def test_read_vault_role_still_reachable_for_clean_device(vault, db) -> None:
    """Kara liste kontrolü temiz cihazın normal akışını bozmamalı."""
    assert read_vault_role(vault, _PIN) == _ROLE


# ── Pentest turu (2026-09-12): open_vault dışındaki üç kardeş fonksiyon ────────
#
# CANLI KANIT: kara listeye alınmadan önce bu üç fonksiyonun hiçbiri
# _reject_if_blacklisted() çağırmıyordu — doğru PIN'le hâlâ çalışıyorlardı.
# UI/UsbTokensView.py::_on_change_role() (admin panelindeki "Rol Değiştir")
# change_vault_role()'u DOĞRUDAN çağırıyor; CORE/pin_rotation.py'nin
# self-servis PIN yenileme akışı change_vault_pin()'i DOĞRUDAN çağırıyor —
# yani bu ikisi CANLI, gerçek UI'dan tetiklenebilen bir yetki-yükseltme/
# iptal-atlatma yoluydu: kara listedeki bir USB'nin sahibi, PIN'i biliyorsa
# kendi rolünü Yönetici'ye çıkarabiliyor VEYA PIN'ini değiştirip cihazı
# canlı tutabiliyordu — kara listenin "PIN doğru olsa bile artık hiçbir şey
# yapamaz" amacını üç noktada delen, open_vault()'ta bir kez bulunup
# düzeltilmiş hatanın tekrarıydı (bkz. SECURITY.md §4.1).

def test_read_vault_role_de_kara_listedeki_cihazi_reddediyor(vault, db) -> None:
    blacklist_usb(vault)
    with pytest.raises(USBAuthError, match="kara listede"):
        read_vault_role(vault, _PIN)


def test_change_vault_role_kara_listedeki_cihazla_ROL_YUKSELTEMIYOR(vault, db) -> None:
    """
    ASIL DÜZELTME: kara listedeki bir USB, doğru PIN'le bile rolünü
    Yönetici'ye YÜKSELTEMEMELİ.

    Bu test düzeltmeden önce başarısız olurdu — change_vault_role() kara
    listeye hiç bakmıyordu, rol sessizce "Yönetici"ye değişiyordu.
    """
    blacklist_usb(vault)

    with pytest.raises(USBAuthError, match="kara listede"):
        change_vault_role(vault, _PIN, "Yönetici")

    # Rol GERÇEKTEN değişmemiş olmalı — bypass'ın sessizce yarı başarılı
    # kalmadığını doğrular.
    _unblacklist(db, vault)
    assert read_vault_role(vault, _PIN) == _ROLE


def test_change_vault_pin_kara_listedeki_cihazla_PIN_YENILEYEMIYOR(vault, db) -> None:
    """
    ASIL DÜZELTME: kara listedeki bir USB, doğru eski PIN'le bile PIN'ini
    yenileyememeli — aksi hâlde kara liste bir cihazı canlı tutmanın önünü
    hiç kesmez.
    """
    blacklist_usb(vault)

    with pytest.raises(USBAuthError, match="kara listede"):
        change_vault_pin(vault, _PIN, "yeni-pin-456")

    # PIN GERÇEKTEN değişmemiş olmalı.
    _unblacklist(db, vault)
    assert read_vault_role(vault, _PIN) == _ROLE
    with pytest.raises(ValueError):
        read_vault_role(vault, "yeni-pin-456")


def test_create_vault_kara_listedeki_hwide_YENIDEN_KURULAMIYOR(db, tmp_path, monkeypatch) -> None:
    """
    reprovision_vault() (kurtarma sonrası yeniden kurulum) create_vault()'u
    anchor_share ile çağırıyor — hedef hwid kara listedeyse bu da
    reddedilmeli, tıpkı taze kayıt gibi (bkz. create_vault docstring'i,
    "bu bir TRUST kararı").
    """
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    hwid = "USB-BL-CREATE-TEST"
    create_vault(hwid, _PIN, _ROLE)
    blacklist_usb(hwid)

    with pytest.raises(USBAuthError, match="kara listede"):
        create_vault(hwid, "baska-bir-pin", _ROLE)


def test_dort_fonksiyon_da_ayni_kontrolden_geciyor(vault, db) -> None:
    """
    open_vault, read_vault_role, change_vault_role, change_vault_pin —
    dördü de AYNI _reject_if_blacklisted() çağrısından geçmeli. Biri
    atlarsa bypass geri gelir (bkz. test_both_entry_paths_reject_
    blacklisted_device'ın aynı gerekçesi, dört giriş yoluna genişletildi).
    """
    blacklist_usb(vault)

    for fn, args in (
        (open_vault, (vault, _PIN)),
        (read_vault_role, (vault, _PIN)),
        (change_vault_role, (vault, _PIN, "Yönetici")),
        (change_vault_pin, (vault, _PIN, "yeni-pin-789")),
    ):
        with pytest.raises(USBAuthError, match="kara listede"):
            fn(*args)


# ── Yardımcının kendisi ───────────────────────────────────────────────────────

def test_helper_is_noop_for_unregistered_hwid(db) -> None:
    """
    Kayıtlı olmayan HWID burada reddedilmez — "kayıtlı değil" durumunu
    çağıranlar kendi mesajlarıyla ele alır.
    """
    vault_manager._reject_if_blacklisted("HIC-KAYITLI-DEGIL")  # istisna yok


def test_blacklist_rejection_is_audited(vault, db) -> None:
    blacklist_usb(vault)

    with pytest.raises(USBAuthError):
        open_vault(vault, _PIN)

    kayitlar = db.fetchall(
        "SELECT detail FROM audit_log WHERE action = 'usb_auth_rejected'"
    )
    assert len(kayitlar) == 1
    assert vault in kayitlar[0]["detail"]
    assert "kara listede" in kayitlar[0]["detail"]


# ── Statik muhafız: bu hata sınıfı BİR DAHA SESSİZCE geri gelmesin ─────────────
#
# Bu proje AYNI hatayı (kara liste kontrolü tek bir giriş yolunda düzeltilip
# kardeş fonksiyonlara YAYILMIYOR) bu hafta üçüncü kez yazdı: önce login akışı
# (open_vault vs authenticate_usb, SECURITY.md §4.1), sonra MC-M147 (USB
# yeniden takma reauth'u farklı bir varsayımla çalışıyordu), şimdi de burada
# (read_vault_role/change_vault_role/change_vault_pin/create_vault). Elle
# hatırlamaya güvenmek yerine: `hwid` VE bir `pin` parametresi (ör. `pin`,
# `old_pin`, `new_pin`) birlikte alan HER `CORE/vault_manager.py` fonksiyonu,
# doğrudan ya da (create_vault/_decrypt_vault/_read_share_1 üzerinden)
# dolaylı olarak `_reject_if_blacklisted()`e ULAŞMALI — bu test modülü
# YENİDEN OKUYUP çağrı grafiğini kendisi kuruyor, yani yeni bir fonksiyon
# eklendiğinde elle güncellenmesi gereken tek şey (varsa) aşağıdaki `_MUAF`
# sözlüğüdür.

#: hwid+pin alıp KASITLI olarak _reject_if_blacklisted'a ulaşmayan
#: fonksiyonlar — her girişin gerekçesi olmalı. Yeni bir muafiyet eklemek
#: güvenlik incelemesi gerektirir, sessizce büyütülmemeli.
_MUAF = {
    "recover_master_key": (
        "Kurtarma parçası + kalan payla master_key'i YALNIZCA OKUYOR, "
        "vault'a hiçbir şey YAZMIYOR — _reject_if_weak_binding'in "
        "recover_master_key'i muaf tuttuğu AYNI gerekçe (vault_manager.py'de "
        "'BURAYA GEÇMİYOR' notu): kullanıcının verisine erişebilmesinin TEK "
        "yolu bu, kapatmak kalıcı kilitlenme üretirdi. Kara listedeki bir "
        "hwid'e YENİ bir vault YAZMAK (create_vault, reprovision_vault'un "
        "iç çağrısı) AYRI bir karar ve GATED."
    ),
}


def _vault_manager_call_graph() -> dict[str, set[str]]:
    kaynak = Path(vault_manager.__file__).read_text(encoding="utf-8")
    agac = ast.parse(kaynak)
    graf: dict[str, set[str]] = {}
    for node in ast.walk(agac):
        if isinstance(node, ast.FunctionDef):
            cagrilar = {
                n.func.id
                for n in ast.walk(node)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            }
            graf[node.name] = cagrilar
    return graf


def _reaches(graf: dict[str, set[str]], baslangic: str, hedef: str,
             gorulen: set[str] | None = None) -> bool:
    gorulen = gorulen if gorulen is not None else set()
    if baslangic in gorulen:
        return False
    gorulen.add(baslangic)
    cagrilar = graf.get(baslangic, set())
    if hedef in cagrilar:
        return True
    return any(_reaches(graf, c, hedef, gorulen) for c in cagrilar if c in graf)


def test_hwid_ve_pin_alan_her_fonksiyon_kara_liste_kontrolune_ulasiyor() -> None:
    kaynak = Path(vault_manager.__file__).read_text(encoding="utf-8")
    agac = ast.parse(kaynak)
    graf = _vault_manager_call_graph()

    assert "_reject_if_blacklisted" in graf, (
        "_reject_if_blacklisted() CORE/vault_manager.py'de bulunamadı — "
        "modül yeniden mi yapılandırıldı? Bu test onun varlığını varsayıyor."
    )

    hedef_fonksiyonlar = []
    for node in ast.walk(agac):
        if not isinstance(node, ast.FunctionDef):
            continue
        argnames = {a.arg for a in node.args.args} | {a.arg for a in node.args.kwonlyargs}
        hwid_var_mi = "hwid" in argnames
        pin_var_mi = any(a == "pin" or a.endswith("_pin") for a in argnames)
        if hwid_var_mi and pin_var_mi:
            hedef_fonksiyonlar.append(node.name)

    # Sağlık kontrolü: bu heuristiğin gerçekten bir şey bulduğunu doğrula —
    # aksi hâlde test sessizce hiçbir şeyi kontrol etmeden yeşil kalırdı.
    assert len(hedef_fonksiyonlar) >= 8, (
        f"Beklenenden az fonksiyon bulundu ({hedef_fonksiyonlar}) — "
        "heuristik (hwid + *pin parametresi) modülün gerçek şekliyle "
        "uyuşmuyor olabilir, test gözden geçirilmeli."
    )

    basarisiz = []
    for ad in hedef_fonksiyonlar:
        if ad in _MUAF:
            continue
        if not _reaches(graf, ad, "_reject_if_blacklisted"):
            basarisiz.append(ad)

    assert not basarisiz, (
        f"{basarisiz} — hwid+PIN alan bu fonksiyon(lar) _reject_if_blacklisted() "
        "kontrolüne (doğrudan ya da başka bir yardımcı üzerinden) hiç "
        "ULAŞMIYOR. Kara listedeki bir cihaz, doğru PIN'le bu fonksiyonu "
        "çağırıp işlemi tamamlayabilir demektir — bkz. bu dosyanın üstündeki "
        "'Pentest turu (2026-09-12)' bulguları. Gerçekten kasıtlıysa "
        "_MUAF sözlüğüne gerekçesiyle eklenmeli."
    )
