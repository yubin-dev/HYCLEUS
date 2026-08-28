"""
CORE.vault_manager.recover_master_key() — çağrı grafiği + reprovision-öncesi
pencere denetimi.

SECURITY.md §4.2'nin "token_id'nin tek koruması reprovision_vault()'un
onu tazelemesi" gerekçesinin iki ayrı iddiasını koda bağlıyor:

  1. YAPISAL — `test_recover_master_key_her_cagri_yerinde_reprovision_
     erisilebilir`: `recover_master_key()`'e yapılan HER üretim-kodu çağrısı,
     AYNI fonksiyon gövdesinde `reprovision_vault()`'u da çağırıyor mu?
     Yöntem `tests/test_tpm_sealing.py`'nin "düşüş kararı YALNIZCA tek
     yerden giriyor" denetimleriyle aynı AST deseni.

     ÖNEMLİ SINIR — bu denetim "reprovisioning HER ZAMAN ÇALIŞIR" demiyor.
     `CORE/recover_vault.py::_cmd_recover()` kullanıcının reprovisioning'i
     REDDETTİĞİ meşru bir dal barındırıyor ("Atlandı" mesajı, satır ~168-174)
     — kullanıcı kurtarılan anahtarı görüp "şimdi değil" diyebilir. Denetlenen
     şey "reprovision_vault AYNI İŞLEMDE erişilebilir mi" (yani kurtarma
     tamamen ayrı, bağlantısız bir betiğe/uç noktaya YAYILMAMIŞ) — "her
     çağrı sonunda gerçekten çalışıyor mu" değil. İkincisi statik olarak
     kanıtlanamaz ve zaten YANLIŞ olurdu: red dalı kasıtlı bir tasarım.

     Reddetme dalının GÜVENLİ olduğu — reprovision hemen çalışmasa bile —
     ayrı ayrı, ÇALIŞMA ANI denetimiyle kanıtlanıyor (madde 2 ve
     `tests/test_vault_hmac_share2.py`).

  2. ÇALIŞMA ANI — `test_vault_recovered_denetim_kaydi_token_id_icermez` ve
     `test_token_id_okuyan_TEK_yer_authenticate_usb`: reprovision-öncesi
     pencerede (reddetme dalı dahil) hiçbir şey — özellikle audit log —
     tamponlanmamış `token_id`'ye dokunmuyor mu? `recover_master_key()`'in
     kendi yazdığı `vault_recovered` kaydı (`CORE/vault_manager.py:1283-1286`)
     yalnızca `hwid` ve `kaynak` (share_1+share_3 / share_2+share_3) içeriyor
     — `token_id` YOK, ne tamponlanmış ne tamponlanmamış hiçbir biçimde.
     `_read_vault_token_id()`'in TEK çağrı yeri `authenticate_usb()`'ın
     3. Katmanı — ve o yol `verify_vault()`'ı DOĞRUDAN çağırıyor, `share_2`
     yokluğu atlaması OLMADAN: `share_2` hâlâ eksikse Katman 2 önce
     reddediyor, Katman 3 (token_id okuma) hiç çalışmıyor.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from CORE import vault_manager
from CORE.vault_manager import create_vault, export_recovery_share, recover_master_key

KOK = Path(__file__).resolve().parent.parent

_HWID = "USB-RECOVERY-GRAPH-TEST"
_PIN = "gizli-pin-321"
_ROLE = "Standart"


@pytest.fixture
def vault_dizini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / "legacy.hclv")
    return tmp_path


# ══════════════════════════════════════════════════════════════════════════════
# 1. Yapısal — her çağrı yerinde reprovision aynı işlemde erişilebilir mi
# ══════════════════════════════════════════════════════════════════════════════


def _cagri_adi(dugum: ast.Call) -> str:
    """`f(...)` → "f";  `m.f(...)` → "f"."""
    if isinstance(dugum.func, ast.Name):
        return dugum.func.id
    if isinstance(dugum.func, ast.Attribute):
        return dugum.func.attr
    return ""


def _uretim_dosyalari() -> list[Path]:
    """CORE/DB/UI + main.py — testler/betikler/BACKLOG DIŞINDAKİ üretim yüzeyi."""
    return [
        yol for kok in ("CORE", "DB", "UI")
        for yol in sorted((KOK / kok).rglob("*.py"))
    ] + [KOK / "main.py"]


def _cagirir_mi(dugum: ast.AST, ad: str) -> bool:
    return any(
        isinstance(d, ast.Call) and _cagri_adi(d) == ad
        for d in ast.walk(dugum)
    )


def test_recover_master_key_her_cagri_yerinde_reprovision_erisilebilir() -> None:
    """
    ASIL YAPISAL DENETİM: `recover_master_key()`'i çağıran her fonksiyon,
    AYNI gövdede `reprovision_vault()`'u da çağırmalı.

    Yeni bir çağrı yeri (bir GUI akışı, bir API uç noktası, başka bir betik)
    reprovision'a hiç dokunmadan eklenirse bu test kırılır — SECURITY.md
    §4.2'nin "token_id yalnızca reprovision ile kapatılır, ve reprovision
    her çağrı yerinde erişilebilir" iddiasının CLI'ye özgü olmadığını,
    genel bir kural olarak kaldığını garanti eder.
    """
    ihlaller: list[str] = []
    cagri_sayisi = 0

    for dosya in _uretim_dosyalari():
        bagil = dosya.relative_to(KOK).as_posix()
        agac = ast.parse(dosya.read_text(encoding="utf-8"))
        for fn in ast.walk(agac):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _cagirir_mi(fn, "recover_master_key"):
                continue
            cagri_sayisi += 1
            if not _cagirir_mi(fn, "reprovision_vault"):
                ihlaller.append(f"{bagil}::{fn.name} (satır {fn.lineno})")

    assert cagri_sayisi > 0, (
        "recover_master_key() üretim kodunda HİÇ çağrılmıyor — bu denetim "
        "boş kümeyi denetliyor olurdu (bkz. test_tpm_sealing.py B-024 dersi)."
    )
    assert not ihlaller, (
        "recover_master_key() şu fonksiyonlarda reprovision_vault() OLMADAN "
        f"çağrılıyor: {ihlaller}. Kurtarılan master_key'in kullanıldığı her "
        "işlem, tamponlanmamış token_id'yi kapatacak reprovision_vault()'u "
        "aynı gövdede erişilebilir tutmalı (bkz. SECURITY.md §4.2)."
    )


def test_recover_master_key_TEK_uretim_cagri_yeri_var() -> None:
    """
    Bugün itibariyle TEK üretim çağrı yeri `CORE/recover_vault.py::
    _cmd_recover`. Bu test o sayıyı sabitliyor — sessizce ikinci bir yol
    (bir GUI, bir API) eklenirse bu test onu FARK EDER, geçmesini
    engellemez ama görünür kılar (yukarıdaki test zaten reprovision'ı
    zorunlu kılıyor).
    """
    bulunanlar = []
    for dosya in _uretim_dosyalari():
        bagil = dosya.relative_to(KOK).as_posix()
        agac = ast.parse(dosya.read_text(encoding="utf-8"))
        for d in ast.walk(agac):
            if isinstance(d, ast.Call) and _cagri_adi(d) == "recover_master_key":
                bulunanlar.append(f"{bagil}:{d.lineno}")

    assert bulunanlar == ["CORE/recover_vault.py:146"], (
        f"recover_master_key() çağrı yerleri değişti: {bulunanlar}. "
        "Yeni bir yer eklendiyse SECURITY.md §4.2'nin çağrı-grafiği "
        "gerekçesi (ve bu dosyanın diğer testleri) yeniden gözden "
        "geçirilmeli — bu satır sayısı bilgi amaçlı, testi KIRMAK için "
        "değil, DEĞİŞİKLİĞİ görünür kılmak için var."
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2. Çalışma anı — reprovision-öncesi pencerede token_id'ye dokunulmuyor mu
# ══════════════════════════════════════════════════════════════════════════════


def test_token_id_okuyan_TEK_yer_authenticate_usb() -> None:
    """
    `_read_vault_token_id()`'in TEK çağıranı `authenticate_usb()` olmalı.

    Bu, "reprovision-öncesi pencerede token_id'ye kimse dokunmuyor" iddiasının
    temel taşı: `recover_master_key()`'in kendisi bu fonksiyonu hiç
    çağırmıyor, dolayısıyla kurtarılan anahtarın hesaplanması token_id'nin
    doğruluğuna hiç bağlı değil. İkinci bir çağıran eklenirse (ör. birisi
    kurtarma akışına bir token_id kontrolü eklerse) bu test kırılır — o an
    SECURITY.md §4.2'nin gerekçesi yeniden değerlendirilmeli.
    """
    agac = ast.parse((KOK / "CORE" / "vault_manager.py").read_text(encoding="utf-8"))
    cagiranlar = []
    for fn in ast.walk(agac):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if fn.name == "_read_vault_token_id":
            continue  # tanımın kendisi, çağrı değil
        # yalnızca DOĞRUDAN gövdedeki çağrıları say (iç içe fonksiyon yok burada)
        dogrudan = [
            d for d in ast.walk(fn)
            if isinstance(d, ast.Call) and _cagri_adi(d) == "_read_vault_token_id"
        ]
        if dogrudan:
            cagiranlar.append(fn.name)

    assert cagiranlar == ["authenticate_usb"], (
        f"_read_vault_token_id() şu fonksiyonlardan çağrılıyor: {cagiranlar}. "
        "Beklenen: yalnızca authenticate_usb (Katman 3). Yeni bir çağıran "
        "SECURITY.md §4.2'nin 'token_id yalnızca authenticate_usb'da "
        "okunuyor, ve o yol share_2 yokluğu atlamasından geçmiyor' "
        "gerekçesini geçersiz kılabilir."
    )


def test_vault_recovered_denetim_kaydi_token_id_icermez(vault_dizini, db) -> None:
    """
    ASIL ÇALIŞMA ANI DENETİMİ: `recover_master_key()`'in yazdığı
    `vault_recovered` denetim kaydı `token_id`'yi (tamponlanmış ya da
    tamponlanmamış) HİÇBİR biçimde içermemeli.

    token_id'yi KURCALAYIP share_2-siz kurtarmayı çalıştırıyoruz — eğer
    audit log kurcalanan değeri (ya da gerçek değeri) herhangi bir biçimde
    sızdırıyorsa bu test bunu YAKALAR. Yakalamıyorsa, kaydın yalnızca
    `hwid` ve `kaynak` içerdiği (CORE/vault_manager.py:1283-1286)
    doğrulanmış olur.
    """
    master_key = bytes(range(32))
    create_vault(_HWID, _PIN, _ROLE, master_key=master_key)
    recovery_share = export_recovery_share(_HWID, _PIN)  # share_2 hâlâ kasadayken

    path = vault_manager._read_vault_path(_HWID)
    raw = bytearray(path.read_bytes())
    offset = vault_manager._TOKEN_ID_OFFSET
    size = vault_manager._TOKEN_ID_SIZE
    tampered_token_id = bytes(b ^ 0xFF for b in raw[offset : offset + size])
    raw[offset:offset + size] = tampered_token_id
    with vault_manager._writable(path):
        path.write_bytes(bytes(raw))

    vault_manager.delete_usb_token(_HWID)  # share_2 kaybı simülasyonu

    recover_master_key(_HWID, recovery_share=recovery_share, pin=_PIN)

    kayitlar = db.fetchall(
        "SELECT detail FROM audit_log WHERE action = 'vault_recovered'"
    )
    assert len(kayitlar) == 1, "vault_recovered kaydı beklenen sayıda değil"
    detail = kayitlar[0]["detail"]

    assert tampered_token_id.hex() not in detail
    assert tampered_token_id not in detail.encode("utf-8", errors="ignore")
    assert "token_id" not in detail.lower()
    assert detail == f"hwid={_HWID} kaynak=share_1+share_3"
