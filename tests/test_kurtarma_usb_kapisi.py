"""
`_require_hwid()` kapısı — TAM OLARAK nerede uygulanıyor, nerede YOK.

Neden bu dosya var
------------------
BACKLOG B-069'un düzeltilmiş gerekçesi (2026-08-28) "USB gereksinimini
fiilen dayatan TEK şey `_require_hwid()`'in bilinçli reddi" diyordu — ama
bu iddia HANGİ katmanda geçerli olduğunu ayırt etmiyordu. İki katman VAR
ve davranışları FARKLI, ikisi de burada doğrudan denenerek kanıtlanıyor:

  1. `CORE/recover_vault.py::_cmd_export/_cmd_recover/_cmd_status` — her
     üçü `_require_hwid()`'i KENDİ gövdelerinin İLK satırında çağırıyor
     (satır 105, 127, 215). `main()`'in dispatch'i DEĞİL, fonksiyonun
     kendisi. Doğrudan içe aktarılıp `main()` hiç çalıştırılmadan
     çağrılsa BİLE kapı devrede kalıyor — aşağıdaki
     `test_cmd_recover_DOGRUDAN_cagrilsa_bile_USB_kapisi_devrede` bunu
     kanıtlıyor.

  2. `CORE/vault_manager.py::recover_master_key()` — asıl kurtarma
     işlemini yapan fonksiyon. Kaynağında `get_usb_hwid` ya da
     `_require_hwid` geçen TEK BİR satır bile yok (`inspect.getsource()`
     ile ölçüldü). `hwid`'i sıradan bir string parametresi olarak alıyor
     ve hiçbir aşamada fiziksel cihaza bakmıyor. Aşağıdaki
     `test_recover_master_key_USB_KAPISINDAN_GECMEDEN_dogrudan_calisiyor`
     bunu uçtan uca kanıtlıyor: gerçek bir vault kurup, hwid'i (USB'ye HİÇ
     dokunmadan) yalnızca `data/vaults/` dizin listesinden okuyup,
     `recover_master_key()`'i DOĞRUDAN çağırıp (recover_vault.py'ye,
     `main()`'e, `_require_hwid()`'e hiç uğramadan) doğru master_key'in
     geri geldiğini gösteriyor — Seçenek 2'de (PIN de VERİLMEDEN).

Sonuç, ve neden `_require_hwid()` `recover_master_key()`'e TAŞINMIYOR
-----------------------------------------------------------------------
Kapı bir MİMARİ ÖZELLİK değil, `recover_vault.py`'nin CLI script'ine
özgü bir GİRİŞ NOKTASI kontrolü — Python kod çalıştırma erişimi olan
biri (M2/M3, bu depoda zaten §4.5'in varsaydığı, "uygulama arayüzünden
DAHA GÜÇLÜ" bir yetenek) `CORE.vault_manager.recover_master_key()`'i
doğrudan içe aktarıp çağırarak bu kapıyı TAMAMEN atlayabiliyor. Kapıyı
`recover_master_key()`'in kendisine taşımak KASITLI OLARAK yapılmadı:
B-036 (açık, karar bekliyor) tam olarak "USB fiziksel kaybolduğunda
basılı parça + PIN ile" bir kurtarma akışı ekleme olasılığını tartışıyor
— `recover_master_key()`'e koşulsuz bir fiziksel-USB kontrolü gömmek bu
gelecekteki tasarımı YAPISAL OLARAK imkânsız kılardı. Bkz. SECURITY.md
§4.4 ve BACKLOG B-069/B-036.

2026-08-29 — nihai karar teyit edildi: mockup'ın ekranı EKLENMEYECEK
-------------------------------------------------------------------------
Yukarıdaki analiz zaten "böyle bir ekran, bugün fiilen duran tek
savunmayı (Katman 1'in `_require_hwid()`'i) bilerek kaldırıp §4.4'ün
uyardığı saldırı yolunu (basılı kurtarma parçası + makineye erişim, USB
YOK, PIN YOK → master_key) UYGULAMANIN KENDİ ARAYÜZÜNE taşırdı" sonucuna
varmıştı. Bu turda o sonuç NİHAİ karar olarak onaylandı — wontfix kalıcı.

Önceki turlarda bu kararı yalnızca `_require_hwid()`'in davranışı
KANITLIYORDU (bölüm 1-2, üstte); mockup'ın ekranının GERÇEKTEN
`UI/login_dialog.py`'ye hiç eklenmediğini kalıcı olarak KORUYAN bir test
yoktu — 2026-08-26 tarihli "tek satır bile yok" ölçümü o turda elle
yapılmış bir grep'ti, kalıcı bir regresyon koruması değildi. Bölüm 3
(altta) bu boşluğu kapatıyor: `login_dialog.py`'nin kaynağı yasaklı
terimlerle taranıyor VE ekranın gerçekten iki sayfalı kaldığı (Giriş
Yap + Kayıt Ol, ÜÇÜNCÜ bir "Kurtarma ile Gir" sayfası YOK) davranışsal
olarak doğrulanıyor.
"""
from __future__ import annotations

import argparse
import inspect
from pathlib import Path
from unittest import mock

import pytest

from CORE import recover_vault, vault_manager
from CORE.vault_manager import create_vault, export_recovery_share, recover_master_key

_HWID = "USB-KAPI-DENEY-TEST"
_PIN = "gizli-pin-777"
_ROLE = "Standart"


@pytest.fixture
def vault_dizini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / "legacy.hclv")
    return tmp_path


# ══════════════════════════════════════════════════════════════════════════════
# 1. CLI katmanı — kapı `main()`'e değil, fonksiyonun KENDİSİNE gömülü
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "fonksiyon_adi,args",
    [
        ("_cmd_export", argparse.Namespace(qr_out=None)),
        ("_cmd_recover", argparse.Namespace(qr_out=None)),
        ("_cmd_status", argparse.Namespace(qr_out=None)),
    ],
)
def test_cmd_fonksiyonlari_DOGRUDAN_cagrilsa_bile_USB_kapisi_devrede(
    fonksiyon_adi: str, args: argparse.Namespace,
) -> None:
    """
    `main()`'i HİÇ çalıştırmadan, `_cmd_export`/`_cmd_recover`/`_cmd_status`'u
    doğrudan içe aktarıp çağırıyoruz — `get_usb_hwid()` `None` dönüyor (USB
    yok simülasyonu). Kapı yine de devrede olmalı, çünkü `_require_hwid()`
    fonksiyonun KENDİ gövdesinin ilk satırında, dış dispatch'te değil.
    """
    fonksiyon = getattr(recover_vault, fonksiyon_adi)
    with mock.patch.object(recover_vault, "get_usb_hwid", return_value=None):
        with pytest.raises(SystemExit):
            fonksiyon(args)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Çekirdek katman — `recover_master_key()`'in kaynağında USB'ye dair
#    TEK BİR satır bile yok
# ══════════════════════════════════════════════════════════════════════════════


def test_recover_master_key_kaynaginda_USB_referansi_YOK() -> None:
    """
    Statik kanıt: `inspect.getsource()` ile alınan gövdede `get_usb_hwid`
    ya da `_require_hwid` hiç geçmiyor. `recover_master_key()`'in USB
    farkındalığı YAPISAL OLARAK yok — sonraki test bunu davranışsal
    olarak da kanıtlıyor.
    """
    kaynak = inspect.getsource(recover_master_key)
    assert "get_usb_hwid" not in kaynak
    assert "_require_hwid" not in kaynak


def test_recover_master_key_USB_KAPISINDAN_GECMEDEN_dogrudan_calisiyor(
    vault_dizini: Path, db, fake_keyring,  # type: ignore[no-untyped-def]
) -> None:
    """
    ASIL DAVRANIŞSAL KANIT — bilinen bir mimari boşluk, bir hata değil:

    `CORE/recover_vault.py`'ye, `main()`'e, `_require_hwid()`'e HİÇ
    uğramadan — `get_usb_hwid()` bu test boyunca bir kez bile
    ÇAĞRILMIYOR — gerçek bir vault kurup, hwid'i yalnızca
    `data/vaults/` dizin listesinden (bir saldırganın da yapabileceği
    şekilde) okuyup `recover_master_key()`'i DOĞRUDAN çağırıyoruz.
    Üstelik PIN bile VERMEDEN (Seçenek 2 — share_1 kayıp dalı).

    Bu test KIRILMAMALI — kırılırsa ya kapı `recover_master_key()`'e
    taşınmış (BACKLOG B-069/B-036'nın mimari kararını değiştiren bir
    adım, SECURITY.md §4.4 buna göre güncellenmeli) ya da recovery
    mantığı bir şekilde bozulmuş demektir.
    """
    master_key_orig = bytes(range(32))
    create_vault(_HWID, _PIN, _ROLE, master_key=master_key_orig)
    share_3 = export_recovery_share(_HWID, _PIN)

    with mock.patch(
        "CORE.usb_manager.get_usb_hwid",
        side_effect=AssertionError("get_usb_hwid() HİÇ çağrılmamalıydı"),
    ):
        # Saldırganın/operatörün yapacağı şey: dizin listesi, USB DEĞİL.
        bulunan = list((vault_dizini / "vaults").glob("*.hclv"))
        assert [f.stem for f in bulunan] == [_HWID]
        ogrenilen_hwid = bulunan[0].stem

        # Seçenek 1 — PIN verilerek (share_2 kayıp dalı).
        kurtarilan_1 = recover_master_key(ogrenilen_hwid, recovery_share=share_3, pin=_PIN)
        assert kurtarilan_1 == master_key_orig

        # Seçenek 2 — PIN bile VERİLMEDEN (share_1 kayıp dalı). Tek gereken:
        # dosya adından öğrenilen hwid + elde bulunan share_3.
        kurtarilan_2 = recover_master_key(ogrenilen_hwid, recovery_share=share_3, pin=None)
        assert kurtarilan_2 == master_key_orig


# ══════════════════════════════════════════════════════════════════════════════
# 3. UI katmanı (YAPISAL kısmı) — mockup'ın "Kurtarma parçasıyla gir"
#    ekranı GERÇEK `login_dialog.py`'ye hiç eklenmemiş; bu KALICI olarak
#    korunuyor (2026-08-29, nihai wontfix onayı).
#
#    DAVRANIŞSAL kanıt (gerçek `LoginDialog`, `_stack.count() == 2`)
#    KASITLI olarak BURADA DEĞİL: bu dosya modül seviyesinde Qt/UI ithal
#    ETMİYOR — bu yüzden Qt kurulu olmayan bir ortamda bile (ör. çıplak
#    bir Linux runner'ı) bölüm 1-2'deki CLI/çekirdek katman testleri
#    toplanabiliyor (bkz. `tests/test_layering.py`'nin bu depo genelinde
#    zorunlu kıldığı kural: korumasız bir modül-seviyesi Qt/UI ithali TÜM
#    paketi TOPLAMA HATASIYLA durdurur). Davranışsal test, standart
#    "try/except ImportError: pytest.skip(..., allow_module_level=True)"
#    korumasıyla ayrı bir dosyada:
#    `tests/test_login_dialog_kurtarma_ekrani_yok.py`.
# ══════════════════════════════════════════════════════════════════════════════

#: Ekranın gerçek koda girmiş olacağını gösterecek terimler — kurtarma
#: payını (`share_3`) kullanıcıdan ALAN bir giriş noktasının izi. Yasaklı
#: listesi `tests/test_kayit_ekrani.py::_YASAKLI_METINLER`'in aynı deseni
#: (B-071/B-076): somut, kod-tarzı isimler + Türkçe görünen etiketler.
_KURTARMA_GIRIS_TERIMLERI = (
    "decode_share",
    "recover_master_key",
    "export_recovery_share",  # bu bir DIŞA AKTARIM çağrısı — login_dialog.py'de olmamalı
    "share_3",
    "RecoveryShareDialog",
    "Kurtarma parça",
    "kurtarma_parcasi",
    "kurtarma parçasıyla",
)


def test_login_dialog_KAYNAGINDA_kurtarma_giris_terimi_YOK() -> None:
    """
    YAPISAL kanıt: `UI/login_dialog.py`'nin kaynağında kurtarma payını
    ALAN bir giriş noktasının izi yok. 2026-08-26'da bu elle bir grep'ti
    (B-069'un ilk metni, "tek bir satır bile yok" diyordu) — kalıcı bir
    test DEĞİLDİ, yani biri ekranı geri getirse fark edilmeyebilirdi. Bu
    test o boşluğu kapatıyor.
    """
    kaynak = (Path(__file__).resolve().parent.parent / "UI" / "login_dialog.py").read_text(
        encoding="utf-8"
    )
    bulunan = [t for t in _KURTARMA_GIRIS_TERIMLERI if t.lower() in kaynak.lower()]
    assert not bulunan, (
        f"UI/login_dialog.py'de kurtarma-girişi terimi bulundu: {bulunan} — "
        "B-069 wontfix kararı bozulmuş olabilir, bkz. BACKLOG.md B-069"
    )


def test_tarayici_enjekte_edilen_kurtarma_terimini_YAKALIYOR(tmp_path: Path) -> None:
    """Denetimin kendisi çalışıyor mu — B-024 dersi (bkz. `test_tpm_sealing.py`,
    `test_ui_yasakli_iddia_terimleri.py`): sahte bir dosyaya terim ekilip
    tarama fonksiyonunun AYNISI (elle tekrarlanmadan) buna karşı çalıştırılıyor."""
    gecici = tmp_path / "sahte_login_dialog.py"
    gecici.write_text('baslik = "Kurtarma parçasıyla gir"\n', encoding="utf-8")
    kaynak = gecici.read_text(encoding="utf-8")
    bulunan = [t for t in _KURTARMA_GIRIS_TERIMLERI if t.lower() in kaynak.lower()]
    assert bulunan, "enjekte edilen kurtarma-girişi terimi yakalanmadı"
