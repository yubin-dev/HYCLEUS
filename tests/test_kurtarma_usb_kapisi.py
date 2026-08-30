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
(altta) bu boşluğu kapatıyor.

2026-08-29 (devam) — kapsam DÜZELTİLDİ: login_dialog.py'ye özel DEĞİL, UI/'nin tamamı
-------------------------------------------------------------------------------------
İlk yazımdaki Bölüm 3 yalnızca `UI/login_dialog.py`'yi tek dosya olarak
tarıyordu — TAM OLARAK B-056/K0-6'nın öğrettiği sınıf sorun: korunması
gereken şey "login ekranına üçüncü bir sayfa eklenmesin" değil,
"`decode_share`/`recover_master_key` gibi kurtarma-yeniden-inşa
fonksiyonlarını `_require_hwid()` kapısı olmadan çağıran kod `UI/`
ağacının HİÇBİR yerinde eklenmesin" — biri bu ekranı `UI/RecoveryEntry
Dialog.py` gibi başka bir dosyaya yazıp `main_window.py`'den bir menü
öğesiyle ya da `AdminPanel.py`'den ayrı bir düğmeyle bağlasa, dosyaya-özgü
tarama bunu KAÇIRIRDI. Tarama K0-6'nın `_ui_dosyalari()`/`rglob("*.py")`
desenine taşındı — aşağıdaki "3. UI katmanı" bölümü.

**Ölçülen gerçek yanlış-pozitif riski.** Naif bir "Kurtarma parça" alt-dize
taraması `UI/AdminPanel.py`'nin MEŞRU dışa-aktarım ekranında ("Kurtarma
Parçasını Göster…" düğmesi, "Kurtarma Parçası" diyalog başlıkları, `UI/
RecoveryShareDialog.py`'nin kendi başlığı) SEKİZ yerde patlardı — ölçüldü,
bkz. aşağıdaki `test_mevcut_UI_dosyalarindaki_mesru_kullanimlar_YANLIS_
POZITIF_URETMIYOR`. Aynı şekilde `export_recovery_share`/
`RecoveryShareDialog`/`share_3` gibi isimler `AdminPanel.py`'nin zaten var
olan, test edilmiş, PIN'le korunan DIŞA AKTARIM akışında (bkz. `tests/
test_recovery_share_ui.py`) MEŞRU olarak geçiyor — bunları da yasaklı
listeye eklemek gün-bir false-positive üretirdi. Ayrım: tehlikeli olan
payı DIŞARI vermek değil, payı İÇERİ alıp master_key'i YENİDEN KURMAK —
bu yüzden yasaklı liste yalnızca `recover_master_key`/`decode_share`'in
GERÇEK ÇAĞRI/İTHAL hedefleri (AST `Call`/`Import`, değişken adları DEĞİL
— bkz. aşağıdaki modül notu) ve mockup'ın "gir" fiilini taşıyan spesifik
etiketleri (`ast.Constant` string taraması, K0-6'nın metodu) ile
sınırlandı.
"""
from __future__ import annotations

import argparse
import ast
import inspect
from pathlib import Path
from unittest import mock

import pytest

from CORE import recover_vault, vault_manager
from CORE.vault_manager import create_vault, export_recovery_share, recover_master_key

KOK = Path(__file__).resolve().parent.parent
_UI_DIZINI = KOK / "UI"

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
# 3. UI katmanı (YAPISAL kısmı) — mockup'ın kurtarma-yeniden-inşa yeteneği
#    GERÇEK `UI/` ağacının HİÇBİR yerine eklenmemiş; bu KALICI olarak
#    korunuyor (2026-08-29, kapsam login_dialog.py'den TÜM UI/'ye genişletildi).
#
#    DAVRANIŞSAL kanıt (gerçek `LoginDialog`, `_stack.count() == 2`)
#    KASITLI olarak BURADA DEĞİL: bu dosya modül seviyesinde Qt/UI ithal
#    ETMİYOR — bu yüzden Qt kurulu olmayan bir ortamda bile (ör. çıplak
#    bir Linux runner'ı) bölüm 1-2'deki CLI/çekirdek katman testleri
#    toplanabiliyor (bkz. `tests/test_layering.py`'nin bu depo genelinde
#    zorunlu kıldığı kural: korumasız bir modül-seviyesi Qt/UI ithali TÜM
#    paketi TOPLAMA HATASIYLA durdurur). Davranışsal test, standart
#    "try/except ImportError: pytest.skip(..., allow_module_level=True)"
#    korumasıyla ayrı bir dosyada: `tests/test_login_dialog_kurtarma_
#    ekrani_yok.py` — ve bu bölüm o testin kapsamadığı GENİŞ soruyu
#    (login akışı dışındaki bir giriş noktası — yeni bir dosya, bir menü
#    öğesi, bir admin düğmesi) kapatıyor.
# ══════════════════════════════════════════════════════════════════════════════


def _ui_dosyalari() -> list[Path]:
    """`rglob` — `tests/test_ui_yasakli_iddia_terimleri.py` (K0-6) ile
    AYNI desen: `UI/` bugün alt dizin içermiyor, ama `glob("*.py")`
    (yalnızca üst düzey) bir alt dizin eklendiğinde onu SESSİZCE
    atlardı — K0-6'da bu gerçek bir ölçülmüş regresyondu, burada baştan
    `rglob`'a geçilerek önlendi (bkz. `test_tarayici_ALT_DIZINDEKI_
    dosyayi_da_yakaliyor` altta)."""
    return sorted(p for p in _UI_DIZINI.rglob("*.py") if "__pycache__" not in p.parts)


#: Yeniden-inşa/çözme fonksiyonları — bir kurtarma payını (`share_3`)
#: ALIP master_key'i yeniden kuran ya da kullanıcı girdisini çözen İKİ
#: fonksiyon. `UI/`'de bugün MEŞRU hiçbir kullanımları yok (ölçüldü,
#: bkz. `test_mevcut_UI_dosyalarindaki_mesru_kullanimlar_YANLIS_
#: POZITIF_URETMIYOR`) — dışa aktarım/gösterim ayrı bir fonksiyon
#: ailesi (`export_recovery_share`/`build_export`/`RecoveryShareDialog`)
#: ve BİLEREK bu listede DEĞİL: `AdminPanel.py`'de zaten var, MEŞRU ve
#: test edilmiş (`tests/test_recovery_share_ui.py`) — payı DIŞARI vermek
#: tehlikeli değil, payı İÇERİ alıp master_key'i YENİDEN KURMAK tehlikeli.
#: `share_3` de BİLEREK listede DEĞİL: yalnızca bir DEĞİŞKEN adı, Python
#: bir değişkenin adına önem vermez — `AdminPanel.py`'nin meşru dışa
#: aktarım kodu da `share_3` adlı yerel bir değişken kullanıyor (bkz.
#: `UI/AdminPanel.py:1154`), bunu yasaklamak hem yanlış pozitif üretirdi
#: hem de yanlış sinyal: gerçek tehlike hangi FONKSİYONUN çağrıldığı,
#: değerin hangi İSİMLE tutulduğu değil.
_YASAKLI_TANIMLAYICILAR = frozenset({"recover_master_key", "decode_share"})

#: Mockup'ın ekran başlığı/etiketi — bir kurtarma payını GİRİP kasayı
#: açan bir EKRANIN izi, "gir/giriş" fiilini TAŞIYAN spesifik biçimler.
#: Yalın "Kurtarma parça(sı/sını)" KÖKÜ BİLEREK YOK: `AdminPanel.py`'nin
#: MEŞRU "Kurtarma Parçasını Göster…" düğmesi ve "Kurtarma Parçası"
#: diyalog başlıklarıyla (dışa aktarım tarafı) SEKİZ yerde çakışırdı —
#: ölçüldü (ilk taslakta), bkz. aşağıdaki mevcut-dosya testi.
_YASAKLI_KURTARMA_METINLERI = (
    "Kurtarma parçasıyla",
    "kurtarma parçasıyla",
    "KURTARMA PARÇASIYLA",
    "Kurtarma ile Gir",
    "kurtarma ile gir",
)


def _cagri_ve_ithal_tanimlayicilari(agac: ast.AST) -> list[tuple[str, int]]:
    """`(tanimlayici, satir)` — bir `Call`'ın hedefi ya da bir `import`
    adı olarak geçen tanımlayıcılar. Yalnızca FONKSİYON/İTHAL hedefleri
    — bir değişkenin ADI (`ast.Name` bir `Call` DIŞINDA, ör. `x =
    share_3` atamasının sol tarafı) burada YOK, kasıtlı (bkz. `_YASAKLI_
    TANIMLAYICILAR`'ın gerekçesi)."""
    bulunan: list[tuple[str, int]] = []
    for dugum in ast.walk(agac):
        if isinstance(dugum, ast.Call):
            ad = getattr(dugum.func, "id", getattr(dugum.func, "attr", ""))
            if ad:
                bulunan.append((ad, dugum.lineno))
        elif isinstance(dugum, ast.ImportFrom):
            bulunan += [(a.name, dugum.lineno) for a in dugum.names]
        elif isinstance(dugum, ast.Import):
            bulunan += [(a.name.split(".")[-1], dugum.lineno) for a in dugum.names]
    return bulunan


def _yasakli_cagrilari_bul(kaynak: str, dosya_adi: str) -> list[tuple[str, int]]:
    """Bir dosyada `_YASAKLI_TANIMLAYICILAR`'dan biri ÇAĞRILMIŞ ya da
    İTHAL EDİLMİŞ mi — `(tanımlayıcı, satır)` çiftleri."""
    agac = ast.parse(kaynak, filename=dosya_adi)
    return [
        (ad, satir) for ad, satir in _cagri_ve_ithal_tanimlayicilari(agac)
        if ad in _YASAKLI_TANIMLAYICILAR
    ]


def _yasakli_metinleri_bul(kaynak: str, dosya_adi: str) -> list[tuple[str, int]]:
    """Bir dosyadaki HER string sabitinde (`ast.Constant`, K0-6'nın
    yöntemi — yorumlar hiç AST'ye girmediği için otomatik dışarıda
    kalıyor) `_YASAKLI_KURTARMA_METINLERI`'nden biri geçiyor mu."""
    agac = ast.parse(kaynak, filename=dosya_adi)
    bulunan: list[tuple[str, int]] = []
    for dugum in ast.walk(agac):
        if isinstance(dugum, ast.Constant) and isinstance(dugum.value, str):
            for terim in _YASAKLI_KURTARMA_METINLERI:
                if terim in dugum.value:
                    bulunan.append((terim, dugum.lineno))
    return bulunan


def _bagil_yol(dosya: Path) -> str:
    """Depo köküne göre bağıl yol — `tmp_path` altındaki test amaçlı
    geçici dosyalar depo dışında olduğundan ada düşer (K0-6'nın aynı
    yardımcısı)."""
    try:
        return dosya.relative_to(KOK).as_posix()
    except ValueError:
        return dosya.name


def _tum_cagri_ihlallerini_tara(dosyalar: list[Path]) -> list[str]:
    ihlaller: list[str] = []
    for dosya in dosyalar:
        bagil = _bagil_yol(dosya)
        kaynak = dosya.read_text(encoding="utf-8")
        for ad, satir in _yasakli_cagrilari_bul(kaynak, bagil):
            ihlaller.append(f"{bagil}:{satir} — {ad}")
    return ihlaller


def _tum_metin_ihlallerini_tara(dosyalar: list[Path]) -> list[str]:
    ihlaller: list[str] = []
    for dosya in dosyalar:
        bagil = _bagil_yol(dosya)
        kaynak = dosya.read_text(encoding="utf-8")
        for terim, satir in _yasakli_metinleri_bul(kaynak, bagil):
            ihlaller.append(f"{bagil}:{satir} — {terim!r}")
    return ihlaller


def test_UI_agacinda_kurtarma_yeniden_insa_cagrisi_YOK() -> None:
    """
    ASIL TARAMA (çağrı/ithal) — `UI/` altındaki HER dosya, alt dizinler
    dahil. `recover_master_key`/`decode_share` hiçbir yerden çağrılmıyor
    ya da ithal edilmiyor mu.

    2026-08-26'nın "tek satır bile yok" ölçümü elle yapılmış bir grep'ti
    ve yalnızca `login_dialog.py`'ye bakıyordu — biri bu yeteneği başka
    bir dosyaya (`UI/RecoveryEntryDialog.py` gibi) yazıp `main_window.py`
    ya da `AdminPanel.py`'den bağlasa KAÇARDI. Bu test artık dosyaya-özgü
    DEĞİL.
    """
    ihlaller = _tum_cagri_ihlallerini_tara(_ui_dosyalari())
    assert not ihlaller, (
        "UI/ ağacında kurtarma-yeniden-inşa çağrısı/ithali bulundu — "
        f"B-069 wontfix kararı bozulmuş olabilir: {ihlaller}"
    )


def test_UI_agacinda_kurtarma_giris_metni_YOK() -> None:
    """ASIL TARAMA (metin) — mockup'ın "gir/giriş" etiketini taşıyan
    dize sabitleri `UI/` ağacının hiçbir yerinde yok."""
    ihlaller = _tum_metin_ihlallerini_tara(_ui_dosyalari())
    assert not ihlaller, (
        f"UI/ ağacında kurtarma-girişi etiketi bulundu: {ihlaller} — "
        "B-069 wontfix kararı bozulmuş olabilir"
    )


def test_ui_dizini_taranacak_dosya_iceriyor() -> None:
    """Denetimin KENDİSİ çalışıyor mu — B-024 dersi (bkz. `test_tpm_
    sealing.py`, `test_ui_yasakli_iddia_terimleri.py`'de aynı desen):
    `UI/` boş/bulunamaz olursa yukarıdaki iki test SESSİZCE boş kümeyi
    denetler ve hep geçer."""
    assert len(_ui_dosyalari()) >= 20, (
        "UI/ dizininde beklenenden az .py dosyası bulundu — tarama "
        "hedefi yanlış olabilir"
    )


def test_mevcut_UI_dosyalarindaki_mesru_kullanimlar_YANLIS_POZITIF_URETMIYOR() -> None:
    """
    `UI/AdminSettingsView.py` (eskiden `UI/AdminPanel.py`'nin bir sekmesi,
    kaldırıldı — dışa aktarım düğmesi: `export_recovery_share`,
    `build_export`, `RecoveryShareDialog`, yerel değişken `share_3`,
    "Kurtarma Parçasını Göster…"/"Kurtarma Parçası" metinleri) ve `UI/
    RecoveryShareDialog.py`'nin (kendi sınıf adı, kendi başlığı) GERÇEK
    ve MEŞRU kullanımları hiçbir taramada YAKALANMAMALI.

    Bu test olmadan yukarıdaki iki asıl test yeşil kalabilirdi ÇÜNKÜ
    taranan liste zaten dar tutulmuştu — bu test o darlığın gerçek
    dosyalara karşı da doğru çalıştığını, "yanlışlıkla fazla dar" değil
    "doğru derecede dar" olduğunu kanıtlıyor.
    """
    for ad in ("AdminSettingsView.py", "RecoveryShareDialog.py"):
        dosya = _UI_DIZINI / ad
        kaynak = dosya.read_text(encoding="utf-8")
        assert _yasakli_cagrilari_bul(kaynak, ad) == [], (
            f"{ad}: meşru dışa-aktarım kodu yanlışlıkla yakalandı (çağrı/ithal)"
        )
        assert _yasakli_metinleri_bul(kaynak, ad) == [], (
            f"{ad}: meşru 'Kurtarma Parçası' metni yanlışlıkla yakalandı"
        )


def test_tarayici_enjekte_edilen_yeniden_insa_cagrisini_yakaliyor(tmp_path: Path) -> None:
    """Denetimin kendisi çalışıyor mu (B-024 dersi) — `tmp_path` ile,
    gerçek dosyalara HİÇ dokunmadan: hem bir İTHAL hem bir ÇAĞRI enjekte
    edilip her ikisinin de AYRI AYRI yakalandığı gösteriliyor."""
    gecici = tmp_path / "sahte_dialog.py"
    gecici.write_text(
        "from CORE.vault_manager import recover_master_key\n\n"
        "def f(hwid, pay):\n"
        "    return recover_master_key(hwid, recovery_share=pay, pin=None)\n",
        encoding="utf-8",
    )
    kaynak = gecici.read_text(encoding="utf-8")
    bulunanlar = _yasakli_cagrilari_bul(kaynak, "sahte_dialog.py")
    adlar = {ad for ad, _ in bulunanlar}
    assert "recover_master_key" in adlar, f"ithal/çağrı yakalanmadı: {bulunanlar}"
    assert len(bulunanlar) == 2, f"hem ithal hem çağrı ayrı ayrı yakalanmalıydı: {bulunanlar}"


def test_tarayici_enjekte_edilen_kurtarma_giris_metnini_yakaliyor(tmp_path: Path) -> None:
    gecici = tmp_path / "sahte_dialog2.py"
    gecici.write_text('baslik = "Kurtarma parçasıyla gir"\n', encoding="utf-8")
    ihlaller = _tum_metin_ihlallerini_tara([gecici])
    assert ihlaller, "enjekte edilen kurtarma-girişi metni yakalanmadı"


def test_tarayici_ALT_DIZINDEKI_dosyayi_da_yakaliyor(tmp_path: Path) -> None:
    """K0-6'nın kalıcı regresyon kanıtının aynısı: bir alt dizindeki
    dosya `rglob` ile yakalanıyor mu (`glob("*.py")` yalnızca üst düzeye
    bakardı ve bunu SESSİZCE atlardı)."""
    alt_dizin = tmp_path / "dialogs"
    alt_dizin.mkdir()
    gecici = alt_dizin / "sahte_alt_dialog.py"
    gecici.write_text(
        "from CORE.vault_manager import recover_master_key\n", encoding="utf-8"
    )
    dosyalar = sorted(p for p in tmp_path.rglob("*.py") if "__pycache__" not in p.parts)
    assert dosyalar == [gecici], f"rglob alt dizindeki dosyayı bulamadı: {dosyalar}"
    kaynak = gecici.read_text(encoding="utf-8")
    assert _yasakli_cagrilari_bul(kaynak, "sahte_alt_dialog.py"), (
        "alt dizindeki enjekte edilen ithal yakalanmadı"
    )
