"""
CORE.tpm_sealing — TPM 2.0 mühürlemesi ve TPM'siz makinede düşüş.

Ölçüm ortamı — B-023 tarzı dürüstlük notu
------------------------------------------
Bu paketin TPM yolu GERÇEK DONANIMDA ölçüldü, mock'lanmadı:

    AMD fTPM 2.0, Level 0, Revision 1.59, Firmware 393248.6
    Microsoft Platform Crypto Provider (ncrypt.dll, CNG)
    2026-08-21, Windows 11 Pro 26200

Ölçülen değerler: anahtar üretimi ~1.33 sn (yalnızca ilk kez), mühürleme
~1.2 ms, mühür açma ~38 ms, durum yoklaması ~1.6 ms. Özel anahtar dışa
AKTARILAMIYOR (`NCryptExportKey` → `NTE_NOT_SUPPORTED`, 0x8009000A).

ÖLÇÜLMEYEN ve bu paketin kapsamadığı şey — açıkça yazılıyor:

  · **CI'da TPM yolu HİÇ ÇALIŞMIYOR.** CI'ın koşucuları Linux ve Windows;
    ikisinde de TPM sağlayıcısı yok. `gercek_tpm` isteyen testler orada
    ATLANIYOR. Yani bu yolun yeşil kalması TEK BİR geliştirme makinesinin
    ölçümüne dayanıyor — B-023'ün ClamAV için söylediğinin aynısı.
  · **Yalnızca tek bir TPM üreticisi görüldü** (AMD fTPM). Intel PTT,
    ayrık TPM yongaları ve sanal TPM'ler (Hyper-V vTPM) DENENMEDİ.
    OAEP'in reddedilmesi bu sağlayıcıda ölçüldü; başka bir üreticide
    farklı olabilir — kod zaten PKCS#1'e sabitlenmiş durumda, yani
    davranış değişmez, ama "her TPM böyle" DENMEDİ.
  · **TPM temizleme senaryosu ölçülmedi.** "TPM silinirse mühür açılmaz"
    iddiası mantıksal; BIOS'tan Clear TPM yapıp doğrulanmadı, çünkü o
    işlem bu makinedeki BitLocker/Windows Hello kayıtlarını da yok eder.
    Yerine, aynı hata YOLU testte üretiliyor (mühürlü kayıt + TPM
    kapalı) ve istisnanın gerçekten fırladığı ölçülüyor.

Varsayılan olarak TPM KAPALI
-----------------------------
`conftest.py::tpm_kapali` autouse ve tüm paket için mühürlemeyi kapatıyor.
Gerekçesi orada yazılı ve kısaca: TPM'li makinede yeşil, TPM'siz makinede
kırmızı olan bir test paketi işe yaramaz.
"""
from __future__ import annotations

import ast
import base64
import sys
from pathlib import Path

import keyring
import pytest

from CORE import secret_store, tpm_sealing, vault_manager
from CORE.secret_store import KeyringUnavailableError
from CORE.tpm_sealing import (
    ETIKET,
    EYLEM_DUSUS,
    EYLEM_ETKIN,
    EYLEM_YENIDEN_MUHUR,
    EYLEM_YENIDEN_MUHUR_BASARISIZ,
    TpmDurum,
    TpmSealingError,
    belki_coz,
    belki_muhurle,
    durum,
    muhurlu_mu,
    oturum_raporu,
)
from CORE.vault_manager import create_vault, open_vault

KOK = Path(__file__).resolve().parent.parent

_BAGLAM = "share_2:TPM-TEST-HWID"


# ══════════════════════════════════════════════════════════════════════════════
# 0. Denetimin KENDİSİ çalışıyor mu
# ══════════════════════════════════════════════════════════════════════════════
#
# Bu blok olmasaydı aşağıdaki her şey sessizce geçebilirdi: `tpm_kapali`
# bozulursa "düşüş" testleri aslında TPM yolunu ölçer, `gercek_tpm`
# bozulursa TPM testleri her makinede atlanır ve kimse fark etmez.


def test_varsayilan_TPM_KAPALI() -> None:
    """Paketin varsayılanı sabit olmalı — makineye göre değişmemeli."""
    assert not durum().kullanilabilir, (
        "conftest'teki `tpm_kapali` çalışmıyor: bu paket TPM'li makinede "
        "TPM'siz makineden FARKLI davranır."
    )


def test_gercek_tpm_fixture_gercekten_TPM_aciyor(gercek_tpm: TpmDurum) -> None:
    """
    Atlanmıyorsa gerçekten donanım konuşuyor olmalı.

    `platform` dizesi TPM'in kendi bildirdiği değer; sabit bir metin
    değil, sağlayıcıdan `PCP_PLATFORM_TYPE` ile okunuyor.
    """
    assert gercek_tpm.kullanilabilir
    assert durum().kullanilabilir, "fixture durumu global olarak açmamış"
    assert "TPM" in gercek_tpm.platform.upper(), (
        f"Sağlayıcı TPM sürümü bildirmedi: {gercek_tpm.platform!r}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. Durum tespiti
# ══════════════════════════════════════════════════════════════════════════════


def test_durum_onbellekli() -> None:
    """
    Her sır yazımında sağlayıcıyı yoklamak yavaş OLMASININ ötesinde
    TEHLİKELİ: aynı oturumda cevap değişirse bazı kayıtlar mühürlü
    bazıları mühürsüz kalır ve bu fark hiçbir yerde görünmez.
    """
    assert durum() is durum()


def test_ozet_iki_durumda_da_farkli_ve_okunur() -> None:
    acik = TpmDurum(True, "", "TPM-Version:2.0")
    kapali = TpmDurum(False, "bu makinede yok")
    assert acik.ozet() != kapali.ozet()
    assert "ETKİN" in acik.ozet()
    # Düşüş özeti kullanıcıya NEREYE düşüldüğünü söylemeli — "TPM yok"
    # tek başına ne olduğunu anlatmıyor.
    assert "anahtar kasas" in kapali.ozet().lower()
    assert "bu makinede yok" in kapali.ozet()


def test_windows_disinda_kullanilamiyor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tpm_sealing.sys, "platform", "linux")
    tpm_sealing.sifirla_onbellek()
    try:
        d = durum()
        assert not d.kullanilabilir
        assert "linux" in d.neden
    finally:
        tpm_sealing.sifirla_onbellek()


# ══════════════════════════════════════════════════════════════════════════════
# 2. GERÇEK TPM ile mühürleme
# ══════════════════════════════════════════════════════════════════════════════


def test_muhur_gidip_geliyor(gercek_tpm: TpmDurum) -> None:
    blob = belki_muhurle("gizli deger", baglam=_BAGLAM)
    assert muhurlu_mu(blob)
    assert belki_coz(blob, baglam=_BAGLAM) == "gizli deger"


def test_muhurlu_blob_sirri_ICERMIYOR(gercek_tpm: TpmDurum) -> None:
    """
    Asıl iddia bu: kasa kaydını kopyalayan biri (M2) sırrı GÖREMEMELİ.
    """
    sir = "cok-ozel-share-2-degeri"
    blob = belki_muhurle(sir, baglam=_BAGLAM)
    assert sir not in blob
    assert sir.encode() not in base64.b64decode(blob[len(ETIKET) + 1:])


@pytest.mark.parametrize(
    "deger", ["", "x", "ç" * 200, "2:" + "c3" * 33, "satır\nsonu\tvar"]
)
def test_cesitli_degerler(gercek_tpm: TpmDurum, deger: str) -> None:
    """Boş dize, unicode, gerçek share_2 biçimi, kontrol karakterleri."""
    assert belki_coz(belki_muhurle(deger, baglam=_BAGLAM), baglam=_BAGLAM) == deger


def _parcala(blob: str) -> tuple[bytes, bytes, bytes, bytes]:
    """`TPM1:` paketini `(sarmal, nonce, etiket, govde)` olarak ayırır."""
    ham = base64.b64decode(blob[len(ETIKET) + 1:])
    n = int.from_bytes(ham[:2], "big")
    return ham[2:2 + n], ham[2 + n:14 + n], ham[14 + n:30 + n], ham[30 + n:]


def test_ayni_deger_HER_SEFERINDE_farkli_blob(gercek_tpm: TpmDurum) -> None:
    """
    Taze DEK + taze nonce, ve İKİSİ DE ayrı ayrı denetleniyor.

    Blob'un tamamını karşılaştırmak YETMİYOR — mutasyonla ölçüldü: DEK
    sabitlense bile taze nonce blob'u değiştiriyor, nonce sabitlense bile
    taze DEK sarmalı değiştiriyor. Yani "bloblar farklı" iddiası iki
    mutasyonu da hayatta bıraktı. Tehlike ikisinin BİRLİKTE sabitlenmesi:
    aynı (anahtar, nonce) çifti GCM'de anahtar akışını tekrar kullanır ve
    şifrelemeyi tamamen çökertir. O yüzden her iki taze değer AYRI
    ölçülüyor.
    """
    a = belki_muhurle("ayni", baglam=_BAGLAM)
    b = belki_muhurle("ayni", baglam=_BAGLAM)
    assert a != b

    sarmal_a, nonce_a, _, govde_a = _parcala(a)
    sarmal_b, nonce_b, _, govde_b = _parcala(b)
    assert nonce_a != nonce_b, "nonce sabit — GCM'de anahtar akışı tekrarı riski"
    assert sarmal_a != sarmal_b, "DEK sabit — aynı sır aynı sarmalı üretiyor"
    # Aynı düz metin, farklı gövde: (DEK, nonce) çifti gerçekten taze.
    assert govde_a != govde_b, "aynı düz metin aynı şifreli gövdeyi verdi"


def test_baska_kaydin_muhru_kullanilamiyor(gercek_tpm: TpmDurum) -> None:
    """
    GCM'in AAD'ı kayıt adı: `totp_secret` blob'u `share_2:<hwid>` yerine
    konamıyor. Aksi hâlde kasaya yazabilen biri iki kaydı takas ederdi.
    """
    blob = belki_muhurle("totp-sirri", baglam="totp_secret")
    with pytest.raises(TpmSealingError, match="GCM"):
        belki_coz(blob, baglam=_BAGLAM)


def _bit_cevir(blob: str, indeks: int) -> str:
    ham = bytearray(base64.b64decode(blob[len(ETIKET) + 1:]))
    ham[indeks] ^= 0x01
    return blob[: len(ETIKET) + 1] + base64.b64encode(bytes(ham)).decode("ascii")


def test_kurcalanmis_govde_reddediliyor(gercek_tpm: TpmDurum) -> None:
    blob = belki_muhurle("dokunulmasin", baglam=_BAGLAM)
    with pytest.raises(TpmSealingError):
        belki_coz(_bit_cevir(blob, -1), baglam=_BAGLAM)


def test_kurcalanmis_DEK_sarmali_reddediliyor(gercek_tpm: TpmDurum) -> None:
    """
    RSA-PKCS#1 tek başına bütünlük vermiyor — bozulmuş bir sarmal ya
    CNG'de patlıyor ya da YANLIŞ bir DEK üretiyor. İkinci durumda
    yakalayan şey GCM etiketi. Hibrit yapının varlık sebebi bu.
    """
    blob = belki_muhurle("dokunulmasin", baglam=_BAGLAM)
    with pytest.raises(TpmSealingError):
        belki_coz(_bit_cevir(blob, 10), baglam=_BAGLAM)


@pytest.mark.parametrize("bozuk", ["TPM1:", "TPM1:!!!!", "TPM1:AAAA"])
def test_bozuk_paketler_temiz_hata_veriyor(gercek_tpm: TpmDurum, bozuk: str) -> None:
    """Kısa/base64 olmayan paket, izleme değil anlaşılır istisna vermeli."""
    with pytest.raises(TpmSealingError):
        belki_coz(bozuk, baglam=_BAGLAM)


# ══════════════════════════════════════════════════════════════════════════════
# 3. Düşüş yolu — GERÇEK keyring arka ucu, mühür yok
# ══════════════════════════════════════════════════════════════════════════════
#
# `conftest.InMemoryKeyring` mock DEĞİL, gerçek bir `KeyringBackend`
# implementasyonu: secret_store hiç değişmeden normal keyring API'siyle
# ona konuşuyor.


def test_dususte_deger_DEGISMEDEN_geciyor() -> None:
    assert belki_muhurle("duz-deger", baglam=_BAGLAM) == "duz-deger"


def test_dususte_kasaya_MUHURSUZ_yaziliyor(fake_keyring) -> None:  # type: ignore[no-untyped-def]
    secret_store.store("dusus-kaydi", "acik-deger")
    ham = fake_keyring.store[(secret_store.SERVICE, "dusus-kaydi")]
    assert ham == "acik-deger"
    assert not muhurlu_mu(ham)


def test_dusus_LOG_A_yaziliyor(caplog: pytest.LogCaptureFixture) -> None:
    """
    Sessiz düşüş yasak (B-025). Bu, kullanıcıya ulaşan üç kanalın
    (denetim kaydı, --selftest, Hakkında) altındaki dördüncü kayıt.
    """
    with caplog.at_level("WARNING", logger="hycleus.tpm"):
        belki_muhurle("x", baglam=_BAGLAM)
    assert any("tpm_muhur_atlandi" in r.message for r in caplog.records), (
        f"Düşüş uyarısı yazılmadı: {[r.message for r in caplog.records]}"
    )


def test_onekle_baslayan_deger_MUHURSUZ_yazilamiyor() -> None:
    """
    Mühürsüz yazılan bir değer önekle başlarsa bir sonraki okumada
    mühürlü sanılır ve açılamaz. Bugünkü sırların hiçbiri böyle
    başlamıyor; sessiz bozulma yerine burada duruluyor.
    """
    with pytest.raises(TpmSealingError, match=ETIKET):
        belki_muhurle(f"{ETIKET}:sahte", baglam=_BAGLAM)


# ══════════════════════════════════════════════════════════════════════════════
# 4. Karışık kayıtlar — geriye dönük uyumluluk ve KAYIP tespiti
# ══════════════════════════════════════════════════════════════════════════════


def test_TPM_li_makinede_ESKI_muhursuz_kayit_okunuyor(gercek_tpm: TpmDurum) -> None:
    """
    Mühürleme öncesinde yazılmış kayıtlar çalışmaya devam etmeli; aksi
    hâlde bu özellik mevcut kurulumları kilitlerdi.
    """
    keyring.set_password(secret_store.SERVICE, "eski-kayit", "muhursuz-eski")
    assert secret_store.load("eski-kayit") == "muhursuz-eski"


def test_muhurlu_kayit_TPM_yokken_None_DONMUYOR(gercek_tpm: TpmDurum) -> None:
    """
    EN KRİTİK TEST. TPM temizlenmiş bir makinenin durumu üretiliyor:
    kasada mühürlü kayıt var, TPM yok.

    None dönmek "kayıt yok" diye okunur ve çağıran tarafı sırrı YENİDEN
    KURMAYA iter — yani hâlâ kurtarılabilir olan bir kasayı kalıcı
    olarak kaybettirir. İstisna fırlamalı.
    """
    secret_store.store("muhurlu-kayit", "kiymetli")
    ham = keyring.get_password(secret_store.SERVICE, "muhurlu-kayit")
    assert ham is not None and muhurlu_mu(ham)

    tpm_sealing.zorla_durum(TpmDurum(False, "test: TPM temizlendi"))
    with pytest.raises(KeyringUnavailableError) as ex:
        secret_store.load("muhurlu-kayit")

    mesaj = str(ex.value)
    assert "mühürlü" in mesaj.lower()
    # Kullanıcı ne yapacağını buradan okuyabilmeli.
    assert "kurtarma" in str(ex.value.__cause__).lower()


def test_muhurleme_patlarsa_MUHURSUZ_yazmaya_dusulmuyor(
    monkeypatch: pytest.MonkeyPatch, fake_keyring,  # type: ignore[no-untyped-def]
) -> None:
    """
    TPM kullanılabilir görünüp mühürleme patlarsa, sessizce mühürsüz
    yazmak B-025'in tam olarak tekrarı olurdu: katman devre dışı, belge
    hâlâ var diyor. Yazma BAŞARISIZ olmalı ve kasada iz kalmamalı.
    """
    tpm_sealing.zorla_durum(TpmDurum(True, "", "sahte-TPM"))
    monkeypatch.setattr(
        tpm_sealing, "muhurle",
        lambda *a, **k: (_ for _ in ()).throw(TpmSealingError("TPM koptu")),
    )
    with pytest.raises(KeyringUnavailableError, match="DÜŞÜLMEDİ"):
        secret_store.store("patlayan", "deger")
    assert (secret_store.SERVICE, "patlayan") not in fake_keyring.store


# ══════════════════════════════════════════════════════════════════════════════
# 5. Kasa AÇILIP KAPANIYOR mu — iki senaryoda da
# ══════════════════════════════════════════════════════════════════════════════


def _kasa_turu(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hwid: str) -> None:
    """Gerçek kasa kur, aç, master key'i karşılaştır."""
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    create_vault(hwid, "123456", "Yönetici")
    rol, anahtar = open_vault(hwid, "123456")
    assert rol == "Yönetici"
    assert len(anahtar) == 32
    # İkinci açılış aynı anahtarı vermeli — mühür her seferinde farklı
    # blob üretiyor ama AÇILAN değer aynı.
    _, anahtar2 = open_vault(hwid, "123456")
    assert anahtar2 == anahtar


def test_kasa_TPM_YOKKEN_acilip_kapaniyor(
    db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,  # type: ignore[no-untyped-def]
) -> None:
    assert not durum().kullanilabilir
    _kasa_turu(tmp_path, monkeypatch, "TPM-YOK-HWID")


def test_kasa_TPM_VARKEN_acilip_kapaniyor(
    gercek_tpm: TpmDurum, db, tmp_path: Path,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Saf ekleme iddiasının asıl sınavı: mühürleme açıkken kasa akışı
    DEĞİŞMEDEN çalışmalı.
    """
    _kasa_turu(tmp_path, monkeypatch, "TPM-VAR-HWID")
    ham = keyring.get_password(secret_store.SERVICE, "share_2:TPM-VAR-HWID")
    assert ham is not None and muhurlu_mu(ham), "share_2 mühürlenmemiş"


def test_TPM_li_kasa_TPM_gidince_ACILMIYOR(
    gercek_tpm: TpmDurum, db, tmp_path: Path,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Mühürlemenin bedeli: TPM giderse kasa açılmaz. Bu bir hata değil,
    özelliğin tanımı — ve sessiz kalmaması şart (çıkış yolu kurtarma
    parçası, SECURITY.md §4.4).
    """
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    create_vault("TPM-GIDEN-HWID", "123456", "Yönetici")

    tpm_sealing.zorla_durum(TpmDurum(False, "test: TPM temizlendi"))
    with pytest.raises(KeyringUnavailableError, match="AÇILAMADI"):
        open_vault("TPM-GIDEN-HWID", "123456")


# ══════════════════════════════════════════════════════════════════════════════
# 5b. Re-seal — mühürsüz ESKİ kurulum, TPM sonradan geldi
# ══════════════════════════════════════════════════════════════════════════════
#
# `store()` yalnızca YAZIMDA mühürlüyor ve share_2 write-once bir sır
# (_save_usb_token, yalnızca create_vault() içinde). TPM ilk kayıt anında
# yoksa ve SONRA gelirse, "bir sonraki yazım" hiç gelmeyebilir — kayıt
# kasada sonsuza dek mühürsüz kalırdı. `CORE/secret_store.py::load()`
# bunu OKUMA sırasında fırsatçı bir yeniden mühürleme ile kapatıyor.
#
# Aşağıdaki ilk test GERÇEK donanıma dokunmuyor: ham `muhurle`/`coz`'u
# sahte ama iç-tutarlı bir şemayla değiştiriyor. Asıl sınanan şey belirli
# bir TPM sağlayıcısının davranışı değil, `secret_store.load()`'un
# ORKESTRASYONU — ne zaman yeniden yazmaya karar verdiği, kaç kez yazdığı,
# denetim kaydına ne düştüğü. Bunun ardından `gercek_tpm` fixture'ıyla
# aynı iddiayı GERÇEK donanımda da doğrulayan ikinci, daha dar bir test var.


def _sahte_muhurle(deger: str, *, baglam: str) -> str:
    """Gerçek CNG'ye dokunmadan, `muhurlu_mu()`'nun tanıyacağı bir blob üretir."""
    return f"{ETIKET}:SAHTE|{baglam}|{deger}"


def _sahte_coz(saklanan: str, *, baglam: str) -> str:
    govde = saklanan[len(ETIKET) + 1:]  # "SAHTE|<baglam>|<deger>"
    if not govde.startswith("SAHTE|"):
        raise TpmSealingError("sahte mühür tanınmadı — test kurulumu bozuk")
    _, kayitli_baglam, deger = govde.split("|", 2)
    if kayitli_baglam != baglam:
        raise TpmSealingError(f"bağlam uyuşmuyor (sahte TPM): {kayitli_baglam!r} != {baglam!r}")
    return deger


def test_ESKI_kurulum_ILK_ACILISTA_otomatik_yeniden_muhurleniyor(
    monkeypatch: pytest.MonkeyPatch, db, tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    """
    ASIL DENETİM: TPM mühürlemesi bu makineye eklenmeden ÖNCE kaydolmuş
    bir kullanıcıyı simüle ediyor (share_2 kasada MÜHÜRSÜZ). TPM sonradan
    gelince, kullanıcı hiçbir şey yapmadan, İLK açılışta (open_vault)
    kayıt otomatik olarak yeniden mühürlenmeli — "bir sonraki yazımı"
    beklemek share_2 için hiç gerçekleşmeyebilir (bkz. secret_store.py
    docstring'i "Re-seal").
    """
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")

    hwid = "TPM-RESEAL-ESKI-HWID"
    username = secret_store.share_2_username(hwid)

    # ── ESKİ KURULUM: TPM yokken kaydol → share_2 mühürsüz yazılır ──────────
    assert not durum().kullanilabilir  # ön koşul: tpm_kapali (autouse)
    create_vault(hwid, "123456", "Yönetici")
    ham_once = keyring.get_password(secret_store.SERVICE, username)
    assert ham_once is not None and not muhurlu_mu(ham_once), (
        "ön koşul: kayıt mühürsüz başlamalı"
    )

    # ── TPM SONRADAN GELDİ (yeni makine, sürücü kuruldu, vb.) ───────────────
    tpm_sealing.zorla_durum(TpmDurum(True, "", "sahte-TPM"))
    monkeypatch.setattr(tpm_sealing, "muhurle", _sahte_muhurle)
    monkeypatch.setattr(tpm_sealing, "coz", _sahte_coz)

    # ── İLK AÇILIŞ: re-seal başka hiçbir şey yapılmadan tetiklenmeli ───────
    rol, anahtar = open_vault(hwid, "123456")
    assert rol == "Yönetici"

    ham_sonra = keyring.get_password(secret_store.SERVICE, username)
    assert ham_sonra is not None and muhurlu_mu(ham_sonra), (
        "ilk açılıştan sonra share_2 HÂLÂ mühürsüz — re-seal tetiklenmedi"
    )
    assert ham_sonra != ham_once, "kasadaki ham kayıt değişmemiş"

    # ── Yeni mühür GERÇEKTEN doğru sırrı taşıyor mu (yalnızca prefix değil) ─
    _, anahtar2 = open_vault(hwid, "123456")
    assert anahtar2 == anahtar, "yeniden mühürlenmiş share_2 farklı bir anahtar veriyor"

    # ── Görünürlük: TEK bir tamamlanma kaydı (ikinci open_vault tekrar
    # yazmamalı — kayıt artık mühürlü, muhurlu_mu() ikinci turda True) ──────
    kayitlar = db.fetchall(
        "SELECT detail FROM audit_log WHERE action = ?", (EYLEM_YENIDEN_MUHUR,)
    )
    assert len(kayitlar) == 1, "re-seal denetim kaydına düşmedi ya da fazla düştü"
    assert username in kayitlar[0]["detail"]

    basarisiz = db.fetchall(
        "SELECT detail FROM audit_log WHERE action = ?", (EYLEM_YENIDEN_MUHUR_BASARISIZ,)
    )
    assert basarisiz == []


def test_reseal_basarisiz_olursa_OKUMA_YINE_DE_calisir(
    monkeypatch: pytest.MonkeyPatch, db,  # type: ignore[no-untyped-def]
) -> None:
    """
    Yeniden mühürleme denemesi patlarsa (TPM hatası) OKUMA engellenmemeli
    — zaten başarıyla okunmuş bir değeri, arkadaki iyileştirme denemesi
    yüzünden vermemek yeni bir kilitlenme yüzeyi açardı. Ama "sessiz
    atlama" da yok: başarısızlık denetim kaydına düşüyor.
    """
    keyring.set_password(secret_store.SERVICE, "eski-kayit-patlayan", "kiymetli-deger")

    tpm_sealing.zorla_durum(TpmDurum(True, "", "sahte-TPM"))
    monkeypatch.setattr(
        tpm_sealing, "muhurle",
        lambda *a, **k: (_ for _ in ()).throw(TpmSealingError("TPM koptu")),
    )

    assert secret_store.load("eski-kayit-patlayan") == "kiymetli-deger", (
        "re-seal denemesi patladığında OKUMA da başarısız oldu"
    )
    ham = keyring.get_password(secret_store.SERVICE, "eski-kayit-patlayan")
    assert ham == "kiymetli-deger", "kayıt hâlâ mühürsüz kalmalıydı (yazma denenmemiş sayılır)"

    kayitlar = db.fetchall(
        "SELECT detail FROM audit_log WHERE action = ?", (EYLEM_YENIDEN_MUHUR_BASARISIZ,)
    )
    assert len(kayitlar) == 1
    assert "eski-kayit-patlayan" in kayitlar[0]["detail"]


def test_gercek_TPM_ile_ESKI_kayit_ilk_okumada_yeniden_muhurleniyor(
    gercek_tpm: TpmDurum,
) -> None:
    """
    `test_TPM_li_makinede_ESKI_muhursuz_kayit_okunuyor`'un devamı: GERÇEK
    donanımla, okumanın çalışması YETMİYOR — kayıt bu okumadan SONRA
    gerçekten mühürlü olmalı, aksi hâlde "ilk açılışta zorunlu re-seal"
    iddiası yalnızca sahte-TPM testinde doğru olur.
    """
    keyring.set_password(secret_store.SERVICE, "eski-share2-gercek-tpm", "2:eskiyedegim")

    assert secret_store.load("eski-share2-gercek-tpm") == "2:eskiyedegim"

    ham = keyring.get_password(secret_store.SERVICE, "eski-share2-gercek-tpm")
    assert ham is not None and muhurlu_mu(ham), (
        "gerçek TPM kullanılabilirken bile ilk okuma kaydı yeniden mühürlemedi"
    )


def test_share_2_DISI_cagri_yerinde_reseal_TETIKLENMIYOR_TAZE_yazimda(
    monkeypatch: pytest.MonkeyPatch, db,  # type: ignore[no-untyped-def]
) -> None:
    """
    `store()`'un share_2 DIŞINDAKİ tek çağıranı TOTP sırrı
    (`store_totp_secret_for_hwid`, `store_totp_secret`) — grep ile
    doğrulandı, `CORE/secret_migration.py` ve `CORE/vault_manager.py`
    dışında üçüncü bir çağıran yok.

    TAZE bir TOTP yazımı (kasada daha önce hiç kayıt yokken) TPM
    kullanılabiliyorsa `store()`'un KENDİ `belki_muhurle()` çağrısıyla
    ZATEN mühürlü yazılır — `load()`'un round-trip doğrulaması bu yüzden
    hiçbir reseal tetiklememeli. Tetiklerse, "taze kayıt" ile "reseal"
    audit zincirinde ayırt edilemez hâle gelirdi.
    """
    tpm_sealing.zorla_durum(TpmDurum(True, "", "sahte-TPM"))
    monkeypatch.setattr(tpm_sealing, "muhurle", _sahte_muhurle)
    monkeypatch.setattr(tpm_sealing, "coz", _sahte_coz)

    secret_store.store_totp_secret_for_hwid("TOTP-TAZE-HWID", "A" * 32)

    ham = keyring.get_password(
        secret_store.SERVICE, secret_store.totp_username("TOTP-TAZE-HWID")
    )
    assert ham is not None and muhurlu_mu(ham), "taze TOTP yazımı mühürlenmedi"

    for eylem in (EYLEM_YENIDEN_MUHUR, EYLEM_YENIDEN_MUHUR_BASARISIZ):
        kayitlar = db.fetchall("SELECT detail FROM audit_log WHERE action = ?", (eylem,))
        assert kayitlar == [], (
            f"taze TOTP kaydı '{eylem}' denetim kaydı düşürdü — reseal, taze "
            "yazımın kendi round-trip doğrulaması tarafından yanlışlıkla "
            "tetiklendi"
        )


def test_reseal_ile_TAZE_kayit_denetim_zincirinde_AYIRT_EDILEBILIYOR(
    monkeypatch: pytest.MonkeyPatch, db, tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    """
    `store()`'un KENDİSİ hiçbir audit etiketi YAZMIYOR (grep ile
    doğrulandı — `CORE/secret_store.py::store()` gövdesinde `DBManager()`
    çağrısı yok) — yani "yeni kayıt" için jenerik bir etiket YOK ve
    `tpm_reseal_completed`/`tpm_reseal_failed` ile çakışabilecek bir şey
    de yok. Bu testte iki senaryoyu ARKA ARKAYA çalıştırıp ayrımı somut
    şekilde kanıtlıyoruz: taze kayıt SIFIR reseal-etiketi bırakıyor, aynı
    kullanıcı adının ESKİ/mühürsüz bir kopyası okunduğunda TAM OLARAK BİR
    `tpm_reseal_completed` bırakıyor — ikisi asla aynı olayla karışmıyor.
    """
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")

    # ── 1. TAZE kayıt: TPM YOKKEN (varsayılan, tpm_kapali autouse) ──────────
    assert not durum().kullanilabilir
    create_vault("AYIRT-TAZE-HWID", "123456", "Yönetici")

    kayitlar = db.fetchall(
        "SELECT detail FROM audit_log WHERE action IN (?, ?)",
        (EYLEM_YENIDEN_MUHUR, EYLEM_YENIDEN_MUHUR_BASARISIZ),
    )
    assert kayitlar == [], "TPM'siz taze kayıt reseal etiketi bırakmamalı"

    # ── 2. TPM SONRADAN geldi, İLK açılış re-seal'i tetikliyor ──────────────
    tpm_sealing.zorla_durum(TpmDurum(True, "", "sahte-TPM"))
    monkeypatch.setattr(tpm_sealing, "muhurle", _sahte_muhurle)
    monkeypatch.setattr(tpm_sealing, "coz", _sahte_coz)
    open_vault("AYIRT-TAZE-HWID", "123456")

    tamamlanan = db.fetchall(
        "SELECT detail FROM audit_log WHERE action = ?", (EYLEM_YENIDEN_MUHUR,)
    )
    assert len(tamamlanan) == 1, (
        "gerçek bir reseal olayı tam olarak bir tpm_reseal_completed satırı "
        "bırakmalı — taze kayıt (0 satır) ile karışmıyor"
    )
    assert "AYIRT-TAZE-HWID" in tamamlanan[0]["detail"]


def test_reseal_yazimi_KESILIRSE_ESKI_kayit_hala_okunabilir(
    monkeypatch: pytest.MonkeyPatch, db, fake_keyring,  # type: ignore[no-untyped-def]
) -> None:
    """
    ATOMİKLİK: `_reseal_firsatci()` tek bir `set_password()` çağrısı
    yapıyor — önce ESKİ kaydı SİLİP sonra YENİYİ yazan bir "create-then-
    delete" adımı YOK (koda bakarak: `CORE/secret_store.py::
    _reseal_firsatci` içinde `delete_password`/`erase` çağrısı yok). Bu
    testte `set_password`'ün KENDİSİ kesintiye uğruyor (güç kaybı/çökme
    benzetimi) — sonrasında ESKİ, mühürsüz kayıt HÂLÂ tam ve okunabilir
    olmalı: K0-3'ün "ikisi de kaybolan/bozulan bir pencere olmamalı"
    ilkesi. Kayıp da yok, bozulma da yok — yalnızca reseal bir dahaki
    okumaya kalıyor.

    `fake_keyring.store` sözlüğüne DOĞRUDAN bakıyoruz (monkeypatch'lenmiş
    `keyring.set_password`'ü geri almaya gerek kalmadan) — bellek içi
    arka ucun kendi durumu, kesintiden etkilenmemiş hâliyle.
    """
    keyring.set_password(secret_store.SERVICE, "kesinti-testi", "eski-deger")

    tpm_sealing.zorla_durum(TpmDurum(True, "", "sahte-TPM"))
    monkeypatch.setattr(tpm_sealing, "muhurle", _sahte_muhurle)
    monkeypatch.setattr(tpm_sealing, "coz", _sahte_coz)

    def _kesilen_yazma(*a, **k):
        raise RuntimeError("simüle edilmiş güç kaybı — set_password ortasında")

    monkeypatch.setattr(keyring, "set_password", _kesilen_yazma)

    # OKUMA yine de başarılı dönmeli — kesinti reseal'i etkiler, okumayı değil.
    assert secret_store.load("kesinti-testi") == "eski-deger"

    # Kesinti keyring.set_password'ü monkeypatch'lediği için kasaya HİÇ
    # dokunulmadı: eski kayıt DEĞİŞMEDEN, olduğu gibi duruyor.
    ham = fake_keyring.store[(secret_store.SERVICE, "kesinti-testi")]
    assert ham == "eski-deger", (
        "kesintiye uğrayan reseal, eski kaydı bozmuş ya da silmiş olmamalı"
    )
    assert not muhurlu_mu(ham), (
        "kayıt hâlâ mühürsüz olmalı — yarım kalmış bir mühür değil, TAMAMEN "
        "eski hâliyle korunmuş olmalı"
    )

    basarisiz = db.fetchall(
        "SELECT detail FROM audit_log WHERE action = ?", (EYLEM_YENIDEN_MUHUR_BASARISIZ,)
    )
    assert len(basarisiz) == 1


def test_windows_golge_kopya_gercek_kasada_TEMIZLENIYOR(
    use_keyring_backend, db,  # type: ignore[no-untyped-def]
) -> None:
    """
    GERÇEK Windows Credential Manager'da (InMemoryKeyring DEĞİL) ölçüldü:
    `keyring` kütüphanesinin Windows arka ucu, aynı serviste birden fazla
    kullanıcı adını "compound target" (`{username}@{service}`) hilesiyle
    simüle ediyor — `set_password()` YENİ değeri her zaman "çıplak" (bare)
    hedefe yazıyor ve yalnızca ORADA BULDUĞU FARKLI bir kullanıcıyı
    compound'a taşıyor, kendi eski compound kopyasına HİÇ dokunmuyor.
    Doğrudan bir betikle doğrulandı: iki kullanıcı adını art arda yazıp
    üçüncüsünü ilk kullanıcıya tekrar yazdırınca, ilk kullanıcının ESKİ
    değeri `{username}@{service}` hedefinde SESSİZCE hayatta kalıyordu.

    `CORE/secret_store.py::_windows_golge_sil()` bunu kapatıyor — bu test
    GERÇEK backend'le fiilen temizlendiğini kanıtlıyor (InMemoryKeyring bu
    hatayı hiç üretmediği için diğer testler bunu YAKALAYAMAZ).
    """
    if sys.platform != "win32":
        pytest.skip("Windows Credential Manager'a özgü davranış")
    try:
        import pywintypes
        import win32cred
        from keyring.backends.Windows import WinVaultKeyring
    except ImportError:
        pytest.skip("pywin32 kurulu değil")

    use_keyring_backend(WinVaultKeyring())

    service = secret_store.SERVICE
    u_eski, u_yeni = "golge-test-eski", "golge-test-yeni"
    compound_eski = f"{u_eski}@{service}"

    def _sil(target: str) -> None:
        try:
            win32cred.CredDelete(Type=win32cred.CRED_TYPE_GENERIC, TargetName=target)
        except pywintypes.error:
            pass

    for hedef in (u_eski, u_yeni, compound_eski, f"{u_yeni}@{service}", service):
        _sil(hedef)  # önceki (yarım kalmış) bir koşudan kalıntı olabilir

    try:
        # 1) u_eski bare'i alır. 2) u_yeni yazılır — u_eski compound'a taşınır.
        secret_store.store(u_eski, "eski-deger")
        secret_store.store(u_yeni, "yeni-deger")

        # ÖN KOŞUL: u_eski'nin gölge kopyası GERÇEKTEN orada.
        assert win32cred.CredRead(Type=win32cred.CRED_TYPE_GENERIC, TargetName=compound_eski)

        # 3) u_eski TEKRAR yazılır (reseal'in de kullandığı aynı üzerine-
        #    yazma deseni) — bu, kendi eski gölge kopyasını temizlemeli.
        secret_store.store(u_eski, "guncel-deger")

        with pytest.raises(pywintypes.error) as ex:
            win32cred.CredRead(Type=win32cred.CRED_TYPE_GENERIC, TargetName=compound_eski)
        assert ex.value.winerror == 1168, "gölge kopya hâlâ okunabiliyor — temizlik çalışmadı"

        assert secret_store.load(u_eski) == "guncel-deger", (
            "temizlik yeni değeri de silmiş olabilir"
        )

        kayitlar = db.fetchall(
            "SELECT detail FROM audit_log WHERE action = ?",
            (secret_store.EYLEM_GOLGE_SILINDI,),
        )
        assert any(f"username={u_eski}" in k["detail"] for k in kayitlar)
    finally:
        for hedef in (u_eski, u_yeni, compound_eski, f"{u_yeni}@{service}", service):
            _sil(hedef)


def test_ensure_available_YAN_ETKI_OLARAK_eski_golgeyi_iyilestiriyor(
    use_keyring_backend,  # type: ignore[no-untyped-def]
) -> None:
    """
    Bu makinenin GERÇEK Credential Manager'ı `_windows_golge_sil()'den
    ÖNCEki yazımlar için tarandığında (BACKLOG B-070'in 2026-08-28 devam
    notu) hiçbir gölge bulunamadı — SECURITY.md §4.13'ün açıkladığı, bu
    testin kanıtladığı nedenle: `main.py` her açılışta `ensure_available()`'ı
    o oturumdaki HERHANGİ bir `store()`'dan ÖNCE çağırıyor, ve onun sonda
    yazımı çıplak yuvayı işgal edeni compound hedefine bir EKLEME değil TAM
    ÜZERİNE YAZMA olarak tahliye ediyor — hiçbir gölge-farkında kod
    olmadan, o kullanıcı adının varsa eski gölgesini kendiliğinden
    iyileştiriyor.

    Bu, `_windows_golge_sil()`'in DÜZELTMESİNİN yerine geçmiyor —
    `ensure_available()` yalnızca BİR SONRAKİ açılışta çalışır, açık
    kalan bir oturumdaki tazecik bir gölgeyi korumaz (bkz. SECURITY.md'nin
    "genel bir garanti DEĞİL" notu) — ama bu makinede gözlemlenen "gölge
    yok" durumunun ŞANS değil, ölçülebilir bir mekanizma olduğunu
    kanıtlıyor.
    """
    if sys.platform != "win32":
        pytest.skip("Windows Credential Manager'a özgü davranış")
    try:
        import pywintypes
        import win32cred
        from keyring.backends.Windows import WinVaultKeyring
    except ImportError:
        pytest.skip("pywin32 kurulu değil")

    use_keyring_backend(WinVaultKeyring())

    service = "HYCLEUS-VERIFY-HEAL-TEST"
    u1, u2 = "heal-test-u1", "heal-test-u2"
    compound_u1 = f"{u1}@{service}"

    def _sil(target: str) -> None:
        try:
            win32cred.CredDelete(Type=win32cred.CRED_TYPE_GENERIC, TargetName=target)
        except pywintypes.error:
            pass

    for hedef in (u1, u2, compound_u1, f"{u2}@{service}", service):
        _sil(hedef)

    try:
        # DÜZELTME-ÖNCESİ ham üzerine-yazma şekli — secret_store.store()
        # DEĞİL, doğrudan keyring.set_password (o zamanki gibi
        # _windows_golge_sil() olmadan): u1, u2 tarafından compound'a
        # tahliye edilir, sonra u1 tekrar yazılır — sentetik bir gölge.
        keyring.set_password(service, u1, "OLD-VALUE")
        keyring.set_password(service, u2, "u2-value")
        keyring.set_password(service, u1, "NEW-VALUE")

        golge_once = win32cred.CredRead(Type=win32cred.CRED_TYPE_GENERIC, TargetName=compound_u1)
        assert golge_once["CredentialBlob"].decode("utf-16-le") == "OLD-VALUE", (
            "ön koşul: sentetik gölge OLD-VALUE taşımalı"
        )

        onceki_service = secret_store.SERVICE
        secret_store.SERVICE = service
        try:
            secret_store.ensure_available()
        finally:
            secret_store.SERVICE = onceki_service

        golge_sonra = win32cred.CredRead(Type=win32cred.CRED_TYPE_GENERIC, TargetName=compound_u1)
        assert golge_sonra["CredentialBlob"].decode("utf-16-le") == "NEW-VALUE", (
            "ensure_available() eski gölgeyi iyileştirmedi — SECURITY.md'nin "
            "'gölge bulunamadı' açıklaması artık geçersiz olabilir"
        )
    finally:
        for hedef in (u1, u2, compound_u1, f"{u2}@{service}", service):
            _sil(hedef)


# ══════════════════════════════════════════════════════════════════════════════
# 6. Görünürlük — düşüş SESSİZ olmamalı
# ══════════════════════════════════════════════════════════════════════════════


def test_oturum_raporu_iki_durumda_FARKLI_eylem() -> None:
    eylem_kapali, detay_kapali = oturum_raporu()
    assert eylem_kapali == EYLEM_DUSUS
    # Denetim kaydını sonradan okuyan biri NE OLDUĞUNU anlamalı.
    assert "muhur" in detay_kapali.lower() or "kasa" in detay_kapali.lower()

    tpm_sealing.zorla_durum(TpmDurum(True, "", "TPM-Version:2.0"))
    eylem_acik, detay_acik = oturum_raporu()
    assert eylem_acik == EYLEM_ETKIN
    assert eylem_acik != eylem_kapali
    assert "TPM-Version:2.0" in detay_acik


def _kaynak(yol: str) -> str:
    return (KOK / yol).read_text(encoding="utf-8")


def test_acilis_denetim_kaydina_yaziyor() -> None:
    """
    `main.py` açılışta `oturum_raporu()`'nu denetim kaydına yazmalı.
    Metin araması değil AST: yorumlar da "oturum_raporu" yazıyor.
    """
    agac = ast.parse(_kaynak("main.py"))
    cagrilar = {_cagri_adi(d) for d in ast.walk(agac) if isinstance(d, ast.Call)}
    assert "tpm_oturum_raporu" in cagrilar, (
        "main.py açılışta TPM durumunu hiç okumuyor — düşüş sessiz kalır."
    )

    # Raporu ÜRETMEK yetmez, YAZILMASI gerekiyor. Mutasyonla ölçüldü:
    # `DBManager().log(...)` satırını silmek, `oturum_raporu()` çağrısı
    # yerinde durduğu için yukarıdaki denetimden geçiyordu.
    yazilan = [
        d for d in ast.walk(agac)
        if isinstance(d, ast.Call) and _cagri_adi(d) == "log"
        and d.args and isinstance(d.args[0], ast.Name)
        and d.args[0].id == "_tpm_eylem"
    ]
    assert yazilan, (
        "main.py TPM raporunu üretiyor ama denetim kaydına YAZMIYOR — "
        "düşüşün kalıcı kanalı bu."
    )


def test_selftest_ciktisinda_TPM_satiri_var() -> None:
    agac = ast.parse(_kaynak("main.py"))
    (fn,) = [
        n for n in ast.walk(agac)
        if isinstance(n, ast.FunctionDef) and n.name == "_selftest"
    ]
    cagrilar = {_cagri_adi(d) for d in ast.walk(fn) if isinstance(d, ast.Call)}
    # Ad takma ile içe aktarılıyor (`durum as _tpm_durum`), ikisi de kabul.
    assert cagrilar & {"durum", "_tpm_durum"}, (
        f"--selftest çıktısı TPM durumunu yazmıyor. Bulunan çağrılar: {sorted(cagrilar)}"
    )


def test_hakkinda_kutusunda_TPM_satiri_var() -> None:
    agac = ast.parse(_kaynak("UI/main_window.py"))
    assert "tpm_durum" in {
        _cagri_adi(d) for d in ast.walk(agac) if isinstance(d, ast.Call)
    }, "Hakkında kutusu TPM durumunu göstermiyor."


# ══════════════════════════════════════════════════════════════════════════════
# 7. TEK KARAR NOKTASI — AST denetimleri
# ══════════════════════════════════════════════════════════════════════════════
#
# Korunan invaryant: mühürleme sisteme TEK yerden giriyor. İkinci bir
# çağrı yeri, TPM yokken sessizce mühürsüz yazan ikinci bir yol demek
# olurdu ve tam olarak bu maddenin engellemek istediği şey o.


def _cagri_adi(dugum: ast.Call) -> str:
    """`f(...)` → "f";  `m.f(...)` → "f"."""
    if isinstance(dugum.func, ast.Name):
        return dugum.func.id
    if isinstance(dugum.func, ast.Attribute):
        return dugum.func.attr
    return ""


def _kullanan_dosyalar(ad: str, *, haric: set[str]) -> list[str]:
    """
    `ad`'ı ÇAĞIRAN ya da `CORE.tpm_sealing`'den İÇE AKTARAN dosyalar.

    İçe aktarma da sayılıyor ve gerekçesi mutasyonla ölçüldü: yalnızca
    çağrı ADINA bakan bir denetim, `from CORE.tpm_sealing import belki_coz
    as _bc` yazan ikinci bir çağrı yerini GÖREMİYOR — takma ad denetimin
    altından geçiyor. Korunmak istenen şey zaten "kim çağırıyor" değil,
    "kimin eli değiyor".
    """
    bulunan = []
    dosyalar = [
        yol for kok in ("CORE", "DB", "UI")
        for yol in sorted((KOK / kok).rglob("*.py"))
    ] + [KOK / "main.py"]

    for yol in dosyalar:
        bagil = yol.relative_to(KOK).as_posix()
        if bagil in haric:
            continue
        agac = ast.parse(yol.read_text(encoding="utf-8"))
        for d in ast.walk(agac):
            if isinstance(d, ast.Call) and _cagri_adi(d) == ad:
                bulunan.append(bagil)
                break
            if (isinstance(d, ast.ImportFrom)
                    and (d.module or "").endswith("tpm_sealing")
                    and any(a.name == ad for a in d.names)):
                bulunan.append(bagil)
                break
    return bulunan


@pytest.mark.parametrize("fonksiyon", ["belki_muhurle", "belki_coz"])
def test_dusus_karari_YALNIZCA_secret_store_dan_geciyor(fonksiyon: str) -> None:
    """
    Düşüş kararını veren iki fonksiyon yalnızca `CORE/secret_store.py`
    içinden çağrılabilir. İkinci bir çağıran, TPM yokken sessizce
    mühürsüz yazan ikinci bir yol açardı.
    """
    ihlal = _kullanan_dosyalar(
        fonksiyon, haric={"CORE/tpm_sealing.py", "CORE/secret_store.py"}
    )
    assert not ihlal, (
        f"`{fonksiyon}()` şu dosyalardan da çağrılıyor: {ihlal}. "
        "Mühürleme sisteme YALNIZCA CORE/secret_store.py üzerinden girmeli."
    )


@pytest.mark.parametrize("fonksiyon", ["muhurle", "coz"])
def test_ham_muhurleme_modul_DISINDAN_cagrilmiyor(fonksiyon: str) -> None:
    """
    Ham `muhurle()`/`coz()` düşüş kararı VERMİYOR — TPM yoksa fırlatıyor.
    Dışarıdan çağrılırsa çağıran taraf o istisnayı yakalayıp kendi
    düşüşünü uydurmaya başlar.
    """
    ihlal = _kullanan_dosyalar(fonksiyon, haric={"CORE/tpm_sealing.py"})
    assert not ihlal, (
        f"`{fonksiyon}()` modül dışından çağrılıyor: {ihlal}. "
        "Dışarıya açık yüz `belki_muhurle`/`belki_coz`."
    )


def test_CNG_erisimi_TEK_modulde() -> None:
    """
    İkinci bir CNG implementasyonu, ikinci bir düşüş davranışı demek.
    `ncrypt` ve `NCrypt*` çağrıları yalnızca `CORE/tpm_sealing.py`'de.
    """
    ihlal = []
    for kok in ("CORE", "DB", "UI"):
        for yol in sorted((KOK / kok).rglob("*.py")):
            bagil = yol.relative_to(KOK).as_posix()
            if bagil == "CORE/tpm_sealing.py":
                continue
            agac = ast.parse(yol.read_text(encoding="utf-8"))
            for d in ast.walk(agac):
                if isinstance(d, ast.Attribute) and d.attr.startswith("NCrypt"):
                    ihlal.append(f"{bagil}:{d.lineno}")
                elif (isinstance(d, ast.Call) and _cagri_adi(d) == "WinDLL"):
                    ihlal.append(f"{bagil}:{d.lineno}")
    assert not ihlal, f"CNG erişimi tpm_sealing dışında: {ihlal}"


def test_kullanilabilir_karari_baska_modulde_TEKRARLANMIYOR() -> None:
    """
    `durum().kullanilabilir` üzerinden DEPOLAMA kararı veren ikinci bir
    yer, mühürlemeyi sessizce atlayan ikinci bir yol olurdu.

    `main.py`, `--selftest` ve Hakkında kutusu `durum()`'u çağırıyor ama
    yalnızca GÖSTERMEK için — `.kullanilabilir` okumuyorlar; bu test tam
    olarak o farkı ölçüyor.
    """
    ihlal = []
    for kok in ("CORE", "DB", "UI"):
        for yol in sorted((KOK / kok).rglob("*.py")):
            bagil = yol.relative_to(KOK).as_posix()
            if bagil == "CORE/tpm_sealing.py":
                continue
            agac = ast.parse(yol.read_text(encoding="utf-8"))
            for d in ast.walk(agac):
                if isinstance(d, ast.Attribute) and d.attr == "kullanilabilir":
                    ihlal.append(f"{bagil}:{d.lineno}")
    assert not ihlal, (
        f"`.kullanilabilir` tpm_sealing dışında okunuyor: {ihlal}. "
        "Düşüş kararı `belki_muhurle()` içinde tek yerde kalmalı."
    )


def test_DEK_ve_nonce_os_urandom_dan_geliyor() -> None:
    """
    Davranışsal test bunu YAKALAYAMIYOR ve gerekçesi ölçüldü.

    DEK sabitlense bile iki mühür farklı görünüyor: PKCS#1 v1.5'in kendi
    dolgusu rastgele, yani sarmal her seferinde değişiyor; nonce de taze
    olduğu için gövde değişiyor. Yani "bloblar farklı" iddiası, kaynağa
    GÖMÜLÜ bir DEK'i hayatta bırakıyor — mutasyonla ölçüldü.

    Gömülü bir DEK burada felaket: gövde artık TPM olmadan, yalnızca bu
    depoyu okuyarak çözülebilir ve TPM sarmalı süs hâline gelir.

    `.semgrep/hycleus.yml::hycleus-hardcoded-key-material` bu sınıfı
    yakalıyor ama isim listesine göre çalışıyor ve `dek` orada yok.
    Denetim bu yüzden burada, yapısal olarak.
    """
    agac = ast.parse(_kaynak("CORE/tpm_sealing.py"))
    (fn,) = [
        n for n in ast.walk(agac)
        if isinstance(n, ast.FunctionDef) and n.name == "muhurle"
    ]
    kaynaklar: dict[str, str] = {}
    for d in ast.walk(fn):
        if (isinstance(d, ast.Assign) and len(d.targets) == 1
                and isinstance(d.targets[0], ast.Name)):
            hedef = d.targets[0].id
            if hedef in ("dek", "nonce"):
                kaynaklar[hedef] = (
                    _cagri_adi(d.value) if isinstance(d.value, ast.Call) else "<literal>"
                )
    assert kaynaklar == {"dek": "urandom", "nonce": "urandom"}, (
        f"DEK ve nonce `os.urandom` ile üretilmeli, bulunan: {kaynaklar}"
    )


def test_denetimler_GERCEKTEN_cagri_buluyor() -> None:
    """
    Yukarıdaki dört denetim boş küme dönen bir tarayıcıyla sessizce
    geçebilirdi. Bu depoda o sınıftan kaza yaşandı (B-024).
    """
    # `belki_muhurle` GERÇEKTEN secret_store'da çağrılıyor mu — yoksa
    # "hiçbir yerde çağrılmıyor" diye geçerdi.
    agac = ast.parse(_kaynak("CORE/secret_store.py"))
    adlar = {_cagri_adi(d) for d in ast.walk(agac) if isinstance(d, ast.Call)}
    assert {"belki_muhurle", "belki_coz"} <= adlar, (
        "secret_store mühürlemeyi hiç çağırmıyor — denetimler boş kümeyi "
        "denetliyor olurdu."
    )
    # Tarayıcı CNG'yi tpm_sealing'in KENDİSİNDE bulabiliyor mu.
    agac = ast.parse(_kaynak("CORE/tpm_sealing.py"))
    ncrypt_var = any(
        isinstance(d, ast.Attribute) and d.attr.startswith("NCrypt")
        for d in ast.walk(agac)
    )
    assert ncrypt_var, "CNG tarayıcısı kör — tpm_sealing'de bile bulamıyor."


# ══════════════════════════════════════════════════════════════════════════════
# 8. Saf ekleme — mevcut çağıranlar etkilenmedi mi
# ══════════════════════════════════════════════════════════════════════════════


def test_secret_store_arayuzu_DEGISMEDI() -> None:
    """
    `store()`/`load()` hâlâ DÜZ METİN alıp döndürüyor. Mühür bu iki
    fonksiyonun içinde açılıp kapanıyor; çağıranların hiçbiri TPM'i
    bilmiyor.
    """
    import inspect

    assert list(inspect.signature(secret_store.store).parameters) == ["username", "value"]
    assert list(inspect.signature(secret_store.load).parameters) == ["username"]


def test_tpm_sealing_UI_ve_DB_ye_bagli_degil() -> None:
    """Katman ihlali: CORE bir sızdırma noktası olmamalı."""
    agac = ast.parse(_kaynak("CORE/tpm_sealing.py"))
    moduller = {
        (d.module or "") for d in ast.walk(agac) if isinstance(d, ast.ImportFrom)
    } | {
        a.name for d in ast.walk(agac) if isinstance(d, ast.Import) for a in d.names
    }
    yasak = {m for m in moduller if m.startswith(("UI", "DB", "PySide6"))}
    assert not yasak, f"tpm_sealing yasak katmanlara bağlı: {yasak}"
