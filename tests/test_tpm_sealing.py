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
from pathlib import Path

import keyring
import pytest

from CORE import secret_store, tpm_sealing, vault_manager
from CORE.secret_store import KeyringUnavailableError
from CORE.tpm_sealing import (
    ETIKET,
    EYLEM_DUSUS,
    EYLEM_ETKIN,
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
