"""
HYCLEUS — TPM 2.0 mühürleme (Windows / CNG), yoksa anahtar kasasına düşüş

Ne yapıyor
----------
`CORE/secret_store.py` sırları işletim sisteminin anahtar kasasında tutuyor.
Windows'ta o kasa DPAPI ile korunuyor: sır, OS KULLANICI HESABINA bağlı.
SECURITY.md'nin M3 modeli tam olarak bunu söylüyor — oturum açmış kullanıcı
olarak çalışan bir saldırgana anahtar kasası `share_2`'yi istediğinde verir.

Bu modül o sırrın üstüne İKİNCİ bir katman koyuyor: değer anahtar kasasına
yazılmadan önce TPM'e mühürleniyor. Mühür açan özel anahtar TPM çipinin
içinde üretiliyor ve dışa AKTARILAMIYOR — ölçüldü, `NCryptExportKey`
`NTE_NOT_SUPPORTED` (0x8009000A) döndürüyor.

Kazanım DAR ve abartılmamalı: M3 hâlâ çalışan makinede TPM'den mühür
açtırabilir (TPM ona da cevap verir, tıpkı anahtar kasası gibi). Kazanılan
şey M2'de: **anahtar kasası blob'u diskle birlikte kopyalansa bile,
mühürlenmiş değer o TPM olmadan açılamıyor.** SECURITY.md §1.2'deki "blob
diskle birlikte gidiyor; OS hesap parolası onu açar" satırı, mühürlenmiş
kayıtlar için artık geçerli değil.


Neden CNG, neden bu yapı
------------------------
Windows'ta TPM'e erişimin bağımlılıksız yolu CNG'nin "Microsoft Platform
Crypto Provider" sağlayıcısı (ncrypt.dll, ctypes). TPM2_Create ile ham
"sealed data" nesnesi CNG'de doğrudan açılmıyor; CNG'nin verdiği şey
TPM'de duran ve dışarı çıkmayan bir ANAHTAR. Mühürleme bu anahtarla
yapılıyor.

Şifreleme HİBRİT, doğrudan RSA değil. Üç ölçülmüş sebep:

  1. **OAEP bu sağlayıcıda çalışmıyor.** Ölçüldü (AMD fTPM 2.0, rev 1.59):
     `NCryptEncrypt` OAEP-SHA256 ve OAEP-SHA1 için `NTE_BAD_FLAGS`
     (0x80090009) döndürüyor; yalnızca PKCS#1 v1.5 kabul ediliyor.
  2. **RSA-2048 PKCS#1 en fazla 245 bayt alıyor.** Bugünkü sırlar sığıyor
     (share_2 ~68 B, TOTP ~32 B) ama sabit bir tavan, ileride eklenecek
     bir sırda sessiz bir duvar olurdu.
  3. **PKCS#1 v1.5 BÜTÜNLÜK vermiyor.** Kurcalanmış bir blob çöpe çözülür
     ve o çöp "sır" diye geri verilirdi. Kasa açılmaz, hata mesajı da
     yanıltıcı olurdu.

Bu yüzden: rastgele 32 baytlık bir DEK üretiliyor, sır DEK ile
AES-256-GCM'leniyor (deponun her yerinde kullanılan aynı ilkel), ve
YALNIZCA DEK TPM anahtarıyla sarmalanıyor. Kurcalanmış bir sarmal, GCM
etiketinde `InvalidTag` olarak patlıyor — sessizce yanlış bir değer
dönmüyor.

PKCS#1 v1.5'in Bleichenbacher sınıfı zayıflığı burada bir kazanım
sağlamıyor: kehanet olarak kullanılacak `NCryptDecrypt` yalnızca makinede
çalışabiliyor, ve orada duran saldırgan (M3) zaten mührü doğrudan
açtırabilir. Uzaktaki bir saldırganın (M1) bu çağrıya hiç erişimi yok.

GCM'in AAD'ı anahtar kasasındaki KULLANICI ADI: bir blob `totp_secret`
kaydından alınıp `share_2:<hwid>` kaydına taşınamıyor.


KRİTİK: mühürlenmiş sır TPM'e BAĞLIDIR
---------------------------------------
TPM temizlenirse (BIOS'tan "Clear TPM", anakart değişimi, bazı firmware
güncellemeleri) anahtar GİDER ve mühürlenmiş her değer KALICI OLARAK
açılamaz hâle gelir. Bu bir hata değil, mühürlemenin tanımı.

  · `share_2` için çıkış yolu VAR: basılı kurtarma parçası (SECURITY.md
    §4.4). Shamir 2-of-3 tam olarak bu durum için.
  · TOTP sırrı için çıkış yolu, yöneticinin ikinci faktörü yeniden
    kurmasıdır.

`coz()` bu durumda SESSİZ KALMIYOR ve None DÖNMÜYOR — `TpmSealingError`
fırlatıyor. None dönmek "kayıt yok" gibi okunur ve çağıran tarafı yeniden
kurmaya, yani veriyi kaybetmeye iterdi.


Düşüş SESSİZ DEĞİL (B-025'in dersi)
------------------------------------
TPM yoksa mühürleme yapılmıyor ve değer anahtar kasasına eskisi gibi
yazılıyor. Bu düşüş kayda geçmek ZORUNDA: sessizce devre dışı kalan bir
güvenlik katmanı, hiç olmamasından kötüdür — belge onun varlığını iddia
etmeye devam eder. B-025'te tam olarak bu yaşandı (HWID sessizce dosyadan
türüyordu, SECURITY.md "cihaza bağlı" diyordu).

Görünürlük üç kanaldan:
  · her oturumda denetim kaydı — `oturum_raporu()`, `main.py` yazıyor
  · `--selftest` çıktısında bir satır
  · Yardım → Hakkında kutusunda bir satır
"""
from __future__ import annotations

import base64
import logging
import os
import struct
import sys
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_log = logging.getLogger("hycleus.tpm")

#: Mühürlenmiş değerin anahtar kasasındaki öneki. Öneksiz kayıtlar
#: mühürsüzdür ve olduğu gibi okunur — geriye dönük uyumluluk buradan
#: geliyor: TPM'li bir makinede eski kayıtlar çalışmaya devam ediyor.
ETIKET = "TPM1"
_AYRAC = ":"

#: TPM'de kalıcı anahtarın adı. Sürüm eki bilinçli: şema değişirse yeni
#: bir anahtar adı kullanılır ve eski mühürler açılabilir kalır.
ANAHTAR_ADI = "HYCLEUS-seal-v1"

#: CNG'nin TPM destekli sağlayıcısı.
SAGLAYICI = "Microsoft Platform Crypto Provider"

_RSA_BITS = 2048

#: Denetim kaydı eylem adları.
EYLEM_ETKIN = "tpm_sealing_active"
EYLEM_DUSUS = "tpm_sealing_unavailable"

# ── CNG sabitleri ────────────────────────────────────────────────────────────
_NCRYPT_PAD_PKCS1_FLAG = 0x00000002
_NCRYPT_ALLOW_DECRYPT_FLAG = 0x00000001
_NTE_BAD_KEYSET = 0x80090016
_NTE_EXISTS = 0x8009000F


class TpmSealingError(RuntimeError):
    """
    Mühürleme ya da mühür açma başarısız.

    YAKALANIP mühürsüz yola düşülmemelidir: mühürlenmiş bir değeri
    açamamak, o sırrın kaybı demektir ve çağıran tarafın bunu bilmesi
    gerekir (bkz. modül başlığı, "KRİTİK").
    """


@dataclass(frozen=True)
class TpmDurum:
    """Bu makinede TPM mühürlemesinin durumu — süreç ömrü boyunca sabit."""

    kullanilabilir: bool
    #: Kullanılamıyorsa insan okur gerekçe; kullanılabiliyorsa boş.
    neden: str = ""
    #: `PCP_PLATFORM_TYPE` — örn. "TPM-Version:2.0 -Level:0-Revision:1.59…"
    platform: str = ""

    def ozet(self) -> str:
        """Tek satırlık, kullanıcıya gösterilebilir özet."""
        if self.kullanilabilir:
            return f"TPM mühürlemesi ETKİN — {self.platform or SAGLAYICI}"
        return f"TPM mühürlemesi YOK — anahtar kasasına düşüldü ({self.neden})"


_durum_onbellek: TpmDurum | None = None


# ══════════════════════════════════════════════════════════════════════════════
# 1. CNG erişimi — bu bölüm YALNIZCA Windows'ta çalışır
# ══════════════════════════════════════════════════════════════════════════════
#
# Import Linux/macOS'ta da başarılı olmalı: CI'ın AppImage işi Linux'ta
# koşuyor ve `main.py --selftest` bu modülü içe aktarıyor. Bu yüzden
# ctypes/WinDLL yüklemesi fonksiyonun İÇİNDE.


def _ncrypt():  # type: ignore[no-untyped-def]
    """`ncrypt.dll`'i yükler. Windows dışında `TpmSealingError`."""
    if sys.platform != "win32":
        raise TpmSealingError(f"CNG yalnızca Windows'ta var (platform={sys.platform})")
    import ctypes

    try:
        return ctypes.WinDLL("ncrypt.dll")
    except OSError as exc:  # pragma: no cover — Windows'ta olması beklenmiyor
        raise TpmSealingError(f"ncrypt.dll yüklenemedi: {exc}") from exc


def _hata(rc: int, ne: str) -> None:
    """Sıfır olmayan `NTSTATUS`'u istisnaya çevirir."""
    if rc:
        raise TpmSealingError(f"{ne} başarısız — 0x{rc & 0xFFFFFFFF:08X}")


def _saglayici_ac():  # type: ignore[no-untyped-def]
    """TPM sağlayıcısını açar; `(ncrypt, handle)` döndürür."""
    import ctypes

    nc = _ncrypt()
    h = ctypes.c_void_p()
    rc = nc.NCryptOpenStorageProvider(ctypes.byref(h), ctypes.c_wchar_p(SAGLAYICI), 0)
    if rc:
        raise TpmSealingError(
            f"TPM sağlayıcısı açılamadı ('{SAGLAYICI}') — 0x{rc & 0xFFFFFFFF:08X}"
        )
    return nc, h


def _platform_dizesi(nc, h) -> str:  # type: ignore[no-untyped-def]
    """`PCP_PLATFORM_TYPE` — TPM sürümünü ve üreticisini taşıyan dize."""
    import ctypes
    import ctypes.wintypes as w

    buf = ctypes.create_string_buffer(512)
    got = w.DWORD()
    rc = nc.NCryptGetProperty(
        h, ctypes.c_wchar_p("PCP_PLATFORM_TYPE"), buf, 512, ctypes.byref(got), 0
    )
    if rc:
        return ""
    try:
        return buf.raw[: got.value].decode("utf-16-le").rstrip("\x00").strip()
    except UnicodeDecodeError:  # pragma: no cover — sağlayıcıya bağlı
        return ""


def _anahtar_ac(nc, h):  # type: ignore[no-untyped-def]
    """
    Kalıcı TPM anahtarını açar; yoksa üretir.

    Üretim ÖLÇÜLDÜ: ~1.33 sn (AMD fTPM 2.0). Yalnızca ilk mühürlemede
    bir kez oluyor; sonraki açılışlar milisaniye mertebesinde.
    """
    import ctypes
    import ctypes.wintypes as w

    k = ctypes.c_void_p()
    rc = nc.NCryptOpenKey(h, ctypes.byref(k), ctypes.c_wchar_p(ANAHTAR_ADI), 0, 0)
    if rc == 0:
        return k
    if (rc & 0xFFFFFFFF) != _NTE_BAD_KEYSET:
        raise TpmSealingError(f"TPM anahtarı açılamadı — 0x{rc & 0xFFFFFFFF:08X}")

    # ── Anahtar yok: üret ────────────────────────────────────────────────
    rc = nc.NCryptCreatePersistedKey(
        h, ctypes.byref(k), ctypes.c_wchar_p("RSA"), ctypes.c_wchar_p(ANAHTAR_ADI), 0, 0
    )
    if (rc & 0xFFFFFFFF) == _NTE_EXISTS:
        # Başka bir süreç araya girdi — onunkini kullan. Yarış burada
        # zararsız: iki süreç de AYNI adlı anahtarı istiyor.
        _hata(nc.NCryptOpenKey(h, ctypes.byref(k), ctypes.c_wchar_p(ANAHTAR_ADI), 0, 0),
              "NCryptOpenKey (yarış sonrası)")
        return k
    _hata(rc, "NCryptCreatePersistedKey")

    uzunluk = w.DWORD(_RSA_BITS)
    _hata(nc.NCryptSetProperty(k, ctypes.c_wchar_p("Length"), ctypes.byref(uzunluk), 4, 0),
          "NCryptSetProperty(Length)")
    # Kullanım BİLEREK yalnızca çözme: bu anahtar imza atmıyor, kimlik
    # kanıtlamıyor. Dar yetki, TPM'de duran bir anahtarın başka bir amaca
    # sessizce kaydırılmasını engelliyor.
    kullanim = w.DWORD(_NCRYPT_ALLOW_DECRYPT_FLAG)
    _hata(nc.NCryptSetProperty(k, ctypes.c_wchar_p("Key Usage"), ctypes.byref(kullanim), 4, 0),
          "NCryptSetProperty(Key Usage)")
    _hata(nc.NCryptFinalizeKey(k, 0), "NCryptFinalizeKey")
    _log.info("tpm_anahtari_uretildi  ad=%s bits=%d", ANAHTAR_ADI, _RSA_BITS)
    return k


def _rsa(nc, k, veri: bytes, *, coz: bool) -> bytes:  # type: ignore[no-untyped-def]
    """TPM anahtarıyla PKCS#1 v1.5 sarmalar / açar. İki geçişli boyut sorgusu."""
    import ctypes
    import ctypes.wintypes as w

    fn = nc.NCryptDecrypt if coz else nc.NCryptEncrypt
    ad = "NCryptDecrypt" if coz else "NCryptEncrypt"
    n = w.DWORD()
    _hata(fn(k, veri, len(veri), None, None, 0, ctypes.byref(n), _NCRYPT_PAD_PKCS1_FLAG),
          f"{ad} (boyut)")
    buf = ctypes.create_string_buffer(n.value)
    _hata(fn(k, veri, len(veri), None, buf, n.value, ctypes.byref(n), _NCRYPT_PAD_PKCS1_FLAG),
          ad)
    return buf.raw[: n.value]


# ══════════════════════════════════════════════════════════════════════════════
# 2. Durum tespiti — TEK karar noktası
# ══════════════════════════════════════════════════════════════════════════════


def durum() -> TpmDurum:
    """
    Bu makinede TPM mühürlemesi kullanılabilir mi.

    Süreç ömrü boyunca ÖNBELLEKLİ: sağlayıcıyı her sır yazımında yoklamak
    hem yavaş olurdu hem de aynı oturumda farklı cevaplar vererek bazı
    kayıtları mühürlü bazılarını mühürsüz bırakabilirdi.

    Yoklama yalnızca sağlayıcıyı AÇIYOR; anahtar üretmiyor. TPM'i olan ama
    HYCLEUS'u ilk kez çalıştıran bir makinede bu çağrı 1.3 saniye
    beklememeli.
    """
    global _durum_onbellek
    if _durum_onbellek is not None:
        return _durum_onbellek

    if sys.platform != "win32":
        _durum_onbellek = TpmDurum(
            False, f"CNG yalnızca Windows'ta — bu platform {sys.platform}"
        )
    else:
        try:
            nc, h = _saglayici_ac()
        except TpmSealingError as exc:
            _durum_onbellek = TpmDurum(False, str(exc))
        else:
            try:
                _durum_onbellek = TpmDurum(True, "", _platform_dizesi(nc, h))
            finally:
                nc.NCryptFreeObject(h)

    _log.info("tpm_durum  %s", _durum_onbellek.ozet())
    return _durum_onbellek


def sifirla_onbellek() -> None:
    """Önbelleği temizler — YALNIZCA testler için."""
    global _durum_onbellek
    _durum_onbellek = None


def zorla_durum(d: TpmDurum) -> None:
    """
    Durumu sabitler — YALNIZCA testler için.

    `tests/conftest.py` bunu autouse olarak "TPM yok"a çekiyor. Gerekçe:
    aksi hâlde test paketi TPM'li ve TPM'siz makinelerde FARKLI sonuç
    verirdi ve makineye göre değişen bir paket, güven veremez. TPM yolunu
    ölçen testler `gercek_tpm` fixture'ıyla açıkça devre dışı bırakıyor.
    """
    global _durum_onbellek
    _durum_onbellek = d


def oturum_raporu() -> tuple[str, str]:
    """
    Oturum başına bir kez yazılacak `(denetim_eylemi, açıklama)`.

    Düşüşün SESSİZ kalmamasının birinci kanalı. `main.py` açılışta bunu
    denetim kaydına yazıyor; ikinci ve üçüncü kanallar `--selftest`
    çıktısı ile Hakkında kutusu.
    """
    d = durum()
    if d.kullanilabilir:
        return EYLEM_ETKIN, f"saglayici={SAGLAYICI} platform={d.platform}"
    return EYLEM_DUSUS, (
        f"neden={d.neden} — sirlar anahtar kasasinda TPM muhru OLMADAN tutuluyor"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 3. Mühürleme / açma
# ══════════════════════════════════════════════════════════════════════════════


def muhurlu_mu(saklanan: str) -> bool:
    """Anahtar kasasından okunan bu değer mühürlü mü."""
    return saklanan.startswith(ETIKET + _AYRAC)


def muhurle(deger: str, *, baglam: str) -> str:
    """
    Değeri TPM'e mühürler ve `"TPM1:<base64>"` döndürür.

    Args:
        deger:  Mühürlenecek sır.
        baglam: Anahtar kasasındaki kullanıcı adı. GCM'in AAD'ı oluyor,
                yani mühür o kayda BAĞLANIYOR — bir blob başka bir kaydın
                yerine konamıyor.

    Raises:
        TpmSealingError — TPM yoksa ya da işlem başarısızsa. Bu istisna
            yakalanıp mühürsüz yazmaya düşülmemeli; düşüş kararı
            `belki_muhurle()`'nin işi ve orada kayda geçiyor.
    """
    if not durum().kullanilabilir:
        raise TpmSealingError(f"TPM kullanılamıyor: {durum().neden}")

    dek = os.urandom(32)
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(dek), modes.GCM(nonce)).encryptor()
    enc.authenticate_additional_data(baglam.encode("utf-8"))
    govde = enc.update(deger.encode("utf-8")) + enc.finalize()

    nc, h = _saglayici_ac()
    try:
        k = _anahtar_ac(nc, h)
        try:
            sarmal = _rsa(nc, k, dek, coz=False)
        finally:
            nc.NCryptFreeObject(k)
    finally:
        nc.NCryptFreeObject(h)

    paket = struct.pack(">H", len(sarmal)) + sarmal + nonce + enc.tag + govde
    return ETIKET + _AYRAC + base64.b64encode(paket).decode("ascii")


def coz(saklanan: str, *, baglam: str) -> str:
    """
    Mühürlü bir değeri açar.

    Raises:
        TpmSealingError — değer mühürlü değilse, TPM yoksa/değiştiyse,
            paket bozuksa ya da GCM etiketi tutmazsa. Hiçbir durumda
            None ya da bozuk bir dize DÖNMÜYOR: mühürlenmiş bir sırrın
            açılamaması, o sırrın kaybıdır ve "kayıt yok" ile
            karıştırılırsa çağıran taraf yeniden kurmaya kalkar.
    """
    if not muhurlu_mu(saklanan):
        raise TpmSealingError("Değer mühürlü değil — coz() çağrılmamalıydı.")

    try:
        paket = base64.b64decode(saklanan[len(ETIKET) + len(_AYRAC):], validate=True)
    except Exception as exc:
        raise TpmSealingError(f"Mühürlü paket base64 olarak çözülemedi: {exc}") from exc

    if len(paket) < 2:
        raise TpmSealingError("Mühürlü paket çok kısa.")
    (n,) = struct.unpack(">H", paket[:2])
    # 2 (uzunluk) + n (sarmal) + 12 (nonce) + 16 (etiket) = en az
    if len(paket) < 2 + n + 28:
        raise TpmSealingError(
            f"Mühürlü paket eksik — {len(paket)} bayt, en az {2 + n + 28} bekleniyordu."
        )
    sarmal = paket[2:2 + n]
    nonce = paket[2 + n:14 + n]
    etiket = paket[14 + n:30 + n]
    govde = paket[30 + n:]

    if not durum().kullanilabilir:
        raise TpmSealingError(
            "Bu kayıt TPM'e mühürlenmiş ama TPM kullanılamıyor: "
            f"{durum().neden}\n"
            "TPM temizlendiyse (BIOS 'Clear TPM', anakart değişimi) mühür "
            "KALICI olarak açılamaz — kurtarma parçasıyla yeniden kurun."
        )

    nc, h = _saglayici_ac()
    try:
        k = _anahtar_ac(nc, h)
        try:
            dek = _rsa(nc, k, sarmal, coz=True)
        finally:
            nc.NCryptFreeObject(k)
    finally:
        nc.NCryptFreeObject(h)

    # CNG, KURCALANMIŞ bir PKCS#1 sarmalını hata vermeden çözebiliyor:
    # ölçüldü, sarmalın 10. baytı çevrildiğinde `NCryptDecrypt` 0 döndürüp
    # BOŞ tampon verdi. Uzunluk denetlenmezse `algorithms.AES()` ham bir
    # `ValueError` fırlatır ve bu modülün istisna sözleşmesinin dışına
    # sızar — `secret_store` yalnızca `TpmSealingError` yakalıyor.
    if len(dek) != 32:
        raise TpmSealingError(
            f"TPM'den çözülen anahtar {len(dek)} bayt (32 bekleniyordu) — "
            "sarmal kurcalanmış ya da başka bir TPM anahtarına ait."
        )

    dec = Cipher(algorithms.AES(dek), modes.GCM(nonce, etiket)).decryptor()
    dec.authenticate_additional_data(baglam.encode("utf-8"))
    try:
        duz = dec.update(govde) + dec.finalize()
    except InvalidTag as exc:
        raise TpmSealingError(
            "Mühürlü paketin GCM etiketi tutmadı — paket kurcalanmış, "
            f"başka bir kayda ait ya da TPM anahtarı değişmiş (bağlam='{baglam}')."
        ) from exc
    return duz.decode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# 4. Düşüş kararı — sistemde TEK yer
# ══════════════════════════════════════════════════════════════════════════════
#
# `tests/test_tpm_sealing.py` bu iki fonksiyonun `CORE/secret_store.py`
# dışından çağrılmadığını ve `durum().kullanilabilir` kararının başka bir
# modülde tekrarlanmadığını AST ile denetliyor. İkinci bir çağrı yeri,
# sessizce mühürsüz yazan ikinci bir yol demek olurdu.


def belki_muhurle(deger: str, *, baglam: str) -> str:
    """
    TPM varsa mühürler, yoksa değeri OLDUĞU GİBİ döndürür.

    Düşüşün tek karar noktası. Düşüş `_log.warning` ile kayda geçiyor;
    kullanıcıya ulaşan kanallar `oturum_raporu()` üzerinden.
    """
    d = durum()
    if not d.kullanilabilir:
        if muhurlu_mu(deger):
            # Mühürsüz yazılacak bir değer önekle başlıyorsa, bir sonraki
            # okumada MÜHÜRLÜ sanılır ve açılamaz. Bugünkü sırların hiçbiri
            # böyle başlamıyor (share_2 "2:<hex>", TOTP base32) ama sessiz
            # bir bozulma yerine burada durmak doğru olan.
            raise TpmSealingError(
                f"Mühürsüz yazılacak değer '{ETIKET}{_AYRAC}' önekiyle "
                "başlıyor — bir sonraki okumada mühürlü sanılırdı."
            )
        _log.warning(
            "tpm_muhur_atlandi  baglam=%s neden=%s — deger anahtar kasasina "
            "MUHURSUZ yaziliyor", baglam, d.neden)
        return deger
    return muhurle(deger, baglam=baglam)


def belki_coz(saklanan: str, *, baglam: str) -> str:
    """
    Mühürlüyse açar, değilse olduğu gibi döndürür.

    Öneksiz kayıtlar mühürlemeden ÖNCE yazılmış olanlar; onları
    reddetmek, çalışan kurulumları kilitlerdi. Bir kayıt bir sonraki
    yazımda kendiliğinden mühürlenir.

    Mühürlü bir kaydın açılamaması SESSİZ GEÇMİYOR — `coz()` fırlatıyor.
    """
    if not muhurlu_mu(saklanan):
        return saklanan
    return coz(saklanan, baglam=baglam)


__all__ = [
    "ANAHTAR_ADI",
    "ETIKET",
    "EYLEM_DUSUS",
    "EYLEM_ETKIN",
    "SAGLAYICI",
    "TpmDurum",
    "TpmSealingError",
    "belki_coz",
    "belki_muhurle",
    "coz",
    "durum",
    "muhurle",
    "muhurlu_mu",
    "oturum_raporu",
    "sifirla_onbellek",
    "zorla_durum",
]
