"""
HYCLEUS — AES-256-GCM dosya şifreleme modülü

Dosya formatı (ikili):
  [4B ] magic     = b'HYCL'
  [1B ] version   = 0x01 (eski) | 0x02 (güncel)
  [12B] nonce     (rastgele, her şifrelemede yeni)
  [4B ] aad_len   (big-endian uint32)
  [xB ] aad       = JSON(metadata)  — şifrelenmez, bütünlük koruması altında
  [nB ] ciphertext (64 KB bloklarla akış)
  [16B] GCM authentication tag
  [?B ] TS_TRAILER — OPSİYONEL, yalnızca v2; bkz. CORE/timestamp.py

AAD alanları (tek karakter değişse decrypt_file() AuthenticationError fırlatır):
  filename, created_at, uploaded_at, last_modified, user_id, hwid

B-092/B-099 — `original_sha256` artık AAD'DE YOK
--------------------------------------------------
AAD şifresiz duruyor (bütünlüğünü GCM tag'i koruyor, ama bunu kontrol
etmek anahtar ister — okumak istemez). Düz metnin SHA-256'sını orada
tutmak, yalnızca bir .hcl KOPYASINA erişen (DB'ye/kimliğe/çalışan
uygulamaya erişimi OLMAYAN — SECURITY.md §1.1'in M2 tanımı) biri için
anahtarsız, kesin bir DOĞRULAMA-ORACLE'I demekti: elindeki bir aday
belgeyi kendisi hash'leyip başlıktaki değerle karşılaştırarak, kasayı
HİÇ çözmeden, o belgenin TAM OLARAK orada olduğunu doğrulayabiliyordu.
Tuz işe yaramaz (saldırgan onu da aday belgeye ekler); yalnızca gerçek
bir SIR (anahtar) bunu kapatır — ki bu zaten "anahtarsız" tanımıyla
çelişir. Karar: `encrypt_file()` özeti hâlâ hesaplayıp DB'ye kaydedilmek
üzere DÖNDÜRÜYOR, ama AAD'ye YAZMIYOR. Bedeli: `CORE/timestamp.py`'nin
"anahtar istemeyen damgalama/doğrulama" tasarımı KALICI olarak feda
edildi — ayrıntı orada. GERİYE DÖNÜK ONARILMIYOR: mevcut bir `.hcl`
dosyasının AAD'sinden bir alanı anahtar olmadan sessizce çıkarmak
mümkün değil (GCM AAD'si ciphertext'e bağlı) — yalnızca BUNDAN SONRA
şifrelenen dosyalar korunuyor. Ayrıntı ve gerekçe: BACKLOG.md B-092,
B-099.


Versiyon 0x02 — RFC 3161 zaman damgası kabı
-------------------------------------------
v2 ile dosyanın SONUNA opsiyonel bir zaman damgası fragmanı (TS_TRAILER)
eklenebilir hâle geldi. Üç kural:

  · **v1 dosyalar okunmaya devam eder.** `_SUPPORTED_VERSIONS` ikisini de
    kabul ediyor; v1'de fragman ARANMAZ (v1'in tanımı gereği fragmanı
    yoktur ve ciphertext'in son byte'ları yanlışlıkla fragman sanılmasın).
  · **Fragman opsiyoneldir.** Yeni şifrelenen her dosya v2 yazılıyor ama
    fragmansız; damga sonradan, ayrı ve isteğe bağlı bir adımda ekleniyor.
    "v2 ama fragmansız" tamamen geçerli bir dosyadır.
  · **Fragman GCM tag'inin DIŞINDADIR.** Aşağıda ayrıntısı var.

Neden başlık değil de fragman (trailer)
---------------------------------------
Damga, şifreleme BİTTİKTEN sonra üretiliyor — TSA'ya gidip dönmesi gerek.
Başlığa yazmak, damgalanan her dosyanın tamamının yeniden yazılması ya da
başlıkta baştan boş yer ayrılması demekti. Sona eklemek, kabın geri kalanını
hiç değiştirmeden bırakıyor: nonce, AAD ve ciphertext ofsetleri sabit kalıyor,
dolayısıyla v1 okuma yolu da aynen çalışmaya devam ediyor.

Bedeli, fragmanın sondan geriye doğru bulunabilmesi gerektiği: bu yüzden
uzunluk alanı ve ikinci bir magic sona konuyor (bkz. `_trailer_offset`).

DÜRÜST SINIR — fragman kriptografik olarak bağlı DEĞİL
------------------------------------------------------
GCM tag'i yalnızca AAD + ciphertext'i kapsıyor; magic, versiyon byte'ı ve
fragman kapsam dışında. Sonuç:

  · Fragman SİLİNEBİLİR ya da kırpılabilir — GCM doğrulaması yine geçer,
    dosya yalnızca "damgasız" görünür. Yani damga bir DOWNGRADE saldırısına
    açık ve fragmanın yokluğu "hiç damgalanmadı" ile ayırt edilemez.
  · Fragman UYDURULAMAZ — içindeki token TSA tarafından imzalı ve belirli
    bir düz metin özetine bağlı. Başka bir dosyanın token'ı buraya
    kopyalansa dosyanın GERÇEK (anahtarla yeniden hesaplanan) özetiyle
    eşleşmez — bkz. `CORE/timestamp_verify.py::verify_timestamp()`.

Yani damga, denetim zinciriyle aynı sınıfta: kurcalamayı ENGELLEMİYOR,
KANIT bırakıyor. Silinmeye karşı koruma, damga kaydının dosyadan bağımsız
bir yerde de tutulmasını gerektirir — bu, sonraki adımların işi.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Literal, overload

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_MAGIC = b"HYCL"

#: İlk format. Zaman damgası fragmanını TANIMIYOR — bu sürümdeki dosyalarda
#: fragman aranmaz. Okuma desteği kalıcıdır; mevcut kasalar dönüştürülmez.
VERSION_LEGACY = 1

#: Fragman taşıyabilen format. Fragmanın VARLIĞINI değil, İHTİMALİNİ belirtir.
VERSION_TIMESTAMPED = 2

#: Yeni şifrelemelerde yazılan sürüm.
_VERSION = VERSION_TIMESTAMPED

#: Okunabilen sürümler. Yeni bir sürüm eklendiğinde buraya da girmeli;
#: tek bir `!= _VERSION` karşılaştırması eski dosyaları kilitlerdi.
_SUPPORTED_VERSIONS = frozenset({VERSION_LEGACY, VERSION_TIMESTAMPED})

_NONCE_SIZE = 12
_TAG_SIZE = 16
_CHUNK = 64 * 1024  # 64 KB

#: Zaman damgası fragmanının magic'i. Fragmanın HEM başında HEM sonunda
#: bulunur: sondaki onu bulmayı, baştaki doğru yere indiğimizi doğrulamayı
#: sağlıyor (bkz. `_trailer_offset`).
TRAILER_MAGIC = b"HTST"

#: Fragmanın son 8 byte'ı: [4B toplam uzunluk][4B TRAILER_MAGIC].
_TRAILER_FOOTER_SIZE = 8

#: Boş bir fragmanın uzunluğu — magic(4) + sürüm(1) + dört adet boş
#: uzunluk-önekli alan (4×4) + toplam uzunluk(4) + magic(4).
_TRAILER_MIN_SIZE = 29

# update_into() hedef tamponun len(veri) + blok_boyu - 1 kadar olmasını ister
# (AES blok boyu 16 byte). Yuvarlak sayı için 16 alındı — bkz. verify_file().
_BLOCK_SLACK = 16

_QUARANTINE_DIR = Path(__file__).parent.parent / "data" / "quarantine"


class AuthenticationError(Exception):
    """Dosya, ciphertext veya AAD metadata bütünlüğü doğrulanamadığında fırlar."""


def zero_bytearray(buf: bytearray) -> None:
    """
    bytearray içeriğini ctypes.memset ile sıfırlar.

    Yalnızca CORE/crypto.py'nin kendi ara tamponları için değil — `bytes`
    DEĞİŞTİRİLEMEZ olduğu için tek gerçek zeroize yolu bu: hassas içeriği
    baştan bir `bytearray`de tutup iş bitince burayla sıfırlamak
    (bkz. `decrypt_file(..., zeroizable=True)`).
    """
    ctypes.memset(
        (ctypes.c_char * len(buf)).from_buffer(buf),
        0,
        len(buf),
    )


def _fmt_ts(posix: float) -> str:
    return datetime.fromtimestamp(posix, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str:
    """Dosyanın SHA-256 özetini şifrelemeden önce hesaplar."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def generate_key() -> bytes:
    """32 byte (256-bit) kriptografik rastgele anahtar üretir."""
    return os.urandom(32)


def _trailer_offset(fin: IO[bytes], file_size: int, body_start: int) -> int | None:
    """
    Zaman damgası fragmanının başladığı ofset — yoksa None.

    Sondan geriye okur: son 4 byte TRAILER_MAGIC ise ondan önceki 4 byte
    fragmanın TOPLAM uzunluğudur (iki magic ve uzunluk alanı DAHİL). O
    uzunluk kadar geri gidilip baştaki magic de doğrulanır.

    İki magic neden gerekli
    -----------------------
    Ciphertext rastgele byte'lardan oluşuyor ve sonu tesadüfen
    TRAILER_MAGIC olabilir (2⁻³²). Tek başına bu, geçerli bir dosyanın
    fragmanlı sanılmasına ve ciphertext'in kırpılmasına yol açardı.
    Uzunluk alanının işaret ettiği yerde İKİNCİ magic'i de aramak, tesadüf
    olasılığını 2⁻⁶⁴'e indiriyor ve uzunluğun tutarlı olmasını şart koşuyor.

    Bu bir güvenlik kontrolü DEĞİL, bir kaza kontrolü: fragman GCM tag'inin
    dışında olduğu için kasıtlı bir saldırgan zaten istediğini yazabilir
    (bkz. modül docstring'i, "DÜRÜST SINIR").

    Dosya imlecini oynatır; çağıran sonrasında kendi konumunu kurmalı.
    """
    # Fragman en azından gövdenin (ciphertext + tag) arkasına sığmalı.
    if file_size - body_start < _TAG_SIZE + _TRAILER_MIN_SIZE:
        return None

    fin.seek(file_size - _TRAILER_FOOTER_SIZE)
    footer = fin.read(_TRAILER_FOOTER_SIZE)
    if len(footer) != _TRAILER_FOOTER_SIZE or footer[4:] != TRAILER_MAGIC:
        return None

    (total,) = struct.unpack(">I", footer[:4])
    if total < _TRAILER_MIN_SIZE or total > file_size:
        return None

    start = file_size - total
    # Gövde en az tag kadar yer kaplamalı; fragman onun içine taşamaz.
    if start < body_start + _TAG_SIZE:
        return None

    fin.seek(start)
    if fin.read(4) != TRAILER_MAGIC:
        return None
    return start


def _read_header(fin: IO[bytes]) -> tuple[int, bytes, bytes, int]:
    """
    `.hcl` başlığını okur ve doğrular: magic, sürüm, nonce, AAD.

    Returns:
        (version, nonce, aad, body_start) — `body_start`, ciphertext'in
        başladığı ofset. Dosya imleci oraya konumlanmış olarak döner.

    Raises:
        ValueError — magic yanlış, sürüm desteklenmiyor ya da HERHANGİ bir
        alan eksik/kısa.

    Neden ortak bir fonksiyon (B-012)
    ---------------------------------
    Bu ayrıştırma `verify_file()` ve `decrypt_file()` içinde AYRI AYRI
    yazılmıştı ve zamanla ayrıştı: `verify_file` dört uzunluk kontrolü
    yapıyordu, `decrypt_file` hiçbirini. Kesik bir dosyada ikisi farklı
    davranıyordu:

        dosya                    verify_file        decrypt_file
        ─────────────────────    ───────────────    ────────────────
        b"HYCL"                  ValueError         IndexError
        b"HYCL\\x02"              ValueError         struct.error

    İkisi de belgelenmiş kümenin (ValueError / AuthenticationError /
    OSError) dışında ve çağıranların `except ValueError` ağından kaçıyordu.
    `struct.error` örneğini fuzzing buldu (`tests/fuzz/fuzz_crypto.py`).

    Kök neden dört eksik `if` değil, İKİ KOPYAYDI. Kopyaları düzeltip
    ayrı bırakmak aynı sapmayı geri getirirdi; bu yüzden tek fonksiyona
    indirildi. İkinci bir uygulamanın geri gelmesini
    `tests/test_crypto.py::test_iki_okuma_yolu_ayni_basligi_kullaniyor`
    engelliyor — B-008'de kullanılan AST denetiminin aynısı.

    `CORE/timestamp.py::read_aad` üçüncü bir okuyucu ama farklı bir işi
    var (yalnızca AAD'yi istiyor, dosyayı yazmak için açıyor) ve buraya
    çekilmedi; format değişirse ikisine de bakılmalı.
    """
    if fin.read(4) != _MAGIC:
        raise ValueError("Geçersiz HYCL dosya formatı.")

    version_byte = fin.read(1)
    if not version_byte:
        raise ValueError("Dosya çok kısa: sürüm baytı okunamadı.")
    version = version_byte[0]
    if version not in _SUPPORTED_VERSIONS:
        raise ValueError(f"Desteklenmeyen versiyon: {version}")

    nonce = fin.read(_NONCE_SIZE)
    if len(nonce) != _NONCE_SIZE:
        raise ValueError("Dosya çok kısa: nonce eksik.")

    raw_aad_len = fin.read(4)
    if len(raw_aad_len) != 4:
        raise ValueError("Dosya çok kısa: AAD uzunluğu okunamadı.")
    (aad_len,) = struct.unpack(">I", raw_aad_len)

    aad = fin.read(aad_len)
    if len(aad) != aad_len:
        raise ValueError("AAD bloğu eksik, dosya bozulmuş.")

    return version, nonce, aad, fin.tell()


def _body_end(fin: IO[bytes], file_size: int, version: int, body_start: int) -> int:
    """
    Ciphertext + GCM tag bölgesinin bittiği ofset.

    Fragman yoksa (ya da dosya v1'se) dosyanın sonu. v1'de ARAMA YAPILMAZ:
    o formatta fragman tanımlı değil ve ciphertext'in son byte'larının
    yanlışlıkla fragman sanılması için hiçbir sebep yok.

    Dosya imlecini oynatır; çağıran sonrasında kendi konumunu kurmalı.
    """
    if version < VERSION_TIMESTAMPED:
        return file_size
    offset = _trailer_offset(fin, file_size, body_start)
    return file_size if offset is None else offset


def encrypt_file(
    src: Path | str,
    key: bytes,
    user_id: int,
    *,
    hwid: str | None = None,
    created_at: str | None = None,
    uploaded_at: str | None = None,
    last_modified: str | None = None,
    dst: Path | str | None = None,
    filename: str | None = None,
) -> tuple[Path, str, str]:
    """
    src dosyasını AES-256-GCM ile şifreler, data/quarantine/<ad>.hcl'e yazar.

    Şifrelemeden önce orijinal dosyanın SHA-256 özeti hesaplanır ve
    DÖNDÜRÜLÜR (DB'ye kaydedilmesi için) — AAD'YE YAZILMAZ (B-092/B-099,
    bkz. modül docstring'i "AAD alanları").

    AAD (şifrelenmez, bütünlük koruması altında — tek karakter değişse
    decrypt_file() AuthenticationError fırlatır):
        filename        — orijinal dosya adı
        created_at      — dosya oluşturma zamanı (ISO 8601, UTC)
        uploaded_at     — sisteme eklenme zamanı (ISO 8601, UTC)
        last_modified   — dosyanın son değişiklik zamanı (ISO 8601, UTC)
        user_id         — işlemi yapan kullanıcı
        hwid            — işlemi yapan cihazın HWID'i

    created_at / last_modified verilmezse src dosyasının OS zaman damgaları kullanılır.
    uploaded_at verilmezse şifreleme anı kullanılır.

    dst / filename — yeniden şifreleme için
    ---------------------------------------
    Normalde çıktı `data/quarantine/<src.name>.hcl` ve AAD'deki `filename`
    de `src.name`'dir. İki durumda bu yetmiyor:

      · `dst` — çıktının BAŞKA bir yola yazılması gerektiğinde. Şeffaf
        erişim (CORE/checkout.py) düzenlenmiş dosyayı önce geçici bir
        yola şifreleyip `os.replace()` ile yerine koyuyor; yarıda kesilen
        bir yazma orijinal `.hcl`'i bozmasın diye.
      · `filename` — AAD'ye yazılacak ad. Yeniden şifrelemede kaynak,
        SafeZone'daki RASTGELE adlı geçici kopya; `src.name` kullanılsaydı
        belgenin gerçek adı o rastgele adla kalıcı olarak değişirdi.

    İkisi de verilmezse davranış değişmez.

    Returns:
        (hcl_path, original_sha256_hex)

    Raises:
        ValueError — anahtar 32 byte değilse
        OSError    — dosya okuma/yazma hatası
    """
    src = Path(src)
    if len(key) != 32:
        raise ValueError(f"Anahtar 32 byte olmalı, {len(key)} byte verildi.")

    # SHA-256 şifrelemeden önce hesaplanır — orijinal içeriği doğrular ve
    # DB'ye kaydedilmek üzere döndürülür. B-092/B-099: AAD'YE YAZILMIYOR —
    # AAD şifresiz olduğu için bir kopyası orada, anahtarsız bir
    # DOĞRULAMA-ORACLE'I olurdu (bkz. modül docstring'i, "AAD alanları").
    sha256_hex = _sha256_file(src)

    stat = src.stat()
    metadata = {
        "filename": filename or src.name,
        "created_at": created_at or _fmt_ts(stat.st_ctime),
        "uploaded_at": uploaded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_modified": last_modified or _fmt_ts(stat.st_mtime),
        "user_id": user_id,
        "hwid": hwid,
    }

    dst = Path(dst) if dst is not None else _QUARANTINE_DIR / f"{src.name}.hcl"
    dst.parent.mkdir(parents=True, exist_ok=True)

    nonce = os.urandom(_NONCE_SIZE)
    aad = json.dumps(metadata, ensure_ascii=False, sort_keys=True).encode()

    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(aad)

    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(_MAGIC)
        fout.write(bytes([_VERSION]))
        fout.write(nonce)
        fout.write(struct.pack(">I", len(aad)))
        fout.write(aad)

        while chunk := fin.read(_CHUNK):
            fout.write(encryptor.update(chunk))
        fout.write(encryptor.finalize())
        fout.write(encryptor.tag)

    return dst, sha256_hex, aad.decode()


@overload
def verify_file(
    src: Path | str,
    key: bytes,
    *,
    hwid: str | None = None,
    return_sha256: Literal[False] = False,
) -> dict: ...


@overload
def verify_file(
    src: Path | str,
    key: bytes,
    *,
    hwid: str | None = None,
    return_sha256: Literal[True],
) -> tuple[dict, str]: ...


def verify_file(
    src: Path | str,
    key: bytes,
    *,
    hwid: str | None = None,
    return_sha256: bool = False,
) -> dict | tuple[dict, str]:
    """
    .hcl dosyasının GCM doğrulamasını yapar — DÜZ METNİ DÖNDÜRMEZ.

    Bütünlük taramasının (CORE/integrity.py) kullandığı dar doğrulama yolu.
    Sözleşmesi decrypt_file() ile aynıdır, tek farkı düz metni vermemesi:
    aynı istisnaları aynı koşullarda fırlatır.

    Args:
        return_sha256: True verilirse, akan blok üzerinden (biriktirmeden —
            aşağıdaki "DÜRÜST SINIR" bölümüyle AYNI ilke) düz metnin
            SHA-256'sı da hesaplanır ve `(meta, sha256_hex)` olarak
            döndürülür. B-092/B-099: `encrypt_file()` artık bu özeti AAD'ye
            YAZMIYOR (anahtarsız bir doğrulama-oracle'ı olmasın diye) —
            `CORE/timestamp.py` gibi GERÇEK, doğrulanmış özete ihtiyaç
            duyan çağıranlar bunu kullanmalı. Varsayılan `False`: mevcut
            çağıranların (CORE/backup.py, CORE/integrity.py) çoğu yalnızca
            GCM tag'ini önemsiyor, ek bir özet geçişinin maliyetini
            ÖDEMEMELİ.

    Returns:
        `return_sha256=False` (varsayılan): metadata_dict — AAD içeriği.
        Düz metin DEĞİL; AAD zaten dosya başlığında şifresiz duruyor (bkz.
        SECURITY.md §3, "Metadata gizliliği"), dolayısıyla döndürmek yeni
        bir şey açığa çıkarmaz.

        `return_sha256=True`: `(metadata_dict, sha256_hex)` — ikinci
        değer düz metnin GERÇEKTEN bu çağrıda, bu anahtarla doğrulanmış
        özeti.

    Neden decrypt_file() ÇAĞRILMIYOR
    --------------------------------
    decrypt_file() tasarımı gereği `bytes(buf)` döndürür: dosyanın tamamı
    düz metin olarak bellekte, üstelik immutable bir nesnede. Kendi ara
    tamponunu (`buf`) `finally` içinde sıfırlıyor ama DÖNDÜRDÜĞÜ kopyayı
    sıfırlayamaz — `bytes` değiştirilemez. Yalnızca tag'i kontrol etmek için
    onu çağırmak üç bedel getirirdi:

      1. Dosyanın tamamı düz metin olarak, silinemeyen bir nesnede belliğe
         açılır. 2 GB'lık bir dosya 2 GB RAM demek; haftalık tarama binlerce
         dosyayı geziyor.
      2. O kopya çöp toplayıcı onu geri alana kadar heap'te kalır ve
         SECURITY.md §3'ün "bellek dökümü düz metin içerebilir" maddesini
         hiç gerek yokken büyütür.
      3. Doğrulamanın maliyeti dosya boyutuyla birlikte belleğe de yansır;
         oysa akış hâlinde doğrulamanın bellek maliyeti sabittir.

    Bu yüzden burada AYNI kripto ilkelleri (Cipher / GCM / AAD) kullanılıyor
    ama düz metin BİRİKTİRİLMİYOR: her blok yeniden kullanılan tek bir
    tampona yazılıp bir sonraki blokla üzerine yazılıyor, çıkışta da
    ctypes.memset ile sıfırlanıyor. GCM'i elle yazmak SÖZ KONUSU DEĞİL —
    tag doğrulaması cryptography kütüphanesinin finalize()'ına ait.

    DÜRÜST SINIR — düz metin "hiç oluşmuyor" değil
    ----------------------------------------------
    GCM'de tag, ciphertext'in tamamı işlendikten sonra doğrulanır; akış
    API'sinde update() çağrısı düz metni ÜRETİR. Yani doğrulama sırasında
    her 64 KB'lık blok kısa süreliğine düz metin olarak `_scratch` içinde
    bulunur. İddia şudur: düz metin hiçbir zaman biriktirilmez, döndürülmez,
    diske yazılmaz ve tampon çıkışta sıfırlanır — "hiç var olmaz" değil.

    Düz metni hiç üretmemek teorik olarak mümkün (tag, GHASH(AAD, C) ile
    ciphertext üzerinden hesaplanabilir) ama bu GHASH'i elle yazmak demek.
    Kendi GCM'ini yazmanın riski, üzerine hemen yazılan 64 KB'lık geçici bir
    tampondan çok daha büyüktür. Takas bilinçli.

    Raises:
        ValueError          — bozuk başlık, desteklenmeyen versiyon, kısa dosya
        AuthenticationError — ciphertext, anahtar veya AAD değiştirilmiş
        OSError             — dosya okuma hatası
    """
    src = Path(src)
    if len(key) != 32:
        raise ValueError(f"Anahtar 32 byte olmalı, {len(key)} byte verildi.")

    with open(src, "rb") as fin:
        version, nonce, aad, body_start = _read_header(fin)
        file_size = fin.seek(0, 2)
        # Zaman damgası fragmanı varsa gövde ondan ÖNCE bitiyor; fragman
        # byte'ları ciphertext sanılırsa GCM doğrulaması hatalı biçimde
        # düşer ve sağlam bir dosya "bozuk" damgası yer.
        body_end = _body_end(fin, file_size, version, body_start)
        ciphertext_len = body_end - body_start - _TAG_SIZE
        if ciphertext_len < 0:
            raise ValueError("Dosya çok kısa, bozulmuş olabilir.")

        fin.seek(body_end - _TAG_SIZE)
        tag = fin.read(_TAG_SIZE)
        fin.seek(body_start)

        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(aad)

        # Tek, yeniden kullanılan tampon. update_into() düz metni buraya
        # yazar; bir sonraki blok üzerine yazar, çıkışta memset'lenir.
        # update_into sözleşmesi: tampon >= len(veri) + blok_boyu - 1.
        scratch = bytearray(_CHUNK + _BLOCK_SLACK)
        # `return_sha256=False` (varsayılan): dönen uzunluk BİLEREK
        # kullanılmıyor, düz metin okunmuyor, yalnızca GCM durumunun
        # ilerlemesi için yazılıyor. `return_sha256=True`: hasher YALNIZCA
        # kendi iç özet durumunu (64-128 bayt) tutuyor, tampondaki düz
        # metnin bir KOPYASINI değil — "biriktirmeme" ilkesi bozulmuyor.
        hasher = hashlib.sha256() if return_sha256 else None
        try:
            view = memoryview(scratch)
            remaining = ciphertext_len
            while remaining > 0:
                chunk = fin.read(min(_CHUNK, remaining))
                if not chunk:
                    raise ValueError("Ciphertext beklenenden kısa, dosya kesilmiş.")
                n = decryptor.update_into(chunk, view)
                if hasher is not None:
                    hasher.update(view[:n])
                remaining -= len(chunk)
            try:
                decryptor.finalize()
            except InvalidTag as exc:
                raise AuthenticationError(
                    "Dosya veya metadata bütünlüğü doğrulanamadı — "
                    "şifreli içerik, anahtar veya AAD değiştirilmiş olabilir."
                ) from exc
        finally:
            # memoryview, bytearray üzerinde dışa aktarılmış tampon tutuyor;
            # ctypes.memset from_buffer() için serbest bırakılması gerekir.
            view.release()
            zero_bytearray(scratch)

        meta = json.loads(aad.decode())
        if hwid is not None and meta.get("hwid") is not None and meta["hwid"] != hwid:
            raise AuthenticationError(
                "HWID uyuşmazlığı — dosya farklı bir cihazda şifrelendi."
            )
        if hasher is not None:
            return meta, hasher.hexdigest()
        return meta


@overload
def decrypt_file(
    src: Path | str,
    key: bytes,
    *,
    hwid: str | None = None,
    zeroizable: Literal[False] = False,
) -> tuple[bytes, dict]: ...


@overload
def decrypt_file(
    src: Path | str,
    key: bytes,
    *,
    hwid: str | None = None,
    zeroizable: Literal[True],
) -> tuple[bytearray, dict]: ...


def decrypt_file(
    src: Path | str,
    key: bytes,
    *,
    hwid: str | None = None,
    zeroizable: bool = False,
) -> tuple[bytes, dict] | tuple[bytearray, dict]:
    """
    data/quarantine/ içindeki .hcl dosyasını çözer.

    Returns:
        (plaintext, metadata_dict)
        plaintext: varsayılan `bytes` — işin bitince referansı kaldır:
            del content
        `zeroizable=True` verilirse `bytearray` — çağıran işi bitince
            `zero_bytearray(content)` ile GERÇEKTEN sıfırlayabilir
            (bkz. aşağıdaki "Bellek güvenliği").

    Bellek güvenliği:
        Ara çözümleme tamponu HER ZAMAN `bytearray` ve iş bitince
        `zero_bytearray()` ile ctypes.memset üzerinden sıfırlanır — ama
        varsayılan modda DÖNDÜRÜLEN kopya `bytes(buf)`, yani AYRI bir
        bellek bölgesi: `bytes` DEĞİŞTİRİLEMEZ olduğu için o kopya asla
        sıfırlanamaz, çağıranın elinden tek çıkış yolu referansı
        kaldırmak (`del content`) ve çöp toplayıcıya güvenmek — bkz.
        `CORE/export.py` modül docstring'i, "Düz metin diske yazılıyor".

        `zeroizable=True` bu sınırı KALDIRMIYOR, farklı bir sınır
        seçiyor: `bytes(buf)` kopyası hiç ÜRETİLMİYOR, çözümlemenin
        kullandığı AYNI `bytearray` çağırana döndürülüyor. Çağıran işini
        bitirince `zero_bytearray(content)` çağırırsa döndürülen
        tampondaki plaintext GERÇEKTEN, geri alınamaz biçimde
        sıfırlanır — normal modda mümkün olmayan bir garanti. Bedeli:
        `bytes` değil `bytearray` almak — `hedef.write_bytes(...)` ve
        benzeri bytes-benzeri arayüzler bytearray'i sorunsuz kabul
        ediyor, ama `==` ile sabit bir `bytes` değeriyle karşılaştırma
        hâlâ çalışır (bytearray/bytes karşılaştırması içerik bazlı).

            content, meta = decrypt_file(path, key)
            try:
                ...  # içeriği işle
            finally:
                del content

            # ya da gerçek sıfırlama isteniyorsa:
            content, meta = decrypt_file(path, key, zeroizable=True)
            try:
                ...
            finally:
                zero_bytearray(content)
                del content

    Raises:
        ValueError          — bozuk başlık veya desteklenmeyen versiyon
        AuthenticationError — ciphertext, anahtar veya AAD metadata değiştirilmiş
        OSError             — dosya okuma hatası
    """
    src = Path(src)
    if len(key) != 32:
        raise ValueError(f"Anahtar 32 byte olmalı, {len(key)} byte verildi.")

    with open(src, "rb") as fin:
        version, nonce, aad, body_start = _read_header(fin)
        file_size = fin.seek(0, 2)
        # Fragman varsa gövde ondan önce bitiyor — bkz. verify_file().
        body_end = _body_end(fin, file_size, version, body_start)
        ciphertext_len = body_end - body_start - _TAG_SIZE
        if ciphertext_len < 0:
            raise ValueError("Dosya çok kısa, bozulmuş olabilir.")

        fin.seek(body_end - _TAG_SIZE)
        tag = fin.read(_TAG_SIZE)
        fin.seek(body_start)

        decryptor = Cipher(
            algorithms.AES(key), modes.GCM(nonce, tag)
        ).decryptor()
        decryptor.authenticate_additional_data(aad)

        # bytearray: mutable — finally bloğunda ctypes.memset ile sıfırlanabilir
        buf = bytearray()
        # `return buf, meta` (zeroizable=True) durumunda finally'nin buf'ı
        # sıfırlamaMASI gerekiyor — döndürdüğümüz değer TAM OLARAK buf'ın
        # kendisi (kopya değil), finally return'den SONRA değil ÖNCE
        # çalışır, yani sıfırlarsak çağıranın eline sıfırlanmış bir
        # tampon geçerdi. Bu bayrak yalnızca "başarıyla, zeroizable=True
        # ile döndük" durumunda True olur — hata yolunda (return'e hiç
        # ulaşılmadan exception fırlarsa) daima False kalır, yani buf
        # yine sıfırlanır.
        buf_cagirana_devrediliyor = False
        try:
            remaining = ciphertext_len
            while remaining > 0:
                chunk = fin.read(min(_CHUNK, remaining))
                buf.extend(decryptor.update(chunk))
                remaining -= len(chunk)
            try:
                buf.extend(decryptor.finalize())
            except InvalidTag as exc:
                raise AuthenticationError(
                    "Dosya veya metadata bütünlüğü doğrulanamadı — "
                    "şifreli içerik, anahtar veya AAD değiştirilmiş olabilir."
                ) from exc
            meta = json.loads(aad.decode())
            if (
                hwid is not None
                and meta.get("hwid") is not None
                and meta["hwid"] != hwid
            ):
                raise AuthenticationError(
                    "HWID uyuşmazlığı — dosya farklı bir cihazda şifrelendi."
                )
            if zeroizable:
                buf_cagirana_devrediliyor = True
                return buf, meta
            return bytes(buf), meta
        finally:
            # Hata ya da başarı fark etmeksizin ara tamponu sıfırla —
            # TEK istisna: buf'ın kendisi az önce çağırana döndürüldüyse.
            if buf and not buf_cagirana_devrediliyor:
                zero_bytearray(buf)
