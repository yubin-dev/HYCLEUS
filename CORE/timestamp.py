"""
HYCLEUS — RFC 3161 güvenilir zaman damgası (adım 1: format + damgalama)

Bir `.hcl` dosyasının DÜZ METİN SHA-256 özetini bir Zaman Damgası
Otoritesi'ne (TSA) imzalatır ve dönen token'ı dosyanın sonuna, ayrı bir
fragman olarak yazar. Kanıtladığı şey tek cümleyle: *"bu içerik, TSA'nın
imzaladığı tarihte zaten vardı."*

Bu adımın KAPSAMI
-----------------
Yalnızca (a) kap formatı ve (b) damgalama akışı. Token'ın imzasının
ÇEVRİMDIŞI DOĞRULANMASI, Merkle ağacı ve arayüz düğmesi SONRAKİ adımlar —
burada bilinçli olarak yok. Bugün token alınıyor, biçimsel tutarlılığı
(status, imprint, nonce, algoritma) kontrol ediliyor ve saklanıyor;
imzasının TSA'nın sertifikasıyla eşleştiği HENÜZ doğrulanmıyor.

Bu sınır, yanlış bir güven duygusu yaratmasın diye açıkça yazılıyor:
şu anki hâliyle fragman, TSA'nın verdiğini SAKLIYOR, doğrulamıyor.


Neden düz metnin özeti damgalanıyor, ciphertext'in değil
--------------------------------------------------------
Damgalanan özet İÇERİĞİ kanıtlamalı, içeriğin o anki şifreli temsilini
değil. Aynı belge yeni bir nonce'la yeniden şifrelendiğinde ciphertext
tümüyle değişir — ciphertext özeti damgalansaydı damga da geçersizleşir,
oysa belge aynı belgedir. Düz metin özeti anahtar rotasyonundan, yeniden
şifrelemeden ve format değişikliklerinden bağımsız kalıyor.

Gizlilik bedeli yok: SHA-256 tek yönlüdür, özetin TSA'ya gitmesi içeriği
açığa çıkarmaz. RFC 3161 zaten bunun için tasarlanmış — protokol asla
belgenin kendisini istemiyor, yalnızca "message imprint" denen özeti.

Özet YENİDEN HESAPLANMIYOR
--------------------------
`encrypt_file()` düz metnin SHA-256'sını şifrelemeden önce hesaplayıp
AAD'ye yazıyor (`original_sha256`). Damgalama onu OKUYOR. Sonuç, bu
modülün en önemli özelliği:

    **Damgalama anahtar İSTEMEZ ve düz metne HİÇ dokunmaz.**

AAD dosya başlığında şifresiz duruyor; damgalamak için dosyayı çözmek
şöyle dursun, oturum anahtarının varlığı bile gerekmiyor. `verify_file()`
için yazılan "düz metni gereksiz yere maruz bırakma" ilkesi burada
kendiliğinden sağlanıyor.

Karşılığında bir sınır var: AAD'nin bütünlüğünü GCM tag'i koruyor ve onu
doğrulamak anahtar ister. Anahtarsız damgalarken `original_sha256`
DOĞRULANMAMIŞ bir alandır. Bu yüzden `timestamp_file()` opsiyonel bir
`key` alıyor: verilirse önce `verify_file()` çalışıyor, yani damga
gerçekten o dosyanın içeriğine bağlanıyor. Verilmezse damga "AAD'nin iddia
ettiği özet" için alınmış olur — çağıranın bilinçli tercihi.


TS_TRAILER biçimi
-----------------
Uzunluk-önekli, deterministik ikili kodlama. `CORE/audit_chain.py` ile aynı
yaklaşım: ayırıcı karakter yok, her alanın önünde uzunluğu var, alan SIRASI
şemanın kendisi. JSON KULLANILMIYOR — token ham DER ve ikili; JSON'a
gömmek base64 (%33 şişme) ve anahtar sırası garantisi gerektirirdi.

    [4B ] TRAILER_MAGIC   = b'HTST'
    [1B ] trailer_version = 0x01
    [4B ] len + hash_algorithm   (utf-8, "sha256")
    [4B ] len + hashed_hex       (utf-8, 64 karakter, damgalanan özet)
    [4B ] len + tsa_url          (utf-8, damgayı veren TSA)
    [4B ] len + token_der        (RFC 3161 TimeStampToken, DER)
    [4B ] toplam uzunluk (big-endian uint32 — bu fragmanın TAMAMI)
    [4B ] TRAILER_MAGIC   = b'HTST'

`hashed_hex` fragmanda AYRICA tutuluyor, token'ın içinden de okunabilecek
olmasına rağmen: fragmanın AAD ile eşleşip eşleşmediğini ASN.1 ayrıştırmadan
kontrol edebilmek için. Tutarsızlık olursa token yine de yetkilidir.

Sondaki uzunluk + magic, fragmanın dosya sonundan geriye doğru
bulunabilmesini sağlıyor; gerekçesi `CORE/crypto.py::_trailer_offset`.


Bağımlılık: asn1crypto — neden rfc3161-client değil
---------------------------------------------------
İki aday da tek paket ekliyor ve ikisinin de yeni geçişli bağımlılığı yok
(rfc3161-client yalnızca zaten kurulu olan `cryptography`'yi istiyor). Yani
sayı eşit; karar başka bir yerden geldi.

`rfc3161-client`'ın istek üreten TEK giriş noktası HAM VERİYİ alıp özeti
kendi hesaplıyor (`TimestampRequestBuilder().data(...)`). Önceden
hesaplanmış bir özetten istek kurmanın yolu yok. Bu, yukarıdaki tasarımın
tam tersi olurdu: AAD'de HAZIR duran özeti yeniden üretmek için dosyanın
tamamını çözüp düz metni kütüphaneye vermek gerekirdi — hem anahtar
zorunlu hâle gelir hem düz metin maruziyeti geri gelirdi.

`asn1crypto` message imprint'i doğrudan bir özetten kurmaya izin veriyor;
ayrıca saf Python (derlenmiş tekerlek yok, iki CI ayağı için de platform
yüzeyi eklemiyor), sıfır bağımlılık ve MIT (proje MIT).

Bunun bedeli dürüstçe şu: asn1crypto YALNIZCA ASN.1 ayrıştırıyor. İmza
doğrulaması (sonraki adım) bize kalıyor — rfc3161-client'ın hazır bir
`Verifier`'ı vardı. Ama o iş kendi kriptografisini yazmak DEĞİL, ASN.1
tesisatı: imza doğrulamasının kendisi zaten `cryptography`'nin
`public_key.verify()`'ına düşecek.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from asn1crypto import algos, core, tsp

from CORE.crypto import (
    _MAGIC,
    _trailer_offset,
    TRAILER_MAGIC,
    VERSION_TIMESTAMPED,
    verify_file,
)

_log = logging.getLogger("hycleus.timestamp")

#: Fragman şeması sürümü — kap sürümünden (0x02) BAĞIMSIZ. Fragmanın iç
#: düzeni değişirse bu artar, kap formatı değişmek zorunda kalmaz.
TRAILER_VERSION = 1

#: Damgalamada kullanılan özet algoritması. AAD'deki original_sha256 ile
#: aynı olmak ZORUNDA — hazır özeti kullanmanın önkoşulu bu.
HASH_ALGORITHM = "sha256"

#: TSA adresinin okunduğu ayar anahtarı (bkz. `tsa_url`).
TSA_URL_SETTING = "tsa_url"

#: Geliştirme/test varsayılanı. freetsa.org ücretsiz ve kayıt istemiyor;
#: üretimde kurumun kendi TSA'sıyla değiştirilmeli — bu yüzden sabit
#: kodlanmıyor, ayarlardan geliyor.
DEFAULT_TSA_URL = "https://freetsa.org/tsr"

_CONTENT_TYPE = "application/timestamp-query"
_ACCEPT_TYPE = "application/timestamp-reply"

#: TSA ağ zaman aşımı (saniye). Damgalama kullanıcı tetiklemeli bir işlem;
#: yanıt vermeyen bir TSA arayüzü süresiz bekletmemeli.
TSA_TIMEOUT = 30

#: Kabul edilen en büyük TSA yanıtı. Sertifika zinciriyle birlikte gerçek
#: token'lar ~5 KB; 256 KB, kötü niyetli ya da bozuk bir sunucunun belleği
#: doldurmasına karşı üst sınır.
_MAX_RESPONSE_BYTES = 256 * 1024

#: RFC 3161 §2.4.2: yalnızca bu ikisi damganın verildiği anlamına gelir.
_GRANTED = frozenset({"granted", "granted_with_mods"})

#: Damgalama sırasında kullanılan geçici dosyanın uzantısı.
_TMP_SUFFIX = ".hcl-ts-tmp"


class TimestampError(Exception):
    """Damgalama akışının herhangi bir adımı başarısız olduğunda fırlar."""


@dataclass(frozen=True)
class TimestampInfo:
    """Bir dosyanın zaman damgası fragmanının çözülmüş hâli."""

    hash_algorithm: str
    hashed_hex: str
    tsa_url: str
    token_der: bytes


# ══════════════════════════════════════════════════════════════════════════════
# 1. Fragman kodlama / çözme
# ══════════════════════════════════════════════════════════════════════════════


def _put(raw: bytes) -> bytes:
    """Uzunluk-önekli alan: [4B uzunluk][veri]."""
    return struct.pack(">I", len(raw)) + raw


def _take(buf: bytes, pos: int) -> tuple[bytes, int]:
    """Uzunluk-önekli alanı okur; (veri, yeni_konum) döndürür."""
    if pos + 4 > len(buf):
        raise TimestampError("Fragman kesilmiş: uzunluk alanı okunamadı.")
    (size,) = struct.unpack(">I", buf[pos : pos + 4])
    pos += 4
    if pos + size > len(buf):
        raise TimestampError(f"Fragman kesilmiş: {size} byte'lık alan eksik.")
    return buf[pos : pos + size], pos + size


def encode_trailer(info: TimestampInfo) -> bytes:
    """
    TimestampInfo'yu ikili fragmana çevirir — bkz. modül docstring'i.

    Deterministik: aynı girdi her zaman byte-byte aynı çıktıyı verir.
    Toplam uzunluk alanı, kendisi ve iki magic DAHİL fragmanın tamamını
    sayar; `_trailer_offset` bu sayıya güvenerek geriye gidiyor.
    """
    body = (
        TRAILER_MAGIC
        + bytes([TRAILER_VERSION])
        + _put(info.hash_algorithm.encode("utf-8"))
        + _put(info.hashed_hex.encode("utf-8"))
        + _put(info.tsa_url.encode("utf-8"))
        + _put(info.token_der)
    )
    total = len(body) + 8  # + toplam uzunluk alanı (4) + kapanış magic (4)
    return body + struct.pack(">I", total) + TRAILER_MAGIC


def decode_trailer(raw: bytes) -> TimestampInfo:
    """
    Ham fragman byte'larını çözer.

    Raises:
        TimestampError — magic tutmuyor, sürüm bilinmiyor ya da alanlar kesik.
    """
    if len(raw) < 5 or raw[:4] != TRAILER_MAGIC:
        raise TimestampError("Fragman TRAILER_MAGIC ile başlamıyor.")
    if raw[-4:] != TRAILER_MAGIC:
        raise TimestampError("Fragman TRAILER_MAGIC ile bitmiyor.")

    version = raw[4]
    if version != TRAILER_VERSION:
        raise TimestampError(
            f"Desteklenmeyen fragman sürümü: {version} "
            f"(bu sürüm {TRAILER_VERSION} okuyor)"
        )

    alg, pos = _take(raw, 5)
    hashed, pos = _take(raw, pos)
    url, pos = _take(raw, pos)
    token, pos = _take(raw, pos)

    # Alanlardan sonra yalnızca [4B uzunluk][4B magic] kalmalı. Fazlası,
    # fragmanın bu sürümün beklediğinden farklı yazıldığı anlamına gelir.
    if pos != len(raw) - 8:
        raise TimestampError(
            f"Fragmanda beklenmeyen {len(raw) - 8 - pos} byte artık veri."
        )

    return TimestampInfo(
        hash_algorithm=alg.decode("utf-8"),
        hashed_hex=hashed.decode("utf-8"),
        tsa_url=url.decode("utf-8"),
        token_der=token,
    )


def read_trailer(path: Path | str) -> TimestampInfo | None:
    """
    Dosyadaki zaman damgası fragmanını okur — damgalanmamışsa None.

    "None" iki durumu birden kapsıyor: dosya hiç damgalanmamış ya da
    fragmanı silinmiş. İkisi ayırt EDİLEMEZ; gerekçesi CORE/crypto.py
    modül docstring'indeki "DÜRÜST SINIR" bölümünde.
    """
    path = Path(path)
    with open(path, "rb") as fin:
        if fin.read(4) != _MAGIC:
            raise TimestampError("Geçersiz HYCL dosya formatı.")
        version_byte = fin.read(1)
        if not version_byte:
            raise TimestampError("Dosya çok kısa, bozulmuş olabilir.")
        if version_byte[0] < VERSION_TIMESTAMPED:
            return None  # v1 fragman taşıyamaz

        body_start = _header_end(fin)
        file_size = fin.seek(0, 2)
        offset = _trailer_offset(fin, file_size, body_start)
        if offset is None:
            return None
        fin.seek(offset)
        return decode_trailer(fin.read(file_size - offset))


def _header_end(fin: Any) -> int:
    """
    Başlığın bittiği (ciphertext'in başladığı) ofset.

    İmleç versiyon byte'ından SONRA olmalı; nonce ve AAD atlanarak
    ilerlenir.
    """
    fin.seek(5 + 12)  # magic(4) + sürüm(1) + nonce(12)
    raw_len = fin.read(4)
    if len(raw_len) != 4:
        raise TimestampError("Dosya çok kısa, AAD uzunluğu okunamadı.")
    (aad_len,) = struct.unpack(">I", raw_len)
    return 21 + aad_len


def read_aad(path: Path | str) -> dict:
    """
    Dosyanın AAD metadata'sını anahtar OLMADAN okur.

    AAD şifresiz saklanıyor (bkz. SECURITY.md §3), dolayısıyla bu yeni bir
    şey açığa çıkarmıyor. Damgalamanın `original_sha256`'yı buradan alması
    ve dosyayı hiç çözmemesi bu sayede mümkün.

    UYARI: burada okunan AAD DOĞRULANMAMIŞTIR. Bütünlüğünü GCM tag'i
    koruyor ama onu kontrol etmek anahtar ister — bkz. modül docstring'i.
    """
    path = Path(path)
    with open(path, "rb") as fin:
        if fin.read(4) != _MAGIC:
            raise TimestampError("Geçersiz HYCL dosya formatı.")
        if not fin.read(1):
            raise TimestampError("Dosya çok kısa, bozulmuş olabilir.")
        fin.seek(5 + 12)
        raw_len = fin.read(4)
        if len(raw_len) != 4:
            raise TimestampError("Dosya çok kısa, AAD uzunluğu okunamadı.")
        (aad_len,) = struct.unpack(">I", raw_len)
        aad = fin.read(aad_len)
        if len(aad) != aad_len:
            raise TimestampError("AAD bloğu eksik, dosya bozulmuş.")
    try:
        meta = json.loads(aad.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TimestampError(f"AAD ayrıştırılamadı: {exc}") from exc
    if not isinstance(meta, dict):
        raise TimestampError("AAD bir JSON nesnesi değil.")
    return meta


def attach_trailer(path: Path | str, info: TimestampInfo) -> None:
    """
    Fragmanı dosyaya yazar; gerekiyorsa kap sürümünü v2'ye yükseltir.

    Neden yerinde ekleme (append) DEĞİL
    -----------------------------------
    Yarım kalmış bir append, dosyayı SESSİZCE BOZUK gösterirdi: eksik
    fragmanda kapanış magic'i bulunmaz, `_trailer_offset` "fragman yok"
    der ve artık byte'lar ciphertext'in parçası sayılır — GCM doğrulaması
    düşer, haftalık bütünlük taraması sağlam dosyayı "bozuk" olarak
    işaretler. Elektrik kesintisi kadar sıradan bir olay veri kaybı
    alarmına dönüşürdü.

    Bu yüzden yazma önce geçici bir kopyaya yapılıp `os.replace()` ile
    yerine konuyor: aynı dizinde, dolayısıyla aynı dosya sisteminde ve
    hem POSIX hem Windows'ta atomik. Yarıda kesilirse geriye yalnızca
    artık bir geçici dosya kalır, orijinal dosyaya hiç dokunulmamış olur.

    Bedeli bir tam dosya kopyası. Damgalama dosya başına bir kez yapılan,
    kullanıcı tetiklemeli bir işlem olduğu için bu takas bilinçli:
    veri güvenliği, tek seferlik I/O maliyetinden önce geliyor.
    """
    path = Path(path)
    tmp = path.with_suffix(path.suffix + _TMP_SUFFIX)
    try:
        shutil.copyfile(path, tmp)
        with open(tmp, "r+b") as fout:
            if fout.read(4) != _MAGIC:
                raise TimestampError("Geçersiz HYCL dosya formatı.")
            version = fout.read(1)[0]
            if version < VERSION_TIMESTAMPED:
                # Sürüm byte'ı GCM tag'inin KAPSAMINDA DEĞİL (AAD yalnızca
                # JSON metadata) — tek byte'ı değiştirmek doğrulamayı
                # etkilemiyor. v1 bırakılsaydı okuyucu fragmanı hiç aramaz,
                # artık byte'lar ciphertext sanılırdı.
                fout.seek(4)
                fout.write(bytes([VERSION_TIMESTAMPED]))
                _log.info("%s: kap sürümü v%d → v%d", path.name, version,
                          VERSION_TIMESTAMPED)
            fout.seek(0, 2)
            fout.write(encode_trailer(info))
            fout.flush()
            os.fsync(fout.fileno())
        os.replace(tmp, path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


# ══════════════════════════════════════════════════════════════════════════════
# 2. RFC 3161 istek / yanıt
# ══════════════════════════════════════════════════════════════════════════════


def build_request(digest: bytes, *, nonce: int | None = None) -> tuple[bytes, int]:
    """
    Verilen özetten DER kodlu bir TimeStampReq üretir.

    Args:
        digest: HAZIR SHA-256 özeti (32 byte ham). Yeniden hesaplanmıyor —
            modül docstring'ine bakın.
        nonce: Test edilebilirlik için dışarıdan verilebilir; normalde
            rastgele üretilir.

    Returns:
        (der_bytes, nonce)

    Nonce neden var
    ---------------
    RFC 3161 §2.4.1: istekteki nonce yanıtta aynen dönmeli. Bu, TSA'nın
    (ya da araya girenin) ELDEKİ ESKİ bir yanıtı tekrar oynatmasını
    engelliyor — nonce eşleşmiyorsa yanıt bu isteğe ait değildir.

    cert_req neden True
    -------------------
    TSA'nın imzalama sertifikasını token'ın içine koymasını istiyor.
    Olmasaydı çevrimdışı doğrulama (sonraki adım) sertifikayı başka bir
    yerden bulmak zorunda kalırdı; damganın kendi kendine yeter olması
    tam da amaç.
    """
    if len(digest) != hashlib.sha256().digest_size:
        raise TimestampError(
            f"SHA-256 özeti 32 byte olmalı, {len(digest)} byte verildi."
        )
    if nonce is None:
        nonce = int.from_bytes(os.urandom(8), "big")

    request = tsp.TimeStampReq({
        "version": "v1",
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": HASH_ALGORITHM}),
            "hashed_message": digest,
        }),
        "nonce": core.Integer(nonce),
        "cert_req": True,
    })
    return request.dump(), nonce


def parse_response(der: bytes, *, digest: bytes, nonce: int) -> bytes:
    """
    TSA yanıtını doğrular ve içindeki TimeStampToken'ı DER olarak döndürür.

    Yapılan kontroller — hepsi BİÇİMSEL, imza doğrulaması bu adımda YOK
    (bkz. modül docstring'i, "Bu adımın KAPSAMI"):

      1. Yanıt ayrıştırılabiliyor mu ve status "granted" mı
      2. Damgalanan imprint BİZİM özetimiz mi — TSA'nın başka bir şeyi
         damgalayıp geri göndermesine karşı
      3. Nonce isteğimizle aynı mı — tekrar oynatmaya karşı
      4. Özet algoritması beklediğimiz mi

    "Token yok" için AYRI bir kontrol yok: RFC 3161'de timeStampToken
    opsiyonel olsa da asn1crypto'nun TimeStampResp şeması onu zorunlu
    sayıyor, dolayısıyla tokensiz bir yanıt daha ayrıştırma aşamasında
    düşüyor. Ayrı bir `if` yazmak ulaşılamayan kod olurdu; testi
    (`test_granted_without_a_token_is_rejected`) bu davranışı sabitliyor.

    Raises:
        TimestampError — yukarıdakilerden biri tutmazsa.
    """
    try:
        response = tsp.TimeStampResp.load(der)
        status = response["status"]["status"].native
    except Exception as exc:
        raise TimestampError(f"TSA yanıtı ayrıştırılamadı: {exc}") from exc

    if status not in _GRANTED:
        # failInfo varsa nedeni söylüyor; yoksa yalnızca status kalıyor.
        detail = ""
        try:
            info = response["status"]["fail_info"].native
            if info:
                detail = f" (fail_info={info})"
        except Exception:  # pragma: no cover — opsiyonel alan
            pass
        raise TimestampError(f"TSA damgayı vermedi: status={status}{detail}")

    try:
        token = response["time_stamp_token"]
        tst_info = token["content"]["encap_content_info"]["content"].parsed
        imprint = tst_info["message_imprint"]
        stamped = imprint["hashed_message"].native
        algorithm = imprint["hash_algorithm"]["algorithm"].native
        got_nonce = tst_info["nonce"].native
    except Exception as exc:
        raise TimestampError(f"TSTInfo okunamadı: {exc}") from exc

    if stamped != digest:
        raise TimestampError(
            "TSA başka bir özeti damgalamış — "
            f"beklenen {digest.hex()}, gelen {bytes(stamped).hex()}"
        )
    if algorithm != HASH_ALGORITHM:
        raise TimestampError(
            f"TSA farklı bir özet algoritması kullanmış: {algorithm}"
        )
    if got_nonce != nonce:
        raise TimestampError(
            f"Nonce uyuşmuyor — istek {nonce}, yanıt {got_nonce}. "
            "Yanıt bu isteğe ait değil (tekrar oynatma olabilir)."
        )

    return bytes(token.dump())


def _http_post(url: str, body: bytes, timeout: int) -> bytes:
    """Gerçek TSA çağrısı. Testler bunun yerine kendi taşıyıcısını verir."""
    import requests  # ağ kullanılmayan yollarda import maliyeti olmasın

    response = requests.post(
        url,
        data=body,
        headers={"Content-Type": _CONTENT_TYPE, "Accept": _ACCEPT_TYPE},
        timeout=timeout,
    )
    if response.status_code != 200:
        raise TimestampError(
            f"TSA HTTP {response.status_code} döndürdü ({url})"
        )
    content = response.content
    if len(content) > _MAX_RESPONSE_BYTES:
        raise TimestampError(
            f"TSA yanıtı çok büyük: {len(content)} byte "
            f"(sınır {_MAX_RESPONSE_BYTES})"
        )
    return content


def tsa_url(db: Any) -> str:
    """
    Ayarlardan TSA adresini okur; yoksa DEFAULT_TSA_URL.

    Şema doğrulaması var: ayar tablosuna `file://` ya da `ftp://` yazılması
    damgalamayı bir yerel dosya okuyucusuna çevirebilirdi.
    """
    raw = (db.get_setting(TSA_URL_SETTING, "") or "").strip()
    url = raw or DEFAULT_TSA_URL
    scheme = urlparse(url).scheme
    if scheme not in ("http", "https"):
        raise TimestampError(
            f"TSA adresi http(s) olmalı, '{scheme}' verildi: {url!r}"
        )
    return url


# ══════════════════════════════════════════════════════════════════════════════
# 3. Damgalama akışı
# ══════════════════════════════════════════════════════════════════════════════


def timestamp_file(
    path: Path | str,
    *,
    url: str = DEFAULT_TSA_URL,
    key: bytes | None = None,
    hwid: str | None = None,
    timeout: int = TSA_TIMEOUT,
    transport: Callable[[str, bytes, int], bytes] | None = None,
) -> TimestampInfo:
    """
    Bir `.hcl` dosyasını damgalar ve fragmanı dosyaya yazar.

    Akış:
        AAD'den original_sha256 oku → (opsiyonel) verify_file ile doğrula →
        TimeStampReq kur → TSA'ya POST → yanıtı kontrol et → fragmanı yaz

    Args:
        path: Damgalanacak `.hcl` dosyası.
        url: TSA adresi. Uygulamada `tsa_url(db)` ile ayarlardan gelir.
        key: Verilirse damgalamadan ÖNCE `verify_file()` çalışır, yani
            AAD'nin (ve dolayısıyla özetin) bütünlüğü doğrulanmış olur.
            Verilmezse damga doğrulanmamış bir özet için alınır — bkz.
            modül docstring'i.
        hwid: `key` verildiğinde `verify_file()`e geçirilir.
        transport: (url, body, timeout) → yanıt byte'ları. Testlerin
            gerçek ağa çıkmadan akışın tamamını koşturmasını sağlıyor.

    Returns:
        Dosyaya yazılan TimestampInfo.

    Raises:
        TimestampError — AAD'de özet yok, TSA reddetti, yanıt tutarsız
            ya da fragman yazılamadı.
        AuthenticationError — `key` verildi ve dosya doğrulanamadı.
    """
    path = Path(path)
    if read_trailer(path) is not None:
        raise TimestampError(
            f"{path.name} zaten damgalı. Yeniden damgalamak eski damgayı "
            "geçersiz kılardı; önce mevcut fragmanı bilinçli olarak kaldırın."
        )

    if key is not None:
        # AuthenticationError bilerek yakalanmıyor: bozuk bir dosyaya damga
        # basmak, bozulmayı "o tarihte böyleydi" diye onaylamak olurdu.
        meta = verify_file(path, key, hwid=hwid)
    else:
        meta = read_aad(path)

    hashed_hex = meta.get("original_sha256")
    if not hashed_hex:
        raise TimestampError(
            f"{path.name}: AAD'de original_sha256 yok — bu dosya, özet alanı "
            "eklenmeden önce şifrelenmiş. Damgalamak için yeniden şifrelenmeli."
        )
    try:
        digest = bytes.fromhex(hashed_hex)
    except ValueError as exc:
        raise TimestampError(
            f"AAD'deki original_sha256 geçerli hex değil: {hashed_hex!r}"
        ) from exc
    if len(digest) != hashlib.sha256().digest_size:
        raise TimestampError(
            f"AAD'deki original_sha256 {len(digest)} byte — SHA-256 değil."
        )

    request_der, nonce = build_request(digest)
    send = transport or _http_post
    try:
        response_der = send(url, request_der, timeout)
    except TimestampError:
        raise
    except Exception as exc:
        raise TimestampError(f"TSA'ya ulaşılamadı ({url}): {exc}") from exc

    token_der = parse_response(response_der, digest=digest, nonce=nonce)
    info = TimestampInfo(
        hash_algorithm=HASH_ALGORITHM,
        hashed_hex=hashed_hex,
        tsa_url=url,
        token_der=token_der,
    )
    attach_trailer(path, info)
    _log.info(
        "%s damgalandı (tsa=%s, token=%d B)", path.name, url, len(token_der)
    )
    return info


__all__ = [
    "DEFAULT_TSA_URL",
    "HASH_ALGORITHM",
    "TSA_TIMEOUT",
    "TSA_URL_SETTING",
    "TRAILER_VERSION",
    "TimestampError",
    "TimestampInfo",
    "attach_trailer",
    "build_request",
    "decode_trailer",
    "encode_trailer",
    "parse_response",
    "read_aad",
    "read_trailer",
    "timestamp_file",
    "tsa_url",
]
