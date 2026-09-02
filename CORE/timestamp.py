"""
HYCLEUS — RFC 3161 güvenilir zaman damgası (adım 1: format + damgalama)

Bir `.hcl` dosyasının DÜZ METİN SHA-256 özetini bir Zaman Damgası
Otoritesi'ne (TSA) imzalatır ve dönen token'ı dosyanın sonuna, ayrı bir
fragman olarak yazar. Kanıtladığı şey tek cümleyle: *"bu içerik, TSA'nın
imzaladığı tarihte zaten vardı."*

Bu modülün KAPSAMI
------------------
(a) kap formatı, (b) tekil damgalama, (c) TOPLU damgalama (Merkle).
Token'ın imzasının ÇEVRİMDIŞI DOĞRULANMASI ayrı bir modülde:
`CORE/timestamp_verify.py`. Burada yapılan kontroller BİÇİMSEL (status,
imprint, nonce, algoritma) — imzanın TSA sertifikasıyla eşleştiği orada
denetleniyor.

Bu sınır, yanlış bir güven duygusu yaratmasın diye açıkça yazılıyor:
bu modül TSA'nın verdiğini SAKLIYOR, imzasını doğrulamıyor.


İKİ DAMGALAMA KİPİ
------------------
    timestamp_file()   → 1 dosya, 1 TSA çağrısı, fragman v1
    timestamp_batch()  → N dosya (+ çıpa), 1 TSA çağrısı, fragman v2

Toplu kipte token KÖKÜ damgalıyor; her dosya kendi yaprağından köke giden
yolu saklıyor. 100 dosya için 100 çağrı ve ~500 KB token yerine 1 çağrı,
~5 KB token ve dosya başına ~224 byte yol. Ağacın güvenlik seçimleri
(alan ayrımı, tek düğüm yükseltmesi) `CORE/merkle.py` docstring'inde.

Tekil kip KALDIRILMADI: tek bir dosyayı damgalamak için ağaç kurmak
gereksiz bir dolaylılık ve v1 fragmanı okuyan mevcut dosyalar var.


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

Özet YENİDEN HESAPLANIYOR — B-092/B-099, mimari karar
-------------------------------------------------------
Bu modül bir zamanlar şöyleydi: `encrypt_file()` düz metnin SHA-256'sını
şifrelemeden önce hesaplayıp AAD'ye yazıyordu (`original_sha256`),
damgalama onu anahtarsız OKUYORDU. Sonuç: "damgalama anahtar İSTEMEZ ve
düz metne HİÇ dokunmaz."

Bu tasarım KALICI olarak TERK EDİLDİ. Sebep, `CORE/crypto.py` modül
docstring'inde ayrıntılı: AAD şifresiz olduğu için `original_sha256`'nın
orada durması, yalnızca bir `.hcl` KOPYASINA erişen (DB'ye/kimliğe/
çalışan uygulamaya erişimi OLMAYAN — SECURITY.md §1.1'in M2 modeli)
biri için anahtarsız, kesin bir DOĞRULAMA-ORACLE'I demekti. Tuz işe
yaramaz — saldırgan onu da aday belgeye ekler; yalnızca gerçek bir SIR
(anahtar) bunu kapatır, ki bu zaten "anahtarsız" tanımıyla ÇELİŞİR.

Karar: oracle'ı kapatmak, "anahtarsız damgalama" özelliğinden daha ağır
bastı. Sonuç:

    **Damgalama artık anahtar İSTİYOR ve düz metni GERÇEKTEN okuyor**
    (akan blok üzerinden, `CORE.crypto.verify_file(..., return_sha256=
    True)` ile — biriktirmeden, `verify_file()`'ın kendi "düz metni
    gereksiz yere maruz bırakma" ilkesiyle AYNI disiplinle).

`timestamp_file()`/`timestamp_batch()`'in `key` parametresi artık
ZORUNLU — `None` verilemez. Karşılığında AAD'nin bütünlüğü VE düz
metnin GERÇEK özeti aynı çağrıda, aynı anahtarla doğrulanmış oluyor;
"AAD'nin iddia ettiği özet" diye anahtarsız bir yol artık YOK.

**GERİYE DÖNÜK ONARILMIYOR.** GCM AAD'si ciphertext'e bağlı; anahtar
olmadan mevcut bir dosyanın AAD'sinden `original_sha256` sessizce
çıkarılamaz. Yalnızca BUNDAN SONRA şifrelenen dosyalar korunuyor —
mevcut HER `.hcl` dosyası, yeniden şifrelenmedikçe (ayrı bir migrasyon
işi, BACKLOG.md B-100) bu oracle'a KALICI olarak açık kalıyor.

Tam gerekçe, tuzun neden işe yaramadığı ve kapsam analizi: BACKLOG.md
B-092 (analiz) ve B-099 (bu karar/uygulama).


TS_TRAILER biçimi
-----------------
Uzunluk-önekli, deterministik ikili kodlama. `CORE/audit_chain.py` ile aynı
yaklaşım: ayırıcı karakter yok, her alanın önünde uzunluğu var, alan SIRASI
şemanın kendisi. JSON KULLANILMIYOR — token ham DER ve ikili; JSON'a
gömmek base64 (%33 şişme) ve anahtar sırası garantisi gerektirirdi.

    [4B ] TRAILER_MAGIC   = b'HTST'
    [1B ] trailer_version = 0x01 | 0x02
    [4B ] len + hash_algorithm   (utf-8, "sha256")
    [4B ] len + hashed_hex       (utf-8, 64 karakter, BU DOSYANIN özeti)
    [4B ] len + tsa_url          (utf-8, damgayı veren TSA)
    [4B ] len + token_der        (RFC 3161 TimeStampToken, DER)
  ── yalnızca v2 ──────────────────────────────────────────────────────
    [4B ] len + merkle_root      (32 ham byte — TOKEN BUNU damgalıyor)
    [4B ] len + leaf_index       (4 byte big-endian uint32)
    [4B ] len + merkle_proof     (her adım: [1B yön][32B kardeş])
  ─────────────────────────────────────────────────────────────────────
    [4B ] toplam uzunluk (big-endian uint32 — bu fragmanın TAMAMI)
    [4B ] TRAILER_MAGIC   = b'HTST'

v2 alanları SONA eklendi ve v1'in alan sırası aynen korundu. Sonuç:
Merkle'sız bir fragman bugün de byte-byte eski hâliyle üretiliyor ve eski
dosyalar okunmaya devam ediyor.

`hashed_hex` fragmanda AYRICA tutuluyor, token'ın içinden de okunabilecek
olmasına rağmen: dosyanın GERÇEK (anahtarla yeniden hesaplanan) özetiyle
eşleşip eşleşmediğini ASN.1 ayrıştırmadan kontrol edebilmek için (bkz.
`CORE/timestamp_verify.py::verify_timestamp()`). Tutarsızlık olursa
token yine de yetkilidir.

**v2'de `hashed_hex` ile token'ın imprint'i EŞLEŞMEZ** — ve bu doğru
davranıştır. Token kökü damgalıyor; dosyanın özeti köke yolla bağlanıyor.
Doğrulama bu yüzden iki adım: (1) yaprak + yol → kök mü, (2) kök imzalı mı.
Bu ayrımı gözden kaçıran bir okuyucu v2 fragmanını "tutarsız" sanır.

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
from CORE.merkle import (
    HASH_SIZE,
    MerkleError,
    MerkleProof,
    build_leaves,
    build_tree,
    leaf_hash,
    verify_proof,
)

_log = logging.getLogger("hycleus.timestamp")

#: Fragman şeması sürümü — kap sürümünden (0x02) BAĞIMSIZ. Fragmanın iç
#: düzeni değişirse bu artar, kap formatı değişmek zorunda kalmaz.
#:
#: v1 = tek dosya, token doğrudan dosyanın özetini damgalıyor
#: v2 = toplu damga, token KÖKÜ damgalıyor + dosyanın Merkle yolu
#:
#: Yazarken v2 yalnızca Merkle alanları varsa kullanılıyor; tekil
#: damgalama hâlâ byte-byte v1 üretiyor. Okurken İKİSİ DE destekleniyor.
TRAILER_VERSION = 1
TRAILER_VERSION_MERKLE = 2

#: Okunabilen fragman sürümleri. Yeni bir sürüm eklenirken buraya da
#: girmezse `decode_trailer` onu reddeder — sessizce yanlış okumaktansa
#: açık hata.
SUPPORTED_TRAILER_VERSIONS = frozenset({TRAILER_VERSION, TRAILER_VERSION_MERKLE})

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
    """
    Bir dosyanın zaman damgası fragmanının çözülmüş hâli.

    Merkle alanları (v2) opsiyonel. Üçü ya BİRLİKTE dolu ya birlikte boş —
    ikisi dolu biri boş bir fragman anlamsız olurdu ve `__post_init__`
    bunu reddediyor.

    v1 ile v2 arasındaki ANLAM FARKI, bu sınıfın en önemli özelliği:

        v1 → `token_der` DOĞRUDAN `hashed_hex`'i damgalıyor
        v2 → `token_der` `merkle_root`'u damgalıyor; `hashed_hex` bu
             dosyanın kendi özeti ve köke `merkle_proof` ile bağlanıyor

    Yani v2'de token'ın imprint'i ile `hashed_hex` EŞLEŞMEZ ve bu doğru
    davranıştır. Doğrulama iki adım: yol köke çıkıyor mu, kök imzalı mı.
    """

    hash_algorithm: str
    hashed_hex: str
    tsa_url: str
    token_der: bytes
    #: Toplu damgada ağacın kökü (32 ham byte). Tekil damgada None.
    merkle_root: bytes | None = None
    #: Bu dosyanın yaprak indisi. Ağacı yeniden kurmak için DEĞİL —
    #: yalnızca teşhis ve kayıt için; doğrulama yolu yürüyor.
    leaf_index: int | None = None
    #: Yaprağı köke bağlayan yol.
    merkle_proof: MerkleProof | None = None

    def __post_init__(self) -> None:
        dolu = [
            self.merkle_root is not None,
            self.leaf_index is not None,
            self.merkle_proof is not None,
        ]
        if any(dolu) and not all(dolu):
            raise TimestampError(
                "Merkle alanları ya birlikte dolu ya birlikte boş olmalı; "
                f"root={dolu[0]} index={dolu[1]} proof={dolu[2]}"
            )
        if self.merkle_root is not None and len(self.merkle_root) != HASH_SIZE:
            raise TimestampError(
                f"Merkle kökü {HASH_SIZE} byte olmalı, "
                f"{len(self.merkle_root)} verildi."
            )

    @property
    def batched(self) -> bool:
        """Toplu (Merkle) damga mı."""
        return self.merkle_root is not None

    @property
    def trailer_version(self) -> int:
        return TRAILER_VERSION_MERKLE if self.batched else TRAILER_VERSION


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
        + bytes([info.trailer_version])
        + _put(info.hash_algorithm.encode("utf-8"))
        + _put(info.hashed_hex.encode("utf-8"))
        + _put(info.tsa_url.encode("utf-8"))
        + _put(info.token_der)
    )
    kok, indis, yol = info.merkle_root, info.leaf_index, info.merkle_proof
    if kok is not None and indis is not None and yol is not None:
        # v2 ek alanları SONA ekleniyor: v1'in alan sırası aynen korunuyor,
        # dolayısıyla Merkle'sız bir fragman byte-byte eskisiyle aynı çıkıyor.
        #
        # Üçünü tek tek kontrol etmek `assert` yerine tercih edildi:
        # `assert` `-O` ile çalıştırıldığında düşer ve tip daraltması da
        # onunla birlikte kaybolur. `__post_init__` zaten "ya hep ya hiç"
        # garantisi veriyor, buradaki kontrol yalnızca onu görünür kılıyor.
        body += (
            _put(kok)
            + _put(struct.pack(">I", indis))
            + _put(encode_proof(yol))
        )
    total = len(body) + 8  # + toplam uzunluk alanı (4) + kapanış magic (4)
    return body + struct.pack(">I", total) + TRAILER_MAGIC


def encode_proof(proof: MerkleProof) -> bytes:
    """
    Merkle yolunu ikili bloba çevirir: her adım `[1B yön][32B kardeş]`.

    Yön byte'ı 0x01 = kardeş SAĞDA, 0x00 = solda. Ayrı bir sayaç alanı
    YOK: blob uzunluğu 33'e tam bölünüyor ve adım sayısını veriyor.
    Sayaç eklemek, uzunlukla çelişebilecek ikinci bir gerçek kaynağı
    yaratırdı.
    """
    return b"".join(
        bytes([1 if sagda else 0]) + kardes
        for kardes, sagda in zip(proof.siblings, proof.right_flags)
    )


def decode_proof(blob: bytes, *, leaf_index: int) -> MerkleProof:
    """Ham blobu `MerkleProof`a çevirir."""
    adim = 1 + HASH_SIZE
    if len(blob) % adim:
        raise TimestampError(
            f"Merkle yolu bozuk: {len(blob)} byte {adim}'e bölünmüyor."
        )
    kardesler: list[bytes] = []
    yonler: list[bool] = []
    for i in range(0, len(blob), adim):
        yon = blob[i]
        if yon not in (0, 1):
            raise TimestampError(
                f"Merkle yolunda geçersiz yön byte'ı: 0x{yon:02x} "
                "(yalnızca 0x00/0x01 geçerli)"
            )
        yonler.append(yon == 1)
        kardesler.append(blob[i + 1 : i + adim])
    try:
        return MerkleProof(
            leaf_index=leaf_index,
            siblings=tuple(kardesler),
            right_flags=tuple(yonler),
        )
    except MerkleError as exc:
        raise TimestampError(f"Merkle yolu geçersiz: {exc}") from exc


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
    if version not in SUPPORTED_TRAILER_VERSIONS:
        raise TimestampError(
            f"Desteklenmeyen fragman sürümü: {version} "
            f"(bu sürüm {sorted(SUPPORTED_TRAILER_VERSIONS)} okuyor)"
        )

    alg, pos = _take(raw, 5)
    hashed, pos = _take(raw, pos)
    url, pos = _take(raw, pos)
    token, pos = _take(raw, pos)

    kok: bytes | None = None
    indis: int | None = None
    yol: MerkleProof | None = None
    if version == TRAILER_VERSION_MERKLE:
        kok, pos = _take(raw, pos)
        ham_indis, pos = _take(raw, pos)
        blob, pos = _take(raw, pos)
        if len(ham_indis) != 4:
            raise TimestampError(
                f"Yaprak indisi 4 byte olmalı, {len(ham_indis)} verildi."
            )
        (indis,) = struct.unpack(">I", ham_indis)
        yol = decode_proof(blob, leaf_index=indis)

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
        merkle_root=kok,
        leaf_index=indis,
        merkle_proof=yol,
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
    şey açığa çıkarmıyor.

    B-092/B-099: bu modül artık BUNU KULLANMIYOR — damgalama/doğrulama
    düz metnin GERÇEK özetini `verify_file(..., return_sha256=True)` ile
    (anahtarla) hesaplıyor, çünkü `encrypt_file()` `original_sha256`'yı
    artık AAD'ye hiç YAZMIYOR (anahtarsız bir doğrulama-oracle'ı olmasın
    diye). Fonksiyon yine de dışa açık ve genel amaçlı kalıyor —
    `filename`/`created_at` gibi DİĞER AAD alanlarını anahtarsız okumak
    hâlâ meşru bir ihtiyaç olabilir; yalnızca ESKİ (bu karardan önce
    şifrelenmiş) dosyalarda `original_sha256` alanı hâlâ görülebilir.

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

    # Sertifika zinciri token'ın İÇİNDE olmak zorunda: çevrimdışı doğrulama
    # (CORE/timestamp_verify.py) yalnızca dosyadaki veriyle çalışıyor ve
    # imzayı doğrulayacak sertifikayı başka hiçbir yerden alamıyor.
    # `certReq=True` gönderdik; uymayan bir TSA'yı SESSİZCE kabul etmek,
    # aylar sonra doğrulanamayan bir damga bırakırdı. Hatayı şimdi ver.
    if not token["content"]["certificates"]:
        raise TimestampError(
            "TSA token'a sertifika gömmemiş (certReq=True istenmesine rağmen) — "
            "bu damga sonradan çevrimdışı doğrulanamaz."
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
    key: bytes,
    *,
    url: str = DEFAULT_TSA_URL,
    hwid: str | None = None,
    timeout: int = TSA_TIMEOUT,
    transport: Callable[[str, bytes, int], bytes] | None = None,
) -> TimestampInfo:
    """
    Bir `.hcl` dosyasını damgalar ve fragmanı dosyaya yazar.

    Akış:
        verify_file(..., return_sha256=True) ile düz metnin GERÇEK özetini
        anahtarla doğrula/hesapla → TimeStampReq kur → TSA'ya POST → yanıtı
        kontrol et → fragmanı yaz

    Args:
        path: Damgalanacak `.hcl` dosyası.
        key: ZORUNLU (B-092/B-099 — bkz. modül docstring'i). Dosya bu
            anahtarla doğrulanıp düz metnin GERÇEK özeti akan blok
            üzerinden hesaplanmadan damga alınamaz; "anahtarsız damgalama"
            kalıcı olarak feda edildi.
        url: TSA adresi. Uygulamada `tsa_url(db)` ile ayarlardan gelir.
        hwid: `verify_file()`e geçirilir.
        transport: (url, body, timeout) → yanıt byte'ları. Testlerin
            gerçek ağa çıkmadan akışın tamamını koşturmasını sağlıyor.

    Returns:
        Dosyaya yazılan TimestampInfo.

    Raises:
        TimestampError — TSA reddetti, yanıt tutarsız ya da fragman
            yazılamadı.
        AuthenticationError — dosya `key`/`hwid` ile doğrulanamadı.
    """
    path = Path(path)
    if read_trailer(path) is not None:
        raise TimestampError(
            f"{path.name} zaten damgalı. Yeniden damgalamak eski damgayı "
            "geçersiz kılardı; önce mevcut fragmanı bilinçli olarak kaldırın."
        )

    # AuthenticationError bilerek yakalanmıyor: bozuk bir dosyaya damga
    # basmak, bozulmayı "o tarihte böyleydi" diye onaylamak olurdu.
    #
    # `hashed_hex` `hashlib.sha256().hexdigest()`'ten geliyor — her zaman
    # 64 geçerli hex karakteri. Eski kod burada AAD'den okunan (ve
    # dolayısıyla bozuk/uydurma olabilecek) bir dizeyi doğruluyordu; artık
    # bu kontrol imkânsız bir durumu sınıyor olurdu, kaldırıldı.
    _meta, hashed_hex = verify_file(path, key, hwid=hwid, return_sha256=True)
    digest = bytes.fromhex(hashed_hex)

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


# ══════════════════════════════════════════════════════════════════════════════
# 4. Toplu damgalama — Merkle ağacı
# ══════════════════════════════════════════════════════════════════════════════
#
# Tek TSA çağrısı, N dosya + (opsiyonel) günlük denetim çıpası. Gerekçe ve
# ağacın güvenlik seçimleri CORE/merkle.py docstring'inde.


#: Denetim çıpası yaprağının önüne konan etiket. Dosya yapraklarıyla
#: KARIŞMAMASI için: ikisi de 32 byte ham özet ve etiket olmasa bir çıpa
#: hash'i bir dosya özetiymiş gibi sunulabilirdi.
ANCHOR_LEAF_LABEL = b"hycleus-audit-anchor:"


@dataclass(frozen=True)
class BatchResult:
    """Bir toplu damgalama turunun sonucu."""

    root: bytes
    token_der: bytes
    tsa_url: str
    #: Damgalanan dosyalar, verilen sırayla.
    paths: tuple[Path, ...]
    #: Çıpa yaprağı dahil edildiyse hash'i.
    anchor_hash: str | None = None
    #: Ağaçtaki toplam yaprak sayısı (dosyalar + varsa çıpa).
    leaf_count: int = 0

    @property
    def saved_calls(self) -> int:
        """Tekil damgalamaya göre kaç TSA çağrısından tasarruf edildi."""
        return max(0, self.leaf_count - 1)

    def summary(self) -> str:
        cipa = " + çıpa" if self.anchor_hash else ""
        return (
            f"{len(self.paths)} dosya{cipa} tek damgada birleşti "
            f"(kök {self.root.hex()[:16]}…, {self.saved_calls} TSA çağrısı "
            f"tasarruf)"
        )


def current_anchor_hash(path: Path | None = None) -> str | None:
    """
    Denetim çıpası dosyasındaki EN SON `last_hash` — hiç çıpa yoksa None.

    Toplu damgalamaya geçirilecek değer bu. Çıpa dosyası
    `CORE/audit_chain.py`'nin yazdığı JSONL; burada yalnızca son satırın
    `last_hash` alanı okunuyor.

    Neden `audit_chain` içinde DEĞİL: o modül zaman damgasını bilmiyor ve
    bilmemeli. Bağımlılık bu yönde — damgalama denetim zincirini biliyor,
    tersi değil. Ters yön, zincire yazan her yolu TSA'ya bağlardı.

    İçe aktarma FONKSİYON İÇİNDE: `audit_chain` modül düzeyinde
    içe aktarılsaydı iki modül birbirine sıkı bağlanır ve damgalama
    testleri denetim zincirinin kurulumunu gerektirirdi.
    """
    from CORE.audit_chain import read_anchors

    kayitlar = read_anchors(path)
    if not kayitlar:
        return None
    son = kayitlar[-1].get("last_hash")
    return str(son) if son else None


def anchor_leaf_payload(anchor_hash: str) -> bytes:
    """
    Denetim çıpası hash'ini yaprak yüküne çevirir.

    `SHA256(b"hycleus-audit-anchor:" ‖ hash_metni)`.

    YÜK TAŞIYAN KISIM SHA-256 SARMALAMASI, etiket değil — ölçüldü.
    Çıpanın ham byte'ları (`bytes.fromhex(anchor_hash)`) doğrudan yaprak
    yükü yapılsaydı, bir çıpa yaprağı ile bir dosya yaprağı BİREBİR aynı
    biçimde görünürdü: ikisi de 32 baytlık ham özet. O zaman elinde çıpa
    hash'i olan biri onu "şu dosyanın özeti" diye sunabilirdi — kripto
    kırmadan, yalnızca TİP KARIŞIKLIĞIYLA. Sarmalama bunu kapatıyor:
    çıpa yükü, hiçbir dosyanın `original_sha256`'sı olmayan türetilmiş
    bir değer.

    Etiketin kendisi bunun ÜSTÜNE eklenen belge niteliğinde bir ayrım;
    kaldıran bir mutasyon hiçbir testi bozmuyor (sarmalama zaten
    ayırıyor). Yine de duruyor: türetmenin amacını koddan okunur kılıyor
    ve ileride ikinci bir "özel yaprak" türü eklenirse ayrımın yeri hazır
    olur.
    """
    return hashlib.sha256(
        ANCHOR_LEAF_LABEL + anchor_hash.encode("utf-8")
    ).digest()


def file_digest(path: Path, *, key: bytes, hwid: str | None) -> str:
    """
    Bir `.hcl` dosyasının damgalanacak/doğrulanacak GERÇEK düz metin özeti.

    B-092/B-099: eskiden AAD'deki `original_sha256`yı anahtarsız OKUYORDU
    (ya da `key` verildiğinde onu yalnızca DOĞRULUYORDU). Artık `key`
    ZORUNLU ve özet her zaman `verify_file(..., return_sha256=True)` ile
    akan blok üzerinden GERÇEKTEN hesaplanıyor — AAD'de böyle bir alan
    hiç yok. `CORE/timestamp_verify.py::verify_timestamp()` de aynı
    fonksiyonu kullanıyor; tek kaynak.
    """
    _meta, hashed_hex = verify_file(path, key, hwid=hwid, return_sha256=True)
    return hashed_hex


def timestamp_batch(
    paths: list[Path | str],
    key: bytes,
    *,
    url: str = DEFAULT_TSA_URL,
    hwid: str | None = None,
    anchor_hash: str | None = None,
    timeout: int = TSA_TIMEOUT,
    transport: Callable[[str, bytes, int], bytes] | None = None,
) -> BatchResult:
    """
    Birden çok dosyayı TEK TSA çağrısıyla damgalar.

    Akış:
        her dosyanın GERÇEK düz metin özetini `key` ile hesapla/doğrula →
        yaprakları kur → (varsa çıpa yaprağını ekle) → ağacı kur → KÖKÜ
        damgala → her dosyaya kendi yolunu içeren v2 fragmanı yaz

    Args:
        paths: Damgalanacak `.hcl` dosyaları. SIRA ANLAMLIDIR: yaprak
            indisleri buradan geliyor.
        key: ZORUNLU (B-092/B-099 — bkz. modül docstring'i). Her dosya
            damgalanmadan önce `verify_file()` ile doğrulanır (tekil
            akıştaki anlamın aynısı) — "anahtarsız damgalama" yok.
        anchor_hash: `CORE.audit_chain`'in günlük çıpasının `last_hash`
            değeri. Verilirse ağaca ETİKETLİ bir yaprak olarak giriyor ve
            iki özellik tek damgada birleşiyor — kullanıcı bir tek
            token'la hem dosyalarının hem denetim kaydının o tarihte var
            olduğunu gösterebiliyor.

    Returns:
        BatchResult.

    Raises:
        TimestampError — liste boş, bir dosya zaten damgalı, TSA
            reddetti ya da fragman yazılamadı.
        AuthenticationError — bir dosya `key`/`hwid` ile doğrulanamadı.

    KISMİ YAZMA UYARISI
    -------------------
    Fragmanlar dosya dosya yazılıyor ve her biri kendi içinde atomik
    (`attach_trailer` → `os.replace`). Ama TUR ATOMİK DEĞİL: 40 dosyanın
    37'si yazıldıktan sonra disk dolarsa ilk 37'si damgalı, son 3'ü
    damgasız kalır. Bu bir tutarsızlık DEĞİL — yazılan 37 fragmanın her
    biri tek başına geçerli ve doğrulanabilir; kalan 3 dosya yeni bir
    turda damgalanabilir. Turu geri almak, geçerli damgaları silmek
    olurdu.

    Yazılamayan dosyalar `TimestampError` içinde adlarıyla bildiriliyor.
    """
    yollar = [Path(p) for p in paths]
    if not yollar:
        raise TimestampError(
            "Toplu damgalama için en az bir dosya gerekiyor — boş bir "
            "ağacın kökü tanımsız olurdu."
        )

    zaten = [p.name for p in yollar if read_trailer(p) is not None]
    if zaten:
        raise TimestampError(
            "Şu dosyalar zaten damgalı: " + ", ".join(zaten) + ". "
            "Yeniden damgalamak eski damgayı geçersiz kılardı; önce mevcut "
            "fragmanlarını bilinçli olarak kaldırın."
        )

    tekrar = {p for p in yollar if yollar.count(p) > 1}
    if tekrar:
        # Aynı dosya iki yaprağa girerse ikinci fragman yazımı birinciyi
        # ezer ve dosya yanlış indisli bir yol taşır.
        raise TimestampError(
            "Aynı dosya listede birden çok kez: "
            + ", ".join(sorted(p.name for p in tekrar))
        )

    ozetler = [file_digest(p, key=key, hwid=hwid) for p in yollar]
    yukler = [bytes.fromhex(h) for h in ozetler]
    if anchor_hash:
        yukler.append(anchor_leaf_payload(anchor_hash))

    yapraklar = build_leaves(yukler)
    agac = build_tree(yapraklar)
    kok = agac.root

    request_der, nonce = build_request(kok)
    send = transport or _http_post
    try:
        response_der = send(url, request_der, timeout)
    except TimestampError:
        raise
    except Exception as exc:
        raise TimestampError(f"TSA'ya ulaşılamadı ({url}): {exc}") from exc

    token_der = parse_response(response_der, digest=kok, nonce=nonce)

    yazilamayan: list[str] = []
    for i, (yol, ozet) in enumerate(zip(yollar, ozetler)):
        bilgi = TimestampInfo(
            hash_algorithm=HASH_ALGORITHM,
            hashed_hex=ozet,
            tsa_url=url,
            token_der=token_der,
            merkle_root=kok,
            leaf_index=i,
            merkle_proof=agac.proof(i),
        )
        try:
            attach_trailer(yol, bilgi)
        except Exception as exc:  # bir dosya turu durdurmasın
            _log.error("%s: fragman yazılamadı: %s", yol.name, exc)
            yazilamayan.append(f"{yol.name} ({exc})")

    if yazilamayan:
        raise TimestampError(
            "Damga alındı ama şu dosyalara yazılamadı: "
            + ", ".join(yazilamayan)
            + ". Diğer dosyaların damgaları GEÇERLİ ve dosyalarında duruyor."
        )

    sonuc = BatchResult(
        root=kok,
        token_der=token_der,
        tsa_url=url,
        paths=tuple(yollar),
        anchor_hash=anchor_hash,
        leaf_count=len(yapraklar),
    )
    _log.info("Toplu damga: %s", sonuc.summary())
    return sonuc


def verify_merkle_path(info: TimestampInfo) -> bool:
    """
    Fragmandaki yolun, fragmandaki köke çıkıp çıkmadığı.

    Yalnızca AĞAÇ tarafını ölçüyor — kökün TSA tarafından imzalandığı ayrı
    bir soru ve `CORE.timestamp_verify.verify_timestamp()`'ın işi. İkisini
    tek fonksiyona toplamak, "yol tutuyor" ile "damga geçerli" arasındaki
    farkı gizlerdi.

    Tekil (v1) damgada True döner: doğrulanacak bir yol yok ve yokluğu bir
    hata değil.
    """
    kok, yol = info.merkle_root, info.merkle_proof
    if kok is None or yol is None:
        return True  # v1 — doğrulanacak yol yok
    try:
        yaprak = leaf_hash(bytes.fromhex(info.hashed_hex))
    except ValueError:
        return False
    return verify_proof(yaprak, yol, kok)


__all__ = [
    "ANCHOR_LEAF_LABEL",
    "BatchResult",
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
    "SUPPORTED_TRAILER_VERSIONS",
    "TRAILER_VERSION_MERKLE",
    "anchor_leaf_payload",
    "current_anchor_hash",
    "decode_proof",
    "encode_proof",
    "file_digest",
    "read_aad",
    "read_trailer",
    "timestamp_batch",
    "timestamp_file",
    "tsa_url",
    "verify_merkle_path",
]
