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
  filename, original_sha256, created_at, uploaded_at, last_modified,
  user_id, hwid


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
    kopyalansa AAD'deki original_sha256 ile eşleşmez.

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
from typing import IO

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


def _zero(buf: bytearray) -> None:
    """bytearray içeriğini ctypes.memset ile sıfırlar — ara tampon temizliği."""
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

    Şifrelemeden önce orijinal dosyanın SHA-256 özeti hesaplanır; hem AAD'a
    bağlanır hem de döndürülür (DB'ye kaydedilmesi için).

    AAD (şifrelenmez, bütünlük koruması altında — tek karakter değişse
    decrypt_file() AuthenticationError fırlatır):
        filename        — orijinal dosya adı
        original_sha256 — şifreleme öncesi SHA-256 (hex)
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

    # SHA-256 şifrelemeden önce hesaplanır — orijinal içeriği doğrular
    sha256_hex = _sha256_file(src)

    stat = src.stat()
    metadata = {
        "filename": filename or src.name,
        "original_sha256": sha256_hex,
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


def verify_file(
    src: Path | str,
    key: bytes,
    *,
    hwid: str | None = None,
) -> dict:
    """
    .hcl dosyasının GCM doğrulamasını yapar — DÜZ METNİ DÖNDÜRMEZ.

    Bütünlük taramasının (CORE/integrity.py) kullandığı dar doğrulama yolu.
    Sözleşmesi decrypt_file() ile aynıdır, tek farkı düz metni vermemesi:
    aynı istisnaları aynı koşullarda fırlatır.

    Returns:
        metadata_dict — AAD içeriği. Düz metin DEĞİL; AAD zaten dosya
        başlığında şifresiz duruyor (bkz. SECURITY.md §3, "Metadata
        gizliliği"), dolayısıyla döndürmek yeni bir şey açığa çıkarmaz.

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
        if fin.read(4) != _MAGIC:
            raise ValueError("Geçersiz HYCL dosya formatı.")
        version_byte = fin.read(1)
        if not version_byte:
            raise ValueError("Dosya çok kısa, bozulmuş olabilir.")
        version = version_byte[0]
        if version not in _SUPPORTED_VERSIONS:
            raise ValueError(f"Desteklenmeyen versiyon: {version}")

        nonce = fin.read(_NONCE_SIZE)
        if len(nonce) != _NONCE_SIZE:
            raise ValueError("Dosya çok kısa, bozulmuş olabilir.")

        raw_aad_len = fin.read(4)
        if len(raw_aad_len) != 4:
            raise ValueError("Dosya çok kısa, bozulmuş olabilir.")
        (aad_len,) = struct.unpack(">I", raw_aad_len)
        aad = fin.read(aad_len)
        if len(aad) != aad_len:
            raise ValueError("AAD bloğu eksik, dosya bozulmuş.")

        body_start = fin.tell()
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
        try:
            view = memoryview(scratch)
            remaining = ciphertext_len
            while remaining > 0:
                chunk = fin.read(min(_CHUNK, remaining))
                if not chunk:
                    raise ValueError("Ciphertext beklenenden kısa, dosya kesilmiş.")
                # Dönen uzunluk BİLEREK kullanılmıyor: düz metin okunmuyor,
                # yalnızca GCM durumunun ilerlemesi için yazılıyor.
                decryptor.update_into(chunk, view)
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
            _zero(scratch)

        meta = json.loads(aad.decode())
        if hwid is not None and meta.get("hwid") is not None and meta["hwid"] != hwid:
            raise AuthenticationError(
                "HWID uyuşmazlığı — dosya farklı bir cihazda şifrelendi."
            )
        return meta


def decrypt_file(
    src: Path | str,
    key: bytes,
    *,
    hwid: str | None = None,
) -> tuple[bytes, dict]:
    """
    data/quarantine/ içindeki .hcl dosyasını çözer.

    Returns:
        (plaintext_bytes, metadata_dict)
        plaintext_bytes: bytes — işin bitince referansı kaldır: del content

    Bellek güvenliği:
        Ara çözümleme tamponu (bytearray) ctypes.memset ile sıfırlanır.
        Döndürülen bytes kopyasının referansını çağıran kaldırmalı:
            content, meta = decrypt_file(path, key)
            try:
                ...  # içeriği işle
            finally:
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
        if fin.read(4) != _MAGIC:
            raise ValueError("Geçersiz HYCL dosya formatı.")
        version = fin.read(1)[0]
        if version not in _SUPPORTED_VERSIONS:
            raise ValueError(f"Desteklenmeyen versiyon: {version}")
        nonce = fin.read(_NONCE_SIZE)
        (aad_len,) = struct.unpack(">I", fin.read(4))
        aad = fin.read(aad_len)

        body_start = fin.tell()
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
            return bytes(buf), meta
        finally:
            # Hata ya da başarı fark etmeksizin ara tamponu sıfırla
            if buf:
                _zero(buf)
