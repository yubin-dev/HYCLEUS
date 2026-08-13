"""
HYCLEUS — AES-256-GCM dosya şifreleme modülü

Dosya formatı (ikili):
  [4B ] magic     = b'HYCL'
  [1B ] version   = 0x01
  [12B] nonce     (rastgele, her şifrelemede yeni)
  [4B ] aad_len   (big-endian uint32)
  [xB ] aad       = JSON(metadata)  — şifrelenmez, bütünlük koruması altında
  [nB ] ciphertext (64 KB bloklarla akış)
  [16B] GCM authentication tag

AAD alanları (tek karakter değişse decrypt_file() AuthenticationError fırlatır):
  filename, created_at, uploaded_at, last_modified, user_id, hwid
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_MAGIC = b"HYCL"
_VERSION = 1
_NONCE_SIZE = 12
_TAG_SIZE = 16
_CHUNK = 64 * 1024  # 64 KB

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


def encrypt_file(
    src: Path | str,
    key: bytes,
    user_id: int,
    *,
    hwid: str | None = None,
    created_at: str | None = None,
    uploaded_at: str | None = None,
    last_modified: str | None = None,
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
        "filename": src.name,
        "original_sha256": sha256_hex,
        "created_at": created_at or _fmt_ts(stat.st_ctime),
        "uploaded_at": uploaded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_modified": last_modified or _fmt_ts(stat.st_mtime),
        "user_id": user_id,
        "hwid": hwid,
    }

    dst = _QUARANTINE_DIR / f"{src.name}.hcl"
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
        if version_byte[0] != _VERSION:
            raise ValueError(f"Desteklenmeyen versiyon: {version_byte[0]}")

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
        ciphertext_len = file_size - body_start - _TAG_SIZE
        if ciphertext_len < 0:
            raise ValueError("Dosya çok kısa, bozulmuş olabilir.")

        fin.seek(-_TAG_SIZE, 2)
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
        if version != _VERSION:
            raise ValueError(f"Desteklenmeyen versiyon: {version}")
        nonce = fin.read(_NONCE_SIZE)
        (aad_len,) = struct.unpack(">I", fin.read(4))
        aad = fin.read(aad_len)

        body_start = fin.tell()
        file_size = fin.seek(0, 2)
        ciphertext_len = file_size - body_start - _TAG_SIZE
        if ciphertext_len < 0:
            raise ValueError("Dosya çok kısa, bozulmuş olabilir.")

        fin.seek(-_TAG_SIZE, 2)
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
