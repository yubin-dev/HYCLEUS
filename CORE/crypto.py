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
"""

import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag  # noqa: F401  — çağıran yakalasın
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_MAGIC = b"HYCL"
_VERSION = 1
_NONCE_SIZE = 12
_TAG_SIZE = 16
_CHUNK = 64 * 1024  # 64 KB

_QUARANTINE_DIR = Path(__file__).parent.parent / "data" / "quarantine"


def generate_key() -> bytes:
    """32 byte (256-bit) kriptografik rastgele anahtar üretir."""
    return os.urandom(32)


def encrypt_file(
    src: "Path | str",
    key: bytes,
    user_id: int,
) -> Path:
    """
    src dosyasını AES-256-GCM ile şifreler, data/quarantine/<ad>.hcl'e yazar.

    AAD olarak geçilen metadata (şifrelenmez, bütünlük koruması altında):
        filename     — orijinal dosya adı
        encrypted_at — şifreleme zamanı (ISO 8601, UTC)
        user_id      — işlemi yapan kullanıcı

    Returns:
        Oluşturulan .hcl dosyasının Path'i

    Raises:
        ValueError — anahtar 32 byte değilse
        OSError    — dosya okuma/yazma hatası
    """
    src = Path(src)
    if len(key) != 32:
        raise ValueError(f"Anahtar 32 byte olmalı, {len(key)} byte verildi.")

    metadata = {
        "filename": src.name,
        "encrypted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_id": user_id,
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

    return dst


def decrypt_file(
    src: "Path | str",
    key: bytes,
) -> "tuple[bytes, dict]":
    """
    data/quarantine/ içindeki .hcl dosyasını çözer.

    Returns:
        (plaintext_bytes, metadata_dict)
        metadata — orijinal dosya adı, şifreleme tarihi, user_id içerir

    Raises:
        ValueError                         — bozuk başlık veya desteklenmeyen versiyon
        cryptography.exceptions.InvalidTag — dosya veya metadata değiştirilmiş
        OSError                            — dosya okuma hatası
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

        chunks = []
        remaining = ciphertext_len
        while remaining > 0:
            chunk = fin.read(min(_CHUNK, remaining))
            chunks.append(decryptor.update(chunk))
            remaining -= len(chunk)
        chunks.append(decryptor.finalize())  # InvalidTag burada fırlar

    return b"".join(chunks), json.loads(aad.decode())
