"""
Bilerek güvensiz kod — semgrep kurallarının kanaryası. ÇALIŞTIRILMAZ.

Dizin yolu `.../canary_semgrep/CORE/...` biçiminde çünkü R1 kuralının
`paths.include` filtresi "CORE/" diyor; kanaryanın o filtreden geçmesi
gerekiyor, yoksa kuralın yolu doğru mu bilemeyiz.
"""
from __future__ import annotations

import hashlib
import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# R1 — hycleus-weak-random-in-core
_zayif_anahtar = random.getrandbits(256).to_bytes(32, "big")
_zayif_secim = random.choice([1, 2, 3])


# R2 — hycleus-aes-ecb-mode
def _ecb(key: bytes) -> object:
    return Cipher(algorithms.AES(key), modes.ECB())


# R3 — hycleus-gcm-literal-nonce
def _sabit_nonce(key: bytes, veri: bytes) -> bytes:
    aead = AESGCM(key)
    return aead.encrypt(b"000000000000", veri, None)


def _sabit_nonce_tek_satir(key: bytes, veri: bytes) -> bytes:
    return AESGCM(key).encrypt(b"111111111111", veri, None)


# R4 — hycleus-static-kdf-salt
def _sabit_tuz(pin: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), b"hycleus-sabit-tuz", 100_000)


# R5 — hycleus-hardcoded-key-material
master_key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
NONCE = b"sabit-nonce-"
pin_salt = b"asla-degismeyen-tuz"
