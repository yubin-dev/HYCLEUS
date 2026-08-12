"""
CORE.crypto — AES-256-GCM çekirdeği için kritik güvenlik testleri.

Tüm testler gerçek encrypt_file() / decrypt_file() çağırır; mock yoktur.
Yalnızca çıktı dizini (_QUARANTINE_DIR) tmp_path'e yönlendirilir ki
testler projenin data/quarantine/ klasörünü kirletmesin.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from CORE import crypto
from CORE.crypto import AuthenticationError, decrypt_file, encrypt_file, generate_key

# .hcl başlık ofsetleri (bkz. CORE/crypto.py modül docstring'i)
_HDR_NONCE = 5                 # magic(4) + version(1)
_HDR_AAD_LEN = _HDR_NONCE + 12
_HDR_AAD = _HDR_AAD_LEN + 4
_TAG_SIZE = 16

_USER_ID = 42
_HWID = "TEST-HWID-0001"


@pytest.fixture(autouse=True)
def _quarantine_to_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Şifreli çıktıları test başına izole bir dizine yönlendirir."""
    out = tmp_path / "quarantine"
    out.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", out)
    return out


@pytest.fixture
def key() -> bytes:
    return generate_key()


@pytest.fixture
def plain_file(tmp_path: Path) -> Path:
    """Blok sınırlarını (64 KB) aşan, deterministik içerikli kaynak dosya."""
    src = tmp_path / "gizli_rapor.bin"
    payload = bytes(range(256)) * 800  # 204 800 B → 3 tam olmayan blok
    src.write_bytes(payload)
    return src


def _parse_hcl(path: Path) -> tuple[bytes, bytes, bytes, bytes]:
    """.hcl dosyasını (nonce, aad, ciphertext, tag) olarak ayrıştırır."""
    raw = path.read_bytes()
    nonce = raw[_HDR_NONCE:_HDR_AAD_LEN]
    (aad_len,) = struct.unpack(">I", raw[_HDR_AAD_LEN:_HDR_AAD])
    aad = raw[_HDR_AAD : _HDR_AAD + aad_len]
    body = raw[_HDR_AAD + aad_len :]
    return nonce, aad, body[:-_TAG_SIZE], body[-_TAG_SIZE:]


def _rebuild_hcl(path: Path, *, aad: bytes, ciphertext: bytes, tag: bytes) -> None:
    """Ayrıştırılmış parçalardan .hcl dosyasını yeniden yazar."""
    raw = path.read_bytes()
    header = raw[:_HDR_AAD_LEN] + struct.pack(">I", len(aad))
    path.write_bytes(header + aad + ciphertext + tag)


# ── 1. Round-trip ─────────────────────────────────────────────────────────────

def test_encrypt_decrypt_round_trip_is_byte_identical(plain_file: Path, key: bytes) -> None:
    """Şifrele → çöz sonucu orijinal dosyayla byte-byte aynı olmalı."""
    original = plain_file.read_bytes()

    hcl_path, sha256_hex, _aad_json = encrypt_file(
        plain_file, key, _USER_ID, hwid=_HWID
    )

    # Şifreli çıktı düz metni sızdırmamalı
    assert hcl_path.exists()
    assert original not in hcl_path.read_bytes()

    content, meta = decrypt_file(hcl_path, key, hwid=_HWID)

    assert content == original
    assert len(content) == len(original)
    assert meta["filename"] == plain_file.name
    assert meta["original_sha256"] == sha256_hex
    assert meta["user_id"] == _USER_ID
    assert meta["hwid"] == _HWID


# ── 2. Ciphertext / tag kurcalama ─────────────────────────────────────────────

@pytest.mark.parametrize("region", ["tag", "ciphertext_last", "ciphertext_first"])
def test_ciphertext_tampering_raises_authentication_error(
    plain_file: Path, key: bytes, region: str
) -> None:
    """Tek bir byte değişse bile decrypt sessizce veri dönmemeli, hata fırlatmalı."""
    hcl_path, _sha, _aad = encrypt_file(plain_file, key, _USER_ID, hwid=_HWID)
    nonce, aad, ciphertext, tag = _parse_hcl(hcl_path)

    if region == "tag":
        mutated_tag = tag[:-1] + bytes([tag[-1] ^ 0xFF])
        _rebuild_hcl(hcl_path, aad=aad, ciphertext=ciphertext, tag=mutated_tag)
    elif region == "ciphertext_last":
        mutated = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0x01])
        _rebuild_hcl(hcl_path, aad=aad, ciphertext=mutated, tag=tag)
    else:
        mutated = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
        _rebuild_hcl(hcl_path, aad=aad, ciphertext=mutated, tag=tag)

    # Dosya gerçekten değişmiş olmalı — testin boşa geçmediğini garanti eder
    assert _parse_hcl(hcl_path)[1:] != (aad, ciphertext, tag)

    with pytest.raises(AuthenticationError):
        decrypt_file(hcl_path, key, hwid=_HWID)


def test_wrong_key_raises_authentication_error(plain_file: Path, key: bytes) -> None:
    """Yanlış anahtarla çözme de GCM doğrulamasına takılmalı."""
    hcl_path, _sha, _aad = encrypt_file(plain_file, key, _USER_ID, hwid=_HWID)

    with pytest.raises(AuthenticationError):
        decrypt_file(hcl_path, generate_key(), hwid=_HWID)


# ── 3. AAD (metadata) kurcalama ───────────────────────────────────────────────

@pytest.mark.parametrize(
    ("old", "new"),
    [
        (b'"user_id": 42', b'"user_id": 43'),      # yetki yükseltme denemesi
        (b'"hwid": "TEST-HWID-0001"', b'"hwid": "TEST-HWID-0002"'),  # cihaz değişimi
        (b'"filename": "gizli_rapor.bin"', b'"filename": "gizli_rapor.bik"'),
    ],
)
def test_aad_metadata_tampering_is_rejected(
    plain_file: Path, key: bytes, old: bytes, new: bytes
) -> None:
    """AAD'daki tek karakterlik değişiklik bile reddedilmeli."""
    hcl_path, _sha, _aad_json = encrypt_file(plain_file, key, _USER_ID, hwid=_HWID)
    _nonce, aad, ciphertext, tag = _parse_hcl(hcl_path)

    assert old in aad, f"AAD içinde {old!r} bulunamadı — test verisi güncel değil"
    mutated_aad = aad.replace(old, new, 1)
    assert len(mutated_aad) == len(aad), "AAD uzunluğu korunmalı (saf içerik kurcalaması)"
    assert mutated_aad != aad

    _rebuild_hcl(hcl_path, aad=mutated_aad, ciphertext=ciphertext, tag=tag)

    with pytest.raises(AuthenticationError):
        decrypt_file(hcl_path, key, hwid=_HWID)


def test_aad_original_sha256_tampering_is_rejected(plain_file: Path, key: bytes) -> None:
    """AAD'a bağlı SHA-256 özeti değiştirilirse dosya çözülememeli."""
    hcl_path, sha256_hex, _aad_json = encrypt_file(plain_file, key, _USER_ID, hwid=_HWID)
    _nonce, aad, ciphertext, tag = _parse_hcl(hcl_path)

    fake_sha = ("0" * 64).encode()
    mutated_aad = aad.replace(sha256_hex.encode(), fake_sha, 1)
    assert mutated_aad != aad

    _rebuild_hcl(hcl_path, aad=mutated_aad, ciphertext=ciphertext, tag=tag)

    with pytest.raises(AuthenticationError):
        decrypt_file(hcl_path, key, hwid=_HWID)


# ── 4. Nonce benzersizliği ────────────────────────────────────────────────────

_NONCE_SAMPLES = 200


def test_nonce_is_unique_across_encryptions(tmp_path: Path, key: bytes) -> None:
    """
    GCM'de nonce tekrarı katastrofiktir (anahtar akışı yeniden kullanılır,
    XOR ile düz metin sızar ve auth anahtarı kurtarılabilir).

    Aynı anahtar + aynı içerikle 200 şifreleme yapılır; tüm nonce'lar farklı olmalı.
    """
    src = tmp_path / "tekrar.bin"
    src.write_bytes(b"HYCLEUS nonce benzersizlik testi\n" * 64)

    nonces: list[bytes] = []
    ciphertexts: list[bytes] = []
    for _ in range(_NONCE_SAMPLES):
        hcl_path, _sha, _aad = encrypt_file(src, key, _USER_ID, hwid=_HWID)
        nonce, _aad_b, ciphertext, _tag = _parse_hcl(hcl_path)
        nonces.append(nonce)
        ciphertexts.append(ciphertext)

    assert len(nonces) == _NONCE_SAMPLES
    assert all(len(n) == 12 for n in nonces), "GCM nonce 12 byte olmalı"
    assert all(n != bytes(12) for n in nonces), "Sabit sıfır nonce kullanılmış"

    duplicates = len(nonces) - len(set(nonces))
    assert duplicates == 0, f"{duplicates} adet nonce tekrarı — GCM anahtar akışı yeniden kullanılmış"

    # Aynı düz metin + aynı anahtar farklı ciphertext üretmeli (nonce gerçekten etkili)
    assert len(set(ciphertexts)) == _NONCE_SAMPLES, "Şifreleme deterministik — nonce ciphertext'e karışmıyor"
