"""
HYCLEUS — Vault yönetim modülü

Vault dosya formatı (.hcl_vault, ikili):
  [4B ] magic      = b'HCLV'
  [1B ] version    = 0x03
  [16B] salt       (Argon2id KEK türetme tuzu)
  [12B] nonce      (AES-256-GCM rastgele nonce)
  [16B] token_id   (UUID bytes — şifrelenmemiş, HMAC korumalı; Katman-3 için)
  [nB ] ciphertext (AES-GCM ile şifrelenmiş: s1_len(2B) || share_1 || role)
  [16B] gcm_tag    (AES-GCM kimlik doğrulama etiketi)
  [32B] hmac       (HMAC-SHA256 imzası; yukarıdaki tüm alanlar üzerinden)

Shamir Secret Sharing (2-of-2):
  · master_key 2 parçaya bölünür (threshold=2, shares=2)
  · share_1 — vault ciphertext içinde şifreli olarak saklanır
  · share_2 — DB usb_tokens tablosuna HWID ile eşleştirilmiş olarak yazılır
  · Master anahtarı yalnızca her iki parça mevcut olduğunda reconstruct_key() ile kurtarılır

USB kimlik doğrulama katmanları (authenticate_usb):
  · Katman 1 — HWID    : usb_tokens tablosunda kayıtlı mı?
  · Katman 2 — HMAC    : vault dosyası bütünlüğü geçerli mi?
  · Katman 3 — Token ID: vault token_id == DB token_id?

Şifreleme güvenlik katmanları:
  · KEK   — Argon2id(password=pin, salt=salt) → 32 byte şifreleme anahtarı
  · GCM   — Şifreleme + bütünlük; HWID cihaz bağlayıcı AAD olarak iletilir
  · HMAC  — HWID'den HKDF ile türetilen 32 byte imza anahtarıyla dosya bütünlüğü
  · SSS   — Vault + DB olmadan master_key kurtarılamaz (2-of-2 zorunlu)
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import hmac as _stdlib_hmac
import os
import secrets
import struct
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import NoReturn

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from DB.db_manager import DBManager

# ── Sabitler ──────────────────────────────────────────────────────────────────
_MAGIC = b"HCLV"
_VERSION = 3
_SALT_SIZE = 16
_NONCE_SIZE = 12
_TOKEN_ID_SIZE = 16   # UUID bytes
_TAG_SIZE = 16
_HMAC_SIZE = 32
_KEY_SIZE = 32

# Argon2id parametreleri — OWASP minimum önerisi
_A2_TIME = 3
_A2_MEM = 65536   # 64 MB
_A2_PARA = 4

# HKDF türetme etiketi — sürüm değişirse güncelle
_HKDF_LABEL = b"hycleus-vault-sign-v1"

# Shamir alanı: 257-bit asal, 32-byte (256-bit) sırları barındırır
# GF(p) içinde 2-of-2 polinom: f(x) = s + a1*x mod p
_SSS_PRIME = 2**256 + 297

# share formatı: "1:<66 hex char>" — 33 byte değer, byte-hizalı
_SSS_SHARE_HEX_LEN = 66  # ceil(257/8) = 33 byte → 66 hex char

# TOKEN_ID, NONCE'tan hemen sonra gelir — şifresiz ama HMAC imzalı
_TOKEN_ID_OFFSET = len(_MAGIC) + 1 + _SALT_SIZE + _NONCE_SIZE  # 33 B

_HEADER_SIZE = _TOKEN_ID_OFFSET + _TOKEN_ID_SIZE  # 49 B
# share_1 = "1:" + 66 hex = 68 B; s1_len prefix = 2B; role min 1 char
_MIN_VAULT_SIZE = _HEADER_SIZE + 2 + 68 + 1 + _TAG_SIZE + _HMAC_SIZE  # 172 B

_VAULT_PATH_LEGACY = Path(__file__).parent.parent / "data" / ".hcl_vault"
_VAULT_DIR         = Path(__file__).parent.parent / "data" / "vaults"


def _read_vault_path(hwid: str) -> Path:
    """Per-HWID vault dosya yolunu döndürür; yoksa eski tek-dosya yoluna düşer."""
    per = _VAULT_DIR / f"{hwid}.hclv"
    if per.exists():
        return per
    return _VAULT_PATH_LEGACY


def _new_vault_path(hwid: str) -> Path:
    """Yeni kayıt için her zaman per-HWID yolunu döndürür."""
    _VAULT_DIR.mkdir(parents=True, exist_ok=True)
    return _VAULT_DIR / f"{hwid}.hclv"

# ── Windows dosya özniteliği sabitleri ────────────────────────────────────────
_FILE_ATTRIBUTE_READONLY = 0x01
_FILE_ATTRIBUTE_NORMAL   = 0x80   # readonly dahil tüm bitleri sıfırlar

_k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
_k32.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.wintypes.DWORD]
_k32.SetFileAttributesW.restype  = ctypes.wintypes.BOOL
_k32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
_k32.GetFileAttributesW.restype  = ctypes.wintypes.DWORD


# ── Özel istisnalar ───────────────────────────────────────────────────────────

class VaultTamperedError(Exception):
    """Vault HMAC imzası doğrulanamadığında fırlatılır."""


class USBAuthError(Exception):
    """USB kimlik doğrulama katmanlarından biri başarısız olduğunda fırlatılır."""


# ── Yardımcı fonksiyonlar ─────────────────────────────────────────────────────

def _derive_signing_key(hwid: str) -> bytes:
    """HWID'den HKDF-SHA256 ile 32 byte HMAC imza anahtarı türetir."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_SIZE,
        salt=_HKDF_LABEL,
        info=b"signing",
    ).derive(hwid.encode())


def _derive_kek(pin: str, salt: bytes) -> bytes:
    """PIN ve salt'tan Argon2id ile 32 byte KEK türetir."""
    return hash_secret_raw(
        secret=pin.encode(),
        salt=salt,
        time_cost=_A2_TIME,
        memory_cost=_A2_MEM,
        parallelism=_A2_PARA,
        hash_len=_KEY_SIZE,
        type=Type.ID,
    )


def _sign(signing_key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 imzası hesaplar."""
    h = HMAC(signing_key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def _sss_split(secret: bytes) -> tuple[str, str]:
    """
    32-byte secret'i 2-of-2 Shamir paylarına böler.

    Polinom: f(x) = s + a1*x  (mod _SSS_PRIME, derece-1)
    share_1 = f(1),  share_2 = f(2)
    Her pay "index:<hex>" formatında döner.
    """
    s = int.from_bytes(secret, "big")
    a1 = secrets.randbelow(_SSS_PRIME - 1) + 1  # [1, PRIME-1]
    y1 = (s + a1) % _SSS_PRIME
    y2 = (s + 2 * a1) % _SSS_PRIME
    fmt = f"{{:0{_SSS_SHARE_HEX_LEN}x}}"
    return f"1:{fmt.format(y1)}", f"2:{fmt.format(y2)}"


def _sss_recover(share_1: str, share_2: str) -> bytes:
    """
    İki Shamir payından orijinal secret'i kurtarır.

    Lagrange x=0: f(0) = 2*y1 - y2  (mod _SSS_PRIME)
    """
    idx1, h1 = share_1.split(":", 1)
    idx2, h2 = share_2.split(":", 1)
    if idx1 != "1" or idx2 != "2":
        raise ValueError(f"Beklenen pay indisleri 1 ve 2, alınan: {idx1!r}, {idx2!r}")
    y1 = int(h1, 16)
    y2 = int(h2, 16)
    secret_int = (2 * y1 - y2) % _SSS_PRIME
    return secret_int.to_bytes(_KEY_SIZE, "big")


def _save_usb_token(hwid: str, share_2: str, token_id_hex: str) -> None:
    """USB token kaydını (share_2 + token_id) DB usb_tokens tablosuna yazar."""
    DBManager().execute(
        "INSERT OR REPLACE INTO usb_tokens (hwid, share_2, token_id) VALUES (?, ?, ?)",
        (hwid, share_2, token_id_hex),
    )


def _set_readonly(path: Path) -> None:
    """Dosyaya FILE_ATTRIBUTE_READONLY uygular."""
    if not _k32.SetFileAttributesW(str(path), _FILE_ATTRIBUTE_READONLY):
        raise OSError(f"Readonly bit ayarlanamadı: {path}  (hata: {ctypes.GetLastError()})")


def _clear_readonly(path: Path) -> None:
    """Dosyadan FILE_ATTRIBUTE_READONLY özelliğini kaldırır."""
    if not _k32.SetFileAttributesW(str(path), _FILE_ATTRIBUTE_NORMAL):
        raise OSError(f"Readonly bit temizlenemedi: {path}  (hata: {ctypes.GetLastError()})")


@contextmanager
def _writable(path: Path) -> Iterator[None]:
    """
    Vault dosyasını geçici olarak yazılabilir yapar.

    Giriş : dosya mevcutsa readonly bitini kaldırır.
    Çıkış : dosya mevcutsa (istisna olsa bile) readonly bitini geri uygular.
    """
    was_readonly = (
        path.exists()
        and bool(_k32.GetFileAttributesW(str(path)) & _FILE_ATTRIBUTE_READONLY)
    )
    if was_readonly:
        _clear_readonly(path)
    try:
        yield
    finally:
        if path.exists():
            _set_readonly(path)


def _rewrite_vault(
    hwid: str, protected: bytes, target: Path | None = None
) -> None:
    """
    Vault dosyasını güvenli biçimde yeniden yazar:
      1. Readonly korumasını geçici olarak kaldırır
      2. HMAC-SHA256 imzası hesaplar
      3. protected + signature'ı diske yazar
      4. Readonly bitini geri uygular

    target verilmezse _read_vault_path(hwid) kullanılır.
    Yeni vault oluştururken target=_new_vault_path(hwid) geçilmeli.
    """
    path = target if target is not None else _read_vault_path(hwid)
    signature = _sign(_derive_signing_key(hwid), protected)
    with _writable(path=path):
        path.write_bytes(protected + signature)


def _read_vault_token_id(hwid: str) -> bytes:
    """Vault dosyasından 16-byte token_id'yi şifre çözmeden okur."""
    raw = _read_vault_path(hwid).read_bytes()
    if len(raw) < _TOKEN_ID_OFFSET + _TOKEN_ID_SIZE:
        raise VaultTamperedError("Vault token_id alanını içermeyecek kadar kısa; bozulmuş.")
    return raw[_TOKEN_ID_OFFSET : _TOKEN_ID_OFFSET + _TOKEN_ID_SIZE]


# ── Genel API ─────────────────────────────────────────────────────────────────

def create_vault(hwid: str, pin: str, role: str) -> Path:
    """
    Yeni bir vault dosyası oluşturur ve data/.hcl_vault'a yazar.

    İşlem adımları:
      1. 32 byte kriptografik rastgele master key üretir
      2. UUID token_id üretir (cihaz bağlama kimliği)
      3. Shamir 2-of-2 ile master_key'i share_1 ve share_2'ye böler
      4. Argon2id ile PIN'den KEK türetir
      5. AES-256-GCM ile (s1_len || share_1 || role) şifreler; HWID AAD
      6. token_id'yi plaintext olarak vault'a ekler (HMAC korumalı)
      7. HMAC-SHA256 imzası hesaplar ve dosyaya yazar
      8. share_2 + token_id'yi DB usb_tokens tablosuna kaydeder

    Args:
        hwid — USB donanım kimliği (cihaz bağlayıcı)
        pin  — Kullanıcı PIN kodu (Argon2id girdisi)
        role — Kullanıcı rolü (örn. "admin", "user")

    Returns:
        Oluşturulan .hcl_vault dosyasının Path nesnesi

    Raises:
        OSError      — dosya yazma hatası
        RuntimeError — DB bağlantısı yoksa (DBManager.connect() çağrılmamış)
    """
    master_key = os.urandom(_KEY_SIZE)
    token_id_bytes = uuid.uuid4().bytes   # 16 byte UUID
    token_id_hex = token_id_bytes.hex()   # DB'de hex string olarak saklanır

    # ── Shamir 2-of-2 bölme ──────────────────────────────────────────────────
    share_1, share_2 = _sss_split(master_key)

    # ── AES-256-GCM şifreleme ────────────────────────────────────────────────
    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)
    kek = _derive_kek(pin, salt)

    share_1_bytes = share_1.encode()
    plaintext = struct.pack(">H", len(share_1_bytes)) + share_1_bytes + role.encode()

    encryptor = Cipher(algorithms.AES(kek), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(hwid.encode())
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag  # 16 byte

    # ── İmzalama + readonly korumalı yazma ──────────────────────────────────
    # token_id şifrelenmemiş ama HMAC kapsamında — değiştirilirse imza bozulur
    protected = (
        _MAGIC + bytes([_VERSION]) + salt + nonce
        + token_id_bytes + ciphertext + tag
    )
    vault_file = _new_vault_path(hwid)
    _rewrite_vault(hwid, protected, target=vault_file)

    # ── share_2 + token_id → DB ───────────────────────────────────────────────
    _save_usb_token(hwid, share_2, token_id_hex)

    return vault_file


def verify_vault(hwid: str) -> None:
    """
    Vault dosyasının HMAC-SHA256 imzasını doğrular.

    Her açılışta çağrılmalıdır; şifre çözme gerçekleştirmez.
    Vault değiştirildikten sonra _rewrite_vault() yeni HMAC'ı otomatik
    hesaplar — bu fonksiyonu tekrar çağırmak yeterlidir.

    Args:
        hwid — USB donanım kimliği

    Raises:
        FileNotFoundError  — vault dosyası bulunamazsa
        VaultTamperedError — dosya çok kısaysa veya HMAC geçersizse
    """
    raw = _read_vault_path(hwid).read_bytes()

    if len(raw) < _MIN_VAULT_SIZE:
        raise VaultTamperedError("Vault dosyası beklenen boyuttan kısa; bozulmuş.")

    stored_hmac = raw[-_HMAC_SIZE:]
    protected = raw[:-_HMAC_SIZE]

    expected_hmac = _sign(_derive_signing_key(hwid), protected)

    if not _stdlib_hmac.compare_digest(expected_hmac, stored_hmac):
        raise VaultTamperedError("Vault HMAC doğrulaması başarısız: dosya değiştirilmiş.")


def authenticate_usb(hwid: str) -> None:
    """
    USB kimlik doğrulama — kara liste + 3 güvenlik katmanı.

    Kara liste  — blacklisted=1 ise anında reddedilir
    Katman 1    — HWID usb_tokens tablosunda kayıtlı mı?
    Katman 2    — Vault HMAC-SHA256 geçerli mi?
    Katman 3    — vault token_id == DB token_id?

    Herhangi biri başarısız olursa audit_log'a kayıt düşer ve
    USBAuthError fırlatılır.

    Args:
        hwid — Takılan USB cihazının donanım kimliği

    Raises:
        USBAuthError — herhangi bir kontrol başarısız olursa
        RuntimeError — DB bağlantısı yoksa
    """
    db = DBManager()

    def _reject(reason: str) -> NoReturn:
        db.log("usb_auth_rejected", detail=f"hwid={hwid} — {reason}")
        raise USBAuthError(reason)

    # ── Katman 1: HWID kayıtlı mı? ───────────────────────────────────────────
    row = db.fetchone(
        "SELECT token_id, blacklisted FROM usb_tokens WHERE hwid = ?", (hwid,)
    )
    if row is None:
        _reject("HWID usb_tokens tablosunda kayıtlı değil.")

    # ── Kara liste kontrolü (Katman 1 içinde, ilk kontrol) ───────────────────
    if row["blacklisted"]:
        _reject("USB cihazı kara listede; erişim reddedildi.")

    db_token_id: str = row["token_id"]

    # ── Katman 2: Vault HMAC geçerli mi? ─────────────────────────────────────
    try:
        verify_vault(hwid)
    except FileNotFoundError:
        _reject("Vault dosyası bulunamadı.")
    except VaultTamperedError as exc:
        _reject(str(exc))

    # ── Katman 3: Token ID eşleşiyor mu? ─────────────────────────────────────
    vault_token_hex = ""  # NoReturn _reject garantisi; başlangıç değeri tip sinyali için
    try:
        vault_token_hex = _read_vault_token_id(hwid).hex()
    except VaultTamperedError as exc:
        _reject(str(exc))

    if not _stdlib_hmac.compare_digest(vault_token_hex, db_token_id):
        _reject("Vault token_id ile DB token_id eşleşmiyor.")

    db.log("usb_auth_success", detail=f"hwid={hwid}")


def blacklist_usb(hwid: str) -> None:
    """
    USB cihazını kara listeye alır.

    Kara listedeki cihazlar authenticate_usb() çağrısında diğer
    kontroller yapılmadan anında reddedilir.

    Args:
        hwid — Kara listeye alınacak USB donanım kimliği

    Raises:
        ValueError   — HWID usb_tokens tablosunda kayıtlı değilse
        RuntimeError — DB bağlantısı yoksa
    """
    db = DBManager()
    row = db.fetchone("SELECT blacklisted FROM usb_tokens WHERE hwid = ?", (hwid,))
    if row is None:
        raise ValueError(f"HWID '{hwid}' usb_tokens tablosunda kayıtlı değil.")
    if row["blacklisted"]:
        return  # zaten kara listede, idempotent
    db.execute("UPDATE usb_tokens SET blacklisted = 1 WHERE hwid = ?", (hwid,))
    db.log("usb_blacklisted", detail=f"hwid={hwid}")


def read_vault_role(hwid: str, pin: str) -> str:
    """
    Vault dosyasını PIN ile çözerek içindeki rolü döndürür.

    Önce verify_vault(hwid) ile HMAC bütünlüğünü doğrular,
    ardından Argon2id KEK türetip AES-256-GCM şifreyi çözer.

    Args:
        hwid — USB donanım kimliği (GCM AAD + HMAC imza anahtarı)
        pin  — Argon2id KEK girdisi

    Returns:
        Vault'ta kayıtlı rol string'i

    Raises:
        FileNotFoundError  — vault dosyası yoksa
        VaultTamperedError — HMAC doğrulaması başarısızsa
        ValueError         — PIN yanlış veya vault formatı geçersizse
    """
    verify_vault(hwid)  # HMAC önce doğrulanır

    raw = _read_vault_path(hwid).read_bytes()

    if raw[:4] != _MAGIC:
        raise VaultTamperedError("Geçersiz vault magic byte'ları.")
    if raw[4] != _VERSION:
        raise ValueError(f"Desteklenmeyen vault versiyonu: {raw[4]}")

    salt  = raw[5 : 5 + _SALT_SIZE]                # 5:21
    nonce = raw[21 : 21 + _NONCE_SIZE]              # 21:33
    # token_id (raw[33:49]) — okunmaz, sadece HMAC koruması altında

    protected  = raw[: -_HMAC_SIZE]                 # HMAC hariç tüm içerik
    tag        = protected[-_TAG_SIZE:]              # protected'in son 16 byte'ı
    ciphertext = protected[_HEADER_SIZE : -_TAG_SIZE]

    kek = _derive_kek(pin, salt)

    decryptor = Cipher(algorithms.AES(kek), modes.GCM(nonce, tag)).decryptor()
    decryptor.authenticate_additional_data(hwid.encode())

    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as exc:
        raise ValueError(
            "PIN yanlış veya vault bozulmuş — GCM kimlik doğrulama başarısız."
        ) from exc

    # Format: s1_len(2B) || share_1(s1_len B) || role
    if len(plaintext) < 3:
        raise ValueError("Vault içeriği çok kısa; bozulmuş.")
    s1_len = struct.unpack(">H", plaintext[:2])[0]
    role_bytes = plaintext[2 + s1_len :]

    if not role_bytes:
        raise ValueError("Vault içinde rol bilgisi bulunamadı.")

    return role_bytes.decode()


def change_vault_role(hwid: str, pin: str, new_role: str) -> None:
    """
    Vault'ta kayıtlı rolü değiştirir.

    Master key ve Shamir payları korunur; yalnızca rol bilgisi güncellenir.
    Yeni bir GCM nonce ile yeniden şifrelenir (aynı KEK, aynı salt).
    Vault HMAC imzası güncellenir, share_2 ve token_id değişmez.

    Args:
        hwid     — USB donanım kimliği (GCM AAD + HMAC imza anahtarı)
        pin      — Vault PIN kodu (KEK türetme girdisi)
        new_role — Yazılacak yeni rol string'i

    Raises:
        FileNotFoundError  — vault dosyası yoksa
        VaultTamperedError — HMAC doğrulaması başarısızsa
        ValueError         — PIN yanlış, vault formatı geçersiz veya rol boşsa
    """
    if not new_role:
        raise ValueError("Yeni rol boş olamaz.")

    verify_vault(hwid)

    raw = _read_vault_path(hwid).read_bytes()

    if raw[:4] != _MAGIC:
        raise VaultTamperedError("Geçersiz vault magic byte'ları.")
    if raw[4] != _VERSION:
        raise ValueError(f"Desteklenmeyen vault versiyonu: {raw[4]}")

    salt       = raw[5 : 5 + _SALT_SIZE]
    nonce      = raw[21 : 21 + _NONCE_SIZE]
    token_id_b = raw[_TOKEN_ID_OFFSET : _TOKEN_ID_OFFSET + _TOKEN_ID_SIZE]

    protected  = raw[:-_HMAC_SIZE]
    tag        = protected[-_TAG_SIZE:]
    ciphertext = protected[_HEADER_SIZE:-_TAG_SIZE]

    kek = _derive_kek(pin, salt)

    decryptor = Cipher(algorithms.AES(kek), modes.GCM(nonce, tag)).decryptor()
    decryptor.authenticate_additional_data(hwid.encode())
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as exc:
        raise ValueError(
            "PIN yanlış veya vault bozulmuş — GCM kimlik doğrulama başarısız."
        ) from exc

    if len(plaintext) < 2:
        raise ValueError("Vault içeriği çok kısa; bozulmuş.")

    s1_len = struct.unpack(">H", plaintext[:2])[0]
    share_1_bytes = plaintext[2 : 2 + s1_len]

    new_plaintext = struct.pack(">H", s1_len) + share_1_bytes + new_role.encode()

    new_nonce = os.urandom(_NONCE_SIZE)
    encryptor = Cipher(algorithms.AES(kek), modes.GCM(new_nonce)).encryptor()
    encryptor.authenticate_additional_data(hwid.encode())
    new_ct = encryptor.update(new_plaintext) + encryptor.finalize()
    new_tag = encryptor.tag

    new_protected = (
        _MAGIC + bytes([_VERSION]) + salt + new_nonce
        + token_id_b + new_ct + new_tag
    )
    _rewrite_vault(hwid, new_protected)


def change_vault_pin(hwid: str, old_pin: str, new_pin: str) -> None:
    """
    Vault PIN'ini değiştirir.

    Eski PIN ile çözülür, yeni salt + yeni KEK ile yeniden şifrelenir.
    Master key ve Shamir payları korunur; yalnızca şifreleme anahtarı yenilenir.

    Raises:
        FileNotFoundError  — vault dosyası yoksa
        VaultTamperedError — HMAC doğrulaması başarısızsa
        ValueError         — eski PIN yanlış, vault formatı geçersiz veya yeni PIN boşsa
    """
    if not new_pin:
        raise ValueError("Yeni PIN boş olamaz.")

    verify_vault(hwid)

    raw = _read_vault_path(hwid).read_bytes()
    if raw[:4] != _MAGIC:
        raise VaultTamperedError("Geçersiz vault magic byte'ları.")
    if raw[4] != _VERSION:
        raise ValueError(f"Desteklenmeyen vault versiyonu: {raw[4]}")

    salt       = raw[5 : 5 + _SALT_SIZE]
    nonce      = raw[21 : 21 + _NONCE_SIZE]
    token_id_b = raw[_TOKEN_ID_OFFSET : _TOKEN_ID_OFFSET + _TOKEN_ID_SIZE]

    protected  = raw[:-_HMAC_SIZE]
    tag        = protected[-_TAG_SIZE:]
    ciphertext = protected[_HEADER_SIZE:-_TAG_SIZE]

    old_kek = _derive_kek(old_pin, salt)
    decryptor = Cipher(algorithms.AES(old_kek), modes.GCM(nonce, tag)).decryptor()
    decryptor.authenticate_additional_data(hwid.encode())
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as exc:
        raise ValueError(
            "Eski PIN yanlış veya vault bozulmuş — GCM kimlik doğrulama başarısız."
        ) from exc

    new_salt  = os.urandom(_SALT_SIZE)
    new_nonce = os.urandom(_NONCE_SIZE)
    new_kek   = _derive_kek(new_pin, new_salt)

    encryptor = Cipher(algorithms.AES(new_kek), modes.GCM(new_nonce)).encryptor()
    encryptor.authenticate_additional_data(hwid.encode())
    new_ct  = encryptor.update(plaintext) + encryptor.finalize()
    new_tag = encryptor.tag

    new_protected = (
        _MAGIC + bytes([_VERSION]) + new_salt + new_nonce
        + token_id_b + new_ct + new_tag
    )
    _rewrite_vault(hwid, new_protected)


def open_vault(hwid: str, pin: str) -> tuple[str, bytes]:
    """
    Vault'u PIN ile açar; rol ve dosya şifreleme için master_key döndürür.

    Returns:
        (role, master_key) — rol string ve 32 byte AES-256 dosya şifreleme anahtarı

    Raises:
        FileNotFoundError  — vault dosyası yoksa
        VaultTamperedError — HMAC doğrulaması başarısızsa
        ValueError         — PIN yanlış veya vault formatı geçersizse
    """
    verify_vault(hwid)

    raw = _read_vault_path(hwid).read_bytes()

    if raw[:4] != _MAGIC:
        raise VaultTamperedError("Geçersiz vault magic byte'ları.")
    if raw[4] != _VERSION:
        raise ValueError(f"Desteklenmeyen vault versiyonu: {raw[4]}")

    salt       = raw[5 : 5 + _SALT_SIZE]
    nonce      = raw[21 : 21 + _NONCE_SIZE]
    protected  = raw[:-_HMAC_SIZE]
    tag        = protected[-_TAG_SIZE:]
    ciphertext = protected[_HEADER_SIZE:-_TAG_SIZE]

    kek = _derive_kek(pin, salt)
    decryptor = Cipher(algorithms.AES(kek), modes.GCM(nonce, tag)).decryptor()
    decryptor.authenticate_additional_data(hwid.encode())
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as exc:
        raise ValueError("PIN yanlış veya vault bozulmuş — GCM kimlik doğrulama başarısız.") from exc

    if len(plaintext) < 3:
        raise ValueError("Vault içeriği çok kısa; bozulmuş.")

    s1_len  = struct.unpack(">H", plaintext[:2])[0]
    share_1 = plaintext[2 : 2 + s1_len].decode()
    role    = plaintext[2 + s1_len :].decode()

    row = DBManager().fetchone("SELECT share_2 FROM usb_tokens WHERE hwid = ?", (hwid,))
    if row is None:
        raise ValueError("USB token DB'de bulunamadı — master_key kurtarılamaz.")

    master_key = _sss_recover(share_1, row["share_2"])
    return role, master_key


def reconstruct_key(share_1: str, share_2: str) -> bytes:
    """
    İki Shamir payını birleştirerek orijinal master_key'i kurtarır.

    Her iki pay da gereklidir; biri eksikse veya bozuksa kurtarma başarısız olur.

    Args:
        share_1 — Vault dosyasından alınan 1. pay ("1:<hex>")
        share_2 — DB usb_tokens tablosundan alınan 2. pay ("2:<hex>")

    Returns:
        32 byte master_key

    Raises:
        ValueError — paylar geçersiz formattaysa veya birbirleriyle uyumsuzsa
    """
    return _sss_recover(share_1, share_2)
