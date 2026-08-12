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

Shamir Secret Sharing (2-of-3):
  · master_key 3 parçaya bölünür (threshold=2, shares=3)
  · share_1 — vault ciphertext içinde şifreli olarak saklanır
  · share_2 — işletim sistemi anahtar kasasına yazılır (bkz. CORE/secret_store.py)
              kasa kaydı: servis "HYCLEUS", kullanıcı adı "share_2:<hwid>"
              DB'deki usb_tokens.share_2 sütunu şema uyumluluğu için duruyor
              ama boş — sır orada TUTULMAZ (migration: CORE/secret_migration.py)
  · share_3 — KURTARMA PARÇASI. Sistemde hiçbir yerde saklanmaz; bir kez
              gösterilip kullanıcı tarafından fiziksel olarak saklanır.
              Aynı polinomdan geldiği için share_1 + share_2'den her an
              yeniden türetilebilir (export_recovery_share).
  · Üç paydan HERHANGİ İKİSİ master_key'i kurtarır (reconstruct_key)

Geriye dönük uyumluluk:
  2-of-2 döneminde oluşturulmuş vault'larda share_1 ve share_2 zaten f(1) ve
  f(2)'dir; f(3) = 2*f(2) - f(1) aynı polinomdan gelir. Mevcut vault'lar
  YENİDEN ANAHTARLANMADAN 2-of-3'e yükseltilir — share_1/share_2 hiç değişmez.

USB kimlik doğrulama katmanları (authenticate_usb):
  · Katman 1 — HWID    : usb_tokens tablosunda kayıtlı mı?
  · Katman 2 — HMAC    : vault dosyası bütünlüğü geçerli mi?
  · Katman 3 — Token ID: vault token_id == DB token_id?

Kara liste (_reject_if_blacklisted):
  Hem authenticate_usb() hem open_vault() aynı kontrolden geçer — yani
  kara listedeki bir cihaz ne USB yeniden takma akışında ne de PIN
  girişinde vault'u açabilir. Bu bir İPTAL değildir: share_1 vault'ta,
  share_2 anahtar kasasında geçerliliğini korur; yalnızca erişim engellenir.
  Gerçek iptal için delete_usb_token() + vault'un yeniden anahtarlanması
  gerekir (bkz. SECURITY.md §4.1).

Şifreleme güvenlik katmanları:
  · KEK   — Argon2id(password=pin, salt=salt) → 32 byte şifreleme anahtarı
  · GCM   — Şifreleme + bütünlük; HWID cihaz bağlayıcı AAD olarak iletilir
  · HMAC  — HWID'den HKDF ile türetilen 32 byte imza anahtarıyla dosya bütünlüğü
  · SSS   — master_key üç paydan herhangi ikisi olmadan kurtarılamaz (2-of-3)
"""
from __future__ import annotations

import ctypes
import hmac as _stdlib_hmac
import os
import secrets
import struct
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, NoReturn

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from CORE import secret_store
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
# GF(p) içinde derece-1 polinom: f(x) = s + a1*x mod p
#
# p = 2^256 + 297 asaldır (Miller-Rabin, 64 tur ile doğrulandı). Bu önemli:
# 2-of-2 şemasında kurtarma yalnızca inv(1)=1 kullanıyordu, yani asallık hiç
# sınanmıyordu. 2-of-3'te genel Lagrange inv(2) gerektiriyor ve şemanın
# bilgi-teorik güvenliği alanın gerçekten bir CİSİM olmasına dayanıyor.
_SSS_PRIME = 2**256 + 297

# 2-of-3: üç pay üretilir, herhangi ikisi anahtarı kurtarır
_SSS_THRESHOLD = 2
_SSS_INDEXES = (1, 2, 3)

# 3. pay = kurtarma parçası. Sistemde HİÇBİR YERDE saklanmaz; bir kez
# gösterilip kullanıcı tarafından fiziksel olarak saklanır.
_SSS_RECOVERY_INDEX = 3

# share formatı: "1:<66 hex char>" — 33 byte değer, byte-hizalı
_SSS_SHARE_HEX_LEN = 66  # ceil(257/8) = 33 byte → 66 hex char

# TOKEN_ID, NONCE'tan hemen sonra gelir — şifresiz ama HMAC imzalı
_TOKEN_ID_OFFSET = len(_MAGIC) + 1 + _SALT_SIZE + _NONCE_SIZE  # 33 B

_HEADER_SIZE = _TOKEN_ID_OFFSET + _TOKEN_ID_SIZE  # 49 B
# share_1 = "1:" + 66 hex = 68 B; s1_len prefix = 2B; role min 1 char
_MIN_VAULT_SIZE = _HEADER_SIZE + 2 + 68 + 1 + _TAG_SIZE + _HMAC_SIZE  # 172 B

from CORE.paths import data_dir as _data_dir
_VAULT_PATH_LEGACY = _data_dir() / ".hcl_vault"
_VAULT_DIR         = _data_dir() / "vaults"


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

# kernel32 yalnızca Windows'ta bağlanır — `import ctypes.wintypes` ve
# `ctypes.windll` diğer platformlarda import anında patlar.
#
# HYCLEUS bir Windows uygulamasıdır ve readonly biti NTFS'e özgüdür; bu modülün
# kripto katmanı (Shamir, Argon2id, HMAC, AES-GCM) ise platformdan bağımsızdır.
# Bağlamayı koşullu yaparak CI'ın Linux ayağı modülü import edip kripto
# testlerini çalıştırabiliyor. Windows dışında _k32 None kalır ve aşağıdaki üç
# readonly yardımcısı no-op'a döner.
_k32: Any = None

if sys.platform == "win32":
    import ctypes.wintypes

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


def _fmt_share(index: int, y: int) -> str:
    """Payı "index:<hex>" biçimine getirir."""
    return f"{index}:{y:0{_SSS_SHARE_HEX_LEN}x}"


def _parse_share(share: str) -> tuple[int, int]:
    """
    "index:<hex>" payını (index, y) olarak ayrıştırır.

    Raises:
        ValueError — biçim bozuksa veya indis geçerli aralıkta değilse
    """
    if ":" not in share:
        raise ValueError(f"Pay biçimi 'indis:hex' olmalı, alınan: {share[:16]!r}")
    idx_raw, hex_raw = share.split(":", 1)
    try:
        index = int(idx_raw)
    except ValueError as exc:
        raise ValueError(f"Pay indisi sayı olmalı, alınan: {idx_raw!r}") from exc
    if index not in _SSS_INDEXES:
        raise ValueError(f"Geçersiz pay indisi {index}; beklenen: {_SSS_INDEXES}")
    try:
        y = int(hex_raw, 16)
    except ValueError as exc:
        raise ValueError("Pay değeri geçerli onaltılık sayı değil.") from exc
    return index, y


def _sss_split(secret: bytes, *, anchor: str | None = None) -> tuple[str, str, str]:
    """
    32-byte secret'i 2-of-3 Shamir paylarına böler.

    Polinom: f(x) = s + a1*x  (mod _SSS_PRIME, derece-1)
    share_1 = f(1),  share_2 = f(2),  share_3 = f(3)

    Eşik 2'dir: üç paydan HERHANGİ İKİSİ anahtarı kurtarır, tek pay hiçbir
    bilgi vermez (derece-1 polinomda tek nokta sonsuz çözüme uyar).

    Args:
        secret — 32 byte master_key
        anchor — verilirse AYNI POLİNOM yeniden kurulur: a1, f(anchor.index)
                 tam olarak anchor'un değerine eşit olacak biçimde çözülür.
                 Kurtarma sonrası yeniden kurulumda kullanılır; kullanıcının
                 elindeki basılı kurtarma parçası böylece geçerli kalır.
                 Verilmezse a1 rastgele seçilir (normal ilk kurulum).

    Returns:
        (share_1, share_2, share_3) — sırasıyla vault, anahtar kasası, kurtarma
    """
    s = int.from_bytes(secret, "big")
    if anchor is None:
        a1 = secrets.randbelow(_SSS_PRIME - 1) + 1  # [1, PRIME-1]
    else:
        # f(x_a) = s + a1*x_a = y_a  →  a1 = (y_a - s) / x_a
        x_a, y_a = _parse_share(anchor)
        a1 = ((y_a - s) * pow(x_a, -1, _SSS_PRIME)) % _SSS_PRIME
    return tuple(  # type: ignore[return-value]
        _fmt_share(i, (s + i * a1) % _SSS_PRIME) for i in _SSS_INDEXES
    )


def _lagrange_at(points: list[tuple[int, int]], x: int) -> int:
    """
    Verilen noktalardan geçen polinomu x noktasında değerlendirir (mod p).

    Derece-1 için iki nokta yeterlidir. Genel Lagrange kullanılır; özel
    (1,2) formülüyle aynı sonucu verir, dolayısıyla mevcut vault'ları bozmaz.
    """
    total = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (x - xj)) % _SSS_PRIME
            den = (den * (xi - xj)) % _SSS_PRIME
        total = (total + yi * num * pow(den, -1, _SSS_PRIME)) % _SSS_PRIME
    return total


def _sss_recover(share_a: str, share_b: str) -> bytes:
    """
    HERHANGİ İKİ Shamir payından orijinal secret'i kurtarır.

    Geçerli kombinasyonlar: (1,2) (1,3) (2,3) — ve simetrik olarak tersleri.
    Aynı indisin iki kez verilmesi reddedilir: tek pay eşiği karşılamaz ve
    sessizce yanlış bir anahtar dönmek, kullanıcının kurtardığını sanmasına
    yol açardı.

    Raises:
        ValueError — pay biçimi bozuksa veya iki pay aynı indise sahipse
    """
    idx_a, y_a = _parse_share(share_a)
    idx_b, y_b = _parse_share(share_b)
    if idx_a == idx_b:
        raise ValueError(
            f"İki pay da {idx_a} indisli — eşik {_SSS_THRESHOLD}, "
            "farklı indisli iki pay gerekli."
        )
    secret_int = _lagrange_at([(idx_a, y_a), (idx_b, y_b)], 0)
    return secret_int.to_bytes(_KEY_SIZE, "big")


def _sss_derive_share(share_a: str, share_b: str, index: int) -> str:
    """
    Bilinen iki paydan üçüncü payı türetir — polinom aynı kalır.

    Geriye dönük uyumluluğun temeli budur: 2-of-2 döneminde oluşturulmuş bir
    vault'ta share_1 ve share_2 zaten f(1) ve f(2)'dir; f(3) = 2*f(2) - f(1)
    aynı polinomdan gelir. Yani mevcut vault'lar YENİDEN ANAHTARLANMADAN
    ve share_1/share_2'ye HİÇ DOKUNULMADAN 2-of-3'e yükseltilebilir.

    Raises:
        ValueError — indis geçersizse veya iki pay aynı indisliyse
    """
    if index not in _SSS_INDEXES:
        raise ValueError(f"Geçersiz pay indisi {index}; beklenen: {_SSS_INDEXES}")
    idx_a, y_a = _parse_share(share_a)
    idx_b, y_b = _parse_share(share_b)
    if idx_a == idx_b:
        raise ValueError(f"İki pay da {idx_a} indisli — türetme için iki farklı pay gerekli.")
    return _fmt_share(index, _lagrange_at([(idx_a, y_a), (idx_b, y_b)], index))


def _save_usb_token(hwid: str, share_2: str, token_id_hex: str) -> None:
    """
    USB token kaydını yazar: share_2 anahtar kasasına, token_id DB'ye.

    share_2 artık DB'de TUTULMAZ. usb_tokens.share_2 sütunu şema uyumluluğu
    için duruyor ama boş string yazılır — HWID satırının kendisi kimlik
    doğrulama katmanları (HWID kaydı, token_id, blacklisted) için gerekli.

    Kasaya yazma önce yapılır ve store() geri okuyup doğrular; kasa
    yazamazsa KeyringUnavailableError fırlar ve DB'ye hiç dokunulmaz.
    """
    secret_store.store(secret_store.share_2_username(hwid), share_2)
    DBManager().execute(
        "INSERT OR REPLACE INTO usb_tokens (hwid, share_2, token_id) VALUES (?, '', ?)",
        (hwid, token_id_hex),
    )


def _load_share_2(hwid: str) -> str:
    """
    share_2'yi anahtar kasasından okur.

    Kasada yoksa DB'ye DÜŞÜLMEZ — migration çalışmamış ya da kayıt silinmiş
    demektir; sessizce düz metin kaynağa dönmek migration'ın amacını yok eder.

    Raises:
        KeyringUnavailableError — kasaya erişilemiyorsa
        ValueError              — kayıt kasada yoksa
    """
    share_2 = secret_store.load(secret_store.share_2_username(hwid))
    if share_2 is None:
        raise ValueError(
            f"HWID '{hwid}' için share_2 anahtar kasasında bulunamadı — "
            "master_key kurtarılamaz.\n"
            "USB kaydı silinmiş ya da migration bu cihazda hiç çalışmamış olabilir."
        )
    return share_2


def delete_usb_token(hwid: str) -> None:
    """
    Bir USB token'ın hem DB satırını hem kasadaki share_2 kaydını siler.

    Yalnızca DB satırını silmek kasada yetim bir sır bırakır; iki kaynağın
    birlikte temizlenmesi için tüm silme noktaları buradan geçmelidir.
    """
    secret_store.erase(secret_store.share_2_username(hwid))
    DBManager().execute("DELETE FROM usb_tokens WHERE hwid = ?", (hwid,))


def _set_readonly(path: Path) -> None:
    """Dosyaya FILE_ATTRIBUTE_READONLY uygular (Windows dışında no-op)."""
    if _k32 is None:
        return
    if not _k32.SetFileAttributesW(str(path), _FILE_ATTRIBUTE_READONLY):
        raise OSError(f"Readonly bit ayarlanamadı: {path}  (hata: {ctypes.GetLastError()})")


def _clear_readonly(path: Path) -> None:
    """Dosyadan FILE_ATTRIBUTE_READONLY özelliğini kaldırır (Windows dışında no-op)."""
    if _k32 is None:
        return
    if not _k32.SetFileAttributesW(str(path), _FILE_ATTRIBUTE_NORMAL):
        raise OSError(f"Readonly bit temizlenemedi: {path}  (hata: {ctypes.GetLastError()})")


@contextmanager
def _writable(path: Path) -> Iterator[None]:
    """
    Vault dosyasını geçici olarak yazılabilir yapar.

    Giriş : dosya mevcutsa readonly bitini kaldırır.
    Çıkış : dosya mevcutsa (istisna olsa bile) readonly bitini geri uygular.

    Windows dışında readonly biti yoktur; bağlam yöneticisi saf geçiş olur.
    """
    was_readonly = (
        _k32 is not None
        and path.exists()
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

def create_vault(
    hwid: str,
    pin: str,
    role: str,
    *,
    master_key: bytes | None = None,
    anchor_share: str | None = None,
) -> Path:
    """
    Yeni bir vault dosyası oluşturur ve data/.hcl_vault'a yazar.

    ⚠️ master_key VERİLMEZSE YENİ BİR ANAHTAR ÜRETİLİR. Mevcut .hcl
    dosyaları eski anahtarla şifrelenmiş olduğundan bir daha AÇILAMAZ.
    Kurtarma sonrası yeniden kurulumda mutlaka master_key geçin
    (bkz. reprovision_vault).

    Args:
        master_key   — verilirse bu anahtar kullanılır (kurtarma akışı);
                       verilmezse yeni rastgele anahtar üretilir
        anchor_share — verilirse AYNI POLİNOM korunur, yani kullanıcının
                       elindeki basılı kurtarma parçası geçerli kalır

    İşlem adımları:
      1. 32 byte kriptografik rastgele master key üretir (master_key verilmediyse)
      2. UUID token_id üretir (cihaz bağlama kimliği)
      3. Shamir 2-of-3 ile master_key'i böler; share_1 ve share_2 saklanır,
         share_3 (kurtarma parçası) saklanmaz — gerektiğinde türetilir
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
    if master_key is None:
        master_key = os.urandom(_KEY_SIZE)
    elif len(master_key) != _KEY_SIZE:
        raise ValueError(f"master_key {_KEY_SIZE} byte olmalı, {len(master_key)} verildi.")
    token_id_bytes = uuid.uuid4().bytes   # 16 byte UUID
    token_id_hex = token_id_bytes.hex()   # DB'de hex string olarak saklanır

    # ── Shamir 2-of-3 bölme ──────────────────────────────────────────────────
    # share_3 (kurtarma parçası) BİLEREK saklanmaz ve döndürülmez: aynı
    # polinomdan geldiği için share_1 + share_2'den her an yeniden türetilebilir
    # (bkz. export_recovery_share). Böylece kurtarma parçası sistemde hiçbir
    # yerde durmaz ve yeni/eski vault ayrımı olmadan tek koddan üretilir.
    share_1, share_2, _share_3_derivable = _sss_split(master_key, anchor=anchor_share)

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
    # open_vault() ile ortak yardımcı — iki giriş yolunun ayrışmaması için
    _reject_if_blacklisted(hwid)

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


def _reject_if_blacklisted(hwid: str) -> None:
    """
    HWID kara listedeyse USBAuthError fırlatır ve audit log'a yazar.

    HEM authenticate_usb() HEM open_vault() bu yardımcıyı çağırır. Kontrol
    tek bir yerde durmalı: daha önce kara liste yalnızca authenticate_usb
    içinde bakılıyordu, oysa giriş ekranı open_vault'u doğrudan çağırıyor —
    yani kara listedeki bir USB geçerli PIN'le vault'u açabiliyordu.

    Kayıt yoksa burada karar verilmez; "kayıtlı değil" durumunu çağıranlar
    kendi bağlamlarına uygun mesajla ele alır.

    Raises:
        USBAuthError — cihaz kara listedeyse
    """
    db = DBManager()
    row = db.fetchone("SELECT blacklisted FROM usb_tokens WHERE hwid = ?", (hwid,))
    if row is None or not row["blacklisted"]:
        return
    reason = "USB cihazı kara listede; erişim reddedildi."
    db.log("usb_auth_rejected", detail=f"hwid={hwid} — {reason}")
    raise USBAuthError(reason)


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
        USBAuthError       — cihaz kara listedeyse
        FileNotFoundError  — vault dosyası yoksa
        VaultTamperedError — HMAC doğrulaması başarısızsa
        ValueError         — PIN yanlış veya vault formatı geçersizse
    """
    share_1, role = _decrypt_vault(hwid, pin)

    row = DBManager().fetchone("SELECT hwid FROM usb_tokens WHERE hwid = ?", (hwid,))
    if row is None:
        raise ValueError("USB token DB'de bulunamadı — master_key kurtarılamaz.")

    master_key = _sss_recover(share_1, _load_share_2(hwid))
    return role, master_key


def _decrypt_vault(hwid: str, pin: str) -> tuple[str, str]:
    """
    Vault'u PIN ile çözer; (share_1, role) döndürür.

    open_vault() ve export_recovery_share() ortak kullanır — kara liste ve
    HMAC kontrolleri tek yerde dursun diye ayrıldı.

    Raises:
        USBAuthError       — cihaz kara listedeyse
        FileNotFoundError  — vault dosyası yoksa
        VaultTamperedError — HMAC doğrulaması başarısızsa
        ValueError         — PIN yanlış veya vault formatı geçersizse
    """
    # Kara liste EN BAŞTA — PIN doğru olsa bile açılmamalı, ve Argon2id
    # maliyetine girmeden reddedilmeli. authenticate_usb ile aynı kontrol.
    _reject_if_blacklisted(hwid)

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
    return plaintext[2 : 2 + s1_len].decode(), plaintext[2 + s1_len :].decode()


def _read_share_1(hwid: str, pin: str) -> str:
    """Vault'tan yalnızca share_1'i okur (rol gerekmediğinde)."""
    return _decrypt_vault(hwid, pin)[0]


def has_recovery_share(hwid: str) -> bool:
    """Bu HWID için kurtarma parçası daha önce dışa aktarılmış mı."""
    row = DBManager().fetchone(
        "SELECT recovery_issued_at FROM usb_tokens WHERE hwid = ?", (hwid,)
    )
    return bool(row and row["recovery_issued_at"])


def export_recovery_share(hwid: str, pin: str) -> str:
    """
    Kurtarma parçasını (Shamir 3. payı) üretir ve döndürür.

    ⚠️ Döndürülen değer SAKLANMAZ. Çağıran taraf kullanıcıya bir kez
    gösterip bellekten bırakmalıdır. Buraya yazılan tek şey, parçanın
    dışa aktarıldığı ZAMAN DAMGASIDIR — parçanın kendisi değil.

    Parça, share_1 (vault, PIN ile açılır) ve share_2 (anahtar kasası)
    üzerinden f(3) olarak türetilir. Aynı polinomdan geldiği için:
      · Vault yeniden anahtarlanmaz, share_1/share_2 hiç değişmez
      · 2-of-2 döneminde oluşturulmuş vault'lar da aynı koddan geçer
      · Kaybedilirse (diğer iki pay hâlâ elde olduğu sürece) yeniden üretilebilir

    Args:
        hwid — USB donanım kimliği
        pin  — vault'u açmak için gereken PIN

    Returns:
        "3:<hex>" biçiminde kurtarma payı

    Raises:
        USBAuthError       — cihaz kara listedeyse
        ValueError         — PIN yanlışsa veya share_2 kasada yoksa
        VaultTamperedError — vault bütünlüğü bozuksa
    """
    share_1 = _read_share_1(hwid, pin)
    share_2 = _load_share_2(hwid)
    share_3 = _sss_derive_share(share_1, share_2, _SSS_RECOVERY_INDEX)

    # Yalnızca "dışa aktarıldı" bilgisi kaydedilir — parçanın kendisi ASLA
    DBManager().execute(
        "UPDATE usb_tokens SET recovery_issued_at = "
        "strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE hwid = ?",
        (hwid,),
    )
    DBManager().log("recovery_share_exported", detail=f"hwid={hwid}")
    return share_3


def recover_master_key(
    hwid: str,
    *,
    recovery_share: str,
    pin: str | None = None,
) -> bytes:
    """
    Kurtarma parçası + kalan bir pay ile master_key'i yeniden oluşturur.

    İki senaryo:
      · share_2 kayıp (kasa silinmiş / yeni makine) → pin verilir, share_1
        vault'tan okunur, (1,3) ile kurtarılır
      · share_1 kayıp (vault dosyası yok/bozuk)     → pin verilmez, share_2
        kasadan okunur, (2,3) ile kurtarılır

    Args:
        hwid           — USB donanım kimliği
        recovery_share — "3:<hex>" kurtarma payı
        pin            — verilirse share_1 vault'tan okunur; yoksa share_2 kasadan

    Returns:
        32 byte master_key

    Raises:
        ValueError — kurtarma payı geçersizse veya kalan pay okunamıyorsa
    """
    _parse_share(recovery_share)  # biçim doğrulaması, erken hata

    if pin is not None:
        kalan = _read_share_1(hwid, pin)
    else:
        kalan = _load_share_2(hwid)

    master_key = _sss_recover(kalan, recovery_share)
    DBManager().log(
        "vault_recovered",
        detail=f"hwid={hwid} kaynak={'share_1+share_3' if pin else 'share_2+share_3'}",
    )
    return master_key


def reprovision_vault(
    hwid: str,
    pin: str,
    role: str,
    *,
    master_key: bytes,
    recovery_share: str,
) -> Path:
    """
    Kurtarma sonrası vault'u YENİDEN KURAR — anahtarı ve polinomu koruyarak.

    Neden ayrı bir fonksiyon: create_vault() varsayılan olarak YENİ bir
    master_key üretir. Kurtarma akışında bunu kullanmak, mevcut .hcl
    dosyalarını kalıcı olarak açılamaz hâle getirirdi.

    Korunanlar:
      · master_key — mevcut .hcl dosyaları açılmaya devam eder
      · polinom    — f(1), f(2), f(3) değerleri aynı kalır, yani kullanıcının
                     elindeki BASILI KURTARMA PARÇASI GEÇERLİLİĞİNİ SÜRDÜRÜR

    Değişenler:
      · vault dosyası yolu (yeni HWID)
      · Argon2id salt + GCM nonce (yeni PIN ile yeniden mühürlenir)
      · token_id (yeni UUID)
      · share_2'nin kasadaki adı ("share_2:<yeni hwid>")

    ⚠️ Güvenlik takası: pay DEĞERLERİ döndürülmediği için, eski kuruluma ait
    bir share_2 kopyası sızmışsa geçerli kalmaya devam eder. Payları
    döndürmek isterseniz recovery_share vermeyin — ama o zaman elinizdeki
    basılı parça geçersizleşir ve yenisini dışa aktarmanız gerekir.

    Args:
        hwid           — YENİ USB'nin donanım kimliği
        pin            — yeni PIN
        role           — kullanıcı rolü
        master_key     — recover_master_key() ile kurtarılmış 32 byte anahtar
        recovery_share — kullanıcının elindeki "3:<hex>" parça (polinom çıpası)

    Returns:
        Yeni vault dosyasının yolu
    """
    _parse_share(recovery_share)
    path = create_vault(
        hwid, pin, role, master_key=master_key, anchor_share=recovery_share
    )
    # Kurtarma parçası değişmedi — daha önce alınmış sayılır
    DBManager().execute(
        "UPDATE usb_tokens SET recovery_issued_at = "
        "strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE hwid = ?",
        (hwid,),
    )
    DBManager().log(
        "vault_reprovisioned",
        detail=f"hwid={hwid} master_key=korundu polinom=korundu",
    )
    return path


def reconstruct_key(share_a: str, share_b: str) -> bytes:
    """
    Herhangi iki Shamir payını birleştirerek orijinal master_key'i kurtarır.

    2-of-3 şema: (1,2) (1,3) (2,3) kombinasyonlarının üçü de çalışır.
    Tek pay yeterli değildir; aynı indisli iki pay reddedilir.

    Args:
        share_a — Herhangi bir pay ("1:<hex>", "2:<hex>" veya "3:<hex>")
        share_b — Farklı indisli ikinci pay

    Pay konumları:
        1 — vault dosyası içinde (Argon2id/PIN ile şifreli)
        2 — işletim sistemi anahtar kasası ("share_2:<hwid>")
        3 — kurtarma parçası; sistemde saklanmaz, kullanıcıda fiziksel olarak

    Returns:
        32 byte master_key

    Raises:
        ValueError — paylar geçersiz formattaysa veya aynı indisliyse
    """
    return _sss_recover(share_a, share_b)
