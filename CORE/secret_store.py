"""
HYCLEUS — İşletim sistemi anahtar kasası (keyring) sarmalayıcısı

Sırlar artık düz metin olarak DB'de veya JSON dosyasında değil, işletim
sisteminin kendi anahtar kasasında tutulur. keyring kütüphanesi arka ucu
platforma göre otomatik seçer:

  · Windows — Credential Manager (DPAPI ile kullanıcı hesabına bağlı şifreleme)
  · macOS   — Keychain
  · Linux   — Secret Service (GNOME Keyring / KWallet)

Adlandırma şeması
-----------------
Servis adı her kayıtta sabit: "HYCLEUS"

Kullanıcı adı (username) alanı sırrın kimliğidir:

  share_2:<hwid>   — USB token'ın Shamir 2. payı
                     HWID ile anahtarlanır çünkü share_2 cihaz başınadır:
                     usb_tokens tablosunda hwid UNIQUE ve her yetkili USB'nin
                     kendi payı var. Sabit bir ad kullanılsaydı ikinci USB
                     birincinin payını ezerdi.

  totp_secret      — TOTP (authenticator) paylaşılan sırrı
                     Sabit ad, çünkü mevcut tasarımda tek bir global sır var
                     (data/totp_secret.json kullanıcı başına değil, kurulum
                     başına tutuluyordu). Kullanıcı başına TOTP'ye geçilirse
                     bu ad "totp_secret:<user_id>" biçimine genişletilmeli.

Erişilemezlik politikası
------------------------
Anahtar kasası açılamıyorsa (başsız Linux, Secret Service yok, kilitli kasa)
ESKİ DAVRANIŞA SESSİZCE DÜŞÜLMEZ. ensure_available() KeyringUnavailableError
fırlatır ve uygulama açılmayı reddeder — aksi halde sır düz metin olarak
diskte kalmaya devam eder ve kullanıcı korunduğunu sanır.

TPM mühürlemesi
---------------
Windows'ta TPM 2.0 varsa değer kasaya yazılmadan ÖNCE TPM'e mühürleniyor
(`CORE/tpm_sealing.py`). Kasa kaydı o zaman `"TPM1:<base64>"` biçiminde
oluyor; öneksiz kayıtlar mühürsüzdür ve olduğu gibi okunuyor, yani mevcut
kurulumlar etkilenmiyor.

Bu modülün ARAYÜZÜ değişmedi: `store()` düz metin alıyor, `load()` düz
metin döndürüyor. Mühür bu iki fonksiyonun içinde açılıp kapanıyor ve
sistemdeki BAŞKA hiçbir yer `tpm_sealing.belki_muhurle/belki_coz`
çağırmıyor — `tests/test_tpm_sealing.py` bunu AST ile denetliyor.

`ensure_available()`'ın sonda kaydı BİLEREK mühürsüz: o yoklama kasanın
erişilebilirliğini ölçüyor, TPM'inkini değil. Mühürlenseydi bir TPM
sorunu "anahtar kasası erişilemiyor" diye rapor edilir ve açılışı
engellerdi — TPM'in yokluğu ise açılışı engellemiyor.
"""
from __future__ import annotations

import secrets
from typing import Any

from CORE import tpm_sealing

SERVICE = "HYCLEUS"

# Kullanıcı adı şeması
_SHARE_2_PREFIX = "share_2:"
TOTP_USERNAME = "totp_secret"

# ensure_available() için tek kullanımlık sonda kaydı
_PROBE_USERNAME = "__hycleus_probe__"

try:
    import keyring as _keyring
    import keyring.errors as _keyring_errors

    _IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover — paket kurulu değilse
    _keyring = None  # type: ignore[assignment]
    _keyring_errors = None  # type: ignore[assignment]
    _IMPORT_ERROR = exc


class KeyringUnavailableError(RuntimeError):
    """
    İşletim sistemi anahtar kasasına erişilemediğinde fırlatılır.

    Bu istisna YAKALANIP eski (düz metin) davranışa düşülmemelidir —
    çağıran taraf kullanıcıya göstermeli ve işlemi durdurmalıdır.
    """


def share_2_username(hwid: str) -> str:
    """share_2 kaydının keyring kullanıcı adını üretir."""
    if not hwid:
        raise ValueError("share_2 için HWID boş olamaz.")
    return f"{_SHARE_2_PREFIX}{hwid}"


def backend_name() -> str:
    """Aktif keyring arka ucunun adı — hata mesajlarında ve audit log'da kullanılır."""
    if _keyring is None:
        return "<keyring kurulu değil>"
    try:
        return type(_keyring.get_keyring()).__name__
    except Exception:
        return "<bilinmiyor>"


def ensure_available() -> None:
    """
    Anahtar kasasının gerçekten yazılıp okunabildiğini doğrular.

    Arka ucun varlığına bakmak yetmez: başsız Linux'ta chainer yüklü görünür
    ama ilk yazmada NoKeyringError fırlar, kilitli bir kasada ise yazma sessizce
    başarısız olabilir. Bu yüzden gerçek bir sonda kaydı yazılır, geri okunur,
    karşılaştırılır ve silinir.

    Raises:
        KeyringUnavailableError — kasa yoksa, kilitliyse veya round-trip tutmazsa
    """
    if _keyring is None:
        raise KeyringUnavailableError(
            "keyring paketi kurulu değil — sırlar güvenli biçimde saklanamaz.\n"
            f"Ayrıntı: {_IMPORT_ERROR}\n"
            "Çözüm: pip install -r requirements.txt"
        )

    canary = secrets.token_hex(16)
    try:
        _keyring.set_password(SERVICE, _PROBE_USERNAME, canary)
        readback = _keyring.get_password(SERVICE, _PROBE_USERNAME)
    except Exception as exc:
        raise KeyringUnavailableError(
            "İşletim sistemi anahtar kasası açılamadı — HYCLEUS başlatılamaz.\n"
            f"Arka uç: {backend_name()}\n"
            f"Ayrıntı: {type(exc).__name__}: {exc}\n\n"
            "Olası nedenler: başsız (headless) Linux oturumu, Secret Service "
            "servisi çalışmıyor, ya da kasa kilitli.\n"
            "HYCLEUS sırları düz metin olarak saklamaya geri dönmez; "
            "kasayı açıp yeniden deneyin."
        ) from exc
    finally:
        # Sonda kaydı her durumda temizlenmeli
        try:
            _keyring.delete_password(SERVICE, _PROBE_USERNAME)
        except Exception:
            pass

    if readback != canary:
        raise KeyringUnavailableError(
            "Anahtar kasası yazma/okuma turu tutmadı — kasa güvenilir değil.\n"
            f"Arka uç: {backend_name()}\n"
            "Yazılan değer geri okunamadı; HYCLEUS başlatılamaz."
        )


def load(username: str) -> str | None:
    """
    Kasadan bir sır okur ve mühürlüyse açar. Kayıt yoksa None döner.

    Mühürlü bir kaydın AÇILAMAMASI None ile karıştırılmıyor: None "kayıt
    yok" demektir ve çağıran tarafı sırrı yeniden kurmaya, yani mevcut
    olanı kaybetmeye iterdi. O durumda istisna fırlıyor.

    Raises:
        KeyringUnavailableError — kasaya erişilemiyorsa (kayıt yokluğu ile
            karıştırma), ya da kayıt TPM'e mühürlü olduğu hâlde açılamıyorsa
            (TPM temizlenmiş ya da değişmiş olabilir)
    """
    if _keyring is None:
        raise KeyringUnavailableError(
            f"keyring paketi kurulu değil — '{username}' okunamaz. Ayrıntı: {_IMPORT_ERROR}"
        )
    try:
        saklanan = _keyring.get_password(SERVICE, username)
    except Exception as exc:
        raise KeyringUnavailableError(
            f"Anahtar kasasından '{username}' okunamadı.\n"
            f"Arka uç: {backend_name()}\n"
            f"Ayrıntı: {type(exc).__name__}: {exc}"
        ) from exc

    if saklanan is None:
        return None
    try:
        return tpm_sealing.belki_coz(saklanan, baglam=username)
    except tpm_sealing.TpmSealingError as exc:
        # Tip BİLEREK korunuyor. Çağıranların hepsi zaten
        # KeyringUnavailableError'ı "sır güvenli biçimde elde edilemedi"
        # diye ele alıyor ve doğru şeyi yapıyor: durdur, kullanıcıya göster.
        # Yeni bir istisna tipi sızdırmak mevcut çağıranların davranışını
        # değiştirirdi. Gerçek sebep `__cause__` zincirinde duruyor.
        raise KeyringUnavailableError(
            f"'{username}' kaydı TPM'e mühürlü ve AÇILAMADI.\nAyrıntı: {exc}"
        ) from exc


def store(username: str, value: str) -> None:
    """
    Kasaya bir sır yazar ve geri okuyarak doğrular.

    Geri okuma şart: migration'da DB/dosya üzerine yazmadan ÖNCE sırrın
    gerçekten kasada olduğundan emin olmalıyız, yoksa sır tamamen kaybolur.

    TPM varsa değer önce mühürleniyor; yoksa eskisi gibi düz yazılıyor ve
    düşüş `tpm_sealing` tarafından kayda geçiyor.

    Raises:
        KeyringUnavailableError — yazma başarısızsa, geri okuma tutmazsa
            ya da TPM kullanılabilir göründüğü hâlde mühürleme patlarsa.
            Son durumda MÜHÜRSÜZ YAZMAYA DÜŞÜLMÜYOR: sessizce zayıflayan
            bir katman, hiç olmamasından kötüdür (B-025).
    """
    if _keyring is None:
        raise KeyringUnavailableError(
            f"keyring paketi kurulu değil — '{username}' yazılamaz. Ayrıntı: {_IMPORT_ERROR}"
        )
    try:
        saklanacak = tpm_sealing.belki_muhurle(value, baglam=username)
    except tpm_sealing.TpmSealingError as exc:
        raise KeyringUnavailableError(
            f"'{username}' TPM'e mühürlenemedi — mühürsüz yazmaya "
            f"DÜŞÜLMEDİ.\nAyrıntı: {exc}"
        ) from exc
    try:
        _keyring.set_password(SERVICE, username, saklanacak)
    except Exception as exc:
        raise KeyringUnavailableError(
            f"Anahtar kasasına '{username}' yazılamadı.\n"
            f"Arka uç: {backend_name()}\n"
            f"Ayrıntı: {type(exc).__name__}: {exc}"
        ) from exc

    if load(username) != value:
        raise KeyringUnavailableError(
            f"'{username}' kasaya yazıldı ama geri okunduğunda eşleşmedi — "
            "kasa güvenilir değil, işlem durduruldu."
        )


def load_totp_secret() -> str | None:
    """
    TOTP paylaşılan sırrını kasadan okur. Kurulmamışsa None.

    Tüm TOTP doğrulama noktaları (login, indirme, toplu indirme, klasör
    indirme) buradan geçmelidir — data/totp_secret.json artık kullanılmıyor.
    """
    return load(TOTP_USERNAME)


def store_totp_secret(secret: str) -> None:
    """TOTP paylaşılan sırrını kasaya yazar (geri okuma doğrulamasıyla)."""
    if not secret:
        raise ValueError("TOTP sırrı boş olamaz.")
    store(TOTP_USERNAME, secret)


def erase(username: str) -> bool:
    """
    Kasadan bir sırrı siler.

    Returns:
        True  — kayıt silindi
        False — kayıt zaten yoktu

    Raises:
        KeyringUnavailableError — kasaya erişilemiyorsa
    """
    if _keyring is None:
        raise KeyringUnavailableError(
            f"keyring paketi kurulu değil — '{username}' silinemez. Ayrıntı: {_IMPORT_ERROR}"
        )
    try:
        _keyring.delete_password(SERVICE, username)
        return True
    except Exception as exc:
        # Kayıt yoksa bu bir hata değil
        no_such: Any = getattr(_keyring_errors, "PasswordDeleteError", None)
        if no_such is not None and isinstance(exc, no_such):
            return False
        raise KeyringUnavailableError(
            f"Anahtar kasasından '{username}' silinemedi.\n"
            f"Arka uç: {backend_name()}\n"
            f"Ayrıntı: {type(exc).__name__}: {exc}"
        ) from exc
