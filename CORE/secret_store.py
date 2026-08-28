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

  totp_secret:<hwid>  — TOTP (authenticator) sırrı, HWID başına (B-059)
                     Eskiden sabit "totp_secret" adıyla TEK bir global sır
                     tüm kullanıcılar arasında paylaşılıyordu — herhangi
                     bir kullanıcı başka birinin 2FA kodunu üretebiliyordu,
                     RBAC'ı anlamsızlaştırıyordu. `CORE/secret_migration.py`
                     bu turda eski global kaydı sistemdeki EN ESKİ onaylı
                     kullanıcının HWID'ine devrediyor (bkz. o modülün
                     `migrate_totp_to_per_hwid()` docstring'i); diğer tüm
                     kullanıcılar yeniden enrollment gerektiriyor.

                     HWID başına seçildi, `users.id` başına DEĞİL (modülün
                     önceki notu "totp_secret:<user_id>" öneriyordu):
                     `users.hwid` artık kısmi UNIQUE (B-060), yani HWID ve
                     kullanıcı kimliği birebir örtüşüyor. HWID, İlk Kurulum
                     sihirbazının QR'ı gösterdiği anda ZATEN elde — henüz
                     hiçbir `users` satırı/`user_id` yokken. `user_id`
                     başına saklamak bu sırayı (QR önce, DB satırı sonra)
                     bir tavuk-yumurta sorununa çevirirdi. HWID başına
                     saklamak hem bu sorunu ortadan kaldırıyor hem de
                     yukarıdaki `share_2:<hwid>` deseniyle simetrik
                     kalıyor.

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

Re-seal — mühürsüz bir kayıt "bir sonraki yazımı" hiç görmeyebilir
--------------------------------------------------------------------
`share_2` WRITE-ONCE bir sır: `_save_usb_token()` onu yalnızca
`create_vault()` içinde bir kez kasaya yazıyor (bkz. `CORE/vault_manager.py`).
TPM bu ilk yazım anında yoksa (makine henüz TPM'i etkinleştirmemiş, sürücü
kurulu değil, vb.) ve SONRA kullanılabilir hâle gelirse, "bir sonraki
yazım" hiçbir zaman gelmez — kayıt kasada SONSUZA KADAR mühürsüz kalırdı,
belge (SECURITY.md §4.13) mühürlemenin varlığını iddia etmeye devam ederken.

Bunu kapatmak için `load()` OKUMA sırasında fırsatçı bir yeniden mühürleme
yapıyor: okunan kayıt mühürsüzse VE TPM şu an kullanılabiliyorsa, değeri
hemen yeniden yazıyor — kullanıcı ayrıca bir şey yapmadan, İLK açılışta.
Karar kendi `.kullanilabilir` okuması YAPMIYOR (bu ikinci bir düşüş karar
noktası olurdu, `tests/test_tpm_sealing.py::
test_kullanilabilir_karari_baska_modulde_TEKRARLANMIYOR` bunu engelliyor);
`belki_muhurle()`'nin döndürdüğü değerin mühürlü olup olmadığına bakarak
çıkarım yapıyor — TPM yoksa `belki_muhurle()` zaten değeri değiştirmeden
döndürür, o durumda hiçbir yazma denenmiyor.

Yeniden mühürleme BAŞARISIZ olursa (TPM hatası, kasa yazma hatası) okuma
YİNE DE BAŞARILI dönüyor — zaten başarıyla okunmuş bir değeri, arkadaki
iyileştirme denemesi patladı diye kullanıcıya vermemek yeni bir kilitlenme
yüzeyi açardı. Ama "sessiz atlama" burada da yok: başarı da başarısızlık
da denetim kaydına (`tpm_reseal_completed` / `tpm_reseal_failed`) ve
uygulama logına düşüyor — bkz. SECURITY.md §4.13.

`ensure_available()`'ın sonda kaydı BİLEREK mühürsüz: o yoklama kasanın
erişilebilirliğini ölçüyor, TPM'inkini değil. Mühürlenseydi bir TPM
sorunu "anahtar kasası erişilemiyor" diye rapor edilir ve açılışı
engellerdi — TPM'in yokluğu ise açılışı engellemiyor.
"""
from __future__ import annotations

import logging
import secrets
import sys
from typing import Any

from CORE import tpm_sealing

_log = logging.getLogger("hycleus.secret_store")

SERVICE = "HYCLEUS"

#: `_windows_golge_sil()` — bir üzerine-yazmanın Windows Credential
#: Manager'da bıraktığı, `get_password()`'ün artık hiç görmediği eski bir
#: "compound" kopyayı temizlediğinde düşen denetim eylemi. Bkz. o
#: fonksiyonun docstring'i ve SECURITY.md §4.13 / BACKLOG B-070.
EYLEM_GOLGE_SILINDI = "credential_shadow_erased"

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

    Kayıt MÜHÜRSÜZSE ve TPM ŞU AN kullanılabiliyorsa, dönmeden önce fırsatçı
    bir yeniden mühürleme (re-seal) deneniyor — bkz. modül docstring'i
    "Re-seal". Bu deneme başarısız olsa bile fonksiyon YİNE DE değeri
    döndürür; başarı/başarısızlık ayrıca kayda geçer, `_reseal_firsatci()`.

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
        deger = tpm_sealing.belki_coz(saklanan, baglam=username)
    except tpm_sealing.TpmSealingError as exc:
        # Tip BİLEREK korunuyor. Çağıranların hepsi zaten
        # KeyringUnavailableError'ı "sır güvenli biçimde elde edilemedi"
        # diye ele alıyor ve doğru şeyi yapıyor: durdur, kullanıcıya göster.
        # Yeni bir istisna tipi sızdırmak mevcut çağıranların davranışını
        # değiştirirdi. Gerçek sebep `__cause__` zincirinde duruyor.
        raise KeyringUnavailableError(
            f"'{username}' kaydı TPM'e mühürlü ve AÇILAMADI.\nAyrıntı: {exc}"
        ) from exc

    if not tpm_sealing.muhurlu_mu(saklanan):
        # Mühürsüz kayıt: TPM ilk yazımda yoktu (ya da hiç yoktu) ve share_2
        # gibi write-once sırlar için "bir sonraki yazım" hiç gelmeyebilir —
        # bkz. modül docstring'i "Re-seal". Okuma zaten başarılı olduğu
        # için burada bir hata olursa BLOKLAMIYORUZ, yalnızca kayda geçiyoruz.
        _reseal_firsatci(username, deger)

    return deger


def _denetim_log(eylem: str, detay: str) -> None:
    """
    Best-effort denetim kaydı. DB henüz bağlı değilse (bu modül login'den
    önce, ör. bir öz-test/CLI aracından da çağrılabilir) sessizce atlanır —
    bu bir OKUMA yolunun yan etkisi, kasa erişimini asla çökertmemeli.
    """
    try:
        from DB.db_manager import DBManager

        DBManager().log(eylem, detail=detay)
    except Exception:
        pass


def _reseal_firsatci(username: str, deger: str) -> None:
    """
    Mühürsüz okunan bir kaydı, TPM şu an kullanılabiliyorsa hemen yeniden
    mühürler. Bkz. modül docstring'i "Re-seal".

    `.kullanilabilir` kararını burada TEKRARLAMIYOR — `belki_muhurle()`nin
    döndürdüğü değerin mühürlü olup olmadığına bakarak çıkarım yapıyor.
    TPM yoksa `belki_muhurle()` `deger`i değiştirmeden döndürür, o zaman
    hiçbir kasa yazması denenmiyor (bugünkü TPM'siz makinelerin ezici
    çoğunluğunda bu fonksiyon her okumada tek bir ucuz kontrolden fazlası
    değil).

    Başarısızlık (TPM hatası, kasa yazma hatası) YUKARI FIRLATILMIYOR —
    `load()` zaten okuduğu değeri döndürmeye devam etmeli. Ama "sessiz
    atlama" yok: başarı da başarısızlık da hem uygulama logına hem denetim
    zincirine düşüyor.
    """
    try:
        yeni = tpm_sealing.belki_muhurle(deger, baglam=username)
    except tpm_sealing.TpmSealingError as exc:
        _log.warning("tpm_yeniden_muhur_basarisiz  username=%s hata=%s", username, exc)
        _denetim_log(
            tpm_sealing.EYLEM_YENIDEN_MUHUR_BASARISIZ,
            f"username={username} hata={exc}",
        )
        return

    if not tpm_sealing.muhurlu_mu(yeni):
        return  # TPM kullanılamıyor — belki_muhurle() zaten deger'i degistirmedi

    try:
        _keyring.set_password(SERVICE, username, yeni)
        dogrulama = _keyring.get_password(SERVICE, username)
    except Exception as exc:
        _log.warning("tpm_yeniden_muhur_basarisiz  username=%s hata=%s", username, exc)
        _denetim_log(
            tpm_sealing.EYLEM_YENIDEN_MUHUR_BASARISIZ,
            f"username={username} hata={type(exc).__name__}: {exc}",
        )
        return

    if dogrulama != yeni:
        _log.warning(
            "tpm_yeniden_muhur_basarisiz  username=%s hata=round-trip tutmadi", username
        )
        _denetim_log(
            tpm_sealing.EYLEM_YENIDEN_MUHUR_BASARISIZ,
            f"username={username} hata=round-trip tutmadi",
        )
        return

    _log.info("tpm_yeniden_muhurlendi  username=%s", username)
    _denetim_log(tpm_sealing.EYLEM_YENIDEN_MUHUR, f"username={username}")
    _windows_golge_sil(username)


def _windows_golge_sil(username: str) -> None:
    """
    Yalnızca Windows + WinVaultKeyring: bir ÖNCEKİ üzerine-yazmanın arkada
    bıraktığı, `get_password()`'ün artık hiç GÖRMEDİĞİ ama kasada hâlâ VAR
    olan bir "compound" kopyayı temizler.

    Ölçüldü — bu makinede, GERÇEK Windows Credential Manager'da: `keyring`
    kütüphanesinin Windows arka ucu (`keyring.backends.Windows.
    WinVaultKeyring`) aynı serviste birden fazla kullanıcı adını, native
    `CredWrite`'ın yalnızca TargetName'e göre anahtarlamasını aşmak için,
    "compound target" (`{username}@{service}`) hilesiyle simüle ediyor.
    `set_password()` YENİ değeri HER ZAMAN "çıplak" (bare) `service`
    hedefine yazıyor; bare hedefte O AN başka bir kullanıcı adı duruyorsa
    önce onu compound hedefe TAŞIYOR — ama üzerine yazılan kullanıcı
    adının KENDİ önceki compound kopyasına HİÇ dokunmuyor. Sonuç: aynı
    `username`'i birden fazla kez yazmak (reseal DAHİL, ama onunla sınırlı
    değil — ör. `setup_usb.py --reset` ile aynı hwid'in yeniden kaydı)
    ESKİ değerin bir kopyasını, `get_password()`'ün asla bakmadığı bir
    hedef adı altında, SÜRESİZ olarak kasada bırakabiliyor.

    Bu, TPM mühürlemesi için önemsiz değil: "yeniden mühürlendi" denen bir
    kaydın ESKİ, mühürSÜZ hâli — DPAPI kırılırsa (M2'nin daha ileri bir
    biçimi, bkz. SECURITY.md §4.13) TPM'siz de okunabilir bir kopya olarak
    — sessizce hayatta kalabiliyordu. Bu fonksiyon o gölge kopyayı,
    YALNIZCA yeni değer güvenle yazılıp doğrulandıktan SONRA (çağıranlara
    bakın: `store()`'un round-trip'inden sonra, `_reseal_firsatci()`'nin
    kendi doğrulamasından sonra), hedefi doğrudan silerek temizliyor —
    `keyring.delete_password()` KULLANILMIYOR çünkü o hem bare hem compound
    hedefte AYNI kullanıcı adını arayıp ikisini de siler; bare'deki YENİ
    değeri de silme riski taşırdı. Bkz. BACKLOG B-070.

    BEST EFFORT ve ASLA fırlatmıyor: bir temizlik adımı, ana yazımdan
    SONRA çalışıyor — burada bir şey ters giderse yalnızca eski gölge
    kopya kalmaya devam eder, zaten güvenle yazılmış yeni değer etkilenmez.
    """
    if sys.platform != "win32" or backend_name() != "WinVaultKeyring":
        return
    try:
        import pywintypes
        import win32cred

        hedef = f"{username}@{SERVICE}"
        try:
            win32cred.CredDelete(Type=win32cred.CRED_TYPE_GENERIC, TargetName=hedef)
        except pywintypes.error as exc:
            if exc.winerror == 1168:  # ERROR_NOT_FOUND — temizlenecek bir şey yok
                return
            raise
    except Exception as exc:
        _log.warning("windows_golge_kopya_silinemedi  username=%s hata=%s", username, exc)
        return

    _log.info("windows_golge_kopya_silindi  username=%s", username)
    _denetim_log(EYLEM_GOLGE_SILINDI, f"username={username}")


def store(username: str, value: str) -> None:
    """
    Kasaya bir sır yazar ve geri okuyarak doğrular.

    Geri okuma şart: migration'da DB/dosya üzerine yazmadan ÖNCE sırrın
    gerçekten kasada olduğundan emin olmalıyız, yoksa sır tamamen kaybolur.

    TPM varsa değer önce mühürleniyor; yoksa eskisi gibi düz yazılıyor ve
    düşüş `tpm_sealing` tarafından kayda geçiyor.

    Doğrulamadan SONRA, Windows'ta, bu `username`'in ÖNCEKİ bir yazımdan
    kalma bir "gölge" kopyası varsa temizleniyor — bkz. `_windows_golge_sil()`
    docstring'i, BACKLOG B-070.

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

    _windows_golge_sil(username)


def load_totp_secret() -> str | None:
    """
    ESKİ global TOTP sırrını kasadan okur. Kurulmamışsa None.

    B-059 SONRASI YENİ KOD BUNU ÇAĞIRMAMALI — gerçek doğrulama noktaları
    (login, indirme, toplu indirme, klasör indirme) artık
    `load_totp_secret_for_hwid()` kullanıyor. Bu fonksiyon yalnızca iki
    yerde kalıyor: (1) `CORE/secret_migration.py::migrate_totp_to_per_hwid()`
    eski kaydı okuyup HWID başına şemaya taşımak için, (2) DEV_MODE'un
    kasa öncesi (`use_vault=False`) yolu — o yol tek operatörlü geliştirme
    senaryosu, RBAC/çok-kullanıcı tehdit modelinin parçası değil.
    """
    return load(TOTP_USERNAME)


def store_totp_secret(secret: str) -> None:
    """
    ESKİ global TOTP sırrını kasaya yazar (geri okuma doğrulamasıyla).

    B-059 SONRASI YENİ KOD BUNU ÇAĞIRMAMALI — bkz. `load_totp_secret()`
    docstring'i. Yalnızca DEV_MODE'un kasa öncesi yolu kullanıyor.
    """
    if not secret:
        raise ValueError("TOTP sırrı boş olamaz.")
    store(TOTP_USERNAME, secret)


def totp_username(hwid: str) -> str:
    """TOTP sırrının HWID başına (B-059) keyring kullanıcı adını üretir."""
    if not hwid:
        raise ValueError("TOTP sırrı için HWID boş olamaz.")
    return f"{TOTP_USERNAME}:{hwid}"


def load_totp_secret_for_hwid(hwid: str) -> str | None:
    """
    Bu HWID'in KENDİ TOTP sırrını kasadan okur. Hiç enroll olmamışsa None.

    None dönmesi bir hata değil: bu HWID ya hiç kayıtlı değil (yeni USB,
    "Kayıt Ol" bekliyor) ya da B-059 göçü sırasında kendisine sır
    devredilmemiş eski bir onaylı/bekleyen kullanıcı (yeniden enrollment
    gerekiyor). Çağıran taraf (`UI/login_dialog.py::_on_login()`) bunu
    ayrı ve açık bir mesajla ele almalı — sessizce "kod yanlış" demek
    yanıltıcı olurdu.
    """
    if not hwid:
        return None
    return load(totp_username(hwid))


def store_totp_secret_for_hwid(hwid: str, secret: str) -> None:
    """Bu HWID'in TOTP sırrını kasaya yazar (geri okuma doğrulamasıyla)."""
    if not secret:
        raise ValueError("TOTP sırrı boş olamaz.")
    store(totp_username(hwid), secret)


def erase_totp_secret_for_hwid(hwid: str) -> bool:
    """
    Bu HWID'in TOTP sırrını kasadan siler.

    `CORE/vault_manager.py::discard_vault()` tarafından, yarım kalan bir
    kayıt denemesini geri almak (B-061) ya da bir USB kaydını tamamen
    kaldırmak için çağrılıyor.
    """
    return erase(totp_username(hwid))


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
