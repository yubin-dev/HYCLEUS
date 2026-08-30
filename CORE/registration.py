"""
HYCLEUS — self-servis kayıt akışının TEK gövdesi (B-060 / B-061)

Neden bu modül var
------------------
`UI/login_dialog.py::_on_register()` ve `UI/RegisterDialog.py::_on_save()`
aynı iki adımı BAĞIMSIZ olarak yeniden yazmıştı: `create_vault()` sonra
ayrı bir `users` INSERT'i. İkisi de aynı iki hatayı taşıyordu:

  B-060 — HWID zaten bir `users` satırına bağlı olsa bile `create_vault()`
          KOŞULSUZ üzerine yazıyordu; bir USB'ye PIN'i bilmeden fiziksel
          erişim tam hesap devralmaya yetiyordu.
  B-061 — `create_vault()` ile INSERT ayrı, atomik olmayan iki commit;
          aralarındaki kesinti (çökme, hata) onaysız `status='approved'`
          üretiyordu (`sync_session_user()`'ın "satır yok -> vault
          oturumu, approved yaz" varsayımı üzerinden).

Bu modül ikisini TEK yerde çözüyor; iki çağıran da (login_dialog,
RegisterDialog) buraya bağlanıyor — "iki çağıran, tek gövde".

Seçilen yön (B-060, seçenek a)
-------------------------------
HWID zaten `users` tablosunda bir satıra bağlıyken (durum pending ya da
approved fark etmez) yeni kayıt REDDEDİLİR — hiç satır, hiç vault
oluşturulmaz. `users.hwid` üzerindeki kısmi UNIQUE indeks
(`DB/migrations.py::_m23_users_hwid_unique`) bunun NİHAİ garantisi;
buradaki ön kontrol yalnızca kullanıcıya okunabilir bir hata mesajı
vermek için var (ham UNIQUE ihlali istisnasından daha iyi bir deneyim).

Meşru yeniden-kayıt senaryosu (ör. bir USB'nin kimliğini sıfırlayıp
başka birine vermek) TAMAMEN KİLİTLENMİYOR: bir yönetici USB Tokenlar
sayfasındaki "Sil" (`UsbTokensView._on_delete()`, artık `users` satırını
da temizliyor, bkz. o fonksiyonun docstring'i) ya da Bekleyen Kayıtlar
sayfasındaki "Reddet" (`PendingRegistrationsView._on_reject()`, pending
satırlar için) eylemiyle o HWID'in satırını kaldırdıktan SONRA aynı HWID
yeniden kayıt olabilir. Bu KASITLI:
bir HWID'in yeniden kullanılması her zaman bir yöneticinin AÇIK bir
kararı olmalı, rastgele bir kayıt denemesinin YAN ETKİSİ değil.

B-059: her kayıt KENDİ TOTP sırrına sahip
----------------------------------------
Eskiden self-servis kayıt hiç TOTP sırrı üretmiyordu — yeni kullanıcı,
onaydan sonra, herkesin paylaştığı GLOBAL sırra güveniyordu (asıl
B-059 hatası). Artık her başarılı kayıt kendi rastgele TOTP sırrını
alıyor (`CORE.secret_store.store_totp_secret_for_hwid`) ve çağıran arayüz
bunu QR/manuel anahtar olarak göstermeli — bkz. `RegistrationResult`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pyotp
from argon2 import PasswordHasher

from CORE import secret_store
from CORE.roles import db_role, is_admin_role
from CORE.vault_manager import create_vault, discard_vault

_PH = PasswordHasher()


@dataclass(frozen=True)
class RegistrationResult:
    """`register_new_user()`'ın döndürdüğü değer."""

    user_id: int
    totp_secret: str


class RegistrationError(Exception):
    """Kayıt reddedildi — çağıran taraf kullanıcıya göstermeli."""


class UsernameTakenError(RegistrationError):
    """Kullanıcı adı zaten alınmış."""

    def __init__(self, username: str) -> None:
        self.username = username
        super().__init__(f"Kullanıcı adı zaten alınmış: {username!r}")


class HwidAlreadyRegisteredError(RegistrationError):
    """
    Bu HWID zaten bir `users` satırına bağlı (B-060).

    `status` — var olan satırın durumu (`'pending'` ya da `'approved'`)
    — çağıran tarafın doğru mesajı seçmesi için taşınıyor.
    """

    def __init__(self, status: str) -> None:
        self.status = status
        super().__init__(f"HWID zaten kayıtlı (durum: {status})")


def register_new_user(
    db: Any,
    *,
    hwid: str,
    username: str,
    pin: str,
    role: str,
    registered_by: str | None = None,
) -> RegistrationResult:
    """
    Yeni bir self-servis kayıt oluşturur; `users.id` + KENDİ TOTP sırrını
    döndürür.

    Her zaman `status='pending'` yazar — bunun DIŞINDA hiçbir yol
    status'u değiştiremez, onay `PendingRegistrationsView._on_approve()` üzerinden
    AYRI, yönetici tarafından tetiklenen bir adım.

    Args:
        db:            `DBManager` benzeri; `fetchone`/`execute`/`log`.
        hwid:          Yeni kullanıcının USB donanım kimliği. TOTP sırrı
                       da bu HWID'e bağlı saklanır (B-059).
        username:      Benzersizliği burada kontrol edilir.
        pin:            Argon2id ile hashlenir (`password_hash`) ve
                        `create_vault()`'a KEK türetme girdisi olarak geçer.
        role:          Arayüz rol adı ("Standart" / "Salt Okunur"...).
        registered_by: Kaydı bir yönetici başlattıysa onun HWID'i —
                        yalnızca denetim kaydına ek bilgi, karar
                        vermede kullanılmaz.

    Returns:
        `RegistrationResult(user_id, totp_secret)` — çağıran arayüz
        `totp_secret`'ı QR kod + manuel anahtar olarak GÖSTERMELİ; bu
        fonksiyon depolamaktan sorumlu, ekrana basmaktan değil.

    Raises:
        UsernameTakenError         — kullanıcı adı zaten alınmış.
        HwidAlreadyRegisteredError — HWID zaten bir satıra bağlı (B-060);
            `create_vault()` bu durumda HİÇ çağrılmaz, var olan vault
            dokunulmadan kalır.
        RuntimeError               — `role` "Yönetici"ye normalize
            oluyor: kayıt akışından ASLA admin üretilemez, admin
            yalnızca İlk Kurulum sihirbazından gelir (bkz. B-058).
        Exception                  — `create_vault()`'un ya da TOTP
            sırrının kasaya yazılmasının fırlattığı her şey (ör.
            `OSError`, `KeyringUnavailableError`) olduğu gibi yukarı
            taşınır; her durumda o ana kadar üretilmiş her şey
            (vault, `users` satırı, TOTP sırrı) `discard_vault()` ile
            geri alınır.
    """
    if is_admin_role(role):
        raise RuntimeError(
            "register_new_user() 'Yönetici' rolüyle çağrıldı — kayıt "
            "akışından asla admin üretilemez (B-058/B-060). Admin "
            "yalnızca İlk Kurulum sihirbazından gelir."
        )

    if db.fetchone("SELECT id FROM users WHERE username = ?", (username,)):
        raise UsernameTakenError(username)

    existing = db.fetchone("SELECT status FROM users WHERE hwid = ?", (hwid,))
    if existing is not None:
        raise HwidAlreadyRegisteredError(existing["status"])

    create_vault(hwid, pin, role)

    totp_secret = pyotp.random_base32()
    try:
        secret_store.store_totp_secret_for_hwid(hwid, totp_secret)
    except Exception:
        # Vault yazıldı ama TOTP sırrı kasaya yazılamadı — yarım bir
        # HWID bırakmamak için vault'u da geri al (B-061 ile aynı disiplin).
        discard_vault(hwid)
        raise

    detail = f"username={username} hwid={hwid} role={role}"
    if registered_by:
        detail += f" registered_by={registered_by}"

    try:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, role, status, hwid) "
            "VALUES (?, ?, ?, 'pending', ?)",
            (username, _PH.hash(pin), db_role(role), hwid),
        )
    except Exception:
        # B-061: `users` satırı yazılamadıysa az önce oluşturulan vault'u
        # VE TOTP sırrını geri al — yarım bir HWID (vault/TOTP var,
        # `users` satırı yok) bırakmak `sync_session_user()`'ın "satır
        # yok -> vault oturumu, approved yaz" dalını tetikleyip onaysız
        # bir hesap üretirdi.
        discard_vault(hwid)
        raise

    user_id = int(cur.lastrowid)
    db.log("user_registered", detail=detail)
    return RegistrationResult(user_id=user_id, totp_secret=totp_secret)
