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
başka birine vermek) TAMAMEN KİLİTLENMİYOR: bir yönetici Admin
Paneli'ndeki "Sil" (`AdminPanel._on_delete()`, artık `users` satırını da
temizliyor, bkz. o fonksiyonun docstring'i) ya da "Reddet"
(`AdminPanel._on_reject()`, pending satırlar için) eylemiyle o HWID'in
satırını kaldırdıktan SONRA aynı HWID yeniden kayıt olabilir. Bu KASITLI:
bir HWID'in yeniden kullanılması her zaman bir yöneticinin AÇIK bir
kararı olmalı, rastgele bir kayıt denemesinin YAN ETKİSİ değil.
"""
from __future__ import annotations

from typing import Any

from argon2 import PasswordHasher

from CORE.roles import db_role, is_admin_role
from CORE.vault_manager import create_vault, discard_vault

_PH = PasswordHasher()


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
) -> int:
    """
    Yeni bir self-servis kayıt oluşturur; `users.id` döndürür.

    Her zaman `status='pending'` yazar — bunun DIŞINDA hiçbir yol
    status'u değiştiremez, onay `AdminPanel._on_approve()` üzerinden
    AYRI, yönetici tarafından tetiklenen bir adım.

    Args:
        db:            `DBManager` benzeri; `fetchone`/`execute`/`log`.
        hwid:          Yeni kullanıcının USB donanım kimliği.
        username:      Benzersizliği burada kontrol edilir.
        pin:            Argon2id ile hashlenir (`password_hash`) ve
                        `create_vault()`'a KEK türetme girdisi olarak geçer.
        role:          Arayüz rol adı ("Standart" / "Salt Okunur"...).
        registered_by: Kaydı bir yönetici başlattıysa onun HWID'i —
                        yalnızca denetim kaydına ek bilgi, karar
                        vermede kullanılmaz.

    Raises:
        UsernameTakenError         — kullanıcı adı zaten alınmış.
        HwidAlreadyRegisteredError — HWID zaten bir satıra bağlı (B-060);
            `create_vault()` bu durumda HİÇ çağrılmaz, var olan vault
            dokunulmadan kalır.
        RuntimeError               — `role` "Yönetici"ye normalize
            oluyor: kayıt akışından ASLA admin üretilemez, admin
            yalnızca İlk Kurulum sihirbazından gelir (bkz. B-058).
        Exception                  — `create_vault()`'un fırlattığı her
            şey (ör. `OSError`) olduğu gibi yukarı taşınır.
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
        # geri al — yarım bir HWID (vault var, `users` satırı yok)
        # bırakmak `sync_session_user()`'ın "satır yok -> vault
        # oturumu, approved yaz" dalını tetikleyip onaysız bir hesap
        # üretirdi.
        discard_vault(hwid)
        raise

    user_id = int(cur.lastrowid)
    db.log("user_registered", detail=detail)
    return user_id
