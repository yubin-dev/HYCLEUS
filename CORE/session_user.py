"""
HYCLEUS — oturum açan kullanıcıyı `users` tablosuna bağlar (B-011)

Neden bu modül var
------------------
HYCLEUS'ta kimlik iki ayrı yerde yaşıyordu ve ikisi birbirinden habersizdi:

    kim olduğun     → vault dosyası (HWID + PIN + rol)
    kim sayıldığın  → `users` tablosu (kayıt sırasında yazılıyor)

Aradaki "oturum açanı kaydet" adımı yoktu. Sonuç, `main.py`'de görünüyordu:
`HycleusWindow` `user_id` parametresi hiç geçilmeden kuruluyordu, yani
varsayılan olan **1** kalıyordu. Gerçekte kim giriş yaparsa yapsın, açtığı
klasörün sahibi 1 numaralı kullanıcı oluyordu.

`folders.owner_id` yabancı anahtarı yüzünden bu, 1 numaralı satır yoksa FK
hatası demekti. İki ayrı yerde (`CORE/folders.py::ensure_owner_exists` ve
`UI/main_window_table.py`) aynı kaçamak yazılmıştı: eksikse uydur.

    INSERT INTO users (id, username, password_hash, role, status, hwid)
    VALUES (?, 'yonetici', '', 'admin', 'approved', ?)

Uydurma satırın üç ayrı zararı vardı:

1. **Denetim kaydını kirletiyordu.** Sonradan bakan biri `users` tablosunda
   gerçek bir "yonetici" hesabı görüyordu; o hesap hiç kaydolmamıştı.
2. **Rolü yalan söylüyordu.** Oturum rolü ne olursa olsun satır `admin`
   yazıyordu.
3. **Boş parola hash'i + admin rolü.** Bugün zararsız (giriş vault
   üzerinden işliyor, `password_hash` doğrulamada kullanılmıyor) ama
   parola tabanlı bir yol eklendiği gün hazır bir açık.

Bu modül kaçamağın yerine geçiyor: kaydı **giriş anında**, yani doğru
anda ve elimizdeki gerçek bilgiyle yazıyor.


Ne YAZILIYOR, ne UYDURULMUYOR
-----------------------------
`sync_session_user()` önce HWID ile mevcut satırı arıyor. Bulursa hiçbir
şey uydurmuyor — o satırın id'sini döndürüyor ve `last_login`'i
güncelliyor. Kayıt akışından (`RegisterDialog`, `LoginDialog`) gelen
kullanıcılar bu dala düşüyor ve artık **kendi** id'leriyle çalışıyorlar;
eskiden hepsi 1'e yazılıyordu.

Satır yoksa oluşturuluyor, çünkü vault'u olup `users` kaydı olmayan
oturumlar gerçek: DEV_MODE ve kayıt akışından önce kurulmuş vault'lar.
Ama oluşturulan satır artık bir insanı taklit etmiyor:

    username       "vault:<hwid>"     — makine ürünü olduğu adından belli
    role           oturumun GERÇEK rolü, sabit 'admin' değil
    password_hash  _PAROLASIZ sentinel — hiçbir doğrulayıcıyla eşleşmez
    status         'approved'         — vault kimlik doğrulaması geçildi
    hwid           oturumun HWID'i

`status='approved'` bir kaçamak değil: bu kullanıcı USB + PIN (+ TOTP)
ile zaten doğrulanmış durumda, `users` satırı ona sonradan eşlik ediyor.
`pending` yazmak yanlış olurdu — onay bekleyen bir şey yok.

`_PAROLASIZ` değeri Argon2 biçiminde DEĞİL, bilerek: `argon2.verify()`
onu ayrıştıramadığı için bu satır parola yoluyla giriş yapamaz. Boş dize
ise ileride "hash yok, geç" gibi yorumlanabilirdi — sessizce doğru olması
şansa kalırdı.

Her iki dalda da denetim kaydı düşüyor (`session_user_linked` /
`session_user_provisioned`), yani bir satırın nereden geldiği sonradan
okunabiliyor. Uydurma satırın en büyük sorunu buydu: izsiz belirmesi.
"""
from __future__ import annotations

import logging
from typing import Any

_log = logging.getLogger("hycleus.session_user")

#: Parola yoluyla giriş yapılamayacağını belirten `password_hash` değeri.
#: Argon2 biçiminde değil — ayrıştırılamadığı için hiçbir doğrulayıcı
#: bunu bir parolayla eşleştiremez. Boş dize KULLANILMIYOR: "hash yok"
#: ile "geçersiz hash" farklı şeyler ve ilki yanlış tarafa yorumlanabilir.
PAROLASIZ = "!vault-only-no-password-login"

#: Otomatik oluşturulan satırların kullanıcı adı ön eki. Bir insanı taklit
#: etmemesi için bilerek makine biçiminde.
VAULT_USERNAME_PREFIX = "vault:"

#: Arayüz rolü → `users.role` sütunu. Sütunda CHECK kısıtı var
#: (`admin` / `user`), yani eşleme zorunlu.
_ROL_ESLEMESI = {"Yönetici": "admin"}


def vault_username(hwid: str) -> str:
    """HWID'den otomatik satırın kullanıcı adını üretir."""
    return f"{VAULT_USERNAME_PREFIX}{hwid}"


def db_role(session_role: str | None) -> str:
    """
    Arayüz rol adını `users.role` değerine çevirir.

    Bilinmeyen rol `user`'a düşüyor — yetki genişletmesi yanlış yön
    olurdu. Eski kaçamak bunun tersini yapıyordu: rol ne olursa olsun
    `admin` yazıyordu.
    """
    return _ROL_ESLEMESI.get(session_role or "", "user")


def sync_session_user(
    db: Any, *, hwid: str, role: str | None = None
) -> int:
    """
    Oturum açan kullanıcıyı `users` tablosuyla eşler; `users.id` döndürür.

    HWID ile satır bulunursa o kullanılıyor (hiçbir alan uydurulmuyor,
    yalnızca `last_login` güncelleniyor). Bulunmazsa vault oturumu için
    bir satır oluşturuluyor — bkz. modül docstring'i.

    Args:
        db:   `DBManager` benzeri; `fetchone`/`execute`/`log` gerekiyor.
        hwid: Oturumun USB donanım kimliği.
        role: Arayüz rol adı ("Yönetici" / "Personel" / None).

    Returns:
        `users.id` — klasör sahipliği ve denetim kaydı için kullanılacak.

    Raises:
        ValueError: `hwid` boşsa. Boş HWID ile satır açmak, birbirinden
            ayırt edilemeyen kullanıcılar üretirdi.
    """
    if not hwid:
        raise ValueError(
            "Oturum kullanıcısı HWID olmadan eşlenemez — boş HWID ile "
            "açılan satırlar birbirinden ayırt edilemez."
        )

    mevcut = db.fetchone(
        "SELECT id, username FROM users WHERE hwid = ? ORDER BY id LIMIT 1",
        (hwid,),
    )
    if mevcut is not None:
        user_id = int(mevcut["id"])
        db.execute(
            "UPDATE users SET last_login = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')"
            " WHERE id = ?",
            (user_id,),
        )
        db.log(
            "session_user_linked",
            user_id=user_id,
            detail=f"username={mevcut['username']} hwid={hwid}",
        )
        return user_id

    kullanici_adi = vault_username(hwid)
    rol = db_role(role)
    _log.info(
        "users satırı yok — vault oturumu için oluşturuluyor  hwid=%s rol=%s",
        hwid, rol,
    )
    cur = db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid,"
        " last_login)"
        " VALUES (?, ?, ?, 'approved', ?,"
        " strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
        (kullanici_adi, PAROLASIZ, rol, hwid),
    )
    user_id = int(cur.lastrowid)
    db.log(
        "session_user_provisioned",
        user_id=user_id,
        detail=f"username={kullanici_adi} hwid={hwid} role={rol}",
    )
    return user_id
