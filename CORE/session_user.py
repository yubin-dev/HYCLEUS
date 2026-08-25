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

from CORE.roles import db_role as _rol_db

_log = logging.getLogger("hycleus.session_user")

#: Parola yoluyla giriş yapılamayacağını belirten `password_hash` değeri.
#: Argon2 biçiminde değil — ayrıştırılamadığı için hiçbir doğrulayıcı
#: bunu bir parolayla eşleştiremez. Boş dize KULLANILMIYOR: "hash yok"
#: ile "geçersiz hash" farklı şeyler ve ilki yanlış tarafa yorumlanabilir.
PAROLASIZ = "!vault-only-no-password-login"

#: Otomatik oluşturulan satırların kullanıcı adı ön eki. Bir insanı taklit
#: etmemesi için bilerek makine biçiminde.
VAULT_USERNAME_PREFIX = "vault:"

def vault_username(hwid: str) -> str:
    """HWID'den otomatik satırın kullanıcı adını üretir."""
    return f"{VAULT_USERNAME_PREFIX}{hwid}"


def db_role(session_role: str | None) -> str:
    """
    Arayüz rol adını `users.role` değerine çevirir.

    Bilinmeyen rol `user`'a düşüyor — yetki genişletmesi yanlış yön
    olurdu. Eski kaçamak bunun tersini yapıyordu: rol ne olursa olsun
    `admin` yazıyordu.

    UYGULAMA `CORE.roles.db_role()`'DE (B-030). Buradaki eski eşleme
    `{"Yönetici": "admin"}` sözlüğüydü ve yalnızca TAM o yazımı tanıyordu;
    ASCII `Yonetici` ile kurtarılmış bir kasa `user` olarak yazılıyordu.
    Bu ad geriye dönük uyumluluk için duruyor — `sync_session_user()` ve
    testler onu kullanıyor.
    """
    return _rol_db(session_role)


def tekil_hwid_satiri(db: Any, hwid: str, kolonlar: str) -> Any:
    """
    `SELECT {kolonlar} FROM users WHERE hwid = ?` sorgusunu TEKİL SONUÇ
    varsayımıyla çalıştırır (B-060/B-061).

    `users.hwid` artık kısmi UNIQUE (`DB/migrations.py::_m23_users_hwid_unique`),
    yani bu sorgu asla birden fazla satır döndürmemeli. Yine de -- eski
    bir veritabanı o göçü henüz çalıştırmadıysa (çakışma bulunup
    RuntimeError ile durduysa) ya da ileride bir yerde bu varsayım
    bozulursa -- sessizce `fetchone()`'un SQLite'ın iç uygulamasına bağlı
    ilk satırını kabul etmek yerine GÖRÜNÜR biçimde çöküyor.

    B-060'ın kök nedenlerinden biri tam olarak buydu: `_on_login()`'daki
    "pending mi" sorgusu `ORDER BY` içermiyordu, ve iki satır (kurbanın
    eski onaylı satırı + saldırganın yeni pending satırı) aynı HWID'e
    bağlıyken hangisinin döndüğü garanti değildi — ölçülen davranışta
    her zaman eski/onaylı satır dönüyordu, yani saldırgan hiç
    engellenmiyordu.
    """
    if not hwid:
        return None
    rows = db.fetchall(f"SELECT {kolonlar} FROM users WHERE hwid = ?", (hwid,))
    if len(rows) > 1:
        raise RuntimeError(
            f"HWID icin users tablosunda {len(rows)} satir var -- "
            "beklenmeyen (UNIQUE kisit ihlal edilmis olmali, bkz. B-060). "
            "Belirsiz sonuc kabul edilmedi."
        )
    return rows[0] if rows else None


def kullanici_bilgisi(db: Any, hwid: str) -> tuple[int, str] | None:
    """
    HWID'ye bağlı `users` satırını SALT OKUNUR arar: `(id, username)`.

    `sync_session_user()`'dan farkı: satır yoksa oluşturmuyor ve denetim
    kaydı düşmüyor. "Bu işlemi kim yaptı" sorusunu yanıtlamak için —
    o soru bir yan etki üretmemeli. Girişte satır zaten yazıldığı için
    burada bulunmaması beklenen bir durum değil, ama None dönmek
    çağıranın bir yer tutucu göstermesine izin veriyor.
    """
    row = tekil_hwid_satiri(db, hwid, "id, username")
    return (int(row["id"]), row["username"]) if row is not None else None


def sistem_kurulmus_mu(db: Any) -> bool:
    """
    Sistemde en az bir onaylı ('approved') kullanıcı var mı (B-058).

    `_first_run`'ın (main.py + UI/login_dialog.py) TEK doğru sorusu bu —
    "bu HWID'nin vault dosyası var mı" DEĞİL. Vault dosyası HWID başına;
    TOTP sırrı ise GLOBAL ve kalıcı, yani daha önce hiç görülmemiş her
    USB için "bu HWID'in vault'u yok" hep doğruydu. Sonuç: kurulu bir
    sistemde ikinci/üçüncü bir USB, "Kayıt Ol" (`status='pending'`)
    yoluna değil, İlk Kurulum sihirbazına (serbest rol seçimi, onaysız
    doğrudan 'approved' yazımı) yeniden düşüyordu — hangi HWID olursa
    olsun.

    Doğru soru HWID'den bağımsız: "sistem hiç bootstrap edildi mi".
    `status='approved'` bunun ölçüsü — o kullanıcı zaten USB+PIN(+TOTP)
    ile doğrulanmış demek (bkz. `sync_session_user()` docstring'i).
    """
    return db.fetchone("SELECT 1 FROM users WHERE status = 'approved' LIMIT 1") is not None


def oturum_yetkisi_gecerli_mi(
    db: Any, hwid: str, oturum_rolu: str | None
) -> tuple[bool, str]:
    """
    B-064/B-066 — açık bir oturumun DB'deki GERÇEK yetkisiyle hâlâ
    uyuşup uyuşmadığını kontrol eder.

    Neden gerekli
    -------------
    `_poll_usb()` (UI/main_window_lock.py) ve `AdminPanel` (USB Yönetimi
    paneli), USB fiziksel olarak SABİT kaldığı sürece "her şey yolunda"
    varsayıyordu — DB'deki `status`/`role`/kara liste durumunu bir daha
    HİÇ okumuyordu. Sonuç: bir yönetici bir kullanıcıyı reddedip
    (`_on_reject`), silip (`_on_delete`) ya da kara listeye alıp
    (`_do_blacklist`) DB'yi değiştirdiğinde, o HWID'e ait ZATEN AÇIK bir
    oturum (USB'si hâlâ takılı) bundan HABERSİZ kalıyor ve eski
    yetkisiyle çalışmaya devam ediyordu.

    Bu fonksiyon USB'nin fiziksel varlığına BAKMAZ (o, çağıranın işi —
    `get_usb_hwid()` ile karşılaştırılmalı); yalnızca DB tarafını
    kontrol eder. İki çağıran: `LockMixin._poll_usb` (ana pencere) ve
    `AdminPanel._yonetici_hala_yetkili` (USB Yönetimi paneli — modal
    olduğu için ana penceredeki döngüden habersiz, kendi kontrolünü
    kendi yapmak zorunda).

    Args:
        oturum_rolu: oturumun GİRİŞTE sahip olduğu arayüz rolü
            ("Yönetici" gibi). `CORE.roles.db_role()` ile DB'nin ikili
            (admin/user) ölçeğine indirgenip karşılaştırılır — DB şeması
            Standart/Salt Okunur ayrımını TUTMUYOR
            (`users.role CHECK(role IN ('admin','user'))`), yani bu
            fonksiyon yalnızca o ikisi arasındaki bir düşüşü
            YAKALAYAMAZ; bu, DB katmanının var olan bir sınırı, bu
            düzeltmenin kapsamı değil.

    Returns:
        (geçerli, sebep) — `geçerli` False ise `sebep` kullanıcıya
        gösterilebilir bir Türkçe cümle.
    """
    satir = db.fetchone(
        "SELECT role, status FROM users WHERE hwid = ?", (hwid,)
    )
    if satir is None:
        return False, "Kullanıcı kaydı artık mevcut değil."
    if satir["status"] != "approved":
        return False, f"Hesap durumu artık '{satir['status']}'."
    if satir["role"] != db_role(oturum_rolu):
        return False, "Yetki düzeyi değişti."

    token = db.fetchone(
        "SELECT blacklisted FROM usb_tokens WHERE hwid = ?", (hwid,)
    )
    if token is not None and token["blacklisted"]:
        return False, "Bu USB cihazı kara listeye alındı."

    return True, ""


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

    mevcut = tekil_hwid_satiri(db, hwid, "id, username")
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
