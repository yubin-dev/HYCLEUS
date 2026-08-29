"""
HYCLEUS — kayıtlı USB token'larının OKUMA tarafı: tek sorgu, iki çağıran.

Neden bu dosya var
------------------
`UI/AdminPanel.py`'nin USB Yönetim Paneli'ndeki "USB Tokenlar" sekmesi ve
`UI/ProfileView.py`'nin "Cihazlar ve oturum" bölümü AYNI SORUYU soruyor:
"hangi USB'ler kayıtlı, rolü ne, ne zaman eklendi, son girişi ne zaman" —
biri TÜM filo için (yönetici), diğeri TEK bir HWID için (kullanıcının kendi
cihazı). Aynı SQL'i iki dosyada ayrı ayrı yazmak, biri güncellenip
diğerinin unutulduğu güne kadar sessizce ayrışırdı (bu deponun defalarca
kapattığı kusur sınıfı — bkz. B-004/B-008, B-007, B-010, B-011). Bu yüzden
tek fonksiyon, opsiyonel `hwid` filtresiyle.

`AdminPanel._load()`'un SQL'i buraya AYNEN taşındı; davranış DEĞİŞMEDİ.

Çoklu cihaz YOK — kasıtlı, şema seviyesinde
--------------------------------------------
`users.hwid` kısmi UNIQUE indeksli (`DB/migrations.py::_m23_users_hwid_
unique`, B-060): bir kullanıcı hesabı en fazla BİR HWID'e bağlanabiliyor.
"Cihazlar ve oturum" bölümünün mockup'ı çoklu cihaz listesi gösterse de,
bugünkü mimaride bir kullanıcının birden fazla kayıtlı USB'si OLAMAZ —
bu bir UI eksikliği değil, B-060'ın kimlik doğrulama modelinin (bir HWID
= bir hesap, aksi hâlde aynı fiziksel token'ı paylaşan iki hesap birbirinin
yetkisini gasp edebilirdi) doğal ve KASITLI bir sonucu. Ayrıntı ve gelecekte
gerçekten çok-cihazlı bir model isteniyorsa ne gerektireceği: SECURITY.md
§4.23, BACKLOG.md B-082.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from DB.db_manager import DBManager

#: `AdminPanel.py`'nin rol/son-giriş sorgusunun baktığı denetim eylemleri —
#: DEĞİŞMEDEN taşındı.
_ROL_EYLEMLERI = ("usb_setup_complete", "usb_role_changed")
_SON_GIRIS_EYLEMI = "usb_auth_success"


@dataclass(frozen=True)
class TokenKaydi:
    """Tek bir USB token kaydı — `usb_tokens` + türetilmiş rol/son giriş."""
    hwid: str
    token_id: str
    blacklisted: bool
    created_at: str
    role: str          # `role_detail`'den ayrıştırılmış; bilinmiyorsa ""
    last_login: str     # ISO zaman damgası; hiç giriş yoksa ""


def token_kayitlarini_getir(db: DBManager, *, hwid: str | None = None) -> list[TokenKaydi]:
    """Kayıtlı USB token'ları döndürür.

    `hwid=None` → TÜM kayıtlar (USB Yönetim Paneli'nin sekmesi).
    `hwid=<değer>` → yalnızca o token (Profil sayfasının "Cihazlar ve
    oturum" bölümü — bugünkü şema gereği en fazla BİR sonuç döner, bkz.
    modül docstring'i).
    """
    kosul = "WHERE u.hwid = ?" if hwid is not None else ""
    params: tuple = (hwid,) if hwid is not None else ()
    rows = db.fetchall(
        f"""
        SELECT
            u.hwid,
            u.token_id,
            u.blacklisted,
            u.created_at,
            (SELECT a.detail FROM audit_log a
             WHERE a.action IN ({",".join("?" for _ in _ROL_EYLEMLERI)})
               AND a.detail LIKE 'hwid=' || u.hwid || '%'
             ORDER BY a.timestamp DESC LIMIT 1)  AS role_detail,
            (SELECT a.timestamp FROM audit_log a
             WHERE a.action = ?
               AND a.detail LIKE 'hwid=' || u.hwid || '%'
             ORDER BY a.timestamp DESC LIMIT 1)  AS last_login
        FROM usb_tokens u
        {kosul}
        ORDER BY u.created_at DESC
        """,
        (*_ROL_EYLEMLERI, _SON_GIRIS_EYLEMI, *params),
    )
    return [
        TokenKaydi(
            hwid=row["hwid"],
            token_id=row["token_id"] or "",
            blacklisted=bool(row["blacklisted"]),
            created_at=row["created_at"] or "",
            role=parse_field(row["role_detail"] or "", "role"),
            last_login=row["last_login"] or "",
        )
        for row in rows
    ]


def parse_field(detail: str, key: str) -> str:
    """`key=value` çiftini parse eder; değer boşluk içerebilir.

    `AdminPanel._parse_field`'dan DEĞİŞMEDEN taşındı — "hwid=X role=Salt
    Okunur old_role=Y" formatında çalışır: sonraki 'kelime=' kalıbı ya da
    satır sonu değerin bitişini belirler.
    """
    prefix = f"{key}="
    start = detail.find(prefix)
    if start == -1:
        return ""
    val_start = start + len(prefix)
    m = re.search(r"\s+\w+=", detail[val_start:])
    end = val_start + m.start() if m else len(detail)
    return detail[val_start:end].strip()


__all__ = ["TokenKaydi", "token_kayitlarini_getir", "parse_field"]
