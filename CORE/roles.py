"""
HYCLEUS — rol adının TEK karar noktası (B-028 / B-030).

Neden bu dosya var
------------------
Rol karşılaştırması depoda **üç farklı normalizasyonla** 19 yerde
yapılıyordu:

    == "Yönetici"                            11 yer
    .strip().lower() == "..."                 7 yer
    .strip().lower().replace("_", " ")        1 yer

ve bir yer (`main_window_table.py`) üç yazımı ayrıca elle kabul ediyordu:
`in ("yönetici", "yonetici", "admin")`. Yani biri sorunla karşılaşmış ve
tek bir çağrı yerini yamamıştı.

Bunun ERİŞİLEBİLİR bir sonucu vardı: `CORE/recover_vault.py` rolü ASCII
`"Yonetici"` olarak yazıyor, giriş akışı kasadan normalize etmeden
okuyordu. Kasa kurtarma işleminden sonra yönetici, yönetici olmayan gibi
davranılıyordu — AdminPanel hiç kurulmuyor, mahrem etiketli dosyalar
gizleniyordu. Yön yetki KAYBI olduğu için güvenlik açığı değil, ama
kilitlenme sınıfı bir kusur: düşen kullanıcı AdminPanel'e giremediği için
kendi rolünü düzeltemiyordu da.

Türkçe büyük/küçük harf tuzağı — ÖLÇÜLDÜ
-----------------------------------------
Sorun yalnızca ASCII/Türkçe yazım farkı değildi. `.lower()` Türkçe
büyük harfli girdide beklenen sonucu VERMİYOR:

    "YÖNETİCİ".lower()  ->  'yöneti̇ci̇'      (10 karakter, 8 değil)
    "YÖNETİCİ".lower() == "yönetici"  ->  False

Sebep `İ` (U+0130): küçük harfi `i` + U+0307 BİRLEŞEN NOKTA. Yani
mevcut yedi `.strip().lower()` çağrısı da bu girdide kırılıyordu.

Çözüm NFKD ayrıştırması + birleşen işaretleri atmak. Bu `ö→o`, `ş→s`,
`ğ→g`, `ç→c`, `İ→i` için çalışıyor. `ı` (U+0131) İSTİSNA: atomik bir
karakter, ayrıştırılamıyor — elle eşleniyor.

Kanonik değer neden ASCII slug
------------------------------
Kanonik biçim `"yonetici"` gibi ASCII bir slug; görünen ad değil.
Görünen ad arayüzün işi (`display_role()`), karar verme işi bu modülün.
Kanonik değeri `"Yönetici"` yapmak, her karşılaştırmayı yeniden Türkçe
karakterli bir sabite bağlardı — yani düzelttiğimiz şeyi geri getirirdi.

Bu modül DEĞER SAKLAMIYOR ve kasayı DEĞİŞTİRMİYOR. Kasadaki eski ASCII
roller okuma anında normalize ediliyor; migration gerekmiyor (kasayı
yeniden yazmak PIN isterdi).
"""
from __future__ import annotations

import unicodedata

# ── Kanonik roller ────────────────────────────────────────────────────────────

#: Arayüz rolleri, kanonik (ASCII slug) biçimde.
ROL_YONETICI = "yonetici"
ROL_STANDART = "standart"
# `hycleus-hardcoded-key-material` kuralı bu satırı YANLIŞ POZİTİF olarak
# işaretliyor: adın içindeki Türkçe "SALT" (yalnızca) sözcüğü kriptografik
# `salt` ile çakışıyor. Değer bir rol adı; ne anahtar, ne nonce, ne tuz.
# Kuralı gevşetmek yerine bu satır susturuldu — kural gerçek gömülü
# anahtarları yakalamaya devam etsin.
# nosemgrep: hycleus-hardcoded-key-material
ROL_SALT_OKUNUR = "salt okunur"

#: `users.role` sütunundaki değerler. Sütunda CHECK kısıtı var.
DB_ADMIN = "admin"
DB_USER = "user"

#: Kanonik rol → kullanıcıya gösterilen ad.
GORUNEN_AD: dict[str, str] = {
    ROL_YONETICI: "Yönetici",
    ROL_STANDART: "Standart",
    ROL_SALT_OKUNUR: "Salt Okunur",
}

#: Arayüzün rol seçimi sunduğu sıra. `AdminPanel._ROLES` ve
#: `login_dialog._SETUP_ROLES` bu listeyle uyumlu olmalı.
SECILEBILIR_ROLLER: tuple[str, ...] = (ROL_YONETICI, ROL_STANDART, ROL_SALT_OKUNUR)

#: Kanonik olmayan yazımlar. Anahtarlar ZATEN katlanmış biçimde
#: (`_katla()` çıktısı), yani buraya Türkçe karakter yazmaya gerek yok.
#:
#: `admin` → yönetici: `users.role` sütununun değeri ve eski
#: `main_window_table.py` da onu yönetici sayıyordu; davranış korunuyor.
#: `user` / `personel` / `kullanici` → standart: hiçbiri yönetici ya da
#: salt-okunur DEĞİL, ve bilinmeyene düşürmek onları yanlışlıkla
#: "rolsüz" yapardı.
_ES_ANLAMLILAR: dict[str, str] = {
    "admin": ROL_YONETICI,
    "administrator": ROL_YONETICI,
    "user": ROL_STANDART,
    "personel": ROL_STANDART,
    "kullanici": ROL_STANDART,
    "standard": ROL_STANDART,
    "readonly": ROL_SALT_OKUNUR,
    "read only": ROL_SALT_OKUNUR,
    "saltokunur": ROL_SALT_OKUNUR,
}

#: NFKD'nin çözemediği harfler. `ı` (U+0131) atomik — ayrıştırması yok.
#: `ÖLÇÜLDÜ: NFKD("ı") == "ı"`.
_ELLE_ESLEME = str.maketrans({"ı": "i", "İ": "i"})


def _katla(ham: str) -> str:
    """Bir rol dizesini karşılaştırılabilir ASCII biçime indirger.

    Sıra önemli: `İ` önce `lower()` ile `i`+birleşen noktaya dönüşüyor,
    NFKD onu ayırıyor, birleşen işaret atılıyor. `ı` ise hiçbir adımda
    çözülmediği için elle eşleniyor.
    """
    s = ham.strip().lower().translate(_ELLE_ESLEME)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = s.replace("_", " ").replace("-", " ")
    return " ".join(s.split())


# ── Genel arayüz ──────────────────────────────────────────────────────────────

def normalize_role(role: str | None) -> str:
    """Rol adını kanonik biçime indirger; tanınmıyorsa boş dize.

    Boş dize BİLEREK: bilinmeyen bir rolü herhangi bir role eşlemek yetki
    kararını tahmine dayandırırdı. Tüketiciler (`is_admin_role`,
    `db_role`) boş dizeyi en dar yetkiye çeviriyor.
    """
    if not role:
        return ""
    katlanmis = _katla(role)
    if katlanmis in GORUNEN_AD:
        return katlanmis
    return _ES_ANLAMLILAR.get(katlanmis, "")


def is_admin_role(role: str | None) -> bool:
    """Bu rol Yönetici mi. Depodaki TEK yönetici karşılaştırması."""
    return normalize_role(role) == ROL_YONETICI


def is_readonly_role(role: str | None) -> bool:
    """Bu rol Salt Okunur mu — yani yazma işlemleri kapalı mı."""
    return normalize_role(role) == ROL_SALT_OKUNUR


def can_write(role: str | None) -> bool:
    """Yazma yetkisi var mı.

    Bilinmeyen rol yazamaz: `normalize_role` onu boş dizeye indiriyor ve
    burada `False` dönüyor. Eski kod `not is_readonly` diyordu, yani
    bilinmeyen bir rol YAZABİLİYORDU — bu düzeltme o yönü daraltıyor.
    Kanonik üç rol için davranış aynı.
    """
    kanonik = normalize_role(role)
    return kanonik in (ROL_YONETICI, ROL_STANDART)


def display_role(role: str | None) -> str:
    """Kullanıcıya gösterilecek ad. Tanınmayan rol olduğu gibi döner."""
    kanonik = normalize_role(role)
    if kanonik:
        return GORUNEN_AD[kanonik]
    return (role or "").strip()


def db_role(role: str | None) -> str:
    """Arayüz rol adını `users.role` değerine çevirir (B-030).

    Bilinmeyen rol `user`'a düşüyor — yetki genişletmesi yanlış yön
    olurdu. Bu kural B-011'de `session_user.db_role()` içinde yazılmıştı;
    uygulama buraya taşındı, `session_user` yeniden dışa aktarıyor.
    """
    return DB_ADMIN if is_admin_role(role) else DB_USER
