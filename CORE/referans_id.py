"""
HYCLEUS — Kurumsal Referans ID

İlk Kurulum sihirbazında Kurumsal seçilirse üretilen, `settings` tablosunda
saklanan ve Kayıt Ol ekranındaki "Referans Kodu" alanıyla GERÇEKTEN
karşılaştırılan tek bir kimlik değeri.

Neden yeni bir sütun/migrasyon değil
-------------------------------------
Kurulum başına TEK bir değer — `CORE/app_mode.py`'nin `app_mode` anahtarıyla
birebir aynı desen: `settings` zaten genel amaçlı bir key-value deposu
(bkz. `DB/db_manager.py::get_setting`/`set_setting`, `imha_ttl_hours` de
aynı yoldan gidiyor). `users` tablosuna kurum/referans sütunu eklemek bu
değerin kullanıcı başına farklı olabileceğini ima ederdi — değil, tüm
kurulum için aynı tek değer.

Benzersizlik — nasıl "garanti" ediliyor
-----------------------------------------
Kurulum başına yalnızca BİR referans_id üretiliyor, yani karşılaştırılacak
bir "diğer kayıtlar" kümesi yok — global bir eşsizlik kaydı tutmanın gerçek
bir karşılığı yok. Bunun yerine üretecin KENDİSİ yeterince geniş bir
rastgele uzaydan seçim yapıyor: `secrets.choice` (CSPRNG) ile 32 sembollük
bir alfabeden (karışabilecek 0/O/1/I harfleri ELENDİ) 8 karakter — 32⁸ ≈
1.1×10¹² olasılık. Bu MATEMATİKSEL bir garanti değil ("KRM-XXXX" gibi kısa
bir kod hiçbir üreteçte olamaz), ama pratikte çakışmasız: 20.000 örneklik
bir testte bile beklenen çakışma olasılığı ~10⁻⁴ (doğum günü sınırı,
bkz. `tests/test_referans_id.py`).
"""
from __future__ import annotations

import secrets
from typing import Any

#: `settings` tablosundaki anahtar adı.
REFERANS_ID_SETTING = "referans_id"

#: Karışabilecek karakterler (0/O, 1/I/L) ELENDİ — elle karşılaştırırken/
#: okurken hata riski azaltmak için (Crockford base32'ye yakın bir seçim).
_ALFABE = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_UZUNLUK = 8
_ONEK = "KRM-"


def generate_referans_id() -> str:
    """Yeni bir Referans ID üretir — saf fonksiyon, DB'ye dokunmaz."""
    gövde = "".join(secrets.choice(_ALFABE) for _ in range(_UZUNLUK))
    return f"{_ONEK}{gövde}"


def get_referans_id(db: Any) -> str | None:
    """Kayıtlı Referans ID; hiç üretilmemişse `None`."""
    deger = db.get_setting(REFERANS_ID_SETTING, "")
    return deger or None


def set_referans_id(db: Any, referans_id: str) -> None:
    """Referans ID'yi kalıcı olarak yazar ve denetim kaydına düşer."""
    db.set_setting(REFERANS_ID_SETTING, referans_id)
    db.log("referans_id_generated", detail=f"key={REFERANS_ID_SETTING}")


__all__ = [
    "REFERANS_ID_SETTING",
    "generate_referans_id",
    "get_referans_id",
    "set_referans_id",
]
