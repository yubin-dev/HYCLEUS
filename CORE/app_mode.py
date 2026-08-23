"""
HYCLEUS — Bireysel/Kurumsal görünüm modu

Bu modül YALNIZCA bir görünürlük filtresi taşır — yetki DEĞİL. RBAC
(CORE/roles.py, can_write/rol_yazabilir, CORE/vault_manager.py) bu
moddan hiç haberdar değil ve olmamalı: mod "hangi ekranlar gösterilsin"
sorusuna cevap veriyor, "kim ne yapabilir" sorusuna değil. AdminPanel'e
giriş zaten `is_admin_role()` ile ayrı, mod'dan bağımsız bir kapıdan
geçiyor (bkz. main_window.py::_on_open_admin_panel, AdminPanel.py).

Neden `settings` tablosu, oturum içi değil
-------------------------------------------
UI/GuvenlikView.py'nin Basit/Gelişmiş kararının TERSİ mantık: o tercih
kullanıcı başına farklı olabilirdi, bu yüzden hiç DB'ye yazılmadı. Mod
ise TÜM kullanıcılar için AYNI görünmeli — aynı kurulumda bir yönetici
"tek kullanıcıyım" derken başka bir yönetici "Bekleyen Kayıtlar"
sekmesini görmeye devam etseydi bu bir kullanıcı tercihi değil bir
tutarsızlık olurdu. `settings` zaten kurulum-geneli bir tablo
(`imha_ttl_hours`, `idle_lock_minutes` ile birebir aynı desen).

Ne zaman seçilir
-----------------
İlk kurulum sihirbazına EKLENMEDİ. Varsayılan KURUMSAL'dır (hiçbir şey
gizlenmez); isteyen sonradan Yönetici Paneli → Ayarlar'dan Bireysel'e
geçer, istediği an geri döner. İki gerekçe: (1) `imha_ttl_hours` ve
hareketsizlik kilidi de aynı şekilde yalnızca Ayarlar'dan değişiyor —
sihirbaza yeni bir soru eklemek bu depoda hiç kullanılmayan bir örüntü
olurdu; (2) sihirbazda yanlış cevaplanmış bir soru "nasıl geri
alacağım" belirsizliği taşır, Ayarlar'dan her an geri dönülebilen bir
anahtar taşımaz.

Var olan kurulumlar (bu göçten önceki veritabanları — bkz.
DB/migrations.py Migration 22) KURUMSAL alır: hiçbir şey gizlenmemiş
hâliyle devam ederler, davranış sessizce değişmez.
"""
from __future__ import annotations

import logging
from typing import Any

_log = logging.getLogger("hycleus.app_mode")

#: Modun tutulduğu settings anahtarı.
APP_MODE_SETTING = "app_mode"

KURUMSAL = "kurumsal"
BIREYSEL = "bireysel"

VALID_MODES: tuple[str, ...] = (KURUMSAL, BIREYSEL)

#: Var olan kurulumlar ve bozuk/tanınmayan değerler buraya düşer — hiçbir
#: şey gizlenmemiş hâl, sessiz bir kısıtlama DEĞİL.
DEFAULT_MODE = KURUMSAL


def get_app_mode(db: Any) -> str:
    """Kayıtlı görünüm modu; tanınmayan/bozuk değerde KURUMSAL'a düşer."""
    deger = db.get_setting(APP_MODE_SETTING, DEFAULT_MODE)
    if deger not in VALID_MODES:
        _log.warning(
            "%s tanınmıyor (%r) — varsayılana dönülüyor: %s",
            APP_MODE_SETTING, deger, DEFAULT_MODE,
        )
        return DEFAULT_MODE
    return deger


def set_app_mode(db: Any, mode: str, *, hwid: str | None = None) -> None:
    """Görünüm modunu yazar ve denetim kaydına düşer.

    Yalnızca `settings` tablosuna yazıyor ve `db.log(...)` çağırıyor —
    hiçbir kullanıcı satırını, hiçbir rolü, hiçbir RBAC kontrolünü
    değiştirmiyor.
    """
    if mode not in VALID_MODES:
        raise ValueError(f"geçersiz mod: {mode!r} — {VALID_MODES} olmalı")
    db.set_setting(APP_MODE_SETTING, mode)
    suffix = f" hwid={hwid}" if hwid else ""
    db.log("app_mode_changed", detail=f"key={APP_MODE_SETTING} value={mode}{suffix}")


def is_bireysel(mode: str) -> bool:
    return mode == BIREYSEL


__all__ = [
    "APP_MODE_SETTING",
    "KURUMSAL",
    "BIREYSEL",
    "VALID_MODES",
    "DEFAULT_MODE",
    "get_app_mode",
    "set_app_mode",
    "is_bireysel",
]
