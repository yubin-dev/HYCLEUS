"""
HYCLEUS — PIN yenilemenin TEK karar ve uygulama noktası (B-003)

PIN politikası 4 haneden 6'ya çıkarıldığında (`f3b70cf`) mevcut hesaplar
olduğu yerde bırakıldı: Argon2id doğrulaması uzunluktan bağımsız çalışıyor,
yani 4-5 haneli eski PIN'ler geçerli kalmaya devam etti. Giriş ekranındaki
eşik de bu yüzden ayrı bir sabite alındı (`LOGIN_MIN_LEN = 4`) — 6'ya
çekilseydi o kullanıcılar KENDİ DOĞRU PIN'leriyle giriş yapamazdı.

Sonuç bir politika boşluğuydu: politikanın koruduğu şey (kısa PIN'e karşı
kaba kuvvet direnci) tam olarak en eski — ve büyük ihtimalle en yetkili —
hesaplarda geçerli değildi.

Bu modül o boşluğu kapatıyor: kısa PIN'le giren kullanıcı, ana pencere
açılmadan önce PIN'ini yenilemek ZORUNDA.


Tespit neden GİRİŞ ANINDA
--------------------------
PIN'in uzunluğu hash'ten çıkarılamaz — Argon2id çıktısı sabit boyutlu.
Düz metin PIN yalnızca tek bir anda elde: doğrulama başarılı olduktan
hemen sonra, `_on_login` içinde. Başka hiçbir yerde bu soru
sorulamıyor.


Neden AYRI bir modül, diyaloğun içinde değil
---------------------------------------------
`UI/ProfileView.py` PIN değiştirmeyi ZATEN uyguluyor: doğrula →
`change_vault_pin()` → `last_pin_changed` güncelle → denetim kaydı.
Zorunlu akış için ikinci bir kopya yazmak, bu deponun beş kez ürettiği
kusurun altıncısı olurdu (B-004/B-008, B-007, B-010, B-011, pay
ayrıştırıcı).

Somut risk: bir gün PIN değişimine yeni bir adım eklenir (örneğin
kurtarma parçasının yeniden üretilmesi) ve yalnızca bir kopyaya eklenir.
İki yoldan biri sessizce eksik kalır.

`tests/test_pin_rotation.py` `change_vault_pin()`'in UI katmanından
DOĞRUDAN çağrılmadığını AST ile denetliyor.


Bu modül PIN'i SAKLAMIYOR
--------------------------
Ne eski ne yeni PIN hiçbir yere yazılıyor. Denetim kaydına giren tek şey
"yenilendi" olgusu, HWID'nin ilk sekiz karakteri ve eski PIN'in
UZUNLUĞU — değeri değil. Uzunluk kayda giriyor çünkü "hangi hesaplar
göç etti" sorusu ancak böyle yanıtlanabiliyor ve tek başına bir sır
değil (zaten politikanın altında olduğu biliniyor).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from CORE.pin_policy import PIN_MIN_LEN, validate_new_pin

_log = logging.getLogger("hycleus.pin_rotation")

#: Zorunlu yenileme denetim kaydı — B-003 akışı.
EYLEM_ZORUNLU = "pin_rotation_forced"
#: Kullanıcının kendi isteğiyle yaptığı değişiklik (ProfileView).
EYLEM_ISTEGE_BAGLI = "pin_changed"


class PinRotationError(Exception):
    """PIN yenilenemedi. Mesaj doğrudan kullanıcıya gösterilebilir."""


def yenileme_gerekli(pin: str) -> bool:
    """Bu PIN mevcut politikanın altında mı — yani yenilenmesi şart mı.

    Tek karar noktası. `len(pin) < PIN_MIN_LEN` karşılaştırmasının
    başka bir yerde tekrarlanması, politika eşiği değiştiğinde iki
    yerden birinin unutulması demek olurdu.
    """
    return len(pin) < PIN_MIN_LEN


def rotate_pin(
    db: Any,
    hwid: str,
    old_pin: str,
    new_pin: str,
    *,
    user_id: int | None = None,
    zorunlu: bool = False,
) -> None:
    """PIN'i değiştirir, kaydı günceller ve denetim kaydı düşer.

    Sıra KRİTİK ve bu sırayla olmalı:

      1. Yeni PIN politikaya uyuyor mu (`validate_new_pin`)
      2. Kasa yeniden şifreleniyor (`change_vault_pin`) ← asıl iş
      3. `users.last_pin_changed` güncelleniyor
      4. Denetim kaydı yazılıyor

    3 ve 4 BAŞARISIZ OLSA BİLE işlem başarılı sayılıyor: kasa 2. adımda
    zaten yeniden şifrelendi ve kullanıcının yeni PIN'i geçerli. Burada
    hata fırlatmak, çalışan bir değişikliği "başarısız" diye bildirip
    kullanıcıyı eski PIN'ini denemeye iterdi — yani gerçek bir
    kilitlenme üretirdi.

    Args:
        db:      `DBManager` benzeri; `execute`/`log` gerekiyor.
        hwid:    Kasanın donanım kimliği.
        old_pin: Doğrulanmış mevcut PIN.
        new_pin: Kullanıcının belirlediği yeni PIN.
        user_id: Biliniyorsa `users.id`. Giriş anında henüz
                 bilinmeyebilir (`sync_session_user` sonra çalışıyor);
                 o durumda `last_pin_changed` atlanıyor ama denetim
                 kaydı yine düşüyor.
        zorunlu: Zorunlu akış mı — yalnızca denetim eylem adını
                 belirliyor, davranışı değiştirmiyor.

    Raises:
        PinRotationError — yeni PIN politikaya uymuyorsa, eski PIN
            yanlışsa ya da kasa yazılamıyorsa. Mesaj kullanıcıya
            gösterilebilir.
    """
    hata = validate_new_pin(new_pin)
    if hata:
        raise PinRotationError(hata)

    if new_pin == old_pin:
        # Zorunlu akışta erişilemez (eski PIN zaten 6'dan kısa, yenisi
        # değil), ama isteğe bağlı akışta mümkün ve anlamsız: kasa
        # yeniden şifrelenir, hiçbir şey değişmez ve denetim kaydı
        # yanıltıcı olur.
        raise PinRotationError("Yeni PIN eskisiyle aynı olamaz.")

    from CORE.vault_manager import change_vault_pin

    try:
        change_vault_pin(hwid, old_pin, new_pin)
    except ValueError as exc:
        raise PinRotationError(str(exc)) from exc
    except Exception as exc:  # dosya yazılamadı, kasa bozuk …
        _log.error("pin_rotation_failed  hwid=%s  exc=%s", hwid[:8], exc)
        raise PinRotationError(f"PIN değiştirilemedi: {exc}") from exc

    _kaydet(db, hwid, old_pin_len=len(old_pin), user_id=user_id, zorunlu=zorunlu)


def _kaydet(
    db: Any, hwid: str, *, old_pin_len: int, user_id: int | None, zorunlu: bool
) -> None:
    """Kayıt tarafı — burada oluşan hata işlemi BAŞARISIZ yapmıyor."""
    simdi = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        if user_id is not None:
            db.execute(
                "UPDATE users SET last_pin_changed = ? WHERE id = ?",
                (simdi, user_id),
            )
        db.log(
            EYLEM_ZORUNLU if zorunlu else EYLEM_ISTEGE_BAGLI,
            user_id=user_id,
            detail=(
                f"hwid={hwid[:8]} eski_uzunluk={old_pin_len} "
                f"yeni_alt_sinir={PIN_MIN_LEN}"
            ),
        )
    except Exception as exc:  # pragma: no cover — kayıt, sonucu engellemez
        _log.warning("pin_rotation_log_failed  hwid=%s  exc=%s", hwid[:8], exc)


__all__ = [
    "EYLEM_ISTEGE_BAGLI",
    "EYLEM_ZORUNLU",
    "PinRotationError",
    "rotate_pin",
    "yenileme_gerekli",
]
