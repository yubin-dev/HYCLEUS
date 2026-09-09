"""
HYCLEUS — kayıp bir yönetici/kullanıcı USB'sini kurtarma parçasıyla YENİ
bir USB'ye devretme (B-11X, doğrulama turu 2026-09-09, Madde 2)

Neden bu modül var
------------------
Gerçek çalıştırmayla doğrulandı: tek onaylı yöneticinin USB'si fiziksel
olarak kaybolursa (ya da bozulursa) sistem KALICI OLARAK KİLİTLENİYOR.
`register_new_user()` hiçbir koşulda ikinci bir 'admin' satırı üretmiyor
(B-058/B-060 — kasıtlı), ve `UsbTokensView`/`PendingRegistrationsView`nin
"Sil"/"Reddet" eylemleri zaten oturum açmış bir admin gerektiriyor — kaybı
YAŞAYAN adminin kendisi bunları KULLANAMIYOR.

`CORE.vault_manager` zaten Shamir kurtarma parçası (share_3) üzerinden
`recover_master_key()`/`reprovision_vault()` sağlıyor — bunlar VAULT
dosyasını yeni bir HWID'e taşıyor (master_key ve polinom KORUNARAK) ama
`users` tablosuna hiç dokunmuyor. Dokunulmazsa `sync_session_user()`
(bkz. o modülün docstring'i) yeni HWID için bulamadığı satırı UYDURUR —
`vault:<yeni_hwid>` adında, İKİNCİ bir onaylı satır; eski satır (`hwid`
eski USB'ye bağlı) DB'de sonsuza kadar kalır VE eski USB (bulunsa/
onarılsa bile) hâlâ açılabilir kalırdı — devralma değil, çoğalma olurdu.

Bu modül üç şeyi TEK işlemde yapıyor:
  1. Kurtarma parçası + kalan bir pay (share_1 ya da share_2) ile
     master_key'i kurtarır, YENİ hwid'e reprovision eder (var olan .hcl
     dosyaları aynı anahtarla açılmaya devam eder, basılı kurtarma
     parçası GEÇERLİLİĞİNİ KORUR — bkz. `reprovision_vault()`).
  2. Var olan `users` satırının `hwid` sütununu GÜNCELLER — yeni bir
     satır OLUŞTURMAZ (B-060'ın "bir HWID = bir hesap" ilkesiyle tutarlı,
     `sync_session_user()`'ın uydurma dalını hiç TETİKLEMEZ).
  3. Eski HWID'i `discard_vault()` ile TAMAMEN geçersiz kılar (vault
     dosyası + usb_token + TOTP sırrı silinir) — eski USB (bulunsa bile)
     bundan sonra ASLA açılamaz.

Kapsamlı olarak DOKUNULMAYAN
-----------------------------
`UI/UsbTokensView.py::_on_delete()`, `UI/PendingRegistrationsView.py`
akışları — ikisi de zaten oturum açmış bir admin senaryosu, bu modülün
çözdüğü "hiç admin giremiyor" durumuyla İLGİSİZ, değiştirilmedi.
`register_new_user()` — ikinci bir admin üretme yasağı KORUNDU, bu modül
YENİ bir kullanıcı değil, VAR OLAN birinin kimliğini taşıyor.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from CORE.roles import display_role
from CORE.secret_store import load_totp_secret_for_hwid, store_totp_secret_for_hwid
from CORE.vault_manager import (
    discard_vault,
    recover_master_key,
    reprovision_vault,
)


class TakeoverError(Exception):
    """Devralma reddedildi — çağıran taraf kullanıcıya göstermeli."""


@dataclass(frozen=True)
class TakeoverResult:
    """`takeover_usb()`'ın döndürdüğü değer."""

    user_id: int
    username: str
    role: str


def takeover_usb(
    db: Any,
    *,
    old_hwid: str,
    new_hwid: str,
    recovery_share: str,
    new_pin: str,
    old_pin: str | None = None,
) -> TakeoverResult:
    """
    Kayıp `old_hwid` USB'sinin hesabını, kurtarma parçasıyla `new_hwid`
    USB'sine devreder.

    Var olan `users` satırının `hwid` sütunu GÜNCELLENİR — yeni bir
    kullanıcı OLUŞTURULMAZ (bkz. modül docstring'i).

    Args:
        db:             `DBManager` benzeri; `fetchone`/`execute`/`log`.
        old_hwid:       kayıp USB'nin donanım kimliği (`users.hwid`'de
                        kayıtlı olmalı).
        new_hwid:       devralınan yeni USB'nin donanım kimliği.
        recovery_share: "3:<hex>" kurtarma payı (kullanıcının elindeki
                        basılı/dışa aktarılmış parça) — bkz.
                        `CORE.vault_manager.export_recovery_share`.
        new_pin:        yeni USB için belirlenecek PIN (mevcut
                        `validate_new_pin()` politikasına tabidir —
                        çağıran taraf bunu ÖNCE doğrulamalı, bu fonksiyon
                        yalnızca `create_vault()`'ın kendi asgari
                        kontrolüne güvenir).
        old_pin:        VERİLİRSE eski vault dosyası hâlâ okunabilir
                        durumdaysa (share_1 yoluyla kurtarma) kullanılır;
                        `None` ise share_2 (bu makinenin anahtar
                        kasası) yoluyla kurtarılır — `recover_master_key()`
                        ile AYNI iki senaryo, bkz. o fonksiyonun docstring'i.

    Returns:
        `TakeoverResult(user_id, username, role)` — `role` arayüz
        biçiminde (ör. "Yönetici"), `open_vault(new_hwid, new_pin)`'e
        doğrudan geçirilebilir bir sonraki normal giriş için DEĞİL —
        bu fonksiyon zaten vault'u yeni hwid'e açık bırakır, çağıran
        taraf `open_vault(new_hwid, new_pin)`'i AYRICA çağırıp oturumu
        (`session_key`) buradan almalı (`_on_setup_confirm()`'ün
        create_vault() sonrası ayrıca open_vault() çağırmasıyla AYNI
        desen).

    Raises:
        TakeoverError — `old_hwid` için `users` satırı yoksa (devralınacak
            hesap yok) ya da `new_hwid` ZATEN başka bir satıra bağlıysa
            (iki hesabı birleştirmeye kalkışmaz, B-060 ihlali olurdu).
        Exception — `recover_master_key()`/`reprovision_vault()`'un
            fırlattığı her şey (yanlış kurtarma parçası, yanlış PIN,
            vault/kasa okunamıyor) OLDUĞU GİBİ yukarı taşınır — bu
            noktada `users` tablosuna HENÜZ dokunulmamıştır.

    Not (rol hassasiyeti): `users.role` DB sütunu yalnızca kaba
    admin/user ayrımı taşır (`CORE.roles.db_role()`) — ince taneli rol
    (Standart/Salt Okunur) vault dosyasının İÇİNDE saklanır. Bu modül
    yalnızca SOLE-ADMIN kilitlenme senaryosunu çözmek için var
    (`display_role(eski_satir["role"])` admin için doğru sonucu —
    "Yönetici" — verir); Standart/Salt Okunur bir kullanıcının USB'sini
    devretmek isteyen bir çağıran, reprovision edilen vault'un rolünün
    her zaman "Standart"a düşeceğini bilmeli.
    """
    eski_satir = db.fetchone(
        "SELECT id, username, role FROM users WHERE hwid = ?", (old_hwid,)
    )
    if eski_satir is None:
        raise TakeoverError(
            f"'{old_hwid}' için devralınacak bir hesap bulunamadı."
        )
    if db.fetchone("SELECT id FROM users WHERE hwid = ?", (new_hwid,)) is not None:
        raise TakeoverError(
            f"Yeni USB ('{new_hwid}') zaten başka bir hesaba bağlı — "
            "önce o kaydı kaldırın."
        )

    # ── Vault katmanı: master_key'i kurtar, YENİ hwid'e yeniden kur ────────
    # PIN/TOTP akışı ATLANMIYOR: bu, çağıranın ÖNCE recover_master_key()'in
    # kendi doğrulamasından (yanlış kurtarma parçası/PIN → Exception, henüz
    # hiçbir DB satırı değişmedi) geçmesi anlamına gelir; SONRA yeni USB
    # için normal giriş akışı (PIN+TOTP) aynen işlemeye devam eder.
    master_key = recover_master_key(old_hwid, recovery_share=recovery_share, pin=old_pin)
    rol_arayuz = display_role(eski_satir["role"])
    reprovision_vault(
        new_hwid, new_pin, rol_arayuz,
        master_key=master_key, recovery_share=recovery_share,
    )

    # TOTP sırrı eski hwid'e bağlıydı — taşınmazsa yeni USB'yle giriş TOTP
    # adımında hiçbir zaman geçemez (self._secret None kalır, login_dialog.py
    # B-059 mesajını verir).
    eski_totp = load_totp_secret_for_hwid(old_hwid)
    if eski_totp is not None:
        store_totp_secret_for_hwid(new_hwid, eski_totp)

    # ── Eski HWID'i TAMAMEN geçersiz kıl ────────────────────────────────
    # SIRALAMA ÖNEMLİ: discard_vault() eski vault dosyasını SİLER — bu
    # noktadan SONRA old_hwid ile hiçbir open_vault()/recover_master_key()
    # çağrısı başarılı olamaz. master_key ve TOTP sırrı YUKARIDA zaten
    # güvenle taşındığı için veri kaybı yok.
    discard_vault(old_hwid)

    # ── users satırını GÜNCELLE: yeni satır DEĞİL, VAR OLANI değiştir ──
    user_id = int(eski_satir["id"])
    db.execute("UPDATE users SET hwid = ? WHERE id = ?", (new_hwid, user_id))

    detail = f"eski_hwid={old_hwid} yeni_hwid={new_hwid} kaynak={'share_1+share_3' if old_pin else 'share_2+share_3'}"
    db.log("usb_devralindi", user_id=user_id, detail=detail)

    return TakeoverResult(
        user_id=user_id, username=str(eski_satir["username"]), role=rol_arayuz,
    )
