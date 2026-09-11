"""
HYCLEUS — TOTP replay-önleme: tüm TOTP doğrulama kapıları için TEK yol.

B-141: `pyotp.TOTP(secret).verify(code, valid_window=1)` bir kodu KENDİ
30 saniyelik adımının DIŞINDA (önceki/sonraki adım) da kabul ediyordu —
yani aynı kod, yakalanıp (omuz üstünden bakma, ekran kaydı) tekrar
gönderilirse, geçerliliği süresince (pratikte ~30-90 sn) BİRDEN FAZLA
kez kabul edilebiliyordu. Dört ayrı TOTP kapısının (kayıt/kurulum onayı
— UI/login_dialog.py, giriş — UI/login_dialog.py, bulk indirme —
UI/main_window_bulk.py, tekli dosya indirme — UI/main_window_files.py,
klasör indirme — UI/main_window_tree.py) hiçbirinde "bu kod zaten
kullanıldı" diye bir kayıt yoktu.

Yöntem — bilerek BASİT
-----------------------
Kullanılan kodun AİT olduğu 30 saniyelik adımı bulup (önceki/şu anki/
sonraki üçünden HANGİSİYLE eşleştiyse) hwid başına DB'de tutmak, aynı ya
da daha ESKİ bir adıma denk gelen bir kodu reddetmek. Karmaşık bir
cache/TTL mekanizması İCAT EDİLMEDİ — TOTP adımları monoton arttığı için
tek bir "son kullanılan adım" sütunu yeterli (bkz. DB/migrations.py::
_m28_totp_replay_guard).
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

import pyotp

from DB.db_manager import DBManager


def _eslesen_adimi_bul(totp: "pyotp.TOTP", code: str, simdi: float | None = None) -> int | None:
    """`code`'un `valid_window=1`'in kapsadığı üç adımdan (önceki/şu anki/
    sonraki) HANGİSİNDE üretildiğini bulur — yalnızca bookkeeping için;
    kabul/red kararının kendisi hâlâ `totp.verify(...)` veriyor (bkz.
    `verify_totp_no_replay`, bu yalnızca ONDAN SONRA çağrılıyor)."""
    t = simdi if simdi is not None else time.time()
    for delta in (-1, 0, 1):
        aday_zaman = t + delta * 30
        if totp.at(int(aday_zaman)) == code:
            return int(aday_zaman // 30)
    return None


def verify_totp_no_replay(
    secret: str,
    code: str,
    hwid: str,
    *,
    db: DBManager | None = None,
    simdi: float | None = None,
) -> bool:
    """
    TOTP kodunu doğrular VE aynı (ya da daha eski) bir adımın tekrar
    kullanılmasını (replay) engeller. Dört TOTP kapısının hepsinin
    kullanması gereken TEK ortak yol — ayrıca kopya kodların birbirinden
    sessizce sapmasını (bkz. MC-Kataloğu M039/M045) önler.

    Kabul kriteri BİREBİR `pyotp.TOTP(secret).verify(code,
    valid_window=1)` — pencere/algoritma burada da GENİŞLETİLMEDİ (bkz.
    tests/test_authz_invariants.py'nin bu dosyayı tarayan AST testleri).
    TEK fark: `verify()` True dönse bile, eşleşen adım daha önce BAŞKA
    bir başarılı doğrulamada zaten kullanılmışsa reddediyor.

    `simdi` yalnızca testler için — verilmezse gerçek `time.time()`
    kullanılır (üretim çağrılarının hiçbiri bunu geçmiyor).
    """
    db = db if db is not None else DBManager()
    t = simdi if simdi is not None else time.time()
    totp = pyotp.TOTP(secret)
    icin_zaman = datetime.fromtimestamp(t, tz=timezone.utc)
    if not totp.verify(code, for_time=icin_zaman, valid_window=1):
        return False
    adim = _eslesen_adimi_bul(totp, code, simdi=t)
    if adim is None:
        # Kuramsal: verify() True dedi ama üç adımın hiçbiri eşleşmedi
        # (saat kayması/yarış durumu) — güvenli tarafta kalıp reddet.
        return False
    row = db.fetchone(
        "SELECT son_adim FROM totp_replay_guard WHERE hwid = ?", (hwid,)
    )
    son_adim = row["son_adim"] if row is not None else None
    if son_adim is not None and adim <= son_adim:
        return False
    db.execute(
        "INSERT INTO totp_replay_guard (hwid, son_adim) VALUES (?, ?)"
        " ON CONFLICT(hwid) DO UPDATE SET son_adim = excluded.son_adim",
        (hwid, adim),
    )
    return True


__all__ = ["verify_totp_no_replay"]
