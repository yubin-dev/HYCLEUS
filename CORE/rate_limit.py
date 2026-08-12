"""
HYCLEUS — Giriş deneme sınırlama (rate limit)

5 başarısız denemeden sonra giriş geçici olarak kilitlenir; her ek
başarısızlıkta kilit süresi artar:

    5. hata → 30 sn
    6. hata → 60 sn
    7. hata → 120 sn
    8. hata → 300 sn
    9+     → 300 sn (tavan)

Başarılı giriş sayacı sıfırlar.

Sayaç neden bellekte değil, veritabanında
-----------------------------------------
Sayaç bellekte tutulsaydı uygulamayı kapatıp açmak sayacı sıfırlardı.
Giriş ekranındaki bir saldırgan Alt+F4 → yeniden başlat döngüsüyle sınırsız
deneme yapabilirdi; kilit birkaç saniyelik bir gecikmeye dönüşür, kaba
kuvvete karşı hiçbir şey yapmazdı. Yani bellekte tutmak kontrolü tamamen
bypass edilebilir kılar.

Veritabanında tutulduğunda kilit yeniden başlatmayı aşar. Saldırganın
elinde yalnızca uygulama arayüzü varsa 5 denemeden sonra gerçekten
beklemek zorunda kalır.

Bu kontrolün SINIRI — ne yapar, ne yapmaz
-----------------------------------------
Bu kontrol YALNIZCA uygulama içi (arayüz üzerinden) kaba kuvvet denemesini
yavaşlatır. Aşağıdakileri ENGELLEMEZ:

  · Dosya sistemine erişimi olan bir saldırgan `data/hycleus.db` dosyasını
    doğrudan açıp `login_attempts` tablosunu silebilir veya `locked_until`
    alanını geçmişe çekebilir. Sayaç şifreli değildir ve olamaz — kilidi
    uygulamanın kendisi okuyabilmek zorunda.

  · Vault dosyasını (`.hclv`) kopyalayıp çevrimdışı kaba kuvvet uygulayan
    bir saldırgan bu koddan hiç geçmez. Oradaki tek savunma Argon2id'nin
    maliyet parametreleridir (time=3, mem=64 MB, para=4), bu sayaç değil.

  · Sistem saatini geri alan bir saldırgan kilidi erken düşürebilir.
    `locked_until` mutlak zaman damgasıdır; monotonik saat kullanmak
    yeniden başlatmayı aşma özelliğini kaybettirirdi (monotonik saat
    açılışta sıfırlanır). Bu bilinçli bir takas.

Kısacası: bu, "USB'yi ve uygulamayı ele geçirmiş ama PIN'i bilmeyen"
saldırganı yavaşlatan bir kontroldür. Diskteki veriyi okuyabilen bir
saldırgana karşı savunma değildir. Gerçek savunma tam disk şifrelemesi +
Argon2id maliyetidir.

(Proje bir SECURITY.md kazandığında bu bölüm oraya taşınmalı.)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_log = logging.getLogger("hycleus.rate_limit")

# Kilit devreye girmeden önceki serbest deneme sayısı
MAX_ATTEMPTS = 5

# Kilit süreleri (saniye). Son değer tavandır ve tekrarlanır.
BACKOFF_SECONDS = (30, 60, 120, 300)

_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(frozen=True)
class LockState:
    """Bir HWID'nin anlık kilit durumu."""

    locked: bool
    remaining_seconds: int
    fail_count: int

    def message(self) -> str:
        """Kullanıcıya gösterilecek metin — kalan süreyi içerir."""
        if not self.locked:
            return ""
        if self.remaining_seconds >= 60:
            dakika, saniye = divmod(self.remaining_seconds, 60)
            sure = f"{dakika} dk {saniye} sn" if saniye else f"{dakika} dk"
        else:
            sure = f"{self.remaining_seconds} sn"
        return f"Çok fazla hatalı deneme — {sure} sonra tekrar deneyin"


def _utcnow() -> datetime:
    """Şimdiki UTC zamanı. Testler bunu monkeypatch'ler."""
    return datetime.now(timezone.utc)


def _fmt(dt: datetime) -> str:
    return dt.strftime(_TS_FORMAT)


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, _TS_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        # Bozuk zaman damgası: kilitli saymak güvenli taraf değil (kalıcı
        # kilitlenme riski), kilitsiz saymak da değil. Kilitsiz sayılır ama
        # sayaç korunur — bir sonraki hata yeniden kilitler.
        _log.warning("login_attempts.locked_until ayrıştırılamadı: %r", value)
        return None


def backoff_for(fail_count: int) -> int:
    """
    Verilen başarısızlık sayısı için kilit süresini (saniye) döndürür.

    MAX_ATTEMPTS altındaysa 0 — henüz kilit yok.
    """
    if fail_count < MAX_ATTEMPTS:
        return 0
    level = fail_count - MAX_ATTEMPTS
    return BACKOFF_SECONDS[min(level, len(BACKOFF_SECONDS) - 1)]


def _row(db: object, hwid: str):
    return db.fetchone(  # type: ignore[attr-defined]
        "SELECT fail_count, locked_until FROM login_attempts WHERE hwid = ?", (hwid,)
    )


def check(db: object, hwid: str) -> LockState:
    """
    Girişe izin verilip verilmediğini döndürür — hiçbir şey yazmaz.

    _on_login'in en başında çağrılır.
    """
    row = _row(db, hwid)
    if row is None:
        return LockState(locked=False, remaining_seconds=0, fail_count=0)

    fail_count = int(row["fail_count"])
    locked_until = _parse(row["locked_until"])
    if locked_until is None:
        return LockState(locked=False, remaining_seconds=0, fail_count=fail_count)

    remaining = int((locked_until - _utcnow()).total_seconds())
    if remaining <= 0:
        return LockState(locked=False, remaining_seconds=0, fail_count=fail_count)

    return LockState(locked=True, remaining_seconds=remaining, fail_count=fail_count)


def record_failure(db: object, hwid: str, *, detail: str = "") -> LockState:
    """
    Başarısız denemeyi kaydeder, gerekiyorsa kilidi kurar ve audit log'a yazar.

    Returns:
        Yeni kilit durumu — çağıran taraf message() ile kullanıcıya gösterir.
    """
    row = _row(db, hwid)
    fail_count = (int(row["fail_count"]) if row is not None else 0) + 1

    lock_seconds = backoff_for(fail_count)
    now = _utcnow()
    locked_until = _fmt(now + timedelta(seconds=lock_seconds)) if lock_seconds else None

    db.execute(  # type: ignore[attr-defined]
        """
        INSERT INTO login_attempts (hwid, fail_count, locked_until, last_attempt)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(hwid) DO UPDATE SET
            fail_count   = excluded.fail_count,
            locked_until = excluded.locked_until,
            last_attempt = excluded.last_attempt
        """,
        (hwid, fail_count, locked_until, _fmt(now)),
    )

    suffix = f" {detail}" if detail else ""
    db.log(  # type: ignore[attr-defined]
        "login_failed",
        detail=f"hwid={hwid} fail_count={fail_count} lock_seconds={lock_seconds}{suffix}",
    )
    if lock_seconds:
        db.log(  # type: ignore[attr-defined]
            "login_rate_limited",
            detail=f"hwid={hwid} fail_count={fail_count} locked_seconds={lock_seconds}",
        )
        _log.warning(
            "Giriş kilitlendi  hwid=%s  fail_count=%d  süre=%ds",
            hwid, fail_count, lock_seconds,
        )

    return LockState(
        locked=bool(lock_seconds),
        remaining_seconds=lock_seconds,
        fail_count=fail_count,
    )


def record_success(db: object, hwid: str) -> None:
    """Başarılı girişi audit log'a yazar ve sayacı sıfırlar."""
    db.execute("DELETE FROM login_attempts WHERE hwid = ?", (hwid,))  # type: ignore[attr-defined]
    db.log("login_success", detail=f"hwid={hwid}")  # type: ignore[attr-defined]


def record_blocked_attempt(db: object, hwid: str, state: LockState) -> None:
    """
    Kilitliyken yapılan denemeyi audit log'a yazar.

    Sayaç artırılmaz — aksi halde kilitli ekrana sürekli basmak kilidi
    sonsuza kadar uzatırdı (kendi kendine DoS).
    """
    db.log(  # type: ignore[attr-defined]
        "login_blocked",
        detail=(
            f"hwid={hwid} fail_count={state.fail_count} "
            f"remaining_seconds={state.remaining_seconds}"
        ),
    )
