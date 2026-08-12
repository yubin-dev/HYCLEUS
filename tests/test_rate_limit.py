"""
CORE.rate_limit — giriş deneme sınırlama testleri.

Gerçek SQLite üzerinde çalışır; zaman `_utcnow` monkeypatch'lenerek kontrol
edilir (sleep yok, testler hızlı ve deterministik).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from CORE import rate_limit
from CORE.rate_limit import BACKOFF_SECONDS, MAX_ATTEMPTS

_HWID = "USB-RL-TEST"


@pytest.fixture
def clock(monkeypatch):
    """Kontrol edilebilir saat — ileri sarmak için advance(saniye)."""

    class Clock:
        def __init__(self) -> None:
            self.now = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)

        def advance(self, seconds: int) -> None:
            self.now += timedelta(seconds=seconds)

    c = Clock()
    monkeypatch.setattr(rate_limit, "_utcnow", lambda: c.now)
    return c


def _audit(db, action: str | None = None) -> list:
    if action is None:
        return db.fetchall("SELECT action, detail FROM audit_log ORDER BY id")
    return db.fetchall(
        "SELECT action, detail FROM audit_log WHERE action = ? ORDER BY id", (action,)
    )


def _fail(db, n: int = 1):
    state = None
    for _ in range(n):
        state = rate_limit.record_failure(db, _HWID)
    return state


# ── Eşik ──────────────────────────────────────────────────────────────────────

def test_first_four_failures_do_not_lock(db, clock) -> None:
    for i in range(1, MAX_ATTEMPTS):
        state = rate_limit.record_failure(db, _HWID)
        assert state.locked is False, f"{i}. hatada kilitlenmemeliydi"
        assert rate_limit.check(db, _HWID).locked is False


def test_sixth_attempt_is_rejected_after_five_failures(db, clock) -> None:
    """5 başarısız denemeden sonra 6. deneme reddedilmeli."""
    state = _fail(db, MAX_ATTEMPTS)

    assert state.locked is True
    assert state.remaining_seconds == BACKOFF_SECONDS[0] == 30

    blocked = rate_limit.check(db, _HWID)
    assert blocked.locked is True
    assert blocked.remaining_seconds == 30
    assert "30 sn" in blocked.message()


def test_clean_hwid_is_not_locked(db, clock) -> None:
    state = rate_limit.check(db, "HIC-DENENMEMIS")
    assert state.locked is False
    assert state.fail_count == 0


# ── Süre dolunca yeniden izin ─────────────────────────────────────────────────

def test_attempt_allowed_after_lock_expires(db, clock) -> None:
    _fail(db, MAX_ATTEMPTS)
    assert rate_limit.check(db, _HWID).locked is True

    clock.advance(29)
    assert rate_limit.check(db, _HWID).locked is True, "süre dolmadan açılmamalı"

    clock.advance(2)  # toplam 31 sn
    assert rate_limit.check(db, _HWID).locked is False, "süre dolunca izin verilmeli"


def test_remaining_seconds_counts_down(db, clock) -> None:
    _fail(db, MAX_ATTEMPTS)
    assert rate_limit.check(db, _HWID).remaining_seconds == 30

    clock.advance(10)
    assert rate_limit.check(db, _HWID).remaining_seconds == 20


# ── Artan gecikme ─────────────────────────────────────────────────────────────

def test_backoff_sequence_is_applied_in_order(db, clock) -> None:
    """5.→30, 6.→60, 7.→120, 8.→300, 9.+→300 (tavan)."""
    beklenen = [30, 60, 120, 300, 300, 300]

    _fail(db, MAX_ATTEMPTS - 1)  # henüz kilit yok

    for i, sure in enumerate(beklenen):
        state = rate_limit.record_failure(db, _HWID)
        assert state.locked is True
        assert state.remaining_seconds == sure, (
            f"{MAX_ATTEMPTS + i}. hatada beklenen {sure} sn, gelen {state.remaining_seconds} sn"
        )
        clock.advance(sure + 1)  # kilidi düşür, sıradaki hataya geç


def test_backoff_for_pure_function() -> None:
    assert rate_limit.backoff_for(0) == 0
    assert rate_limit.backoff_for(4) == 0
    assert rate_limit.backoff_for(5) == 30
    assert rate_limit.backoff_for(6) == 60
    assert rate_limit.backoff_for(7) == 120
    assert rate_limit.backoff_for(8) == 300
    assert rate_limit.backoff_for(99) == 300, "tavan aşılmamalı"


def test_lock_ceiling_is_five_minutes() -> None:
    assert max(BACKOFF_SECONDS) == 300


# ── Başarılı giriş sayacı sıfırlar ────────────────────────────────────────────

def test_success_resets_counter(db, clock) -> None:
    _fail(db, MAX_ATTEMPTS - 1)
    assert rate_limit.check(db, _HWID).fail_count == 4

    rate_limit.record_success(db, _HWID)

    state = rate_limit.check(db, _HWID)
    assert state.fail_count == 0
    assert state.locked is False

    # Sıfırlandıktan sonra yeniden 5 hata gerekmeli, 1 değil
    for _ in range(MAX_ATTEMPTS - 1):
        assert rate_limit.record_failure(db, _HWID).locked is False
    assert rate_limit.record_failure(db, _HWID).locked is True


def test_success_after_lock_expiry_clears_backoff_level(db, clock) -> None:
    """Kilit dolup başarılı giriş yapılırsa gecikme baştan başlamalı."""
    _fail(db, MAX_ATTEMPTS)          # 30 sn kilit
    clock.advance(31)
    rate_limit.record_success(db, _HWID)

    _fail(db, MAX_ATTEMPTS)
    assert rate_limit.check(db, _HWID).remaining_seconds == 30, "gecikme sıfırlanmamış"


# ── Kalıcılık: yeniden başlatma kilidi kaldırmamalı ───────────────────────────

def test_lock_survives_reconnect(db, clock, tmp_path) -> None:
    """
    Sayaç DB'de olduğu için uygulamayı kapatıp açmak kilidi kaldırmamalı.

    Bellekte tutulsaydı bu test geçmezdi — ve kontrol bypass edilebilir olurdu.
    """
    from DB.db_manager import DBManager

    _fail(db, MAX_ATTEMPTS)
    db_path = db._db_path
    db.close()
    DBManager._instance = None

    yeniden = DBManager(db_path)
    yeniden.connect(hwid="TEST-HWID-DB")
    try:
        state = rate_limit.check(yeniden, _HWID)
        assert state.locked is True, "yeniden başlatma kilidi kaldırdı — bypass"
        assert state.fail_count == MAX_ATTEMPTS
    finally:
        yeniden.close()
        DBManager._instance = None


# ── Audit log ─────────────────────────────────────────────────────────────────

def test_every_failure_is_audited(db, clock) -> None:
    _fail(db, 3)

    kayitlar = _audit(db, "login_failed")
    assert len(kayitlar) == 3
    for row in kayitlar:
        assert _HWID in row["detail"]
        assert "fail_count=" in row["detail"]


def test_success_is_audited(db, clock) -> None:
    rate_limit.record_success(db, _HWID)

    kayitlar = _audit(db, "login_success")
    assert len(kayitlar) == 1
    assert _HWID in kayitlar[0]["detail"]


def test_lock_trigger_is_audited_separately(db, clock) -> None:
    """Kilidin devreye girdiği an ayrı bir kayıt olmalı — inceleme için."""
    _fail(db, MAX_ATTEMPTS)

    kayitlar = _audit(db, "login_rate_limited")
    assert len(kayitlar) == 1
    assert "locked_seconds=30" in kayitlar[0]["detail"]


def test_blocked_attempt_is_audited_without_extending_lock(db, clock) -> None:
    """
    Kilitliyken yapılan deneme loglanmalı ama sayacı ARTIRMAMALI.

    Artırsaydı kilitli ekrana basmaya devam etmek kilidi sonsuza uzatırdı.
    """
    _fail(db, MAX_ATTEMPTS)
    onceki = rate_limit.check(db, _HWID)

    for _ in range(3):
        state = rate_limit.check(db, _HWID)
        rate_limit.record_blocked_attempt(db, _HWID, state)

    sonraki = rate_limit.check(db, _HWID)
    assert sonraki.fail_count == onceki.fail_count, "kilitli deneme sayacı artırmış"
    assert len(_audit(db, "login_blocked")) == 3


def test_full_attempt_sequence_is_fully_audited(db, clock) -> None:
    """Her deneme (başarılı/başarısız/engellenen) audit log'a düşmeli."""
    _fail(db, 2)
    rate_limit.record_success(db, _HWID)
    _fail(db, MAX_ATTEMPTS)
    rate_limit.record_blocked_attempt(db, _HWID, rate_limit.check(db, _HWID))

    eylemler = [r["action"] for r in _audit(db)]
    assert eylemler.count("login_failed") == 7
    assert eylemler.count("login_success") == 1
    assert eylemler.count("login_rate_limited") == 1
    assert eylemler.count("login_blocked") == 1


# ── Kullanıcıya gösterilen mesaj ──────────────────────────────────────────────

@pytest.mark.parametrize(
    ("saniye", "beklenen"),
    [(30, "30 sn"), (60, "1 dk"), (90, "1 dk 30 sn"), (120, "2 dk"), (300, "5 dk")],
)
def test_message_shows_remaining_time(saniye: int, beklenen: str) -> None:
    state = rate_limit.LockState(locked=True, remaining_seconds=saniye, fail_count=5)
    assert beklenen in state.message()


def test_message_is_empty_when_not_locked() -> None:
    assert rate_limit.LockState(locked=False, remaining_seconds=0, fail_count=2).message() == ""


def test_corrupt_locked_until_does_not_permanently_lock(db, clock) -> None:
    """Bozuk zaman damgası kalıcı kilitlenmeye yol açmamalı."""
    db.execute(
        "INSERT INTO login_attempts (hwid, fail_count, locked_until) VALUES (?, ?, ?)",
        (_HWID, 5, "bozuk-zaman"),
    )
    state = rate_limit.check(db, _HWID)
    assert state.locked is False
    assert state.fail_count == 5, "sayaç korunmalı — sonraki hata yeniden kilitler"
