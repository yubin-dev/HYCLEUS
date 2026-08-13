"""
HYCLEUS — Hareketsizlik kilidi testleri

Zaman SAHTE: `IdleTracker`'ın bütün zaman alan metotları bir `now`
parametresi kabul ediyor, dolayısıyla 10 dakikalık eşik gerçek 10 dakika
beklemeden sınanıyor. Testlerin hiçbiri `time.sleep()` çağırmıyor.

Kapsam dışı — Qt tarafı
-----------------------
`main_window.eventFilter` / `_tick_idle` / `_lock("idle")` bir QApplication
gerektiriyor ve bu test paketi başsız çalışıyor. O katman bilerek İNCE
tutuldu: olay geldiğinde `record_activity()`, tik'te `should_lock()`.
Karar veren her satır burada sınanıyor; Qt tarafında kalan şey iki çağrı
ve bir küme işlemi.

Test edilmeyen Qt davranışları (elle doğrulanmalı):
  · event filter'ın QApplication'a kurulması
  · örtünün gösterilmesi/gizlenmesi ve tıklanınca PIN sorması
  · AdminPanel combo'sunun kaydedilen değeri geri yüklemesi
"""
from __future__ import annotations

import pytest

from CORE.audit_chain import verify_audit_chain
from CORE.idle_lock import (
    DEFAULT_IDLE_MINUTES,
    IDLE_DISABLED,
    IDLE_OPTIONS,
    IDLE_TIMEOUT_SETTING,
    MAX_IDLE_MINUTES,
    MIN_IDLE_MINUTES,
    IdleTracker,
    get_idle_timeout_minutes,
    log_idle_lock,
    set_idle_timeout_minutes,
    timeout_milliseconds,
)


def _actions(db) -> list[str]:
    return [r["action"] for r in db.fetchall("SELECT action FROM audit_log ORDER BY id")]


# ══════════════════════════════════════════════════════════════════════════════
# 1. Zamanlama — sahte saatle
# ══════════════════════════════════════════════════════════════════════════════


def test_tracker_does_not_lock_before_the_timeout():
    t = IdleTracker.from_minutes(10)
    t.record_activity(now=1000.0)

    assert t.should_lock(now=1000.0) is False
    assert t.should_lock(now=1000.0 + 599.0) is False        # 9 dk 59 sn


def test_tracker_locks_exactly_at_the_timeout():
    t = IdleTracker.from_minutes(10)
    t.record_activity(now=1000.0)
    assert t.should_lock(now=1000.0 + 600.0) is True         # tam 10 dk


def test_tracker_locks_after_the_timeout():
    t = IdleTracker.from_minutes(5)
    t.record_activity(now=0.0)
    assert t.should_lock(now=301.0) is True


@pytest.mark.parametrize("minutes", [1, 5, 10, 15, 30, 60])
def test_timeout_boundary_holds_for_every_offered_option(minutes: int):
    """Arayüzde sunulan her seçenek için eşik saniyesi doğru olmalı."""
    t = IdleTracker.from_minutes(minutes)
    t.record_activity(now=0.0)
    esik = minutes * 60
    assert t.should_lock(now=esik - 0.5) is False
    assert t.should_lock(now=esik) is True


def test_idle_seconds_counts_from_the_last_activity():
    t = IdleTracker.from_minutes(10)
    t.record_activity(now=100.0)
    assert t.idle_seconds(now=160.0) == pytest.approx(60.0)


def test_remaining_seconds_counts_down():
    t = IdleTracker.from_minutes(10)
    t.record_activity(now=0.0)
    assert t.remaining_seconds(now=0.0) == pytest.approx(600.0)
    assert t.remaining_seconds(now=240.0) == pytest.approx(360.0)
    assert t.remaining_seconds(now=600.0) == pytest.approx(0.0)
    assert t.remaining_seconds(now=9999.0) == pytest.approx(0.0)   # negatife düşmez


def test_backwards_clock_does_not_postpone_the_lock():
    """
    Geri giden bir saat kaynağı kilidi ERTELEYEMEMELİ.

    monotonic saat normalde geri gitmez; bu test sözleşmeyi sabitliyor —
    idle_seconds() asla negatif dönmüyor, yani "gelecekte" bir son
    etkileşim damgası sonsuz bir hareketsizlik kredisi üretmiyor.
    """
    t = IdleTracker.from_minutes(5)
    t.record_activity(now=1000.0)
    assert t.idle_seconds(now=500.0) == 0.0
    assert t.should_lock(now=500.0) is False


# ══════════════════════════════════════════════════════════════════════════════
# 2. Etkileşim sayacı sıfırlıyor
# ══════════════════════════════════════════════════════════════════════════════


def test_activity_resets_the_countdown():
    t = IdleTracker.from_minutes(10)
    t.record_activity(now=0.0)

    assert t.should_lock(now=599.0) is False
    t.record_activity(now=599.0)          # kullanıcı son anda fareyi oynattı
    assert t.should_lock(now=600.0) is False
    assert t.should_lock(now=1198.0) is False
    assert t.should_lock(now=1199.0) is True   # 599 + 600


def test_repeated_activity_keeps_the_session_open_indefinitely():
    """Sürekli çalışan bir kullanıcı asla kilitlenmemeli."""
    t = IdleTracker.from_minutes(5)
    now = 0.0
    t.record_activity(now=now)
    for _ in range(50):
        now += 299.0
        assert t.should_lock(now=now) is False
        t.record_activity(now=now)
    assert t.should_lock(now=now + 300.0) is True


def test_activity_after_disarm_does_not_rearm_by_itself():
    """
    Kilit tetiklendikten sonra FARE HAREKETİ oturumu AÇMAMALI.

    Bu, mekanizmanın ekran koruyucudan ayrıldığı nokta: açılış yalnızca
    rearm() ile, yani PIN doğrulandıktan sonra.
    """
    t = IdleTracker.from_minutes(5)
    t.record_activity(now=0.0)
    assert t.should_lock(now=300.0) is True
    t.disarm()

    t.record_activity(now=301.0)
    assert t.armed is False
    assert t.should_lock(now=900.0) is False   # tekrar tetiklenmiyor da


def test_rearm_restores_the_countdown():
    t = IdleTracker.from_minutes(5)
    t.record_activity(now=0.0)
    t.disarm()

    t.rearm(now=1000.0)
    assert t.armed is True
    assert t.should_lock(now=1299.0) is False
    assert t.should_lock(now=1300.0) is True


def test_disarm_prevents_repeated_triggering():
    """Tik saniyede bir çalışıyor — kilit yalnızca BİR kez tetiklenmeli."""
    t = IdleTracker.from_minutes(1)
    t.record_activity(now=0.0)

    tetikleme = 0
    for saniye in range(60, 120):
        if t.should_lock(now=float(saniye)):
            tetikleme += 1
            t.disarm()
    assert tetikleme == 1


# ══════════════════════════════════════════════════════════════════════════════
# 3. Kapalı hâli
# ══════════════════════════════════════════════════════════════════════════════


def test_zero_minutes_disables_the_lock():
    t = IdleTracker.from_minutes(IDLE_DISABLED)
    t.record_activity(now=0.0)
    assert t.disabled is True
    assert t.should_lock(now=10**9) is False
    assert t.remaining_seconds(now=0.0) == float("inf")


def test_reconfigure_switches_the_threshold_and_resets():
    t = IdleTracker.from_minutes(60)
    t.record_activity(now=0.0)
    assert t.should_lock(now=1800.0) is False

    t.reconfigure(5, now=1800.0)
    assert t.should_lock(now=2099.0) is False
    assert t.should_lock(now=2100.0) is True


def test_reconfigure_to_zero_disables_a_running_tracker():
    t = IdleTracker.from_minutes(5)
    t.record_activity(now=0.0)
    t.reconfigure(IDLE_DISABLED, now=0.0)
    assert t.should_lock(now=10**6) is False


def test_timeout_milliseconds_conversion():
    assert timeout_milliseconds(10) == 600_000
    assert timeout_milliseconds(1) == 60_000
    assert timeout_milliseconds(0) == 0
    assert timeout_milliseconds(-5) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 4. Ayar okuma / yazma
# ══════════════════════════════════════════════════════════════════════════════


def test_default_applies_when_nothing_is_configured(db):
    assert get_idle_timeout_minutes(db) == DEFAULT_IDLE_MINUTES


def test_configured_value_round_trips(db):
    set_idle_timeout_minutes(db, 30)
    assert get_idle_timeout_minutes(db) == 30
    assert db.get_setting(IDLE_TIMEOUT_SETTING) == "30"


def test_zero_round_trips_as_disabled(db):
    set_idle_timeout_minutes(db, IDLE_DISABLED)
    assert get_idle_timeout_minutes(db) == IDLE_DISABLED


def test_garbage_setting_falls_back_to_default_not_disabled(db):
    """
    Bozuk ayar kilidi KAPATMAMALI.

    Kapatsaydı, ayarı bozmak güvenlik kontrolünü sessizce devre dışı
    bırakmanın en kolay yolu olurdu.
    """
    db.set_setting(IDLE_TIMEOUT_SETTING, "on dakika")
    assert get_idle_timeout_minutes(db) == DEFAULT_IDLE_MINUTES


@pytest.mark.parametrize("deger", ["-1", "99999", "1441"])
def test_out_of_range_setting_falls_back_to_default(db, deger: str):
    db.set_setting(IDLE_TIMEOUT_SETTING, deger)
    assert get_idle_timeout_minutes(db) == DEFAULT_IDLE_MINUTES


@pytest.mark.parametrize("deger", [-1, 1441, 99999])
def test_setter_rejects_out_of_range_values(db, deger: int):
    with pytest.raises(ValueError):
        set_idle_timeout_minutes(db, deger)


def test_setter_accepts_the_boundaries(db):
    set_idle_timeout_minutes(db, MIN_IDLE_MINUTES)
    assert get_idle_timeout_minutes(db) == MIN_IDLE_MINUTES
    set_idle_timeout_minutes(db, MAX_IDLE_MINUTES)
    assert get_idle_timeout_minutes(db) == MAX_IDLE_MINUTES


def test_every_offered_option_is_accepted_by_the_setter(db):
    """Arayüzdeki her seçenek doğrulamadan geçmeli — combo ile CORE ayrışmasın."""
    for minutes in IDLE_OPTIONS:
        set_idle_timeout_minutes(db, minutes)
        assert get_idle_timeout_minutes(db) == minutes


# ══════════════════════════════════════════════════════════════════════════════
# 5. Denetim kaydı
# ══════════════════════════════════════════════════════════════════════════════


def test_lock_trigger_is_logged(db):
    log_idle_lock(db, idle_seconds=612.4, timeout_minutes=10, hwid="TEST-HWID")

    row = db.fetchone(
        "SELECT action, detail FROM audit_log WHERE action = 'idle_lock_triggered'"
    )
    assert row is not None
    assert "timeout_minutes=10" in row["detail"]
    assert "idle_seconds=612" in row["detail"]
    assert "hwid=TEST-HWID" in row["detail"]


def test_lock_trigger_entry_is_in_the_hash_chain(db):
    onceki = verify_audit_chain(db.conn).checked
    log_idle_lock(db, idle_seconds=600, timeout_minutes=10)

    sonuc = verify_audit_chain(db.conn)
    assert sonuc.ok is True
    assert sonuc.checked == onceki + 1

    hashsiz = db.fetchone(
        "SELECT COUNT(*) AS n FROM audit_log"
        " WHERE action = 'idle_lock_triggered' AND entry_hash IS NULL"
    )["n"]
    assert hashsiz == 0


def test_changing_the_timeout_is_logged_as_a_setting_change(db):
    set_idle_timeout_minutes(db, 15, hwid="TEST-HWID")
    row = db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'setting_changed'"
        " ORDER BY id DESC LIMIT 1"
    )
    assert f"key={IDLE_TIMEOUT_SETTING}" in row["detail"]
    assert "value=15" in row["detail"]


def test_disabling_the_lock_gets_its_own_audit_action(db):
    """
    Kilidi kapatmak, süresini değiştirmekle AYNI ŞEY DEĞİL.

    Ayrı bir action olmasaydı, bir güvenlik kontrolünün devre dışı
    bırakılması sıradan bir ayar değişikliği gibi görünürdü.
    """
    set_idle_timeout_minutes(db, IDLE_DISABLED, hwid="TEST-HWID")

    actions = _actions(db)
    assert "idle_lock_disabled" in actions
    assert "setting_changed" not in actions


def test_reenabling_after_disable_logs_a_setting_change(db):
    set_idle_timeout_minutes(db, IDLE_DISABLED)
    set_idle_timeout_minutes(db, 10)
    actions = _actions(db)
    assert actions.count("idle_lock_disabled") == 1
    assert actions.count("setting_changed") == 1


def test_rejected_value_is_not_written_or_logged(db):
    set_idle_timeout_minutes(db, 10)
    with pytest.raises(ValueError):
        set_idle_timeout_minutes(db, 5000)
    assert get_idle_timeout_minutes(db) == 10
    assert _actions(db).count("setting_changed") == 1
