import logging
from datetime import datetime, timezone
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None
_INTERVAL_MINUTES = 10

# Saklama süresi gün çözünürlüğünde işler — dakikada bir bakmanın anlamı yok.
# Saatte bir, gün dönümünü makul bir gecikmeyle yakalar.
_SWEEP_INTERVAL_MINUTES = 60


def _purge_expired() -> None:
    """
    Süresi dolmuş Karantina dosyalarını DB'den ve diskten temizler.

    Bu, Karantina'nın 24 saatlik giriş sayacıdır — saklama süresiyle ilgisi
    yoktur. Ama saklama süresi İŞLEYEN bir dosya bu temizliğe yakalanırsa
    sessizce yok olurdu: kullanıcı hiçbir uyarı görmez, hiçbir onay istenmez,
    erken silme koruması hiç devreye girmez. Bu yüzden temizlik, saklama
    süresi altındaki dosyaları ATLAR (bkz. CORE/disposal.py).
    """
    from CORE.disposal import is_retention_protected
    from DB.db_manager import DBManager
    try:
        db = DBManager()
        expired = db.fetchall(
            """
            SELECT id, filename, filepath
            FROM files
            WHERE label = 'Karantina'
              AND expires_at IS NOT NULL
              AND datetime(expires_at) <= datetime('now')
            """
        )
        if not expired:
            return

        purged = 0
        for row in expired:
            if is_retention_protected(db, row["id"]):
                logger.info(
                    "Karantina temizliği atlandı — saklama süresi işliyor (id=%s, %s)",
                    row["id"], row["filename"],
                )
                db.log(
                    "retention_hold",
                    target_type="file",
                    target_id=row["id"],
                    detail=f"filename={row['filename']} karantina temizliginden korundu",
                )
                continue

            # .hcl dosyasını diskten sil
            try:
                hcl = Path(row["filepath"])
                if hcl.exists():
                    hcl.unlink()
            except Exception as exc:
                logger.warning("Dosya silinemedi %s: %s", row["filepath"], exc)

            # DB kaydını sil — quarantine ON DELETE CASCADE ile otomatik silinir
            db.execute("DELETE FROM files WHERE id = ?", (row["id"],))
            db.log(
                "expired_purge",
                target_type="file",
                target_id=row["id"],
                detail=f"filename={row['filename']}",
            )
            purged += 1

        if purged:
            logger.info("%d süresi dolmuş dosya temizlendi.", purged)

    except Exception as exc:
        logger.error("Karantina temizliği başarısız: %s", exc)


def _sweep_retention() -> None:
    """
    Saklama süresi dolmuş dosyaları İmha Odası'na taşır.

    DİSKTEN SİLMEZ — yalnızca taşır ve `expires_at = NULL` bırakır, yani
    dosya orada onay bekler. Gerekçe için CORE/disposal.py docstring'i.
    """
    from CORE.disposal import sweep_retention_expired
    from DB.db_manager import DBManager
    try:
        sweep_retention_expired(DBManager())
    except Exception as exc:
        logger.error("Saklama süresi süpürmesi başarısız: %s", exc)


def start_scheduler() -> None:
    """Arka plan zamanlayıcısını başlatır. Uygulama başlangıcında bir kez çağrılır."""
    global _scheduler
    if _scheduler is not None:
        return

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        _purge_expired,
        trigger="interval",
        minutes=_INTERVAL_MINUTES,
        id="purge_expired",
        next_run_time=datetime.now(timezone.utc),  # başlangıçta hemen bir kez çalışır
        misfire_grace_time=60,
    )
    # Saklama süresi süpürmesi ayrı bir görev: Karantina temizliği bir hata
    # yüzünden düşerse süpürme çalışmaya devam etsin (ve tersi).
    _scheduler.add_job(
        _sweep_retention,
        trigger="interval",
        minutes=_SWEEP_INTERVAL_MINUTES,
        id="sweep_retention",
        next_run_time=datetime.now(timezone.utc),
        misfire_grace_time=300,
    )
    _scheduler.start()
    logger.info(
        "Zamanlayıcı başlatıldı — karantina temizliği %d dk, "
        "saklama süresi süpürmesi %d dk aralıkla.",
        _INTERVAL_MINUTES,
        _SWEEP_INTERVAL_MINUTES,
    )


def stop_scheduler() -> None:
    """Zamanlayıcıyı durdurur. Uygulama kapatılırken çağrılır."""
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Zamanlayıcı durduruldu.")
