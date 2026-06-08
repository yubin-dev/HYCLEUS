import logging
from datetime import datetime, timezone
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None
_INTERVAL_MINUTES = 10


def _purge_expired() -> None:
    """Süresi dolmuş Karantina dosyalarını DB'den ve diskten temizler."""
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

        for row in expired:
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

        logger.info("%d süresi dolmuş dosya temizlendi.", len(expired))

    except Exception as exc:
        logger.error("Karantina temizliği başarısız: %s", exc)


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
    _scheduler.start()
    logger.info(
        "Zamanlayıcı başlatıldı — her %d dakikada bir karantina temizlenir.",
        _INTERVAL_MINUTES,
    )


def stop_scheduler() -> None:
    """Zamanlayıcıyı durdurur. Uygulama kapatılırken çağrılır."""
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Zamanlayıcı durduruldu.")
