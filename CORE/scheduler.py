import logging
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None
_INTERVAL_MINUTES = 10

# Saklama süresi gün çözünürlüğünde işler — dakikada bir bakmanın anlamı yok.
# Saatte bir, gün dönümünü makul bir gecikmeyle yakalar.
_SWEEP_INTERVAL_MINUTES = 60

# Denetim çıpası günde bir yazılır; saatlik bakmak gün dönümünü makul bir
# gecikmeyle yakalar (bkz. _anchor_audit_chain).
_ANCHOR_INTERVAL_MINUTES = 60

# Bütünlük taraması HAFTALIK çalışır ama tetikleyicisi haftalık DEĞİL:
# görev saatte bir "vakti geldi mi" diye soruyor, kapıyı
# settings.integrity_last_sweep tutuyor. Gerekçe CORE/integrity.py —
# maybe_run_weekly_sweep() docstring'inde: haftalık bir interval/cron
# tetikleyicisi, haftalarca açık kalmayan bir masaüstü uygulamasında
# taramanın hiç çalışmaması demek olurdu.
_INTEGRITY_INTERVAL_MINUTES = 60

# Oturum anahtarını taramaya taşıyan sağlayıcı. Anahtarın KOPYASI burada
# tutulmuyor: start_scheduler() bir çağrılabilir alıyor ve anahtar zaten
# HycleusWindow'da duruyor (bkz. SECURITY.md §3 — bellek). Sağlayıcı None
# dönerse tarama sessizce atlanır.
_key_provider: Callable[[], bytes | None] | None = None
_hwid: str | None = None

# Kapanışta yarıda kalan taramanın temiz durmasını sağlar. stop_scheduler()
# shutdown(wait=False) çağırıyor, yani süren bir tarama daemon thread'iyle
# birlikte yarıda kesilirdi ve özetini hiç yazmazdı.
_stop_event = threading.Event()


def _purge_expired() -> None:
    """
    Süresi dolmuş Karantina dosyalarını DB'den ve diskten temizler.

    Bu, Karantina'nın 24 saatlik giriş sayacıdır — saklama süresiyle ilgisi
    yoktur. Ama saklama süresi İŞLEYEN bir dosya bu temizliğe yakalanırsa
    sessizce yok olurdu: kullanıcı hiçbir uyarı görmez, hiçbir onay istenmez,
    erken silme koruması hiç devreye girmez. Bu yüzden temizlik, saklama
    süresi altındaki dosyaları ATLAR (bkz. CORE/disposal.py).
    """
    from CORE.disposal import purge_expired_file
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

        # Silme mantığı CORE/disposal.py'de ve arayüzün İmha sayacı da AYNI
        # fonksiyonu çağırıyor. İki ayrı uygulama olduğu sürece yalnızca
        # birinde saklama koruması vardı (B-008).
        purged = sum(
            purge_expired_file(
                db, row["id"], source="quarantine_ttl", filepath=row["filepath"]
            )
            for row in expired
        )

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


def _anchor_audit_chain() -> None:
    """
    Denetim zincirinin ucunu günde bir kez veritabanının dışına yazar.

    Açılış ve kapanış çıpaları main.py'de yazılıyor; bu görev günlerce açık
    bırakılan kurulumlar için: uygulama hiç kapanmazsa iki çıpa arasında
    haftalar geçebilirdi ve o aralıkta yapılan bir yeniden yazım
    karşılaştırılacak hiçbir dış referans bulamazdı.

    Zaten bugüne ait bir çıpa varsa hiçbir şey yazılmaz (bkz.
    CORE/audit_chain.py — maybe_write_daily_anchor).
    """
    from CORE.audit_chain import maybe_write_daily_anchor
    from DB.db_manager import DBManager
    try:
        maybe_write_daily_anchor(DBManager())
    except Exception as exc:
        logger.error("Denetim zinciri çıpası yazılamadı: %s", exc)


def _integrity_sweep() -> None:
    """
    Haftalık bütünlük taraması — vakti gelmediyse hiçbir şey yapmaz.

    UI THREAD'İ KULLANILMIYOR ve QThreadPool'a da gerek yok: APScheduler
    zaten GUI dışı bir daemon thread'inde çalışıyor ve bu kod yolu Qt'ye hiç
    dokunmuyor. Gerekçenin tamamı CORE/integrity.py'de; kısaca:

      · İş disk-bağımlı. Dosya okumaları GIL'i bırakıyor, AES yerel kodda
        64 KB'lık kısa parçalar hâlinde çalışıyor; GUI thread'i aç kalmıyor.
      · QThreadPool kullanmak CORE'a Qt bağımlılığı sokardı. CORE şu an
        başsız test edilebiliyor ve bu bilinçli bir kural
        (bkz. CORE/file_records.py docstring'i — aynı dersin bedeli
        ödenmişti).
      · Paralellik de kazandırmazdı: tek diskte eşzamanlı okuma çoğu zaman
        yavaşlatır, üstelik aynı SQLite bağlantısına yazma çekişmesi ekler.
    """
    from CORE.integrity import maybe_run_weekly_sweep
    from DB.db_manager import DBManager

    if _key_provider is None:
        return
    try:
        key = _key_provider()
    except Exception as exc:
        logger.warning("Bütünlük taraması için anahtar alınamadı: %s", exc)
        return
    if not key:
        # DEV_MODE öncesi ya da oturum kapanmış — sessizce atla.
        return

    try:
        report = maybe_run_weekly_sweep(
            DBManager(),
            key,
            hwid=_hwid,
            should_continue=lambda: not _stop_event.is_set(),
        )
        if report is not None and not report.clean:
            logger.warning("%s", report.summary())
    except Exception as exc:
        logger.error("Bütünlük taraması başarısız: %s", exc)


def start_scheduler(
    *,
    key_provider: Callable[[], bytes | None] | None = None,
    hwid: str | None = None,
) -> None:
    """
    Arka plan zamanlayıcısını başlatır. Uygulama başlangıcında bir kez çağrılır.

    Args:
        key_provider: oturum anahtarını döndüren çağrılabilir. Verilmezse
                      bütünlük taraması kayıtlı olur ama her turda anahtarsız
                      olduğu için atlanır. Anahtarın kendisi yerine bir
                      sağlayıcı alınıyor: modül düzeyinde ikinci bir kopya
                      tutmamak için.
        hwid:         verilirse AAD hwid kontrolü ve vault imzası doğrulaması
                      da yapılır.
    """
    global _scheduler, _key_provider, _hwid
    _key_provider = key_provider
    _hwid = hwid
    _stop_event.clear()
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
    # Günlük denetim çıpası. Saatlik tetiklenir ama günde en fazla bir satır
    # yazar — tetikleme sıklığı yalnızca gün dönümünü ne kadar gecikmeyle
    # yakaladığını belirler.
    _scheduler.add_job(
        _anchor_audit_chain,
        trigger="interval",
        minutes=_ANCHOR_INTERVAL_MINUTES,
        id="anchor_audit_chain",
        next_run_time=datetime.now(timezone.utc),
        misfire_grace_time=300,
    )
    # Bütünlük taraması. Saatlik tetikleniyor ama haftada bir kez iş yapıyor
    # (bkz. _INTEGRITY_INTERVAL_MINUTES ve _integrity_sweep).
    #
    # next_run_time BİLEREK verilmedi — diğer görevlerin aksine bu, açılışta
    # HEMEN çalışmamalı: binlerce dosyayı okuyan bir tarama, kullanıcı henüz
    # ana pencereyi görmeden diski meşgul ederdi. İlk tur bir saat sonra.
    _scheduler.add_job(
        _integrity_sweep,
        trigger="interval",
        minutes=_INTEGRITY_INTERVAL_MINUTES,
        id="integrity_sweep",
        misfire_grace_time=600,
    )
    _scheduler.start()
    logger.info(
        "Zamanlayıcı başlatıldı — karantina temizliği %d dk, "
        "saklama süresi süpürmesi %d dk, denetim çıpası %d dk, "
        "bütünlük taraması %d dk aralıkla (haftalık kapıyla).",
        _INTERVAL_MINUTES,
        _SWEEP_INTERVAL_MINUTES,
        _ANCHOR_INTERVAL_MINUTES,
        _INTEGRITY_INTERVAL_MINUTES,
    )


def stop_scheduler() -> None:
    """Zamanlayıcıyı durdurur. Uygulama kapatılırken çağrılır."""
    global _scheduler, _key_provider
    # Önce bayrağı kaldır: süren bir bütünlük taraması bir sonraki dosyaya
    # geçmeden temiz biçimde dursun ve özetini yazabilsin.
    _stop_event.set()
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Zamanlayıcı durduruldu.")
    _key_provider = None
