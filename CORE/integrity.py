"""
HYCLEUS — Bütünlük taraması (integrity sweep)

Haftada bir, kayıtlı her `.hcl` dosyasının GCM doğrulamasını yapar ve
sonucu hem `files` tablosuna hem denetim kaydına yazar. Amaç, bir dosyanın
bozulduğunu KULLANICI ONU AÇMAYA ÇALIŞTIĞINDA değil, ondan önce öğrenmek:
sessiz disk bozulması, yarım kalmış bir kopyalama ya da dosyaya doğrudan
müdahale, aksi hâlde aylar sonra — yedeklerin de dönmüş olabileceği bir
zamanda — ortaya çıkardı.

Ne doğrulanıyor
---------------
· **Her `.hcl` için GCM tag** — `CORE.crypto.verify_file()`. Ciphertext'in
  ya da AAD metadata'sının tek byte'ı değişse doğrulama düşer.
· **Vault dosyasının HMAC'ı** — `CORE.vault_manager.verify_vault()`, tarama
  başına bir kez. `.hcl` dosyalarının AYRI bir HMAC'ı YOKTUR; onlarda
  bütünlüğü GCM tag'i sağlar (bkz. CORE/crypto.py dosya formatı). Sistemdeki
  tek ayrı HMAC vault dosyasınındır ve PIN gerektirmeden doğrulanabildiği
  için taramaya dahil edildi.

Düz metin taranmaz
------------------
Tarama `decrypt_file()` KULLANMAZ. Gerekçe `CORE.crypto.verify_file()`
docstring'inde ayrıntılı: decrypt_file dosyanın tamamını silinemeyen bir
`bytes` nesnesi olarak döndürür, doğrulama için buna gerek yok ve binlerce
dosyada bedeli hem bellek hem maruziyet olarak büyür.

Yanlış anahtara karşı koruma
----------------------------
Yanlış anahtarla yapılan doğrulama, bozuk dosyayla AYNI hatayı verir —
GCM ikisini ayırt edemez. Tarama oturum anahtarını tüm dosyalar için
kullandığından, yanlış bir anahtar TÜM kasayı "bozuk" olarak işaretlerdi.
Bu, yanlış olduğu için işe yaramaz bir uyarıdan da beter olurdu: kullanıcı
her dosyanın bozulduğunu görür, gerçek bir bozulmayı fark edemez hâle
gelirdi.

Bu yüzden tarama, dosyaların TAMAMI tag hatası verirse (ve dosya sayısı
_WRONG_KEY_MIN_FILES'tan fazlaysa) sonucu bozulma saymaz: hiçbir satırı
işaretlemez, `integrity_sweep_aborted` denetim kaydı düşer ve rapor
`suspected_wrong_key` bayrağını taşır. Takas açık — gerçekten her dosyası
bozulmuş bir kasa da bu dala düşer. O durumda da denetim kaydı bir uyarı
bırakıyor, yani olay sessizce geçmiyor; yanlış işaretleme ise geri
alınması zor bir hata olurdu.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from CORE.crypto import AuthenticationError, verify_file
from CORE.scheduled_checks import TS_FORMAT, ZamanKapisi

_log = logging.getLogger("hycleus.integrity")

#: Zaman damgası biçimi. Tek kaynak `CORE/scheduled_checks.py`; buradaki
#: ad geriye dönük uyumluluk için duruyor.
_TS_FORMAT = TS_FORMAT

#: Son başarılı taramanın zamanı — haftalık kapıyı bu belirler.
LAST_SWEEP_SETTING = "integrity_last_sweep"

#: Taramalar arası asgari süre.
SWEEP_INTERVAL_DAYS = 7

#: Haftalık kapı. Desenin tamamı ve neden interval/cron tetikleyicisinin
#: yetmediği `CORE/scheduled_checks.py` docstring'inde.
_SWEEP_KAPISI = ZamanKapisi(
    LAST_SWEEP_SETTING,
    timedelta(days=SWEEP_INTERVAL_DAYS),
    "bütünlük taraması",
)

#: Yanlış anahtar şüphesi için gereken en az dosya sayısı. Bunun altında
#: "hepsi bozuk" gerçekten hepsinin bozuk olması demek olabilir; üç dosyada
#: %100 hata oranı bir örüntü sayılmaz.
_WRONG_KEY_MIN_FILES = 3

#: files.integrity_status güncellemeleri kaç satırda bir yazılsın.
#: db.execute() her çağrıda commit ediyor; binlerce dosyada bu binlerce
#: fsync demek olurdu. Toplu yazma tek transaction kullanıyor, ama tamamını
#: sona bırakmak da yarıda kesilen taramada hiçbir sonucu kaydetmezdi.
_FLUSH_EVERY = 200


class IntegrityStatus(str, Enum):
    """
    Bir dosyanın son bütünlük kontrolünün sonucu.

    `str` türevi: doğrudan SQLite'a yazılabiliyor ve okunan metinle
    karşılaştırılabiliyor, ayrı bir dönüşüm katmanı gerekmiyor.
    """

    #: GCM doğrulaması geçti.
    OK = "ok"
    #: Tag tutmadı — içerik, AAD ya da anahtar uyuşmuyor.
    TAG_MISMATCH = "tag_mismatch"
    #: Kayıt var ama dosya diskte yok.
    MISSING = "missing"
    #: Dosya var, okunamıyor (izin, G/Ç hatası, kilitli).
    UNREADABLE = "unreadable"
    #: Başlık bozuk: magic/versiyon tutmuyor ya da dosya kesilmiş.
    MALFORMED = "malformed"
    #: AAD'daki hwid bu cihaza ait değil — yalnızca hwid verilirse üretilir.
    HWID_MISMATCH = "hwid_mismatch"

    def __str__(self) -> str:
        return self.value


#: Bozulma sayılan durumlar. OK dışındaki her şey değil: HWID uyuşmazlığı
#: bir yetki bulgusudur, dosya sağlam olabilir (bkz. _classify).
CORRUPT_STATUSES = frozenset(
    {
        IntegrityStatus.TAG_MISMATCH,
        IntegrityStatus.MISSING,
        IntegrityStatus.UNREADABLE,
        IntegrityStatus.MALFORMED,
    }
)


@dataclass(frozen=True)
class FileVerdict:
    """Tek bir dosyanın kontrol sonucu."""

    file_id: int
    filename: str
    filepath: str
    status: IntegrityStatus
    reason: str

    @property
    def ok(self) -> bool:
        return self.status is IntegrityStatus.OK

    @property
    def corrupt(self) -> bool:
        return self.status in CORRUPT_STATUSES

    def __str__(self) -> str:
        return f"[{self.status}] {self.filename} — {self.reason}"


@dataclass(frozen=True)
class SweepReport:
    """Bir tarama turunun tamamı."""

    started_at: str
    finished_at: str
    total: int
    checked: int
    ok: int
    corrupt: int
    verdicts: list[FileVerdict] = field(default_factory=list)
    vault_status: str | None = None
    vault_reason: str = ""
    #: Tarama yarıda durduruldu (uygulama kapanıyor).
    aborted: bool = False
    #: Tüm dosyalar tag hatası verdi — anahtar yanlış olabilir, işaretleme
    #: yapılmadı. Bkz. modül docstring'i.
    suspected_wrong_key: bool = False

    @property
    def clean(self) -> bool:
        """Hiç bozuk dosya yok ve vault imzası geçerli."""
        return (
            self.corrupt == 0
            and not self.suspected_wrong_key
            and self.vault_status in (None, "ok")
        )

    def corrupt_verdicts(self) -> list[FileVerdict]:
        return [v for v in self.verdicts if v.corrupt]

    def summary(self) -> str:
        parcalar = [
            f"{self.checked}/{self.total} dosya kontrol edildi",
            f"{self.ok} sağlam",
            f"{self.corrupt} bozuk",
        ]
        if self.vault_status is not None:
            parcalar.append(f"vault imzası: {self.vault_status}")
        if self.aborted:
            parcalar.append("TARAMA YARIDA DURDURULDU")
        if self.suspected_wrong_key:
            parcalar.append(
                "TÜM DOSYALAR TAG HATASI VERDİ — anahtar yanlış olabilir, "
                "hiçbir kayıt bozuk olarak işaretlenmedi"
            )
        bas = "Bütünlük taraması" if not self.clean else "Bütünlük taraması temiz"
        return f"{bas}: " + ", ".join(parcalar) + "."


def _utcnow() -> datetime:
    """Şimdiki UTC zamanı. Testler bunu monkeypatch'ler."""
    return datetime.now(timezone.utc)


def _fmt(dt: datetime) -> str:
    return dt.strftime(_TS_FORMAT)


def _classify(path: Path, key: bytes, *, hwid: str | None) -> tuple[IntegrityStatus, str]:
    """
    Tek dosyayı doğrular ve sonucu sınıflandırır — HİÇBİR ZAMAN fırlatmaz.

    Beklenen her arıza bir duruma çevriliyor; tarama tek bir bozuk dosya
    yüzünden durmamalı. Beklenmeyen istisnalar da UNREADABLE'a düşüyor ve
    gerekçede istisna tipiyle birlikte görünüyor — yutulmuyor, ama taramayı
    da kesmiyor.
    """
    if not path.exists():
        return IntegrityStatus.MISSING, f"dosya diskte yok: {path}"
    try:
        verify_file(path, key, hwid=hwid)
    except AuthenticationError as exc:
        # verify_file HWID uyuşmazlığını da AuthenticationError ile bildiriyor;
        # ikisi ayrı bulgu, mesajdan ayrıştırmak yerine hwid'i tekrar sormak
        # kırılgan olurdu — bu yüzden metin kontrolü tek yerde ve dar tutuldu.
        if hwid is not None and "HWID" in str(exc):
            return IntegrityStatus.HWID_MISMATCH, str(exc)
        return IntegrityStatus.TAG_MISMATCH, str(exc)
    except ValueError as exc:
        return IntegrityStatus.MALFORMED, str(exc)
    except OSError as exc:
        return IntegrityStatus.UNREADABLE, f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # beklenmeyen — taramayı kesme, ama sakla
        _log.exception("Beklenmeyen doğrulama hatası: %s", path)
        return IntegrityStatus.UNREADABLE, f"beklenmeyen hata {type(exc).__name__}: {exc}"
    return IntegrityStatus.OK, ""


def _flush_statuses(db: Any, rows: Sequence[tuple[str, str, int]]) -> None:
    """
    files.integrity_status / integrity_checked_at toplu günceller.

    db.execute() yerine doğrudan bağlantı kullanılıyor: o her çağrıda commit
    ediyor ve binlerce dosyada binlerce fsync anlamına gelirdi.
    """
    if not rows:
        return
    db.conn.executemany(
        "UPDATE files SET integrity_status = ?, integrity_checked_at = ? WHERE id = ?",
        rows,
    )
    db.conn.commit()


def _check_vault(hwid: str | None) -> tuple[str | None, str]:
    """Vault dosyasının HMAC imzasını doğrular. hwid yoksa atlanır."""
    if hwid is None:
        return None, ""
    # Yerel import: vault_manager açılışta ağır iş yapıyor ve integrity'nin
    # testleri onu gerektirmiyor.
    from CORE.vault_manager import VaultTamperedError, verify_vault

    try:
        verify_vault(hwid)
    except FileNotFoundError as exc:
        return "missing", str(exc)
    except VaultTamperedError as exc:
        return "tampered", str(exc)
    except Exception as exc:
        _log.warning("Vault imzası doğrulanamadı: %s", exc)
        return "unreadable", f"{type(exc).__name__}: {exc}"
    return "ok", ""


def sweep_integrity(
    db: Any,
    key: bytes,
    *,
    hwid: str | None = None,
    should_continue: Callable[[], bool] | None = None,
) -> SweepReport:
    """
    Kayıtlı tüm `.hcl` dosyalarını doğrular, sonucu DB'ye ve denetim kaydına yazar.

    Args:
        key:             oturum anahtarı (32 byte).
        hwid:            verilirse AAD'daki hwid de kontrol edilir ve vault
                         imzası doğrulanır.
        should_continue: her dosyadan önce çağrılır; False dönerse tarama
                         temiz biçimde durur ve `aborted=True` raporlanır.
                         Kapanış sırasında yarım kalan taramanın yanıltıcı
                         bir özet yazmasını engeller.

    Denetim kaydına YALNIZCA başlangıç, bitiş ve BOZUK dosyalar yazılır.
    Sağlam dosyaları tek tek yazmak, haftalık taramada binlerce satır demek
    olurdu ve denetim kaydını okunamaz hâle getirirdi; sağlam sonuç zaten
    `files.integrity_status` içinde duruyor.

    Bütün yazmalar `db.log()` üzerinden, yani hash zincirinden geçer
    (bkz. CORE/audit_chain.py).
    """
    if len(key) != 32:
        raise ValueError(f"Anahtar 32 byte olmalı, {len(key)} byte verildi.")

    started = _utcnow()
    rows = db.fetchall("SELECT id, filename, filepath FROM files ORDER BY id")
    total = len(rows)

    db.log("integrity_sweep_started", detail=f"file_count={total}")
    _log.info("Bütünlük taraması başladı — %d dosya", total)

    verdicts: list[FileVerdict] = []
    pending: list[tuple[str, str, int]] = []
    aborted = False
    now_text = _fmt(started)

    for row in rows:
        if should_continue is not None and not should_continue():
            aborted = True
            _log.info("Bütünlük taraması durduruldu — %d/%d", len(verdicts), total)
            break

        status, reason = _classify(Path(row["filepath"]), key, hwid=hwid)
        verdicts.append(
            FileVerdict(
                file_id=int(row["id"]),
                filename=row["filename"] or "",
                filepath=row["filepath"] or "",
                status=status,
                reason=reason,
            )
        )
        pending.append((status.value, now_text, int(row["id"])))
        if len(pending) >= _FLUSH_EVERY:
            _flush_statuses(db, pending)
            pending.clear()

    checked = len(verdicts)
    tag_failures = [v for v in verdicts if v.status is IntegrityStatus.TAG_MISMATCH]
    suspected_wrong_key = (
        checked >= _WRONG_KEY_MIN_FILES and len(tag_failures) == checked
    )

    if suspected_wrong_key:
        # Hiçbir satır işaretlenmiyor — modül docstring'indeki gerekçe.
        pending.clear()
        _log.critical(
            "Bütünlük taraması: %d dosyanın TAMAMI tag hatası verdi — "
            "anahtar yanlış olabilir, işaretleme yapılmadı.", checked,
        )
    else:
        _flush_statuses(db, pending)
        pending.clear()

    vault_status, vault_reason = _check_vault(hwid)

    ok_count = sum(1 for v in verdicts if v.ok)
    corrupt_list = [] if suspected_wrong_key else [v for v in verdicts if v.corrupt]

    for verdict in corrupt_list:
        db.log(
            "integrity_check_failed",
            target_type="file",
            target_id=verdict.file_id,
            detail=(
                f"status={verdict.status} filename={verdict.filename}"
                f" reason={verdict.reason}"
            ),
        )
        _log.warning("Bütünlük hatası  %s", verdict)

    if vault_status not in (None, "ok"):
        db.log(
            "integrity_vault_failed",
            detail=f"status={vault_status} reason={vault_reason}",
        )
        _log.error("Vault imzası doğrulanamadı  status=%s  %s", vault_status, vault_reason)

    finished = _utcnow()
    report = SweepReport(
        started_at=now_text,
        finished_at=_fmt(finished),
        total=total,
        checked=checked,
        ok=ok_count,
        corrupt=len(corrupt_list),
        verdicts=verdicts,
        vault_status=vault_status,
        vault_reason=vault_reason,
        aborted=aborted,
        suspected_wrong_key=suspected_wrong_key,
    )

    if suspected_wrong_key:
        db.log(
            "integrity_sweep_aborted",
            detail=(
                f"checked={checked} all_tag_mismatch=1"
                " reason=anahtar yanlis olabilir, isaretleme yapilmadi"
            ),
        )
    else:
        db.log(
            "integrity_sweep_finished",
            detail=(
                f"total={total} checked={checked} ok={ok_count}"
                f" corrupt={len(corrupt_list)}"
                f" vault={vault_status if vault_status else 'skipped'}"
                f" aborted={int(aborted)}"
                f" duration_seconds={int((finished - started).total_seconds())}"
            ),
        )

    _log.info("%s", report.summary())
    return report


def last_sweep_at(db: Any) -> datetime | None:
    """Son tamamlanmış taramanın zamanı; hiç çalışmadıysa None."""
    return _SWEEP_KAPISI.son_calisma(db)


def sweep_due(db: Any) -> bool:
    """
    Son taramanın üzerinden SWEEP_INTERVAL_DAYS geçtiyse True.

    Saat `_utcnow()` üzerinden AÇIKÇA geçiriliyor: bu modülün testleri onu
    monkeypatch'liyor ve kapı kendi saatini dayatsaydı o yama sessizce
    etkisiz kalırdı.
    """
    return _SWEEP_KAPISI.vakti_geldi_mi(db, simdi=_utcnow())


def maybe_run_weekly_sweep(
    db: Any,
    key: bytes,
    *,
    hwid: str | None = None,
    should_continue: Callable[[], bool] | None = None,
) -> SweepReport | None:
    """
    Haftalık tarama vakti geldiyse çalıştırır, gelmediyse None döner.

    Neden "haftalık interval job" DEĞİL de zaman damgası kapısı
    ------------------------------------------------------------
    APScheduler'ın `interval weeks=1` tetikleyicisi süreç ömrüne göre
    sayar: HYCLEUS masaüstü uygulaması, haftalarca açık kalmıyor. Uygulama
    her gün kapanıp açılsaydı tarama HİÇ çalışmazdı. `cron` tetikleyicisi
    (ör. pazar 03:00) da işe yaramaz — o saatte uygulama büyük ihtimalle
    kapalı.

    Bu yüzden zamanlayıcı sık ama ucuz aralıklarla soruyor, kapıyı
    `settings.integrity_last_sweep` tutuyor. Böylece tarama yeniden
    başlatmayı aşıyor ve uygulama bir hafta sonra ilk açıldığında kısa süre
    içinde çalışıyor. Aynı desen günlük denetim çıpasında da kullanılıyor
    (CORE/audit_chain.py — maybe_write_daily_anchor).

    Zaman damgası yalnızca TAMAMLANAN taramadan sonra yazılır: yarıda
    kesilen ya da yanlış anahtar şüphesiyle duran bir tur haftalık sayacı
    ilerletmez, yoksa bir kez yarıda kalan tarama bir hafta boyunca
    tekrarlanmazdı.
    """
    if not sweep_due(db):
        return None

    report = sweep_integrity(
        db, key, hwid=hwid, should_continue=should_continue
    )

    if not report.aborted and not report.suspected_wrong_key:
        _SWEEP_KAPISI.isaretle(db, zaman=report.finished_at)
    return report
