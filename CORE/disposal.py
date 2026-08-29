"""
HYCLEUS — İmha akışı (saklama süresi ile İmha Odası'nın birleştiği yer)

CORE/retention.py saklama süresinin ne olduğunu tanımlar; bu modül o sürenin
silme işlemleri üzerinde NE YAPTIĞINI tanımlar.

İki senaryo — ve neden birbirine karışmazlar
--------------------------------------------
1. ERKEN SİLME: kullanıcı, saklama süresi HENÜZ DOLMAMIŞ bir dosyayı silmeye
   kalkar. Engellenir (koruma açıksa yönetici onayı, kapalıysa uyarı).
2. SÜRESİ DOLMUŞ SÜPÜRME: saklama süresi DOLMUŞ dosyalar sistem tarafından
   İmha Odası'na taşınır.

Ayrım tek bir soruya dayanıyor ve başka hiçbir şeye bakmıyor:

        destruction_date_for_file(db, file_id) > bugün ?
              EVET → erken (senaryo 1)
              HAYIR → süresi dolmuş (senaryo 2)

Bir dosya aynı anda ikisi birden OLAMAZ, çünkü aynı tarih karşılaştırmasının
iki yanı bunlar. `check_disposal()` bu tarihi BİR KEZ hesaplar ve dallanır;
süre dolmuşsa erken-silme dalına hiç girilmez — yani süpürme sırasında bir
dosyanın "erken silme" kontrolüne takılması mümkün değildir. Süpürme ayrıca
onay parametresi de taşımaz: taşıyabilseydi, kontrolü atlatmanın bir yolu
olurdu. (bkz. tests/test_disposal.py::TestSenaryoAyrimi)

KRİTİK — süresi dolmuş dosya neden expires_at=NULL ile taşınıyor
----------------------------------------------------------------
İmha Odası ONAY KAPISI DEĞİL, SAYAÇTIR. Bir dosya oraya `expires_at = now +
imha_ttl_hours` (varsayılan 24 saat) ile taşınır ve UI'daki sayaç sıfıra
inince dosyayı DİSKTEN KALICI OLARAK SİLER — kimseye bir daha sormadan
(UI/main_window.py::_tick_expiry → _purge_expired_file).

Saklama süresi dolmuş bir dosyayı bu sayaçla taşımak, saklama sistemini
otomatik bir veri imha hattına çevirirdi: süre dolar dolmaz dosya İmha
Odası'na düşer, 24 saat sonra da kimse onaylamadan yok olurdu.

Bu yüzden süpürme `expires_at = NULL` yazar. Mevcut UI bunu zaten destekliyor:
sayaç, expires_at'i olmayan satırı atlıyor ("Süre belirlenmemiş dosyalar").
Dosya İmha Odası'nda SÜRESİZ bekler; diskten kaldırmak için `purge_file()`
çağrılmalıdır ve o da açık onay ister.

Saklama süresi dolmak, dosyanın silinmesi GEREKTİĞİ anlamına gelmez; yalnızca
artık silinmesinin SERBEST olduğu anlamına gelir. Kararı insan verir.

UI bağlantısı (bu adımda değil)
-------------------------------
UI değişikliği sonraki adım. main_window.py bugün silme işlemlerini satır içi
SQL ile yapıyor — CORE tarafında sarmalanacak bir fonksiyon yok. Buradaki
fonksiyonlar o çağrı yerlerinin birebir karşılığı olacak biçimde yazıldı:

    _on_ctx_move_to_imha / _on_ctx_move_label(..., "Imha")  → move_to_imha()
    _purge_expired_file                                     → purge_file()
    scheduler._purge_expired                                → korundu, guard eklendi

Çökmeye dayanıklı KALICI silme (2026-08-29)
--------------------------------------------
`purge_file()`/`purge_expired_file()` bir dosyayı yok ederken iki bağımsız
adım atıyor: diskten `unlink()` ve `files` satırının `DELETE`'i. Süreç TAM
BU İKİSİNİN ARASINDA ölürse (güç kesintisi, kilitlenme, öldürülen süreç),
veritabanı artık diskte olmayan bir dosyayı hâlâ var sanır.

Bu ikisi arasına `disposal_queue` tablosu (DB/migrations.py Migration 25)
girer — bir yazarkasa defteri gibi:

    1. FİİLİ silmeden ÖNCE niyet `disposal_queue`'ya yazılır (`_enqueue()`).
       `db.execute()` her çağrıda kendi COMMIT'ini yapıyor (DB/db_manager.py),
       yani bu satır artık DİSKTE KALICI.
    2. Diskten `unlink()` denenir.
    3. `files` satırı silinir, kuyruk satırı kaldırılır (`_dequeue()`).

Süreç 1-3 arasının HERHANGİ bir noktasında ölse de sonuç aynı: kuyrukta bir
satır kalır. `resume_pending_disposals()` açılışta bu satırları bulur ve
kaldığı yerden bitirir — 2 ve 3'ün HER İKİSİ de idempotent (dosya zaten
silinmişse `exists()` False döner; `files`/kuyruk satırı zaten silinmişse
DELETE etkisiz), yani hangi adımda kesildiği önemli değil, sonuç hep aynı
tutarlı duruma yakınsıyor. Bu, `CORE/safezone.py::purge_orphans()` ile aynı
"normal kapanışta boş kalır, doluysa önceki oturum çökmüştür" deseni
(main.py'de aynı açılış bölümünde, ondan hemen sonra çağrılır).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from CORE.retention import RetentionError, destruction_date_for_file
from CORE.roles import DB_ADMIN

if TYPE_CHECKING:  # pragma: no cover
    from DB.db_manager import DBManager

logger = logging.getLogger(__name__)

LABEL_IMHA = "Imha"

# ──────────────────────────────────────────────────────────────────────────────
# Karar tipleri
# ──────────────────────────────────────────────────────────────────────────────

#: Silinebilir — profil yok ya da saklama süresi dolmuş. Onay gerekmez.
DECISION_ALLOWED = "allowed"

#: Süre dolmamış ama erken silme koruması KAPALI — kullanıcı onayı yeter.
DECISION_NEEDS_WARNING = "needs_warning"

#: Süre dolmamış ve erken silme koruması AÇIK — yönetici onayı şart.
DECISION_NEEDS_ADMIN = "needs_admin"


class EarlyDeletionBlocked(RetentionError):
    """Saklama süresi dolmamış bir dosya, gereken onay olmadan silinmeye çalışıldı."""

    def __init__(self, message: str, check: DisposalCheck) -> None:
        super().__init__(message)
        self.check = check


@dataclass(frozen=True)
class DisposalCheck:
    """
    Bir dosyanın silinip silinemeyeceğinin kararı.

    Attributes:
        decision:         DECISION_* sabitlerinden biri
        destruction_date: hesaplanan imha tarihi (None = süresiz profil ya da
                          profilsiz dosya — ikisi farklı şey, `has_profile`e bak)
        has_profile:      dosya bir saklama profiline bağlı mı
        protected:        profilin erken_silme_koruması açık mı
        reason:           audit log ve UI için insan okunur gerekçe
    """

    decision: str
    destruction_date: date | None
    has_profile: bool
    protected: bool
    reason: str

    @property
    def retention_expired(self) -> bool:
        """Saklama süresi dolmuş mu — senaryo ayrımının tek ölçütü."""
        return self.has_profile and self.decision == DECISION_ALLOWED

    @property
    def needs_approval(self) -> bool:
        return self.decision in (DECISION_NEEDS_WARNING, DECISION_NEEDS_ADMIN)


def _today() -> date:
    """Bugünün UTC tarihi — şemadaki zaman damgaları da UTC."""
    return datetime.now(timezone.utc).date()


# ──────────────────────────────────────────────────────────────────────────────
# Karar
# ──────────────────────────────────────────────────────────────────────────────


def check_disposal(db: DBManager, file_id: int, *, today: date | None = None) -> DisposalCheck:
    """
    Bir dosyanın silinmesi/İmha Odası'na taşınması için ne gerektiğini söyler.

    Hiçbir şey değiştirmez — yalnızca karar döndürür.

    Karar sırası (ilk eşleşen kazanır):
      1. Profil yok           → ALLOWED  (muaf; mevcut davranış aynen sürer)
      2. Süre dolmuş          → ALLOWED  (erken değil — senaryo 2'nin alanı)
      3. Süresiz profil       → erken    (süre HİÇ dolmaz, bkz. aşağıdaki not)
      4. Süre dolmamış        → erken    → koruma açıksa ADMIN, kapalıysa WARNING

    Süresiz profiller hakkında:
        'Süresiz arşiv' profilinin imha tarihi yoktur. "Tarihi yok" ile "tarihi
        geçti" aynı şey DEĞİLDİR: süresi hiç dolmayan bir dosyanın silinmesi her
        zaman erkendir. Bu yüzden süresiz profiller kalıcı olarak koruma
        altındadır ve ancak onayla silinebilir.

    Raises:
        RetentionError: dosya yoksa, ya da elle giriş gereken profilde
                        başlangıç tarihi boşsa (retention.py'den gelir —
                        hesaplanamayan tarihi "süre dolmuş" saymak, dosyayı
                        sessizce silinebilir kılardı).
    """
    row = db.fetchone("SELECT id, retention_profile_id FROM files WHERE id = ?", (file_id,))
    if row is None:
        raise RetentionError(f"Dosya bulunamadı: id={file_id}")

    if row["retention_profile_id"] is None:
        return DisposalCheck(
            decision=DECISION_ALLOWED,
            destruction_date=None,
            has_profile=False,
            protected=False,
            reason="Dosya bir saklama profiline bağlı değil — kontrol uygulanmadı.",
        )

    profile = db.fetchone(
        "SELECT early_delete_protection FROM retention_profiles WHERE id = ?",
        (row["retention_profile_id"],),
    )
    if profile is None:
        raise RetentionError(f"Profil bulunamadı: id={row['retention_profile_id']}")
    protected = bool(profile["early_delete_protection"])

    destruction_date = destruction_date_for_file(db, file_id)
    now = today or _today()

    # ── Senaryo ayrımının tek satırı ──────────────────────────────────────
    # Süre dolmuşsa erken silme dalına HİÇ girilmez; koruma bayrağına da,
    # onaya da bakılmaz. Süresiz profilde tarih yoktur → süre asla dolmaz.
    if destruction_date is not None and destruction_date <= now:
        return DisposalCheck(
            decision=DECISION_ALLOWED,
            destruction_date=destruction_date,
            has_profile=True,
            protected=protected,
            reason=f"Saklama süresi doldu ({destruction_date.isoformat()}).",
        )

    if destruction_date is None:
        detail = "Profil süresiz — saklama süresi hiçbir zaman dolmaz."
    else:
        detail = f"Saklama süresi {destruction_date.isoformat()} tarihine kadar sürüyor."

    if protected:
        return DisposalCheck(
            decision=DECISION_NEEDS_ADMIN,
            destruction_date=destruction_date,
            has_profile=True,
            protected=True,
            reason=f"{detail} Erken silme koruması açık — yönetici onayı gerekli.",
        )
    return DisposalCheck(
        decision=DECISION_NEEDS_WARNING,
        destruction_date=destruction_date,
        has_profile=True,
        protected=False,
        reason=f"{detail} Erken silme koruması kapalı — kullanıcı onayı yeterli.",
    )


def is_admin(db: DBManager, user_id: int | None) -> bool:
    """
    Kullanıcının RBAC'ta Administrator (users.role = 'admin') olup olmadığı.

    Onay, çağıranın gönderdiği bir bayrağa değil VERİTABANINA sorulur: UI'dan
    gelen "bu kullanıcı yönetici" bilgisine güvenmek, koruma kontrolünü
    çağıranın insafına bırakmak olurdu.
    """
    if user_id is None:
        return False
    row = db.fetchone("SELECT role FROM users WHERE id = ?", (user_id,))
    # Sütun değeri CHECK kısıtıyla zaten `admin`/`user`; sabit
    # `CORE.roles`'tan geliyor ki rol adları tek yerde dursun (B-028).
    return row is not None and row["role"] == DB_ADMIN


def _require_approval(
    db: DBManager,
    file_id: int,
    check: DisposalCheck,
    *,
    user_id: int | None,
    user_confirmed: bool,
    approved_by: int | None,
    action: str,
) -> str:
    """
    Karara göre gereken onayı doğrular; eksikse engeller ve audit log'a yazar.

    Returns:
        Audit log detayına eklenecek onay notu ('' = onay gerekmedi).
    """
    if check.decision == DECISION_ALLOWED:
        return ""

    if check.decision == DECISION_NEEDS_ADMIN:
        if not is_admin(db, approved_by):
            db.log(
                "early_disposal_blocked",
                user_id=user_id,
                target_type="file",
                target_id=file_id,
                detail=f"action={action} reason={check.reason} approved_by={approved_by}",
            )
            raise EarlyDeletionBlocked(
                f"Erken silme engellendi. {check.reason} "
                f"Yönetici onayı olmadan bu işlem yapılamaz.",
                check,
            )
        return f"erken silme - yönetici onaylı (approved_by={approved_by})"

    # DECISION_NEEDS_WARNING
    if not user_confirmed:
        db.log(
            "early_disposal_blocked",
            user_id=user_id,
            target_type="file",
            target_id=file_id,
            detail=f"action={action} reason={check.reason} user_confirmed=False",
        )
        raise EarlyDeletionBlocked(
            f"Erken silme onaylanmadı. {check.reason} "
            f"Devam etmek için kullanıcı onayı gerekli.",
            check,
        )
    return "erken silme - kullanici uyarildi ve onayladi"


# ──────────────────────────────────────────────────────────────────────────────
# Çökmeye dayanıklı kuyruk — modül docstring'indeki "yazarkasa defteri"
# ──────────────────────────────────────────────────────────────────────────────


def _enqueue(
    db: DBManager,
    *,
    file_id: int,
    filename: str | None,
    filepath: str | None,
    action: str,
    user_id: int | None,
    source: str | None,
) -> int:
    """Fiziksel silmeden ÖNCE niyeti kalıcı olarak kaydeder; kuyruk id'sini döndürür."""
    cur = db.execute(
        "INSERT INTO disposal_queue"
        " (file_id, filename, filepath, action, user_id, source)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (file_id, filename, filepath, action, user_id, source),
    )
    return int(cur.lastrowid or 0)


def _dequeue(db: DBManager, queue_id: int) -> None:
    """İşlem tamamlandı — kuyruk satırı kaldırılır. Zaten yoksa etkisiz (idempotent)."""
    db.execute("DELETE FROM disposal_queue WHERE id = ?", (queue_id,))


@dataclass(frozen=True)
class DisposalResumeReport:
    """`resume_pending_disposals()`'ın sonucu — `CORE/safezone.py::PurgeReport` ile aynı biçim."""

    resumed: int = 0
    failed: int = 0
    #: Tamamlanan dosyaların adları — denetim/UI için.
    names: list[str] = field(default_factory=list)
    #: (dosya adı, hata) çiftleri.
    errors: list[tuple[str, str]] = field(default_factory=list)

    @property
    def had_pending(self) -> bool:
        return self.resumed > 0 or self.failed > 0

    def summary(self) -> str:
        if not self.had_pending:
            return "İmha kuyruğu temiz — yarım kalan işlem yok."
        parcalar = [f"{self.resumed} işlem tamamlandı"]
        if self.failed:
            parcalar.append(f"{self.failed} işlem TAMAMLANAMADI")
        return "İmha kuyruğu: " + ", ".join(parcalar) + "."


def resume_pending_disposals(db: DBManager) -> DisposalResumeReport:
    """
    Açılış kurtarması — `disposal_queue`'da satır varsa ÖNCEKİ OTURUM çökmüştür.

    Her satır 1-3 adımlarının (modül docstring'i) hangi noktasında kesildiği
    bilinmeden aynı şekilde ele alınır, çünkü ikisi de idempotent:

        1. Diskteki dosya hâlâ duruyorsa silinir (yoksa zaten adım 2
           tamamlanmış demektir, atlanır).
        2. `files` satırı silinir (yoksa zaten etkisiz).
        3. Kuyruk satırı kaldırılır.

    Tek bir satırın hatası (kilitli dosya, vb.) döngüyü DURDURMAZ — kalan
    satırlar yine denenir ve arıza raporda görünür; `CORE/safezone.py::
    purge()`'ün "erken çıkmak silinebilecekleri de bırakırdı" gerekçesiyle
    aynı. `system_write()` ile sarılı: bu açılış zamanı bir sistem işlemi,
    kimsenin arayüz rolü ADINA değil (`sweep_retention_expired()`'daki aynı
    gerekçe) — ayrıca `disposal_queue` de RBAC korumalı bir tablo olduğu
    için sarmalama olmadan `_dequeue()` bile başarısız olurdu.
    """
    rows = db.fetchall("SELECT * FROM disposal_queue ORDER BY id")
    resumed = 0
    failed = 0
    names: list[str] = []
    errors: list[tuple[str, str]] = []

    for row in rows:
        queue_id = row["id"]
        file_id = row["file_id"]
        filename = row["filename"] or "?"
        filepath = row["filepath"]
        try:
            if filepath:
                try:
                    path = Path(filepath)
                    if path.exists():
                        path.unlink()
                except OSError as exc:
                    logger.warning(
                        "Yarım kalan imha: dosya diskten silinemedi %s: %s", filepath, exc,
                    )

            with db.system_write():
                db.execute("DELETE FROM files WHERE id = ?", (file_id,))
                _dequeue(db, queue_id)

            db.log(
                "disposal_resumed",
                target_type="file",
                target_id=file_id,
                detail=(
                    f"filename={filename} filepath={filepath} action={row['action']}"
                    f" source={row['source']} queue_id={queue_id}"
                ),
            )
            resumed += 1
            names.append(filename)
        except Exception as exc:  # bir satırın hatası kalanları durdurmamalı
            failed += 1
            errors.append((filename, f"{type(exc).__name__}: {exc}"))
            logger.error(
                "Yarım kalan imha tamamlanamadı (queue_id=%s, file_id=%s): %s",
                queue_id, file_id, exc,
            )

    if resumed or failed:
        logger.warning(
            "Açılışta %d yarım kalan imha işlemi bulundu (%d tamamlandı, %d "
            "başarısız) — önceki oturum düzgün kapanmamış olabilir.",
            resumed + failed, resumed, failed,
        )
    return DisposalResumeReport(resumed=resumed, failed=failed, names=names, errors=errors)


# ──────────────────────────────────────────────────────────────────────────────
# Senaryo 1 — kullanıcı kaynaklı silme (erken silme koruması burada uygulanır)
# ──────────────────────────────────────────────────────────────────────────────


def move_to_imha(
    db: DBManager,
    file_id: int,
    *,
    user_id: int | None = None,
    user_confirmed: bool = False,
    approved_by: int | None = None,
    ttl_hours: int | None = None,
    hwid: str | None = None,
) -> DisposalCheck:
    """
    Dosyayı İmha Odası'na taşır — erken silme kontrolünden geçirerek.

    main_window.py'deki `_on_ctx_move_to_imha` / `_on_ctx_move_label(..., 'Imha')`
    işlemlerinin CORE karşılığı. Davranış korundu: label 'Imha' olur ve
    `expires_at` TTL sayacı kurulur (kullanıcı bilerek attıysa sayaç doğrudur).

    Args:
        user_confirmed: koruma KAPALI profillerde kullanıcının uyarıyı onayladığı.
        approved_by:    koruma AÇIK profillerde onaylayan yöneticinin user_id'si.
                        Yöneticilik DB'den doğrulanır.
        ttl_hours:      İmha Odası sayacı; None ise `imha_ttl_hours` ayarı.

    Returns:
        Uygulanan DisposalCheck — çağıran ne olduğunu loglayabilsin diye.

    Raises:
        EarlyDeletionBlocked: gereken onay yoksa (dosyaya DOKUNULMAZ).
        RetentionError:       dosya/profil yoksa ya da tarih hesaplanamıyorsa.
    """
    check = check_disposal(db, file_id)
    note = _require_approval(
        db, file_id, check,
        user_id=user_id, user_confirmed=user_confirmed,
        approved_by=approved_by, action="move_to_imha",
    )

    if ttl_hours is None:
        try:
            ttl_hours = int(db.get_setting("imha_ttl_hours", "24"))
        except ValueError:
            ttl_hours = 24

    expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    db.execute(
        "UPDATE files SET label = ?, expires_at = ? WHERE id = ?",
        (LABEL_IMHA, expires_at, file_id),
    )
    detail = f"hwid={hwid} expires_at={expires_at} decision={check.decision}"
    if note:
        detail = f"{detail} onay={note}"
    db.log(
        "file_moved_to_imha",
        user_id=user_id,
        target_type="file",
        target_id=file_id,
        detail=detail,
    )
    return check


def purge_file(
    db: DBManager,
    file_id: int,
    *,
    user_id: int | None = None,
    user_confirmed: bool = False,
    approved_by: int | None = None,
) -> DisposalCheck:
    """
    Dosyayı diskten ve veritabanından KALICI olarak siler.

    main_window.py'deki `_purge_expired_file` işleminin CORE karşılığı.

    Onay burada BİR KEZ DAHA istenir. İmha Odası'na taşınırken onay alınmış
    olabilir, ama diskten silmek geri alınamaz: taşıma ile silme arasında
    profil değişmiş ya da dosya oraya süpürmeyle düşmüş olabilir. Geri
    alınamayan işlemde kontrolü tekrarlamak ucuz, atlamak pahalıdır.

    Raises:
        EarlyDeletionBlocked: gereken onay yoksa (dosya SİLİNMEZ).
    """
    row = db.fetchone("SELECT filename, filepath FROM files WHERE id = ?", (file_id,))
    if row is None:
        raise RetentionError(f"Dosya bulunamadı: id={file_id}")

    check = check_disposal(db, file_id)
    note = _require_approval(
        db, file_id, check,
        user_id=user_id, user_confirmed=user_confirmed,
        approved_by=approved_by, action="purge_file",
    )

    filepath = row["filepath"]
    queue_id = _enqueue(
        db, file_id=file_id, filename=row["filename"], filepath=filepath,
        action="purge_file", user_id=user_id, source="purge_file",
    )

    if filepath:
        try:
            path = Path(filepath)
            if path.exists():
                path.unlink()
        except OSError as exc:
            logger.warning("Dosya diskten silinemedi %s: %s", filepath, exc)

    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    _dequeue(db, queue_id)
    detail = f"filename={row['filename']} filepath={filepath} decision={check.decision}"
    if note:
        detail = f"{detail} onay={note}"
    db.log(
        "file_purged",
        user_id=user_id,
        target_type="file",
        target_id=file_id,
        detail=detail,
    )
    return check


# ──────────────────────────────────────────────────────────────────────────────
# Senaryo 2 — süresi dolmuş dosyaların süpürülmesi (sistem kaynaklı)
# ──────────────────────────────────────────────────────────────────────────────


def sweep_retention_expired(
    db: DBManager, *, today: date | None = None
) -> list[int]:
    """
    Saklama süresi dolmuş dosyaları İmha Odası'na taşır. DİSKTEN SİLMEZ.

    APScheduler'ın periyodik görevi buradan çağırır (CORE/scheduler.py).

    `expires_at = NULL` yazılır — modül docstring'indeki gerekçeye bakın: TTL
    kurmak, süresi dolan her dosyayı 24 saat sonra onaysız yok ederdi. NULL ile
    dosya İmha Odası'nda süresiz bekler, kaldırmak için purge_file() gerekir.

    Bu fonksiyon ONAY PARAMETRESİ ALMAZ. Alsaydı erken silme kontrolünü
    atlatmanın bir yolu olurdu; sadece süresi DOLMUŞ dosyalara dokunur, o
    dosyalar için de zaten onay gerekmez.

    Returns:
        Taşınan dosya id'leri.
    """
    now = today or _today()
    candidates = db.fetchall(
        "SELECT id FROM files"
        " WHERE retention_profile_id IS NOT NULL AND label <> ?",
        (LABEL_IMHA,),
    )

    moved: list[int] = []
    for row in candidates:
        file_id = row["id"]
        try:
            check = check_disposal(db, file_id, today=now)
        except RetentionError as exc:
            # Tarihi hesaplanamayan dosya (ör. elle giriş gereken profilde
            # başlangıç tarihi boş) ATLANIR. Süresi dolmuş saymak, kullanıcı
            # verisini eksik veriye dayanarak imhaya göndermek olurdu.
            logger.warning("Saklama süresi hesaplanamadı, atlandı (id=%s): %s", file_id, exc)
            continue

        if not check.retention_expired:
            continue  # süresi dolmamış — senaryo 1'in alanı, buraya karışmaz

        # RBAC (DB/db_manager.py) `files` yazılarını rol bazında kısıtlıyor
        # — bu süpürme kimsenin rolü ADINA değil, sistem ADINA çalışıyor
        # (fonksiyon docstring'i: "onay parametresi almaz"), bu yüzden
        # `system_write()` ile rol denetimini bilerek atlıyor.
        with db.system_write():
            db.execute(
                "UPDATE files SET label = ?, expires_at = NULL WHERE id = ?",
                (LABEL_IMHA, file_id),
            )
        db.log(
            "retention_sweep",
            target_type="file",
            target_id=file_id,
            detail=(
                f"imha_tarihi={check.destruction_date} "
                f"expires_at=NULL (otomatik silme YOK, onay bekliyor)"
            ),
        )
        moved.append(file_id)

    if moved:
        logger.info("%d dosyanın saklama süresi doldu, İmha Odası'na taşındı.", len(moved))
    return moved


def purge_expired_file(
    db: DBManager,
    file_id: int,
    *,
    source: str,
    filepath: str | None = None,
) -> bool:
    """
    Süresi dolmuş bir dosyayı otomatik olarak siler — SAKLAMA KORUMASI DAHİL.

    Otomatik temizleyicilerin TEK giriş noktası. İki çağıranı var ve ikisi
    de farklı bir sayacı işletiyor:

        CORE/scheduler.py::_purge_expired   → Karantina'nın 24 saatlik sayacı
        UI/main_window_table.py::_tick_expiry → İmha Odası geri sayımı

    Neden tek fonksiyon
    -------------------
    Bu iki akış daha önce AYRI yazılmıştı ve yalnızca biri saklama
    korumasını uyguluyordu. Sonuç, kullanıcının göremeyeceği bir tutarsızlık
    olmuştu: uygulama KAPALIYKEN saklama süresi işleyen bir dosya korunuyor,
    uygulama AÇIKKEN aynı dosya korumasız siliniyordu (BACKLOG B-008; kök
    nedeni B-004 ile aynı — "aynı iş, iki uygulama, farklı güvenlik").

    `purge_file()` bu işi YAPAMAZDI: o kullanıcı tetiklemeli yol ve onay
    istiyor (`EarlyDeletionBlocked` fırlatıyor). Otomatik bir sayacın
    soracağı kimse yok; doğru davranış sormak değil, ATLAMAK.

    Args:
        source: Hangi sayaç tetikledi — denetim kaydına giriyor. "Bu dosya
            neden silindi" sorusunun yanıtı hangi mekanizmanın çalıştığını
            içermeli.
        filepath: Biliniyorsa diskteki yol. Verilmezse DB'den okunuyor;
            arayüz onu zaten elinde tuttuğu için ikinci bir sorgu gerekmiyor.

    Returns:
        True  — dosya silindi
        False — saklama süresi işlediği için ATLANDI (dosya duruyor)

    İstisna FIRLATMIYOR: iki çağıran da döngü içinde ve tek bir dosyanın
    hatası kalanları durdurmamalı. Hatalar günlüğe yazılıyor.
    """
    if is_retention_protected(db, file_id):
        row = db.fetchone("SELECT filename FROM files WHERE id = ?", (file_id,))
        ad = row["filename"] if row else "?"
        logger.info(
            "Otomatik temizlik atlandı — saklama süresi işliyor (id=%s, %s, %s)",
            file_id, ad, source,
        )
        db.log(
            "retention_hold",
            target_type="file",
            target_id=file_id,
            detail=f"filename={ad} source={source} otomatik temizlikten korundu",
        )
        return False

    row = db.fetchone("SELECT filename, filepath FROM files WHERE id = ?", (file_id,))
    ad = row["filename"] if row else "?"
    yol = filepath or (row["filepath"] if row else None)

    # RBAC (DB/db_manager.py) — bkz. sweep_retention_expired()'daki aynı
    # gerekçe: bu bir sayaç işlemi, kullanıcının rolü ADINA değil. Kuyruk
    # (`disposal_queue`) da korumalı tablolardan, o yüzden enqueue/dequeue
    # de bu sarmalamanın içinde.
    with db.system_write():
        queue_id = _enqueue(
            db, file_id=file_id, filename=ad, filepath=yol,
            action="purge_expired_file", user_id=None, source=source,
        )

    if yol:
        try:
            path = Path(yol)
            if path.exists():
                path.unlink()
        except OSError as exc:
            # Dosya silinemese bile DB kaydı temizleniyor: aksi hâlde satır
            # her turda yeniden denenir ve kullanıcı süresi dolmuş bir
            # dosyayı listede görmeye devam ederdi.
            logger.warning("Dosya diskten silinemedi %s: %s", yol, exc)

    with db.system_write():
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        _dequeue(db, queue_id)
    db.log(
        "expired_purge",
        target_type="file",
        target_id=file_id,
        detail=f"filename={ad} filepath={yol} source={source}",
    )
    return True


def is_retention_protected(db: DBManager, file_id: int, *, today: date | None = None) -> bool:
    """
    Dosya hâlâ saklama süresi altında mı — otomatik temizleyiciler için kısa kontrol.

    scheduler._purge_expired (Karantina TTL temizliği) bunu kullanır: saklama
    süresi işleyen bir dosya, başka bir otomatik mekanizma tarafından
    silinmemelidir.
    """
    try:
        return check_disposal(db, file_id, today=today).needs_approval
    except RetentionError:
        # Hesaplanamıyorsa KORUMALI say — belirsizlikte veri korunur.
        return True
