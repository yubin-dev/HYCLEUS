"""
HYCLEUS — Sırların anahtar kasasına taşınması (migration)

Eski konumlar (düz metin):
  · share_2      → SQLite usb_tokens.share_2 sütunu
  · TOTP sırrı   → data/totp_secret.json

Yeni konum: işletim sistemi anahtar kasası (bkz. CORE/secret_store.py)

Şema versiyonu
--------------
`PRAGMA user_version` ile takip edilir — SQLite'ın bu iş için ayırdığı alan.
Mevcut kurulumların hepsi 0'dan başlar (db_manager şimdiye kadar versiyon
tutmuyordu, ALTER TABLE'ları try/except ile idare ediyordu).

  0 → hiçbir sır taşınmamış (migration öncesi tüm kurulumlar)
  1 → share_2 anahtar kasasında
  2 → TOTP sırrı anahtar kasasında (HENÜZ global — tek kayıt)
  3 → TOTP sırrı HWID başına (B-059) — bkz. migrate_totp_to_per_hwid()
  4 → vault HMAC imza anahtarı share_2-bazlı (SECURITY.md §4.2) —
      bkz. migrate_vault_hmac()

Her adım tamamlandığında versiyon ayrı ayrı yükseltilir; yarıda kesilen bir
migration yeniden başlatıldığında tamamlanmış adımı tekrarlamaz.

Sıralama (veri kaybına karşı kritik)
------------------------------------
  1. Sırrı eski yerinden OKU
  2. Anahtar kasasına YAZ ve geri okuyup DOĞRULA  ← burada patlarsa eski kopya duruyor
  3. Eski kopyanın üzerine rastgele veri YAZ
  4. Eski kopyayı SİL / boşalt
  5. Kalıntıyı temizle (WAL checkpoint + VACUUM / fsync + unlink)
  6. Şema versiyonunu yükselt

Adım 2 başarılı olmadan 3'e geçilmez. Adımların hepsi idempotenttir: yarıda
kesilirse yeniden çalıştırmak güvenlidir.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from CORE import secret_store
from CORE.paths import data_dir as _data_dir
from CORE.secure_erase import overwrite_text_column, purge_sqlite_residue, shred_file

_log = logging.getLogger("hycleus.migration")

# Şema versiyonları
SCHEMA_SHARE_2 = 1
SCHEMA_TOTP = 2
SCHEMA_TOTP_PER_HWID = 3
SCHEMA_VAULT_HMAC_SHARE2 = 4
CURRENT_SCHEMA_VERSION = SCHEMA_VAULT_HMAC_SHARE2

_TOTP_FILE = _data_dir() / "totp_secret.json"


class MigrationError(RuntimeError):
    """Migration tamamlanamadığında fırlatılır — uygulama açılmamalıdır."""


@dataclass
class MigrationReport:
    """Migration sonucu — çağıran taraf audit log'a yazabilsin diye."""

    ran: bool = False
    from_version: int = 0
    to_version: int = 0
    share_2_migrated: int = 0
    share_2_already_in_keyring: int = 0
    totp_migrated: bool = False
    totp_per_hwid_migrated_to: str | None = None
    vault_hmac_migrated: int = 0
    vault_hmac_already_new: int = 0
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if not self.ran:
            return f"migration atlandı (şema v{self.from_version} güncel)"
        totp_per_hwid = (
            f"devralan_hwid={self.totp_per_hwid_migrated_to}"
            if self.totp_per_hwid_migrated_to
            else "devir yok"
        )
        return (
            f"şema v{self.from_version} → v{self.to_version}; "
            f"share_2 taşınan={self.share_2_migrated} "
            f"zaten kasada={self.share_2_already_in_keyring}; "
            f"totp taşındı={self.totp_migrated}; "
            f"totp-per-hwid: {totp_per_hwid}; "
            f"vault hmac yeniden imzalanan={self.vault_hmac_migrated} "
            f"zaten yeni şema={self.vault_hmac_already_new}"
        )


# ── Şema versiyonu ────────────────────────────────────────────────────────────

def get_schema_version(db: object) -> int:
    """PRAGMA user_version okur."""
    row = db.conn.execute("PRAGMA user_version").fetchone()  # type: ignore[attr-defined]
    return int(row[0]) if row is not None else 0


def set_schema_version(db: object, version: int) -> None:
    """PRAGMA user_version yazar. PRAGMA parametreleştirilemez — int doğrulaması şart."""
    if not isinstance(version, int) or version < 0:
        raise ValueError(f"Şema versiyonu negatif olmayan tam sayı olmalı: {version!r}")
    db.conn.execute(f"PRAGMA user_version = {version:d}")  # type: ignore[attr-defined]
    db.conn.commit()  # type: ignore[attr-defined]


# ── share_2 migration ─────────────────────────────────────────────────────────

def migrate_share_2(db: object, report: MigrationReport) -> None:
    """
    usb_tokens.share_2 sütunundaki tüm payları anahtar kasasına taşır.

    Satır SİLİNMEZ — HWID kaydı (Katman 1), token_id (Katman 3) ve blacklisted
    bayrağı orada durmalıdır. Yalnızca share_2 sütunu temizlenir.
    """
    rows = db.fetchall(  # type: ignore[attr-defined]
        "SELECT hwid, share_2 FROM usb_tokens WHERE share_2 IS NOT NULL AND share_2 != ''"
    )
    if not rows:
        _log.info("share_2 migration: taşınacak kayıt yok")
        return

    touched = False
    for row in rows:
        hwid = row["hwid"]
        db_value = row["share_2"]
        username = secret_store.share_2_username(hwid)

        existing = secret_store.load(username)
        if existing is None:
            # 1-2. Kasaya yaz + geri okuyup doğrula (store() içinde)
            secret_store.store(username, db_value)
            report.share_2_migrated += 1
            _log.info("share_2 kasaya taşındı  hwid=%s", hwid)
        elif existing == db_value:
            # Önceki yarım kalmış migration — kasa zaten doğru, DB kopyası artık
            report.share_2_already_in_keyring += 1
            _log.info("share_2 zaten kasada  hwid=%s", hwid)
        else:
            # Kasadaki değer DB'dekinden farklı: kasa yetkili kaynaktır.
            # DB kopyası bayat düz metin — üzerine yazılıp silinecek, ama
            # sessizce geçilmemeli.
            report.share_2_already_in_keyring += 1
            note = (
                f"UYARI: hwid={hwid} için kasadaki share_2 DB'dekinden farklı; "
                "kasadaki değer korundu, DB kopyası temizlendi."
            )
            report.notes.append(note)
            _log.warning(note)

        # 3-4. Üzerine yaz, sonra boşalt
        overwrite_text_column(
            db.conn,  # type: ignore[attr-defined]
            table="usb_tokens",
            column="share_2",
            where_column="hwid",
            where_value=hwid,
        )
        touched = True

    # 5. Kalıntıyı temizle — VACUUM pahalı, tüm satırlardan sonra bir kez
    if touched:
        purge_sqlite_residue(db.conn)  # type: ignore[attr-defined]


# ── TOTP migration (bir sonraki commit'te devreye girecek) ────────────────────

def migrate_totp_secret(totp_file: Path | None = None) -> str | None:
    """
    data/totp_secret.json içindeki sırrı anahtar kasasına taşır ve dosyayı imha eder.

    Returns:
        Taşınan sır (kasaya yazıldıysa), zaten taşınmışsa/dosya yoksa None
    """
    path = totp_file if totp_file is not None else _TOTP_FILE
    if not path.exists():
        _log.info("TOTP migration: %s yok, taşınacak sır yok", path)
        return None

    try:
        secret = json.loads(path.read_text(encoding="utf-8"))["secret"]
    except Exception as exc:
        raise MigrationError(
            f"TOTP sırrı okunamadı: {path}\n"
            f"Ayrıntı: {type(exc).__name__}: {exc}\n"
            "Dosya bozuksa elle düzeltin; HYCLEUS sırrı kaybetmemek için "
            "dosyayı silmedi."
        ) from exc

    if not isinstance(secret, str) or not secret:
        raise MigrationError(f"TOTP sırrı boş veya metin değil: {path}")

    existing = secret_store.load(secret_store.TOTP_USERNAME)
    if existing is None:
        secret_store.store(secret_store.TOTP_USERNAME, secret)
        _log.info("TOTP sırrı kasaya taşındı")
    elif existing != secret:
        _log.warning(
            "UYARI: kasadaki TOTP sırrı dosyadakinden farklı; kasadaki korundu."
        )

    shred_file(path)
    return secret


# ── TOTP-per-HWID migration (B-059) ────────────────────────────────────────────

def migrate_totp_to_per_hwid(db: object, report: MigrationReport) -> None:
    """
    Paylaşılan/global TOTP sırrını (B-059) HWID başına şemaya taşır.

    B-059'un hatası: `secret_store.TOTP_USERNAME` altında TEK bir global
    kayıt vardı ve TÜM kullanıcılar aynı authenticator kodunu üretiyordu
    — herhangi bir kullanıcı başka birinin 2FA kodunu üretebiliyordu,
    RBAC'ı anlamsızlaştırıyordu.

    Devir kararı: eski global sır sistemdeki EN ESKİ onaylı kullanıcının
    (`SELECT hwid FROM users WHERE status='approved' ORDER BY id LIMIT 1`
    — muhtemelen ilk admin, B-058'in ilk kurulum sihirbazıyla oluşan
    kullanıcı) HWID'ine devrediliyor. Bu kimlik böylece KESİNTİSİZ
    çalışmaya devam ediyor — authenticator uygulamasını yeniden taramasına
    gerek yok. Alternatif (HERKESİ zorla yeniden enrollment'a sokmak,
    yani sırrı kimseye devretmeden silmek) BİLEREK seçilmedi: bu turda
    yeniden-enrollment AKIŞI (arayüz) henüz YOK — yalnızca öneri
    (BACKLOG B-059), bu yüzden TÜM kullanıcıları anında ve geri dönüşsüz
    kilitlemek "sessizce kırıp kullanıcıyı sistem dışında bırakma"
    riskinin en kötü hâli olurdu: hiç kimse (bir admin bile) giremezdi.
    En eski onaylı kullanıcıyı ayrıcalıklı tutmak, en azından BİR kişinin
    (tipik olarak sistemi yöneten kişi) diğerlerinin yeniden enrollment'ını
    ADMIN PANELİNDEN yönetebilmesini sağlıyor.

    DİĞER TÜM onaylı/bekleyen kullanıcılar bu göçten SONRA kendi TOTP
    kaydına sahip DEĞİL — bir sonraki girişlerinde
    `UI/login_dialog.py::_on_login()` "Bu USB için authenticator kaydı
    bulunamadı" mesajını gösterecek (sessizce "kod yanlış" demek yerine).
    Bu SESSİZCE olmuyor: hangi HWID'lerin etkilendiği `report.notes`'a
    yazılıyor, `main.py` bunu hem log'a hem audit_log'a düşürüyor.

    Neden HWID başına, `users.id` başına DEĞİL: `CORE/secret_store.py`'nin
    modül docstring'inde ayrıntılı gerekçe var (özet: `users.hwid` artık
    kısmi UNIQUE — B-060 — yani HWID ve kullanıcı kimliği birebir
    örtüşüyor; HWID, İlk Kurulum sihirbazının QR'ı gösterdiği anda ZATEN
    elde, `user_id` başına saklamak bunu bir tavuk-yumurta sorununa
    çevirirdi).
    """
    eski_sir = secret_store.load(secret_store.TOTP_USERNAME)
    if eski_sir is None:
        _log.info("TOTP-per-hwid migration: taşınacak global sır yok")
        return

    satir = db.fetchone(  # type: ignore[attr-defined]
        "SELECT hwid FROM users WHERE status = 'approved' ORDER BY id LIMIT 1"
    )
    if satir is None or not satir["hwid"]:
        note = (
            "UYARI (B-059): global bir TOTP sırrı vardı ama onaylı hiçbir "
            "kullanıcı yok — sır kimseye devredilemedi, kasadan silindi."
        )
        report.notes.append(note)
        _log.warning(note)
        secret_store.erase(secret_store.TOTP_USERNAME)
        return

    devralan_hwid = str(satir["hwid"])
    secret_store.store_totp_secret_for_hwid(devralan_hwid, eski_sir)
    secret_store.erase(secret_store.TOTP_USERNAME)
    report.totp_per_hwid_migrated_to = devralan_hwid
    _log.info("TOTP sırrı HWID başına devredildi  devralan_hwid=%s", devralan_hwid)

    digerleri = db.fetchall(  # type: ignore[attr-defined]
        "SELECT hwid, username, status FROM users"
        " WHERE hwid IS NOT NULL AND hwid != '' AND hwid != ?",
        (devralan_hwid,),
    )
    if digerleri:
        etkilenen = ", ".join(
            f"{r['username']}({r['status']})" for r in digerleri
        )
        note = (
            "UYARI (B-059): şu kullanıcılar artık KENDİ TOTP kaydına "
            f"sahip değil, yeniden enrollment gerekiyor: {etkilenen}"
        )
        report.notes.append(note)
        _log.warning(note)


# ── Vault HMAC migration (SECURITY.md §4.2) ────────────────────────────────────

def migrate_vault_hmac(db: object, report: MigrationReport) -> None:
    """
    Her kayıtlı USB'nin vault HMAC imzasını share_2-bazlı yeni şemaya taşır.

    Gerçek işi CORE/vault_manager.migrate_vault_hmac_to_share2() yapıyor —
    dosya biçimi bilgisi orada kalsın diye. Bu fonksiyon yalnızca kayıtlı
    HWID'ler üzerinde döner ve sonucu MigrationReport'a toplar.

    PIN GEREKMEZ (bkz. migrate_vault_hmac_to_share2 docstring'i) — bu yüzden
    diğer adımlar gibi uygulama açılırken, girişten önce çalışabiliyor.

    Bozuk/kurcalanmış olduğu için doğrulanamayan bir dosyaya DOKUNULMAZ;
    o karar haftalık bütünlük taramasına bırakılır — burası yalnızca bir
    uyarı notu düşer.

    KeyringUnavailableError kasıtlı olarak burada YAKALANMAZ ve yukarı
    fırlar — registration.py'nin de izlediği kural (bkz. o modülün
    docstring'i): kasa gerçekten erişilemezse migration sessizce "bu HWID'i
    atladım" demek yerine tamamen durmalı, aksi hâlde bir sonraki adım
    (login) share_2'ye zaten güvenemeyecek bir durumda devam ederdi.
    """
    from CORE import vault_manager  # yerel import: döngüsel bağımlılığı önler
    from CORE.secret_store import KeyringUnavailableError

    rows = db.fetchall("SELECT hwid FROM usb_tokens")  # type: ignore[attr-defined]
    if not rows:
        _log.info("vault HMAC migration: kayıtlı USB token yok")
        return

    for row in rows:
        hwid = row["hwid"]
        try:
            sonuc = vault_manager.migrate_vault_hmac_to_share2(hwid)
        except KeyringUnavailableError:
            raise
        except Exception as exc:
            note = (
                f"UYARI: hwid={hwid} vault HMAC migration hata verdi — "
                f"{type(exc).__name__}: {exc}"
            )
            report.notes.append(note)
            _log.warning(note)
            continue

        if sonuc == "migrated":
            report.vault_hmac_migrated += 1
            _log.info("vault HMAC yeni şemaya taşındı  hwid=%s", hwid)
        elif sonuc == "already_new":
            report.vault_hmac_already_new += 1
        elif sonuc == "skipped_unverifiable":
            note = (
                f"UYARI: hwid={hwid} vault HMAC ne yeni ne eski şemayla "
                "doğrulanamadı — dosya bozuk/kurcalanmış olabilir, migration "
                "DOKUNMADI. Bütünlük taraması bunu ayrıca işaretleyecek."
            )
            report.notes.append(note)
            _log.warning(note)
        elif sonuc == "skipped_no_share_2":
            note = (
                f"UYARI: hwid={hwid} için share_2 kasada yok — vault HMAC "
                "migration atlandı; bu HWID zaten açılamaz durumda."
            )
            report.notes.append(note)
            _log.warning(note)
        # "skipped_no_vault": sessiz — eski paylaşılan tek-dosya yoluna
        # düşen ya da dosyası elle silinmiş bir kayıt olabilir, uyarıya değmez.


# ── Giriş noktası ─────────────────────────────────────────────────────────────

def run_migrations(db: object) -> MigrationReport:
    """
    Gerekli migration'ları sırayla çalıştırır.

    Anahtar kasası erişilemezse KeyringUnavailableError fırlatır ve HİÇBİR
    şeye dokunmaz — eski düz metin kopyalar yerinde kalır, uygulama açılmaz.

    Raises:
        KeyringUnavailableError — kasa yoksa/kilitliyse
        MigrationError          — migration yarıda kaldıysa
    """
    report = MigrationReport()
    report.from_version = get_schema_version(db)
    report.to_version = report.from_version

    if report.from_version >= CURRENT_SCHEMA_VERSION:
        _log.debug("Migration gerekmiyor — şema v%d", report.from_version)
        return report

    # Kasa çalışmıyorsa hiç başlama
    secret_store.ensure_available()

    report.ran = True

    if report.from_version < SCHEMA_SHARE_2:
        migrate_share_2(db, report)
        set_schema_version(db, SCHEMA_SHARE_2)
        report.to_version = SCHEMA_SHARE_2

    if report.from_version < SCHEMA_TOTP:
        report.totp_migrated = migrate_totp_secret() is not None
        set_schema_version(db, SCHEMA_TOTP)
        report.to_version = SCHEMA_TOTP

    if report.from_version < SCHEMA_TOTP_PER_HWID:
        migrate_totp_to_per_hwid(db, report)
        set_schema_version(db, SCHEMA_TOTP_PER_HWID)
        report.to_version = SCHEMA_TOTP_PER_HWID

    if report.from_version < SCHEMA_VAULT_HMAC_SHARE2:
        migrate_vault_hmac(db, report)
        set_schema_version(db, SCHEMA_VAULT_HMAC_SHARE2)
        report.to_version = SCHEMA_VAULT_HMAC_SHARE2

    _log.info("Migration tamamlandı: %s", report.summary())
    return report
