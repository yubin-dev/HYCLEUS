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
  2 → TOTP sırrı anahtar kasasında

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
CURRENT_SCHEMA_VERSION = SCHEMA_TOTP

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
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if not self.ran:
            return f"migration atlandı (şema v{self.from_version} güncel)"
        return (
            f"şema v{self.from_version} → v{self.to_version}; "
            f"share_2 taşınan={self.share_2_migrated} "
            f"zaten kasada={self.share_2_already_in_keyring}; "
            f"totp taşındı={self.totp_migrated}"
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

    _log.info("Migration tamamlandı: %s", report.summary())
    return report
