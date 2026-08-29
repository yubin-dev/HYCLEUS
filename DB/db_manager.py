"""
HYCLEUS — Veritabanı Yöneticisi

Şu an düz sqlite3 kullanıyor.
sqlcipher3 geçişi: connect() içindeki iki satırı değiştir (yoruma bakın).
"""
from __future__ import annotations

import re
import sqlite3
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from CORE.paths import data_dir as _data_dir
_DEFAULT_DB_PATH = _data_dir() / "hycleus.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user'
                          CHECK(role IN ('admin', 'user')),
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    filename        TEXT    NOT NULL,
    filepath        TEXT    NOT NULL UNIQUE,
    label           TEXT    NOT NULL DEFAULT 'Genel'
                            CHECK(label IN ('Genel', 'Kritik', 'Karantina', 'Imha')),
    size_bytes      INTEGER,
    hash_sha256     TEXT,
    original_sha256 TEXT,
    added_by        INTEGER REFERENCES users(id) ON DELETE SET NULL,
    added_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS quarantine (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id         INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    reason          TEXT    NOT NULL,
    quarantined_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    quarantined_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    released_at     TEXT,
    status          TEXT    NOT NULL DEFAULT 'active'
                            CHECK(status IN ('active', 'released', 'destroyed'))
);

-- entry_hash: bkz. CORE/audit_chain.py. NULL = zincir dışı kayıt (zincir
-- başlamadan önce yazılmış ya da append_entry() yerine doğrudan INSERT
-- edilmiş). Zincir kurulumu sonradan geldiği için sütun NULL kabul eder;
-- NOT NULL yapmak eski kayıtları taşınamaz hâle getirirdi.
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action      TEXT    NOT NULL,
    target_type TEXT,
    target_id   INTEGER,
    detail      TEXT,
    timestamp   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    entry_hash  TEXT
);

CREATE TABLE IF NOT EXISTS usb_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    hwid         TEXT    NOT NULL UNIQUE,
    share_2      TEXT    NOT NULL,
    token_id     TEXT    NOT NULL DEFAULT '',
    blacklisted  INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS tags (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    color      TEXT    NOT NULL DEFAULT '#89b4fa',
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS file_tags (
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    tag_id  INTEGER NOT NULL REFERENCES tags(id)  ON DELETE CASCADE,
    PRIMARY KEY (file_id, tag_id)
);

CREATE INDEX IF NOT EXISTS idx_files_label       ON files(label);
-- Tekrar tespiti (CORE/duplicates.py) her yüklemede bu sütunu sorguluyor;
-- indekssiz her dosya için tam tablo taraması olurdu. Kısmi indeks:
-- original_sha256 eski kayıtlarda NULL ve NULL satırlar hiçbir zaman
-- eşleşmiyor, dolayısıyla indekste yer kaplamalarına gerek yok.
CREATE INDEX IF NOT EXISTS idx_files_sha256      ON files(original_sha256)
                                                 WHERE original_sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
CREATE INDEX IF NOT EXISTS idx_audit_log_user    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_time    ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_file_tags_file    ON file_tags(file_id);
CREATE INDEX IF NOT EXISTS idx_file_tags_tag     ON file_tags(tag_id);
"""


class HWIDMissingError(RuntimeError):
    """USB HWID sağlanmadan veritabanı açılmaya çalışıldığında fırlar."""


class YazmaYetkisiYokError(PermissionError):
    """
    Salt Okunur (veya bilinmeyen) rollü bir oturum iş verisi yazmaya
    kalktığında fırlar.

    Neden burada, UI'da değil
    --------------------------
    RBAC (CORE/roles.py, can_write) eskiden YALNIZCA UI'da uygulanıyordu:
    düğmeleri gizlemek/pasifleştirmek (`UI/main_window*.py::
    _apply_role_restrictions`). Bu, düğmeyi hiç görmeyen bir kullanıcıyı
    durdurur ama düğmeyi ATLAYAN hiçbir yolu durdurmaz — CLI, doğrudan bir
    CORE fonksiyon çağrısı, ya da unutulmuş bir kontrol (`UI/TagDialog.py`
    bugün TAM OLARAK bu — `is_readonly_role`'a hiç bakmıyor, yalnızca
    kendini açan düğmenin gizlenmesine güveniyor).

    Bu istisna DBManager.execute()'un kendisinden fırlıyor — yani "her
    yazma fonksiyonu rolü kontrol etmeli" isteği tek bir choke point'te
    karşılanıyor, her CORE/UI çağrı yerine ayrı ayrı dağıtılmıyor.
    """


#: RBAC'ın DB katmanında zorlandığı tablolar — iş verisi. `UI/main_window*.py`
#: bugün bu YÜZEYLERİ zaten düğme gizleyerek kısıtlıyor (dosya ekle/sil,
#: klasör oluştur/sil, etiket oluştur/sil, karantina). Bu küme onların DB
#: karşılığı; ikinci bir liste İCAT EDİLMEDİ.
#:
#: BİLEREK DIŞARIDA BIRAKILANLAR — hepsi ölçülüp doğrulandı:
#:   users            — oturum defteri (CORE/session_user.py::
#:                       sync_session_user); giriş/reauth HER rolde
#:                       çalışmalı, aksi hâlde salt okunur bir kullanıcı
#:                       giriş bile yapamaz.
#:   login_attempts   — hız sınırlama (CORE/rate_limit.py); başarısız PIN
#:                       denemesi rol BELLİ OLMADAN önce de, mevcut oturum
#:                       reddedilirken de çalışmalı.
#:   settings         — karışık bir tablo: `imha_ttl_hours`/`idle_lock_minutes`
#:                       /`app_mode` yalnızca AdminPanel'den (is_admin_role
#:                       ile AYRI bir kapı) yazılıyor, ama
#:                       `CORE/backup_reminder.py::ertele()`/`yedek_alindi()`
#:                       ROLDEN BAĞIMSIZ her kullanıcının tetikleyebileceği
#:                       "Yedek Al…" menüsünden çalışıyor (ÖLÇÜLDÜ:
#:                       UI/main_window.py Görünüm menüsü can_write
#:                       KONTROLÜ YOK). Anahtar bazlı ayrım bu turun
#:                       kapsamı dışında — BACKLOG'a not düşüldü.
#:   audit_log        — zaten DBManager.execute()'u hiç kullanmıyor
#:                       (CORE.audit_chain.append_entry ham conn'a yazıyor);
#:                       zaten bu kontrolün DIŞINDA, ayrıca hariç tutmaya
#:                       gerek yok.
#:   usb_tokens       — kayıt/kurtarma akışının parçası, rol henüz
#:                       oturumla ilişkilenmemişken de yazılabilmeli.
#:
#: Yönetici-vs-Standart ayrımı (ör. yalnızca yöneticinin retention_profiles
#: şablonu değiştirebilmesi) bu kümenin kapsamı DIŞINDA: `can_write()` o
#: ikisini AYIRMIYOR (ikisi de yazabilir), yalnızca Salt Okunur'u dışlıyor.
#: Bu, CORE/session_user.py::oturum_yetkisi_gecerli_mi()'nin kendi
#: docstring'inde işaretlediği türden bilinen bir sınır — bu düzeltmenin
#: kapsamı değil.
_RBAC_KORUMALI_TABLOLAR: frozenset[str] = frozenset({
    "files", "folders", "tags", "file_tags", "quarantine",
    "retention_profiles", "disposal_queue",
})

#: `execute()`'a gelen SQL'in hedef tablosunu çıkarır. Bu depoda `execute()`
#: yalnızca uygulama SQL'i için kullanılıyor (şema/migration ham `conn`
#: üzerinden gidiyor — bkz. _apply_schema), yani biçim sabit ve öngörülebilir.
_YAZMA_HEDEFI_DESENI = re.compile(
    r"^\s*(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM)"
    r"\s+[\"'`\[]?([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)


def _sql_yazma_islemi(sql: str) -> str:
    """SQL'in yazma fiilini döndürür — `rbac_write_rejected` audit detayı için."""
    ust = sql.lstrip().upper()
    for fiil in ("INSERT", "UPDATE", "DELETE", "REPLACE"):
        if ust.startswith(fiil):
            return fiil
    return "?"


class DBManager:
    """Uygulama genelinde tek örnek (singleton) veritabanı yöneticisi."""

    # Sınıf düzeyinde tip bildirimleri — type checker'ların __new__ atamasını görmesi için
    _instance: DBManager | None = None
    _db_path: Path
    _conn: sqlite3.Connection | None
    _hwid: str | None
    _key: bytes | None
    _role: str | None
    _sistem_yazma: threading.local

    def __new__(cls, db_path: str | Path | None = None) -> DBManager:
        if cls._instance is None:
            obj = super().__new__(cls)
            obj._db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
            obj._conn = None
            obj._hwid = None
            obj._key = None
            # Etkileşimli oturumun rolü — `set_active_role()` ile ayarlanır
            # (bkz. UI/main_window.py::_apply_role_restrictions). None =
            # henüz bir oturum bağlanmadı (açılış, göç, testler, arka plan
            # sistem kodu) — bu durumda YAZMA KISITLANMAZ, eski davranış
            # korunur. Rol yalnızca AÇIKÇA ayarlandıktan sonra kısıtlama
            # başlar.
            obj._role = None
            # Sistem yazılarının (ör. otomatik saklama/karantina süpürmesi
            # — CORE/disposal.py) rol denetimini atlaması için iş
            # parçacığı-yerel sayaç. Thread-local OLMASI ZORUNLU:
            # APScheduler arka plan iş parçacığı ve QThreadPool dosya
            # işçileri AYNI DBManager tekil örneğini paylaşıyor; paylaşılan
            # (thread-local OLMAYAN) bir sayaç bir iş parçacığının
            # bypass'ını başka birine SIZDIRIRDI.
            obj._sistem_yazma = threading.local()
            cls._instance = obj
        return cls._instance

    # ------------------------------------------------------------------
    # Bağlantı
    # ------------------------------------------------------------------

    def connect(
        self,
        hwid: str | None,
        key: bytes | None = None,
    ) -> None:
        """
        Veritabanı bağlantısını açar.

        Args:
            hwid: USB seri numarası. None gelirse HWIDMissingError fırlar.
            key:  AES-256 anahtarı (32 byte). sqlcipher3 geçişine hazır;
                  şu an bağlantıda kullanılmıyor, saklanıyor.

        Raises:
            HWIDMissingError: hwid None ise.
            ValueError:       key sağlandı ama 32 byte değilse.
        """
        if self._conn is not None:
            return

        if hwid is None:
            raise HWIDMissingError(
                "USB HWID eksik — veritabanı açılamaz. "
                "Lütfen yetkili USB cihazını takın."
            )

        if key is not None and len(key) != 32:
            raise ValueError(
                f"AES-256 anahtarı 32 byte olmalı, {len(key)} byte verildi."
            )

        self._hwid = hwid
        self._key = key  # sqlcipher3 geçişinde PRAGMA key olarak kullanılacak

        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        # sqlcipher3 geçişi için bu iki satırı değiştir:
        #   import sqlcipher3
        #   self._conn = sqlcipher3.connect(str(self._db_path))
        #   self._conn.execute(f"PRAGMA key=\"x'{self._key.hex()}'\"")
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

        self._apply_schema()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
            self._hwid = None
            self._key = None
            self._role = None
            DBManager._instance = None

    def open(
        self,
        hwid: str | None,
        key: bytes | None = None,
    ) -> DBManager:
        """connect() çağırır ve self döndürür — with bloğu için kullanım kolaylığı.

        Örnek::

            with DBManager().open(hwid=hwid, key=key) as db:
                db.log("startup")
        """
        self.connect(hwid=hwid, key=key)
        return self

    def _apply_schema(self) -> None:
        if self._conn is None:
            raise RuntimeError("_apply_schema çağrıldı ama bağlantı yok.")
        # PRAGMA'lar executescript() dışında çağrılmalı: script önceki transaction'ı
        # commit edip autocommit moduna geçer; bağlantı ayarları ayrı execute ile kalıcı olur
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        # Denetim zinciri yazarken BEGIN IMMEDIATE ile yazma kilidi alınıyor
        # (bkz. CORE/audit_chain.py). Tarama thread'i kendi bağlantısını
        # açtığı için iki yazar çakışabilir; varsayılan 0 ms ile çakışan
        # yazma anında "database is locked" ile düşerdi.
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._conn.executescript(_SCHEMA)
        # Migration: expires_at sonradan eklendi
        try:
            self._conn.execute("ALTER TABLE files ADD COLUMN expires_at TEXT")
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        # Migration: original_sha256 sonradan eklendi
        try:
            self._conn.execute("ALTER TABLE files ADD COLUMN original_sha256 TEXT")
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        # Migration: token_id sonradan eklendi
        try:
            self._conn.execute(
                "ALTER TABLE usb_tokens ADD COLUMN token_id TEXT NOT NULL DEFAULT ''"
            )
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        # Migration: blacklisted sonradan eklendi
        try:
            self._conn.execute(
                "ALTER TABLE usb_tokens ADD COLUMN blacklisted INTEGER NOT NULL DEFAULT 0"
            )
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        # Migration: users.status — pending/approved kayıt onay sistemi
        try:
            self._conn.execute(
                "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'approved'"
            )
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        # Migration: users.hwid — USB token bağlantısı
        try:
            self._conn.execute("ALTER TABLE users ADD COLUMN hwid TEXT")
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        # Migration: tags.is_private — mahrem etiket sistemi
        try:
            self._conn.execute(
                "ALTER TABLE tags ADD COLUMN is_private INTEGER NOT NULL DEFAULT 0"
            )
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        # Migration: users.last_pin_changed — PIN güncelleme tarihi
        try:
            self._conn.execute("ALTER TABLE users ADD COLUMN last_pin_changed TEXT")
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        # Migration: folders — hiyerarşik klasör sistemi
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS folders (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT    NOT NULL,
                parent_id  INTEGER REFERENCES folders(id) ON DELETE CASCADE,
                owner_id   INTEGER REFERENCES users(id)   ON DELETE SET NULL,
                created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            )
        """)
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id)"
        )
        # Migration: files.folder_id — klasöre atama
        try:
            self._conn.execute(
                "ALTER TABLE files ADD COLUMN folder_id INTEGER REFERENCES folders(id) ON DELETE SET NULL"
            )
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        # Migration: files.aad_metadata — şifreleme sırasında kullanılan AAD JSON
        try:
            self._conn.execute("ALTER TABLE files ADD COLUMN aad_metadata TEXT")
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        # auth_codes tablosu B-062 ile KALDIRILDI (bkz. DB/migrations.py
        # Migration 24, `_m24_auth_codes_kaldir`) — bu blok artık BİLEREK
        # burada YOK. `senkronize()`'ın çalıştıracağı 24 numaralı göç, bu
        # tabloyu (13 numaralı tarihsel göç aracılığıyla oluşmuş olabilecek
        # eski kurulumlar dahil) DROP ediyor; burada yeniden YARATMAMAK
        # önemli, yoksa her açılışta oluşup göçle tekrar silinen bir
        # döngüye girerdi.
        # Migration: usb_tokens.recovery_issued_at — Shamir 3. payının (kurtarma
        # parçası) dışa aktarıldığı zaman. YALNIZCA ZAMAN DAMGASI; parçanın
        # kendisi hiçbir zaman saklanmaz (bkz. CORE/recovery_share.py).
        # NULL = henüz kurtarma parçası alınmamış → kullanıcı uyarılır.
        try:
            self._conn.execute(
                "ALTER TABLE usb_tokens ADD COLUMN recovery_issued_at TEXT"
            )
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        # Migration: login_attempts — giriş deneme sınırlama (bkz. CORE/rate_limit.py)
        # Sayaç bilerek DB'de tutulur: bellekte olsaydı uygulamayı yeniden
        # başlatmak kilidi sıfırlar ve kontrolü tamamen bypass edilebilir kılardı.
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                hwid         TEXT    PRIMARY KEY,
                fail_count   INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                last_attempt TEXT
            )
        """)
        # Migration: settings — uygulama ayarları
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        self._conn.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('imha_ttl_hours', '24')"
        )
        # Migration: retention_profiles — saklama süresi profilleri
        # (bkz. CORE/retention.py — sabitler, CRUD ve imha tarihi hesabı orada)
        #
        # duration_value ile duration_unit arasındaki bağ CHECK ile zorlanıyor:
        # 'suresiz' profilin süre değeri OLAMAZ, diğerlerinin ise NULL veya
        # sıfır/negatif olamaz. Böylece "süresiz ama 5 birim" gibi anlamsız bir
        # satır veritabanı seviyesinde temsil edilemez hâle geliyor.
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS retention_profiles (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                name           TEXT    NOT NULL UNIQUE,
                duration_value INTEGER,
                duration_unit  TEXT    NOT NULL
                               CHECK(duration_unit IN ('gun', 'ay', 'yil', 'suresiz')),
                start_type     TEXT    NOT NULL DEFAULT 'yukleme_tarihi'
                               CHECK(start_type IN
                                     ('yukleme_tarihi', 'belge_tarihi', 'olay_tarihi')),
                legal_basis    TEXT,
                early_delete_protection INTEGER NOT NULL DEFAULT 1
                               CHECK(early_delete_protection IN (0, 1)),
                is_builtin     INTEGER NOT NULL DEFAULT 0
                               CHECK(is_builtin IN (0, 1)),
                created_at     TEXT NOT NULL
                               DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                updated_at     TEXT NOT NULL
                               DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                CHECK (
                    (duration_unit =  'suresiz' AND duration_value IS NULL)
                 OR (duration_unit <> 'suresiz' AND duration_value IS NOT NULL
                                                AND duration_value > 0)
                )
            )
        """)
        # Migration: files.retention_profile_id — dosyanın saklama profili.
        # ON DELETE SET NULL bilinçli: profil silinince dosya KAYBOLMAMALI,
        # yalnızca profilsiz kalmalı (added_by ile aynı mantık).
        try:
            self._conn.execute(
                "ALTER TABLE files ADD COLUMN retention_profile_id INTEGER"
                " REFERENCES retention_profiles(id) ON DELETE SET NULL"
            )
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        # Migration: files.retention_start_date — kullanıcının elle girdiği
        # başlangıç tarihi (YYYY-MM-DD). YALNIZCA start_type 'belge_tarihi' veya
        # 'olay_tarihi' iken anlamlıdır; 'yukleme_tarihi' profillerinde NULL
        # kalır ve hesapta files.added_at kullanılır.
        try:
            self._conn.execute("ALTER TABLE files ADD COLUMN retention_start_date TEXT")
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_files_retention"
            " ON files(retention_profile_id)"
        )
        # Migration: audit_log(target_type, target_id) — envanter raporu her
        # dosya için "son işlem" tarihini bu tabloya sorguyor
        # (CORE/inventory.py). İndekssiz sorgu, dosya sayısı × audit kaydı
        # kadar tarama demekti.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_target"
            " ON audit_log(target_type, target_id)"
        )
        # Migration: files.integrity_status / integrity_checked_at —
        # haftalık bütünlük taramasının sonucu (bkz. CORE/integrity.py).
        # NULL = bu dosya HİÇ kontrol edilmedi; 'ok' ile karıştırılmamalı,
        # bu yüzden varsayılan verilmiyor. Değerler IntegrityStatus enum'u.
        try:
            self._conn.execute("ALTER TABLE files ADD COLUMN integrity_status TEXT")
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        try:
            self._conn.execute("ALTER TABLE files ADD COLUMN integrity_checked_at TEXT")
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        # Bozuk dosyaları listelemek "WHERE integrity_status <> 'ok'" ile
        # yapılıyor; indekssiz sorgu tüm dosya tablosunu tarardı.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_files_integrity"
            " ON files(integrity_status)"
        )
        # Migration: audit_log.entry_hash — denetim kaydı hash zinciri
        # (bkz. CORE/audit_chain.py). Bu sütun eklenmeden önce yazılmış
        # satırlarda NULL kalır ve zincire DAHİL EDİLMEZ: o kayıtlar
        # yazılırken "önceki hash" diye bir şey yoktu, geriye dönük
        # hesaplanamaz. Sınır ensure_chain_started()'ın yazdığı genesis
        # kaydıyla açıkça işaretlenir.
        try:
            self._conn.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")
        except sqlite3.OperationalError:
            pass  # kolon zaten var
        self._conn.commit()

        # ── Göç defteri ────────────────────────────────────────────────────
        #
        # Yukarıdaki blokların HEPSİ `DB/migrations.py` içinde numaralı
        # olarak kayıtlı (1..TEMEL_SURUM). `senkronize()` onları YENİDEN
        # ÇALIŞTIRMIYOR — az önce yapıldılar — yalnızca deftere
        # damgalıyor. Yani bu satır bugün davranışı DEĞİŞTİRMİYOR.
        #
        # Değiştirdiği tek şey görünürlük: bundan sonra bir veritabanına
        # bakan kişi hangi göçlerin ne zaman uygulandığını
        # `schema_migrations` tablosundan okuyabiliyor. `except: pass`
        # deseni bunu asla söyleyemiyordu.
        #
        # TEMEL_SURUM üstündeki göçler GERÇEKTEN buradan çalışacak; v3.0'ın
        # TPM ve .hclx maddeleri o numaraları kullanacak.
        #
        # `PRAGMA user_version` bu defter için KULLANILMIYOR: onu
        # CORE/secret_migration.py sır taşıma sayacı olarak tutuyor ve
        # paylaşmak sır taşımanın sessizce atlanmasına yol açardı.
        # Gerekçenin tamamı DB/migrations.py modül docstring'inde.
        from DB.migrations import senkronize

        senkronize(self._conn)

        # Yerel importlar: DB katmanı CORE'a modül seviyesinde bağlanmasın.

        # Zincir başlangıcı — idempotent, yalnızca ilk açılışta genesis yazar.
        # seed_builtin_templates()'ten ÖNCE: genesis, denetim kaydının ilk
        # satırı olsun.
        from CORE.audit_chain import ensure_chain_started

        ensure_chain_started(self._conn)

        # Hazır şablonlar yalnızca ilk açılışta yazılır (bkz. CORE/retention.py).
        from CORE.retention import seed_builtin_templates

        seed_builtin_templates(self)

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError(
                "Veritabanı bağlantısı yok. Önce connect() çağırın."
            )
        return self._conn

    # ------------------------------------------------------------------
    # RBAC — yazma yetkisi (B-0xx: "salt okunur UI'ı atlarsa" bulgusu)
    # ------------------------------------------------------------------

    def set_active_role(self, role: str | None) -> None:
        """
        Etkileşimli oturumun arayüz rolünü ayarlar.

        `UI/main_window.py::_apply_role_restrictions()` bunu çağırıyor —
        girişte, reauth'ta ve `reload_app_mode()`'da; yani rol ne zaman
        BİLİNİR/DEĞİŞİRSE tek yerden. İkinci bir "rolü DB'ye bildir" yolu
        İCAT EDİLMEDİ.

        `None` verilirse kısıtlama TAMAMEN kalkar (bkz. `_role` alanının
        `__new__`'deki gerekçesi) — testler ve açılış/göç kodu bu
        varsayılanla çalışmaya devam eder.
        """
        self._role = role

    @contextmanager
    def system_write(self) -> Iterator[None]:
        """
        Bu blok içindeki yazılar için rol denetimini ASKIYA ALIR.

        YALNIZCA gerçekten "kimseye sormadan" çalışması gereken, önceden
        onaylanmış sistem işlemleri için: `CORE/disposal.py::
        purge_expired_file()` (süresi dolmuş sayaç — hem arka plan
        zamanlayıcısından hem de İmha Odası'nı izleyen kullanıcının UI
        zamanlayıcısından tetiklenir) ve `sweep_retention_expired()`
        (saklama süresi süpürmesi). İkisi de "otomatik temizleyicilerin
        TEK giriş noktası" — bkz. o modülün docstring'i: "otomatik bir
        sayacın soracağı kimse yok; doğru davranış sormak değil, ATLAMAK."

        Rol yerine THREAD-LOCAL bir sayaç kullanılıyor (ambient `_role`
        DEĞİL): APScheduler'ın arka plan iş parçacığı ve QThreadPool dosya
        işçileri aynı tekil DBManager'ı paylaşıyor, yani paylaşılan bir
        bayrak bir iş parçacığının bypass'ını DİĞERİNE sızdırırdı —
        özellikle `_FileRunnable.run()` (dosya EKLEME, QThreadPool
        işçisinde) tam olarak korunması GEREKEN yazının kendisi.
        """
        yerel = self._sistem_yazma
        yerel.derinlik = getattr(yerel, "derinlik", 0) + 1
        try:
            yield
        finally:
            yerel.derinlik -= 1

    def _yazma_yetkisini_dogrula(self, sql: str) -> None:
        if self._role is None:
            return
        if getattr(self._sistem_yazma, "derinlik", 0) > 0:
            return
        eslesme = _YAZMA_HEDEFI_DESENI.match(sql)
        if eslesme is None:
            return
        tablo = eslesme.group(1).lower()
        if tablo not in _RBAC_KORUMALI_TABLOLAR:
            return

        from CORE.roles import can_write

        if can_write(self._role):
            return

        # K1-14: reddi de audit zincirine bağla — `weak_hwid_binding_rejected`
        # (CORE/vault_manager.py) ve `usb_auth_rejected` ile AYNI desen,
        # "reddet ve neden olduğunu kaydet". Bu, depodaki en kritik red
        # (salt okunur bir oturumun iş verisi değiştirmeye kalkması) hiçbir
        # iz bırakmadan sessizce geçmesin diye.
        #
        # Rekürsiyon/sonsuz döngü YOK: `self.log()` `CORE.audit_chain.
        # append_entry()`'ye YÖNLENDİRİYOR ve o `self.execute()`'u hiç
        # GÖRMÜYOR — doğrudan `self.conn` (ham sqlite3.Connection) üzerinde
        # yazıyor. Ayrıca `audit_log` zaten `_RBAC_KORUMALI_TABLOLAR`'IN
        # DIŞINDA. İki AYRI, birbirinden bağımsız garanti — biri
        # değişse bile diğeri tek başına yeterli.
        islem = _sql_yazma_islemi(sql)
        try:
            kare = sys._getframe(2)  # execute()'u ÇAĞIRANIN çerçevesi
            baglam = f"{kare.f_globals.get('__name__', '?')}.{kare.f_code.co_name}:{kare.f_lineno}"
        except ValueError:  # pragma: no cover — yalnızca çerçeve yığını çok sığsa olur
            baglam = "bilinmiyor"
        self.log(
            "rbac_write_rejected",
            detail=f"role={self._role!r} table={tablo} op={islem} caller={baglam}",
        )
        raise YazmaYetkisiYokError(
            f"Rol {self._role!r} '{tablo}' tablosuna yazamaz "
            "(Salt Okunur ya da tanınmayan rol)."
        )

    # ------------------------------------------------------------------
    # Yardımcı metotlar
    # ------------------------------------------------------------------

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        self._yazma_yetkisini_dogrula(sql)
        cur = self.conn.execute(sql, params)
        self.conn.commit()
        return cur

    def fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    # ------------------------------------------------------------------
    # Audit log kolaylığı
    # ------------------------------------------------------------------

    def get_setting(self, key: str, default: str = "") -> str:
        row = self.fetchone("SELECT value FROM settings WHERE key = ?", (key,))
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def log(
        self,
        action: str,
        *,
        user_id: int | None = None,
        target_type: str | None = None,
        target_id: int | None = None,
        detail: str | None = None,
    ) -> None:
        """
        Denetim kaydı yazar — kayıt hash zincirine eklenir.

        Düz INSERT yerine CORE.audit_chain.append_entry() kullanılır: kayıt
        eklenir, veritabanının ürettiği id/timestamp ile birlikte geri
        okunur ve hash'i yazılır; üçü tek transaction içinde. Bu yolu
        atlayan doğrudan bir INSERT hash'siz kalır ve verify_audit_chain()
        tarafından "unhashed" olarak raporlanır.
        """
        from CORE.audit_chain import append_entry

        append_entry(
            self.conn,
            action,
            user_id=user_id,
            target_type=target_type,
            target_id=target_id,
            detail=detail,
        )

    def verify_audit_chain(self):
        """
        Denetim kaydı hash zincirini baştan sona doğrular.

        CORE.audit_chain.verify_audit_chain()'e yönlendirir; ayrıntı ve
        sınırlar için o modülün docstring'ine bakın. Sonuç doğruysa
        truthy'dir, değilse hangi kayıttan itibaren kırıldığını raporlar.
        """
        from CORE.audit_chain import verify_audit_chain as _verify

        return _verify(self.conn)

    # ------------------------------------------------------------------
    # Bağlam yöneticisi
    # ------------------------------------------------------------------

    def __enter__(self) -> DBManager:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
