"""
HYCLEUS — Veritabanı Yöneticisi

Şu an düz sqlite3 kullanıyor.
sqlcipher3 geçişi: connect() içindeki iki satırı değiştir (yoruma bakın).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

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

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action      TEXT    NOT NULL,
    target_type TEXT,
    target_id   INTEGER,
    detail      TEXT,
    timestamp   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
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
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
CREATE INDEX IF NOT EXISTS idx_audit_log_user    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_time    ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_file_tags_file    ON file_tags(file_id);
CREATE INDEX IF NOT EXISTS idx_file_tags_tag     ON file_tags(tag_id);
"""


class HWIDMissingError(RuntimeError):
    """USB HWID sağlanmadan veritabanı açılmaya çalışıldığında fırlar."""


class DBManager:
    """Uygulama genelinde tek örnek (singleton) veritabanı yöneticisi."""

    # Sınıf düzeyinde tip bildirimleri — type checker'ların __new__ atamasını görmesi için
    _instance: DBManager | None = None
    _db_path: Path
    _conn: sqlite3.Connection | None
    _hwid: str | None
    _key: bytes | None

    def __new__(cls, db_path: str | Path | None = None) -> DBManager:
        if cls._instance is None:
            obj = super().__new__(cls)
            obj._db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
            obj._conn = None
            obj._hwid = None
            obj._key = None
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
        # Migration: auth_codes — geçici 8 haneli yönetici paylaşım kodları
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_codes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
                code       TEXT    NOT NULL,
                expires_at TEXT    NOT NULL,
                used       INTEGER NOT NULL DEFAULT 0,
                created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            )
        """)
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
        self._conn.commit()

        # Hazır şablonlar yalnızca ilk açılışta yazılır (bkz. CORE/retention.py).
        # Yerel import: DB katmanı CORE'a modül seviyesinde bağlanmasın.
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
    # Yardımcı metotlar
    # ------------------------------------------------------------------

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
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
        self.execute(
            """
            INSERT INTO audit_log (user_id, action, target_type, target_id, detail)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, action, target_type, target_id, detail),
        )

    # ------------------------------------------------------------------
    # Bağlam yöneticisi
    # ------------------------------------------------------------------

    def __enter__(self) -> DBManager:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
