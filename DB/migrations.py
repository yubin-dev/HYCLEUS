"""
HYCLEUS — veritabanı şema göçlerinin TEK kayıt defteri

Bugüne kadar şema değişiklikleri `DB/db_manager.py::_apply_schema()` içinde,
sırayla yazılmış `try: ALTER TABLE ... except OperationalError: pass`
blokları olarak yaşıyordu. Çalışıyordu — ama üç şeyi söyleyemiyordu:

  1. **Kaç göç var ve hangileri.** Yanıt yalnızca 200 satırlık bir
     fonksiyonu okuyarak bulunabiliyordu.
  2. **Bir veritabanına hangileri uygulanmış.** Hiçbir yerde yazmıyordu;
     `except: pass` deseni "zaten vardı" ile "az önce ekledim"i ayırt
     etmiyor.
  3. **Bir göç ne zaman ve neden eklendi.** Yalnızca git geçmişinde.

Bu modül üçünü de kayda geçiriyor. `MIGRATIONS` demeti numaralı, sıralı
ve değişmez; `schema_migrations` tablosu hangisinin ne zaman uygulandığını
tutuyor.


BU TUR DAVRANIŞI DEĞİŞTİRMİYOR
-------------------------------
`_apply_schema()` olduğu gibi duruyor ve şemayı hâlâ o kuruyor. Buradaki
1–21 numaralı göçler, onun YAPTIĞI işin kaydı — üretimde yeniden
ÇALIŞTIRILMIYORLAR, `TEMEL_SURUM`'a kadar "uygulanmış" diye
damgalanıyorlar (`_temeli_damgala`).

Bu bir iddia değil, ÖLÇÜLEN bir eşdeğerlik:
`tests/test_migrations.py::test_kayit_defteri_apply_schema_ile_AYNI_semayi_
uretiyor` boş bir veritabanına yalnızca bu dosyadaki göçleri uygulayıp
`sqlite_master` çıktısını `_apply_schema()`'nınkiyle karşılaştırıyor.
Kayıt yanlışsa test düşer. Yani "belgelendirme" burada yaslanabilir bir
belgelendirme.

22 ve sonrası GERÇEKTEN buradan çalışacak. v3.0'ın TPM ve `.hclx`
maddeleri şema değişikliği getirecek; iskelet onlar için hazır.


⚠️ `PRAGMA user_version` BU DEFTERE AİT DEĞİL
----------------------------------------------
SQLite'ın şema versiyonu için ayırdığı alan `PRAGMA user_version` ve ilk
bakışta doğru yer orası görünüyor. **KULLANILMIYOR, çünkü ZATEN
DOLU:** `CORE/secret_migration.py` onu sırların anahtar kasasına
taşınmasını izlemek için kullanıyor (0 = taşınmadı, 1 = share_2 taşındı,
2 = TOTP taşındı).

Bu deftere `user_version` verilseydi sessiz ve ciddi bir kaza olurdu:
şema göçleri sayacı 21'e çıkarır, `secret_migration` ise
`from_version >= CURRENT_SCHEMA_VERSION` (yani 21 >= 2) görüp
**sır taşımayı tümüyle atlardı.** Sonuç: `usb_tokens.share_2` ve
`data/totp_secret.json` düz metin olarak yerinde kalır ve kimse fark
etmez.

Bu yüzden defter kendi tablosunda: `schema_migrations`. Ayrıca
`tests/test_migrations.py::test_defter_user_version_a_DOKUNMUYOR` bu
sınırı sabitliyor.


ÜÇ AYRI SÜRÜM EKSENİ — birbirine karıştırılmamalı
--------------------------------------------------
Depoda "versiyon" diyen üç bağımsız sayaç var ve üçü farklı şeyi anlatıyor:

| Eksen | Nerede tutuluyor | Neyi anlatıyor |
|---|---|---|
| **Şema göçleri** | `schema_migrations` tablosu (bu dosya) | Veritabanının YAPISI |
| **Sır taşıma** | `PRAGMA user_version` (`CORE/secret_migration.py`) | Sırların NEREDE durduğu |
| **Dosya biçimi** | Dosyanın kendi baytları | Bir `.hcl` dosyasının BİÇİMİ |

Üçüncüsü ikiye ayrılıyor ve ikisi de dosyanın içinde:

  · **Kap sürümü** (`CORE/crypto.py`) — `VERSION_LEGACY = 1`,
    `VERSION_TIMESTAMPED = 2`. Dosyanın 5. baytı.
  · **Fragman sürümü** (`CORE/timestamp.py`) — `TRAILER_VERSION = 1`
    (tekil damga), `TRAILER_VERSION_MERKLE = 2` (toplu damga).

Bunlar veritabanına YAZILMIYOR ve buraya göç olarak eklenemez: her dosya
kendi sürümünü taşıyor, tek bir sayaç bütün dosyaları anlatamaz. Eski
sürümlü dosyalar okunmaya devam ediyor (`_SUPPORTED_VERSIONS`), yani
"göç" diye bir şey de yok — dönüştürme değil, geriye dönük okuma.

`CORE/backup.py::FORMAT` (`"HYCLEUS-BACKUP-V1"`) dördüncü bir eksen ve o
da yedek dizininin manifestosunda duruyor.


YENİ BİR GÖÇ NASIL EKLENİR
---------------------------
1. `MIGRATIONS` demetinin SONUNA bir `Migration` ekleyin. Numara
   kesintisiz artmalı; `test_numaralar_kesintisiz_ve_sirali` bunu
   denetliyor.
2. `uygula` fonksiyonu **idempotent** olmalı: `IF NOT EXISTS` kullanın ya
   da `ALTER TABLE`'ı `sutun_ekle()` ile sarın. Yarıda kesilen bir açılış
   yeniden denenecek.
3. Numarayı ASLA yeniden kullanmayın ve var olan bir göçün `uygula`
   gövdesini DEĞİŞTİRMEYİN — sahadaki veritabanlarında o göç zaten
   uygulanmış olarak damgalı, yeni gövde hiç çalışmaz. Düzeltme
   gerekiyorsa yeni bir numara açın.
4. Geri alma (`down`) BİLEREK YOK. Şifreli bir kasada geri alma, veri
   kaybının en kolay yolu: bir sütunu düşürmek onunla birlikte içeriğini
   de siler ve `.hcl` dosyalarındaki AAD'yi geçersizleştirebilir. Geri
   dönüş yolu yedektir (`CORE/backup.py`), göç değil.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Callable

#: Göç kaydının tutulduğu tablo. `PRAGMA user_version` DEĞİL — gerekçe
#: modül docstring'inde.
LEDGER_TABLE = "schema_migrations"

#: `_apply_schema()`'nın bugün kurduğu şemanın karşılığı olan son göç
#: numarası. Bu numaraya kadar olanlar ÇALIŞTIRILMADAN damgalanıyor;
#: sonrakiler gerçekten uygulanıyor.
#:
#: v3.0 (TPM, .hclx) buradan sonrasını kullanacak.
TEMEL_SURUM = 21

_LEDGER_DDL = f"""
CREATE TABLE IF NOT EXISTS {LEDGER_TABLE} (
    numara      INTEGER PRIMARY KEY,
    ad          TEXT NOT NULL,
    uygulandi   TEXT NOT NULL
                DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    kaynak      TEXT NOT NULL
                CHECK(kaynak IN ('temel', 'gocmen'))
)
"""


@dataclass(frozen=True)
class Migration:
    """Tek bir şema göçü.

    `ad` bir kimlik değil, insan için: kayıt tablosunda numaranın yanında
    duruyor ki bir veritabanına bakan kişi "17 uygulanmış" yerine
    "17 retention-profiles-tablosu uygulanmış" görsün.
    """

    numara: int
    ad: str
    aciklama: str
    uygula: Callable[[sqlite3.Connection], None]


# ── Yardımcılar ───────────────────────────────────────────────────────────────


def sutun_ekle(conn: sqlite3.Connection, tablo: str, tanim: str) -> None:
    """`ALTER TABLE ... ADD COLUMN`, sütun zaten varsa sessizce geçer.

    SQLite'ta `ADD COLUMN IF NOT EXISTS` yok; idempotentlik ancak hatayı
    yutarak sağlanıyor. `_apply_schema()`'daki desenin aynısı, tek bir
    yerde toplanmış hâli.

    Yalnızca `OperationalError` yutuluyor ve mesajı KONTROL EDİLİYOR:
    çıplak `except OperationalError: pass`, "tablo yok" ya da "sözdizimi
    hatası" gibi gerçek kusurları da yutardı — bir göç sessizce hiçbir şey
    yapmamış olur ve bu ancak aylar sonra fark edilirdi.
    """
    try:
        conn.execute(f"ALTER TABLE {tablo} ADD COLUMN {tanim}")
    except sqlite3.OperationalError as exc:
        if "duplicate column name" not in str(exc).lower():
            raise


# ══════════════════════════════════════════════════════════════════════════════
# Göçler — 1..21 GERİYE DÖNÜK KAYIT
#
# Bu numaralar `_apply_schema()`'nın bugün yaptığı işin sırasını izliyor.
# Üretimde çalıştırılmıyorlar (bkz. modül docstring'i); doğrulukları
# tests/test_migrations.py'deki şema karşılaştırmasıyla ölçülüyor.
# ══════════════════════════════════════════════════════════════════════════════


def _m01_baslangic_semasi(conn: sqlite3.Connection) -> None:
    # `DB/db_manager.py::_SCHEMA` — yedi tablo ve temel indeksler.
    # İçerik oradan İÇE AKTARILIYOR, kopyalanmıyor: iki kopya zamanla
    # ayrışırdı ve hangisinin doğru olduğu belirsizleşirdi.
    from DB.db_manager import _SCHEMA

    conn.executescript(_SCHEMA)


def _m02_files_expires_at(conn: sqlite3.Connection) -> None:
    sutun_ekle(conn, "files", "expires_at TEXT")


def _m03_files_original_sha256(conn: sqlite3.Connection) -> None:
    sutun_ekle(conn, "files", "original_sha256 TEXT")


def _m04_usb_tokens_token_id(conn: sqlite3.Connection) -> None:
    sutun_ekle(conn, "usb_tokens", "token_id TEXT NOT NULL DEFAULT ''")


def _m05_usb_tokens_blacklisted(conn: sqlite3.Connection) -> None:
    sutun_ekle(conn, "usb_tokens", "blacklisted INTEGER NOT NULL DEFAULT 0")


def _m06_users_status(conn: sqlite3.Connection) -> None:
    sutun_ekle(conn, "users", "status TEXT NOT NULL DEFAULT 'approved'")


def _m07_users_hwid(conn: sqlite3.Connection) -> None:
    sutun_ekle(conn, "users", "hwid TEXT")


def _m08_tags_is_private(conn: sqlite3.Connection) -> None:
    sutun_ekle(conn, "tags", "is_private INTEGER NOT NULL DEFAULT 0")


def _m09_users_last_pin_changed(conn: sqlite3.Connection) -> None:
    sutun_ekle(conn, "users", "last_pin_changed TEXT")


def _m10_folders(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS folders (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            parent_id  INTEGER REFERENCES folders(id) ON DELETE CASCADE,
            owner_id   INTEGER REFERENCES users(id)   ON DELETE SET NULL,
            created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id)"
    )


def _m11_files_folder_id(conn: sqlite3.Connection) -> None:
    # ON DELETE SET NULL bilinçli: klasör silinince dosya KAYBOLMAMALI.
    sutun_ekle(
        conn, "files",
        "folder_id INTEGER REFERENCES folders(id) ON DELETE SET NULL",
    )


def _m12_files_aad_metadata(conn: sqlite3.Connection) -> None:
    sutun_ekle(conn, "files", "aad_metadata TEXT")


def _m13_auth_codes(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_codes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
            code       TEXT    NOT NULL,
            expires_at TEXT    NOT NULL,
            used       INTEGER NOT NULL DEFAULT 0,
            created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        )
    """)


def _m14_usb_tokens_recovery_issued_at(conn: sqlite3.Connection) -> None:
    # YALNIZCA ZAMAN DAMGASI; kurtarma parçasının kendisi hiç saklanmıyor.
    sutun_ekle(conn, "usb_tokens", "recovery_issued_at TEXT")


def _m15_login_attempts(conn: sqlite3.Connection) -> None:
    # Sayaç bilerek DB'de: bellekte olsaydı uygulamayı yeniden başlatmak
    # kilidi sıfırlar ve kontrolü bypass edilebilir kılardı.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            hwid         TEXT    PRIMARY KEY,
            fail_count   INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            last_attempt TEXT
        )
    """)


def _m16_settings(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES ('imha_ttl_hours', '24')"
    )


def _m17_retention_profiles(conn: sqlite3.Connection) -> None:
    # duration_value ile duration_unit arasındaki bağ CHECK ile zorlanıyor:
    # "süresiz ama 5 birim" gibi anlamsız bir satır veritabanı seviyesinde
    # temsil edilemez.
    conn.execute("""
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


def _m18_files_retention_alanlari(conn: sqlite3.Connection) -> None:
    # ON DELETE SET NULL bilinçli: profil silinince dosya profilsiz kalır,
    # kaybolmaz.
    sutun_ekle(
        conn, "files",
        "retention_profile_id INTEGER"
        " REFERENCES retention_profiles(id) ON DELETE SET NULL",
    )
    # YALNIZCA start_type 'belge_tarihi'/'olay_tarihi' iken anlamlı.
    sutun_ekle(conn, "files", "retention_start_date TEXT")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_files_retention"
        " ON files(retention_profile_id)"
    )


def _m19_idx_audit_log_target(conn: sqlite3.Connection) -> None:
    # Envanter raporu her dosya için "son işlem" tarihini audit_log'a
    # soruyor; indekssiz sorgu dosya × kayıt kadar tarama demekti.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_log_target"
        " ON audit_log(target_type, target_id)"
    )


def _m20_files_integrity_alanlari(conn: sqlite3.Connection) -> None:
    # NULL = bu dosya HİÇ kontrol edilmedi; 'ok' ile karıştırılmamalı, bu
    # yüzden varsayılan verilmiyor.
    sutun_ekle(conn, "files", "integrity_status TEXT")
    sutun_ekle(conn, "files", "integrity_checked_at TEXT")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_files_integrity"
        " ON files(integrity_status)"
    )


def _m21_audit_log_entry_hash(conn: sqlite3.Connection) -> None:
    # Bu sütun eklenmeden önce yazılmış satırlarda NULL kalır ve zincire
    # DAHİL EDİLMEZ: o kayıtlar yazılırken "önceki hash" yoktu.
    sutun_ekle(conn, "audit_log", "entry_hash TEXT")


#: Numaralı, SIRALI, değişmez göç listesi. Sıra anlamlıdır: 11 numara
#: `folders` tablosuna referans veriyor, yani 10'dan sonra gelmek ZORUNDA.
MIGRATIONS: tuple[Migration, ...] = (
    Migration(1,  "baslangic-semasi",
              "Yedi temel tablo ve indeksleri (users, files, quarantine, "
              "audit_log, usb_tokens, tags, file_tags).",
              _m01_baslangic_semasi),
    Migration(2,  "files-expires-at",
              "İmha Odası geri sayımı için son kullanma tarihi.",
              _m02_files_expires_at),
    Migration(3,  "files-original-sha256",
              "Düz metnin özeti — tekrar tespiti ve bütünlük kontrolü.",
              _m03_files_original_sha256),
    Migration(4,  "usb-tokens-token-id",
              "USB token'ın mantıksal kimliği.",
              _m04_usb_tokens_token_id),
    Migration(5,  "usb-tokens-blacklisted",
              "Kayıp/çalıntı USB'yi engelleme bayrağı.",
              _m05_usb_tokens_blacklisted),
    Migration(6,  "users-status",
              "pending/approved kayıt onay sistemi.",
              _m06_users_status),
    Migration(7,  "users-hwid",
              "Kullanıcıyı USB token'ına bağlayan alan.",
              _m07_users_hwid),
    Migration(8,  "tags-is-private",
              "Mahrem etiket sistemi — yönetici olmayana gizlenen dosyalar.",
              _m08_tags_is_private),
    Migration(9,  "users-last-pin-changed",
              "PIN'in en son ne zaman değiştirildiği.",
              _m09_users_last_pin_changed),
    Migration(10, "folders-tablosu",
              "Hiyerarşik klasör sistemi ve parent indeksi.",
              _m10_folders),
    Migration(11, "files-folder-id",
              "Dosyayı klasöre bağlayan alan. 10'dan SONRA gelmek zorunda.",
              _m11_files_folder_id),
    Migration(12, "files-aad-metadata",
              "Şifrelemede kullanılan AAD'nin JSON kopyası.",
              _m12_files_aad_metadata),
    Migration(13, "auth-codes-tablosu",
              "Geçici 8 haneli yönetici paylaşım kodları.",
              _m13_auth_codes),
    Migration(14, "usb-tokens-recovery-issued-at",
              "Kurtarma parçasının dışa aktarıldığı an. Parçanın KENDİSİ "
              "hiçbir zaman saklanmıyor.",
              _m14_usb_tokens_recovery_issued_at),
    Migration(15, "login-attempts-tablosu",
              "Giriş deneme sınırlaması. Bellekte değil DB'de, çünkü yeniden "
              "başlatmak kilidi sıfırlamamalı.",
              _m15_login_attempts),
    Migration(16, "settings-tablosu",
              "Uygulama ayarları ve imha_ttl_hours varsayılanı.",
              _m16_settings),
    Migration(17, "retention-profiles-tablosu",
              "KVKK saklama süresi profilleri; tutarlılık CHECK ile zorlanıyor.",
              _m17_retention_profiles),
    Migration(18, "files-retention-alanlari",
              "Dosyanın saklama profili, elle girilen başlangıç tarihi ve "
              "profil indeksi. 17'den SONRA gelmek zorunda.",
              _m18_files_retention_alanlari),
    Migration(19, "idx-audit-log-target",
              "Envanter raporunun 'son işlem' sorgusu için hedef indeksi.",
              _m19_idx_audit_log_target),
    Migration(20, "files-integrity-alanlari",
              "Haftalık bütünlük taramasının sonucu ve indeksi. NULL = hiç "
              "kontrol edilmedi, 'ok' değil.",
              _m20_files_integrity_alanlari),
    Migration(21, "audit-log-entry-hash",
              "Denetim kaydı hash zinciri sütunu. Öncesindeki satırlarda "
              "NULL kalır ve zincire dahil edilmez.",
              _m21_audit_log_entry_hash),
    # ── v3.0 buradan devam edecek ──────────────────────────────────────────
    # Migration(22, "tpm-...", "...", _m22_...),
    # Migration(23, "hclx-...", "...", _m23_...),
)


# ── Defter ────────────────────────────────────────────────────────────────────


def defteri_kur(conn: sqlite3.Connection) -> None:
    """`schema_migrations` tablosunu oluşturur (idempotent)."""
    conn.execute(_LEDGER_DDL)


def uygulananlar(conn: sqlite3.Connection) -> set[int]:
    """Bu veritabanına uygulanmış göç numaraları."""
    defteri_kur(conn)
    return {
        int(satir[0])
        for satir in conn.execute(f"SELECT numara FROM {LEDGER_TABLE}")
    }


def bekleyenler(conn: sqlite3.Connection) -> tuple[Migration, ...]:
    """Henüz uygulanmamış göçler, sıralı."""
    olan = uygulananlar(conn)
    return tuple(g for g in MIGRATIONS if g.numara not in olan)


def _damgala(conn: sqlite3.Connection, goc: Migration, kaynak: str) -> None:
    conn.execute(
        f"INSERT OR IGNORE INTO {LEDGER_TABLE} (numara, ad, kaynak)"
        " VALUES (?, ?, ?)",
        (goc.numara, goc.ad, kaynak),
    )


def _temeli_damgala(conn: sqlite3.Connection) -> int:
    """`TEMEL_SURUM`'a kadar olan göçleri ÇALIŞTIRMADAN uygulanmış sayar.

    Çağıran (`_apply_schema()`) bu şemayı az önce kendisi kurdu; onları
    yeniden çalıştırmak boşuna iş olurdu. Daha önemlisi, bu tur için
    verilen söz "davranış değişmeyecek" — göçleri gerçekten koşturmak,
    boot yolunu değiştirmek olurdu.

    Returns:
        Yeni damgalanan göç sayısı. Var olan bir kurulumda ilk açılışta
        21, sonrakilerde 0.
    """
    olan = uygulananlar(conn)
    n = 0
    for goc in MIGRATIONS:
        if goc.numara <= TEMEL_SURUM and goc.numara not in olan:
            _damgala(conn, goc, "temel")
            n += 1
    return n


def senkronize(conn: sqlite3.Connection) -> list[int]:
    """Defteri günceller ve `TEMEL_SURUM` üstündeki bekleyen göçleri uygular.

    `_apply_schema()`'nın sonunda çağrılıyor. Bugün ikinci yarısı BOŞ —
    21 üstünde göç yok — yani davranış değişmiyor. v3.0'da TPM ve `.hclx`
    göçleri buradan çalışacak.

    Her göç KENDİ işleminde: biri düşerse öncekiler kalıcı olur ve
    yeniden çalıştırmak kaldığı yerden devam eder. Hepsini tek işleme
    almak, 22 başarılıyken 23'ün düşmesi hâlinde 22'yi de geri alırdı ve
    bir sonraki açılış aynı yerden yeniden düşerdi.

    Returns:
        Bu çağrıda GERÇEKTEN uygulanan göçlerin numaraları.
    """
    defteri_kur(conn)
    _temeli_damgala(conn)
    conn.commit()

    calisan: list[int] = []
    for goc in bekleyenler(conn):
        goc.uygula(conn)
        _damgala(conn, goc, "gocmen")
        conn.commit()
        calisan.append(goc.numara)
    return calisan


def sifirdan_kur(conn: sqlite3.Connection) -> list[int]:
    """Boş bir bağlantıya BÜTÜN göçleri gerçekten uygular.

    Üretimde KULLANILMIYOR — `_apply_schema()` şemayı kendi kuruyor. Bu
    fonksiyon, kayıt defterinin doğruluğunu ÖLÇMEK için var: testler
    bununla kurulan şemayı `_apply_schema()`'nınkiyle karşılaştırıyor.

    v3.0'da `_apply_schema()` bu listeye devredilirse giriş noktası bu
    olacak; o yüzden şimdiden doğru çalışıyor ve test ediliyor.
    """
    defteri_kur(conn)
    calisan: list[int] = []
    for goc in bekleyenler(conn):
        goc.uygula(conn)
        _damgala(conn, goc, "gocmen")
        calisan.append(goc.numara)
    conn.commit()
    return calisan


def durum(conn: sqlite3.Connection) -> list[tuple[int, str, str, str]]:
    """Defterin okunur dökümü: `(numara, ad, uygulandi, kaynak)`.

    Teşhis için: bir kurulumda hangi göçlerin ne zaman uygulandığını
    görmek, "bu veritabanı hangi sürümden geliyor" sorusunun tek
    yanıtıdır.
    """
    defteri_kur(conn)
    return [
        (int(r[0]), str(r[1]), str(r[2]), str(r[3]))
        for r in conn.execute(
            f"SELECT numara, ad, uygulandi, kaynak FROM {LEDGER_TABLE}"
            " ORDER BY numara"
        )
    ]


__all__ = [
    "LEDGER_TABLE",
    "MIGRATIONS",
    "TEMEL_SURUM",
    "Migration",
    "bekleyenler",
    "defteri_kur",
    "durum",
    "senkronize",
    "sifirdan_kur",
    "sutun_ekle",
    "uygulananlar",
]
