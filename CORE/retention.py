"""
HYCLEUS — Saklama profilleri (veri modeli + CRUD + imha tarihi hesabı)

Bir *saklama profili*, bir dosyanın ne kadar süre saklanacağını ve bu sürenin
hangi tarihten itibaren işleyeceğini tanımlar. Profil dosyaya bağlanır
(`files.retention_profile_id`), imha tarihi ise SAKLANMAZ — istendiğinde
hesaplanır (bkz. "Neden imha tarihi kolonu yok").

Bu modül YALNIZCA veri modelidir. Silme akışı, UI ve envanter raporu ayrı
adımlardır; burada hiçbir dosya silinmez, hiçbir şey zorlanmaz.

`expires_at` ile karıştırmayın
------------------------------
`files.expires_at` saklama süresiyle İLGİSİZDİR: bir dosya İmha Odası'na
atıldığında kurulan geri-alma süresidir (varsayılan 24 saat, `imha_ttl_hours`)
ve süresi dolunca CORE/scheduler.py dosyayı diskten siler. Saklama süresi ise
tersini söyler — "bu tarihe kadar SİLİNMEMELİ". İki alan asla birbirinin yerine
kullanılmamalıdır.

Neden imha tarihi kolonu yok
----------------------------
İmha tarihi profil + başlangıç tarihinin türevidir. Kolon olarak saklansaydı
profil düzenlendiğinde (ör. 10 yıl → 15 yıl) o profile bağlı tüm dosyaların
kolonu bayatlardı ve toplu güncelleme gerekirdi; unutulan tek satır dosyayı
erken imhaya açardı. Türetilmiş değer türetilmiş kalıyor.

Yasal dayanak metinleri hakkında
--------------------------------
Hazır şablonlardaki `legal_basis` alanları kullanıcı için BAŞLANGIÇ NOKTASIDIR,
hukuki görüş değildir. Şablonlar düzenlenebilir ve silinebilir; kurumun kendi
saklama politikası esastır.
"""
from __future__ import annotations

import calendar
import sqlite3
from datetime import date, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover — yalnızca tip denetimi için
    from DB.db_manager import DBManager

# ──────────────────────────────────────────────────────────────────────────────
# Sabitler
#
# Veritabanına yazılan değerler bilerek ASCII: mevcut şemada da etiketler
# ASCII tutuluyor ('Imha'). Kullanıcıya gösterilecek Türkçe karşılıklar
# UI adımının işi — burada veri değeri var, ekran metni değil.
# ──────────────────────────────────────────────────────────────────────────────

UNIT_DAY = "gun"
UNIT_MONTH = "ay"
UNIT_YEAR = "yil"
UNIT_UNLIMITED = "suresiz"

VALID_UNITS = frozenset({UNIT_DAY, UNIT_MONTH, UNIT_YEAR, UNIT_UNLIMITED})

START_UPLOAD = "yukleme_tarihi"
START_DOCUMENT = "belge_tarihi"
START_EVENT = "olay_tarihi"

VALID_START_TYPES = frozenset({START_UPLOAD, START_DOCUMENT, START_EVENT})

#: Başlangıç tarihini kullanıcının ELLE girmesi gereken tipler.
#: Bu tiplerde `files.retention_start_date` zorunludur; yükleme tarihinden
#: türetilemez, çünkü belgenin/olayın tarihi yükleme tarihinden bağımsızdır.
MANUAL_START_TYPES = frozenset({START_DOCUMENT, START_EVENT})

#: Şablonların bir kez yazıldığını işaretleyen ayar anahtarı.
_SEED_FLAG = "retention_templates_seeded"


class RetentionError(ValueError):
    """Saklama profili doğrulama/işlem hatası."""


class DuplicateProfileNameError(RetentionError):
    """Aynı isimde bir profil zaten var (name UNIQUE)."""


# ──────────────────────────────────────────────────────────────────────────────
# Hazır şablonlar
#
# DB'ye seed olarak yazılır ve SONRASINDA SIRADAN SATIRDIR: kullanıcı
# düzenleyebilir, silebilir. `is_builtin` yalnızca kökeni işaretler; salt-okunur
# anlamına GELMEZ ve CRUD tarafından hiçbir yerde kısıtlama olarak kullanılmaz.
# ──────────────────────────────────────────────────────────────────────────────

BUILTIN_TEMPLATES: tuple[dict[str, Any], ...] = (
    {
        "name": "Geçici belgeler — 30 gün",
        "duration_value": 30,
        "duration_unit": UNIT_DAY,
        "start_type": START_UPLOAD,
        "legal_basis": None,
        # Tek şablon istisnası: bu profilin amacı zaten erken temizlik.
        "early_delete_protection": False,
    },
    {
        "name": "Kısa süreli — 1 yıl",
        "duration_value": 1,
        "duration_unit": UNIT_YEAR,
        "start_type": START_UPLOAD,
        "legal_basis": None,
        "early_delete_protection": True,
    },
    {
        "name": "Orta süreli — 2 yıl",
        "duration_value": 2,
        "duration_unit": UNIT_YEAR,
        "start_type": START_UPLOAD,
        "legal_basis": None,
        "early_delete_protection": True,
    },
    {
        "name": "Vergi belgeleri — 5 yıl",
        "duration_value": 5,
        "duration_unit": UNIT_YEAR,
        # Süre belgenin kendi tarihinden işler, yüklendiği günden değil.
        "start_type": START_DOCUMENT,
        "legal_basis": "VUK m.253 — defter ve belgelerin saklanması",
        "early_delete_protection": True,
    },
    {
        "name": "Mali müşavir — 10 yıl",
        "duration_value": 10,
        "duration_unit": UNIT_YEAR,
        "start_type": START_DOCUMENT,
        "legal_basis": "TTK m.82 — ticari defter ve belgelerin saklanması",
        "early_delete_protection": True,
    },
    {
        # "15-20 yıl" bir ARALIK; tek satır aralık tutamaz. Üst sınır seçildi:
        # saklama süresinde hata payı uzun tarafta olmalı — erken imha geri
        # alınamaz, geç imha alınabilir. Aralık isimde ve dayanakta korunuyor.
        "name": "Uzun süreli saklama — 15-20 yıl",
        "duration_value": 20,
        "duration_unit": UNIT_YEAR,
        # Tipik olarak bir olaydan işler (ör. iş ilişkisinin sona ermesi).
        "start_type": START_EVENT,
        "legal_basis": "Kurum politikası — 15-20 yıl aralığının üst sınırı uygulanır",
        "early_delete_protection": True,
    },
    {
        "name": "Süresiz arşiv",
        "duration_value": None,
        "duration_unit": UNIT_UNLIMITED,
        "start_type": START_UPLOAD,
        "legal_basis": None,
        "early_delete_protection": True,
    },
)


# ──────────────────────────────────────────────────────────────────────────────
# Tarih aritmetiği
# ──────────────────────────────────────────────────────────────────────────────


def parse_date(value: str | date | datetime) -> date:
    """
    Tarih benzeri bir değeri `date`'e çevirir.

    Hem 'YYYY-MM-DD' (kullanıcı girişi, `retention_start_date`) hem de
    'YYYY-MM-DDTHH:MM:SSZ' (şemanın zaman damgası biçimi, `files.added_at`)
    kabul edilir: zaman damgasının yalnızca tarih kısmı alınır. Saklama süresi
    gün çözünürlüğünde işler, saat/dakika anlamsızdır.
    """
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    if not text:
        raise RetentionError("Başlangıç tarihi boş.")
    try:
        return date.fromisoformat(text[:10])
    except ValueError as exc:
        raise RetentionError(f"Tarih çözümlenemedi: {value!r}") from exc


def _add_months(start: date, months: int) -> date:
    """
    Takvim kurallarına göre ay ekler; taşan günü ayın son gününe KIRPAR.

    Kenar durum — 31 Ocak + 1 ay:
        Şubat'ın 31'i yoktur. Kırpma uygulanır → 28 Şubat (artık yılda 29).
        Bu, dateutil.relativedelta ve yaygın hukuki yorumla aynı davranıştır.
        Alternatif (1 Mart'a taşmak) imha tarihini bir gün İLERİ atardı; ay
        sonuna kırpmak da bir gün GERİ almaz — ayın son günü hâlâ o aydır.

    Kırpma kalıcı değildir: her hesap ORİJİNAL başlangıç tarihinden yapılır.
    31 Ocak + 1 ay = 28 Şubat, ama 31 Ocak + 3 ay = 30 Nisan (28 Şubat + 2 ay
    değil). Kırpılmış tarih üzerinden zincirleme ekleme yapılmadığı için gün
    bilgisi aşınmaz.
    """
    total = start.month - 1 + months
    year = start.year + total // 12
    month = total % 12 + 1
    last_day = calendar.monthrange(year, month)[1]
    return date(year, month, min(start.day, last_day))


def add_duration(start: date, duration_value: int | None, duration_unit: str) -> date | None:
    """
    Başlangıç tarihine süre ekler.

    Returns:
        date — hesaplanan tarih
        None — süre 'suresiz' ise (imha tarihi yoktur)
    """
    if duration_unit not in VALID_UNITS:
        raise RetentionError(f"Geçersiz süre birimi: {duration_unit!r}")

    if duration_unit == UNIT_UNLIMITED:
        return None

    if duration_value is None:
        raise RetentionError(f"{duration_unit!r} birimi için süre değeri zorunlu.")

    if duration_unit == UNIT_DAY:
        # Gün eklemede takvim kuralı yok; artık gün timedelta'da zaten doğru.
        return start + timedelta(days=duration_value)
    if duration_unit == UNIT_MONTH:
        return _add_months(start, duration_value)
    # UNIT_YEAR — ay üzerinden gidiyoruz ki 29 Şubat + 1 yıl da kırpılsın
    # (29 Şubat 2024 + 1 yıl → 28 Şubat 2025, çünkü 2025 artık yıl değil).
    return _add_months(start, duration_value * 12)


def compute_destruction_date(profile: Any, start_date: str | date | datetime) -> date | None:
    """
    Profil + başlangıç tarihinden imha tarihini hesaplar.

    Args:
        profile:    `retention_profiles` satırı (sqlite3.Row veya dict) —
                    `duration_value` ve `duration_unit` alanları okunur.
        start_date: Sürenin işlemeye başladığı tarih.

    Returns:
        date — imha edilebileceği tarih
        None — profil süresiz

    Not: dönen tarih, saklama yükümlülüğünün BİTTİĞİ gündür; "bu tarihten önce
    silme" anlamına gelir. Silme akışı ayrı bir adım — bu fonksiyon hiçbir şey
    silmez, yalnızca tarih döndürür.
    """
    return add_duration(
        parse_date(start_date),
        profile["duration_value"],
        profile["duration_unit"],
    )


def resolve_start_date(file_row: Any, profile: Any) -> date:
    """
    Bir dosya için sürenin hangi tarihten işleyeceğini belirler.

    - `yukleme_tarihi` → `files.added_at`
    - `belge_tarihi` / `olay_tarihi` → `files.retention_start_date` (elle girilen)

    Raises:
        RetentionError: elle giriş gerektiren bir tipte `retention_start_date`
                        boşsa. Sessizce yükleme tarihine düşmek YANLIŞ olurdu:
                        2019 tarihli bir belge bugün yüklendiğinde imha tarihi
                        altı yıl ileri kayardı.
    """
    start_type = profile["start_type"]
    if start_type in MANUAL_START_TYPES:
        manual = file_row["retention_start_date"]
        if not manual:
            raise RetentionError(
                f"{start_type!r} profili için başlangıç tarihi elle girilmeli "
                f"(files.retention_start_date boş)."
            )
        return parse_date(manual)
    return parse_date(file_row["added_at"])


def destruction_date_for_file(db: DBManager, file_id: int) -> date | None:
    """
    Bir dosyanın imha tarihini hesaplar.

    Returns:
        date — hesaplanan imha tarihi
        None — dosyanın profili yok, ya da profil süresiz

    Raises:
        RetentionError: dosya bulunamazsa, ya da profil elle giriş gerektirip
                        başlangıç tarihi boşsa.
    """
    row = db.fetchone(
        "SELECT added_at, retention_profile_id, retention_start_date"
        " FROM files WHERE id = ?",
        (file_id,),
    )
    if row is None:
        raise RetentionError(f"Dosya bulunamadı: id={file_id}")
    if row["retention_profile_id"] is None:
        return None

    profile = get_profile(db, row["retention_profile_id"])
    if profile is None:
        # FK ON DELETE SET NULL nedeniyle normalde erişilemez; yine de
        # sessizce yanlış tarih üretmektense açıkça hata verilir.
        raise RetentionError(
            f"Dosyanın profili bulunamadı: profile_id={row['retention_profile_id']}"
        )
    return compute_destruction_date(profile, resolve_start_date(row, profile))


# ──────────────────────────────────────────────────────────────────────────────
# Doğrulama
# ──────────────────────────────────────────────────────────────────────────────


def _validate(
    name: str,
    duration_value: int | None,
    duration_unit: str,
    start_type: str,
) -> None:
    """Şemadaki CHECK'lerin Python tarafındaki karşılığı (anlaşılır mesajlarla)."""
    if not name or not name.strip():
        raise RetentionError("Profil adı boş olamaz.")
    if duration_unit not in VALID_UNITS:
        raise RetentionError(
            f"Geçersiz süre birimi: {duration_unit!r}. "
            f"Geçerli değerler: {', '.join(sorted(VALID_UNITS))}"
        )
    if start_type not in VALID_START_TYPES:
        raise RetentionError(
            f"Geçersiz başlangıç tipi: {start_type!r}. "
            f"Geçerli değerler: {', '.join(sorted(VALID_START_TYPES))}"
        )
    if duration_unit == UNIT_UNLIMITED:
        if duration_value is not None:
            raise RetentionError("'suresiz' profilin süre değeri olamaz.")
    else:
        if duration_value is None:
            raise RetentionError(f"{duration_unit!r} birimi için süre değeri zorunlu.")
        if duration_value <= 0:
            raise RetentionError("Süre değeri pozitif olmalı.")


# ──────────────────────────────────────────────────────────────────────────────
# CRUD — profiller
# ──────────────────────────────────────────────────────────────────────────────


def create_profile(
    db: DBManager,
    *,
    name: str,
    duration_value: int | None,
    duration_unit: str,
    start_type: str = START_UPLOAD,
    legal_basis: str | None = None,
    early_delete_protection: bool = True,
    is_builtin: bool = False,
) -> int:
    """
    Yeni saklama profili oluşturur ve id'sini döndürür.

    Raises:
        RetentionError:            alanlar geçersizse
        DuplicateProfileNameError: aynı isimde profil varsa
    """
    _validate(name, duration_value, duration_unit, start_type)
    try:
        cur = db.execute(
            """
            INSERT INTO retention_profiles
                (name, duration_value, duration_unit, start_type,
                 legal_basis, early_delete_protection, is_builtin)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name.strip(),
                duration_value,
                duration_unit,
                start_type,
                legal_basis,
                int(early_delete_protection),
                int(is_builtin),
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise DuplicateProfileNameError(f"Bu isimde bir profil zaten var: {name!r}") from exc
    return int(cur.lastrowid or 0)


def get_profile(db: DBManager, profile_id: int) -> sqlite3.Row | None:
    return db.fetchone("SELECT * FROM retention_profiles WHERE id = ?", (profile_id,))


def get_profile_by_name(db: DBManager, name: str) -> sqlite3.Row | None:
    return db.fetchone("SELECT * FROM retention_profiles WHERE name = ?", (name,))


def list_profiles(db: DBManager) -> list[sqlite3.Row]:
    """Tüm profilleri isme göre sıralı döndürür."""
    return db.fetchall("SELECT * FROM retention_profiles ORDER BY name")


def update_profile(db: DBManager, profile_id: int, **fields: Any) -> bool:
    """
    Profilin verilen alanlarını günceller.

    Yalnızca gönderilen alanlar değişir. Doğrulama, mevcut satırla birleştirilmiş
    SONUÇ üzerinden yapılır: tek başına `duration_unit='suresiz'` göndermek,
    satırda duran süre değeriyle birlikte geçersiz bir birleşim oluşturur ve
    reddedilir (şemadaki CHECK de aynı şeyi söyler).

    Returns:
        True  — güncellendi
        False — böyle bir profil yok
    """
    allowed = {
        "name",
        "duration_value",
        "duration_unit",
        "start_type",
        "legal_basis",
        "early_delete_protection",
        "is_builtin",
    }
    unknown = set(fields) - allowed
    if unknown:
        raise RetentionError(f"Bilinmeyen alan(lar): {', '.join(sorted(unknown))}")
    if not fields:
        raise RetentionError("Güncellenecek alan verilmedi.")

    current = get_profile(db, profile_id)
    if current is None:
        return False

    merged = dict(current)
    merged.update(fields)
    _validate(
        merged["name"],
        merged["duration_value"],
        merged["duration_unit"],
        merged["start_type"],
    )

    if "name" in fields and fields["name"] is not None:
        fields["name"] = str(fields["name"]).strip()
    for flag in ("early_delete_protection", "is_builtin"):
        if flag in fields:
            fields[flag] = int(bool(fields[flag]))

    assignments = ", ".join(f"{col} = ?" for col in fields)
    params = tuple(fields.values()) + (profile_id,)
    try:
        db.execute(
            f"UPDATE retention_profiles SET {assignments},"
            f" updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?",
            params,
        )
    except sqlite3.IntegrityError as exc:
        raise DuplicateProfileNameError(
            f"Bu isimde bir profil zaten var: {fields.get('name')!r}"
        ) from exc
    return True


def delete_profile(db: DBManager, profile_id: int) -> bool:
    """
    Profili siler. Hazır şablonlar dâhil her profil silinebilir.

    Profile bağlı dosyalar SİLİNMEZ: FK `ON DELETE SET NULL` olduğu için
    yalnızca profilsiz kalırlar.

    Returns:
        True  — silindi
        False — böyle bir profil yok
    """
    cur = db.execute("DELETE FROM retention_profiles WHERE id = ?", (profile_id,))
    return cur.rowcount > 0


# ──────────────────────────────────────────────────────────────────────────────
# Şablon seed'i
# ──────────────────────────────────────────────────────────────────────────────


def seed_builtin_templates(db: DBManager, *, force: bool = False) -> int:
    """
    Hazır şablonları veritabanına YALNIZCA BİR KEZ yazar.

    Bir kereliğine olması şart: `INSERT OR IGNORE`'ı her açılışta çalıştırmak,
    kullanıcının SİLDİĞİ şablonları bir sonraki açılışta geri getirirdi —
    yani silme sessizce çalışmamış olurdu. Bunun yerine `settings` tablosunda
    bir bayrak tutuluyor (mevcut `imha_ttl_hours` ile aynı desen).

    Args:
        force: bayrağı yok sayıp eksik şablonları yeniden yazar (isim çakışması
               olanlar atlanır). Kullanıcı isteyerek "şablonları geri getir"
               derse diye — kendiliğinden asla çalışmaz.

    Returns:
        Eklenen satır sayısı.
    """
    if not force and db.get_setting(_SEED_FLAG) == "1":
        return 0

    inserted = 0
    for template in BUILTIN_TEMPLATES:
        try:
            create_profile(db, is_builtin=True, **template)
            inserted += 1
        except DuplicateProfileNameError:
            continue  # kullanıcı aynı isimde bir profil oluşturmuş — dokunma

    db.set_setting(_SEED_FLAG, "1")
    return inserted


# ──────────────────────────────────────────────────────────────────────────────
# CRUD — dosya ↔ profil bağı
# ──────────────────────────────────────────────────────────────────────────────


def assign_profile(
    db: DBManager,
    file_id: int,
    profile_id: int | None,
    start_date: str | date | datetime | None = None,
) -> bool:
    """
    Bir dosyaya saklama profili atar (veya `profile_id=None` ile atamayı kaldırır).

    Elle giriş gerektiren profillerde (`belge_tarihi` / `olay_tarihi`)
    `start_date` ZORUNLUDUR — eksikse atama hiç yapılmaz. Bunu atama anında
    reddetmek, hesaplama anına ertelemekten iyidir: aksi hâlde dosya, imha
    tarihi hesaplanamayan bir profille bağlı kalırdı.

    Returns:
        True  — atandı
        False — böyle bir dosya yok
    """
    if db.fetchone("SELECT id FROM files WHERE id = ?", (file_id,)) is None:
        return False

    if profile_id is None:
        db.execute(
            "UPDATE files SET retention_profile_id = NULL, retention_start_date = NULL"
            " WHERE id = ?",
            (file_id,),
        )
        return True

    profile = get_profile(db, profile_id)
    if profile is None:
        raise RetentionError(f"Profil bulunamadı: id={profile_id}")

    needs_manual = profile["start_type"] in MANUAL_START_TYPES
    if needs_manual and start_date is None:
        raise RetentionError(
            f"{profile['start_type']!r} profili için başlangıç tarihi zorunlu."
        )

    stored: str | None = None
    if start_date is not None:
        # parse_date doğrulama görevi de görüyor: bozuk tarih DB'ye girmesin.
        stored = parse_date(start_date).isoformat()
        if not needs_manual:
            # 'yukleme_tarihi' profilinde elle tarihin bağlayıcı bir anlamı yok;
            # saklamak, hesapta kullanılmayan bir alanın doğru sanılmasına yol
            # açardı. Bilerek yok sayılıyor.
            stored = None

    db.execute(
        "UPDATE files SET retention_profile_id = ?, retention_start_date = ? WHERE id = ?",
        (profile_id, stored, file_id),
    )
    return True


def files_using_profile(db: DBManager, profile_id: int) -> list[sqlite3.Row]:
    """Profile bağlı dosyalar — profil silinmeden önce etkiyi göstermek için."""
    return db.fetchall(
        "SELECT id, filename, retention_start_date FROM files"
        " WHERE retention_profile_id = ? ORDER BY filename",
        (profile_id,),
    )
