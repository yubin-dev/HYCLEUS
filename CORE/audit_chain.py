"""
HYCLEUS — Denetim kaydı hash zinciri

Denetim kaydı (`audit_log`) şifresiz bir SQLite tablosudur; dosyaya yazabilen
bir saldırgan satır silebilir ya da değiştirebilir. Bu modül bunu
ENGELLEMEZ — **fark edilebilir** kılar. Her kayıt bir önceki kaydın hash'ini
içine alır, böylece tek bir satırı sessizce değiştirmek mümkün olmaz:

    hash_n = SHA256( hash_(n-1) || kanonik(kayıt_n) )

`hash_0` (genesis) 32 sıfır byte'tır — hex karşılığı 64 sıfır karakteri
(`GENESIS_HASH`). Sabit ve gizli olmayan bir değerdir; zincirin gizliliğe
değil, yerel tutarlılığa dayandığını açıkça göstermek için bilinçle böyle
seçildi (aşağıdaki "Bu neyi korumaz" başlığına bakın).


Kanonik serileştirme — neden JSON değil
---------------------------------------
Hash'in yeniden üretilebilmesi için kaydın byte temsili tek anlamlı olmak
zorunda. JSON bunu sağlayabilir (`sort_keys=True`, sabit `separators`) ama
üç zayıf noktası var: unicode kaçış davranışı sürüme/parametreye bağlı,
`ensure_ascii` farkı sessizce farklı byte'lar üretir ve yıllar sonra bir
kütüphane güncellemesi eski hash'leri doğrulanamaz hâle getirebilir. Denetim
kaydının hash'i on yıl sonra da aynı çıkmak zorunda.

Bunun yerine **uzunluk önekli, sabit alan sıralı** bir kodlama kullanılıyor:

    HYCLEUS-AUDIT-V1\\n
    id=<bayt_sayısı>:<utf-8 bayt>\\n
    timestamp=<bayt_sayısı>:<utf-8 bayt>\\n
    user_id=NULL\\n
    action=<bayt_sayısı>:<utf-8 bayt>\\n
    target_type=NULL\\n
    target_id=<bayt_sayısı>:<utf-8 bayt>\\n
    detail=<bayt_sayısı>:<utf-8 bayt>\\n

Uzunluk öneki alan-enjeksiyonunu imkânsız kılar: ayraçla birleştirilmiş bir
biçimde `detail="x\\naction=..."` yazan bir saldırgan başka bir kaydın byte
temsilini taklit edebilirdi. Uzunluk yazılıyken bu yapılamaz. `NULL` ile
boş metin de ayrı kodlanır (`NULL` harfle, uzunluk hep rakamla başlar);
`detail IS NULL` ile `detail = ''` farklı hash üretir.

**Hangi alanlar giriyor:** `id`, `timestamp`, `user_id`, `action`,
`target_type`, `target_id`, `detail` — yani `audit_log`'un `entry_hash`
dışındaki TÜM sütunları. `id` bilerek dahil: kaydı zincirdeki konumuna
bağlar ve doğrulama raporunun "şu id'den itibaren kırık" diyebilmesini
sağlar. `entry_hash` doğal olarak dışarıda — kendi kendini hash'leyemez.

**Değerler her zaman SQLite'ın SAKLADIĞI hâlleriyle hash'lenir**, ekleme
öncesi Python değerleriyle değil. Bu yüzden `append_entry()` önce INSERT
eder, satırı geri okur, sonra hash'i UPDATE ile yazar (hepsi tek
transaction). `id` ve `timestamp` zaten veritabanı tarafından üretiliyor;
tip dönüşümü (INTEGER affinity) de böylece hesaba katılmış oluyor.
Doğrulama aynı satırı aynı şekilde okur, dolayısıyla sonuç tekrarlanabilir.

`prev_hash` ayrı bir sütun olarak SAKLANMIYOR: bir önceki kaydın
`entry_hash`'i zaten tabloda duruyor, ikinci kez yazmak birbiriyle
çelişebilecek gereksiz bir kopya olurdu ve saldırgana karşı hiçbir şey
kazandırmazdı (ikisini birden değiştirmek tek satır fazla iş demek).


Zincir nerede başlıyor — geriye dönük kayıtlar
----------------------------------------------
Bu güncellemeden ÖNCE yazılmış kayıtlar zincire alınamaz: o kayıtlar
yazılırken "önceki hash" diye bir şey yoktu, dolayısıyla geriye dönük
hesaplanacak bir hash de yok. Şimdi hesaplansaydı ortaya zincirin
korumadığı, ama korumuş gibi görünen bir bölge çıkardı — en kötü sonuç bu
olurdu.

Bunun yerine sınır açıkça işaretleniyor. `ensure_chain_started()` zincirin
ilk halkası olarak `audit_chain_genesis` adlı gerçek bir denetim kaydı
yazar; bu kaydın `detail` alanı o an tabloda kaç zincirlenmemiş satır
olduğunu ve son zincirlenmemiş id'yi yazar. Kaydın id'si ayrıca
`settings` tablosuna `audit_chain_start_id` olarak konur.

`verify_audit_chain()` bu id'den küçük satırları doğrulamaz; onları
`unchained_before` olarak RAPORLAR. Yani "öncesi kapsam dışı" bilgisi hem
denetim kaydının kendi içinde (genesis satırı), hem raporda görünür.
Sessizce baştan başlanmaz. Aynı sınır SECURITY.md §4.6'da da yazılı.


Bu neyi korumaz
---------------
· **Zincirin tamamen yeniden yazılması.** Hash anahtarsızdır (HMAC değil).
  Veritabanına yazabilen biri satırı değiştirip ondan SONRAKİ bütün
  hash'leri yeniden hesaplayabilir; sonuç tutarlı bir zincir olur.
  Anahtarlı bir MAC bunu çözmez, çünkü anahtar aynı makinede durmak
  zorunda olurdu (bkz. SECURITY.md §4.2 — vault HMAC'ında aynı sorun).
  Bunun karşılığı zincir değil, **anchor**tır: son hash düzenli olarak
  veritabanının dışına yazılır, orayla karşılaştırıldığında yeniden yazım
  ortaya çıkar.

· **Kuyruğun kesilmesi.** Son N kaydı silmek zincirde ne boşluk ne de
  uyuşmazlık bırakır — kalan kısım kusursuz doğrulanır. Bunu yakalayan tek
  şey anchor'dır (`verify_against_anchor()`).

· **Hiç yazılmamış olay.** Zincir yazılan kayıtların bütünlüğünü gösterir,
  eksiksizliğini değil.

Kısacası: zincir + anchor birlikte "kurcalama kanıtı" verir, "kurcalama
engeli" değil. Tam tehdit modeli için SECURITY.md §3 ve §4.6.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from CORE.paths import data_dir

_log = logging.getLogger("hycleus.audit_chain")

# ── Serileştirme ──────────────────────────────────────────────────────────────

#: Kanonik biçimin sürüm etiketi. Biçim değişirse bu etiket de değişmeli;
#: eski kayıtlar eski etiketle doğrulanmaya devam eder.
SERIALIZATION_VERSION = "HYCLEUS-AUDIT-V1"
_HEADER = SERIALIZATION_VERSION.encode("utf-8") + b"\n"

#: Hash'lenen alanlar ve SIRASI. Sıra biçimin parçasıdır — değiştirilemez.
FIELD_ORDER: tuple[str, ...] = (
    "id",
    "timestamp",
    "user_id",
    "action",
    "target_type",
    "target_id",
    "detail",
)
_SELECT_FIELDS = ", ".join(FIELD_ORDER)

#: İlk kaydın "önceki hash"i — 32 sıfır byte, hex olarak 64 sıfır karakteri.
GENESIS_HASH = "0" * 64

#: Zincirin başladığı yeri işaretleyen özel denetim kaydının action'ı.
GENESIS_ACTION = "audit_chain_genesis"

#: Genesis kaydının id'sinin tutulduğu settings anahtarı.
CHAIN_START_SETTING = "audit_chain_start_id"

# ── Anchor ────────────────────────────────────────────────────────────────────

ANCHOR_VERSION = "HYCLEUS-ANCHOR-V1"
ANCHOR_FILENAME = "audit_anchor.log"

#: USB token'ın bağlama kökünde anchor dosyasının konduğu alt klasör.
#: Bkz. usb_anchor_path().
USB_ANCHOR_SUBDIR = "HYCLEUS"

#: Yerel disk anchor dosyasının yolunu ezen ortam değişkeni — özel kurulumlar
#: (ör. bir ağ paylaşımı) için. Bkz. anchor_path(). Genel izolasyon iddiasını
#: TAŞIMAZ — onu otomatik USB kopyası (usb_anchor_path()) taşır; bkz. bu
#: modülün "Anchor" başlıklı bölümündeki gerekçe.
ANCHOR_ENV_VAR = "HYCLEUS_AUDIT_ANCHOR"

_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Aynı süreçteki iki thread'in aynı bağlantı üzerinde iç içe BEGIN açmasını
# engeller. Farklı bağlantılar arası yarışı bu kilit çözmez — onu
# BEGIN IMMEDIATE + busy_timeout hallediyor (bkz. _begin_immediate).
_APPEND_LOCK = threading.RLock()
_ANCHOR_LOCK = threading.RLock()

#: Yazma kilidini beklerken tolere edilen süre. Tarama thread'i kendi
#: bağlantısını açıyor (CORE/scanner.py) — varsayılan 0 ms ile o yazma
#: "database is locked" ile düşerdi.
_BUSY_TIMEOUT_MS = 5000


# ══════════════════════════════════════════════════════════════════════════════
# Kanonik biçim ve hash
# ══════════════════════════════════════════════════════════════════════════════


def _encode_field(name: str, value: Any) -> bytes:
    """Tek alanı `ad=uzunluk:baytlar\\n` (ya da `ad=NULL\\n`) olarak kodlar."""
    if value is None:
        return f"{name}=NULL\n".encode("utf-8")
    raw = (value if isinstance(value, str) else str(value)).encode("utf-8")
    return f"{name}={len(raw)}:".encode("utf-8") + raw + b"\n"


def canonical_bytes(entry: Mapping[str, Any]) -> bytes:
    """
    Bir denetim kaydının tek anlamlı byte temsilini üretir.

    Args:
        entry: FIELD_ORDER'daki her anahtarı içeren eşleme. Eksik anahtar
               sessizce NULL sayılmaz — KeyError fırlar, çünkü "alan yoktu"
               ile "alan NULL'dı" farklı hash üretmeli ve karışması
               doğrulanamayan kayıt demek olurdu.
    """
    parts = [_HEADER]
    for name in FIELD_ORDER:
        if name not in entry:
            raise KeyError(f"Kanonik biçimde zorunlu alan eksik: {name!r}")
        parts.append(_encode_field(name, entry[name]))
    return b"".join(parts)


def compute_entry_hash(prev_hash: str, entry: Mapping[str, Any]) -> str:
    """
    hash_n = SHA256(hash_(n-1) || kanonik(kayıt)) — hex olarak döner.

    `prev_hash` hex metindir (ilk kayıt için GENESIS_HASH) ve hash'e ham 32
    byte olarak girer; hex metnin kendisi olarak değil.
    """
    if not isinstance(prev_hash, str) or len(prev_hash) != 64:
        raise ValueError(f"Önceki hash 64 karakter hex olmalı, alınan: {prev_hash!r}")
    try:
        prev_raw = bytes.fromhex(prev_hash)
    except ValueError as exc:
        raise ValueError(f"Önceki hash geçerli hex değil: {prev_hash!r}") from exc
    return hashlib.sha256(prev_raw + canonical_bytes(entry)).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# Bağlantı yardımcıları
# ══════════════════════════════════════════════════════════════════════════════


def _connection(source: Any) -> sqlite3.Connection:
    """DBManager ya da ham sqlite3.Connection kabul eder."""
    if isinstance(source, sqlite3.Connection):
        return source
    conn = getattr(source, "conn", None)
    if isinstance(conn, sqlite3.Connection):
        return conn
    raise TypeError(f"sqlite3.Connection ya da DBManager bekleniyordu: {type(source)!r}")


def _begin_immediate(conn: sqlite3.Connection) -> None:
    """
    Yazma kilidini HEMEN alarak transaction açar.

    Neden DEFERRED değil: zincir "son hash'i oku → yeni kaydı yaz" adımından
    oluşuyor. Python'un varsayılan davranışında BEGIN ilk DML'e kadar
    ertelenir, yani SELECT kilitsiz çalışır; iki yazar aynı önceki hash'i
    okuyup iki kaydı aynı halkaya bağlayabilirdi ve zincir çatallanırdı.
    BEGIN IMMEDIATE okuma-yazma çiftini bölünmez yapar.
    """
    conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    if conn.in_transaction:
        # Bu kod yolunda açık bir transaction beklenmiyor: DBManager her
        # execute()'tan sonra commit ediyor. Yine de bir çağıran yarım
        # bırakmışsa iç içe BEGIN hata verirdi — önce kapatıyoruz.
        conn.commit()
    conn.execute("BEGIN IMMEDIATE")


def _row_to_entry(row: Sequence[Any]) -> dict[str, Any]:
    """_SELECT_FIELDS sırasıyla okunmuş satırı kanonik eşlemeye çevirir."""
    return dict(zip(FIELD_ORDER, row))


def _previous_hash(conn: sqlite3.Connection, before_id: int) -> str:
    """
    `before_id`'den önceki son ZİNCİRLİ kaydın hash'i; yoksa GENESIS_HASH.

    `entry_hash IS NULL` satırlar atlanır. Bu, doğrulayıcının davranışıyla
    birebir aynı olmak zorunda: zincir dışı kalmış bir satır (eski kayıt ya
    da zinciri atlayan doğrudan INSERT) halkayı koparmaz, sadece kendisi
    kapsam dışı sayılır.
    """
    row = conn.execute(
        "SELECT entry_hash FROM audit_log"
        " WHERE id < ? AND entry_hash IS NOT NULL"
        " ORDER BY id DESC LIMIT 1",
        (before_id,),
    ).fetchone()
    return GENESIS_HASH if row is None else str(row[0])


# ══════════════════════════════════════════════════════════════════════════════
# Yazma
# ══════════════════════════════════════════════════════════════════════════════


def append_entry(
    source: Any,
    action: str,
    *,
    user_id: int | None = None,
    target_type: str | None = None,
    target_id: int | None = None,
    detail: str | None = None,
) -> int:
    """
    Denetim kaydını zincire ekler ve yeni kaydın id'sini döndürür.

    INSERT → satırı geri oku → hash'i UPDATE et; üçü tek transaction içinde.
    İki adım gerekli çünkü `id` ve `timestamp` veritabanı tarafından
    üretiliyor ve hash tam olarak SAKLANAN değerlerin üzerinden hesaplanmalı
    (modül docstring'ine bakın).

    Hata durumunda transaction geri alınır ve istisna yükselir — hash'siz
    yarım kayıt bırakılmaz.
    """
    conn = _connection(source)
    with _APPEND_LOCK:
        _begin_immediate(conn)
        try:
            cur = conn.execute(
                "INSERT INTO audit_log (user_id, action, target_type, target_id, detail)"
                " VALUES (?, ?, ?, ?, ?)",
                (user_id, action, target_type, target_id, detail),
            )
            new_id = int(cur.lastrowid or 0)
            row = conn.execute(
                f"SELECT {_SELECT_FIELDS} FROM audit_log WHERE id = ?", (new_id,)
            ).fetchone()
            if row is None:  # pragma: no cover — INSERT başarılıysa olamaz
                raise RuntimeError(f"Eklenen denetim kaydı geri okunamadı: id={new_id}")

            digest = compute_entry_hash(_previous_hash(conn, new_id), _row_to_entry(row))
            conn.execute(
                "UPDATE audit_log SET entry_hash = ? WHERE id = ?", (digest, new_id)
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return new_id


def chain_start_id(source: Any) -> int | None:
    """
    Zincirin başladığı kaydın id'si; zincir hiç başlatılmamışsa None.

    Önce `settings.audit_chain_start_id`'ye bakar. O silinmişse genesis
    kaydının kendisi aranır — işaretin iki ayrı yerde durması, birini silen
    bir saldırganın sınırı belirsizleştirmesini zorlaştırır.
    """
    conn = _connection(source)
    row = conn.execute(
        "SELECT value FROM settings WHERE key = ?", (CHAIN_START_SETTING,)
    ).fetchone()
    if row is not None:
        try:
            return int(row[0])
        except (TypeError, ValueError):
            _log.warning("settings.%s sayıya çevrilemedi: %r", CHAIN_START_SETTING, row[0])

    row = conn.execute(
        "SELECT MIN(id) FROM audit_log WHERE action = ?", (GENESIS_ACTION,)
    ).fetchone()
    return None if row is None or row[0] is None else int(row[0])


def ensure_chain_started(source: Any) -> int:
    """
    Zincir başlamamışsa genesis kaydını yazar; her hâlükârda başlangıç id'sini döner.

    Idempotent — her açılışta çağrılabilir. Genesis kaydı sıradan bir
    `audit_log` satırıdır ve zincirin ilk halkasıdır: kendi hash'i
    GENESIS_HASH üzerinden hesaplanır.
    """
    conn = _connection(source)
    existing = chain_start_id(conn)
    if existing is not None:
        return existing

    legacy = conn.execute("SELECT COUNT(*), MAX(id) FROM audit_log").fetchone()
    legacy_count = int(legacy[0] or 0)
    legacy_last = legacy[1]

    detail = (
        f"serialization={SERIALIZATION_VERSION}"
        f" genesis_hash={GENESIS_HASH}"
        f" unchained_before={legacy_count}"
        f" last_unchained_id={legacy_last if legacy_last is not None else 'none'}"
        " note=bu kayittan oncesi zincirlenmemistir"
    )
    start_id = append_entry(conn, GENESIS_ACTION, detail=detail)

    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (CHAIN_START_SETTING, str(start_id)),
    )
    conn.commit()

    _log.info(
        "Denetim zinciri başlatıldı  start_id=%d  zincirlenmemiş_önceki=%d",
        start_id, legacy_count,
    )
    return start_id


# ══════════════════════════════════════════════════════════════════════════════
# Doğrulama
# ══════════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ChainBreak:
    """Zincirde tespit edilen tek bir kırılma."""

    #: "no_chain" | "gap" | "unhashed" | "modified"
    kind: str
    #: İlgili kaydın id'si. "gap" için kayıp aralığın İLK id'si.
    entry_id: int | None
    detail: str

    def __str__(self) -> str:
        yer = f"id={self.entry_id}" if self.entry_id is not None else "id=?"
        return f"[{self.kind}] {yer} — {self.detail}"


@dataclass(frozen=True)
class ChainVerification:
    """`verify_audit_chain()` sonucu. Doğruysa truthy'dir."""

    ok: bool
    #: Zincire dahil edilip hash'i doğrulanan kayıt sayısı.
    checked: int
    #: Zincir başlamadan önce yazılmış, kapsam dışı kayıt sayısı.
    unchained_before: int
    start_id: int | None
    #: Zincirin son geçerli hash'i — anchor'a yazılan değer.
    last_hash: str | None
    last_id: int | None
    breaks: list[ChainBreak] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok

    @property
    def first_broken_id(self) -> int | None:
        """Zincirin kırıldığı ilk kaydın id'si — sağlamsa None."""
        for brk in self.breaks:
            if brk.entry_id is not None:
                return brk.entry_id
        return None

    def summary(self) -> str:
        kapsam = (
            f"{self.checked} kayıt doğrulandı"
            f" (zincir başlangıcı id={self.start_id};"
            f" {self.unchained_before} eski kayıt kapsam dışı)"
        )
        if self.ok:
            return f"Denetim zinciri sağlam — {kapsam}."
        satirlar = [f"Denetim zinciri KIRIK — {kapsam}."]
        if self.first_broken_id is not None:
            satirlar.append(f"İlk kırılma: id={self.first_broken_id}")
        satirlar.extend(f"  · {brk}" for brk in self.breaks)
        return "\n".join(satirlar)


#: `link_status()` / `link_statuses()` dönüş değerleri — HALKA sütunu (UI).
LINK_INTACT = "intact"
LINK_BROKEN = "broken"
LINK_OUT_OF_SCOPE = "out_of_scope"


def link_status(verification: ChainVerification, entry_id: int) -> str:
    """
    Tek bir denetim kaydının HALKA durumu — `LINK_INTACT` | `LINK_BROKEN`
    | `LINK_OUT_OF_SCOPE`.

    YENİ bir hash hesaplaması YAPMIYOR. `verify_audit_chain()` zincirdeki
    HER kaydı zaten bir kez hesaplayıp karşılaştırıyor ve yalnızca
    BAŞARISIZ olanları `breaks`'e yazıyor (bkz. o fonksiyonun docstring'i
    — "hangi kayıttan itibaren" sorusuna kaydettiği yanıt). Burada
    yapılan tek şey o SONUCUN tek bir satır için OKUNMASI:

      · `entry_id`, zincir başlamadan ÖNCEki bir kayıtsa (`start_id`'den
        küçük) ya da zincir hiç başlamadıysa → kapsam dışı. "Doğrulandı
        ve sağlam" ile "hiç doğrulanmadı" FARKLI iddialar; ikisini de
        "sağlam" göstermek yanlış güven verirdi (bkz.
        `CORE/hwid_probe.py::compare()`'in aynı "bilinmiyor" ayrımı).
      · `entry_id`, "modified" ya da "unhashed" türünde bir `ChainBreak`'in
        `entry_id`'siyse → kırık.
      · İkisi de değilse → sağlam — çünkü `verify_audit_chain()` o kaydı
        zaten kontrol ETTİ (checked'e sayıldı) ve bir sorun bulmadı.

    Not: bir "gap" kırılması (silinmiş ara kayıt) doğrudan hiçbir
    GÖRÜNÜR satırın `entry_id`'sine denk gelmez — silinen id zaten
    tabloda yok. Ama pratik sonucu yine bu fonksiyonla görünür: gap'ten
    SONRAKİ ilk mevcut kayıt, `_previous_hash` zincirlemesi bozulduğu
    için neredeyse her zaman KENDİ `modified` kırılmasını üretir (bkz.
    `verify_audit_chain()`'in döngüsü — gap tespitinden sonra işleme
    AYNI satırla devam ediyor). Yani gap'in etkisi burada ayrıca
    kodlanmadan, doğal sonucu üzerinden zaten yakalanıyor.
    """
    start = verification.start_id
    if start is None or entry_id < start:
        return LINK_OUT_OF_SCOPE
    for brk in verification.breaks:
        if brk.entry_id == entry_id and brk.kind in ("modified", "unhashed"):
            return LINK_BROKEN
    return LINK_INTACT


def link_statuses(verification: ChainVerification, entry_ids: Sequence[int]) -> dict[int, str]:
    """`link_status()`'u birden çok kayıt için tek geçişte uygular (UI tablosu)."""
    return {entry_id: link_status(verification, entry_id) for entry_id in entry_ids}


def _format_missing(missing: list[int]) -> str:
    if len(missing) <= 10:
        return ", ".join(str(m) for m in missing)
    head = ", ".join(str(m) for m in missing[:10])
    return f"{head}, … (+{len(missing) - 10} tane daha)"


def verify_audit_chain(source: Any) -> ChainVerification:
    """
    Zinciri baştan sona gezer ve her hash'in gerçekten türetildiğini doğrular.

    Kırılma türleri:

    ``no_chain``
        Zincir hiç başlatılmamış (genesis kaydı ve settings anahtarı yok).
    ``gap``
        Zincirli bölgede id atlaması var — AUTOINCREMENT id yeniden
        kullanmadığı için bu, silinmiş kayıt anlamına gelir. Kuyruğu değil
        ARADAN silmeyi yakalar; hangi id'lerin kaybolduğunu ismen raporlar.
    ``unhashed``
        Zincirli bölgede `entry_hash IS NULL` bir satır — `append_entry()`
        yerine doğrudan INSERT edilmiş. Halkayı koparmaz (yazar da bu
        satırları atlıyor), ama kapsam dışıdır ve bildirilir.
    ``modified``
        Saklanan hash, kaydın içeriğinden yeniden hesaplananla uyuşmuyor.

    Kırılmadan SONRA zincir, saklanan hash üzerinden takip edilmeye devam
    eder. Yani tek bir satırı değiştirmek tek bir `modified` üretir, ondan
    sonraki her kaydı da kırık göstermez — rapor "hangi kayıttan itibaren"
    sorusuna tam yanıt verebilsin diye.

    Kuyruğun kesilmesi (son N kaydın silinmesi) BU FONKSİYONLA
    YAKALANAMAZ — geriye kusursuz doğrulanan bir zincir kalır. Onun için
    `verify_against_anchor()` var.
    """
    conn = _connection(source)
    start = chain_start_id(conn)

    if start is None:
        toplam = int(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] or 0)
        return ChainVerification(
            ok=False,
            checked=0,
            unchained_before=toplam,
            start_id=None,
            last_hash=None,
            last_id=None,
            breaks=[
                ChainBreak(
                    kind="no_chain",
                    entry_id=None,
                    detail=(
                        "Zincir başlatılmamış: genesis kaydı da"
                        f" settings.{CHAIN_START_SETTING} de yok."
                        " ensure_chain_started() çağrılmalı."
                    ),
                )
            ],
        )

    unchained_before = int(
        conn.execute("SELECT COUNT(*) FROM audit_log WHERE id < ?", (start,)).fetchone()[0]
        or 0
    )

    rows = conn.execute(
        f"SELECT {_SELECT_FIELDS}, entry_hash FROM audit_log WHERE id >= ? ORDER BY id",
        (start,),
    ).fetchall()

    breaks: list[ChainBreak] = []
    prev_hash = GENESIS_HASH
    last_hash: str | None = None
    last_id: int | None = None
    checked = 0
    expected_id = start

    for row in rows:
        entry = _row_to_entry(row[: len(FIELD_ORDER)])
        stored = row[len(FIELD_ORDER)]
        entry_id = int(entry["id"])

        if entry_id != expected_id:
            missing = list(range(expected_id, entry_id))
            breaks.append(
                ChainBreak(
                    kind="gap",
                    entry_id=expected_id,
                    detail=(
                        f"{len(missing)} kayıt eksik (id: {_format_missing(missing)});"
                        f" sıradaki mevcut kayıt id={entry_id}."
                        " AUTOINCREMENT id yeniden kullanmaz — satır silinmiş."
                    ),
                )
            )
        expected_id = entry_id + 1

        if stored is None:
            breaks.append(
                ChainBreak(
                    kind="unhashed",
                    entry_id=entry_id,
                    detail=(
                        f"action={entry['action']!r} kaydının hash'i yok —"
                        " zinciri atlayarak doğrudan INSERT edilmiş."
                    ),
                )
            )
            continue  # yazar da hash'siz satırları atlıyor; prev_hash korunur

        computed = compute_entry_hash(prev_hash, entry)
        if computed != str(stored):
            breaks.append(
                ChainBreak(
                    kind="modified",
                    entry_id=entry_id,
                    detail=(
                        f"action={entry['action']!r} —"
                        f" saklanan {str(stored)[:16]}…,"
                        f" hesaplanan {computed[:16]}…;"
                        " kaydın içeriği veya bir öncekinin hash'i değişmiş."
                    ),
                )
            )

        # Kırılmadan sonra SAKLANAN hash'ten devam: bozulmamış kayıtlar
        # ardıl hata üretmesin, rapor tek bir noktayı göstersin.
        prev_hash = str(stored)
        last_hash = str(stored)
        last_id = entry_id
        checked += 1

    return ChainVerification(
        ok=not breaks,
        checked=checked,
        unchained_before=unchained_before,
        start_id=start,
        last_hash=last_hash,
        last_id=last_id,
        breaks=breaks,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Anchor — zincirin ucunu veritabanının DIŞINA yazmak
# ══════════════════════════════════════════════════════════════════════════════
#
# Neden veritabanının kendisi olmaz
# ---------------------------------
# Zincirin tek gerçek zayıflığı yeniden yazılabilmesi: `audit_log`'a
# yazabilen biri bir satırı değiştirip sonraki bütün hash'leri yeniden
# hesaplayabilir, sonuç kusursuz doğrulanan bir zincirdir. Son hash'i AYNI
# veritabanında saklamak hiçbir şey eklemezdi — aynı saldırı yüzeyi, aynı
# tek yazma işlemi.
#
# Neden ayrı dosya — VE neden TEK dosya yetmez (B-090)
# -----------------------------------------------------
# Seçenekler: (a) yerel diskte ayrı bir append-only dosya, (b) kullanıcının
# USB token'ı, (c) uzak sunucu. (c) bu projede yok — HYCLEUS tamamen
# çevrimdışı çalışıyor ve ağ bağımlılığı eklemek tehdit modelini büyütürdü.
#
# Önceki tasarım YALNIZCA (a)'ya varsayılan olarak yazıyordu; (b)'yi
# HYCLEUS_AUDIT_ANCHOR ortam değişkeniyle bir SEÇENEK olarak sunuyordu. Bu
# YARIM bir çözümdü: env var başka bir DİZİNE yönlendiriyor olsa bile o
# dizin genellikle AYNI diskte, AYNI dosya sisteminde duruyor —
# veritabanına yazabilen saldırgan (bu modülün tüm tehdit modelinin
# varsaydığı kişi) o dizine de yazabilir. Anchor'ı "veritabanının DIŞINA"
# taşımanın kazandırdığı şey yalnızca ayrı bir DOSYA değil, ayrı bir GÜVEN
# ALANIdır — env var'la taşınan bir dosya bunu vermiyordu.
#
# Bu yüzden artık (a) VE (b) BİRLİKTE, varsayılan olarak: her `write_anchor()`
# çağrısı önce yerel diske (`data/audit_anchor.log`) yazar, SONRA o an takılı
# USB token'ın kendi bağlama kökünde (`usb_anchor_path()`,
# `CORE/usb_manager.py::get_usb_mount_root()`) AYNI kaydı ikinci bir kopya
# olarak yazar. USB token HYCLEUS'ta zaten ZORUNLU bir bileşen — oturum
# açıkken takılı olmak ZORUNDA (main_window'un `_poll_usb()`'si çıkarılınca
# kilitliyor) — yani "ek altyapı" gerekmiyor, kimlik doğrulaması için ZATEN
# orada duran cihaz yeniden kullanılıyor. USB kopyası fiziksel bir cihaz
# üzerinde durduğu için makineden SÖKÜLEBİLİR — env var'lı bir dizinin asla
# veremediği şey bu.
#
# USB kopyası yine de BEST-EFFORT: USB o an takılı değilse (CLI aracı,
# DEV_MODE, USB çıkarılmışken bir arka plan görevi) yazılamaz ve bu
# SESSİZCE atlanır — yerel disk kopyası HER ZAMAN yazılır, tek nokta
# bağımlılığı USB kopyasına TAŞINMAZ. "Bazen çalışan" bir kontrolün hiç
# olmamasından beter olduğu ilkesi burada da geçerli: USB kopyası yerel
# kopyanın YERİNE değil, ONA EK bir ikinci kanıt.
#
# HYCLEUS_AUDIT_ANCHOR hâlâ duruyor (yerel kopyanın konumunu özel kurulumlar
# için değiştirmek isteyenler için — ör. bir ağ paylaşımı) ama artık TEK
# başına "izolasyon" iddiasının karşılığı DEĞİL; o iddiayı taşıyan otomatik
# USB kopyasıdır.
#
# "Append-only" bu kodun disiplinidir, işletim sisteminin garantisi DEĞİL:
# dosyaya yazabilen onu kesebilir de. Bu yüzden her satır bir öncekinin
# hash'ini taşır (`prev_anchor_hash`) — anchor dosyasının kendisi de bir
# zincirdir ve tek satırının değiştirilmesi `verify_anchor_file()` ile
# yakalanır. TEK bir dosyanın kendi iç zinciri, o dosyanın TAMAMEN yeniden
# yazılmasına karşı korumasız (zincirin kendisiyle AYNI zayıflık — yukarıdaki
# modül docstring'inin "Bu neyi korumaz" bölümüne bakın). İki BAĞIMSIZ
# kopyayı (yerel + USB) KARŞILAŞTIRMAK (`verify_anchor_replicas()`) bunu
# kapatır: saldırganın ikisini de, AYNI ANDA, tutarlı biçimde değiştirmesi
# gerekir — biri diskte, diğeri makineden SÖKÜLEBİLEN bir cihazda.


@dataclass(frozen=True)
class AnchorCheck:
    """`verify_against_anchor()` / `verify_anchor_file()` sonucu."""

    ok: bool
    anchors_checked: int
    problems: list[str] = field(default_factory=list)
    latest: dict[str, Any] | None = None

    def __bool__(self) -> bool:
        return self.ok

    def summary(self) -> str:
        if self.anchors_checked == 0:
            return "Anchor kaydı yok — karşılaştırılacak bir şey bulunamadı."
        if self.ok:
            return f"Anchor doğrulandı ({self.anchors_checked} kayıt)."
        return "Anchor UYUŞMUYOR:\n" + "\n".join(f"  · {p}" for p in self.problems)


def anchor_path() -> Path:
    """
    YEREL disk anchor dosyasının yolu — iki kopyadan BİRİNCİSİ (B-090).

    HYCLEUS_AUDIT_ANCHOR tanımlıysa o kullanılır; değilse
    `data/audit_anchor.log`. Bu yol her hâlükârda AYNI diskte durur —
    izolasyonu sağlayan bu DEĞİL, `usb_anchor_path()`'in döndürdüğü ikinci,
    fiziksel olarak ayrı kopyadır.
    """
    override = os.getenv(ANCHOR_ENV_VAR)
    if override:
        return Path(override)
    return data_dir() / ANCHOR_FILENAME


def usb_anchor_path(hwid: str | None = None) -> Path | None:
    """
    Takılı USB token'ın bağlama kökündeki anchor dosyasının yolu — iki
    kopyadan İKİNCİSİ, GERÇEK izolasyonu taşıyan (B-090).

    Args:
        hwid: Hangi USB'nin arandığı. Verilmezse `get_usb_hwid()` ile o an
              takılı olan bulunur.

    Returns:
        USB takılıysa ve bağlama kökü okunabiliyorsa
        `<bağlama_kökü>/HYCLEUS/audit_anchor.log`; USB takılı değilse,
        hwid okunamıyorsa ya da bağlama kökü bulunamıyorsa None.

        None dönmesi bir HATA değil — çağıranın (write_anchor()) bu
        çağrıda ikinci kopyayı yazamayacağı, yerel kopyanın yine de
        yazılacağı anlamına gelir. Bkz. bu modülün üstündeki "Anchor"
        bölümünün "Neden ayrı dosya" gerekçesi.
    """
    from CORE.usb_manager import get_usb_hwid, get_usb_mount_root

    target_hwid = hwid if hwid is not None else get_usb_hwid()
    if not target_hwid:
        return None
    root = get_usb_mount_root(target_hwid)
    if root is None:
        return None
    return root / USB_ANCHOR_SUBDIR / ANCHOR_FILENAME


def _utcnow() -> datetime:
    """Şimdiki UTC zamanı. Testler bunu monkeypatch'ler."""
    return datetime.now(timezone.utc)


def _serialize_anchor(record: Mapping[str, Any]) -> str:
    """Anchor satırının kanonik JSON metni — anahtarlar sıralı, boşluksuz."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def read_anchors(path: Path | None = None) -> list[dict[str, Any]]:
    """Anchor dosyasındaki kayıtları sırayla döndürür. Dosya yoksa boş liste."""
    target = path or anchor_path()
    if not target.exists():
        return []
    records: list[dict[str, Any]] = []
    for lineno, raw in enumerate(target.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            _log.warning("Anchor satırı ayrıştırılamadı  dosya=%s  satır=%d", target, lineno)
    return records


def _raw_anchor_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _append_anchor_line(target: Path, base: Mapping[str, Any]) -> dict[str, Any]:
    """
    `base`'i (DB'den türetilmiş, dosyaya ÖZGÜ olmayan alanlar) hedef
    dosyanın KENDİ `seq`/`prev_anchor_hash` zincirine ekler.

    Bilerek dosya-başına: yerel ve USB kopyaları farklı satır SAYISINA sahip
    olabilir (USB her yazımda takılı olmayabilir — bkz. write_anchor()), bu
    yüzden ikisi AYNI `seq` numarasını PAYLAŞMAZ; her dosya kendi iç
    zincirinde tutarlı kalır (`verify_anchor_file()` bunu dosya başına
    doğrular). `last_id`/`last_hash`/`entry_count`/`chain_start_id`/`reason`/
    `anchored_at` — yani DB'den o anda okunan İÇERİK — ikisinde de AYNIdır;
    `verify_anchor_replicas()` karşılaştırması bunlara bakar.
    """
    lines = _raw_anchor_lines(target)
    record = dict(base)
    record["seq"] = len(lines) + 1
    record["prev_anchor_hash"] = _line_hash(lines[-1]) if lines else GENESIS_HASH
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(_serialize_anchor(record) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return record


def _usb_hwid_dogrulanmis_mi(conn: sqlite3.Connection, hwid: str, source: Any) -> bool:
    """
    `hwid`'in GERÇEKTEN bu oturuma/veritabanına ait olduğunu doğrular —
    `write_anchor()`'ın otomatik-bulunan USB'ye YAZMADAN ÖNCE çağırdığı
    çapraz-kontrol (B-090 takibi).

    Neden gerekli — `get_usb_mount_root(hwid)`'in KENDİSİ hwid eşleşmesini
    zaten doğru yapıyor (`tests/test_usb_mount_root.py`'de kanıtlandı: iki
    USB takılıyken her hwid KENDİ sürücü harfine eşleşiyor, çapraz eşleşme
    yok). Ama bu, VERİLEN hwid'in doğru sürücüyü bulacağını kanıtlıyor —
    write_anchor()'ın VERDİĞİ hwid'in doğru olduğunu DEĞİL. `write_anchor()`
    otomatik modda hwid'i `get_usb_hwid()`'den alıyor: o an takılı USB'lerin
    WMI numaralandırma sırasındaki İLKİ. Aynı anda BİRDEN FAZLA kayıtlı USB
    takılıysa (ör. iki yönetici token'ı, ya da bu oturumun token'ı çıkarılıp
    BAŞKA bir kayıtlı token takılmışsa) `get_usb_hwid()` bu OTURUMUN kendi
    token'ı OLMAYAN bir hwid döndürebilir — `get_usb_mount_root()` o zaman
    "doğru" ama YANLIŞ bir sürücüye, yani BAŞKA BİR KULLANICININ USB'sine,
    kusursuz biçimde eşleşir. Bu fonksiyon o ikinci, çağıran-seviyesi
    boşluğu kapatıyor.

    İki katman, İLKİ varsa yeterli:
      1. `source` bir DBManager'sa VE `_hwid`'i biliniyorsa (oturum GERÇEKTEN
         bu hwid'le authenticate olmuş — `DBManager.connect(hwid=...)`) —
         DOĞRUDAN karşılaştırma. EN GÜÇLÜ kontrol: `get_usb_hwid()`'in o an
         bulduğu USB'nin, oturum AÇILIRKEN doğrulanan hwid'le AYNI fiziksel
         cihaz olduğunu kanıtlar — birden fazla kayıtlı USB aynı anda
         takılıyken bile. Üretimdeki HER `write_anchor()` çağrısı
         (`main.py`) `DBManager()` SINGLETON'ını geçiriyor, yani bu katman
         üretimde HER ZAMAN devrede.
      2. `source` ham bir `sqlite3.Connection`'sa (oturumun hwid'i
         bilinmiyor — ör. bir CLI aracı, ya da testler) — `usb_tokens`
         tablosunda KAYITLI ve KARA LİSTEYE ALINMAMIŞ bir hwid mi diye
         bakılır. Daha ZAYIF (HANGİ kullanıcıya ait olduğunu ayırt etmez)
         ama en azından TAMAMEN yabancı/kayıtsız bir USB'ye yazılmasını
         engeller.
    """
    session_hwid = getattr(source, "_hwid", None)
    if session_hwid is not None:
        return hwid == session_hwid
    row = conn.execute(
        "SELECT 1 FROM usb_tokens WHERE hwid = ? AND blacklisted = 0", (hwid,)
    ).fetchone()
    return row is not None


def write_anchor(
    source: Any,
    reason: str,
    *,
    path: Path | None = None,
    usb_path: Path | None = None,
    write_usb: bool = True,
) -> dict[str, Any] | None:
    """
    Zincirin o anki son hash'ini anchor dosyasına ekler — YEREL diske HER
    ZAMAN, takılı USB token'a da (varsayılan) İKİNCİ bir kopya olarak
    (B-090).

    Args:
        reason: Neden yazıldığı — "startup" | "shutdown" | "daily" | "manual".
                Anchor satırında saklanır; sonradan hangi olayın hangi ucu
                sabitlediğini görebilmek için.
        path: Yerel kopyanın hedefi. Verilmezse `anchor_path()`.
        usb_path: USB kopyasının hedefi. Verilmezse, o an takılı USB'nin
                  hwid'i ÖNCE `_usb_hwid_dogrulanmis_mi()` ile doğrulanır,
                  SONRA `usb_anchor_path()` ile bulunur; doğrulama
                  BAŞARISIZ olursa (ya da hiçbir USB bulunamazsa, ya da
                  `write_usb=False` ise) USB kopyası hiç YAZILMAZ. `usb_path`
                  AÇIKÇA verildiğinde bu doğrulama ATLANIR — çağıran
                  hedefi zaten kendisi seçmiştir (testlerin `path=`'i
                  kullanma biçimiyle AYNI "açık yol her zaman kazanır"
                  sözleşmesi).
        write_usb: USB kopyasının denenip denenmeyeceği. Varsayılan True.

    Returns:
        YEREL kopya için yazılan anchor kaydı; zincirde hiç hash'li kayıt
        yoksa None. (USB kopyası yazılmış olsa da olmasa da dönen kayıt
        HER ZAMAN yerel kopyayı temsil eder — geriye dönük uyumluluk için;
        `usb_anchor_path()` ile USB kopyasının kendisi ayrıca okunabilir.)

    USB kopyası BEST-EFFORT: takılı değilse, hwid'i DOĞRULANAMAZSA ya da
    yazma herhangi bir nedenle başarısız olursa (çıkarılmış, salt-okunur,
    vb.) bu SESSİZCE atlanır (uyarı loglanır) — yerel kopyanın yazılması
    bundan ETKİLENMEZ. Tek nokta bağımlılığı USB'ye TAŞINMAZ.

    Anchor YAZILMADAN ÖNCE zincir doğrulanmaz — bilinçli. Kırık bir zincirin
    ucunu da sabitlemek işe yarar: bir sonraki karşılaştırma "kırılma ne
    zaman oluştu" sorusuna aralık verebilir. Doğrulamak çağıranın işi.
    """
    conn = _connection(source)
    target = path or anchor_path()

    row = conn.execute(
        "SELECT id, entry_hash FROM audit_log"
        " WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if row is None:
        _log.info("Anchor yazılmadı — zincirde hash'li kayıt yok.")
        return None

    entry_count = int(
        conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE entry_hash IS NOT NULL"
        ).fetchone()[0]
        or 0
    )

    base = {
        "version": ANCHOR_VERSION,
        "anchored_at": _utcnow().strftime(_TS_FORMAT),
        "reason": reason,
        "chain_start_id": chain_start_id(conn),
        "last_id": int(row[0]),
        "last_hash": str(row[1]),
        "entry_count": entry_count,
    }

    with _ANCHOR_LOCK:
        record = _append_anchor_line(target, base)

        usb_target: Path | None = None
        if write_usb:
            if usb_path is not None:
                usb_target = usb_path
            else:
                from CORE.usb_manager import get_usb_hwid

                aday_hwid = get_usb_hwid()
                if aday_hwid is None:
                    pass  # USB takılı değil — sessizce atla, mevcut davranış
                elif not _usb_hwid_dogrulanmis_mi(conn, aday_hwid, source):
                    _log.warning(
                        "USB anchor kopyası ATLANDI — takılı USB'nin hwid'i"
                        " (%.12s…) bu oturumun/tabanın doğruladığı hwid'le"
                        " uyuşmuyor; BAŞKA bir USB'ye yazılması ENGELLENDİ.",
                        aday_hwid,
                    )
                else:
                    usb_target = usb_anchor_path(aday_hwid)
        if usb_target is not None:
            try:
                _append_anchor_line(usb_target, base)
            except Exception:
                _log.warning(
                    "USB anchor kopyası yazılamadı — yerel kopya yine de"
                    " yazıldı  dosya=%s",
                    usb_target,
                    exc_info=True,
                )
            else:
                _log.info("USB anchor kopyası yazıldı  dosya=%s", usb_target)

    _log.info(
        "Anchor yazıldı  reason=%s  last_id=%d  hash=%.16s…  dosya=%s",
        reason, record["last_id"], record["last_hash"], target,
    )
    return record


def maybe_write_daily_anchor(
    source: Any,
    *,
    path: Path | None = None,
    reason: str = "daily",
) -> dict[str, Any] | None:
    """
    O gün (UTC) henüz anchor yazılmadıysa yazar.

    Günlük çıpa açılışta ve zamanlayıcıdan çağrılır; günlerce açık kalan bir
    kurulumda da günde en az bir uç noktası sabitlenmiş olur. Kapanıştaki
    anchor bundan bağımsız, her zaman yazılır (bkz. write_anchor).
    """
    target = path or anchor_path()
    bugun = _utcnow().strftime("%Y-%m-%d")
    with _ANCHOR_LOCK:
        for record in reversed(read_anchors(target)):
            anchored = str(record.get("anchored_at", ""))
            if anchored.startswith(bugun):
                return None
            break  # yalnızca en son kayda bakılır
    return write_anchor(source, reason, path=target)


def verify_against_anchor(source: Any, *, path: Path | None = None) -> AnchorCheck:
    """
    Veritabanını anchor dosyasındaki en son çıpayla karşılaştırır.

    Yakaladığı şey `verify_audit_chain()`'in yakalayamadığı iki durumdur:
    kuyruğun kesilmesi ve zincirin baştan yeniden yazılması. Her ikisinde de
    çıpalanan `last_id` ya kaybolmuş ya da farklı bir hash taşıyor olur.

    `anchors_checked == 0` ise hiçbir şey doğrulanmamıştır (dosya yok) —
    `ok` bu durumda True döner ama tek başına anlam taşımaz.
    """
    conn = _connection(source)
    target = path or anchor_path()
    records = read_anchors(target)
    if not records:
        return AnchorCheck(ok=True, anchors_checked=0, problems=[], latest=None)

    latest = records[-1]
    problems: list[str] = []

    last_id = latest.get("last_id")
    last_hash = latest.get("last_hash")
    anchored_at = latest.get("anchored_at", "?")

    row = conn.execute(
        "SELECT entry_hash FROM audit_log WHERE id = ?", (last_id,)
    ).fetchone()

    if row is None:
        problems.append(
            f"Çıpalanan kayıt veritabanında yok: id={last_id}"
            f" ({anchored_at} tarihinde çıpalanmıştı) — kayıtlar kuyruktan silinmiş."
        )
    elif row[0] is None:
        problems.append(f"Çıpalanan kaydın hash'i silinmiş: id={last_id}.")
    elif str(row[0]) != str(last_hash):
        problems.append(
            f"Çıpalanan kaydın hash'i değişmiş: id={last_id},"
            f" çıpa {str(last_hash)[:16]}…, veritabanı {str(row[0])[:16]}… —"
            " zincir yeniden yazılmış."
        )

    mevcut = int(
        conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE entry_hash IS NOT NULL"
        ).fetchone()[0]
        or 0
    )
    capalanan = int(latest.get("entry_count") or 0)
    if mevcut < capalanan:
        problems.append(
            f"Zincirli kayıt sayısı azalmış: çıpa {capalanan}, şimdi {mevcut}."
        )

    return AnchorCheck(
        ok=not problems, anchors_checked=len(records), problems=problems, latest=latest
    )


def verify_anchor_file(path: Path | None = None) -> AnchorCheck:
    """
    Anchor dosyasının KENDİ iç zincirini doğrular.

    Her satır bir öncekinin SHA-256'sını taşır; bu yüzden araya girip tek bir
    çıpayı değiştirmek yakalanır. Dosyanın SONUNDAN satır silmek yakalanmaz —
    onun karşılığı dosyanın makine dışına alınmış bir kopyasıdır.
    """
    target = path or anchor_path()
    lines = _raw_anchor_lines(target)
    if not lines:
        return AnchorCheck(ok=True, anchors_checked=0, problems=[], latest=None)

    problems: list[str] = []
    beklenen_prev = GENESIS_HASH
    latest: dict[str, Any] | None = None

    for index, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            problems.append(f"Satır {index}: JSON olarak ayrıştırılamadı.")
            beklenen_prev = _line_hash(line)
            continue

        latest = record
        gercek_prev = str(record.get("prev_anchor_hash", ""))
        if gercek_prev != beklenen_prev:
            problems.append(
                f"Satır {index}: prev_anchor_hash uyuşmuyor —"
                f" beklenen {beklenen_prev[:16]}…, bulunan {gercek_prev[:16]}…"
            )
        if record.get("seq") != index:
            problems.append(
                f"Satır {index}: seq={record.get('seq')} sıra numarasıyla uyuşmuyor."
            )
        beklenen_prev = _line_hash(line)

    return AnchorCheck(
        ok=not problems, anchors_checked=len(lines), problems=problems, latest=latest
    )


#: `verify_anchor_replicas()`'in karşılaştırdığı alanlar — DB'den o anda
#: okunan İÇERİK. `seq`/`prev_anchor_hash` bilerek DIŞARIDA: bunlar
#: dosyaya ÖZGÜ (bkz. `_append_anchor_line()`), iki kopya arasında farklı
#: olmaları BEKLENİR ve tek başına bir tutarsızlık DEĞİLDİR.
_REPLICA_COMPARED_FIELDS: tuple[str, ...] = (
    "last_id",
    "last_hash",
    "entry_count",
    "chain_start_id",
    "reason",
    "anchored_at",
)


def verify_anchor_replicas(
    *,
    local_path: Path | None = None,
    usb_path: Path | None = None,
    hwid: str | None = None,
) -> AnchorCheck:
    """
    Yerel disk anchor'ıyla USB'deki ikinci kopyayı KARŞILAŞTIRIR (B-090).

    Yakaladığı şey `verify_anchor_file()`'ın yakalayamadığı bir sınıf: TEK
    bir dosyanın kendi iç zinciri baştan sona tutarlı olabilir ama İÇERİĞİ
    bilerek DEĞİŞTİRİLMİŞ olabilir — saldırgan değiştirdiği satırdan
    SONRAKİ `seq`/`prev_anchor_hash` zincirini de o dosyanın İÇİNDE yeniden
    tutarlı hâle getirebilir (zincirin kendisiyle AYNI zayıflık, bkz. modül
    docstring'inin "Bu neyi korumaz" bölümü — TEK dosya için de geçerli).
    Bunu yakalayan tek şey, BAĞIMSIZ bir İKİNCİ kopyayla karşılaştırmaktır:
    saldırganın şimdi İKİSİNİ DE, aynı anda, tutarlı biçimde değiştirmesi
    gerekir — biri diskte, diğeri makineden fiziksel olarak SÖKÜLEBİLEN bir
    USB'de.

    Karşılaştırma ORTAK ÖNEK üzerinden yapılır: iki dosya farklı SAYIDA
    kayıt taşıyabilir (USB her `write_anchor()` çağrısında takılı
    olmayabilir — best-effort ikinci kopya, bkz. o fonksiyonun docstring'i)
    ve bu FARK TEK BAŞINA sorun DEĞİLDİR. Sorun, HER İKİ dosyada da VAR olan
    bir sıradaki (satır 1 ile satır 1, satır 2 ile satır 2, ...) kaydın
    `_REPLICA_COMPARED_FIELDS`'teki alanlarının UYUŞMAMASIDIR — bu, o
    ortak-önek konumunda iki kopyadan birinin BAĞIMSIZ olarak değiştirildiği
    anlamına gelir (hangisinin değiştirildiği bu karşılaştırmadan tek başına
    ÇIKARILAMAZ — `verify_against_anchor()`'ı HER İKİ dosyayla ayrı ayrı
    çalıştırmak veritabanıyla hangisinin uyuştuğunu gösterir).

    `usb_path` verilmezse `usb_anchor_path(hwid)` ile o an takılı USB'de
    bulunur. USB kopyası hiç yoksa (dosya yok, ya da USB o an takılı değil)
    ya da yerel kopya boşsa `anchors_checked=0` ile `ok=True` döner —
    karşılaştırılacak bir şey yok; bu "tutarlı" değil "ölçülmedi" anlamına
    gelir (bkz. `AnchorCheck.summary()`'nin aynı ayrımı).
    """
    local_target = local_path or anchor_path()
    local_records = read_anchors(local_target)

    usb_target = usb_path if usb_path is not None else usb_anchor_path(hwid)
    usb_records = read_anchors(usb_target) if usb_target is not None else []

    if not local_records or not usb_records:
        return AnchorCheck(ok=True, anchors_checked=0, problems=[], latest=None)

    problems: list[str] = []
    ortak = min(len(local_records), len(usb_records))

    for index in range(ortak):
        yerel = local_records[index]
        usb = usb_records[index]
        farklar = [
            f"{alan}: yerel {yerel.get(alan)!r}, USB {usb.get(alan)!r}"
            for alan in _REPLICA_COMPARED_FIELDS
            if yerel.get(alan) != usb.get(alan)
        ]
        if farklar:
            problems.append(f"Satır {index + 1} iki kopyada FARKLI — " + "; ".join(farklar))

    latest = local_records[ortak - 1]
    return AnchorCheck(
        ok=not problems, anchors_checked=ortak, problems=problems, latest=latest
    )
