"""
HYCLEUS — Şifreli yedekleme ve doğrulanabilir geri yükleme

Kapattığı boşluk: Shamir 2-of-3 kurtarma (2.1) ANAHTAR kaybını çözüyor,
ama diskin kendisi giderse (arıza, çalınma, silinme) veri yine kayıp.
Bu modül MEDYA kaybını kapatıyor. İkisi ayrı sorun, ayrı çözüm — ve
aşağıdaki "neden .hclv yedeklenmiyor" kararının dayanağı bu.


KARAR 1 — `.hcl` dosyaları OLDUĞU GİBİ kopyalanıyor
----------------------------------------------------
Sarmalama şifrelemesi EKLENMİYOR. Dosyalar zaten AES-256-GCM ile, dosya
başına ayrı nonce'la şifreli. İkinci bir katman:

  · gizlilik KAZANDIRMIYOR — `.hcl` başlığındaki AAD (özgün ad, düz metin
    SHA-256, zaman damgaları, user_id, hwid) kasada da okunabilir durumda
    (SECURITY.md §3). Yedekte sarmalamak, kaynak makinede zaten açık olan
    bir şeyi yalnızca yedekte gizlerdi; saldırgan diski okuyabiliyorsa
    ikisine de erişiyor. AAD maruziyeti düzeltilecekse bu bir FORMAT
    değişikliği olur, bir yedekleme özelliği değil.
  · ikinci bir anahtar yönetimi sorunu yaratırdı,
  · her yedekte tüm kasayı yeniden şifrelemek demekti.

Bedeli açık: yedekteki dosya adları (`sozlesme.docx.hcl`) kasadakiyle aynı
şeyi sızdırıyor — ne fazlası ne eksiği.


KARAR 2 — VERİTABANI şifreleniyor, asıl sorun o
------------------------------------------------
SECURITY.md §3 açıkça söylüyor: SQLite veritabanı ŞİFRESİZ. Dosya adları,
kullanıcı kayıtları, roller, HWID'ler ve denetim günlüğünün tamamı diskte
düz metin. Bunu olduğu gibi harici bir diske kopyalamak, binadan çıkan bir
USB'ye bütün envanteri düz metin yazmak olurdu — kasanın kendisinden daha
kötü, çünkü harici medya kaybolmaya çok daha yatkın.

Bu yüzden gereken tablolar kanonik JSON'a çıkarılıp `encrypt_file()` ile
şifreleniyor ve yedeğe `metadata.hcl` olarak giriyor. Yeni bir kripto
YOK — kasadaki dosyalarla aynı ilkel, aynı anahtar, aynı garanti.


KARAR 3 — anahtar kasası (`.hclv`) YEDEKLENMİYOR
-------------------------------------------------
Bilerek. `.hclv` içinde Argon2id ile korunan `share_1` duruyor. Yedeğe
konsaydı, harici medyayı ele geçiren biri çevrimdışı kaba kuvvet için
hazır bir hedef bulurdu — ve harici medya tam olarak kaybolan şeydir.

Anahtar kaybı zaten 2.1'in işi: Shamir kurtarma parçasıyla `share_1`
yeniden üretiliyor. Ayrım net kalsın diye burada tekrarlanmıyor:

    yedek  → medya kaybı
    Shamir → anahtar kaybı

Sonuç: bu yedekten geri dönmek için anahtarınız ÇALIŞIYOR olmalı. Anahtar
da kaybolduysa önce 2.1, sonra bu.


KARAR 4 — hangi tablolar
------------------------
Yedeklenen (ve geri yüklenebilen):
    files, folders, tags, file_tags, retention_profiles, quarantine

Yedeklenen ama GERİ YÜKLENMEYEN:
    audit_log — uyumluluk için saklanması değerli, ama başka bir
    veritabanına yazmak zararlı olurdu: zincir çıpalanmış (§4.6) ve
    kopyalanan kayıtlar aynı geçmişi iddia eden İKİNCİ bir zincir
    yaratırdı, üstelik çıpayla tutmayan. Geri yüklemede ayrı bir dosyaya
    çıkarılıyor: okunabilir, ama canlı zincire karışmıyor.

Hiç yedeklenmeyen:
    users, usb_tokens   — kimlik ve cihaz kaydı; parola hash'leri ve
                          (göç etmemişse) share_2 taşıyor. Başka bir
                          makineye taşınmaları zaten yanlış olurdu.
    settings            — `audit_chain_start_id`, `integrity_last_sweep`
                          gibi O VERİTABANINA ait durum. Geri yüklemek
                          zincir ve tarama durumunu bozardı.
    login_attempts      — geçici durum.


Yedek düzeni
------------
    <hedef>/
      manifest.json      düz metin — biçim, tarih, sayılar, her dosyanın
                         ŞİFRELİ hâlinin SHA-256'sı
      metadata.hcl       şifreli tablo dökümü
      files/*.hcl        kasadan olduğu gibi kopyalar

Manifestodaki özetler CIPHERTEXT'in özeti; düz metin özeti DEĞİL. İki
sebep: (a) anahtar olmadan bozulma/kesilme tespit edilebiliyor, (b) düz
metin özeti bir belgeyi çözmeden DOĞRULAMAYA yarıyor ve onu düz metin bir
manifestoya yazmak §3'teki maruziyeti gereksizce çoğaltırdı.

Manifesto düz metin olduğu için DEĞİŞTİRİLEBİLİR. Buna karşı aynı liste
`metadata.hcl` içinde de duruyor; anahtarla yapılan doğrulama ikisini
karşılaştırıyor ve uyuşmazlığı bildiriyor.
"""
from __future__ import annotations

import hashlib
import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from CORE.crypto import AuthenticationError, decrypt_file, encrypt_file, verify_file

_log = logging.getLogger("hycleus.backup")

FORMAT = "HYCLEUS-BACKUP-V1"
MANIFEST_NAME = "manifest.json"
METADATA_NAME = "metadata.hcl"
FILES_DIRNAME = "files"

_CHUNK = 64 * 1024

#: Yedeklenen ve geri yüklenebilen tablolar.
RESTORABLE_TABLES = (
    "files", "folders", "tags", "file_tags", "retention_profiles", "quarantine",
)

#: Yedeklenen ama geri YÜKLENMEYEN tablolar — gerekçe modül docstring'inde.
REFERENCE_TABLES = ("audit_log",)

#: Hiç yedeklenmeyenler; belge amaçlı, kodda kullanılmıyor.
EXCLUDED_TABLES = (
    "users", "usb_tokens", "settings", "login_attempts",
)


class BackupError(Exception):
    """Yedekleme, doğrulama ya da geri yükleme başarısız olduğunda fırlar."""


@dataclass(frozen=True)
class BackupEntry:
    """Yedekteki tek bir dosya."""

    name: str
    size: int
    sha256: str          # ŞİFRELİ dosyanın özeti — bkz. modül docstring'i


@dataclass
class BackupReport:
    """Bir yedekleme işleminin sonucu."""

    path: Path
    file_count: int = 0
    total_bytes: int = 0
    skipped: list[str] = field(default_factory=list)
    created_at: str = ""

    def summary(self) -> str:
        mb = self.total_bytes / 1024 / 1024
        s = f"{self.file_count} dosya, {mb:.1f} MB → {self.path}"
        if self.skipped:
            s += f" ({len(self.skipped)} dosya atlandı)"
        return s


@dataclass
class VerifyReport:
    """Bir yedek doğrulamasının sonucu."""

    ok: bool = True
    checked: int = 0
    missing: list[str] = field(default_factory=list)
    corrupt: list[str] = field(default_factory=list)
    auth_failed: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    manifest_mismatch: bool = False
    deep: bool = False
    error: str | None = None
    #: Kullanıcı doğrulamayı yarıda kesti.
    #:
    #: `ok` bu durumda ZORLA False. Yarım kalmış bir tarama "sağlam"
    #: diyemez: 500 dosyanın 3'ünü okuyup durmakla 3 dosyalık sağlam bir
    #: yedeği doğrulamak, rapordan ayırt edilemez olurdu. Yanlış yön
    #: burada "sağlam sanmak".
    cancelled: bool = False
    #: Manifestoda listelenen toplam dosya sayısı. `checked` yarıda
    #: kesilmiş bir taramada bundan küçük kalır; ikisi birlikte "ne
    #: kadarı bakıldı" sorusunu yanıtlıyor.
    total: int = 0

    def summary(self) -> str:
        if self.error:
            return f"Yedek OKUNAMADI — {self.error}"
        if self.cancelled:
            return (
                f"Doğrulama YARIDA KESİLDİ — {self.total} dosyanın "
                f"{self.checked} tanesine bakıldı."
            )
        if self.ok:
            derinlik = "GCM doğrulaması dahil" if self.deep else "yalnızca özet"
            return f"Yedek SAĞLAM — {self.checked} dosya ({derinlik})."
        parcalar = []
        if self.missing:
            parcalar.append(f"{len(self.missing)} eksik")
        if self.corrupt:
            parcalar.append(f"{len(self.corrupt)} bozuk")
        if self.auth_failed:
            parcalar.append(f"{len(self.auth_failed)} doğrulanamadı")
        if self.manifest_mismatch:
            parcalar.append("manifesto uyuşmuyor")
        return "Yedek KUSURLU — " + ", ".join(parcalar) + "."


@dataclass
class RestoreReport:
    """Bir geri yükleme işleminin sonucu."""

    dest: Path
    restored: int = 0
    metadata_tables: dict[str, int] = field(default_factory=dict)
    reference_written: list[str] = field(default_factory=list)

    def summary(self) -> str:
        t = ", ".join(f"{k}={v}" for k, v in sorted(self.metadata_tables.items()))
        return f"{self.restored} dosya geri yüklendi → {self.dest}  [{t}]"


# ══════════════════════════════════════════════════════════════════════════════
# Yardımcılar
# ══════════════════════════════════════════════════════════════════════════════


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(payload: dict) -> bytes:
    """
    Deterministik JSON — aynı girdi her zaman aynı bayt dizisi.

    `CORE/audit_chain.py` ile aynı gerekçe: anahtar sırası garanti
    edilmezse aynı içerik farklı özetler üretir ve doğrulama anlamsızlaşır.
    """
    return json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _dump_tables(db: Any, tables: tuple[str, ...]) -> dict[str, list[dict]]:
    """Tabloları JSON'a çevrilebilir sözlük listelerine çıkarır."""
    dokum: dict[str, list[dict]] = {}
    for tablo in tables:
        try:
            rows = db.fetchall(f"SELECT * FROM {tablo}")  # noqa: S608 — sabit liste
        except Exception as exc:
            _log.warning("tablo okunamadı: %s (%s)", tablo, exc)
            dokum[tablo] = []
            continue
        dokum[tablo] = [
            {k: r[k] for k in r.keys() if not isinstance(r[k], bytes)} for r in rows
        ]
    return dokum


# ══════════════════════════════════════════════════════════════════════════════
# 1. Yedekleme
# ══════════════════════════════════════════════════════════════════════════════


def create_backup(
    db: Any,
    dest: Path | str,
    key: bytes,
    *,
    vault_dir: Path | str | None = None,
    user_id: int = 1,
    hwid: str | None = None,
    on_progress: Callable[[int, int, str], None] | None = None,
) -> BackupReport:
    """
    Kasayı ve metadata'yı `dest` altına yedekler.

    Args:
        vault_dir: `.hcl` dosyalarının bulunduğu dizin. Verilmezse
            `CORE.crypto._QUARANTINE_DIR`.
        on_progress: (sıra, toplam, ad) — arayüzün ilerleme göstermesi için.

    Raises:
        BackupError — hedef yazılabilir değilse ya da metadata
            şifrelenemezse. TEK BİR dosyanın kopyalanamaması yedeği
            durdurmuyor; atlananlar rapora giriyor ve manifestoya
            YAZILMIYOR (yoksa doğrulama her seferinde "eksik" derdi).
    """
    from CORE import crypto

    kaynak = Path(vault_dir) if vault_dir else crypto._QUARANTINE_DIR
    dest = Path(dest)
    hedef_dosyalar = dest / FILES_DIRNAME

    try:
        hedef_dosyalar.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BackupError(f"Yedek dizini oluşturulamadı: {exc}") from exc

    hcl_listesi = sorted(p for p in kaynak.glob("*.hcl") if p.is_file()) \
        if kaynak.exists() else []

    rapor = BackupReport(path=dest, created_at=_now())
    girdiler: list[BackupEntry] = []

    for i, src in enumerate(hcl_listesi, start=1):
        if on_progress:
            on_progress(i, len(hcl_listesi), src.name)
        hedef = hedef_dosyalar / src.name
        try:
            shutil.copy2(src, hedef)
            boyut = hedef.stat().st_size
            girdiler.append(BackupEntry(src.name, boyut, _sha256(hedef)))
            rapor.file_count += 1
            rapor.total_bytes += boyut
        except OSError as exc:
            # Kilitli ya da okunamayan tek bir dosya bütün yedeği
            # düşürmemeli; eksik bir yedek, hiç yedek olmamasından iyidir
            # — yeter ki EKSİK OLDUĞU görünsün.
            _log.warning("yedeklenemedi: %s (%s)", src.name, exc)
            rapor.skipped.append(src.name)
            hedef.unlink(missing_ok=True)

    # ── Metadata: şifreli ────────────────────────────────────────────────
    icerik = {
        "format": FORMAT,
        "created_at": rapor.created_at,
        "tables": _dump_tables(db, RESTORABLE_TABLES),
        "reference": _dump_tables(db, REFERENCE_TABLES),
        # Manifestonun şifreli kopyası: düz metin manifesto değiştirilirse
        # anahtarla yapılan doğrulama farkı görüyor.
        "entries": [
            {"name": e.name, "size": e.size, "sha256": e.sha256} for e in girdiler
        ],
    }

    ham = dest / "_metadata.json"
    try:
        ham.write_bytes(_canonical(icerik))
        encrypt_file(
            ham, key, user_id=user_id, hwid=hwid,
            dst=dest / METADATA_NAME, filename="metadata.json",
        )
    except Exception as exc:
        raise BackupError(f"Metadata şifrelenemedi: {exc}") from exc
    finally:
        # Düz metin döküm ASLA yedekte kalmamalı — içinde bütün dosya
        # adları, etiketler ve denetim günlüğü var.
        if ham.exists():
            _shred_plaintext(ham)

    metadata_yolu = dest / METADATA_NAME
    manifest = {
        "format": FORMAT,
        "created_at": rapor.created_at,
        "hwid": hwid,
        "file_count": rapor.file_count,
        "total_bytes": rapor.total_bytes,
        "metadata": {
            "name": METADATA_NAME,
            "size": metadata_yolu.stat().st_size,
            "sha256": _sha256(metadata_yolu),
        },
        "entries": [
            {"name": e.name, "size": e.size, "sha256": e.sha256} for e in girdiler
        ],
    }
    (dest / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    try:
        db.log(
            "backup_created", user_id=user_id,
            detail=(f"dest={dest} files={rapor.file_count} "
                    f"bytes={rapor.total_bytes} skipped={len(rapor.skipped)}"),
        )
    except Exception as exc:  # denetim kaydı yedeği engellemesin
        _log.warning("backup_log_failed  exc=%s", exc)

    # B-015: hatırlatma kapısını ilerlet. Yedek BURADA tamamlandı — damgayı
    # arayüzün yazmasına bırakmak, CLI'dan alınan yedeklerin hatırlatmayı
    # susturmaması demek olurdu (CORE/backup_cli.py aynı fonksiyonu
    # çağırıyor). Denetim kaydı gibi bu da yedeği engellemiyor.
    try:
        from CORE.backup_reminder import yedek_alindi
        yedek_alindi(db, zaman=rapor.created_at)
    except Exception as exc:
        _log.warning("backup_reminder_update_failed  exc=%s", exc)

    _log.info("backup  %s", rapor.summary())
    return rapor


def _shred_plaintext(path: Path) -> None:
    """Geçici düz metin dökümü güvenli siler."""
    from CORE.secure_erase import shred_file

    try:
        shred_file(path)
    except OSError as exc:  # pragma: no cover — dosya kilitli
        _log.error("gecici dokum silinemedi: %s (%s)", path, exc)
        path.unlink(missing_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Doğrulama — GERİ YÜKLEMEDEN
# ══════════════════════════════════════════════════════════════════════════════


def read_manifest(backup_dir: Path | str) -> dict:
    """Manifestoyu okur ve biçimini doğrular."""
    yol = Path(backup_dir) / MANIFEST_NAME
    if not yol.is_file():
        raise BackupError(f"Manifesto bulunamadı: {yol}")
    try:
        manifest = json.loads(yol.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError(f"Manifesto okunamadı: {exc}") from exc
    if manifest.get("format") != FORMAT:
        raise BackupError(
            f"Desteklenmeyen yedek biçimi: {manifest.get('format')!r} "
            f"(bu sürüm {FORMAT} okuyor)"
        )
    return manifest


def verify_backup(
    backup_dir: Path | str,
    *,
    key: bytes | None = None,
    hwid: str | None = None,
    on_progress: Callable[[int, int, str], None] | None = None,
    should_continue: Callable[[], bool] | None = None,
) -> VerifyReport:
    """
    Yedeği GERİ YÜKLEMEDEN doğrular.

    İki derinlik:

      · **Anahtarsız** — manifesto okunabiliyor mu, listelenen her dosya
        yerinde mi, boyutları ve ŞİFRELİ özetleri tutuyor mu. Bozulmayı,
        kesilmeyi ve eksik dosyayı yakalıyor. Anahtar olmadan çalışması
        önemli: yedeğin sağlamlığını kontrol etmek için kasayı açmak
        gerekmemeli.
      · **Anahtarlı** (`key` verilirse) — ek olarak her `.hcl` için GCM
        tag doğrulaması (`CORE.crypto.verify_file()`). Bu, düz metni
        BELLEĞE ALMADAN yapılıyor; o ilkelin varlık sebebi zaten bu.
        Ayrıca manifestonun şifreli kopyayla tutarlılığı sınanıyor.

    Hiçbir durumda hedefe YAZMIYOR.

    Args:
        on_progress: (sıra, toplam, ad) — `create_backup()` ile aynı
            sözleşme.
        should_continue: Her dosyadan ÖNCE soruluyor; `False` dönerse
            tarama durur ve rapor `cancelled=True` ile döner.

            Neden `on_progress`'in dönüş değeri DEĞİL: aynı adı taşıyan
            parametrenin `create_backup()`'ta `None` döndürüp burada
            anlam taşıması, iki çağrı yerini sessizce ayrıştırırdı.
            Ayrı ad, ayrı iş.

            Neden iptal gerekiyor: doğrulama her baytı OKUYOR (derin
            modda iki kez — bir kez özet, bir kez GCM). Ölçüldü, işlemci
            tarafında ~1,3 GB/s; ama yedeğin doğal yeri harici disk ve
            orada sınır diskin okuma hızı. 50 GB'lık bir yedek ~120 MB/s
            bir diskte on dakikaları buluyor. Durdurulamayan on dakikalık
            bir kontrol, çalıştırılmayan bir kontrole dönüşür.
    """
    backup_dir = Path(backup_dir)
    rapor = VerifyReport(deep=key is not None)

    try:
        manifest = read_manifest(backup_dir)
    except BackupError as exc:
        rapor.ok = False
        rapor.error = str(exc)
        return rapor

    dosya_dizini = backup_dir / FILES_DIRNAME
    girdiler = manifest.get("entries", [])
    beklenen = {e["name"] for e in girdiler}
    rapor.total = len(girdiler)

    for sira, girdi in enumerate(girdiler, start=1):
        if should_continue is not None and not should_continue():
            rapor.cancelled = True
            rapor.ok = False
            return rapor
        if on_progress:
            on_progress(sira, len(girdiler), girdi["name"])
        yol = dosya_dizini / girdi["name"]
        rapor.checked += 1
        if not yol.is_file():
            rapor.missing.append(girdi["name"])
            continue
        if yol.stat().st_size != girdi["size"] or _sha256(yol) != girdi["sha256"]:
            rapor.corrupt.append(girdi["name"])
            continue
        if key is not None:
            try:
                verify_file(yol, key, hwid=hwid)
            except AuthenticationError:
                rapor.auth_failed.append(girdi["name"])
            except (ValueError, OSError):
                rapor.corrupt.append(girdi["name"])

    # metadata.hcl
    meta = manifest.get("metadata") or {}
    meta_yolu = backup_dir / meta.get("name", METADATA_NAME)
    if not meta_yolu.is_file():
        rapor.missing.append(meta.get("name", METADATA_NAME))
    elif meta.get("sha256") and _sha256(meta_yolu) != meta["sha256"]:
        rapor.corrupt.append(meta.get("name", METADATA_NAME))
    elif key is not None:
        try:
            icerik = _read_metadata(meta_yolu, key, hwid=hwid)
        except BackupError:
            rapor.auth_failed.append(meta.get("name", METADATA_NAME))
        else:
            # Düz metin manifesto değiştirilmiş mi — şifreli kopyayla karşılaştır.
            sifreli = {
                (e["name"], e["size"], e["sha256"]) for e in icerik.get("entries", [])
            }
            duz = {
                (e["name"], e["size"], e["sha256"])
                for e in manifest.get("entries", [])
            }
            if sifreli != duz:
                rapor.manifest_mismatch = True

    # Manifestoda olmayan fazladan dosyalar — hata değil, bilgi.
    if dosya_dizini.is_dir():
        rapor.extra = sorted(
            p.name for p in dosya_dizini.iterdir()
            if p.is_file() and p.name not in beklenen
        )

    rapor.ok = not (
        rapor.missing or rapor.corrupt or rapor.auth_failed or rapor.manifest_mismatch
    )
    return rapor


def _read_metadata(path: Path, key: bytes, *, hwid: str | None = None) -> dict:
    """`metadata.hcl`'i çözer ve JSON'a ayrıştırır."""
    try:
        icerik, _meta = decrypt_file(path, key, hwid=hwid)
    except Exception as exc:
        raise BackupError(f"Metadata çözülemedi: {exc}") from exc
    try:
        return json.loads(icerik.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError(f"Metadata ayrıştırılamadı: {exc}") from exc
    finally:
        del icerik


# ══════════════════════════════════════════════════════════════════════════════
# 3. Geri yükleme
# ══════════════════════════════════════════════════════════════════════════════


def restore_backup(
    backup_dir: Path | str,
    dest: Path | str,
    key: bytes,
    *,
    hwid: str | None = None,
    overwrite: bool = False,
    skip_verify: bool = False,
    on_progress: Callable[[int, int, str], None] | None = None,
) -> RestoreReport:
    """
    Yedeği AYRI BİR KONUMA geri yükler.

    Neden canlı kasanın üzerine yazmıyor
    ------------------------------------
    Geri yükleme çoğu zaman panikle yapılan bir işlem ve geri alınamaz.
    Canlı kasanın üzerine yazmak iki şeyi riske atardı: yedekten SONRA
    eklenmiş dosyalar (yedekte yoklar, silinirlerdi) ve yedeğin kendisi
    bozuksa geriye dönülecek hiçbir şey kalmaması.

    Bu yüzden hedef ayrı bir dizin ve BOŞ olmak zorunda. Dolu bir dizine
    yazmak `overwrite=True` istiyor — sessizce değil, açıkça. Kullanıcı
    sonucu inceleyip yerine kendisi taşıyor.

    Metadata `metadata.json` olarak yazılıyor; canlı veritabanına
    DOKUNULMUYOR (bkz. `apply_metadata`). `audit_log` ayrı bir dosyaya
    çıkıyor — gerekçe modül docstring'inde.

    Raises:
        BackupError — doğrulama düşerse (atlanmadıysa), hedef doluysa
            ya da yazma başarısız olursa.
    """
    backup_dir = Path(backup_dir)
    dest = Path(dest)

    if not skip_verify:
        dogrulama = verify_backup(backup_dir, key=key, hwid=hwid)
        if not dogrulama.ok:
            raise BackupError(
                f"Yedek doğrulanamadı, geri yükleme YAPILMADI — "
                f"{dogrulama.summary()}"
            )

    if dest.exists() and any(dest.iterdir()) and not overwrite:
        raise BackupError(
            f"Hedef dizin boş değil: {dest}\n"
            "Var olan veriyi ezmemek için geri yükleme durduruldu. "
            "Boş bir dizin seçin ya da bilerek üzerine yazmak için "
            "overwrite=True verin."
        )

    manifest = read_manifest(backup_dir)
    hedef_dosyalar = dest / FILES_DIRNAME
    hedef_dosyalar.mkdir(parents=True, exist_ok=True)

    rapor = RestoreReport(dest=dest)
    girdiler = manifest.get("entries", [])
    for i, girdi in enumerate(girdiler, start=1):
        if on_progress:
            on_progress(i, len(girdiler), girdi["name"])
        kaynak = backup_dir / FILES_DIRNAME / girdi["name"]
        shutil.copy2(kaynak, hedef_dosyalar / girdi["name"])
        rapor.restored += 1

    icerik = _read_metadata(backup_dir / METADATA_NAME, key, hwid=hwid)
    tablolar = icerik.get("tables", {})
    (dest / "metadata.json").write_text(
        json.dumps(tablolar, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    rapor.metadata_tables = {ad: len(satirlar) for ad, satirlar in tablolar.items()}

    for ad, satirlar in (icerik.get("reference") or {}).items():
        yol = dest / f"{ad}.json"
        yol.write_text(
            json.dumps(satirlar, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        rapor.reference_written.append(yol.name)

    _log.info("restore  %s", rapor.summary())
    return rapor


def apply_metadata(db: Any, metadata: dict, *, user_id: int | None = None) -> dict[str, int]:
    """
    Geri yüklenen tablo dökümünü CANLI veritabanına yazar.

    `restore_backup()`'tan AYRI tutuldu bilerek: geri yükleme dosyaları
    diske koyuyor ve orada duruyor; veritabanına dokunmak ayrı, geri
    alınamaz bir karar. İkisini tek çağrıda birleştirmek, kullanıcının
    yedeği inceleme fırsatını elinden alırdı.

    `INSERT OR REPLACE` kullanıyor — aynı id'li satır varsa yedektekiyle
    değişiyor. Bu, "yedek doğru olan" varsayımı; çağıran bunu bilerek
    seçmeli.

    Returns:
        {tablo: yazılan_satır_sayısı}
    """
    yazilan: dict[str, int] = {}
    for tablo in RESTORABLE_TABLES:
        satirlar = metadata.get(tablo) or []
        if not satirlar:
            yazilan[tablo] = 0
            continue
        sutunlar = list(satirlar[0].keys())
        yer = ", ".join("?" for _ in sutunlar)
        sql = (
            f"INSERT OR REPLACE INTO {tablo} ({', '.join(sutunlar)}) VALUES ({yer})"
        )  # noqa: S608 — tablo adı sabit listeden
        n = 0
        for satir in satirlar:
            db.execute(sql, tuple(satir.get(c) for c in sutunlar))
            n += 1
        yazilan[tablo] = n

    db.log(
        "backup_metadata_applied", user_id=user_id,
        detail=" ".join(f"{k}={v}" for k, v in sorted(yazilan.items())),
    )
    return yazilan


def latest_backup(parent: Path | str) -> Path | None:
    """
    Bir dizin altındaki en yeni yedeği bulur.

    Yedekler `hycleus-backup-<tarih>` biçiminde adlandırıldığında işe
    yarıyor; CLI varsayılan adı böyle üretiyor.
    """
    parent = Path(parent)
    if not parent.is_dir():
        return None
    adaylar = [
        p for p in parent.iterdir()
        if p.is_dir() and (p / MANIFEST_NAME).is_file()
    ]
    if not adaylar:
        return None
    return max(adaylar, key=lambda p: (p / MANIFEST_NAME).stat().st_mtime)


def default_backup_name(*, now: datetime | None = None) -> str:
    an = now or datetime.now(timezone.utc)
    return f"hycleus-backup-{an.strftime('%Y%m%d-%H%M%S')}"


__all__ = [
    "EXCLUDED_TABLES",
    "FORMAT",
    "MANIFEST_NAME",
    "METADATA_NAME",
    "REFERENCE_TABLES",
    "RESTORABLE_TABLES",
    "BackupEntry",
    "BackupError",
    "BackupReport",
    "RestoreReport",
    "VerifyReport",
    "apply_metadata",
    "create_backup",
    "default_backup_name",
    "latest_backup",
    "read_manifest",
    "restore_backup",
    "verify_backup",
]
