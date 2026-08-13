"""
HYCLEUS — SafeZone: uygulamaya özel geçici çalışma alanı

Şifresi çözülmüş bir dosyanın diske inmesi gereken her durumda hedef burasıdır:
`data/safezone/`. Sistem TEMP'i BİLEREK kullanılmıyor.

Neden sistem TEMP olmaz
-----------------------
`%TEMP%` / `/tmp` üç ayrı nedenle yanlış yer:

  1. **Temizliği bizim elimizde değil.** İşletim sistemi ve "disk temizleme"
     araçları TEMP'i kendi takvimlerine göre siliyor — ve `unlink` ile
     siliyorlar, üzerine yazarak değil. Yani düz metin, biz haberdar bile
     olmadan diskte okunabilir hâlde kalır.
  2. **Kapsamı bizim dizinimizden geniş.** TEMP'i arama servisleri
     indeksliyor, yedekleme araçları kopyalıyor, başka süreçler geziyor.
     `data/` dizini ise uygulamanın kendi alanı; kullanıcının tam disk
     şifrelemesi ve dizin izinleri konusundaki kararları oraya birebir
     uygulanıyor.
  3. **Farklı birimde olabilir.** TEMP başka bir diskteyse `shred_file()`'ın
     üzerine yazma varsayımı bambaşka bir dosya sistemine taşınır ve
     hakkında hiçbir şey bilmediğimiz bir ortamda çalışır. `data/` ile aynı
     birimde kalmak, zaten SECURITY.md'de tarif edilmiş ortamda kalmak
     demektir.

Yaşam döngüsü
-------------
  · **Açılışta**  — `purge_orphans()`: içeride ne bulursa ARTAKALANDIR.
    Normal kapanış SafeZone'u boşaltıyor, dolayısıyla dolu bir SafeZone
    "önceki oturum çökmüş" demektir. Temizlenir ve denetime düşer.
  · **Çalışırken** — `safezone_file()` bağlam yöneticisi dosyayı ayırır ve
    blok biterken (hata olsa bile) imha eder.
  · **Kapanışta**  — `purge_on_exit()`: kalan her şey imha edilir.

Silme her zaman `CORE.secure_erase.shred_file()` ile: rastgele byte'larla
üzerine yaz → fsync → truncate → unlink. Aynı fonksiyon, aynı garantiler ve
aynı sınırlar (SSD wear leveling, kopyala-yaz dosya sistemleri — bkz.
secure_erase.py docstring'i).

Bugünkü durum — ileriye dönük altyapı
-------------------------------------
Şu an HYCLEUS düz metni HİÇBİR ZAMAN geçici bir dosyaya yazmıyor: indirme
akışı kullanıcının seçtiği yola doğrudan yazıyor, klasör indirme ZIP'i yine
kullanıcının seçtiği yola kuruyor. Yani bugün SafeZone'a yönlendirilecek
mevcut bir akış YOK.

Bu modül gelecekteki "aç / önizle" akışı (plan 3.2) için hazır duruyor.
Altyapıyı akıştan önce koymanın nedeni basit: o akış yazılırken en kolay
yol `tempfile.NamedTemporaryFile` olacak ve güvenli yol hazır değilse
kolay yol seçilir.
"""
from __future__ import annotations

import logging
import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from CORE.paths import data_dir
from CORE.secure_erase import shred_file

_log = logging.getLogger("hycleus.safezone")

#: SafeZone dizininin data/ altındaki adı.
SAFEZONE_DIRNAME = "safezone"

#: Dizini başka bir yere taşımak için (ör. RAM disk). Test izolasyonu da
#: bunu kullanıyor.
SAFEZONE_ENV_VAR = "HYCLEUS_SAFEZONE"

#: Dizin izinleri — yalnızca sahibi. Windows'ta etkisiz (aşağıdaki nota bak).
_DIR_MODE = 0o700


@dataclass(frozen=True)
class PurgeReport:
    """Bir temizlik turunun sonucu."""

    shredded: int = 0
    failed: int = 0
    #: İmha edilen dosyaların adları — denetim kaydına yazılır.
    names: list[str] = field(default_factory=list)
    #: (dosya adı, hata) çiftleri.
    errors: list[tuple[str, str]] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return self.failed == 0

    @property
    def had_leftovers(self) -> bool:
        return self.shredded > 0 or self.failed > 0

    def summary(self) -> str:
        if not self.had_leftovers:
            return "SafeZone temiz — artakalan dosya yok."
        parcalar = [f"{self.shredded} dosya güvenli silindi"]
        if self.failed:
            parcalar.append(f"{self.failed} dosya SİLİNEMEDİ")
        return "SafeZone: " + ", ".join(parcalar) + "."


def safezone_dir(*, create: bool = True) -> Path:
    """
    SafeZone dizininin yolu; `create` ise oluşturur.

    HYCLEUS_SAFEZONE tanımlıysa o kullanılır, değilse `data/safezone/`.

    İZİN NOTU — dürüst sınır: POSIX'te dizin 0o700 ile oluşturuluyor.
    Windows'ta `mode` yok sayılır ve dizin üst dizinin ACL'ini devralır;
    yani orada SafeZone'u koruyan şey `data/` dizininin izinleridir, bu kod
    değil. HYCLEUS bir Windows uygulaması olduğu için pratikte geçerli olan
    da budur — SECURITY.md §1'deki "oturum açmış OS kullanıcısı güvenilir"
    varsayımıyla tutarlı.
    """
    override = os.getenv(SAFEZONE_ENV_VAR)
    target = Path(override) if override else data_dir() / SAFEZONE_DIRNAME
    if create:
        target.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
    return target


def _iter_files(root: Path) -> Iterator[Path]:
    """SafeZone içindeki tüm dosyalar (alt dizinler dahil)."""
    if not root.exists():
        return
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def list_leftovers() -> list[Path]:
    """SafeZone'da duran dosyalar. Boşsa boş liste."""
    return list(_iter_files(safezone_dir(create=False)))


def allocate(suffix: str = "", prefix: str = "hycleus") -> Path:
    """
    SafeZone içinde benzersiz bir dosya yolu ayırır (dosyayı OLUŞTURMAZ).

    Ad rastgele: orijinal dosya adı SafeZone'da görünmemeli. Dizin listesi
    bile "şu belge açıldı" bilgisini sızdırır ve bu bilgi dosya imha
    edildikten sonra da dizin girdisinde kalabilir.
    """
    root = safezone_dir()
    while True:
        candidate = root / f"{prefix}_{secrets.token_hex(16)}{suffix}"
        if not candidate.exists():
            return candidate


def purge(*, reason: str = "manual") -> PurgeReport:
    """
    SafeZone'daki HER dosyayı güvenli siler ve boşalan alt dizinleri kaldırır.

    Tek bir dosya silinemezse (kilitli, izin yok) tarama DURMAZ — kalanlar
    yine imha edilir ve arıza raporda görünür. Erken çıkmak, silinebilecek
    dosyaları da diskte bırakırdı.
    """
    root = safezone_dir(create=False)
    shredded = 0
    failed = 0
    names: list[str] = []
    errors: list[tuple[str, str]] = []

    for path in _iter_files(root):
        try:
            if shred_file(path):
                shredded += 1
                names.append(path.name)
        except OSError as exc:
            failed += 1
            errors.append((path.name, f"{type(exc).__name__}: {exc}"))
            _log.error("SafeZone dosyası silinemedi: %s — %s", path, exc)
        except Exception as exc:  # beklenmeyen — diğer dosyaları engelleme
            failed += 1
            errors.append((path.name, f"{type(exc).__name__}: {exc}"))
            _log.exception("SafeZone dosyası silinirken beklenmeyen hata: %s", path)

    # Boşalan alt dizinleri kaldır — SafeZone'un kökü kalır.
    if root.exists():
        for path in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if path.is_dir():
                try:
                    path.rmdir()
                except OSError:
                    pass  # boş değil ya da kilitli — sorun değil

    report = PurgeReport(shredded=shredded, failed=failed, names=names, errors=errors)
    if report.had_leftovers:
        _log.info("SafeZone temizliği (%s): %s", reason, report.summary())
    return report


def _log_purge(db: Any, report: PurgeReport, *, action: str, reason: str) -> None:
    """Temizlik sonucunu denetim kaydına yazar (hash zincirinden geçer)."""
    if db is None or not report.had_leftovers:
        return
    detail = f"reason={reason} shredded={report.shredded} failed={report.failed}"
    if report.names:
        gorunen = ", ".join(report.names[:10])
        if len(report.names) > 10:
            gorunen += f", … (+{len(report.names) - 10})"
        detail += f" files=[{gorunen}]"
    try:
        db.log(action, detail=detail)
    except Exception as exc:  # denetim yazılamadıysa temizlik yine de olmuştur
        _log.error("SafeZone temizliği denetim kaydına yazılamadı: %s", exc)


def purge_orphans(db: Any = None) -> PurgeReport:
    """
    Açılış temizliği — SafeZone'da ne varsa ÖNCEKİ OTURUMDAN kalmıştır.

    Normal kapanış SafeZone'u boşaltıyor (purge_on_exit). Dolayısıyla
    açılışta dolu bir SafeZone yalnızca bir anlama gelir: önceki oturum
    çökmüş, elektrik kesilmiş ya da süreç öldürülmüş. Dosyalar imha edilir
    ve olay `safezone_orphans_purged` olarak denetime düşer — sessizce
    temizlemek, bir çökme kanıtını da silmek olurdu.
    """
    report = purge(reason="startup_orphans")
    if report.had_leftovers:
        _log.warning(
            "Önceki oturumdan %d artakalan SafeZone dosyası bulundu — "
            "uygulama düzgün kapanmamış olabilir.", report.shredded + report.failed,
        )
    _log_purge(db, report, action="safezone_orphans_purged", reason="startup_orphans")
    return report


def purge_on_exit(db: Any = None) -> PurgeReport:
    """Kapanış temizliği — SafeZone'da kalan her şey imha edilir."""
    report = purge(reason="shutdown")
    _log_purge(db, report, action="safezone_purged", reason="shutdown")
    return report


@contextmanager
def safezone_file(suffix: str = "", prefix: str = "hycleus") -> Iterator[Path]:
    """
    SafeZone'da geçici bir dosya ayırır ve blok biterken güvenle imha eder.

    Şifresi çözülmüş içeriğin diske inmesi gereken akışların kullanacağı
    arayüz budur::

        with safezone_file(suffix=".pdf") as tmp:
            tmp.write_bytes(plaintext)
            goster(tmp)
        # blok bitti — dosya üzerine yazılıp silindi

    İmha `finally` içinde: blok bir istisnayla çıksa da dosya kalmaz. Bir
    şey ters giderse imha hatası YUTULMAZ, loglanır — ama asıl istisnanın
    üstünü örtmemesi için yeniden fırlatılmaz.
    """
    path = allocate(suffix=suffix, prefix=prefix)
    try:
        yield path
    finally:
        try:
            if shred_file(path):
                _log.debug("SafeZone dosyası imha edildi: %s", path.name)
        except Exception as exc:
            _log.error("SafeZone dosyası imha edilemedi: %s — %s", path, exc)
