"""
HYCLEUS — İmha Odası geri sayımı

İmha Odası'na taşınan dosya `files.expires_at` alıyor ve arayüzde saniyede
bir güncellenen bir geri sayım gösteriliyor. Sayacın matematiği — kalan
sürenin hesaplanması, biçimlendirilmesi, hangi eşikte hangi rengin
gösterileceği ve süresi dolanların tespiti — buradaydı değil, bir Qt
metodunun (`_tick_expiry`) ortasındaydı: 85 satırlık bir döngü içinde tablo
hücresi güncellemeleriyle iç içe.

Bu modül o matematiği ayırıyor. Kazanç ölçülebilir: geri sayımın eşik
davranışı (10 dk kırmızı, 1 saat sarı) artık saniye saniye test edilebiliyor;
önce edilemiyordu, çünkü bir QTableWidget ve çalışan bir olay döngüsü
gerekiyordu.

Renk ADI döndürülür, renk KODU değil
------------------------------------
`urgency()` "red" / "yellow" / "green" döndürüyor; `#f38ba8` değil. Somut
renk temaya bağlı (koyu/açık) ve tema arayüzün sorunu. CORE'un bildiği şey
"bu dosya acil mi", hangi tonda gösterileceği değil.

TTL varsayılanı neden burada
----------------------------
`imha_ttl_hours` ayarını okuyan üç ayrı yer vardı ve üçü de kendi
`try/except`'inde 24'e düşüyordu. Tek yerde toplandı; ayarın bozuk olması
sayacı kurmayı engellememeli ama sessizce farklı bir varsayılana da
düşmemeli.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

_log = logging.getLogger("hycleus.expiry")

_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

#: İmha TTL'inin tutulduğu settings anahtarı.
TTL_SETTING = "imha_ttl_hours"

#: Ayar okunamazsa kullanılan süre.
DEFAULT_TTL_HOURS = 24

#: Aciliyet eşikleri (saniye). Sıra önemli: ilk eşleşen kazanır.
CRITICAL_SECONDS = 600     # 10 dk → "red"
WARNING_SECONDS = 3600     # 1 saat → "yellow"


def _utcnow() -> datetime:
    """Şimdiki UTC zamanı. Testler bunu monkeypatch'ler."""
    return datetime.now(timezone.utc)


def parse_expires_at(value: str | None) -> datetime | None:
    """
    `files.expires_at` metnini datetime'a çevirir; boş/bozuksa None.

    None dönmek "süre belirlenmemiş" demek ve bu geçerli bir durum:
    saklama süresi süpürmesi süresi dolan dosyaya bilerek `expires_at = NULL`
    yazıyor (bkz. CORE/disposal.py — sayaç kurmak onaysız imha olurdu).
    """
    if not value:
        return None
    try:
        return datetime.strptime(value, _TS_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        _log.warning("expires_at ayrıştırılamadı: %r", value)
        return None


def format_expires_at(moment: datetime) -> str:
    """datetime'ı `files.expires_at` biçimine çevirir."""
    return moment.strftime(_TS_FORMAT)


def ttl_hours(db: Any) -> int:
    """
    Yapılandırılmış İmha TTL süresi (saat); okunamazsa DEFAULT_TTL_HOURS.

    Arayüzdeki `_get_imha_ttl_hours()` ile birebir aynı davranış — üç ayrı
    kopyası vardı, burada birleşti.
    """
    try:
        return int(db.get_setting(TTL_SETTING, str(DEFAULT_TTL_HOURS)))
    except (TypeError, ValueError):
        _log.warning("%s sayıya çevrilemedi — %d saat kullanılıyor",
                     TTL_SETTING, DEFAULT_TTL_HOURS)
        return DEFAULT_TTL_HOURS
    except Exception as exc:
        _log.warning("%s okunamadı (%s) — %d saat kullanılıyor",
                     TTL_SETTING, exc, DEFAULT_TTL_HOURS)
        return DEFAULT_TTL_HOURS


def expiry_from_now(db: Any, *, now: datetime | None = None) -> str:
    """
    "Şimdi + TTL" değerini `expires_at` biçiminde döndürür.

    Dosya İmha Odası'na taşınırken kullanılıyor; dört ayrı çağrı yerinde
    aynı iki satır yazılıydı.
    """
    başlangıç = now or _utcnow()
    return format_expires_at(başlangıç + timedelta(hours=ttl_hours(db)))


def remaining_seconds(expires_at: str | None, *, now: datetime | None = None) -> float | None:
    """
    Kalan süre (saniye); süre belirlenmemişse None.

    NEGATİF DÖNEBİLİR — süresi geçmiş bir dosya için eksi değer döner ve
    çağıran bunu `<= 0` diye kontrol edip imha eder. Sıfıra kırpmak, "tam
    şu an doldu" ile "üç gün önce doldu"yu ayırt edilemez yapardı.
    """
    hedef = parse_expires_at(expires_at)
    if hedef is None:
        return None
    return (hedef - (now or _utcnow())).total_seconds()


def is_expired(expires_at: str | None, *, now: datetime | None = None) -> bool:
    """
    Süre doldu mu? Süre belirlenmemişse False.

    Sınır dahil: kalan süre tam 0 ise DOLMUŞ sayılır — arayüzdeki
    `remaining <= 0` kontrolüyle birebir aynı.
    """
    kalan = remaining_seconds(expires_at, now=now)
    return kalan is not None and kalan <= 0


def format_countdown(seconds: float) -> str:
    """
    Kalan saniyeyi `SS:DD:SS` biçiminde yazar.

    Saat alanı taşmaz: 100 saat `100:00:00` olur, sıfırlanmaz. Negatif
    değer `00:00:00` döner — çağıran zaten süresi dolanı ayrı ele alıyor,
    ama biçimlendirici eksi işaret göstermemeli.
    """
    toplam = max(0, int(seconds))
    saat, artan = divmod(toplam, 3600)
    dakika, saniye = divmod(artan, 60)
    return f"{saat:02d}:{dakika:02d}:{saniye:02d}"


def urgency(seconds: float) -> str:
    """
    Kalan süreye göre aciliyet ADI: "red" | "yellow" | "green".

    Renk KODU değil — somut ton temaya bağlı ve tema arayüzün sorunu
    (bkz. modül docstring'i).
    """
    if seconds < CRITICAL_SECONDS:
        return "red"
    if seconds < WARNING_SECONDS:
        return "yellow"
    return "green"


@dataclass(frozen=True)
class CountdownRow:
    """Tek bir satırın geri sayım durumu."""

    #: Süre belirlenmemişse None — arayüz "—" gösteriyor.
    remaining: float | None
    expired: bool

    @property
    def unset(self) -> bool:
        return self.remaining is None

    def text(self) -> str:
        """Hücrede gösterilecek metin."""
        if self.remaining is None:
            return "—"
        return format_countdown(self.remaining)

    def urgency(self) -> str | None:
        """Aciliyet adı; süre belirlenmemişse None."""
        return None if self.remaining is None else urgency(self.remaining)


def countdown_for(expires_at: str | None, *, now: datetime | None = None) -> CountdownRow:
    """Tek satırın geri sayım durumunu hesaplar."""
    anlik = now or _utcnow()
    kalan = remaining_seconds(expires_at, now=anlik)
    return CountdownRow(
        remaining=kalan,
        expired=kalan is not None and kalan <= 0,
    )


@dataclass(frozen=True)
class BannerState:
    """
    İmha Odası başlığındaki özet bandın durumu.

    Üç hâl var ve arayüzdeki üç dalın birebir karşılığı:
      · en yakın imha sayacı  → soonest is not None
      · "İmha Odası boş"      → empty
      · "Süre belirlenmemiş"  → ikisi de değil
    """

    #: En yakın imhaya kalan süre; hiç süreli dosya yoksa None.
    soonest: float | None
    empty: bool

    def text(self) -> str:
        if self.soonest is not None:
            return f"⏱  En yakın imha: {format_countdown(self.soonest)}"
        return "İmha Odası boş" if self.empty else "Süre belirlenmemiş dosyalar"

    def urgency(self) -> str | None:
        return None if self.soonest is None else urgency(self.soonest)


def banner_for(
    remaining_values: list[float | None], *, row_count: int | None = None
) -> BannerState:
    """
    Görünen satırların kalan sürelerinden özet bandı hesaplar.

    Args:
        remaining_values: her satırın kalan süresi (None = süresiz).
                          Süresi DOLMUŞ satırlar buraya girmemeli; arayüz
                          onları zaten tablodan siliyor.
        row_count:        banttaki "boş" kararı için satır sayısı. Verilmezse
                          listenin uzunluğu kullanılır.

    "Boş" ile "süresiz dosyalar var" ayrımı önemli: ikisi de sayaç
    göstermiyor ama kullanıcıya söyledikleri farklı.
    """
    canli = [v for v in remaining_values if v is not None]
    toplam = len(remaining_values) if row_count is None else row_count
    return BannerState(
        soonest=min(canli) if canli else None,
        empty=toplam == 0,
    )
