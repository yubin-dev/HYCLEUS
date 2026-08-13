"""
HYCLEUS — Hareketsizlik kilidi (idle auto-lock)

USB takılı kalsa bile, kullanıcı N dakika hiçbir şey yapmazsa oturum
kilitlenir. Kapattığı boşluk şu: HYCLEUS'un donanım kilidi yalnızca USB
ÇEKİLDİĞİNDE devreye giriyor, ama masasından kalkıp giden bir kullanıcı
USB'yi genellikle takılı bırakır. O anda ekranın başına geçen biri için
hiçbir engel yoktur — vault açık, dosyalar erişilebilir.

Bu modülde Qt YOK
-----------------
Zamanlama kararı burada, saf Python'da; Qt tarafı (event filter, QTimer,
overlay) UI/main_window.py'de ve ince tutuldu. Böylece "ne zaman
kilitlenmeli" sorusu başsız test edilebiliyor — CORE'un Qt'siz kalması
bilinçli bir kural (bkz. CORE/file_records.py docstring'i).

Neden monotonic saat
--------------------
`time.monotonic()` kullanılıyor, duvar saati değil. Hareketsizlik SÜRE
ölçümüdür ve sistem saati geri alınırsa duvar saati negatif "geçen süre"
üretir; kullanıcı kilidi saati değiştirerek erteleyebilirdi.

Bu, CORE/rate_limit.py'nin tersi bir tercih ve fark bilinçli: giriş kilidi
yeniden başlatmayı AŞMAK zorunda olduğu için mutlak zaman damgası kullanıyor
(monotonic saat açılışta sıfırlanır). Hareketsizlik kilidi ise yalnızca
süreç içinde anlamlı — uygulama kapanırsa oturum zaten bitmiştir.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

_log = logging.getLogger("hycleus.idle_lock")

#: Hareketsizlik süresinin tutulduğu settings anahtarı (dakika).
IDLE_TIMEOUT_SETTING = "idle_lock_minutes"

#: Varsayılan: 10 dakika. Kısa bir mola kilitlemeyecek kadar uzun, masadan
#: ayrılıp dönmeyi kapsayacak kadar kısa.
DEFAULT_IDLE_MINUTES = 10

#: 0 = kapalı. Yönetici bilerek kapatabilir ama bu ayrıca denetime düşer
#: (bkz. set_idle_timeout_minutes).
IDLE_DISABLED = 0

#: Alt sınır 1 dakika: daha kısası uygulamayı kullanılamaz hâle getirirdi
#: (bir belgeyi okumak bile kilitlenmeye yeter). Üst sınır 24 saat —
#: ötesi "kapalı" demektir ve onun için IDLE_DISABLED var.
MIN_IDLE_MINUTES = 1
MAX_IDLE_MINUTES = 1440

#: Arayüzde sunulan seçenekler (0 = Kapalı).
IDLE_OPTIONS: tuple[int, ...] = (IDLE_DISABLED, 1, 5, 10, 15, 30, 60)


def timeout_milliseconds(minutes: int) -> int:
    """Dakikayı QTimer'ın beklediği milisaniyeye çevirir."""
    return max(0, int(minutes) * 60 * 1000)


def get_idle_timeout_minutes(db: Any) -> int:
    """
    Yapılandırılmış hareketsizlik süresi (dakika); 0 ise kapalı.

    Bozuk ya da aralık dışı bir değer varsayılana düşer — kilit ayarı
    okunamıyor diye kilidi TAMAMEN kapatmak, güvenlik kontrolünü sessizce
    devre dışı bırakmak olurdu.
    """
    raw = db.get_setting(IDLE_TIMEOUT_SETTING, "")
    if raw == "":
        return DEFAULT_IDLE_MINUTES
    try:
        minutes = int(raw)
    except (TypeError, ValueError):
        _log.warning(
            "%s sayıya çevrilemedi (%r) — varsayılana dönülüyor: %d dk",
            IDLE_TIMEOUT_SETTING, raw, DEFAULT_IDLE_MINUTES,
        )
        return DEFAULT_IDLE_MINUTES

    if minutes == IDLE_DISABLED:
        return IDLE_DISABLED
    if not (MIN_IDLE_MINUTES <= minutes <= MAX_IDLE_MINUTES):
        _log.warning(
            "%s aralık dışı (%d) — varsayılana dönülüyor: %d dk",
            IDLE_TIMEOUT_SETTING, minutes, DEFAULT_IDLE_MINUTES,
        )
        return DEFAULT_IDLE_MINUTES
    return minutes


def set_idle_timeout_minutes(db: Any, minutes: int, *, hwid: str | None = None) -> None:
    """
    Hareketsizlik süresini yazar ve denetim kaydına düşer.

    Kilidi KAPATMAK ayrı bir action ile kaydediliyor: bir güvenlik
    kontrolünün devre dışı bırakılması, süresinin değiştirilmesiyle aynı
    şey değil ve denetim kaydında da öyle görünmemeli.
    """
    minutes = int(minutes)
    if minutes != IDLE_DISABLED and not (MIN_IDLE_MINUTES <= minutes <= MAX_IDLE_MINUTES):
        raise ValueError(
            f"Hareketsizlik süresi {MIN_IDLE_MINUTES}-{MAX_IDLE_MINUTES} dakika"
            f" arasında ya da {IDLE_DISABLED} (kapalı) olmalı; {minutes} verildi."
        )

    db.set_setting(IDLE_TIMEOUT_SETTING, str(minutes))
    suffix = f" hwid={hwid}" if hwid else ""
    if minutes == IDLE_DISABLED:
        db.log(
            "idle_lock_disabled",
            detail=f"key={IDLE_TIMEOUT_SETTING} value=0{suffix}",
        )
        _log.warning("Hareketsizlik kilidi KAPATILDI%s", suffix)
    else:
        db.log(
            "setting_changed",
            detail=f"key={IDLE_TIMEOUT_SETTING} value={minutes}{suffix}",
        )


def log_idle_lock(db: Any, *, idle_seconds: float, timeout_minutes: int,
                  hwid: str | None = None) -> None:
    """Kilit devreye girdiğinde denetim kaydına yazar (hash zincirinden geçer)."""
    suffix = f" hwid={hwid}" if hwid else ""
    db.log(
        "idle_lock_triggered",
        detail=(
            f"timeout_minutes={timeout_minutes}"
            f" idle_seconds={int(idle_seconds)}{suffix}"
        ),
    )
    _log.info(
        "Hareketsizlik kilidi devreye girdi — %d sn (%d dk eşiği)",
        int(idle_seconds), timeout_minutes,
    )


@dataclass
class IdleTracker:
    """
    "Kilitlenmeli mi?" kararının tamamı — Qt'siz, dolayısıyla test edilebilir.

    Kullanım (UI tarafı):
        · her fare/klavye olayında  → record_activity()
        · saniyede bir tik'te       → should_lock() sorulur

    Neden her olayda QTimer YENİDEN BAŞLATILMIYOR
    ---------------------------------------------
    Yaygın Qt deseni olayda `timer.start()` çağırmaktır. Burada bunun yerine
    olay yalnızca bir zaman damgası yazıyor ve ayrı bir tik zamanlayıcısı
    karar veriyor. Sonuç aynı — etkileşim geri sayımı sıfırlar — ama maliyet
    çok daha düşük: fare hareketi saniyede yüzlerce olay üretir ve her
    birinde bir QTimer'ı durdurup yeniden kurmak, Qt olay döngüsüne
    gereksiz iş bindirir. Zaman damgası yazmak tek bir float ataması.

    Ayrıca kararın kendisi böylece Qt'den tamamen ayrıldı: bu sınıfın
    testleri sahte bir saatle çalışıyor, dakikalarca beklemiyor.
    """

    #: 0 → kilit kapalı.
    timeout_seconds: float
    #: Kilit devreye girdikten sonra False olur; tekrar tekrar tetiklenmesin.
    armed: bool = True
    _last_activity: float = field(default_factory=time.monotonic)

    @classmethod
    def from_minutes(cls, minutes: int) -> IdleTracker:
        return cls(timeout_seconds=float(max(0, int(minutes)) * 60))

    @property
    def disabled(self) -> bool:
        return self.timeout_seconds <= 0

    def record_activity(self, now: float | None = None) -> None:
        """Kullanıcı etkileşimi — geri sayımı sıfırlar."""
        self._last_activity = time.monotonic() if now is None else now

    def idle_seconds(self, now: float | None = None) -> float:
        """
        Son etkileşimden bu yana geçen süre.

        Negatif dönmez: sahte/geri giden bir saat kaynağı verilse bile
        sonuç 0'a kırpılır, aksi hâlde kilit sonsuza kadar ertelenebilirdi.
        """
        current = time.monotonic() if now is None else now
        return max(0.0, current - self._last_activity)

    def remaining_seconds(self, now: float | None = None) -> float:
        """Kilide kalan süre; kapalıysa sonsuz."""
        if self.disabled:
            return float("inf")
        return max(0.0, self.timeout_seconds - self.idle_seconds(now))

    def should_lock(self, now: float | None = None) -> bool:
        """
        Kilit şimdi devreye girmeli mi?

        Kapalıysa ya da zaten tetiklenmişse (armed=False) False döner.
        """
        if self.disabled or not self.armed:
            return False
        return self.idle_seconds(now) >= self.timeout_seconds

    def disarm(self) -> None:
        """Kilit tetiklendi — yeniden kurulana kadar bir daha tetiklenmesin."""
        self.armed = False

    def rearm(self, now: float | None = None) -> None:
        """Oturum yeniden açıldı — sayacı sıfırla ve kilidi tekrar kur."""
        self.armed = True
        self.record_activity(now)

    def reconfigure(self, minutes: int, now: float | None = None) -> None:
        """Süre ayarı değiştiğinde çağrılır; sayaç baştan başlar."""
        self.timeout_seconds = float(max(0, int(minutes)) * 60)
        self.record_activity(now)
