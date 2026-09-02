"""
HYCLEUS — Toplu dosya işleme için dinamik iş parçacığı sayısı

`UI/main_window.py`'nin dosya-ekleme iş parçacığı havuzu (`QThreadPool`)
uzun süre SABİT 6 işçiyle çalıştı. Bu modül o sabiti, sistemde O AN
kullanılabilir RAM'e göre küçülebilen bir öneri ile değiştiriyor.

ÖLÇÜLEN GERÇEK: kripto katmanının kendisi zaten küçük
-------------------------------------------------------
`CORE/crypto.py::encrypt_file()` dosyayı 64 KB'lık bloklar hâlinde
OKUYUP YAZIYOR (`_CHUNK`) — asla tamamını belleğe almıyor. Ölçüldü: 6
işçi, her biri 100 MB'lık bir dosyayı EŞ ZAMANLI şifrelerken (600 MB
toplam veri) sürecin RSS'i yalnızca ~1 MB büyüdü. Yani "6 işçi × tampon
boyutu" kripto tamponunun KENDİSİNDEN kaynaklanan bir şişme DEĞİL.

Öyleyse bu modül NEDEN VAR
---------------------------
Bir işçinin GERÇEK bellek ayak izi yalnızca kripto tamponundan ibaret
değil: her `_FileRunnable` kendi OS iş parçacığı yığınını (Windows'ta
varsayılan ~1 MB REZERVE, mutlaka COMMIT edilmiş değil), `scan_file()`
için ayrı bir ALT SÜREÇ (virüs tarayıcı, kendi belleği bu sürecin
RSS'ine YANSIMAZ ama sistemin TOPLAM kullanılabilir RAM'ini tüketir) ve
Qt/GC nesne yükünü taşıyor. Bugünün masaüstlerinde bu toplam önemsiz;
eski/kısıtlı bir adli bilişim istasyonunda (1-2 GB RAM) ya da gelecekte
`_CHUNK` büyürse/işçi başına iş büyürse ÖNEMLİ hâle gelebilir. Sabit "6"
bu ihtimali hiç ölçmüyordu.

Tasarım: TAMPON BOYUTU değil İŞÇİ SAYISI ayarlanıyor
------------------------------------------------------
`CORE/crypto.py::_CHUNK` GCM akışının kendi sabiti; onu makineye göre
değiştirmek `verify_file()`/`decrypt_file()`/`encrypt_file()` genelinde
paylaşılan, dikkatle gerekçelendirilmiş bir değeri dokunaklı hâle
getirirdi (bkz. o modülün docstring'i) — kazanç da yok, zaten küçük.
Bunun yerine `QThreadPool.setMaxThreadCount()`'a giden sayı küçülüyor:
daha az işçi, daha az eş zamanlı iş parçacığı yığını + alt süreç.

Kullanılabilir RAM'in bir KESRİ (`_TAVAN_ORANI`) bütçe olarak ayrılıyor
— TOPLAM RAM değil: sistemde zaten çalışan başka programlar varsa
`available` onu zaten dışlıyor, `total`'a göre karar vermek yanıltıcı
olurdu.

`psutil` erişilemezse (kurulu değil, platform desteklemiyor,
`AccessDenied`) SESSİZCE 6'ya (sabit varsayılan) düşülür — bu bir
GÜVENLİK kontrolü DEĞİL (bkz. `CORE/secret_store.py`'nin "eski davranışa
sessizce düşülmez" ilkesiyle KARIŞTIRILMASIN): en kötü ihtimalle
DÜNKÜ davranışa (sabit 6 işçi) dönülür, hiçbir koruma zayıflamaz.
"""
from __future__ import annotations

import logging

_log = logging.getLogger("hycleus.worker_sizing")

#: Bugüne kadarki sabit değer — RAM bol olduğunda (ve `psutil`
#: erişilemediğinde) davranış AYNI kalır, yalnızca gerçekten düşük RAM'de
#: küçülür.
DEFAULT_MAX_WORKERS = 6

#: Kullanılabilir RAM'in en fazla bu kesri işçi havuzuna ayrılabilir.
#: Yarısı: kalan yarı işletim sistemi, diğer uygulamalar ve HYCLEUS'un
#: kendi diğer belleği (Qt, DB önbelleği, vb.) için pay bırakıyor.
_TAVAN_ORANI = 0.5

#: Bir işçinin GERÇEK kripto tamponundan (64 KB, önemsiz) ÇOK daha
#: kapsamlı, MUHAFAZAKÂR bir bütçe — OS iş parçacığı yığını, `scan_file()`
#: alt sürecinin sistem geneli tükettiği RAM ve Qt/GC yükü için pay.
#: Modül docstring'indeki ölçüme göre GERÇEK kullanım bunun çok altında;
#: kasıtlı olarak cömert tutuldu ki düşük-RAM'de erken küçülsün.
_ISCI_BASINA_BUTCE_BYTES = 50 * 1024 * 1024  # 50 MB


def _kullanilabilir_ram_bytes() -> int:
    """`psutil.virtual_memory().available` — yerel import (bkz. modül docstring'i)."""
    import psutil

    return int(psutil.virtual_memory().available)


def recommended_thread_count(
    *,
    max_count: int = DEFAULT_MAX_WORKERS,
    min_count: int = 1,
    available_bytes: int | None = None,
) -> int:
    """
    Toplu dosya-ekleme iş parçacığı havuzu için önerilen boyut.

    Args:
        max_count:       RAM bol olduğunda tavan (bugünkü sabit davranış).
        min_count:       RAM ne kadar az olursa olsun asla bunun altına
                          inilmez — en azından TEK bir dosya işlenebilmeli.
        available_bytes: TESTLER için — verilirse `psutil` hiç
                          çağrılmaz, düşük-RAM senaryoları gerçek bir
                          bellek darlığı yaratmadan simüle edilebilir.

    `psutil` erişilemezse (bkz. modül docstring'i, "sessizce düşülür")
    `max_count` döner — bu bir güvenlik düşüşü değil, dünkü davranış.
    """
    if available_bytes is None:
        try:
            available_bytes = _kullanilabilir_ram_bytes()
        except Exception as exc:
            _log.warning(
                "kullanilabilir_ram_olculemedi  hata=%s — sabit varsayılana "
                "(max_count=%d) düşülüyor", exc, max_count,
            )
            return max_count

    butce = int(available_bytes * _TAVAN_ORANI)
    onerilen = butce // _ISCI_BASINA_BUTCE_BYTES
    return max(min_count, min(max_count, onerilen))


__all__ = [
    "DEFAULT_MAX_WORKERS",
    "recommended_thread_count",
]
