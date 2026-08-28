"""
HYCLEUS — USB donanim kimligi okuyucu

DEV_MODE=true ortam degiskeni ile gercek USB olmadan gelistirme yapilabilir.

Zayıf bağlama (UUID yedeği) — B-025 / SECURITY.md
---------------------------------------------------
Bazı USB bellek sınıflarında depolama yığını kullanılamaz bir seri
bildiriyor (boş, "0", kontrol karakteri — bkz. BACKLOG.md B-025, gerçek bir
KIOXIA TransMemory cihazında ölçüldü). Bu durumda `_sanitize_hwid()`
`usb_ids.json`'da SAKLI, KALICI bir UUID'ye düşüyor: aynı fiziksel cihaz
sonraki takmalarda aynı kimliği almaya devam ediyor, ama o kimlik artık
DONANIMDAN değil, `data/` dizinindeki bir dosyadan geliyor. "Donanıma bağlı
kasa" iddiası bu cihaz sınıfı için doğru değil (SECURITY.md M2 — out of
scope notu) — `data/`'nın bir kopyasını tutan biri, USB'nin kendisi
olmadan aynı kimliği yeniden üretir.

Bu modül bu durumu artık SESSİZCE geçmiyor: `is_uuid_fallback_hwid()`
verilen bir hwid'in bu yedekten gelip gelmediğini söylüyor, ve ilk kez bir
UUID atandığında bir uyarı log'a düşüyor. Kritik işlemlerin (vault açma,
USB kaydı, imzalama) bu durumdaki bir hwid için REDDEDİLMESİ
`CORE/vault_manager.py`'nin sorumluluğu — bu modül yalnızca durumu
GÖRÜNÜR kılıyor, politika kararını vermiyor (katman ayrımı: bu modül USB
donanımından, vault_manager güvenlik politikasından sorumlu).
"""

import json
import logging
import os
import re
import sys
import uuid
from pathlib import PureWindowsPath

_log = logging.getLogger("hycleus.usb")

DEV_MODE: bool = os.getenv("DEV_MODE", "").lower() in ("1", "true", "yes")
_DEV_HWID = "DEV-HWID-1234"

# Dosya adı ve DB değeri olarak güvenli karakterler
_SAFE_HWID_RE = re.compile(r"[^a-zA-Z0-9_\-]")


def _wmic_yolu() -> str:
    """
    `wmic.exe`'nin TAM yolu (B-018 / bandit B607).

    Kısmi yol (`"wmic"`) `PATH` üzerinden arama demek. Saldırganın `PATH`'te
    önce gelen bir dizine yazabildiği bir senaryoda kendi `wmic.exe`'si
    çalışır. Bu, makineye zaten yazma erişimi gerektiriyor — yani
    SECURITY.md §1'in sınırının içinde ve tek başına bir açık değil. Ama
    sertleştirmesi ucuz ve `PATH`'e hiç bakmamak her zaman daha iyi.

    `SystemRoot` okunamıyorsa (kuramsal; Windows'ta her zaman tanımlı)
    `C:\\Windows` varsayılıyor. Dönen yolun VAR OLDUĞU kontrol edilmiyor:
    yoksa `subprocess` zaten `FileNotFoundError` fırlatır ve çağıran onu
    zaten yakalıyor — iki kat kontrol, iki kat sapma yolu demek olurdu.

    `PureWindowsPath` KULLANILIYOR, `Path` değil. `Path` çalıştığı
    platformun ayracını seçiyor: Linux'ta sonuç
    `C:\\Windows/System32/wbem/wmic.exe` gibi karışık bir dize oluyor.
    Bu fonksiyon yalnızca Windows'ta ÇAĞRILIYOR ama her platformda
    IMPORT ediliyor ve test ediliyor; çıktısının platformdan bağımsız
    olması gerekiyor. (İlk hâli `Path` kullanıyordu ve CI'ın Ubuntu ayağı
    tam olarak bu yüzden kırıldı.)
    """
    kok = os.environ.get("SystemRoot") or r"C:\Windows"
    return str(PureWindowsPath(kok) / "System32" / "wbem" / "wmic.exe")

# Boş/geçersiz seri numaraları için kalıcı UUID haritası
from CORE.paths import data_dir as _data_dir
_USB_IDS_FILE = _data_dir() / "usb_ids.json"


def _get_or_create_uuid(raw: str) -> str:
    """
    raw seri numarası için kalıcı UUID döndürür.
    İlk çağrıda uuid4 üretilir ve usb_ids.json'a kaydedilir;
    sonraki çağrılarda aynı UUID geri döner.

    İlk üretim artık SESSİZ değil: bir uyarı log'a düşer. Bu, "donanıma
    bağlı" iddiasının bu cihaz için geçerli olmadığı anın — B-025'in tam
    olarak şikayet ettiği görünmezliğin — kayda geçtiği tek yer.
    """
    mapping: dict[str, str] = {}
    if _USB_IDS_FILE.exists():
        try:
            mapping = json.loads(_USB_IDS_FILE.read_text(encoding="utf-8"))
        except Exception:
            mapping = {}

    if raw not in mapping:
        yeni_uuid = str(uuid.uuid4())
        mapping[raw] = yeni_uuid
        try:
            _USB_IDS_FILE.parent.mkdir(parents=True, exist_ok=True)
            _USB_IDS_FILE.write_text(
                json.dumps(mapping, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            pass  # yazma başarısız olursa geçici UUID döner ama en azından çökmez
        _log.warning(
            "USB seri numarası okunamadı — kalıcı UUID atandı (zayıf "
            "bağlama, donanıma bağlı DEĞİL): uuid=%s",
            yeni_uuid,
        )

    return mapping[raw]


def is_uuid_fallback_hwid(hwid: str) -> bool:
    """
    `hwid`, seri numarası okunamadığı için `usb_ids.json`'a atanmış bir
    UUID yedeği mi?

    Canlı bir USB probu GEREKMEZ — yalnızca dosyanın DEĞERLER kümesine
    bakar. `_get_or_create_uuid()` HER ZAMAN bu dosyaya yazdığı için (yukarı
    bakın), buradaki eşleşme kanonik: dosyada olmayan bir değer hiçbir
    zaman bu yedek yoldan üretilmemiştir.

    Bu, `CORE/vault_manager.py` gibi USB donanım algılamasından (wmi/wmic)
    bağımsız kalması gereken modüllerin de "bu kimlik zayıf mı" sorusunu,
    canlı algılama mantığına hiç dokunmadan sorabilmesini sağlar.
    """
    if not _USB_IDS_FILE.exists():
        return False
    try:
        mapping: dict[str, str] = json.loads(_USB_IDS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return False
    return hwid in mapping.values()


def _sanitize_hwid(raw: str) -> str | None:
    """
    Kontrol karakterleri ve özel semboller temizlenir.
    Temizlemeden sonra boş veya '0' kalırsa UUID fallback kullanılır.
    Sonuç her zaman dosya adı ve DB değeri olarak güvenlidir.
    """
    cleaned = _SAFE_HWID_RE.sub("", raw.strip())
    if not cleaned or cleaned == "0":
        return _get_or_create_uuid(raw)
    return cleaned


def get_usb_hwid() -> str | None:
    """
    Takili USB depolama aygitinin seri numarasini dondurur.

    DEV_MODE=true ise 'DEV-HWID-1234' dondurur (gercek USB gerekmez).
    Birden fazla USB varsa ilki alinir.
    Seri numara boş, '0' veya kontrol karakteri içeriyorsa usb_ids.json'dan
    kalıcı UUID tahsis edilir — aynı fiziksel USB her zaman aynı kimlikle
    döner, ama bu ZAYIF bir bağlama (bkz. modül docstring'i,
    `is_uuid_fallback_hwid()`). Bu fonksiyon o durumda hâlâ bir kimlik
    DÖNDÜRÜR — reddetmiyor; kritik işlemler için reddetme kararı
    `CORE/vault_manager.py`'de, `is_uuid_fallback_hwid()`'i burada
    tanımlanan kimliğe uygulayarak veriliyor.

    Returns:
        str  — USB seri numarasi (HWID veya UUID)
        None — USB takili degil veya seri numara okunamadi
    """
    # EXE olarak çalışırken DEV_MODE ne olursa olsun gerçek USB okunur
    if DEV_MODE and not hasattr(sys, "frozen"):
        return _DEV_HWID

    # ── Yöntem 1: wmi modülü ─────────────────────────────────────────────────
    try:
        import wmi  # type: ignore[import]
        for disk in wmi.WMI().Win32_DiskDrive():
            if getattr(disk, "InterfaceType", "") == "USB":
                serial = getattr(disk, "SerialNumber", "")
                if serial and serial != "?":
                    hwid = _sanitize_hwid(str(serial))
                    if hwid:
                        return hwid
    except Exception:
        pass

    # ── Yöntem 2: wmic subprocess fallback ──────────────────────────────────
    try:
        import subprocess
        out = subprocess.check_output(
            [_wmic_yolu(), "diskdrive", "get",
             "InterfaceType,SerialNumber,Model", "/format:csv"],
            text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for line in out.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 4:
                continue
            itype, serial = parts[1], parts[3]
            if itype == "USB" and serial:
                hwid = _sanitize_hwid(serial)
                if hwid:
                    return hwid
    except Exception:
        pass

    return None
