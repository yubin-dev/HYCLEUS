"""
HYCLEUS — USB donanim kimligi okuyucu

DEV_MODE=true ortam degiskeni ile gercek USB olmadan gelistirme yapilabilir.
"""

import json
import os
import re
import sys
import uuid
from pathlib import Path

DEV_MODE: bool = os.getenv("DEV_MODE", "").lower() in ("1", "true", "yes")
_DEV_HWID = "DEV-HWID-1234"

# Dosya adı ve DB değeri olarak güvenli karakterler
_SAFE_HWID_RE = re.compile(r"[^a-zA-Z0-9_\-]")

# Boş/geçersiz seri numaraları için kalıcı UUID haritası
from CORE.paths import data_dir as _data_dir
_USB_IDS_FILE = _data_dir() / "usb_ids.json"


def _get_or_create_uuid(raw: str) -> str:
    """
    raw seri numarası için kalıcı UUID döndürür.
    İlk çağrıda uuid4 üretilir ve usb_ids.json'a kaydedilir;
    sonraki çağrılarda aynı UUID geri döner.
    """
    mapping: dict[str, str] = {}
    if _USB_IDS_FILE.exists():
        try:
            mapping = json.loads(_USB_IDS_FILE.read_text(encoding="utf-8"))
        except Exception:
            mapping = {}

    if raw not in mapping:
        mapping[raw] = str(uuid.uuid4())
        try:
            _USB_IDS_FILE.parent.mkdir(parents=True, exist_ok=True)
            _USB_IDS_FILE.write_text(
                json.dumps(mapping, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            pass  # yazma başarısız olursa geçici UUID döner ama en azından çökmez

    return mapping[raw]


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
    kalıcı UUID tahsis edilir — aynı fiziksel USB her zaman aynı kimlikle döner.

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
            ["wmic", "diskdrive", "get", "InterfaceType,SerialNumber,Model", "/format:csv"],
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
