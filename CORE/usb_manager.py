"""
HYCLEUS — USB donanim kimligi okuyucu

DEV_MODE=true ortam degiskeni ile gercek USB olmadan gelistirme yapilabilir.
"""

import os

DEV_MODE: bool = os.getenv("DEV_MODE", "").lower() in ("1", "true", "yes")
_DEV_HWID = "DEV-HWID-1234"


def get_usb_hwid() -> str | None:
    """
    Takili USB depolama aygitinin seri numarasini dondurur.

    DEV_MODE=true ise 'DEV-HWID-1234' dondurur (gercek USB gerekmez).
    Birden fazla USB varsa ilki alinir.

    Returns:
        str  — USB seri numarasi (HWID)
        None — USB takili degil veya seri numara okunamadi
    """
    if DEV_MODE:
        return _DEV_HWID

    try:
        import wmi  # type: ignore[import]  — Windows'a ozgu

        for disk in wmi.WMI().Win32_DiskDrive():
            if getattr(disk, "InterfaceType", None) == "USB":
                serial = getattr(disk, "SerialNumber", None)
                if serial and serial.strip():
                    return serial.strip()
        return None
    except Exception:
        return None
