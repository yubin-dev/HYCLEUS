import hashlib
import logging
import os
import sys

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(name)-24s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)

_log = logging.getLogger("hycleus.main")

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from CORE.scheduler import start_scheduler, stop_scheduler
from CORE.usb_manager import get_usb_hwid
from DB.db_manager import DBManager, HWIDMissingError
from UI.login_dialog import LoginDialog
from UI.main_window import HycleusWindow


def _dev_key(hwid: str) -> bytes:
    """DEV_MODE için HWID'den deterministik 32-byte anahtar türetir."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        hwid.encode(),
        b"HYCLEUS-DEV-FILE-KEY-SALT-v1",
        100_000,
    )


def main() -> None:
    app = QApplication(sys.argv)

    hwid = get_usb_hwid()
    if hwid is None:
        QMessageBox.critical(
            None,
            "USB Bulunamadı",
            "Yetkili USB cihazı takılı değil.\nUygulama başlatılamaz.",
        )
        sys.exit(1)

    dev_mode = os.getenv("DEV_MODE", "").lower() in ("1", "true", "yes")

    # DB bağlantısını geçici boş anahtar ile aç (şifreleme anahtarı login'den sonra gelir)
    try:
        DBManager().connect(hwid=hwid, key=None)
    except HWIDMissingError as exc:
        QMessageBox.critical(None, "Hata", str(exc))
        sys.exit(1)

    if dev_mode:
        role        = "Yönetici"
        session_key = _dev_key(hwid)
        _log.info("DEV_MODE aktif — HWID'den deterministik anahtar türetildi  hwid=%s", hwid)
    else:
        dialog = LoginDialog(hwid=hwid)
        if dialog.exec() != LoginDialog.Accepted:
            sys.exit(0)
        _log.info(
            "dialog_result  role=%s  key_len=%d  accepted=%s",
            dialog.role,
            len(dialog.session_key) if dialog.session_key else 0,
            dialog.result(),
        )
        role        = dialog.role
        session_key = dialog.session_key
        if not session_key:
            QMessageBox.critical(None, "Hata", "Vault anahtarı alınamadı.")
            sys.exit(1)

    start_scheduler()
    app.aboutToQuit.connect(stop_scheduler)

    win = HycleusWindow(hwid=hwid, key=session_key, role=role)
    win.show()
    # Kısıtlamalar show() sonrasında uygulanmalı — Qt ilk paint'te
    # __init__ içindeki setVisible() çağrılarını sıfırlayabilir.
    QTimer.singleShot(0, win._apply_role_restrictions)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
