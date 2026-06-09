import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)-24s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)

from PySide6.QtWidgets import QApplication, QMessageBox

from CORE.crypto import generate_key
from CORE.scheduler import start_scheduler, stop_scheduler
from CORE.usb_manager import get_usb_hwid
from DB.db_manager import DBManager, HWIDMissingError
from UI.login_dialog import LoginDialog
from UI.main_window import HycleusWindow


def main() -> None:
    app = QApplication(sys.argv)

    # USB kontrolü — vault modu için login'den önce yapılır;
    # DEV_MODE'da get_usb_hwid() sahte HWID döndürür, bu dal hiç çalışmaz.
    hwid = get_usb_hwid()
    if hwid is None:
        QMessageBox.critical(
            None,
            "USB Bulunamadı",
            "Yetkili USB cihazı takılı değil.\nUygulama başlatılamaz.",
        )
        sys.exit(1)

    # DB bağlantısı önce açılır: kurulum aşamasında create_vault() DB'ye yazar.
    session_key = generate_key()
    try:
        DBManager().connect(hwid=hwid, key=session_key)
    except HWIDMissingError as exc:
        QMessageBox.critical(None, "Hata", str(exc))
        sys.exit(1)

    # DEV_MODE: login atla, doğrudan yönetici oturumu aç.
    dev_mode = os.getenv("DEV_MODE", "").lower() in ("1", "true", "yes")
    if dev_mode:
        role = "Yönetici"
    else:
        dialog = LoginDialog(hwid=hwid)
        if dialog.exec() != LoginDialog.Accepted:
            sys.exit(0)
        role = dialog.role

    start_scheduler()
    app.aboutToQuit.connect(stop_scheduler)

    win = HycleusWindow(hwid=hwid, key=session_key, role=role)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
