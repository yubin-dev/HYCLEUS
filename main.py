import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from CORE.crypto import generate_key
from CORE.scheduler import start_scheduler, stop_scheduler
from CORE.usb_manager import get_usb_hwid
from DB.db_manager import DBManager, HWIDMissingError
from UI.login_dialog import LoginDialog
from UI.main_window import HycleusWindow


def main() -> None:
    app = QApplication(sys.argv)

    # Kimlik doğrulama
    dialog = LoginDialog()
    if dialog.exec() != LoginDialog.Accepted:
        sys.exit(0)

    # USB kontrolü
    hwid = get_usb_hwid()
    if hwid is None:
        QMessageBox.critical(
            None,
            "USB Bulunamadı",
            "Yetkili USB cihazı takılı değil.\nUygulama başlatılamaz.",
        )
        sys.exit(1)



    # Oturum anahtarı + DB bağlantısı
    session_key = generate_key()
    try:
        DBManager().connect(hwid=hwid, key=session_key)
    except HWIDMissingError as exc:
        QMessageBox.critical(None, "Hata", str(exc))
        sys.exit(1)

    start_scheduler()
    app.aboutToQuit.connect(stop_scheduler)

    win = HycleusWindow(hwid=hwid, key=session_key, role=dialog.role)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
