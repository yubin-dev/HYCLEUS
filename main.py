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
from CORE.secret_migration import MigrationError, run_migrations
from CORE.secret_store import KeyringUnavailableError, backend_name, ensure_available
from CORE.usb_manager import get_usb_hwid
from CORE.vault_manager import has_recovery_share
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

    # sys.frozen → PyInstaller EXE; ortam değişkeni miras alınsa bile DEV_MODE kapalı
    if hasattr(sys, "frozen"):
        dev_mode = False
    else:
        dev_mode = os.getenv("DEV_MODE", "").lower() in ("1", "true", "yes")

    # ── use_vault + first_run: tek noktada hesapla, LoginDialog'a geç ─────────
    from CORE.vault_manager import _read_vault_path as _rvp
    from UI.login_dialog import _load_secret as _ls
    _use_vault = not dev_mode   # hwid None kontrolü yukarıda yapıldı
    if _use_vault:
        _vault_path   = _rvp(hwid)
        _vault_exists = _vault_path.exists()
        _secret       = _ls()
        _first_run    = (_secret is None) or (not _vault_exists)
    else:
        _vault_path   = None
        _vault_exists = False
        _secret       = None
        _first_run    = False   # DEV_MODE — LoginDialog gösterilmeyecek
    # ─────────────────────────────────────────────────────────────────────────

    # ── Anahtar kasası zorunlu ───────────────────────────────────────────────
    # Sırlar (share_2, TOTP) OS anahtar kasasında tutuluyor. Kasa açılamıyorsa
    # ESKİ DÜZ METİN DAVRANIŞINA DÜŞÜLMEZ — uygulama açılmayı reddeder.
    try:
        ensure_available()
        _log.info("Anahtar kasası hazır  backend=%s", backend_name())
    except KeyringUnavailableError as exc:
        QMessageBox.critical(None, "Anahtar Kasası Erişilemiyor", str(exc))
        _log.critical("Anahtar kasası erişilemiyor — başlatma iptal: %s", exc)
        sys.exit(1)

    # DB bağlantısını geçici boş anahtar ile aç (şifreleme anahtarı login'den sonra gelir)
    try:
        DBManager().connect(hwid=hwid, key=None)
    except HWIDMissingError as exc:
        QMessageBox.critical(None, "Hata", str(exc))
        sys.exit(1)

    # ── Sır migration'ı ──────────────────────────────────────────────────────
    # Düz metin sırları (DB usb_tokens.share_2, data/totp_secret.json) kasaya
    # taşır ve eski kopyaları imha eder. Şema versiyonu ile korunur; tamamlanmış
    # migration tekrar çalışmaz.
    try:
        report = run_migrations(DBManager())
        if report.ran:
            _log.info("Sır migration'ı: %s", report.summary())
            DBManager().log("secret_migration", detail=report.summary())
            for note in report.notes:
                _log.warning(note)
                DBManager().log("secret_migration_warning", detail=note)
    except (KeyringUnavailableError, MigrationError) as exc:
        QMessageBox.critical(None, "Sır Taşıma Hatası", str(exc))
        _log.critical("Migration başarısız — başlatma iptal: %s", exc)
        sys.exit(1)

    if dev_mode:
        role        = "Yönetici"
        session_key = _dev_key(hwid)
        _log.info("DEV_MODE aktif — HWID'den deterministik anahtar türetildi  hwid=%s", hwid)
    else:
        dialog = LoginDialog(hwid=hwid, first_run=_first_run, use_vault=_use_vault)
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

    # ── Kurtarma parçası uyarısı ─────────────────────────────────────────────
    # 2-of-2 döneminde kurulmuş vault'lar sessizce eski şemada bırakılmaz.
    # Otomatik migration YAPILAMAZ: kurtarma parçası kullanıcıya gösterilip
    # fiziksel olarak saklanmak zorunda; arka planda üretip kimseye
    # göstermemek işe yaramaz. Bu yüzden kullanıcı bilgilendirilir ve
    # yönlendirilir — ama açılış engellenmez.
    try:
        if not has_recovery_share(hwid):
            _log.warning("Kurtarma parçası alınmamış  hwid=%s", hwid)
            QMessageBox.warning(
                None,
                "Kurtarma Parçası Alınmamış",
                "Bu vault şu an 2-of-2 gibi davranıyor.\n\n"
                "Vault dosyanız veya anahtar kasası kaydınız kaybolursa "
                "dosyalarınıza bir daha erişemezsiniz.\n\n"
                "Kurtarma parçasını almak için:\n"
                "    python CORE/recover_vault.py --export\n\n"
                "Bu işlem vault'unuzu değiştirmez; mevcut paylarınız aynı kalır.",
            )
    except Exception as exc:  # DB/şema sorunları açılışı engellemesin
        _log.warning("Kurtarma parçası durumu okunamadı: %s", exc)

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
