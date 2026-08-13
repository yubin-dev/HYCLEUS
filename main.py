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

from CORE.audit_chain import (
    maybe_write_daily_anchor,
    verify_against_anchor,
    write_anchor,
)
from CORE.safezone import purge_on_exit, purge_orphans
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

    # ── Denetim zinciri çıpası ───────────────────────────────────────────────
    # Zincir DBManager.connect() içinde kuruluyor (bkz. CORE/audit_chain.py);
    # burada yapılan iş yalnızca ucunu veritabanının DIŞINA sabitlemek.
    #
    # Önce ÖNCEKİ oturumun çıpasıyla karşılaştırılır: kuyruktan kayıt silmek
    # ya da zinciri yeniden yazmak yalnızca burada görünür — zincirin kendi
    # doğrulaması bu iki durumda kusursuz sonuç verir. Uyuşmazlık açılışı
    # ENGELLEMEZ, çünkü denetim kaydı bir erişim kontrolü değil; ama hem
    # kullanıcıya söylenir hem de kaydın kendisine düşülür.
    try:
        anchor_check = verify_against_anchor(DBManager())
        if not anchor_check:
            _log.critical("Denetim çıpası uyuşmuyor:\n%s", anchor_check.summary())
            DBManager().log(
                "audit_anchor_mismatch",
                detail=" | ".join(anchor_check.problems),
            )
            QMessageBox.warning(
                None,
                "Denetim Kaydı Uyuşmuyor",
                "Denetim kaydı, en son çıpalanan durumla eşleşmiyor —\n"
                "kayıtlar silinmiş ya da değiştirilmiş olabilir.\n\n"
                f"{anchor_check.summary()}\n\n"
                "Uygulama açılmaya devam ediyor; bu bir erişim engeli değil,\n"
                "bir kurcalama uyarısıdır.",
            )
        maybe_write_daily_anchor(DBManager())
    except Exception as exc:  # çıpa sorunu açılışı engellemesin
        _log.warning("Denetim çıpası işlenemedi: %s", exc)

    # ── SafeZone artakalan temizliği ─────────────────────────────────────────
    # SafeZone'da dosya bulmak, önceki oturumun DÜZGÜN KAPANMADIĞI anlamına
    # gelir (normal kapanış onu boşaltıyor). Çözülmüş içerik diskte kalmış
    # olabilir; imha edilip denetime yazılıyor. Bkz. CORE/safezone.py.
    try:
        rapor = purge_orphans(DBManager())
        if rapor.had_leftovers:
            _log.warning("Açılışta SafeZone artığı: %s", rapor.summary())
        if not rapor.clean:
            QMessageBox.warning(
                None,
                "Geçici Dosya Temizliği",
                "Önceki oturumdan kalan geçici dosyaların bir kısmı "
                "silinemedi:\n\n"
                + "\n".join(f"· {ad}: {hata}" for ad, hata in rapor.errors[:5])
                + "\n\nBu dosyalar çözülmüş içerik barındırıyor olabilir.",
            )
    except Exception as exc:  # temizlik sorunu açılışı engellemesin
        _log.error("SafeZone açılış temizliği başarısız: %s", exc)

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

    # key_provider: haftalık bütünlük taraması GCM tag'lerini doğrulamak için
    # oturum anahtarına ihtiyaç duyuyor. Anahtarın kopyası zamanlayıcı
    # modülünde tutulmuyor — buradaki tek örneğe erişen bir çağrılabilir
    # geçiliyor (bkz. CORE/scheduler.py, start_scheduler).
    start_scheduler(key_provider=lambda: session_key, hwid=hwid)
    app.aboutToQuit.connect(stop_scheduler)

    def _safezone_on_quit() -> None:
        """
        Kapanışta SafeZone'u boşaltır — çözülmüş hiçbir kopya diskte kalmasın.

        Çıpadan ÖNCE bağlanıyor: Qt aboutToQuit alıcılarını bağlanma
        sırasıyla çağırıyor, dolayısıyla temizliğin denetim kaydı da
        çıpalanan zincire giriyor.
        """
        try:
            rapor = purge_on_exit(DBManager())
            if rapor.had_leftovers:
                _log.info("Kapanış SafeZone temizliği: %s", rapor.summary())
        except Exception as exc:
            _log.error("Kapanış SafeZone temizliği başarısız: %s", exc)

    app.aboutToQuit.connect(_safezone_on_quit)

    def _anchor_on_quit() -> None:
        """Kapanışta zincirin son hâlini çıpalar — oturumun kapanış mührü."""
        try:
            write_anchor(DBManager(), "shutdown")
        except Exception as exc:
            _log.warning("Kapanış çıpası yazılamadı: %s", exc)

    app.aboutToQuit.connect(_anchor_on_quit)

    win = HycleusWindow(hwid=hwid, key=session_key, role=role)
    win.show()
    # Kısıtlamalar show() sonrasında uygulanmalı — Qt ilk paint'te
    # __init__ içindeki setVisible() çağrılarını sıfırlayabilir.
    QTimer.singleShot(0, win._apply_role_restrictions)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
