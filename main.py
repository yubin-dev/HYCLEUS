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
from CORE.console import ensure_utf8_console
from CORE.safezone import purge_on_exit, purge_orphans
from CORE.scheduler import start_scheduler, stop_scheduler
from CORE.secret_migration import MigrationError, run_migrations
from CORE.secret_store import KeyringUnavailableError, backend_name, ensure_available
from CORE.session_user import sync_session_user
from CORE.tpm_sealing import oturum_raporu as tpm_oturum_raporu
from CORE.usb_manager import get_usb_hwid
from CORE.vault_manager import has_recovery_share
from DB.db_manager import DBManager, HWIDMissingError
from UI.login_dialog import LoginDialog
from UI.main_window import HycleusWindow


# ── GUI'siz komutlar ──────────────────────────────────────────────────────────
#
# Bu iki bayrak paketlenmiş yapıyı sınamak için var. Bir GUI uygulamasının
# "çalışıyor mu" sorusu başsız bir koşucuda cevaplanamaz: main() USB
# bulamayınca QMessageBox açıyor ve o kutu tıklanmayı bekleyerek asılı
# kalıyor. --selftest o duvarın ÖNÜNDE duruyor.
#
# Asıl ölçtüğü şey PyInstaller'ın gizli import'ları: reportlab, qrcode ve
# keyring FONKSİYON İÇİNDE import ediliyor (CORE/inventory.py,
# CORE/recovery_share.py, CORE/secret_store.py). Donmuş bir yapıda eksik
# kalırlarsa hata ancak kullanıcı PDF almaya ya da kurtarma karekodunu
# görmeye çalıştığında — yani en kötü anda — ortaya çıkar.

#: Donmuş yapıda içe aktarılabilirliği denetlenen uygulama modülleri.
#: `tests/test_packaging.py` bu listenin CORE/ ve DB/ ile eşleştiğini
#: denetliyor — elle tutulan bir liste sessizce eskir.
_SELFTEST_MODULLERI: tuple[str, ...] = (
    "CORE.audit_chain", "CORE.audit_report", "CORE.backup", "CORE.backup_cli",
    "CORE.backup_reminder", "CORE.checkout", "CORE.console", "CORE.crypto",
    "CORE.disposal", "CORE.duplicates", "CORE.expiry", "CORE.export",
    "CORE.file_queries", "CORE.file_records", "CORE.folders", "CORE.hwid_probe",
    "CORE.idle_lock", "CORE.integrity", "CORE.inventory", "CORE.merkle",
    "CORE.paths", "CORE.pin_policy", "CORE.pin_rotation",
    "CORE.rate_limit", "CORE.recover_vault",
    "CORE.roles",
    "CORE.recovery_share", "CORE.retention", "CORE.safezone", "CORE.scanner",
    "CORE.scanner_backends", "CORE.scheduled_checks", "CORE.scheduler",
    "CORE.secret_migration", "CORE.secret_store", "CORE.secure_erase",
    "CORE.session_user", "CORE.setup_usb", "CORE.timestamp",
    "CORE.timestamp_report",
    "CORE.timestamp_verify", "CORE.tpm_sealing",
    "CORE.usb_manager", "CORE.vault_manager",
    "CORE.verify_timestamp_cli", "CORE.version",
    "DB.db_manager", "DB.migrations",
)

#: Üçüncü taraf modüller. Ağırlık, yalnızca FONKSİYON İÇİNDE import edilen
#: ve bu yüzden PyInstaller'ın statik analizinin gözden kaçırabileceği
#: kümede — reportlab, qrcode, keyring.
#:
#: `cryptography.hazmat.primitives.ciphers` modül seviyesinde import
#: ediliyor, yani PyInstaller onu zaten görüyor. Yine de listede: import
#: etmek yerli (Rust) uzantının GERÇEKTEN yüklendiğini ölçüyor ve donmuş
#: yapıda kırılabilecek tek şey saf Python modülleri değil.
#:
#: Burada olmayan ve OLMAMASI gereken: `...ciphers.aead`. İlk yazımda
#: listedeydi ve donmuş yapıda "eksik" raporlandı — ama HYCLEUS AESGCM'i
#: değil düşük seviyeli `Cipher/algorithms/modes` arayüzünü kullanıyor
#: (CORE/crypto.py). Yani eksik olan paketleme değil, listenin kendisiydi.
_SELFTEST_UCUNCU_TARAF: tuple[str, ...] = (
    "apscheduler.schedulers.background",
    "argon2",
    "asn1crypto.tsp",
    "cryptography.hazmat.primitives.ciphers",
    "keyring",
    "pyotp",
    "qrcode",
    "qrcode.image.svg",
    "reportlab.lib.pagesizes",
    "reportlab.platypus",
)

#: Platforma ÖZGÜ modüller. Yalnızca eşleşen platformda denenirler.
#:
#: Windows grubu B-024'ün ikinci yarısını kapatıyor. Linux spec'i
#: `excludes=['wmi', 'pythoncom', …]` taşıyor — çünkü o paketler Linux'ta
#: kurulamıyor. O satırın Windows spec'ine kopyalanması HWID okumasını
#: SESSİZCE bozardı: `CORE/usb_manager.get_usb_hwid()` her iki yöntemi de
#: `except Exception: pass` ile sarıyor, yani eksik `wmi` bir hata değil
#: "USB bulunamadı" olarak görünür ve uygulama açılmayı reddeder.
#:
#: Statik bir denetim (tests/test_packaging.py::test_windows_spec_wmi_
#: excludelamiyor) spec'in metnine bakıyor; buradaki denetim PAKETİN
#: KENDİSİNE bakıyor. İkisi farklı soruları cevaplıyor: "spec doğru mu"
#: ve "üretilen dosyada gerçekten var mı".
_SELFTEST_PLATFORM: dict[str, tuple[str, ...]] = {
    "win32": ("wmi", "pythoncom", "win32api", "win32con"),
}


def _selftest() -> int:
    """Paketlenmiş yapının bütünlüğünü GUI açmadan raporlar.

    Çıkış kodu 0 = her modül yüklendi. Ortam bilgisi (data dizini, AV
    motoru, anahtar kasası) BİLGİ amaçlı yazılıyor ve sonucu etkilemiyor:
    başsız bir koşucuda anahtar kasası zaten yok ve bu bir paketleme
    hatası değil.
    """
    import importlib
    import platform

    from CORE.paths import data_dir, running_in_appimage
    from CORE.version import __version__

    print(f"HYCLEUS   : {__version__}")
    print(f"Python    : {platform.python_version()}  ({sys.platform})")
    print(f"Donmuş    : {'evet' if hasattr(sys, 'frozen') else 'hayır'}")
    print(f"AppImage  : {'evet' if running_in_appimage() else 'hayır'}")
    print(f"data dizini: {data_dir()}")

    platform_modulleri = _SELFTEST_PLATFORM.get(sys.platform, ())
    if platform_modulleri:
        print(f"Platform modülleri: {sys.platform} → {', '.join(platform_modulleri)}")
    else:
        print(f"Platform modülleri: {sys.platform} → (yok)")

    denenecek = _SELFTEST_MODULLERI + _SELFTEST_UCUNCU_TARAF + platform_modulleri
    hatalar: list[str] = []
    for ad in denenecek:
        try:
            importlib.import_module(ad)
        except Exception as exc:
            hatalar.append(f"{ad}: {type(exc).__name__}: {exc}")

    toplam = len(denenecek)
    print(f"Modüller  : {toplam - len(hatalar)}/{toplam} yüklendi")

    # Bilgi satırları — başarısızlık sayılmıyorlar.
    try:
        from CORE.scanner_backends import select_backend
        motor = select_backend()
        print(f"AV motoru : {motor.ad}  (kullanılabilir: "
              f"{'evet' if motor.available() else 'hayır'})")
    except Exception as exc:
        print(f"AV motoru : okunamadı ({exc})")

    try:
        from CORE.secret_store import backend_name
        print(f"Anahtar kasası: {backend_name()}")
    except Exception as exc:
        print(f"Anahtar kasası: erişilemiyor ({type(exc).__name__})")

    # TPM düşüşünün GÖRÜNÜRLÜK kanallarından biri (diğer ikisi: açılıştaki
    # denetim kaydı ve Hakkında kutusu). Sessizce devre dışı kalan bir
    # güvenlik katmanı, hiç olmamasından kötüdür — B-025.
    try:
        from CORE.tpm_sealing import durum as _tpm_durum
        print(f"TPM mühürleme: {_tpm_durum().ozet()}")
    except Exception as exc:
        print(f"TPM mühürleme: okunamadı ({type(exc).__name__})")

    if hatalar:
        print("\nYÜKLENEMEYEN MODÜLLER:")
        for satir in hatalar:
            print(f"  · {satir}")
        return 1

    print("\nSELFTEST OK")
    return 0


def _erken_komut(args: list[str]) -> int | None:
    """GUI'siz bayrakları işler. `None` = normal açılışa devam."""
    if not ({"--version", "--selftest"} & set(args)):
        return None

    # Modül seviyesindeki basicConfig DEBUG'a ayarlı ve keyring'in arka uç
    # taraması onlarca satır basıyor. Bu iki komutun çıktısı MAKİNE
    # TARAFINDAN okunuyor (packaging/linux/smoke-test.sh); araya karışan
    # günlük satırları onu kırılgan yapar.
    logging.getLogger().setLevel(logging.WARNING)

    if "--version" in args:
        ensure_utf8_console()
        from CORE.version import __version__
        print(__version__)
        return 0
    if "--selftest" in args:
        ensure_utf8_console()
        return _selftest()
    return None


def _dev_key(hwid: str) -> bytes:
    """
    DEV_MODE için HWID'den deterministik 32-byte anahtar türetir.

    Sabit tuz BİLİNÇLİ ve kaldırılamaz: bu türetmenin tek işi aynı HWID'den
    her seferinde aynı anahtarı üretmek. Rastgele tuz onu imkânsız kılardı —
    tuzun kendisini bir yere yazmak gerekirdi ve o yer zaten anahtarın
    kendisini yazabileceğimiz yer olurdu.

    Bu, güvenlik açığı değil, BELGELENMİŞ bir zayıflık: SECURITY.md §4.3
    "DEV_MODE dosya anahtarını yalnızca HWID'den türetir" diyor. DEV_MODE
    üretimde kapalıdır; açıkken kasa PIN ve TOTP olmadan da açılır, yani
    tuz bu tabloda en zayıf halka bile değil.
    """
    # nosemgrep: hycleus-static-kdf-salt
    return hashlib.pbkdf2_hmac(
        "sha256",
        hwid.encode(),
        b"HYCLEUS-DEV-FILE-KEY-SALT-v1",
        100_000,
    )


def main() -> None:
    # QApplication'dan ÖNCE: --version/--selftest başsız çalışmalı, Qt'nin
    # ekran sunucusu araması bile olmadan.
    kod = _erken_komut(sys.argv[1:])
    if kod is not None:
        sys.exit(kod)

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

    # ── TPM mühürleme durumu ─────────────────────────────────────────────────
    # Sırlar TPM varsa mühürlenerek kasaya yazılıyor (CORE/tpm_sealing.py).
    # TPM yoksa mühürsüz yazılıyor ve bu DÜŞÜŞ SESSİZ KALMAMALI: sessizce
    # devre dışı kalan bir güvenlik katmanı, hiç olmamasından kötüdür —
    # belge onun varlığını iddia etmeye devam eder (B-025'in dersi).
    #
    # Modal uyarı BİLEREK YOK. TPM'siz makine (Linux, macOS, eski donanım)
    # olağan durum; her açılışta kapatılacak bir kutu, kullanıcıyı tıklayıp
    # geçmeye eğitir ve uyarının kendisini değersizleştirir. Kalıcı ve
    # okunabilir üç kanal seçildi: her oturumda denetim kaydı, --selftest
    # çıktısı, Hakkında kutusu. Asıl alarm zaten mühür AÇILAMADIĞINDA
    # çalıyor ve orası bir istisna (CORE/secret_store.py::load).
    try:
        _tpm_eylem, _tpm_detay = tpm_oturum_raporu()
        _log.info("tpm_sealing  %s  %s", _tpm_eylem, _tpm_detay)
        DBManager().log(_tpm_eylem, detail=_tpm_detay)
    except Exception as exc:  # görünürlük açılışı ENGELLEMEMELİ
        _log.warning("TPM durumu raporlanamadı: %s", exc)

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

    # ── Yedekleme hatırlatması (B-015) ───────────────────────────────────────
    # Yedekleme özelliği vardı ama hatırlatması yoktu; yedek yalnızca
    # kullanıcının aklına geldiğinde alınıyordu. Kullanılmayan bir yedekleme
    # özelliği, olmayan bir yedekleme özelliğidir.
    #
    # ENGELLEYİCİ DEĞİL: uyarı gösterilip geçiliyor, açılış durmuyor. "Sonra
    # sorma" bir eşik süresi daha susturuyor. Kararın hangi durumda hangi
    # cümleyi kurduğu CORE/backup_reminder.py'de — burada yalnızca gösterim.
    try:
        from CORE.backup_reminder import YedekDurum, ertele, yedek_durumu

        durum = yedek_durumu(DBManager())
        if durum.uyarilmali:
            _log.info("Yedek hatırlatması: %s", durum.durum)
            kutu = QMessageBox(None)
            kutu.setIcon(QMessageBox.Warning)
            kutu.setWindowTitle("Yedekleme Hatırlatması")
            kutu.setText(durum.mesaj())
            tamam = kutu.addButton("Tamam", QMessageBox.AcceptRole)
            sonra = kutu.addButton(
                f"Sonra sorma ({durum.esik_gun} gün)", QMessageBox.RejectRole
            )
            # Hedef erişilemiyorsa erteleme sunulmuyor: sorun yedeğin eskimesi
            # değil, kontrol edilememesi — ve o disk takılınca kendiliğinden
            # geçiyor. Ertelemek, gerçek bir "yedek eski" uyarısını da
            # bastırırdı.
            if durum.durum is YedekDurum.HEDEF_ERISILEMIYOR:
                kutu.removeButton(sonra)
            kutu.exec()
            if kutu.clickedButton() is not tamam:
                ertele(DBManager())
    except Exception as exc:  # hatırlatma açılışı engellemesin
        _log.warning("Yedek hatırlatması gösterilemedi: %s", exc)

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

    # ── Oturum kullanıcısını `users` tablosuna bağla (B-011) ─────────────────
    # Buraya kadar kimlik yalnızca vault dosyasında yaşıyordu; `users` tablosu
    # ondan habersizdi. HycleusWindow'a `user_id` hiç geçilmediği için sahiplik
    # her oturumda varsayılan 1'e yazılıyor, o satır yoksa da klasör oluşturma
    # sırasında UYDURULUYORDU (iki ayrı yerde). Artık bağlantı burada, giriş
    # anında ve gerçek bilgiyle kuruluyor.
    #
    # Başarısızlık açılışı ENGELLEMİYOR: kullanıcı zaten USB + PIN ile
    # doğrulandı ve dosyalarına erişimi `users` tablosuna bağlı değil. Geri
    # düşülen 1 değeri eski davranış — ama artık sessiz değil, kaydı düşüyor.
    try:
        user_id = sync_session_user(DBManager(), hwid=hwid, role=role)
    except Exception as exc:
        _log.error("Oturum kullanıcısı eşlenemedi (hwid=%s): %s", hwid, exc)
        user_id = 1

    win = HycleusWindow(hwid=hwid, key=session_key, role=role, user_id=user_id)
    win.show()
    # Kısıtlamalar show() sonrasında uygulanmalı — Qt ilk paint'te
    # __init__ içindeki setVisible() çağrılarını sıfırlayabilir.
    QTimer.singleShot(0, win._apply_role_restrictions)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
