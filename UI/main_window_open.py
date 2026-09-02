"""
HYCLEUS — Şeffaf erişim, arayüz tarafı

"Aç" komutu, dosya izleyici ve varsayılan uygulamayı başlatma. Karar
mantığının tamamı `CORE/checkout.py` içinde ve Qt'siz test edilebiliyor;
burada olan yalnızca Qt'ye bağlı olan kısım:

  · `QFileSystemWatcher` — değişikliği ERKEN yakalamak için
  · `QTimer` — izleyicinin kaçırdığı durumlar için yoklama ağı
  · `os.startfile` / `xdg-open` / `open` — varsayılan uygulamayı açmak
  · `QMessageBox` — kullanıcıya sormak

İzleyici bir OPTİMİZASYON
--------------------------
Bazı uygulamalar kaydederken dosyanın üzerine yazmıyor; yeni bir dosya
yazıp adını eskisinin üzerine taşıyor. Bu, `QFileSystemWatcher`'ın
izlediği düğümü düşürüyor ve olay hiç gelmiyor.

Bu yüzden üç katman var ve doğruluk EN ALTTAKİNDE:

  1. İzleyici olayı        → en hızlı, ama kaçırabilir
  2. Yoklama zamanlayıcısı → izleyici kaçırırsa yakalar (varsayılan 5 sn)
  3. Kapanışta check-in    → ikisi de kaçırsa bile özet karşılaştırması
                             değişikliği kesin yakalar

Üçü de aynı `CORE.checkout.has_changed()` kararını kullanıyor; fark
yalnızca ne zaman sorulduğu.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QFileSystemWatcher, QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from CORE.checkout import (
    CheckoutError,
    CheckoutRegistry,
    apply_checkin,
    check_in,
    check_in_all,
    check_out,
    has_changed,
    is_settled,
    log_checkout,
)
from CORE.safezone import safezone_dir
from DB.db_manager import DBManager

_log = logging.getLogger("hycleus.ui")

#: İzleyicinin kaçırdığı değişiklikleri yakalayan yoklama aralığı (ms).
#: 5 sn: kullanıcı kaydettikten sonra en geç bu kadar sonra geri
#: yazılıyor. Daha sık yoklamak her açık belge için sürekli hash
#: hesaplamak demek; daha seyrek olsa kapanışa kadar bekleyebilirdi.
POLL_INTERVAL_MS = 5_000


def open_with_default_app(path: Path) -> None:
    """
    Dosyayı işletim sisteminin varsayılan uygulamasıyla açar.

    Windows dışı yollar HYCLEUS'un hedef platformu değil ama geliştirme
    ve test ortamları için duruyor.
    """
    if sys.platform == "win32":
        # B606 (kabuksuz süreç başlatma): kabuk zaten yok — os.startfile
        # Windows'un kendi dosya ilişkilendirmesini çağırır, komut satırı
        # birleştirmesi yapmaz. Aşağıdaki susturma bilerek ID'siz: bandit
        # 1.9'da ID verilirse bulgu susuyor ama yanında "no failed test"
        # uyarısı basılıyor (B606 eklentisinin raporlama kimliği farklı).
        os.startfile(str(path))  # type: ignore[attr-defined]  # noqa: S606  # nosec
    # B607 (kısmi çalıştırılabilir yolu) aşağıdaki iki satırda GEREKÇELİ
    # susturuldu; denetim depo genelinde AÇIK kaldı (B-018). `wmic` tam yola
    # çevrildi çünkü Windows'ta `System32\wbem\wmic.exe` sabit. Bunlar öyle
    # değil: `xdg-open` dağıtıma göre /usr/bin ya da /usr/local/bin altında,
    # macOS `open`'ı da PATH üzerinden çözülmesi beklenen bir araç. Tam yol
    # yazmak, çalışan bir çağrıyı VARSAYIMA dayanarak kırmak olurdu.
    #
    # Risk kabul edilebilir: ikisi de Windows dışı yollar (HYCLEUS'un hedef
    # platformu değil) ve PATH ele geçirilmişse saldırganın makinede zaten
    # yazma erişimi var — SECURITY.md §1'in sınırının içinde.
    elif sys.platform == "darwin":
        # macOS `open` PATH üzerinden çözülmesi beklenen bir araç
        subprocess.Popen(["open", str(path)])  # nosec B607
    else:
        # `xdg-open` dağıtıma göre /usr/bin ya da /usr/local/bin altında
        subprocess.Popen(["xdg-open", str(path)])  # nosec B607


class OpenMixin:
    """Şeffaf erişim: aç → düzenle → geri şifrele."""

    # ── Kurulum ───────────────────────────────────────────────────────────────

    def _init_checkout(self) -> None:
        """`HycleusWindow.__init__` içinden çağrılıyor."""
        self._checkouts = CheckoutRegistry()
        self._watcher = QFileSystemWatcher(self)
        self._watcher.fileChanged.connect(self._on_watched_change)
        # Dizin de izleniyor: sil-ve-yeniden-yaz eden uygulamalarda dosya
        # yolu izlemesi düşüyor, dizin olayı ise geliyor.
        self._watcher.directoryChanged.connect(self._on_watched_change)

        self._checkout_timer = QTimer(self)
        self._checkout_timer.setInterval(POLL_INTERVAL_MS)
        self._checkout_timer.timeout.connect(self._sweep_checkouts)

    # ── Aç ────────────────────────────────────────────────────────────────────

    def _on_ctx_open(self, file_id: int | None, filepath: str | None) -> None:
        """Sağ tık → Aç."""
        if file_id is None or not filepath:
            QMessageBox.warning(self, "Aç", "Dosya yolu bulunamadı.")
            return

        db = DBManager()
        aad_hwid = self._aad_hwid_of(file_id)

        try:
            entry = check_out(
                self._checkouts, db=db, file_id=file_id, hcl_path=filepath,
                key=self._key, aad_hwid=aad_hwid, user_id=self._user_id,
            )
        except CheckoutError as exc:
            _log.error("checkout_failed  file_id=%s exc=%s", file_id, exc)
            QMessageBox.critical(self, "Aç", str(exc))
            return

        try:
            log_checkout(db, entry, user_id=self._user_id, hwid=self._hwid)
        except Exception as exc:  # denetim kaydı açmayı engellemesin
            _log.warning("checkout_log_failed  exc=%s", exc)

        # Yol izlemesi + dizin izlemesi. addPath aynı yolu iki kez
        # eklemiyor, tekrar açmada sorun çıkmıyor.
        self._watcher.addPath(str(entry.safe_path))
        kok = str(safezone_dir())
        if kok not in self._watcher.directories():
            self._watcher.addPath(kok)
        if not self._checkout_timer.isActive():
            self._checkout_timer.start()

        try:
            open_with_default_app(entry.safe_path)
        except Exception as exc:
            _log.error("launch_failed  path=%s exc=%s", entry.safe_path, exc)
            QMessageBox.warning(
                self, "Aç",
                f"Dosya çözüldü ama varsayılan uygulama açılamadı:\n{exc}\n\n"
                f"Geçici kopya: {entry.safe_path}",
            )

        self._refresh_open_banner()

    def _aad_hwid_of(self, file_id: int) -> str | None:
        """`decrypt_file`'a geçilecek HWID — AAD'den okunuyor."""
        import json

        try:
            row = DBManager().fetchone(
                "SELECT aad_metadata FROM files WHERE id = ?", (file_id,))
            if row and row["aad_metadata"]:
                return json.loads(row["aad_metadata"]).get("hwid")
        except Exception:
            pass
        return None

    # ── Değişiklik yakalama ───────────────────────────────────────────────────

    def _on_watched_change(self, _path: str) -> None:
        """
        İzleyici olayı geldi — hemen değil, durulunca yaz.

        Doğrudan buradan geri yazmak, yarı yazılmış bir dosyayı
        şifrelemek olurdu. Karar `_sweep_checkouts` içinde ve orada
        `is_settled()` kontrolü var.
        """
        QTimer.singleShot(int(1000), self._sweep_checkouts)

    def _sweep_checkouts(self) -> None:
        """
        Açık belgeleri gözden geçirir; durulmuş ve değişmiş olanları yazar.

        Hem izleyici olayından hem yoklama zamanlayıcısından çağrılıyor;
        ikisi de aynı kararı veriyor, fark yalnızca ne zaman sorulduğu.
        """
        if not getattr(self, "_checkouts", None) or not len(self._checkouts):
            if getattr(self, "_checkout_timer", None):
                self._checkout_timer.stop()
            return

        db = DBManager()
        for entry in self._checkouts.all():
            # İzlenen yol silinip yeniden yazılmış olabilir; izlemeyi tazele.
            if entry.exists() and str(entry.safe_path) not in self._watcher.files():
                self._watcher.addPath(str(entry.safe_path))

            if not (has_changed(entry) and is_settled(entry)):
                continue
            try:
                sonuc = check_in(
                    self._checkouts, entry.file_id, self._key, db=db,
                    user_id=self._user_id, hwid=self._hwid,
                    reason="autosave", shred=False,   # belge açık kalıyor
                )
                apply_checkin(db, sonuc, user_id=self._user_id, hwid=self._hwid)
            except CheckoutError as exc:
                _log.error("autosave_failed  file_id=%s exc=%s", entry.file_id, exc)

        self._refresh_open_banner()

    # ── Kapat ─────────────────────────────────────────────────────────────────

    def _on_ctx_close_file(self, file_id: int | None) -> None:
        """Sağ tık → Bitir: geri yaz, geçici kopyayı sil."""
        if file_id is None or file_id not in self._checkouts:
            return
        entry = self._checkouts.get(file_id)
        if entry is not None:
            self._watcher.removePath(str(entry.safe_path))

        db = DBManager()
        try:
            sonuc = check_in(
                self._checkouts, file_id, self._key, db=db,
                user_id=self._user_id, hwid=self._hwid, reason="manual",
            )
            apply_checkin(db, sonuc, user_id=self._user_id, hwid=self._hwid)
        except CheckoutError as exc:
            QMessageBox.critical(
                self, "Bitir",
                f"{exc}\n\nDüzenlenmiş kopya SİLİNMEDİ; değişikliğiniz "
                "kaybolmasın diye SafeZone'da bırakıldı.",
            )
            return

        self._refresh_open_banner()
        self._refresh_table()

    def _close_all_checkouts(self, reason: str = "shutdown") -> None:
        """
        Kapanışta ve oturum kilidinde çağrılıyor.

        Oturum kilidinde de çağrılmasının sebebi: kilit ekranı düz metin
        kopyaları diskte bırakırsa, kilidin koruduğu şeyin yanında açık
        bir kapı kalırdı.
        """
        if not getattr(self, "_checkouts", None) or not len(self._checkouts):
            return
        db = DBManager()
        for sonuc in check_in_all(
            self._checkouts, self._key, db=db,
            user_id=self._user_id, hwid=self._hwid, reason=reason,
        ):
            try:
                apply_checkin(db, sonuc, user_id=self._user_id, hwid=self._hwid)
            except Exception as exc:
                _log.error("checkin_apply_failed  file_id=%s exc=%s",
                           sonuc.file_id, exc)
        if getattr(self, "_checkout_timer", None):
            self._checkout_timer.stop()

    # ── Görünürlük ────────────────────────────────────────────────────────────

    def _refresh_open_banner(self) -> None:
        """
        Kaç belgenin açık olduğunu gösterir.

        Görünürlük bir süs değil: açık her belge SafeZone'da DÜZ METİN
        olarak duruyor. Kullanıcının kaç tane olduğunu görmesi gerekiyor,
        yoksa "kapatmayı unuttum" sessiz bir duruma dönüşür.
        """
        etiket = getattr(self, "_open_files_label", None)
        if etiket is None:
            return
        n = len(self._checkouts)
        etiket.setText(f"  {n} belge açık  " if n else "")
        etiket.setVisible(bool(n))


class BackupMixin:
    """
    Yedek ALMA ve DOĞRULAMA — arayüz tarafı.

    GERİ YÜKLEME komut satırında kalıyor (`CORE/backup_cli.py --restore`)
    ve bu ayrım bilinçli: geri yüklemenin tipik senaryosu "disk gitti,
    yeni makine" ve o makinede grafik arayüz AÇILMIYOR — `main.py` takılı
    ve kayıtlı bir USB ile bir vault dosyası istiyor, ikisi de yok.
    Ayrıntılı gerekçe `CORE/backup_cli.py` modül docstring'inde.

    Yedek alma ve doğrulama ise rutin işler ve ikisi de zaten çalışan bir
    oturumda yapılıyor. Menüde olmalarının sebebi basit: bulunamayan bir
    yedekleme özelliği, olmayan bir yedekleme özelliğidir — ve hiç
    doğrulanmayan bir yedek, olmayan bir yedektir.

    Doğrulama komut satırından KALKMIYOR. `--verify` orada duruyor ve
    orada durması gerekiyor: çıkış kodu var, yani bir betik ya da
    zamanlanmış bir iş sonucu okuyabilir; bir diyalog kutusu okuyamaz.
    """

    def _on_create_backup(self) -> None:
        from PySide6.QtWidgets import QFileDialog, QProgressDialog

        from CORE.backup import BackupError, create_backup, default_backup_name

        hedef = QFileDialog.getExistingDirectory(
            self, "Yedeğin yazılacağı dizini seçin (harici disk önerilir)")
        if not hedef:
            return

        yol = Path(hedef) / default_backup_name()
        if yol.exists():
            QMessageBox.warning(
                self, "Yedek Al",
                f"Bu ada sahip bir dizin zaten var:\n{yol}\n\n"
                "Bir dakika bekleyip tekrar deneyin.")
            return

        ilerleme = QProgressDialog("Yedekleniyor…", "İptal", 0, 0, self)
        ilerleme.setWindowTitle("Yedek Al")
        ilerleme.setMinimumDuration(0)
        ilerleme.setValue(0)

        def _adim(i: int, n: int, ad: str) -> None:
            ilerleme.setMaximum(n)
            ilerleme.setValue(i)
            ilerleme.setLabelText(f"({i}/{n})  {ad}")
            QApplication.processEvents()

        try:
            rapor = create_backup(
                DBManager(), yol, self._key,
                user_id=self._user_id, hwid=self._hwid, on_progress=_adim,
            )
        except BackupError as exc:
            ilerleme.close()
            QMessageBox.critical(self, "Yedek Al", str(exc))
            return
        finally:
            ilerleme.close()

        mesaj = [rapor.summary(), ""]
        if rapor.skipped:
            mesaj += [
                f"⚠  {len(rapor.skipped)} dosya kopyalanamadı ve yedeğe "
                "GİRMEDİ:", *(f"   • {ad}" for ad in rapor.skipped[:10]), "",
            ]
        mesaj += [
            "Yedeği doğrulamak için menüden “Yedek Doğrula…” seçin.",
            "Betikten çalıştırmak isterseniz (çıkış kodu döner):",
            f"  python CORE/backup_cli.py --verify \"{yol}\" --deep",
            "",
            "Not: anahtar kasası (.hclv) yedeğe DAHİL DEĞİL. Anahtar kaybı",
            "için kurtarma parçasını kullanın (recover_vault.py --export).",
        ]
        QMessageBox.information(self, "Yedek Tamamlandı", "\n".join(mesaj))

    def _on_verify_backup(self, *, sade: bool = False) -> None:
        """
        Bir yedek dizinini GERİ YÜKLEMEDEN doğrular.

        `sade` YALNIZCA Güvenlik sekmesinden geliyor (`UI/GuvenlikView.py`);
        hamburger menüsü varsayılanı kullanıyor ve bugünkü çıktısı
        DEĞİŞMİYOR.

        Komut satırındaki `--verify --deep` ile AYNI fonksiyonu
        (`CORE.backup.verify_backup`) çağırıyor; ikinci bir doğrulama
        uygulaması DEĞİL.

        Derin mod varsayılan: anahtar oturumda zaten elde, yani bütünlük
        mührü kontrolünün ek bir kullanıcı adımı yok. CLI'da opsiyonel
        olmasının sebebi orada anahtarın USB + PIN istemesi.

        İlerleme ve iptal ZORUNLU, süs değil: doğrulama her baytı okuyor
        (derin modda iki kez) ve yedeğin doğal yeri harici disk. Ölçüldü —
        işlemci tarafında ~1,3 GB/s, ama 120 MB/s bir diskte 50 GB'lık bir
        yedek on dakikaları buluyor.
        """
        from PySide6.QtWidgets import QFileDialog, QProgressDialog

        from CORE.backup import verify_backup
        from UI.BackupVerifyDialog import BackupVerifyDialog

        secilen = QFileDialog.getExistingDirectory(
            self, "Doğrulanacak yedek dizinini seçin")
        if not secilen:
            return
        yedek = Path(secilen)

        ilerleme = QProgressDialog("Yedek doğrulanıyor…", "İptal", 0, 0, self)
        ilerleme.setWindowTitle("Yedek Doğrula")
        ilerleme.setMinimumDuration(0)
        ilerleme.setValue(0)

        def _adim(i: int, n: int, ad: str) -> None:
            ilerleme.setMaximum(n)
            ilerleme.setValue(i)
            ilerleme.setLabelText(f"({i}/{n})  {ad}")
            QApplication.processEvents()

        try:
            rapor = verify_backup(
                yedek, key=self._key, hwid=self._hwid,
                on_progress=_adim,
                should_continue=lambda: not ilerleme.wasCanceled(),
            )
        except Exception as exc:
            # `verify_backup()` beklenen hataları rapora çeviriyor
            # (`error` alanı); buraya yalnızca öngörülmeyen bir okuma
            # hatası düşer. Yakalanmazsa pencere kapanırdı.
            _log.error("verify_backup_error  dir=%s  exc=%s", yedek, exc)
            QMessageBox.critical(
                self, "Yedek Doğrula",
                f"Yedek doğrulanamadı — beklenmeyen bir hata oluştu.\n\n{exc}")
            return
        finally:
            ilerleme.close()

        # Denetim kaydı: "yedeğim sağlam mı" sorusunun ne zaman sorulduğu
        # ve ne yanıt aldığı, yedekleme disiplininin kendisi kadar önemli.
        try:
            DBManager().log(
                "backup_verified",
                user_id=self._user_id,
                detail=(
                    f"hwid={self._hwid} dir={yedek} ok={rapor.ok} "
                    f"deep={rapor.deep} checked={rapor.checked}/{rapor.total} "
                    f"cancelled={rapor.cancelled}"
                ),
            )
        except Exception as exc:  # pragma: no cover — kayıt, sonucu engellemez
            _log.warning("backup_verify_log_failed  exc=%s", exc)

        icerik = BackupVerifyDialog(rapor, yedek, sade=sade, T=self._T)
        self._open_slide_over(f"Yedek Doğrula · {yedek.name}", icerik)
