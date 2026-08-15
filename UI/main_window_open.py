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
from PySide6.QtWidgets import QMessageBox

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
        os.startfile(str(path))  # type: ignore[attr-defined]  # noqa: S606
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


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
                self._checkouts, file_id=file_id, hcl_path=filepath,
                key=self._key, aad_hwid=aad_hwid,
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
                    self._checkouts, entry.file_id, self._key,
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
                self._checkouts, file_id, self._key,
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
            self._checkouts, self._key,
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
