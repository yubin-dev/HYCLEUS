"""
HYCLEUS — Dosya tablosu, sürükle-bırak ve toplu işçiler

UI/main_window.py'den 2.7 refactor'ünde ayrıldı. Metot gövdeleri
kelimesi kelimesine taşındı; davranış değişmedi.

`HycleusWindow` bu mixin'i miras alıyor, dolayısıyla `self` hâlâ
pencerenin kendisi ve çağrı yerleri değişmedi.
"""
import json
import logging
# timedelta modül seviyesinde artık kullanılmıyor: "şimdi + TTL" hesabı
# CORE/expiry.py'ye taşındı. _FileRunnable.run() kendi yerel import'unu
# yapıyor (worker thread'inde çalışıyor, bkz. satır ~218).
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger("hycleus.ui")

from PySide6.QtCore import (
    QEvent,
    QObject,
    QRunnable,
    QThread,
    Qt,
    QTimer,
    Signal,
)

# Hareketsizlik sayacını sıfırlayan olaylar. Yalnızca GERÇEK kullanıcı
# etkileşimi: zamanlayıcı tik'leri, boyama ve pencere olayları buraya
# GİRMEZ — girseydi ekranda dönen bir ilerleme çubuğu bile oturumu sonsuza
# kadar açık tutardı.
_ACTIVITY_EVENTS = frozenset({
    QEvent.MouseButtonPress,
    QEvent.MouseButtonRelease,
    QEvent.MouseButtonDblClick,
    QEvent.MouseMove,
    QEvent.KeyPress,
    QEvent.KeyRelease,
    QEvent.Wheel,
    QEvent.TouchBegin,
    QEvent.TouchUpdate,
})
from PySide6.QtGui import (
    QColor,
    QDragEnterEvent,
    QDragMoveEvent,
    QDropEvent,
    QResizeEvent,
)
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QTableWidgetItem,
    QWidget,
)


from CORE.crypto import encrypt_file
from CORE.duplicates import (
    find_duplicates_for_file,
    format_duplicate_warning,
    log_duplicate_decision,
)
from CORE.expiry import banner_for, countdown_for, ttl_hours
from CORE.file_records import record_encrypted_file
from CORE.scanner import ScanResult, scan_file
from CORE.usb_manager import DEV_MODE as _DEV_MODE, get_usb_hwid
from DB.db_manager import DBManager

from UI.main_window_palette import (
    _LABEL_PILL_STYLE,
    _VERDICT_BADGE,
)


# ── Batch file-processing worker ─────────────────────────────────────────────

class _ProcessSignals(QObject):
    """Main-thread signal bridge for QRunnable workers."""
    file_done = Signal(object)   # dict result


class _FileRunnable(QRunnable):
    """Encrypt → DB insert → scan a single file in the thread pool."""

    def __init__(
        self,
        src: Path,
        key: bytes,
        hwid: str,
        label: str,
        folder_id: int | None,
        signals: _ProcessSignals,
        ttl_hours: int = 24,
        user_id: int = 1,
    ) -> None:
        super().__init__()
        self.setAutoDelete(True)
        self._src       = src
        self._key       = key
        self._hwid      = hwid
        self._label     = label
        self._folder_id = folder_id
        self._signals   = signals
        self._ttl_hours = ttl_hours
        self._user_id   = user_id

    def run(self) -> None:
        from datetime import datetime, timedelta, timezone as _tz
        result: dict = {
            "ok": False, "filename": self._src.name,
            "label": self._label, "folder_id": self._folder_id,
        }

        try:
            hcl_path, sha256_hex, aad_json = encrypt_file(
                self._src, self._key, user_id=self._user_id, hwid=self._hwid,
            )
        except Exception as exc:
            result["error"] = f"Şifreleme: {exc}"
            self._signals.file_done.emit(result)
            return

        expires_at = (
            datetime.now(_tz.utc) + timedelta(hours=self._ttl_hours)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        today      = datetime.now(_tz.utc).strftime("%Y-%m-%d")
        size_bytes = self._src.stat().st_size

        try:
            db = DBManager()
            # SQL CORE/file_records.py'ye taşındı: satır içi durduğu sürece
            # Qt'siz test edilemiyordu ve added_by kolonu gözden kaçmıştı.
            file_id = record_encrypted_file(
                db,
                filename=self._src.name,
                filepath=str(hcl_path),
                label=self._label,
                size_bytes=size_bytes,
                expires_at=expires_at,
                original_sha256=sha256_hex,
                aad_metadata=aad_json,
                folder_id=self._folder_id,
                added_by=self._user_id,
            )
            db.log("file_added", user_id=self._user_id,
                   target_type="file", target_id=file_id,
                   detail=f"label={self._label} hwid={self._hwid} hcl={hcl_path.name}")
        except Exception as exc:
            result["error"] = f"Veritabanı: {exc}"
            self._signals.file_done.emit(result)
            return

        verdict = ""
        mock    = False
        try:
            sr      = scan_file(hcl_path, file_id=file_id)
            verdict = sr.verdict
            mock    = sr.mock
        except Exception:
            pass

        result.update({
            "ok": True, "file_id": file_id,
            "filename": self._src.name, "label": self._label,
            "size_bytes": size_bytes, "date": today,
            "sha256": sha256_hex, "filepath": str(hcl_path),
            "expires_at": expires_at, "verdict": verdict, "mock": mock,
        })
        self._signals.file_done.emit(result)


# ── Scan worker ───────────────────────────────────────────────────────────────

class _ScanWorker(QObject):
    finished = Signal(int, object)  # (row, ScanResult)

    def __init__(self, path: Path, file_id: int, row: int) -> None:
        super().__init__()
        self._path    = path
        self._file_id = file_id
        self._row     = row

    def run(self) -> None:
        _log.info("worker_run  file=%s  file_id=%d", self._path.name, self._file_id)
        try:
            result = scan_file(self._path, file_id=self._file_id)
        except Exception:
            _log.exception("worker_error  file=%s", self._path.name)
            from CORE.scanner import _mock, _sha256
            result = _mock(_sha256(self._path))
        self.finished.emit(self._row, result)


class TableMixin:
    """Dosya tablosu, sürükle-bırak ve toplu işçiler."""

    def _populate_table(self, rows: list) -> None:
        for row in rows:
            verdict, mock = "", False
            if row["scan_reason"]:
                try:
                    d       = json.loads(row["scan_reason"])
                    verdict = d.get("verdict", "")
                    mock    = d.get("mock", False)
                except Exception:
                    pass
            self._insert_row(
                row["filename"],
                row["label"],
                self._fmt_size(row["size_bytes"] or 0),
                (row["added_at"] or "")[:10],
                scan_verdict=verdict,
                scan_mock=mock,
                file_id=row["id"],
                sha256=row["original_sha256"],
                filepath=row["filepath"] or "",
                expires_at=row["expires_at"] or "",
            )

    # ── Tablo yardımcıları ────────────────────────────────────────────────────

    def _insert_row(
        self, name: str, label: str, size: str, date: str,
        scan_verdict: str = "", scan_mock: bool = False,
        file_id: int | None = None,
        sha256: str | None = None,
        filepath: str = "",
        expires_at: str = "",
    ) -> None:
        row    = self._table.rowCount()
        is_hcl = filepath.endswith(".hcl")
        self._table.insertRow(row)

        # Sütun 0 — dosya adı
        display_name = ("🔒  " + name) if is_hcl else name
        name_item    = QTableWidgetItem(display_name)
        name_item.setData(Qt.UserRole,     file_id)
        name_item.setData(Qt.UserRole + 1, sha256)
        name_item.setData(Qt.UserRole + 2, label)
        name_item.setData(Qt.UserRole + 3, filepath)
        name_item.setData(Qt.UserRole + 4, expires_at)
        if is_hcl:
            name_item.setForeground(QColor("#2563EB"))
        self._table.setItem(row, 0, name_item)

        # Sütun 1 — etiket pill (setCellWidget)
        fg, bg = _LABEL_PILL_STYLE.get(label, ("#6B7280", "#F3F4F6"))
        pill = QLabel(label)
        pill.setAlignment(Qt.AlignCenter)
        pill.setStyleSheet(
            f"QLabel {{ color: {fg}; background: {bg}; border-radius: 12px;"
            f" padding: 2px 8px; font-size: 13px; font-weight: 500; }}"
        )
        pill_wrap = QWidget()
        pill_wrap.setAttribute(Qt.WA_TransparentForMouseEvents)
        pill_wrap.setStyleSheet("background: transparent;")
        ph = QHBoxLayout(pill_wrap)
        ph.setContentsMargins(8, 8, 8, 8)
        ph.addWidget(pill)
        self._table.setCellWidget(row, 1, pill_wrap)

        # Sütunlar 2-3 — boyut, tarih
        size_item = QTableWidgetItem(size)
        date_item = QTableWidgetItem(date)
        size_item.setTextAlignment(Qt.AlignCenter)
        date_item.setTextAlignment(Qt.AlignCenter)
        self._table.setItem(row, 2, size_item)
        self._table.setItem(row, 3, date_item)

        # Sütun 4 — tarama sonucu
        if scan_verdict:
            text, color = _VERDICT_BADGE.get(scan_verdict, ("—", "#9CA3AF"))
            if scan_mock:
                text, color = text + " (m)", "#9CA3AF"
            self._set_scan_badge(row, text, color)

    def _set_scan_badge(self, row: int, text: str, color: str) -> None:
        if row >= self._table.rowCount():
            return
        item = QTableWidgetItem(text)
        item.setForeground(QColor(color))
        item.setTextAlignment(Qt.AlignCenter)
        self._table.setItem(row, 4, item)

    @staticmethod
    def _fmt_size(size_bytes: int) -> str:
        size: float = float(size_bytes)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    # ── İmha Odası sayacı ─────────────────────────────────────────────────────

    def _tick_expiry(self) -> None:
        """
        İmha Odası geri sayımını saniyede bir tazeler.

        Matematiğin tamamı CORE/expiry.py'de: kalan süre, biçim, aciliyet
        eşikleri ve "boş mu / süresiz mi" ayrımı. Buradaki iş yalnızca
        hücreleri boyamak ve süresi dolanları tablodan düşürmek.
        """
        if self._current_label != "Imha":
            return
        now = datetime.now(timezone.utc)
        expired_rows: list[tuple[int, int | None, str]] = []
        kalanlar: list[float | None] = []

        for row in range(self._table.rowCount()):
            name_item = self._table.item(row, 0)
            if name_item is None:
                continue
            expires_str: str    = name_item.data(Qt.UserRole + 4) or ""
            file_id: int | None = name_item.data(Qt.UserRole)
            filepath: str       = name_item.data(Qt.UserRole + 3) or ""

            durum = countdown_for(expires_str, now=now)
            if durum.expired:
                expired_rows.append((row, file_id, filepath))
                continue

            kalanlar.append(durum.remaining)
            ci = self._table.item(row, 3)
            if ci:
                ci.setText(durum.text())
                aciliyet = durum.urgency()
                if aciliyet is not None:
                    ci.setForeground(QColor(self._T[aciliyet]))

        for row, file_id, filepath in sorted(expired_rows, key=lambda t: t[0], reverse=True):
            self._table.removeRow(row)
            self._purge_expired_file(file_id, filepath)

        bant = banner_for(kalanlar, row_count=self._table.rowCount())
        aciliyet = bant.urgency()
        renk = self._T[aciliyet] if aciliyet else self._T["subtext"]
        self._expiry_banner.setText(bant.text())
        self._expiry_banner.setStyleSheet(
            f"color:{renk}; font-size:13px;"
            + ("font-weight:600;" if aciliyet else "")
            + f"background:{self._T['sidebar']}; border-radius:8px; padding:4px 12px;"
            f"margin:4px 12px 0;"
        )

    def _purge_expired_file(self, file_id: int | None, filepath: str) -> None:
        if filepath:
            try:
                p = Path(filepath)
                if p.exists():
                    p.unlink()
            except Exception:
                pass
        if file_id is not None:
            try:
                db = DBManager()
                db.execute("DELETE FROM files WHERE id = ?", (file_id,))
                db.log("expired_purge", target_type="file", target_id=file_id,
                       detail=f"label=Imha filepath={filepath}")
            except Exception:
                pass

    def _get_imha_ttl_hours(self) -> int:
        """İmha TTL süresi — hesap CORE/expiry.py'de."""
        return ttl_hours(DBManager())

    def _start_scan(self, path: Path, file_id: int, row: int) -> None:
        self._set_scan_badge(row, "⟳ Taranıyor...", "#D97706")
        worker = _ScanWorker(path, file_id, row)
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_scan_done)
        worker.finished.connect(thread.quit)
        worker.finished.connect(
            lambda w=worker: self._workers.remove(w) if w in self._workers else None
        )
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(
            lambda t=thread: self._threads.remove(t) if t in self._threads else None
        )
        self._workers.append(worker)
        self._threads.append(thread)
        QTimer.singleShot(0, thread.start)

    def _on_scan_done(self, row: int, result: ScanResult) -> None:
        text, color = _VERDICT_BADGE.get(result.verdict, ("—", "#9CA3AF"))
        if result.mock:
            text, color = text + " (m)", "#9CA3AF"
        self._set_scan_badge(row, text, color)

    # ── Drag & drop ───────────────────────────────────────────────────────────

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if self._role.strip().lower() == "salt okunur":
            event.ignore()
            return
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._drop_hint.setStyleSheet(
                "QLabel { color: #2563EB; font-size: 13px;"
                " border: 2px dashed #2563EB; border-radius: 8px;"
                " background: #EFF6FF; margin: 12px; }"
            )
        else:
            event.ignore()

    def dragMoveEvent(self, event: QDragMoveEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragLeaveEvent(self, event) -> None:
        self._reset_drop_hint_style()

    def dropEvent(self, event: QDropEvent) -> None:
        self._reset_drop_hint_style()
        if self._role.strip().lower() == "salt okunur":
            _log.debug("drop_blocked  role=%r", self._role)
            event.ignore()
            return
        for url in event.mimeData().urls():
            local = url.toLocalFile()
            if not local:
                continue
            p = Path(local)
            if p.is_dir():
                self._handle_dropped_folder(p, label="Karantina")
            elif p.is_file():
                self._handle_dropped_file(p, label="Karantina")

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._overlay.resize(self.size())

    def _reset_drop_hint_style(self) -> None:
        T = self._T
        bg = T["sidebar"] if self._dark else "#FAFAFA"
        self._drop_hint.setStyleSheet(
            f"QLabel {{ color: #9CA3AF; font-size: 13px;"
            f" border: 2px dashed #D1D5DB; border-radius: 8px;"
            f" background: {bg}; margin: 12px; }}"
        )

    def _handle_dropped_file(self, src: Path, label: str = "Karantina",
                             folder_id: int | None = None) -> None:
        if not src.is_file():
            return
        if get_usb_hwid() is None:
            QMessageBox.warning(self, "USB Bulunamadı",
                                "Yetkili USB cihazı takılı değil.\nDosya eklenemez.")
            self._refresh_usb_badge()
            return
        self._start_batch([(src, label, folder_id)])

    def _handle_dropped_folder(self, folder: Path, label: str = "Karantina") -> None:
        files = sorted(p for p in folder.rglob("*") if p.is_file())
        if not files:
            QMessageBox.information(self, "Klasör Ekle",
                                    f"'{folder.name}' klasöründe dosya bulunamadı.")
            return

        folder_id: int | None = None
        try:
            db = DBManager()
            _urow = db.fetchone("SELECT id FROM users WHERE id = ?", (self._user_id,))
            if _urow is None:
                _ehwid = "DEV-HWID-1234" if _DEV_MODE else (self._hwid or "")
                db.execute(
                    "INSERT INTO users (id, username, password_hash, role, status, hwid)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (self._user_id, "yonetici", "", "admin", "approved", _ehwid),
                )
            db.execute("INSERT INTO folders (name, owner_id) VALUES (?, ?)",
                       (folder.name, self._user_id))
            _frow = db.fetchone(
                "SELECT id FROM folders WHERE name = ? AND owner_id = ? ORDER BY id DESC LIMIT 1",
                (folder.name, self._user_id),
            )
            if _frow:
                folder_id = _frow["id"]
            db.log("folder_created",
                   detail=f"name={folder.name} hwid={self._hwid} via=drag_drop files={len(files)}")
        except Exception as exc:
            _log.warning("folder_create_failed  exc=%s", exc)

        self._start_batch([(f, label, folder_id) for f in files])

    # ── Batch pipeline ────────────────────────────────────────────────────────

    def _check_duplicates(
        self, files: list[tuple[Path, str, int | None]]
    ) -> list[tuple[Path, str, int | None]]:
        """
        Yüklemeden ÖNCE tekrar taraması; kullanıcının onayladığı listeyi döndürür.

        Uyarı ENGELLEYİCİ DEĞİL: aynı içerikli belgelerin bilerek tutulması
        gereken durumlar var (farklı sürümler aynı içeriğe sahip olabilir,
        ya da bir belgenin iki bağlamda da bulunması istenebilir). Bu yüzden
        varsayılan düğme "Yine de ekle".

        Neden burada, `_FileRunnable` içinde değil
        ------------------------------------------
        Yükleme QThreadPool'da paralel koşuyor ve Qt diyalogları yalnızca
        ana iş parçacığından açılabiliyor. Kontrol worker'ın içine konsaydı
        soruyu soracak yer olmazdı. Ayrıca tek bir toplu soru, 150 dosyalık
        bir klasörde 150 ayrı diyalogdan iyi.

        Ana iş parçacığında hash'lemenin bedeli ölçüldü: 150 küçük belge
        0,61 s, 500 MB'lık tek dosya 0,27 s (küçük dosyalarda maliyet
        dosya açmaktan geliyor, veri hacminden değil). Bekleme imleci bu
        süre için yeterli; ayrı bir iş parçacığı bu ölçekte karmaşıklığı
        hak etmiyor.
        """
        if not files:
            return files

        yonetici = self._role.strip().lower() in ("yönetici", "yonetici", "admin")
        bulgular: list[tuple[Path, str, list]] = []

        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            db = DBManager()
            for src, _label, _fid in files:
                try:
                    _sha, eslesmeler = find_duplicates_for_file(
                        db, src, include_private=yonetici
                    )
                except OSError as exc:
                    # Okunamayan dosya burada durdurulmuyor: asıl hata
                    # şifreleme adımında zaten raporlanacak ve oradaki
                    # mesaj daha doğru. Tekrar kontrolü bir kolaylık.
                    _log.warning("dup_check_failed  file=%s exc=%s", src.name, exc)
                    continue
                if eslesmeler:
                    bulgular.append((src, _sha, eslesmeler))
        finally:
            QApplication.restoreOverrideCursor()

        if not bulgular:
            return files

        if len(bulgular) == 1:
            src, _sha, eslesmeler = bulgular[0]
            metin = format_duplicate_warning(src.name, eslesmeler)
        else:
            metin = (
                f"{len(bulgular)} dosya, kasada zaten kayıtlı belgelerle "
                "aynı içeriğe sahip:\n\n"
                + "\n\n".join(
                    format_duplicate_warning(src.name, esl)
                    for src, _s, esl in bulgular[:5]
                )
                + ("\n\n…" if len(bulgular) > 5 else "")
            )

        kutu = QMessageBox(self)
        kutu.setIcon(QMessageBox.Question)
        kutu.setWindowTitle("Mükerrer Belge")
        kutu.setText(metin)
        kutu.setInformativeText("Yine de eklensin mi?")
        yine_de = kutu.addButton("Yine de Ekle", QMessageBox.AcceptRole)
        kutu.addButton("Tekrarları Atla", QMessageBox.RejectRole)
        kutu.setDefaultButton(yine_de)
        kutu.exec()

        eklendi = kutu.clickedButton() is yine_de
        tekrar_yollari = {src for src, _s, _e in bulgular}

        try:
            db = DBManager()
            for src, sha, esl in bulgular:
                log_duplicate_decision(
                    db, filename=src.name, sha256=sha, matches=esl,
                    added_anyway=eklendi, user_id=self._user_id,
                )
        except Exception as exc:  # denetim kaydı yüklemeyi engellemesin
            _log.warning("dup_log_failed  exc=%s", exc)

        if eklendi:
            return files
        return [t for t in files if t[0] not in tekrar_yollari]

    def _start_batch(self, files: list[tuple[Path, str, int | None]]) -> None:
        files = self._check_duplicates(files)
        if not files:
            return

        if self._batch_done >= self._batch_total:
            self._batch_total  = 0
            self._batch_done   = 0
            self._batch_errors = 0
            self._batch_has_folder = False

        self._batch_total += len(files)
        self._batch_has_folder = self._batch_has_folder or any(
            fid is not None for _, _, fid in files
        )
        self._update_progress_banner()

        ttl = self._get_imha_ttl_hours()
        for src, label, folder_id in files:
            runnable = _FileRunnable(
                src=src, key=self._key, hwid=self._hwid,
                label=label, folder_id=folder_id,
                signals=self._batch_signals, ttl_hours=ttl,
            )
            self._pool.start(runnable)

    def _on_file_done(self, result: dict) -> None:
        self._batch_done += 1
        if result.get("ok"):
            self._insert_row(
                result["filename"], result["label"],
                self._fmt_size(result["size_bytes"]),
                result["date"],
                scan_verdict=result["verdict"],
                scan_mock=result["mock"],
                file_id=result["file_id"],
                sha256=result["sha256"],
                filepath=result["filepath"],
                expires_at=result["expires_at"],
            )
            self._table.scrollToBottom()
        else:
            self._batch_errors += 1
            _log.warning("batch_file_error  file=%s  err=%s",
                         result.get("filename"), result.get("error"))
        self._update_progress_banner()
        if self._batch_done >= self._batch_total:
            self._on_batch_complete()

    def _on_batch_complete(self) -> None:
        success = self._batch_done - self._batch_errors
        errors  = self._batch_errors
        self._progress_banner.setVisible(False)
        if self._batch_has_folder:
            self._refresh_folder_sidebar()
        msg = f"Tamamlandı — {success}/{self._batch_done} dosya işlendi"
        if errors:
            msg += f", {errors} hata"
        QMessageBox.information(self, "Yükleme Tamamlandı", msg)

    def _update_progress_banner(self) -> None:
        if self._batch_total == 0:
            self._progress_banner.setVisible(False)
            return
        self._progress_banner.setText(
            f"⏳  {self._batch_done}/{self._batch_total} işlendi"
            + (f"  ({self._batch_errors} hata)" if self._batch_errors else "")
        )
        self._progress_banner.setVisible(True)

