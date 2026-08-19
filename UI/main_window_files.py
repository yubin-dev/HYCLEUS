"""
HYCLEUS — Tekil dosya işlemleri (sağ tık menüsü)

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
from pathlib import Path

_log = logging.getLogger("hycleus.ui")

from PySide6.QtCore import (
    QEvent,
    QPoint,
    QThread,
    Qt,
    QTimer,
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
from PySide6.QtWidgets import (
    QFileDialog,
    QInputDialog,
    QMenu,
    QMessageBox,
)

import pyotp

from CORE.crypto import AuthenticationError, decrypt_file
from CORE.folders import (
    assign_file_to_folder,
)
from CORE.expiry import expiry_from_now
from CORE.scanner import ScanResult
from DB.db_manager import DBManager

from CORE.secret_store import load_totp_secret
from CORE.roles import is_readonly_role
from UI.main_window_table import _ScanWorker
from UI.main_window_palette import (
    _VERDICT_BADGE,
)


class FileActionsMixin:
    """Tekil dosya işlemleri (sağ tık menüsü)."""

    # ── Context menu ──────────────────────────────────────────────────────────

    def _on_context_menu(self, pos: QPoint) -> None:
        if is_readonly_role(self._role):
            _log.debug("context_menu_blocked  fn=_on_context_menu  role=%r", self._role)
            return

        selected_rows = sorted({idx.row() for idx in self._table.selectedIndexes()})
        clicked_row   = self._table.rowAt(pos.y())
        if len(selected_rows) > 1 and clicked_row in selected_rows:
            self._on_bulk_context_menu(pos, selected_rows)
            return

        row = self._table.rowAt(pos.y())
        if row < 0:
            return
        name_item = self._table.item(row, 0)
        if name_item is None:
            return
        label:    str       = name_item.data(Qt.UserRole + 2) or ""
        file_id:  int | None = name_item.data(Qt.UserRole)
        filepath: str | None = name_item.data(Qt.UserRole + 3)

        T = self._T
        menu_style = (
            f"QMenu {{ background:{T['topbar']}; color:{T['text']};"
            f" border:1px solid {T['border']}; border-radius:8px; padding:4px 0; }}"
            f"QMenu::item {{ padding:9px 22px; font-size:13px; }}"
            f"QMenu::item:selected {{ background:#EFF6FF; color:{T['text']};"
            f" border-radius:4px; }}"
            f"QMenu::separator {{ height:1px; background:{T['border']}; margin:4px 10px; }}"
        )

        menu     = QMenu(self)
        menu.setStyleSheet(menu_style)

        # Şeffaf erişim: açıksa "Bitir", değilse "Aç". İkisi aynı anda
        # anlamsız olurdu — belge ya çıkışta ya değil.
        act_open = act_close = None
        if label != "Imha":
            acik = file_id is not None and file_id in getattr(
                self, "_checkouts", ())
            if acik:
                act_close = menu.addAction("✔  Bitir  (geri şifrele)")
            else:
                act_open = menu.addAction("📄  Aç")
            menu.addSeparator()

        act_tags = menu.addAction("🏷  Etiket Ata")

        act_scan = act_download = act_approve = act_reject = act_move_folder = act_kritik = act_imha = None
        if label == "Genel":
            menu.addSeparator()
            act_download    = menu.addAction("⬇  İndir")
            act_kritik      = menu.addAction("🛡  Kritik'e Taşı")
            act_move_folder = menu.addAction("📂  Klasöre Taşı")
            act_imha        = menu.addAction("🔥  İmha Odasına At")
        elif label == "Kritik":
            menu.addSeparator()
            act_download    = menu.addAction("⬇  İndir")
            act_move_folder = menu.addAction("📂  Klasöre Taşı")
            act_imha        = menu.addAction("🔥  İmha Odasına At")
        elif label == "Karantina":
            menu.addSeparator()
            act_scan        = menu.addAction("🔍  Tara")
            act_download    = menu.addAction("⬇  İndir")
            act_move_folder = menu.addAction("📂  Klasöre Taşı")
            menu.addSeparator()
            act_kritik  = menu.addAction("🛡  Kritik'e Taşı")
            act_approve = menu.addAction("Onayla  →  Genel'e taşı")
            act_reject  = menu.addAction("Reddet  →  İmha Odası'na taşı")
            act_imha    = menu.addAction("🔥  İmha Odasına At")

        action = menu.exec(self._table.viewport().mapToGlobal(pos))

        if action is None:
            return
        if action == act_open:
            self._on_ctx_open(file_id, filepath)
        elif action == act_close:
            self._on_ctx_close_file(file_id)
        elif action == act_tags:
            self._on_ctx_assign_tags(file_id)
        elif action == act_scan:
            self._on_ctx_scan(row, file_id, filepath)
        elif action == act_download:
            self._on_ctx_download(file_id, filepath)
        elif action == act_kritik:
            self._on_ctx_move_to_kritik(row, file_id)
        elif action == act_move_folder:
            self._on_ctx_move_to_folder(file_id)
        elif action == act_approve:
            self._on_ctx_move_label(row, file_id, "Genel")
        elif action == act_reject:
            self._on_ctx_move_label(row, file_id, "Imha")
        elif action == act_imha:
            self._on_ctx_move_to_imha(row, file_id)

    def _on_ctx_download(self, file_id: int | None, filepath: str | None) -> None:
        if not filepath:
            QMessageBox.warning(self, "İndir", "Dosya yolu bulunamadı.")
            return
        try:
            secret = load_totp_secret()
        except Exception as exc:
            QMessageBox.critical(self, "İndir", f"TOTP anahtarı okunamadı.\n\n{exc}")
            return
        if not secret:
            QMessageBox.critical(self, "İndir", "TOTP anahtarı kurulmamış.")
            return

        code, ok = QInputDialog.getText(self, "Kimlik Doğrulama",
                                        "Authenticator kodunu girin (6 hane):")
        if not ok:
            return
        code = code.strip()
        totp_ok = (
            code.isdigit()
            and len(code) == 6
            and pyotp.TOTP(secret).verify(code, valid_window=1)
        )

        db = DBManager()
        if not totp_ok:
            db.log("download_totp_failed", target_type="file", target_id=file_id,
                   detail=f"hwid={self._hwid}")
            QMessageBox.warning(self, "Erişim Reddedildi",
                                "Authenticator kodu geçersiz.\nDosya indirilmedi.")
            return

        aad_hwid: str | None = None
        raw_aad: str | None = None
        if file_id is not None:
            try:
                aad_row = db.fetchone(
                    "SELECT aad_metadata FROM files WHERE id = ?", (file_id,)
                )
                raw_aad = aad_row["aad_metadata"] if aad_row else None
                if raw_aad:
                    aad_hwid = json.loads(raw_aad).get("hwid")
            except Exception:
                pass
        # aad_hwid biliniyorsa GCM + Python HWID kontrolü yap.
        # bilinmiyorsa (eski kayıt veya NULL), hwid=None geç — GCM AAD kimlik
        # doğrulaması zaten hwid'i koruma altına alır.
        _log.debug(
            "download  file_id=%s  self_hwid=%s  aad_hwid=%s  key_len=%s  aad_metadata=%s",
            file_id, self._hwid, aad_hwid,
            len(self._key) if self._key else 0,
            raw_aad[:80] + "..." if raw_aad and len(raw_aad) > 80 else raw_aad,
        )
        try:
            content, meta = decrypt_file(filepath, self._key, hwid=aad_hwid)
        except AuthenticationError as exc:
            _log.error("download_auth_error  file_id=%s  exc=%s", file_id, exc)
            QMessageBox.critical(self, "Bütünlük Hatası",
                                 f"Dosya bütünlüğü doğrulanamadı:\n{exc}")
            return
        except Exception as exc:
            _log.error("download_decrypt_error  file_id=%s  exc=%s", file_id, exc)
            QMessageBox.critical(self, "Şifre Çözme Hatası", str(exc))
            return

        original_name = meta.get("filename", Path(filepath).stem)
        save_path, _  = QFileDialog.getSaveFileName(self, "Dosyayı Kaydet", original_name)
        if not save_path:
            del content
            return
        try:
            Path(save_path).write_bytes(content)
        except Exception as exc:
            QMessageBox.critical(self, "Kaydetme Hatası", str(exc))
            return
        finally:
            del content

        db.log("file_downloaded", target_type="file", target_id=file_id,
               detail=f"hwid={self._hwid} dest={save_path}")
        QMessageBox.information(self, "İndir", f"Dosya başarıyla kaydedildi:\n{save_path}")

    def _on_ctx_assign_tags(self, file_id: int | None) -> None:
        if file_id is None:
            QMessageBox.warning(self, "Etiket", "Dosya kimliği bulunamadı.")
            return
        from UI.TagDialog import TagDialog
        dlg = TagDialog(file_id=file_id, role=self._role, parent=self)
        if dlg.exec() == TagDialog.Accepted:
            self._refresh_tag_sidebar()
            if self._current_tag_id is not None:
                self._load_tag_files(self._current_tag_id)

    def _on_ctx_scan(self, row: int, file_id: int | None, filepath: str | None) -> None:
        if not filepath:
            QMessageBox.warning(self, "Tarama", "Dosya yolu bulunamadı.")
            return
        path = Path(filepath)
        if not path.exists():
            QMessageBox.warning(self, "Tarama", f"Dosya bulunamadı:\n{filepath}")
            return

        self._set_scan_badge(row, "⟳ Taranıyor...", "#D97706")
        worker = _ScanWorker(path, file_id or 0, row)
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(
            lambda r, res, fid=file_id: self._on_ctx_scan_done(r, res, fid)
        )
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

    def _on_ctx_scan_done(self, row: int, result: ScanResult, file_id: int | None) -> None:
        text, color = _VERDICT_BADGE.get(result.verdict, ("—", "#9CA3AF"))
        if result.mock:
            text, color = text + " (m)", "#9CA3AF"
        self._set_scan_badge(row, text, color)
        if result.verdict == "malicious":
            QMessageBox.warning(self, "Zararlı Dosya",
                                "Tarama zararlı içerik tespit etti.\n"
                                "Dosya otomatik olarak İmha Odası'na taşınıyor.")
            self._on_ctx_move_label(row, file_id, "Imha", auto=True)

    def _on_ctx_move_label(
        self, row: int, file_id: int | None, new_label: str, *, auto: bool = False,
    ) -> None:
        if file_id is None:
            QMessageBox.warning(self, "Taşıma Hatası", "Dosya kimliği bulunamadı.")
            return
        label_display = "Genel" if new_label == "Genel" else "İmha Odası"
        if not auto:
            fname_item = self._table.item(row, 0)
            fname      = fname_item.text() if fname_item else "?"
            confirm    = QMessageBox.question(
                self, "Dosyayı Taşı",
                f"'{fname}'\n\nKarantina → {label_display}\n\nDevam edilsin mi?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if confirm != QMessageBox.Yes:
                return
        try:
            db = DBManager()
            db.execute("UPDATE files SET label = ? WHERE id = ?", (new_label, file_id))
            db.log("file_label_changed", target_type="file", target_id=file_id,
                   detail=f"hwid={self._hwid} from=Karantina to={new_label} auto={auto}")
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        self._table.removeRow(row)
        if not auto:
            QMessageBox.information(self, "Taşındı", f"Dosya '{label_display}' etiketine taşındı.")

    def _on_ctx_move_to_kritik(self, row: int, file_id: int | None) -> None:
        if file_id is None:
            return
        fname_item = self._table.item(row, 0)
        fname = fname_item.text() if fname_item else "?"
        confirm = QMessageBox.question(
            self, "Kritik'e Taşı",
            f"'{fname}'\n\nDosya Kritik etiketine taşınacak.\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            db = DBManager()
            db.execute("UPDATE files SET label = 'Kritik' WHERE id = ?", (file_id,))
            db.log("file_label_changed", target_type="file", target_id=file_id,
                   detail=f"hwid={self._hwid} to=Kritik")
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))
            return
        self._table.removeRow(row)
        QMessageBox.information(self, "Taşındı", "Dosya Kritik etiketine taşındı.")

    def _on_ctx_move_to_imha(self, row: int, file_id: int | None) -> None:
        if file_id is None:
            return
        fname_item = self._table.item(row, 0)
        fname = fname_item.text() if fname_item else "?"
        confirm = QMessageBox.question(
            self, "İmha Odasına At",
            f"'{fname}'\n\nDosya İmha Odası'na taşınacak ve 24 saat içinde silinecek.\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        expires_at = expiry_from_now(DBManager())
        try:
            db = DBManager()
            db.execute(
                "UPDATE files SET label = 'Imha', expires_at = ? WHERE id = ?",
                (expires_at, file_id),
            )
            db.log("file_moved_to_imha", target_type="file", target_id=file_id,
                   detail=f"hwid={self._hwid} expires_at={expires_at}")
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        self._table.removeRow(row)
        QMessageBox.information(self, "İmha Odasına Taşındı",
                                "Dosya İmha Odası'na taşındı. 24 saat içinde silinecek.")

    def _on_ctx_move_to_folder(self, file_id: int | None) -> None:
        if file_id is None:
            return
        try:
            folders = DBManager().fetchall("SELECT id, name FROM folders ORDER BY name")
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))
            return
        if not folders:
            QMessageBox.information(self, "Klasöre Taşı",
                                    "Henüz klasör yok. Önce bir klasör oluşturun.")
            return

        T = self._T
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu {{ background:{T['topbar']}; color:{T['text']};"
            f" border:1px solid {T['border']}; border-radius:8px; padding:4px 0; }}"
            f"QMenu::item {{ padding:9px 22px; font-size:13px; }}"
            f"QMenu::item:selected {{ background:#EFF6FF; color:{T['text']}; border-radius:4px; }}"
        )
        acts = {}
        for folder in folders:
            acts[menu.addAction(f"📂  {folder['name']}")] = folder["id"]

        action = menu.exec(self._table.viewport().mapToGlobal(
            self._table.visualItemRect(self._table.currentItem()).center()
        ))
        if action not in acts:
            return
        target_folder_id = acts[action]
        try:
            assign_file_to_folder(
                DBManager(), file_id, target_folder_id, hwid=self._hwid
            )
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))

