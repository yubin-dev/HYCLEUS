"""
HYCLEUS — Toplu dosya işlemleri (çoklu seçim)

UI/main_window.py'den 2.7 refactor'ünde ayrıldı. Metot gövdeleri
kelimesi kelimesine taşındı; davranış değişmedi.

`HycleusWindow` bu mixin'i miras alıyor, dolayısıyla `self` hâlâ
pencerenin kendisi ve çağrı yerleri değişmedi.
"""
import logging
# timedelta modül seviyesinde artık kullanılmıyor: "şimdi + TTL" hesabı
# CORE/expiry.py'ye taşındı. _FileRunnable.run() kendi yerel import'unu
# yapıyor (worker thread'inde çalışıyor, bkz. satır ~218).
from pathlib import Path

_log = logging.getLogger("hycleus.ui")

from PySide6.QtCore import (
    QEvent,
    QPoint,
    Qt,
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
    QApplication,
    QFileDialog,
    QInputDialog,
    QMenu,
    QMessageBox,
    QProgressDialog,
)

import pyotp

from CORE.export import export_to_directory, format_errors
from CORE.expiry import expiry_from_now
from DB.db_manager import DBManager

from CORE.secret_store import load_totp_secret
from CORE.usb_manager import DEV_MODE as _DEV_MODE


class BulkActionsMixin:
    """Toplu dosya işlemleri (çoklu seçim)."""

    def _on_bulk_context_menu(self, pos: QPoint, rows: list[int]) -> None:
        file_ids:  list[int] = []
        labels:    list[str] = []
        filepaths: list[str] = []
        for r in rows:
            item = self._table.item(r, 0)
            if item is not None:
                fid      = item.data(Qt.UserRole)
                label    = item.data(Qt.UserRole + 2) or ""
                filepath = item.data(Qt.UserRole + 3) or ""
                if fid is not None:
                    file_ids.append(fid)
                    labels.append(label)
                    filepaths.append(filepath)
        if not file_ids:
            return

        n              = len(file_ids)
        all_karantina  = all(lbl == "Karantina" for lbl in labels)
        any_not_kritik = any(lbl != "Kritik"    for lbl in labels)
        any_not_imha   = any(lbl != "Imha"      for lbl in labels)

        T = self._T
        mstyle = (
            f"QMenu {{ background:{T['topbar']}; color:{T['text']};"
            f" border:1px solid {T['border']}; border-radius:8px; padding:4px 0; }}"
            f"QMenu::item {{ padding:9px 22px; font-size:13px; }}"
            f"QMenu::item:selected {{ background:{T['accent_tint']}; color:{T['tint_text']}; border-radius:4px; }}"
            f"QMenu::separator {{ height:1px; background:{T['border']}; margin:4px 10px; }}"
        )
        menu = QMenu(self)
        menu.setStyleSheet(mstyle)

        act_tags     = menu.addAction(f"🏷  Toplu Etiket Ata  ({n} dosya)")
        menu.addSeparator()
        act_download = menu.addAction(f"⬇  Seçilenleri İndir  ({n} dosya)")
        menu.addSeparator()
        act_approve  = None
        act_kritik   = None
        act_imha     = None
        if all_karantina:
            act_approve = menu.addAction(f"✅  Karantinadan Çıkar  ({n} dosya)  →  Genel")
        if any_not_kritik:
            act_kritik = menu.addAction(f"🛡  Seçilenleri Kritik'e Taşı  ({n} dosya)")
        if any_not_imha:
            act_imha   = menu.addAction(f"🔥  Seçilenleri İmha Odasına At  ({n} dosya)")

        action = menu.exec(self._table.viewport().mapToGlobal(pos))
        if action == act_tags:
            self._on_ctx_bulk_assign_tags(file_ids)
        elif action == act_download:
            self._on_ctx_bulk_download(file_ids, filepaths)
        elif action == act_approve:
            self._on_ctx_bulk_approve(rows, file_ids)
        elif action == act_kritik:
            self._on_ctx_bulk_move_to_kritik(rows, file_ids, labels)
        elif action == act_imha:
            self._on_ctx_bulk_move_to_imha(rows, file_ids)

    def _on_ctx_bulk_assign_tags(self, file_ids: list[int]) -> None:
        from UI.TagDialog import TagDialog
        dlg = TagDialog(file_id=file_ids[0], role=self._role, parent=self, file_ids=file_ids)
        if dlg.exec() == TagDialog.Accepted:
            self._refresh_tag_sidebar()
            if self._current_tag_id is not None:
                self._load_tag_files(self._current_tag_id)

    def _on_ctx_bulk_approve(self, rows: list[int], file_ids: list[int]) -> None:
        confirm = QMessageBox.question(
            self, "Karantinadan Çıkar",
            f"{len(file_ids)} dosya Karantina → Genel olarak taşınacak.\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            db = DBManager()
            for fid in file_ids:
                db.execute("UPDATE files SET label = 'Genel' WHERE id = ?", (fid,))
                db.log("file_label_changed", target_type="file", target_id=fid,
                       detail=f"hwid={self._hwid} from=Karantina to=Genel auto=False bulk=True")
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        for row in sorted(rows, reverse=True):
            self._table.removeRow(row)
        QMessageBox.information(self, "Taşındı",
                                f"{len(file_ids)} dosya Genel etiketine taşındı.")

    def _on_ctx_bulk_move_to_kritik(
        self, rows: list[int], file_ids: list[int], labels: list[str],
    ) -> None:
        to_move = [(r, fid) for r, fid, lbl in zip(rows, file_ids, labels)
                   if lbl != "Kritik"]
        if not to_move:
            QMessageBox.information(self, "Kritik'e Taşı",
                                    "Seçili dosyaların tümü zaten Kritik etiketinde.")
            return
        confirm = QMessageBox.question(
            self, "Kritik'e Taşı",
            f"{len(to_move)} dosya Kritik etiketine taşınacak.\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        moved = 0
        try:
            db = DBManager()
            for _, fid in to_move:
                db.execute("UPDATE files SET label = 'Kritik' WHERE id = ?", (fid,))
                db.log("file_label_changed", target_type="file", target_id=fid,
                       detail=f"hwid={self._hwid} to=Kritik bulk=True")
                moved += 1
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        for row in sorted((r for r, _ in to_move), reverse=True):
            self._table.removeRow(row)
        QMessageBox.information(self, "Taşındı", f"{moved} dosya Kritik etiketine taşındı.")

    def _on_ctx_bulk_move_to_imha(self, rows: list[int], file_ids: list[int]) -> None:
        confirm = QMessageBox.question(
            self, "İmha Odasına At",
            f"{len(file_ids)} dosya İmha Odası'na taşınacak ve süre sonunda silinecek.\n"
            "Devam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        expires_at = expiry_from_now(DBManager())
        moved = 0
        try:
            db = DBManager()
            for fid in file_ids:
                db.execute(
                    "UPDATE files SET label = 'Imha', expires_at = ? WHERE id = ?",
                    (expires_at, fid),
                )
                db.log("file_moved_to_imha", target_type="file", target_id=fid,
                       detail=f"hwid={self._hwid} expires_at={expires_at} bulk=True")
                moved += 1
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        for row in sorted(rows, reverse=True):
            self._table.removeRow(row)
        QMessageBox.information(self, "İmha Odasına Taşındı",
                                f"{moved} dosya İmha Odası'na taşındı.")

    def _on_ctx_bulk_download(
        self, file_ids: list[int], filepaths: list[str],
    ) -> None:
        try:
            secret = load_totp_secret()
        except Exception as exc:
            QMessageBox.critical(self, "İndir", f"TOTP anahtarı okunamadı.\n\n{exc}")
            return
        if not secret:
            QMessageBox.critical(self, "İndir", "TOTP anahtarı kurulmamış.")
            return

        code, ok = QInputDialog.getText(
            self, "Kimlik Doğrulama", "Authenticator kodunu girin (6 hane):"
        )
        if not ok:
            return
        code = code.strip()
        if not (code.isdigit() and len(code) == 6
                and pyotp.TOTP(secret).verify(code, valid_window=1)):
            DBManager().log("bulk_download_totp_failed",
                            detail=f"hwid={self._hwid} count={len(file_ids)}")
            QMessageBox.warning(self, "Erişim Reddedildi", "Authenticator kodu geçersiz.")
            return

        save_dir = QFileDialog.getExistingDirectory(self, "Dosyaların Kaydedileceği Klasörü Seç")
        if not save_dir:
            return
        dest_dir = Path(save_dir)

        prog = QProgressDialog("Dosyalar indiriliyor…", "İptal", 0, len(file_ids), self)
        prog.setWindowTitle("Toplu İndirme")
        prog.setMinimumDuration(0)
        prog.setValue(0)

        def _ilerleme(index: int, kisa_ad: str) -> None:
            prog.setLabelText(f"İndiriliyor ({index + 1}/{len(file_ids)}): {kisa_ad}")
            prog.setValue(index)
            QApplication.processEvents()

        sonuc = export_to_directory(
            DBManager(),
            list(zip(file_ids, filepaths)),
            self._key,
            dest_dir,
            session_hwid=self._hwid,
            # B-010: klasör→ZIP akışıyla aynı değer. Eskiden buraya hiçbir
            # şey geçilmiyordu, yani AAD sütunu eksik dosyalarda hwid
            # doğrulaması sessizce devre dışı kalıyordu.
            hwid_fallback="DEV-HWID-1234" if _DEV_MODE else self._hwid,
            on_progress=_ilerleme,
            should_continue=lambda: not prog.wasCanceled(),
        )
        saved, errors = sonuc.saved, sonuc.errors

        prog.setValue(len(file_ids))
        prog.close()

        msg = f"{saved} dosya kaydedildi:\n{save_dir}"
        if errors:
            msg += f"\n\nAtlanan ({len(errors)}):\n{format_errors(errors)}"
        QMessageBox.information(self, "İndirme Tamamlandı", msg)

