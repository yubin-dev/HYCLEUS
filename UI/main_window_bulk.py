"""
HYCLEUS — Toplu dosya işlemleri (çoklu seçim)

UI/main_window.py'den 2.7 refactor'ünde ayrıldı. Metot gövdeleri
kelimesi kelimesine taşındı; davranış değişmedi.

`HycleusWindow` bu mixin'i miras alıyor, dolayısıyla `self` hâlâ
pencerenin kendisi ve çağrı yerleri değişmedi.


İkinci giriş noktası: kutucuklar + toplu işlem çubuğu (B-094)
----------------------------------------------------------------
Çoklu seçimin TEK giriş noktası sağ tık menüsüydü (`_on_bulk_context_menu`,
seçili SATIRLAR üzerinden). Artık ikinci bir yol var: `UI/
main_window_table.py::_insert_row()`'un sütun 0'a eklediği kutucuklar +
`UI/main_window_layout.py::_make_bulk_toolbar()`'ın kurduğu, 1+ kutucuk
işaretliyken görünen araç çubuğu.

Kural burada da AYNI — **iki giriş noktası, tek gövde**: `_on_bulk_toolbar_*`
metotları YENİ bir toplu işlem UYGULAMIYOR, `_checked_selection()` ile
işaretli satırlardan aynı `(rows, file_ids, labels, filepaths)` şeklini
üretip mevcut `_on_ctx_bulk_*` gövdelerini ÇAĞIRIYOR. "Karantinadan Çıkar"
araç çubuğunda BİLİNÇLİ olarak YOK (yalnızca Karantina etiketinde anlamlı,
görev onu istemedi) — sağ tık menüsü hâlâ sunuyor.

Tekli mi toplu mu — karar
--------------------------
Görev her toplu işlemin "mevcut tekli `db_manager.py` fonksiyonlarını
sırayla mı çağıracağı yoksa toplu bir fonksiyon mu gerekeceği" kararını
istedi. Karar: SIRAYLA — çünkü `_on_ctx_bulk_*` gövdeleri zaten (bu turdan
ÖNCE de) `db.execute()`'u dosya başına bir DÖNGÜDE çağırıyordu, TEK bir
toplu SQL (`UPDATE ... WHERE id IN (...)`) DEĞİL. Bu turda DEĞİŞTİRİLMEDİ:

  1. Dosya başına AYRI bir denetim kaydı (`db.log(...)`, `target_id=fid`)
     düşüyor — TEK bir toplu UPDATE bunu ya kaybederdi ya da KENDİ döngüsünü
     GEREKTİRİRDİ (verimlilik kazancı YOK, yalnızca karmaşıklık).
  2. K1-14'ün DB seviyesi rol denetimi (`DBManager.execute()` →
     `_yazma_yetkisini_dogrula()`, `DB/db_manager.py`) HER `execute()`
     çağrısında ÇALIŞIYOR — döngü BU YÜZDEN salt okunur bir rolü İLK
     yinelemede durduruyor (`YazmaYetkisiYokError`, bir `PermissionError`
     alt sınıfı), `try/except` sarıcısı `QMessageBox.critical` ile
     gösterip döngüyü orada BIRAKIYOR. Tek bir toplu SQL de rolü
     REDDEDERDİ ama farkı GÖRÜNMEZ kılardı: KISMİ bir başarı yerine
     hepsi-ya-da-hiçbiri — burada zaten rol OTURUM boyunca sabit olduğu
     için (yinelemeler arasında DEĞİŞMİYOR) bu ayrım pratikte SONUÇSUZ,
     ama davranışı DEĞİŞTİRMEK bu turun kapsamı DIŞINDAydı.

Bu kararın kanıtı `tests/test_bulk_toolbar_rbac.py`'de: salt okunur bir
rolün kutucuklarla bile toplu imha/taşıma YAPAMADIĞINI, yetkili bir
rolün toplu işlemi TÜM seçili dosyalara doğru uyguladığını doğruluyor.
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

from CORE.secret_store import load_totp_secret_for_hwid
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
        dlg = TagDialog(file_id=file_ids[0], role=self._role, parent=self, file_ids=file_ids, T=self._T)
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
            secret = load_totp_secret_for_hwid(self._hwid)
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
            # K1-15: yalnızca "İptal" düğmesi DEĞİL — `self._locked` de.
            # `_ilerleme()` her turda `QApplication.processEvents()`
            # çağırıyor, yani bu döngü Qt olay döngüsüne yeniden giriş
            # yapabiliyor; USB tam bu sırada çekilirse `_poll_usb()` →
            # `_lock()` çalışır ve `self._locked` True olur. Eskiden bu
            # döngü bunu HİÇ görmüyordu — kilit ekranı görünse bile
            # kalan dosyalar çözülüp yazılmaya devam ederdi (ölçüldü,
            # bkz. tests/test_export.py::
            # test_lock_ortasinda_daha_fazla_dosya_yazilmiyor).
            should_continue=lambda: not prog.wasCanceled() and not self._locked,
        )
        saved, errors = sonuc.saved, sonuc.errors

        prog.setValue(len(file_ids))
        prog.close()

        if sonuc.cancelled and self._locked and not prog.wasCanceled():
            QMessageBox.warning(
                self, "İndirme Durduruldu",
                f"Oturum kilitlendiği için indirme yarıda durduruldu.\n"
                f"{saved} dosya kaydedildi, kalanlar işlenmedi.\n\n{save_dir}",
            )
            return

        msg = f"{saved} dosya kaydedildi:\n{save_dir}"
        if errors:
            msg += f"\n\nAtlanan ({len(errors)}):\n{format_errors(errors)}"
        QMessageBox.information(self, "İndirme Tamamlandı", msg)

    # ── Kutucuklar + araç çubuğu — ikinci giriş noktası (B-094) ──────────────

    def _checked_selection(self) -> tuple[list[int], list[int], list[str], list[str]]:
        """
        İşaretli kutucuklara sahip satırlardan `(rows, file_ids, labels,
        filepaths)` üretir — `_on_bulk_context_menu()`'nun seçili
        SATIRLARDAN aynı veriyi ürettiği döngüyle AYNI şekil, kaynak
        farklı: seçili satırlar yerine işaretli kutucuklar.
        """
        rows: list[int] = []
        file_ids: list[int] = []
        labels: list[str] = []
        filepaths: list[str] = []
        for r in range(self._table.rowCount()):
            item = self._table.item(r, 0)
            if item is None or item.checkState() != Qt.Checked:
                continue
            fid = item.data(Qt.UserRole)
            if fid is None:
                continue
            rows.append(r)
            file_ids.append(fid)
            labels.append(item.data(Qt.UserRole + 2) or "")
            filepaths.append(item.data(Qt.UserRole + 3) or "")
        return rows, file_ids, labels, filepaths

    def _on_table_item_changed(self, item) -> None:  # noqa: ARG002 — Qt slot imzası
        """
        Kutucuk durumu DAHİL herhangi bir hücre değişiminde (satır ekleme,
        tarama rozeti) ateşleniyor — yalnızca işaretli sayıyı sayıp araç
        çubuğunu gösterip/gizliyor ve etiketini güncelliyor; ucuz bir
        işlem, fazladan tetiklenmesi zararsız (bkz. `_make_bulk_toolbar()`
        yakınındaki bağlama yorumu).

        Toplu işlem düğmelerinin HER birinden SONRA da elle çağrılıyor:
        Kritik'e Taşı/İmhaya At işaretli satırları `removeRow()` ile
        kaldırıyor ama bu `itemChanged`'i TETİKLEMİYOR (yapısal bir
        değişiklik, veri değişimi değil) — elle çağrı olmasaydı araç
        çubuğu, altındaki dosyalar gittikten SONRA bile görünür kalırdı.
        """
        _, file_ids, _, _ = self._checked_selection()
        n = len(file_ids)
        self._bulk_toolbar.setVisible(n > 0)
        if n:
            # Türkçe sayıdan sonra çoğul eki ALMAZ ("1 dosya"/"5 dosya").
            self._bulk_toolbar_label.setText(f"{n} dosya seçili")

    def _on_bulk_toolbar_tags(self) -> None:
        _, file_ids, _, _ = self._checked_selection()
        if not file_ids:
            return  # Düğme yalnızca 1+ işaretliyken görünür — savunma amaçlı.
        self._on_ctx_bulk_assign_tags(file_ids)
        self._on_table_item_changed(None)

    def _on_bulk_toolbar_kritik(self) -> None:
        rows, file_ids, labels, _ = self._checked_selection()
        if not file_ids:
            return
        self._on_ctx_bulk_move_to_kritik(rows, file_ids, labels)
        self._on_table_item_changed(None)

    def _on_bulk_toolbar_download(self) -> None:
        _, file_ids, _, filepaths = self._checked_selection()
        if not file_ids:
            return
        self._on_ctx_bulk_download(file_ids, filepaths)
        self._on_table_item_changed(None)

    def _on_bulk_toolbar_imha(self) -> None:
        rows, file_ids, _, _ = self._checked_selection()
        if not file_ids:
            return
        self._on_ctx_bulk_move_to_imha(rows, file_ids)
        self._on_table_item_changed(None)

