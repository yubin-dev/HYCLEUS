"""
HYCLEUS — Kenar çubuğu ağaçları — klasörler ve etiketler

UI/main_window.py'den 2.7 refactor'ünde ayrıldı. Metot gövdeleri
kelimesi kelimesine taşındı; davranış değişmedi.

`HycleusWindow` bu mixin'i miras alıyor, dolayısıyla `self` hâlâ
pencerenin kendisi ve çağrı yerleri değişmedi.
"""
import logging
import random
# timedelta modül seviyesinde artık kullanılmıyor: "şimdi + TTL" hesabı
# CORE/expiry.py'ye taşındı. _FileRunnable.run() kendi yerel import'unu
# yapıyor (worker thread'inde çalışıyor, bkz. satır ~218).

_log = logging.getLogger("hycleus.ui")

from PySide6.QtCore import (
    QEvent,
    QPoint,
    QSize,
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
from PySide6.QtGui import (
    QIcon,
)
from PySide6.QtWidgets import (
    QFileDialog,
    QInputDialog,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
)

import pyotp

from CORE.folders import (
    create_folder,
    delete_folder,
    folder_subtree_summary,
    is_descendant,
    list_folders,
    move_folder,
    move_folder_to_imha,
)
from CORE.export import export_to_zip
from CORE.file_queries import (
    files_by_folder,
    files_by_tag,
)
from CORE.usb_manager import DEV_MODE as _DEV_MODE
from DB.db_manager import DBManager

from CORE.secret_store import load_totp_secret_for_hwid
from CORE.roles import is_admin_role, is_readonly_role
from UI.main_window_palette import (
    _TAG_COLORS,
    _make_dot_pixmap,
)


class TreeMixin:
    """Kenar çubuğu ağaçları — klasörler ve etiketler."""

    def _refresh_tag_sidebar(self) -> None:
        while self._tag_container_layout.count():
            item = self._tag_container_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self._tag_btns.clear()
        if self._active_tag_btn is not None:
            self._active_tag_btn = None

        try:
            tags = DBManager().fetchall("SELECT id, name, color, is_private FROM tags ORDER BY name")
        except Exception:
            return

        if not tags:
            empty = QLabel("  Henüz etiket yok")
            empty.setStyleSheet(
                f"color:{self._T['subtext']}; font-size:11px; padding:4px 8px;"
                "background:transparent;"
            )
            self._tag_container_layout.addWidget(empty)
            return

        for tag in tags:
            tag_id     = tag["id"]
            name       = tag["name"]
            color      = tag["color"]
            is_private = bool(tag["is_private"])

            if is_private and not is_admin_role(self._role):
                continue

            is_active = (tag_id == self._current_tag_id)
            display   = f"  {'🔒 ' if is_private else ''}{name}"
            btn = QPushButton(display)
            btn.setFixedHeight(36)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setProperty("tag_color", color)
            btn.setIcon(QIcon(_make_dot_pixmap(color)))
            btn.setIconSize(QSize(8, 8))
            btn.setProperty("is_private", is_private)
            btn.setStyleSheet(self._tag_btn_style(color=color, active=is_active))
            btn.clicked.connect(
                lambda checked=False, tid=tag_id, tname=name, tc=color, b=btn:
                self._on_tag_click(tid, tname, tc, b)
            )
            btn.setContextMenuPolicy(Qt.CustomContextMenu)
            btn.customContextMenuRequested.connect(
                lambda pos, tid=tag_id, tname=name, b=btn:
                self._on_tag_context_menu(pos, tid, tname, b)
            )
            self._tag_btns[tag_id] = btn
            if is_active:
                self._active_tag_btn = btn
            self._tag_container_layout.addWidget(btn)

    # ── Klasör sistemi ────────────────────────────────────────────────────────

    def _refresh_folder_sidebar(self) -> None:
        """
        Kenar çubuğu klasör ağacını yeniden çizer — TÜM hiyerarşi, tek
        seviye değil (B-123). Eskiden ham bir `WHERE parent_id IS NULL`
        sorgusu yalnızca KÖK klasörleri listeliyordu; `folders.parent_id`
        DB'de zaten hiyerarşiyi destekliyordu ama UI'dan hiç erişilemezdi.

        `list_folders()` (CORE/folders.py) düz, ada göre sıralı bir liste
        döndürüyor; ebeveyn→çocuk eşlemesi VE girinti burada kuruluyor
        (`_ekle()`, derinlik-öncelikli özyineleme). Her düğme artık dosya
        sayısını da gösteriyor (`f.file_count`, `list_folders()` zaten
        hesaplıyordu — `tests/test_folders.py`'de test ediliyordu ama
        sidebar'a hiç bağlanmamıştı).
        """
        while self._folder_container_layout.count():
            item = self._folder_container_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self._folder_btns.clear()

        try:
            klasorler = list_folders(DBManager())
        except Exception:
            return

        cocuklar: dict[int | None, list] = {}
        for f in klasorler:
            cocuklar.setdefault(f.parent_id, []).append(f)

        def _ekle(parent_id: int | None, derinlik: int) -> None:
            for f in cocuklar.get(parent_id, []):
                is_active = (f.id == self._current_folder_id)
                girinti = "      " + "    " * derinlik

                btn = QPushButton(f"{girinti}📂  {f.name}   ·   {f.file_count}")
                btn.setFixedHeight(34)
                btn.setCursor(Qt.PointingHandCursor)
                btn.setStyleSheet(self._folder_btn_style(active=is_active))
                btn.clicked.connect(
                    lambda checked=False, fid_=f.id, fn=f.name, b=btn:
                    self._on_folder_click(fid_, fn, b)
                )
                btn.setContextMenuPolicy(Qt.CustomContextMenu)
                btn.customContextMenuRequested.connect(
                    lambda pos, fid_=f.id, fn=f.name, b=btn:
                    self._on_folder_context_menu(pos, fid_, fn, b)
                )
                self._folder_btns[f.id] = btn
                self._folder_container_layout.addWidget(btn)
                _ekle(f.id, derinlik + 1)

        _ekle(None, 0)

    def _on_folder_click(self, folder_id: int, folder_name: str, btn: QPushButton) -> None:
        if self._active_tag_btn is not None:
            prev = self._active_tag_btn.property("tag_color") or self._T["accent"]
            self._active_tag_btn.setStyleSheet(self._tag_btn_style(color=prev, active=False))
            self._active_tag_btn = None
        self._current_tag_id = None

        if self._active_folder_btn is not None and self._active_folder_btn is not btn:
            try:
                self._active_folder_btn.setStyleSheet(self._folder_btn_style(active=False))
            except RuntimeError:
                pass  # Qt nesnesi sidebar yenilemesinde silinmiş olabilir

        self._active_folder_btn = btn
        btn.setStyleSheet(self._folder_btn_style(active=True))

        if self._active_btn is not None:
            self._active_btn.setStyleSheet(self._nav_btn_style(active=False))
        self._active_btn    = self._nav_btns["Genel"]
        self._active_btn.setStyleSheet(self._nav_btn_style(active=True))

        self._current_label     = "Genel"
        self._current_folder_id = folder_id
        self._page_title.setText(f"📂 {folder_name}")

        self._search_bar.blockSignals(True)
        self._search_bar.clear()
        self._search_bar.blockSignals(False)
        self._expiry_banner.setVisible(False)
        self._table.horizontalHeaderItem(3).setText("Tarih")
        self._load_folder_files(folder_id)

    def _load_folder_files(self, folder_id: int) -> None:
        self._table.setRowCount(0)
        try:
            # B-007: diğer üç görünümle aynı biçimde role bağlı
            rows = files_by_folder(
                DBManager(), folder_id,
                include_private=is_admin_role(self._role),
            )
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı", str(exc))
            return
        self._populate_table(rows)

    def _on_folder_context_menu(self, pos: QPoint, folder_id: int, folder_name: str,
                                btn: QPushButton) -> None:
        if is_readonly_role(self._role):
            _log.debug("context_menu_blocked  fn=_on_folder_context_menu  role=%r", self._role)
            return
        T = self._T
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu {{ background:{T['topbar']}; color:{T['text']};"
            f" border:1px solid {T['border']}; border-radius:8px; padding:4px 0; }}"
            f"QMenu::item {{ padding:9px 22px; font-size:13px; }}"
            f"QMenu::item:selected {{ background:{T['accent_tint']}; color:{T['tint_text']}; border-radius:4px; }}"
        )
        act_dl     = menu.addAction("⬇  Klasörü İndir (ZIP)")
        act_alt    = menu.addAction("📁  Buraya Alt Klasör Ekle")
        act_move   = menu.addAction("➡  Taşı…")
        act_imha   = menu.addAction("🔥  İmha Odasına At")
        act_del    = menu.addAction("🗑  Klasörü Sil")

        action = menu.exec(btn.mapToGlobal(pos))
        if action == act_dl:
            self._on_folder_download(folder_id, folder_name)
        elif action == act_alt:
            self._on_create_subfolder(folder_id, folder_name)
        elif action == act_move:
            self._on_move_folder(folder_id, folder_name)
        elif action == act_imha:
            self._on_folder_move_to_imha(folder_id, folder_name)
        elif action == act_del:
            self._on_folder_delete(folder_id, folder_name)

    def _on_create_folder(self) -> None:
        from PySide6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(self, "Klasör Oluştur", "Klasör adı:")
        if not ok or not name.strip():
            return
        try:
            create_folder(
                DBManager(), name, owner_id=self._user_id, hwid=self._hwid
            )
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))
            return
        self._refresh_folder_sidebar()

    def _on_create_subfolder(self, parent_id: int, parent_name: str) -> None:
        """"Buraya Alt Klasör Ekle" (B-123) — sağ tıklanan klasörün ALTINA
        yeni bir klasör oluşturur. `_on_create_folder()`'dan tek farkı
        `parent_id` — DB kaydı, denetim kaydı, yenileme AYNI kod yolu."""
        name, ok = QInputDialog.getText(
            self, "Alt Klasör Oluştur", f"'{parent_name}' altında yeni klasör adı:"
        )
        if not ok or not name.strip():
            return
        try:
            create_folder(
                DBManager(), name, owner_id=self._user_id, hwid=self._hwid,
                parent_id=parent_id,
            )
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))
            return
        self._refresh_folder_sidebar()

    def _on_move_folder(self, folder_id: int, folder_name: str) -> None:
        """"Taşı…" (B-123) — hedef listesi kendisini VE kendi alt ağacını
        BAŞTAN eler (`is_descendant()`, CORE/folders.py): döngü oluşturacak
        bir seçim kullanıcıya hiç GÖSTERİLMİYOR. `move_folder()`'ın kendi
        `ValueError` koruması yine de duruyor — burası ikinci, ön bir kapı."""
        db = DBManager()
        try:
            tum_klasorler = list_folders(db)
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))
            return

        KOK_ETIKETI = "— Kök (üst klasör yok) —"
        secenekler = [KOK_ETIKETI]
        id_by_secenek: dict[str, int] = {}
        for f in tum_klasorler:
            if f.id == folder_id or is_descendant(db, f.id, folder_id):
                continue
            secenekler.append(f.name)
            id_by_secenek[f.name] = f.id

        secim, ok = QInputDialog.getItem(
            self, "Klasörü Taşı", f"'{folder_name}' nereye taşınsın?",
            secenekler, 0, False,
        )
        if not ok:
            return
        hedef_id = id_by_secenek.get(secim)  # KOK_ETIKETI ise None kalır

        try:
            move_folder(db, folder_id, hedef_id, hwid=self._hwid)
        except ValueError as exc:
            QMessageBox.warning(self, "Taşınamadı", str(exc))
            return
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        self._refresh_folder_sidebar()

    def _on_folder_move_to_imha(self, folder_id: int, folder_name: str) -> None:
        confirm = QMessageBox.question(
            self, "Klasörü İmha Et",
            f"'{folder_name}' klasöründeki tüm dosyalar İmha Odası'na taşınacak "
            f"ve 24 saat içinde silinecek.\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            tasinan = move_folder_to_imha(DBManager(), folder_id, hwid=self._hwid)
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı Hatası", str(exc))
            return
        # Aktif görünüm klasör içindeyse Genel'e dön, değilse tabloyu yenile
        if self._current_folder_id == folder_id:
            self._current_folder_id = None
            self._active_folder_btn = None
            self._on_sidebar_click("Genel", self._nav_btns["Genel"])
        else:
            self._refresh_folder_sidebar()
            if self._current_label:
                self._load_label(self._current_label)
        QMessageBox.information(
            self, "İmha Odasına Taşındı",
            f"'{folder_name}' klasöründeki {tasinan} dosya 24 saat içinde imha edilecek.",
        )

    def _on_folder_delete(self, folder_id: int, folder_name: str) -> None:
        """
        Silme onayı artık ALT AĞACI da hesaba katıyor (B-123): `ON DELETE
        CASCADE` çok seviyeli kademelendiği için (canlı doğrulandı, bkz.
        `CORE/folders.py::folder_subtree_summary()` docstring'i) kullanıcı
        büyük bir ağacı tek "Evet" ile, kapsamını GÖRMEDEN silebiliyordu.
        """
        db = DBManager()
        try:
            alt_agac_id, dosya_sayisi = folder_subtree_summary(db, folder_id)
        except Exception:
            alt_agac_id, dosya_sayisi = [folder_id], 0
        alt_klasor_sayisi = len(alt_agac_id) - 1  # kendisi hariç

        if alt_klasor_sayisi > 0:
            mesaj = (
                f"'{folder_name}' klasörü ve {alt_klasor_sayisi} alt klasörü,"
                f" içindeki {dosya_sayisi} dosyayla birlikte silinecek.\n\n"
                "Dosyalar silinmez, klasörden çıkarılır.\nDevam edilsin mi?"
            )
        else:
            mesaj = (
                f"'{folder_name}' klasörü silinecek.\n\n"
                f"İçindeki {dosya_sayisi} dosya klasörden çıkarılır ama silinmez."
                "\nDevam edilsin mi?"
            )
        confirm = QMessageBox.question(
            self, "Klasörü Sil", mesaj,
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            delete_folder(db, folder_id, folder_name)
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))
            return
        if self._current_folder_id == folder_id:
            self._current_folder_id = None
            self._active_folder_btn = None
            self._on_sidebar_click("Genel", self._nav_btns["Genel"])
        else:
            self._refresh_folder_sidebar()

    def _on_folder_download(self, folder_id: int, folder_name: str) -> None:

        try:
            secret = load_totp_secret_for_hwid(self._hwid)
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
        if not totp_ok:
            DBManager().log("folder_download_totp_failed", detail=f"folder={folder_name}")
            QMessageBox.warning(self, "Erişim Reddedildi", "Authenticator kodu geçersiz.")
            return

        try:
            files = DBManager().fetchall(
                "SELECT id, filename, filepath, aad_metadata FROM files WHERE folder_id = ?",
                (folder_id,),
            )
        except Exception as exc:
            QMessageBox.critical(self, "Veritabanı", str(exc))
            return

        if not files:
            QMessageBox.information(self, "Klasör İndir", "Klasörde dosya bulunamadı.")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self, "ZIP Olarak Kaydet", f"{folder_name}.zip", "ZIP Arşivi (*.zip)"
        )
        if not save_path:
            return

        try:
            sonuc = export_to_zip(
                DBManager(), files, self._key, save_path,
                hwid_fallback="DEV-HWID-1234" if _DEV_MODE else self._hwid,
            )
        except Exception as exc:
            QMessageBox.critical(self, "ZIP Hatası", str(exc))
            return
        errors = sonuc.errors

        DBManager().log("folder_downloaded", target_type="folder", target_id=folder_id,
                        detail=f"zip={save_path} hwid={self._hwid}")

        msg = f"ZIP kaydedildi:\n{save_path}"
        if errors:
            msg += f"\n\nAtlanan dosyalar ({len(errors)}):\n" + "\n".join(errors)
        QMessageBox.information(self, "Klasör İndir", msg)

    def _on_tag_click(self, tag_id: int, tag_name: str, tag_color: str, btn: QPushButton) -> None:
        if btn.property("is_private") and not is_admin_role(self._role):
            QMessageBox.warning(
                self, "Erişim Reddedildi",
                "Bu klasör gizlidir, erişim yetkiniz yok."
            )
            return
        if self._active_btn is not None:
            self._active_btn.setStyleSheet(self._nav_btn_style(active=False))
            self._active_btn = None

        if self._active_tag_btn is not None and self._active_tag_btn is not btn:
            prev = self._active_tag_btn.property("tag_color") or self._T["accent"]
            self._active_tag_btn.setStyleSheet(self._tag_btn_style(color=prev, active=False))

        self._active_tag_btn = btn
        btn.setStyleSheet(self._tag_btn_style(color=tag_color, active=True))

        self._current_label  = ""
        self._current_tag_id = tag_id
        self._page_title.setText(f"# {tag_name}")

        self._search_bar.blockSignals(True)
        self._search_bar.clear()
        self._search_bar.blockSignals(False)

        self._expiry_banner.setVisible(False)
        self._table.horizontalHeaderItem(3).setText("Tarih")
        self._load_tag_files(tag_id)

    def _on_tag_context_menu(self, pos: QPoint, tag_id: int, tag_name: str, btn: QPushButton) -> None:
        if is_readonly_role(self._role):
            _log.debug("context_menu_blocked  fn=_on_tag_context_menu  role=%r", self._role)
            return
        T = self._T
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu {{ background:{T['topbar']}; color:{T['text']};"
            f" border:1px solid {T['border']}; border-radius:8px; padding:4px 0; }}"
            f"QMenu::item {{ padding:9px 22px; font-size:13px; }}"
            f"QMenu::item:selected {{ background:#FEE2E2; color:#DC2626; border-radius:4px; }}"
        )
        act_delete = menu.addAction("🗑  Etiketi Sil")
        if menu.exec(btn.mapToGlobal(pos)) == act_delete:
            self._on_tag_delete(tag_id, tag_name)

    def _on_tag_delete(self, tag_id: int, tag_name: str) -> None:
        confirm = QMessageBox.question(
            self, "Etiketi Sil",
            f"'{tag_name}' etiketi silinecek.\n\nDosyalar etkilenmez, sadece etiket kaldırılır.\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            db = DBManager()
            db.execute("DELETE FROM file_tags WHERE tag_id = ?", (tag_id,))
            db.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
            db.log("tag_deleted", target_type="tag", target_id=tag_id,
                   detail=f"name={tag_name} hwid={self._hwid}")
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))
            return
        if self._current_tag_id == tag_id:
            self._current_tag_id = None
            self._active_tag_btn = None
            self._on_sidebar_click("Genel", self._nav_btns["Genel"])
        else:
            self._refresh_tag_sidebar()

    def _load_tag_files(self, tag_id: int) -> None:
        self._table.setRowCount(0)
        try:
            # B-007: kenar çubuğu engeli KALDIRILMADI — iki katman birlikte
            rows = files_by_tag(
                DBManager(), tag_id,
                include_private=is_admin_role(self._role),
            )
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı", str(exc))
            return
        self._populate_table(rows)

    def _on_new_tag(self) -> None:
        name, ok = QInputDialog.getText(self, "Yeni Etiket", "Etiket adı:")
        if not ok or not name.strip():
            return
        # Etiket rengi görsel bir tercih; hiçbir güvenlik kararına girmiyor.
        # SECURITY.md §5'in "tüm rastgelelik os.urandom/secrets" iddiası
        # anahtar, nonce, tuz ve Shamir katsayısı içindir — renk seçimi değil.
        color = random.choice(_TAG_COLORS)  # nosec B311
        try:
            DBManager().execute(
                "INSERT OR IGNORE INTO tags (name, color) VALUES (?, ?)",
                (name.strip(), color),
            )
            self._refresh_tag_sidebar()
        except Exception as exc:
            QMessageBox.warning(self, "Hata", str(exc))

