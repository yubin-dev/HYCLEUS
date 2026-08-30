"""
HYCLEUS — Denetim Günlüğü: tam sayfa görünüm

Modal'dan tam sayfaya
----------------------
`UI/AuditLogDialog.py`'nin (kaldırıldı) yerini alıyor. Eskiden bir
`QDialog` olarak `.exec()` ile açılıyordu; artık `UI/GuvenlikView.py` ile
AYNI desende `_govde_yigini` (`QStackedWidget`) içinde bir sayfa — dosya
görünümünden ayrılıp geri dönüldüğünde durum (filtre, seçili sekme)
KORUNUYOR, ayrı bir pencere olsaydı ya kopyalanır ya kaybolurdu.

Sayfa `centralWidget()`'ın İÇİNDE olduğu için `GuvenlikView.py`'nin aynı
kuralı geçerli: kendi `setStyleSheet()`'ini ÇAĞIRMIYOR, stil
`UI/main_window_theme.py::_apply_theme()`'in merkezi QSS'inden
`#audit_view` nesne adıyla cascade ediyor (B-055).


Sekmeler — Tümü/Dosya/Kimlik/Yönetim/Uyarı
--------------------------------------------
Beşi de AYNI tabloyu filtreliyor; beş ayrı `QTableWidget` kurup veriyi beş
kopyada senkron tutmak yerine `QTabBar` (sayfasız) kullanıldı — sekme
şeridi Qt'nin kendi görselini veriyor, "sayfa" kısmı elle yönetiliyor
(`currentChanged` → `_load()`). `QTabWidget` (bkz. `UI/AdminPanel.py`)
burada YANLIŞ araç olurdu: onun sayfaları GERÇEKTEN farklı içerik taşıyor
(USB Tokenlar/Bekleyen Kayıtlar/Ayarlar), burada ise beşi de "aynı
tabloyu farklı süz" — beş kopya tablo, beş kopya durum demek olurdu.

Dosya/Kimlik/Yönetim ayrımı `_kategori()`'de action adı üzerinden
yapılıyor (bilinen action'ların TAM kümesi — bkz. aşağıdaki üç frozenset).
Bilinmeyen bir action hiçbir kategoriye DÜŞMÜYOR (yalnızca Tümü'nde
görünüyor) — tahmini bir önek eşleşmesi yanlış kategoriye sessizce
düşürebilirdi, boş bırakmak daha güvenli bir varsayılan. Uyarı sekmesi
AYRI bir eksen: eski `AuditLogDialog._is_failure()` (BURAYA taşındı,
değişmedi) action'ın BAŞARISIZLIK içerip içermediğine bakıyor, kategoriden
bağımsız — bir "login_failed" hem Kimlik'te hem Uyarı'da görünebilir.


HALKA sütunu — verify_audit_chain()'e DAYANIYOR, yeni hesaplama YOK
---------------------------------------------------------------------
Karar (görev metninin sorduğu soru): `CORE/audit_chain.py::
verify_audit_chain()` zaten her kaydı bir kez hesaplayıp `ChainVerification.
breaks`'e yalnızca başarısız olanları yazıyor. İkinci bir hash yürüyüşü
YAZMAK yerine `CORE/audit_chain.py::link_statuses()` bu SONUCU satır
bazında okuyor (bkz. o fonksiyonun docstring'i — aynı tek-karar-noktası
gerekçesi `CORE/pin_rotation.py`/`CORE/hwid_probe.py`'de de var). `_load()`
zinciri TEK SEFERDE (`CORE.audit_report.zincir_raporu()` ile) doğruluyor;
sonuç hem HALKA sütununa hem (dışa aktarımda) TXT başlığına besleniyor —
iki ayrı doğrulama çağrısı değil, aynı sonucun iki kullanımı.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from PySide6.QtCore import QDate, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QDateEdit,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTabBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from CORE.audit_chain import GENESIS_ACTION, LINK_BROKEN, LINK_INTACT, link_statuses
from CORE.audit_report import HALKA_METNI
from CORE.hclx import (
    EYLEM_ACILDI as _HCLX_ACILDI,
    EYLEM_REDDEDILDI as _HCLX_REDDEDILDI,
    EYLEM_URETILDI as _HCLX_URETILDI,
)
from CORE.pin_rotation import EYLEM_ISTEGE_BAGLI, EYLEM_ZORUNLU
from CORE.secret_store import EYLEM_GOLGE_SILINDI
from CORE.tpm_sealing import (
    EYLEM_DUSUS,
    EYLEM_ETKIN,
    EYLEM_YENIDEN_MUHUR,
    EYLEM_YENIDEN_MUHUR_BASARISIZ,
)
from CORE.trusted_roots import EYLEM_EKLENDI, EYLEM_SILINDI
from DB.db_manager import DBManager

#: Sayfa başlığı — kenar çubuğu düğmesi ve üst bar aynı sabiti kullanıyor
#: (bkz. `UI/GuvenlikView.py::SAYFA_ADI`'nın aynı deseni).
SAYFA_ADI = "Denetim Günlüğü"

_FAIL_KEYWORDS = frozenset(
    {"fail", "denied", "blacklist", "error", "reject", "lock", "invalid", "unauthorized"}
)


def _is_failure(action: str) -> bool:
    """Uyarı sekmesinin süzgeci — `AuditLogDialog.py`'den DEĞİŞMEDEN taşındı."""
    low = action.lower()
    return any(k in low for k in _FAIL_KEYWORDS)


# ── Kategori — Dosya / Kimlik / Yönetim ────────────────────────────────────────
#
# Kod tabanındaki `.log(...)` çağrılarının TAMAMI (`grep -rn "\.log("`)
# taranarak çıkarılan action envanteri. Yeni bir action eklenip buraya
# girilmezse yalnızca Tümü'nde görünür — YANLIŞ kategoriye düşmez.
#
# Kendi `EYLEM_*` sabiti OLAN action'lar (hclx/pin_rotation/tpm_sealing/
# trusted_roots/secret_store/audit_chain) LİTERAL yazılmıyor, İTHAL
# EDİLİYOR — `tests/test_hclx.py::test_denetim_eylemleri_yalnizca_hclx_
# modulunden` gibi denetimler tam olarak bunu arıyor: aynı dizeyi başka
# bir dosyada literal olarak yeniden yazmak, o modülün "tek yazan ben"
# garantisini SESSİZCE ikinci bir kopyaya açar (burada yalnızca OKUNUYOR,
# yazılmıyor, ama denetim niyeti ayırt etmiyor — ithal etmek zaten daha
# doğrusu). Kendi sabiti OLMAYAN action'lar (file_added, login_success,
# …) kod tabanının geri kalanında zaten yalnızca inline literal olarak
# geçiyor; onlar için ithal edilecek bir isim yok.

_KATEGORI_KIMLIK = frozenset({
    "login_success", "login_failed", "login_blocked", "login_rate_limited",
    "usb_auth_success", "usb_auth_rejected",
    "weak_hwid_binding_rejected", "weak_hwid_uuid_assigned",
    "idle_lock_triggered", "idle_lock_disabled",
    "idle_unlock_success", "idle_unlock_failed",
    "session_logged_out", "manual_unlock_success", "manual_unlock_failed",
    "session_revoked", "session_user_linked", "session_user_provisioned",
    EYLEM_ZORUNLU, EYLEM_ISTEGE_BAGLI,
    _HCLX_URETILDI, _HCLX_ACILDI, _HCLX_REDDEDILDI,
    EYLEM_ETKIN, EYLEM_DUSUS, EYLEM_YENIDEN_MUHUR, EYLEM_YENIDEN_MUHUR_BASARISIZ,
    "vault_recovered", "vault_reprovisioned",
    EYLEM_GOLGE_SILINDI,
    "user_registered",
})

_KATEGORI_DOSYA = frozenset({
    "file_added", "file_downloaded", "file_label_changed", "file_moved_to_imha",
    "file_moved_to_folder", "file_checked_in", "file_closed_unchanged",
    "file_opened", "file_purged", "file_reopened",
    "folder_created", "folder_deleted", "folder_downloaded",
    "folder_download_totp_failed", "download_totp_failed", "bulk_download_totp_failed",
    "tag_deleted", "file_tags_updated", "file_tags_bulk_updated",
    "expired_purge", "retention_hold", "retention_sweep", "early_disposal_blocked",
    "timestamp_verified",
})

_KATEGORI_YONETIM = frozenset({
    "app_mode_changed", "backup_created", "backup_metadata_applied", "backup_verified",
    "setting_changed", "startup",
    "rbac_write_rejected",
    EYLEM_EKLENDI, EYLEM_SILINDI,
    "usb_blacklisted", "usb_unblacklisted", "usb_deleted", "usb_reset", "usb_reset_complete",
    "usb_role_changed",
    "user_approved", "user_rejected",
    "referans_id_generated",
    "integrity_sweep_started", "integrity_sweep_finished", "integrity_sweep_aborted",
    "integrity_check_failed", "integrity_vault_failed",
    "recovery_share_exported",
    GENESIS_ACTION,
})

#: `(sekme adı, kategori anahtarı)` — sıra `_sekmeler` kurulum sırasıyla AYNI
#: olmalı. "tumu"/"uyari" kategori kümesiyle değil özel mantıkla süzülüyor.
_SEKMELER: tuple[tuple[str, str], ...] = (
    ("Tümü", "tumu"),
    ("Dosya", "dosya"),
    ("Kimlik", "kimlik"),
    ("Yönetim", "yonetim"),
    ("Uyarı", "uyari"),
)


def _kategori(action: str) -> str | None:
    """Bilinen action kümelerinden biriyle eşleşiyorsa kategori adı, yoksa None."""
    if action in _KATEGORI_KIMLIK:
        return "kimlik"
    if action in _KATEGORI_DOSYA:
        return "dosya"
    if action in _KATEGORI_YONETIM:
        return "yonetim"
    return None


def _sekmeye_uyuyor(sekme: str, action: str) -> bool:
    if sekme == "tumu":
        return True
    if sekme == "uyari":
        return _is_failure(action)
    return _kategori(action) == sekme


#: HALKA sütunu görüntü metinleri — `CORE/audit_report.py::HALKA_METNI`'den
#: İTHAL EDİLİYOR (taşındı): CSV/PDF dışa aktarımı AYNI eşlemeyi
#: kullanıyor, ikinci bir kopya YAZILMADI.
_HALKA_METNI = HALKA_METNI


class AuditLogView(QWidget):
    """Denetim günlüğü — filtre + sekmeler + tablo (HALKA sütunu dahil)."""

    def __init__(self, pencere: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._pencere = pencere
        self._sekme_indeksi = 0  # "Tümü"
        self._son_rapor: Any = None
        self._son_export_satirlari: list[Any] = []
        self.setObjectName("audit_view")
        self._build_ui()
        # BİLEREK burada DB'ye dokunulmuyor: bu sayfa `HycleusWindow.
        # __init__`'te (GuvenlikView ile aynı yerde) kuruluyor — her
        # oturum açılışında, sayfa hiç ziyaret edilmese bile, tüm
        # denetim tablosunu okuyup zinciri yürütmek (`verify_audit_chain`
        # HER zincirli kaydı hash'liyor) gereksiz bir başlangıç maliyeti
        # olurdu. İlk gerçek yük `yenile()` ile geliyor — sayfa GÖRÜNÜR
        # olduğunda (`main_window.py::_on_open_audit_log`).

    # ── Kurulum ──────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        baslik = QLabel("Denetim Günlüğü")
        baslik.setObjectName("audit_baslik")
        layout.addWidget(baslik)

        aciklama = QLabel(
            "Her satırın HALKA sütunu, o kaydın hash zincirindeki KENDİ "
            "bağının sağlam mı kırık mı olduğunu gösterir — genel zincir "
            "durumu için Güvenlik sayfasındaki \"Denetim Zincirini "
            "Doğrula\"ya bakın."
        )
        aciklama.setWordWrap(True)
        aciklama.setObjectName("audit_aciklama")
        layout.addWidget(aciklama)

        self._tab_bar = QTabBar()
        self._tab_bar.setObjectName("audit_sekmeler")
        for ad, _kategori_anahtari in _SEKMELER:
            self._tab_bar.addTab(ad)
        self._tab_bar.currentChanged.connect(self._sekme_degisti)
        layout.addWidget(self._tab_bar)

        layout.addLayout(self._make_filter_bar())
        layout.addWidget(self._make_table(), 1)
        layout.addLayout(self._make_footer())

    def _make_filter_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        bar.addWidget(QLabel("Başlangıç:"))
        self._date_start = QDateEdit()
        self._date_start.setCalendarPopup(True)
        self._date_start.setDate(QDate.currentDate().addDays(-30))
        self._date_start.setDisplayFormat("dd.MM.yyyy")
        bar.addWidget(self._date_start)

        bar.addWidget(QLabel("Bitiş:"))
        self._date_end = QDateEdit()
        self._date_end.setCalendarPopup(True)
        self._date_end.setDate(QDate.currentDate())
        self._date_end.setDisplayFormat("dd.MM.yyyy")
        bar.addWidget(self._date_end)

        bar.addWidget(QLabel("İşlem:"))
        self._action_combo = QComboBox()
        bar.addWidget(self._action_combo)

        btn_filter = QPushButton("Filtrele")
        btn_filter.setObjectName("audit_btn_filtrele")
        btn_filter.setCursor(Qt.PointingHandCursor)
        btn_filter.clicked.connect(self._load)
        bar.addWidget(btn_filter)

        btn_reset = QPushButton("Sıfırla")
        btn_reset.setObjectName("audit_btn_sifirla")
        btn_reset.setCursor(Qt.PointingHandCursor)
        btn_reset.clicked.connect(self._reset_filters)
        bar.addWidget(btn_reset)

        bar.addStretch()
        return bar

    def _make_table(self) -> QTableWidget:
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["Zaman", "İşlem", "Kullanıcı", "HWID", "HALKA"]
        )
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(False)
        return self._table

    def _make_footer(self) -> QHBoxLayout:
        footer = QHBoxLayout()

        self._count_label = QLabel("Toplam: 0 kayıt")
        self._count_label.setObjectName("audit_sayac")
        footer.addWidget(self._count_label)

        footer.addStretch()

        # Üç format — mockup'ın istediği üçü: Düz metin (TXT, mevcut),
        # Tablo (CSV — Excel/SIEM için ayrık sütunlu), İmzalı Rapor (PDF —
        # özet + zincir doğrulama + dış çıpa, bkz. `CORE/audit_report.py::
        # export_pdf()`'in "İmzalı ne demek" notu).
        btn_export = QPushButton("Düz Metin (TXT)")
        btn_export.setObjectName("audit_btn_disa_aktar")
        btn_export.setCursor(Qt.PointingHandCursor)
        btn_export.clicked.connect(self._export_txt)
        footer.addWidget(btn_export)

        btn_export_csv = QPushButton("Tablo (CSV)")
        btn_export_csv.setObjectName("audit_btn_disa_aktar_csv")
        btn_export_csv.setCursor(Qt.PointingHandCursor)
        btn_export_csv.clicked.connect(self._export_csv)
        footer.addWidget(btn_export_csv)

        btn_export_pdf = QPushButton("İmzalı Rapor (PDF)")
        btn_export_pdf.setObjectName("audit_btn_disa_aktar_pdf")
        btn_export_pdf.setCursor(Qt.PointingHandCursor)
        btn_export_pdf.clicked.connect(self._export_pdf)
        footer.addWidget(btn_export_pdf)

        return footer

    # ── Sekme ────────────────────────────────────────────────────────────────

    def _sekme_degisti(self, index: int) -> None:
        self._sekme_indeksi = index
        self._load()

    # ── Veri yükleme ─────────────────────────────────────────────────────────

    def _populate_action_filter(self) -> None:
        """
        `İşlem` açılır kutusunu DOLDURUR — çağrıldığında ÖNCE temizler,
        sonra mevcut seçimi KORUR. `yenile()` bu metodu her sayfa
        açılışında tekrar çağırıyor (bkz. orada), yani açılıştan sonra
        eklenen yeni bir action türü de listede görünür — eski modal her
        `.exec()`'te zaten YENİ bir örnekti, bu aynı tazeliği sayfa
        yeniden kullanılırken de veriyor.
        """
        onceki = self._action_combo.currentData() if self._action_combo.count() else None
        self._action_combo.clear()
        self._action_combo.addItem("Tümü", None)
        try:
            rows = DBManager().fetchall(
                "SELECT DISTINCT action FROM audit_log ORDER BY action"
            )
            for row in rows:
                self._action_combo.addItem(row["action"], row["action"])
        except Exception:
            pass
        if onceki is not None:
            index = self._action_combo.findData(onceki)
            if index >= 0:
                self._action_combo.setCurrentIndex(index)

    def _reset_filters(self) -> None:
        self._date_start.setDate(QDate.currentDate().addDays(-30))
        self._date_end.setDate(QDate.currentDate())
        self._action_combo.setCurrentIndex(0)
        self._tab_bar.setCurrentIndex(0)
        self._load()

    def yenile(self) -> None:
        """Sayfaya HER dönüşte çağrılıyor — `main_window.py::
        _on_open_audit_log()`. Sayfa arkada dururken (dosya görünümünde
        gezinirken) yeni bir denetim kaydı oluşmuş olabilir; geri
        dönüldüğünde bayat bir tablo göstermek yanıltıcı olurdu. İlk
        çağrı aynı zamanda sayfanın İLK gerçek DB yüküdür (bkz.
        `__init__`'teki gecikmeli yükleme notu)."""
        self._populate_action_filter()
        self._load()

    def _load(self) -> None:
        start_iso = self._date_start.date().toString("yyyy-MM-dd") + "T00:00:00Z"
        end_iso   = self._date_end.date().toString("yyyy-MM-dd") + "T23:59:59Z"
        selected_action = self._action_combo.currentData()

        params: list = [start_iso, end_iso]
        action_clause = ""
        if selected_action is not None:
            action_clause = " AND a.action = ?"
            params.append(selected_action)

        try:
            db = DBManager()
            rows = db.fetchall(
                f"""
                SELECT a.id, a.timestamp, a.action, u.username, a.user_id, a.detail
                FROM audit_log a
                LEFT JOIN users u ON u.id = a.user_id
                WHERE a.timestamp >= ? AND a.timestamp <= ?
                {action_clause}
                ORDER BY a.timestamp DESC
                """,
                tuple(params),
            )
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı Hatası", str(exc))
            return

        # HALKA — tek doğrulama çağrısı, TÜM görünür satırlara uygulanıyor.
        # `zincir_raporu()` hem burada hem `_export_txt()`'te çağrılıyor;
        # ikisi AYNI CORE fonksiyonuna gidiyor, ikinci bir hesaplama yolu
        # açılmadı (bkz. modül docstring'i).
        from CORE.audit_report import zincir_raporu

        try:
            self._son_rapor = zincir_raporu(db)
            halkalar = link_statuses(self._son_rapor.zincir, [r["id"] for r in rows])
        except Exception as exc:  # zincir okunamazsa tablo YİNE de dolmalı
            self._son_rapor = None
            halkalar = {}
            _log_uyari = f"zincir okunamadı: {exc}"
        else:
            _log_uyari = None

        sekme = _SEKMELER[self._sekme_indeksi][1]

        # CSV/PDF dışa aktarımının HAM veri kaynağı — TAM OLARAK tabloda
        # GÖRÜNEN satırlarla aynı filtre (tarih + işlem + sekme), yalnızca
        # kırpılmamış hâliyle. İkinci bir sorgu YAZILMADI: `_export_csv()`/
        # `_export_pdf()` bu listeyi `_load()` SONRASI okuyor — `_export_
        # txt()`'in `self._table`'ı okuduğu desenle AYNI "dışa aktarımdan
        # hemen önce yeniden yükle" garantisi (bkz. B-073 takip notu).
        from CORE.audit_report import DenetimSatiri

        self._son_export_satirlari: list[DenetimSatiri] = []

        self._table.setRowCount(0)
        for row in rows:
            action = row["action"] or ""
            if not _sekmeye_uyuyor(sekme, action):
                continue
            username = row["username"]
            if not username:
                username = f"#{row['user_id']}" if row["user_id"] else "—"
            halka = halkalar.get(row["id"], "out_of_scope") if halkalar else "out_of_scope"
            self._insert_row(
                entry_id=row["id"],
                ts=row["timestamp"] or "",
                action=action,
                user=username,
                hwid=self._extract_hwid(row["detail"] or ""),
                failure=_is_failure(action),
                halka=halka,
            )
            self._son_export_satirlari.append(DenetimSatiri(
                id=row["id"],
                zaman=row["timestamp"] or "",
                islem=action,
                kullanici=username,
                kullanici_id=row["user_id"],
                hwid=self._extract_hwid_full(row["detail"] or ""),
                detay=row["detail"] or "",
                halka=halka,
            ))

        self._count_label.setText(f"Toplam: {self._table.rowCount()} kayıt")
        if _log_uyari:
            self._count_label.setText(
                f"{self._count_label.text()} — HALKA hesaplanamadı ({_log_uyari})"
            )

    # ── Tablo yardımcıları ───────────────────────────────────────────────────

    def _insert_row(
        self, entry_id: int, ts: str, action: str, user: str, hwid: str,
        failure: bool, halka: str,
    ) -> None:
        T = self._pencere._T if self._pencere is not None else None
        row = self._table.rowCount()
        self._table.insertRow(row)

        ts_display = ts.replace("T", " ").rstrip("Z")
        halka_metin = _HALKA_METNI.get(halka, halka)
        values = [ts_display, action, user, hwid, halka_metin]

        for col, text in enumerate(values):
            item = QTableWidgetItem(text)
            if col == 0:
                # `audit_log.id` — testlerin bir gösterilen satırı gerçek
                # kayda geri bağlayabilmesi için (bkz.
                # tests/test_audit_log_view.py). Görünürde YOK, yalnızca
                # veri rolü.
                item.setData(Qt.UserRole, entry_id)
            if col == 4 and T is not None:
                # HALKA sütunu — B-055: renk kaynağı self._pencere._T, yeni
                # bir renk İCAT EDİLMEDİ. Sağlam=green, Kopuk=red, Kapsam
                # Dışı=subtext (ne "doğru" ne "yanlış" — hiç doğrulanmadı).
                # `AuditLogDialog._insert_row`'un aynı deseni: `_tint`
                # token'ı DEĞİL, `fg`'nin alpha'lı hâli kullanılıyor.
                if halka == LINK_BROKEN:
                    fg = T["red"]
                elif halka == LINK_INTACT:
                    fg = T["green"]
                else:
                    fg = T["subtext"]
                item.setForeground(QColor(fg))
                tint = QColor(fg)
                tint.setAlpha(36)
                item.setBackground(tint)
            elif failure and T is not None:
                item.setForeground(QColor(T["red"]))
                tint = QColor(T["red"])
                tint.setAlpha(36)
                item.setBackground(tint)
            self._table.setItem(row, col, item)

    @staticmethod
    def _extract_hwid_full(detail: str) -> str:
        """TAM HWID, kırpılmadan — CSV/PDF dışa aktarımı için.

        `_extract_hwid()`'in tabloda gösterdiği 16 karakterlik kırpma
        UI'nin okunabilirlik kararı; "Tablo" (CSV) dışa aktarımının
        amacı TAM OLARAK bunun tersi — ayrık, KIRPILMAMIŞ sütunlar
        (bkz. `CORE/audit_report.py::DenetimSatiri` docstring'i).
        """
        for part in detail.split():
            if part.startswith("hwid="):
                return part[5:]
        return "—"

    @classmethod
    def _extract_hwid(cls, detail: str) -> str:
        val = cls._extract_hwid_full(detail)
        return val[:16] + "…" if len(val) > 16 else val

    # ── Dışa aktarım — ortak yardımcılar ─────────────────────────────────────

    def _filtre_ozeti(self) -> str:
        """Şu anki filtrelerin insan-okunur özeti — PDF başlığında VE
        indirme denetim kaydının `detail` alanında kullanılıyor, iki ayrı
        biçim YAZILMADI."""
        baslangic = self._date_start.date().toString("dd.MM.yyyy")
        bitis = self._date_end.date().toString("dd.MM.yyyy")
        sekme_adi = _SEKMELER[self._sekme_indeksi][0]
        secili_islem = self._action_combo.currentData()
        islem = self._action_combo.currentText() if secili_islem else "Tümü"
        return f"{baslangic}–{bitis}, sekme={sekme_adi}, işlem={islem}"

    def _log_disa_aktarim(self, bicim: str) -> None:
        """İndirme eyleminin KENDİSİNİ denetim kaydına yazar.

        `UI/main_window_files.py::db.log("file_downloaded", ...)` ile AYNI
        "başarılı yazımdan HEMEN sonra, başarı mesajından ÖNCE" sırası —
        üç dışa aktarım metodu da (`_export_txt`/`_export_csv`/
        `_export_pdf`) bunu AYNI noktada çağırıyor. TEK action adı
        (`audit_log_exported`) ve `format=` alanı: üç format `usb_role_
        changed`/`setting_changed`'in zaten yaptığı gibi AYNI kavramsal
        eylemin varyasyonu, üç ayrı action adı yerine `detail=`'da ayrışıyor.
        """
        DBManager().log(
            "audit_log_exported",
            user_id=getattr(self._pencere, "_user_id", None),
            detail=(
                f"format={bicim} kayit_sayisi={len(self._son_export_satirlari)} "
                f"filtre=({self._filtre_ozeti()})"
            ),
        )

    # ── Düz metin (TXT) dışa aktarım ─────────────────────────────────────────

    def _export_txt(self) -> None:
        default_name = (
            f"audit_log_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.txt"
        )
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Denetim Günlüğü Dışa Aktar",
            str(Path.home() / default_name),
            "Text Dosyası (*.txt)",
        )
        if not path:
            return

        # AuditLogDialog.py'den DEĞİŞMEDEN taşındı: tablo ve başlıktaki
        # zincir özeti AYNI ana ait olmak zorunda (bkz. B-073 takip
        # maddesi) — dışa aktarımdan HEMEN önce yeniden yükleniyor.
        self._load()

        col_w = [22, 32, 16, 20, 12]
        header_parts = ["Zaman", "İşlem", "Kullanıcı", "HWID", "HALKA"]
        sep = "-" * (sum(col_w) + len(col_w) * 2 + 1)

        def fmt_row(vals: list[str]) -> str:
            return "  ".join(v.ljust(w)[:w] for v, w in zip(vals, col_w))

        try:
            from CORE.audit_report import txt_basligi

            lines: list[str] = txt_basligi(
                self._son_rapor, kayit_sayisi=self._table.rowCount(),
            )
        except Exception as exc:
            lines = [
                "HYCLEUS — Denetim Günlüğü",
                f"Dışa aktarım: "
                f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
                sep,
                f"Zincir durumu : DOĞRULANAMADI ({exc})",
                sep,
            ]

        lines += [fmt_row(header_parts), sep]

        for row in range(self._table.rowCount()):
            vals = [
                (self._table.item(row, col) or QTableWidgetItem()).text()
                for col in range(5)
            ]
            lines.append(fmt_row(vals))

        lines += [sep, f"Toplam: {self._table.rowCount()} kayıt", ""]

        try:
            Path(path).write_text("\n".join(lines), encoding="utf-8")
        except Exception as exc:
            QMessageBox.critical(self, "Dışa Aktarma Hatası", str(exc))
            return

        self._log_disa_aktarim("txt")
        QMessageBox.information(
            self,
            "Dışa Aktarıldı",
            f"Denetim günlüğü başarıyla dışa aktarıldı:\n{path}",
        )

    # ── Tablo (CSV) dışa aktarım ─────────────────────────────────────────────

    def _export_csv(self) -> None:
        default_name = (
            f"audit_log_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
        )
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Denetim Günlüğü Dışa Aktar — Tablo (CSV)",
            str(Path.home() / default_name),
            "CSV Dosyası (*.csv)",
        )
        if not path:
            return

        # `_export_txt()` ile AYNI garanti: dışa aktarımdan HEMEN önce
        # yeniden yükleniyor, ki `self._son_export_satirlari` sayfa açık
        # dururken arka planda oluşmuş yeni kayıtları da kapsasın (B-073
        # takip maddesi — bkz. `_export_txt()`'in aynı yorumu).
        self._load()

        try:
            from CORE.audit_report import export_csv

            export_csv(self._son_export_satirlari, path)
        except Exception as exc:
            QMessageBox.critical(self, "Dışa Aktarma Hatası", str(exc))
            return

        self._log_disa_aktarim("csv")
        QMessageBox.information(
            self,
            "Dışa Aktarıldı",
            f"Denetim günlüğü tablo (CSV) olarak dışa aktarıldı:\n{path}",
        )

    # ── İmzalı Rapor (PDF) dışa aktarım ──────────────────────────────────────

    def _export_pdf(self) -> None:
        default_name = (
            f"audit_log_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Denetim Günlüğü Dışa Aktar — İmzalı Rapor (PDF)",
            str(Path.home() / default_name),
            "PDF Dosyası (*.pdf)",
        )
        if not path:
            return

        self._load()  # bkz. _export_csv()'nin aynı yorumu

        if self._son_rapor is None:
            QMessageBox.critical(
                self, "Dışa Aktarma Hatası",
                "Zincir doğrulaması hesaplanamadığı için imzalı rapor "
                "üretilemiyor — 'Düz Metin' veya 'Tablo' seçeneğini deneyin.",
            )
            return

        try:
            from CORE.audit_report import export_pdf

            export_pdf(
                self._son_export_satirlari, self._son_rapor, path,
                filters_note=self._filtre_ozeti(),
            )
        except RuntimeError as exc:  # reportlab kurulu değil
            QMessageBox.critical(self, "Dışa Aktarma Hatası", str(exc))
            return
        except Exception as exc:
            QMessageBox.critical(self, "Dışa Aktarma Hatası", str(exc))
            return

        self._log_disa_aktarim("pdf")
        QMessageBox.information(
            self,
            "Dışa Aktarıldı",
            f"Denetim günlüğü imzalı rapor (PDF) olarak dışa aktarıldı:\n{path}",
        )


__all__ = ["SAYFA_ADI", "AuditLogView"]
