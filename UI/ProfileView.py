"""
HYCLEUS — Profil: tam sayfa görünüm

Modal'dan tam sayfaya
----------------------
`UI/ProfileDialog.py`'nin (kaldırıldı) yerini alıyor. Eskiden bir `QDialog`
olarak `.exec()` ile açılıyordu; artık `UI/GuvenlikView.py`/`UI/
AuditLogView.py` ile AYNI desende `_govde_yigini` (`QStackedWidget`)
içinde bir sayfa — dosya görünümünden ayrılıp geri dönüldüğünde seçili
sekme KORUNUYOR, ayrı bir pencere olsaydı her açılışta "Profil" sekmesine
sıfırlanırdı.

Sayfa `centralWidget()`'ın İÇİNDE olduğu için aynı kural geçerli: kendi
`setStyleSheet()`'ini ÇAĞIRMIYOR, stil `UI/main_window_theme.py::
_apply_theme()`'in merkezi QSS'inden `#profil_view` nesne adıyla cascade
ediyor (B-055).

Kimlik etiketleri (avatar/ad/rol) `__init__`'te ANINDA doluyor — bellekte
zaten duran `pencere._username`/`_role` okunuyor, DB'ye gidilmiyor.
`yenile()` bunları YİNE de tazeler (B-065: USB değişirse — `_trigger_
usb_reauth()` — aynı pencere örneği FARKLI bir kullanıcıyı temsil etmeye
başlayabilir) ve ASIL DB yükünü (cihaz + kendi işlemlerim) burada yapar —
`AuditLogView.yenile()` ile AYNI gerekçe: sayfa arkada dururken (dosya
görünümünde gezinirken) döndürebilecek bayat veri sorunu.


Cihazlar ve oturum — veri kaynağı
------------------------------------
`CORE/usb_tokens.py::token_kayitlarini_getir()` — USB Yönetim Paneli'nin
(`UI/AdminPanel.py`) "USB Tokenlar" sekmesiyle AYNI fonksiyon, `hwid=`
filtresiyle daraltılmış. AYRI bir sorgu YAZILMADI: aynı veriyi iki yerde
farklı biçimde tutmak, biri güncellenip diğerinin unutulduğu güne kadar
sessizce ayrışırdı.

Çoklu cihaz YOK, kasıtlı: `users.hwid` kısmi UNIQUE (B-060) — bir hesap
en fazla BİR HWID'e bağlı olabiliyor. Bu bölüm bu yüzden en fazla TEK
satır gösterir; bu bir eksiklik değil, şemanın kimlik doğrulama modelinin
doğal sonucu. Ayrıntı: SECURITY.md §4.23, BACKLOG.md B-082.

"Şu an takılı" — `CORE.usb_manager.get_usb_hwid()` ile CANLI karşılaştırma
(kayıt zamanı bir alan değil): kullanıcı profile bakarken USB'yi çekmiş
olabilir (henüz `_poll_usb` kilitlememiş olabilir — 3 sn'lik tik aralığı).

"Oturumu kapat" — `pencere._on_manual_logout()`'a delege ediyor (bkz. `UI/
main_window_lock.py`). Gövde BURADA DEĞİL: aynı `_lock()`/`_unlock()`
mekanizması `_poll_usb`/hareketsizlik kilidiyle PAYLAŞILIYOR, ikinci bir
kilit uygulaması YAZILMADI.


Kendi işlemlerim — veri kaynağı
-----------------------------------
`audit_log` tablosunun `user_id = pencere._user_id` ile daraltılmış,
zaman sıralı son `_ISLEM_LIMIT` kaydı — `UI/AuditLogView.py`'nin tam
konsolunun (filtreler, HALKA zincir sütunu, TXT dışa aktarım) KÜÇÜK bir
alt kümesi, KOPYASI değil: burada sekme/filtre/HALKA yok, çünkü amaç
"tüm denetim günlüğünü yönet" değil "son işlemlerime hızlı bir bakış."
Tam günlük gerekiyorsa kullanıcı zaten (yetkisi varsa) Denetim Günlüğü
sayfasına gidebilir.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from CORE.pin_rotation import PinRotationError, rotate_pin
from CORE.usb_manager import get_usb_hwid
from CORE.usb_tokens import token_kayitlarini_getir
from DB.db_manager import DBManager

#: Sayfa başlığı — kenar çubuğu/üst bar AYNI sabiti kullanıyor (bkz.
#: `UI/AuditLogView.py::SAYFA_ADI`'nın aynı deseni).
SAYFA_ADI = "Profil"

#: "Kendi işlemlerim" listesinin gösterdiği en fazla kayıt sayısı — bir
#: hızlı bakış, tam bir konsol değil (bkz. modül docstring'i).
_ISLEM_LIMIT = 20

_TAB_ADLARI = ("Profil", "Cihazlar", "İşlemlerim", "İletişim")


def _sep() -> QFrame:
    f = QFrame()
    f.setObjectName("profil_sep")
    f.setFrameShape(QFrame.HLine)
    return f


def _fmt_ts(ts: str) -> str:
    return ts.replace("T", " ").rstrip("Z") if ts else "—"


class ProfileView(QWidget):
    """Profil sayfası — Profil / Cihazlar / İşlemlerim / İletişim sekmeleri."""

    def __init__(self, pencere: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._pencere = pencere
        self.setObjectName("profil_view")
        self._build_ui()

    # ── Kurulum ──────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._make_header())
        root.addWidget(self._make_tab_bar())
        root.addWidget(self._make_pages(), 1)

    def _make_header(self) -> QFrame:
        hdr = QFrame()
        hdr.setObjectName("profil_header")
        hdr.setFixedHeight(96)

        lay = QHBoxLayout(hdr)
        lay.setContentsMargins(24, 0, 24, 0)
        lay.setSpacing(16)

        ad = self._pencere._username or "?"
        self._avatar_lbl = QLabel(ad[0].upper() if ad else "?")
        self._avatar_lbl.setObjectName("avatar_lbl")
        self._avatar_lbl.setAlignment(Qt.AlignCenter)
        lay.addWidget(self._avatar_lbl)

        info = QVBoxLayout()
        info.setSpacing(2)

        self._name_lbl = QLabel(ad)
        self._name_lbl.setObjectName("user_name")
        info.addWidget(self._name_lbl)

        self._role_lbl = QLabel(self._pencere._role)
        self._role_lbl.setObjectName("user_role")
        info.addWidget(self._role_lbl)

        lay.addLayout(info)
        lay.addStretch()
        return hdr

    def _make_tab_bar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("profil_tab_bar")
        bar.setFixedHeight(42)

        lay = QHBoxLayout(bar)
        lay.setContentsMargins(16, 0, 16, 0)
        lay.setSpacing(0)

        self._tab_btns: list[QPushButton] = []
        for i, ad in enumerate(_TAB_ADLARI):
            btn = QPushButton(ad)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda checked=False, idx=i: self._switch_tab(idx))
            self._tab_btns.append(btn)
            lay.addWidget(btn)

        lay.addStretch()
        return bar

    def _make_pages(self) -> QWidget:
        self._stack = QStackedWidget()
        self._stack.addWidget(self._make_profil_page())
        self._stack.addWidget(self._make_cihazlar_page())
        self._stack.addWidget(self._make_islemlerim_page())
        self._stack.addWidget(self._make_iletisim_page())
        self._switch_tab(0)
        return self._stack

    def _switch_tab(self, idx: int) -> None:
        self._stack.setCurrentIndex(idx)
        for i, btn in enumerate(self._tab_btns):
            btn.setProperty("tab_on", "true" if i == idx else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    # ── Yenileme (sayfaya her dönüşte) ──────────────────────────────────────

    def yenile(self) -> None:
        """`main_window.py::_on_open_profile()`'ın her çağrısında çalışır —
        bkz. modül docstring'i."""
        self._refresh_identity()
        self._load_pin_warning()
        self._load_cihaz()
        self._load_islemlerim()

    def _refresh_identity(self) -> None:
        ad = self._pencere._username or "?"
        self._avatar_lbl.setText(ad[0].upper() if ad else "?")
        self._name_lbl.setText(ad)
        self._role_lbl.setText(self._pencere._role)

    # ── Profil sayfası ────────────────────────────────────────────────────────

    def _make_profil_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("profil_page")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 16, 24, 16)
        lay.setSpacing(8)

        sec1 = QLabel("BİLGİLER")
        sec1.setObjectName("section_lbl")
        lay.addWidget(sec1)

        self._bilgi_kullanici = self._info_row("Kullanıcı Adı", "")
        lay.addWidget(self._bilgi_kullanici)
        self._bilgi_rol = self._info_row("Rol", "")
        lay.addWidget(self._bilgi_rol)
        self._bilgi_hwid = self._info_row("HWID", "")
        lay.addWidget(self._bilgi_hwid)
        self._doldur_bilgiler()

        self._pin_warn = QLabel()
        self._pin_warn.setObjectName("warn_lbl")
        self._pin_warn.setWordWrap(True)
        self._pin_warn.setVisible(False)
        lay.addWidget(self._pin_warn)

        lay.addWidget(_sep())

        sec2 = QLabel("PIN DEĞİŞTİR")
        sec2.setObjectName("section_lbl")
        lay.addWidget(sec2)

        self._old_pin = QLineEdit()
        self._old_pin.setPlaceholderText("Mevcut PIN")
        self._old_pin.setEchoMode(QLineEdit.Password)
        lay.addWidget(self._old_pin)

        self._new_pin = QLineEdit()
        self._new_pin.setPlaceholderText("Yeni PIN")
        self._new_pin.setEchoMode(QLineEdit.Password)
        lay.addWidget(self._new_pin)

        self._new_pin2 = QLineEdit()
        self._new_pin2.setPlaceholderText("Yeni PIN (tekrar)")
        self._new_pin2.setEchoMode(QLineEdit.Password)
        lay.addWidget(self._new_pin2)

        btn_pin = QPushButton("PIN'i Güncelle")
        btn_pin.setObjectName("btn_primary")
        btn_pin.setCursor(Qt.PointingHandCursor)
        btn_pin.clicked.connect(self._on_change_pin)
        lay.addWidget(btn_pin)

        lay.addStretch()
        return page

    def _doldur_bilgiler(self) -> None:
        self._set_info_row(self._bilgi_kullanici, self._pencere._username or "")
        self._set_info_row(self._bilgi_rol, self._pencere._role)
        hwid = self._pencere._hwid or ""
        self._set_info_row(self._bilgi_hwid, hwid[:16] + "..." if hwid else "—")

    @staticmethod
    def _info_row(key: str, value: str) -> QWidget:
        w = QWidget()
        w.setObjectName("profil_bilgi_satiri")
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 2, 0, 2)
        h.setSpacing(8)
        k = QLabel(key)
        k.setObjectName("field_key")
        v = QLabel(value)
        v.setObjectName("field_val")
        h.addWidget(k)
        h.addWidget(v)
        h.addStretch()
        return w

    @staticmethod
    def _set_info_row(row: QWidget, value: str) -> None:
        v = row.findChild(QLabel, "field_val")
        if v is not None:
            v.setText(value)

    def _load_pin_warning(self) -> None:
        try:
            row = DBManager().fetchone(
                "SELECT last_pin_changed FROM users WHERE id = ?",
                (self._pencere._user_id,),
            )
        except Exception:
            return
        if row is None or not row["last_pin_changed"]:
            self._pin_warn.setText(
                "⚠  PIN değiştirme tarihi bilinmiyor — güvenliğiniz için güncelleyin."
            )
            self._pin_warn.setVisible(True)
            return
        try:
            changed = datetime.strptime(
                row["last_pin_changed"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - changed).days
            if age_days >= 180:
                self._pin_warn.setText(
                    f"⚠  PIN'iniz {age_days} gündür değiştirilmedi "
                    f"(son: {row['last_pin_changed'][:10]}). 6 ayda bir "
                    "güncellemeniz önerilir."
                )
                self._pin_warn.setVisible(True)
            else:
                self._pin_warn.setVisible(False)
        except ValueError:
            pass

    def _on_change_pin(self) -> None:
        old = self._old_pin.text().strip()
        new = self._new_pin.text().strip()
        rep = self._new_pin2.text().strip()

        if not old or not new or not rep:
            QMessageBox.warning(self, "PIN", "Tüm alanlar doldurulmalıdır.")
            return
        if new != rep:
            QMessageBox.warning(self, "PIN", "Yeni PIN'ler eşleşmiyor.")
            return
        # Doğrulama, kasa yeniden şifreleme, `last_pin_changed` güncelleme
        # ve denetim kaydı TEK YERDE: `CORE/pin_rotation.py`. Zorunlu
        # yenileme akışı (B-003) da aynı fonksiyonu çağırıyor — ikinci bir
        # uygulama, bu deponun beş kez ürettiği kusur sınıfı olurdu.
        try:
            rotate_pin(
                DBManager(), self._pencere._hwid, old, new,
                user_id=self._pencere._user_id, zorunlu=False,
            )
        except PinRotationError as exc:
            QMessageBox.warning(self, "PIN Hatası", str(exc))
            return
        except Exception as exc:
            QMessageBox.critical(self, "Hata", str(exc))
            return

        self._old_pin.clear()
        self._new_pin.clear()
        self._new_pin2.clear()
        self._pin_warn.setVisible(False)
        QMessageBox.information(self, "PIN", "PIN başarıyla güncellendi.")

    # ── Cihazlar ve oturum sayfası ───────────────────────────────────────────

    def _make_cihazlar_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("profil_page")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 16, 24, 16)
        lay.setSpacing(8)

        sec = QLabel("CİHAZLAR VE OTURUM")
        sec.setObjectName("section_lbl")
        lay.addWidget(sec)

        ipucu = QLabel(
            "Hesabınıza kayıtlı USB güvenlik anahtarı ve oturum durumu. "
            "HYCLEUS bir hesabı en fazla bir cihaza bağlar (bkz. Yardım)."
        )
        ipucu.setWordWrap(True)
        ipucu.setObjectName("profil_ipucu")
        lay.addWidget(ipucu)

        self._cihaz_table = QTableWidget(0, 4)
        self._cihaz_table.setHorizontalHeaderLabels(
            ["Token ID", "Kayıt Tarihi", "Durum", "Şu An Takılı"]
        )
        hdr = self._cihaz_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._cihaz_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._cihaz_table.setSelectionMode(QTableWidget.NoSelection)
        self._cihaz_table.verticalHeader().setVisible(False)
        self._cihaz_table.setFixedHeight(110)
        lay.addWidget(self._cihaz_table)

        btn_logout = QPushButton("Oturumu Kapat")
        btn_logout.setObjectName("btn_secondary")
        btn_logout.setCursor(Qt.PointingHandCursor)
        btn_logout.setFixedWidth(160)
        btn_logout.clicked.connect(self._on_logout)
        lay.addWidget(btn_logout)

        lay.addStretch()
        return page

    def _load_cihaz(self) -> None:
        self._cihaz_table.setRowCount(0)
        try:
            kayitlar = token_kayitlarini_getir(
                DBManager(), hwid=self._pencere._hwid
            )
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı Hatası", str(exc))
            return

        canli_hwid = get_usb_hwid()
        for kayit in kayitlar:
            r = self._cihaz_table.rowCount()
            self._cihaz_table.insertRow(r)

            token_id = kayit.token_id
            self._cihaz_table.setItem(
                r, 0,
                QTableWidgetItem(
                    token_id[:20] + "…" if len(token_id) > 20 else token_id or "—"
                ),
            )
            self._cihaz_table.setItem(r, 1, QTableWidgetItem(_fmt_ts(kayit.created_at)))
            self._cihaz_table.setItem(
                r, 2, QTableWidgetItem("Kara Liste" if kayit.blacklisted else "Aktif")
            )
            takili = "✓ Evet" if kayit.hwid == canli_hwid else "Hayır"
            self._cihaz_table.setItem(r, 3, QTableWidgetItem(takili))

    def _on_logout(self) -> None:
        if QMessageBox.question(
            self, "Oturumu Kapat",
            "Oturumu kapatmak istediğinize emin misiniz?\n\n"
            "Devam etmek için yeniden vault PIN'inizi girmeniz gerekecek.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        # Gövde main_window_lock.py'de — aynı kilit örtüsü/PIN doğrulama
        # mekanizması hareketsizlik kilidiyle PAYLAŞILIYOR (bkz. modül
        # docstring'i).
        self._pencere._on_manual_logout()

    # ── Kendi işlemlerim sayfası ─────────────────────────────────────────────

    def _make_islemlerim_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("profil_page")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 16, 24, 16)
        lay.setSpacing(8)

        sec = QLabel("KENDİ İŞLEMLERİM")
        sec.setObjectName("section_lbl")
        lay.addWidget(sec)

        ipucu = QLabel(f"Hesabınızla yapılan son {_ISLEM_LIMIT} işlem.")
        ipucu.setObjectName("profil_ipucu")
        lay.addWidget(ipucu)

        self._islem_table = QTableWidget(0, 3)
        self._islem_table.setHorizontalHeaderLabels(["Zaman", "İşlem", "Detay"])
        hdr = self._islem_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)
        self._islem_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._islem_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._islem_table.verticalHeader().setVisible(False)
        lay.addWidget(self._islem_table, 1)

        return page

    def _load_islemlerim(self) -> None:
        self._islem_table.setRowCount(0)
        try:
            rows = DBManager().fetchall(
                """
                SELECT timestamp, action, detail
                FROM audit_log
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (self._pencere._user_id, _ISLEM_LIMIT),
            )
        except Exception as exc:
            QMessageBox.warning(self, "Veritabanı Hatası", str(exc))
            return

        for row in rows:
            r = self._islem_table.rowCount()
            self._islem_table.insertRow(r)
            self._islem_table.setItem(r, 0, QTableWidgetItem(_fmt_ts(row["timestamp"] or "")))
            self._islem_table.setItem(r, 1, QTableWidgetItem(row["action"] or ""))
            detay = row["detail"] or ""
            self._islem_table.setItem(
                r, 2, QTableWidgetItem(detay[:120] + "…" if len(detay) > 120 else detay)
            )

    # ── İletişim sayfası ──────────────────────────────────────────────────────

    def _make_iletisim_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("profil_page")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(12)

        lbl = QLabel("Destek ve iletişim için ContactDialog'u açın.")
        lbl.setWordWrap(True)
        lbl.setObjectName("profil_ipucu")
        lay.addWidget(lbl)

        btn = QPushButton("💬  Destek ve İletişim Penceresini Aç")
        btn.setObjectName("btn_primary")
        btn.setCursor(Qt.PointingHandCursor)
        btn.clicked.connect(self._open_contact)
        lay.addWidget(btn)

        lay.addStretch()
        return page

    def _open_contact(self) -> None:
        from UI.ContactDialog import ContactDialog
        ContactDialog(self).exec()


__all__ = ["SAYFA_ADI", "ProfileView"]
