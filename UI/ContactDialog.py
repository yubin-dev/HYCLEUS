"""HYCLEUS — Destek ve İletişim Diyaloğu

B-062 (2026-08-25): bu dosya eskiden "Auth Kodu Paylaş" / "İletişim" diye
iki sekmeli bir yapıydı. Auth Kodu Paylaş sekmesi TÜM onaylı kullanıcıların
adını/rolünü listeliyor ve seçilenlerden biri için `auth_codes` tablosuna
8 haneli bir kod yazıyordu — ama bu kod repo genelinde HİÇBİR YERDE okunup
doğrulanmıyordu (login akışının hiçbir dalı bu tabloya bakmıyor); yarım/ölü
bir özellikti. Üstelik sekme rol kontrolsüzdü: Standart/Salt Okunur dahil
herhangi bir oturum bu bilgi ifşasına ve kod üretimine erişebiliyordu.

Karar (kullanıcıyla birlikte verildi): özellik TAMAMEN kaldırıldı — sekme
yapısı, kullanıcı listesi, kod üretimi/kopyalama, `auth_codes` tablosu
(bkz. `DB/migrations.py::_m24_auth_codes_kaldir`) ve ilgili QSS/importlar.
Geriye yalnızca tek sayfalı "İletişim" içeriği (sistem bilgileri + sorun
bildirme) kaldı — bu içerik hiçbir zaman ayrıcalıklı değildi, her rolün
kullanabileceği bir destek ekranı.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from CORE.version import surum_etiketi
from DB.db_manager import DBManager

#: Tek kaynak: CORE/version.py. Elle yazmayın — bkz. BACKLOG B-017.
_APP_VERSION = surum_etiketi()

_QSS = """
QDialog  { background: #FFFFFF; }
QWidget  { color: #111827; background: transparent; }
QLabel   { color: #111827; background: transparent; }

QLabel#dlg_title    { font-size: 18px; font-weight: 700; color: #111827; }
QLabel#section_lbl  { font-size: 11px; font-weight: 600; color: #9CA3AF;
                       letter-spacing: 1px; }

QFrame#top_sep  { background: #E5E7EB; max-height: 1px; border: none; }
QFrame#sys_box  { background: #F9FAFB; border: 1px solid #E5E7EB;
                   border-radius: 8px; }

QLineEdit { background: transparent; color: #111827; border: none;
            border-bottom: 2px solid #E5E7EB; font-size: 14px;
            min-height: 40px; padding: 4px 0; }
QLineEdit:focus { border-bottom: 2px solid #2563EB; }

QTextEdit { background: #F9FAFB; color: #111827;
            border: 1px solid #E5E7EB; border-radius: 8px;
            font-size: 13px; padding: 8px; }

QPushButton#btn_secondary { background: transparent; color: #374151;
                             border: 1px solid #D1D5DB; border-radius: 8px;
                             font-size: 14px; min-height: 40px; padding: 0 16px; }
QPushButton#btn_secondary:hover { background: #F3F4F6; }
"""


class ContactDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Destek ve İletişim")
        self.setFixedSize(520, 480)
        self.setStyleSheet(_QSS)
        self._build_ui()

    # ── UI kurulumu ───────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Başlık
        header = QWidget()
        header.setStyleSheet("background: #FFFFFF;")
        h_lay = QVBoxLayout(header)
        h_lay.setContentsMargins(28, 24, 28, 8)
        title = QLabel("Destek ve İletişim")
        title.setObjectName("dlg_title")
        h_lay.addWidget(title)
        root.addWidget(header)

        sep = QFrame()
        sep.setObjectName("top_sep")
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        root.addWidget(sep)

        root.addWidget(self._make_contact_page(), 1)

    # ── İletişim ──────────────────────────────────────────────────────────────

    def _make_contact_page(self) -> QWidget:
        page = QWidget()
        page.setStyleSheet("background: #FFFFFF;")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(28, 20, 28, 24)
        lay.setSpacing(14)

        # Sistem bilgileri
        sys_lbl = QLabel("SİSTEM BİLGİLERİ")
        sys_lbl.setObjectName("section_lbl")
        lay.addWidget(sys_lbl)

        sys_box = QFrame()
        sys_box.setObjectName("sys_box")
        sys_v = QVBoxLayout(sys_box)
        sys_v.setContentsMargins(16, 12, 16, 12)
        sys_v.setSpacing(8)
        sys_v.addWidget(self._info_row("Versiyon", _APP_VERSION))
        sys_v.addWidget(self._info_row("Kurulum Tarihi", self._get_install_date()))
        sys_v.addWidget(self._info_row("Toplam Dosya", str(self._get_file_count())))
        lay.addWidget(sys_box)

        # Sorun bildir
        report_lbl = QLabel("SORUN BİLDİR")
        report_lbl.setObjectName("section_lbl")
        lay.addWidget(report_lbl)

        self._report_title = QLineEdit()
        self._report_title.setPlaceholderText("Sorun başlığı...")
        lay.addWidget(self._report_title)

        self._report_desc = QTextEdit()
        self._report_desc.setPlaceholderText("Sorunu açıklayın...")
        self._report_desc.setFixedHeight(100)
        lay.addWidget(self._report_desc)

        self._btn_copy_report = QPushButton("Mail Metnini Kopyala")
        self._btn_copy_report.setObjectName("btn_secondary")
        self._btn_copy_report.setCursor(Qt.PointingHandCursor)
        self._btn_copy_report.clicked.connect(self._on_copy_report)
        lay.addWidget(self._btn_copy_report)

        hint = QLabel("yunusemre.is@outlook.com adresine yapıştırın")
        hint.setStyleSheet("color: #9CA3AF; font-size: 12px; background: transparent;")
        lay.addWidget(hint)

        lay.addStretch()
        return page

    @staticmethod
    def _info_row(label: str, value: str) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        lbl = QLabel(label)
        lbl.setStyleSheet("color: #6B7280; font-size: 13px; background: transparent;")
        val = QLabel(value)
        val.setStyleSheet(
            "color: #111827; font-size: 13px; font-weight: 600; background: transparent;"
        )
        h.addWidget(lbl)
        h.addStretch()
        h.addWidget(val)
        return w

    @staticmethod
    def _get_install_date() -> str:
        try:
            row = DBManager().fetchone("SELECT MIN(timestamp) AS t FROM audit_log")
            if row and row["t"]:
                return row["t"][:10]
        except Exception:
            pass
        return "Bilinmiyor"

    @staticmethod
    def _get_file_count() -> int:
        try:
            row = DBManager().fetchone("SELECT COUNT(*) AS c FROM files")
            return row["c"] if row else 0
        except Exception:
            return 0

    def _on_copy_report(self) -> None:
        title = self._report_title.text().strip() or "(başlık yok)"
        desc  = self._report_desc.toPlainText().strip() or "(açıklama yok)"
        text = (
            f"Konu: HYCLEUS Sorun Bildirimi — {title}\n"
            f"Alıcı: yunusemre.is@outlook.com\n\n"
            f"Açıklama:\n{desc}\n\n"
            f"--- Sistem Bilgileri ---\n"
            f"Versiyon      : {_APP_VERSION}\n"
            f"Kurulum Tarihi: {self._get_install_date()}\n"
            f"Toplam Dosya  : {self._get_file_count()}\n"
        )
        QApplication.clipboard().setText(text)
        self._btn_copy_report.setText("✓ Kopyalandı")
        QTimer.singleShot(
            2000,
            lambda: self._btn_copy_report.setText("Mail Metnini Kopyala"),
        )
