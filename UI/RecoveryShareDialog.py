"""
HYCLEUS — Kurtarma parçası dışa aktarım modalı

Bu pencere, sistemin gösterdiği EN TEHLİKELİ ekrandır: içeriği, kalan tek
payla birlikte kasadaki her dosyanın anahtarını verir. Tasarımın tamamı bu
tek cümleden türüyor.

Üretim: TEK YOL
---------------
Ne QR ne base32 burada üretiliyor. İkisi de `CORE/recovery_share.py`'nin
`build_export()` çıktısından geliyor ve bu pencere onları yalnızca
GÖSTERİYOR. İkinci bir üretim yolu (örneğin arayüzün kendi QR'ını çizmesi)
iki biçimin ayrışmasına açık kapı bırakırdı: kullanıcı QR'ı basar, base32'yi
okur ve ikisi farklı payı taşır. Bir AST denetimi
(`tests/test_recovery_share_ui.py`) bu pencerenin `qrcode`'u kendi başına
çağırmadığını doğruluyor.

Uyarı metni de üretilmiyor: `RecoveryExport.warning` (yani
`recovery_share.WARNING_TEXT`) gösteriliyor. Komut satırı ve arayüz AYNI
cümleleri söylüyor.


Onay kutusu — neden KAPATMA ENGELİ DEĞİL
-----------------------------------------
"Tamam" düğmesi, onay kutusu işaretlenene kadar pasif. Ama pencere Esc ile
ya da başlık çubuğundan HER ZAMAN kapanabiliyor.

Ayrım bilinçli. B-003'te zorunlu diyalog denenmişti ve oradan çıkan ders
şuydu: kullanıcıyı bir pencerede HAPSETMEK, onu bilgilendirmiyor —
yalnızca rastgele bir düğmeye basmaya itiyor. Burada engellenmesi gereken
şey "kazayla Tamam'a basıp parçayı bir daha görememek"; kullanıcının
pencereyi bilerek kapatması ise meşru bir karar (ör. yazıcıyı hazırlamaya
gitmek).

Kapatma yolu açık olduğu için onay kutusu bir GÜVENLİK KONTROLÜ değil, bir
DİKKAT kontrolü. Docstring bunu açıkça söylüyor ki biri onu güvenlik
garantisi sanıp üstüne bir şey inşa etmesin.


Pano — buton var, otomatik değil
---------------------------------
Panoya kopyalama, bu parçayı DİJİTAL ortama taşımanın ta kendisi ve
`WARNING_TEXT` bunu yapmamayı söylüyor. Yine de düğme var: kullanıcı
parçayı bir yazıcı kuyruğuna ya da parola yöneticisine elle yazmak yerine
kopyalayacaksa, bunu bilerek yapması, uygulamanın onu engellemeye
çalışmasından iyi (engellenen kullanıcı ekran görüntüsü alır — daha kötü).

Bu yüzden: tıklandığında ÖNCE uyarı, sonra kopyalama. Ve kopyalanan içerik
`PANO_TEMIZLEME_SN` saniye sonra otomatik siliniyor.

Otomatik temizlemenin DÜRÜST sınırı:
  · Pano geçmişi tutan araçlar (Windows Win+V, pano yöneticileri) kopyayı
    zaten almış olur; oradan silemeyiz.
  · Başka bir uygulama arada panoyu okuduysa iş işten geçmiştir.
  · Kullanıcı bu sürede başka bir şey kopyalarsa panoyu TEMİZLEMİYORUZ —
    onun verisini silmek bizim işimiz değil.
Yani temizleme bir garanti değil, maruz kalma penceresini daraltan bir
önlem. Etiket kullanıcıya bunu söylüyor.


Ekran yakalama
--------------
Qt'nin platformdan bağımsız bir "beni yakalama" API'si YOK. Windows'ta
`SetWindowDisplayAffinity` var ve kullanılıyor; diğer platformlarda
karşılığı yok.

Sonuç kullanıcıya GÖRÜNÜR biçimde yazılıyor. Sessizce denemek, B-025'in
tam olarak uyardığı şey olurdu: kapalı bir koruma, hiç olmayan bir
korumadan kötü — çünkü belge onun varlığını iddia ediyor gibi okunur.
Windows dışı platformlardaki boşluk B-049 olarak kayıtlı.
"""
from __future__ import annotations

import logging
import sys
from typing import Any

from PySide6.QtCore import QByteArray, Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from CORE.recovery_share import RecoveryExport

_log = logging.getLogger(__name__)

#: Onay kutusunun metni. Rehber ve testler buradan okuyor.
ONAY_METNI = "Bu parçayı yazdırdım ve güvenli bir yere koydum"

#: Panoya kopyalamadan ÖNCE gösterilen uyarı.
PANO_UYARISI = (
    "Pano, bilgisayarınızdaki diğer uygulamalar tarafından okunabilir ve "
    "şifrelenmez.\n\n"
    "Panoya geçmiş tutan araçlar (Windows'ta Win+V) kopyayı kalıcı olarak "
    "saklayabilir — bu durumda otomatik temizleme onu geri alamaz.\n\n"
    "Kopyaladıktan sonra panoyu temizleyin. HYCLEUS bunu {sn} saniye sonra "
    "kendisi de deneyecek."
)

#: Kopyalanan içerik kaç saniye sonra panodan silinmeye çalışılır.
PANO_TEMIZLEME_SN = 30

#: Ekran yakalama koruması durum metinleri — tek yerde.
KORUMA_ETKIN = "🛡  Ekran yakalama engellendi (bu pencere görüntüde çıkmaz)."
KORUMA_YOK = (
    "⚠  Ekran yakalama ENGELLENEMEDİ — bu pencere ekran görüntüsüne ve "
    "ekran kaydına düşebilir. {neden}"
)

#: Windows `SetWindowDisplayAffinity` bayrakları.
_WDA_NONE = 0x00000000
_WDA_MONITOR = 0x00000001            # yakalamada SİYAH çıkar (Win7+)
_WDA_EXCLUDEFROMCAPTURE = 0x00000011  # yakalamada HİÇ çıkmaz (Win10 2004+)


def ekran_yakalamayi_engelle(pencere: QWidget) -> tuple[bool, str]:
    """
    Pencereyi ekran yakalamanın dışında bırakmayı DENER.

    Tek karar noktası: koruma isteyen her yer buradan geçmeli, yoksa biri
    bayrağı unutur ve fark edilmez.

    Returns:
        `(başarılı, açıklama)`. Başarısızlık ölümcül DEĞİL — çağıran taraf
        sonucu kullanıcıya yazıyor.
    """
    if sys.platform != "win32":
        return False, f"Bu özellik yalnızca Windows'ta var (platform: {sys.platform})."

    try:
        import ctypes

        hwnd = int(pencere.winId())
        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        # Önce en güçlü kip. Win10 2004 öncesinde başarısız oluyor; o zaman
        # WDA_MONITOR'a düşülüyor — yakalamada pencere SİYAH çıkar, yani
        # içerik yine korunur ama kullanıcı "bir şey vardı" görür.
        for bayrak in (_WDA_EXCLUDEFROMCAPTURE, _WDA_MONITOR):
            if user32.SetWindowDisplayAffinity(hwnd, bayrak):
                return True, ""
        kod = ctypes.get_last_error() if hasattr(ctypes, "get_last_error") else 0
        return False, f"Windows koruma isteğini reddetti (kod {kod})."
    except Exception as exc:  # noqa: BLE001 — ctypes çeşitli tip atıyor
        return False, f"Koruma kurulamadı: {type(exc).__name__}."


class RecoveryShareDialog(QDialog):
    """
    Kurtarma parçasını bir kez gösterir — QR + base32 yan yana.

    Args:
        disa_aktarim: `CORE.recovery_share.build_export()` çıktısı. Bu
            pencere onu ÜRETMİYOR, yalnızca gösteriyor.
        parent: üst pencere.
        pano_saniye: otomatik pano temizleme süresi. Testler için
            kısaltılabilir; varsayılanı değiştirmek için buraya değil
            `PANO_TEMIZLEME_SN`'e dokunun.
    """

    def __init__(self, disa_aktarim: RecoveryExport, parent: Any = None, *,
                 pano_saniye: int = PANO_TEMIZLEME_SN) -> None:
        super().__init__(parent)
        self._export = disa_aktarim
        self._pano_saniye = pano_saniye
        self._kalan = 0
        self._pano_zamanlayici: QTimer | None = None

        self.setWindowTitle("HYCLEUS — Kurtarma Parçası")
        self.setModal(True)
        self.setMinimumWidth(760)

        # Koruma, pencere GÖSTERİLMEDEN kuruluyor: `winId()` burada
        # yerli pencereyi zorluyor ve bayrak ilk boyamadan önce yerleşiyor.
        self._koruma_var, self._koruma_neden = ekran_yakalamayi_engelle(self)

        self._kur()

    # ── Kurulum ──────────────────────────────────────────────────────────

    def _kur(self) -> None:
        yerlesim = QVBoxLayout(self)
        yerlesim.setContentsMargins(20, 18, 20, 18)
        yerlesim.setSpacing(12)

        yerlesim.addWidget(self._koruma_satiri())
        yerlesim.addWidget(self._uyari_bloku())
        yerlesim.addLayout(self._govde())
        yerlesim.addWidget(self._pano_satiri())
        yerlesim.addWidget(self._onay_satiri())
        yerlesim.addLayout(self._dugmeler())

    def _koruma_satiri(self) -> QLabel:
        """
        Ekran koruması durumu — HER İKİ DURUMDA da yazılıyor.

        Yalnızca sorun varken yazmak, "yazmıyorsa her şey yolunda" diye
        okunur ve o çıkarım sessiz bir düşüşte yanlış olur (B-025).
        """
        etiket = QLabel(
            KORUMA_ETKIN if self._koruma_var
            else KORUMA_YOK.format(neden=self._koruma_neden))
        etiket.setObjectName("kurtarma_koruma_durumu")
        etiket.setWordWrap(True)
        etiket.setStyleSheet(
            "color:#166534; font-size:12px;" if self._koruma_var
            else "color:#B45309; font-size:12px; font-weight:600;")
        return etiket

    def _uyari_bloku(self) -> QWidget:
        """`WARNING_TEXT` — komut satırıyla AYNI cümleler, yeniden yazılmıyor."""
        etiket = QLabel(self._export.warning)
        etiket.setObjectName("kurtarma_uyari")
        etiket.setWordWrap(True)
        etiket.setTextInteractionFlags(Qt.TextSelectableByMouse)
        etiket.setStyleSheet(
            "background:#FEF2F2; color:#7F1D1D; border:1px solid #FCA5A5;"
            "border-radius:8px; padding:10px 12px; font-size:12px;")
        return etiket

    def _govde(self) -> QHBoxLayout:
        satir = QHBoxLayout()
        satir.setSpacing(16)
        satir.addWidget(self._qr_bloku(), 0)
        satir.addWidget(self._base32_bloku(), 1)
        return satir

    def _qr_bloku(self) -> QWidget:
        kutu = QWidget()
        lay = QVBoxLayout(kutu)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        baslik = QLabel("QR — yazdırmak için")
        baslik.setStyleSheet("font-size:12px; font-weight:600;")
        lay.addWidget(baslik)

        if self._export.qr_svg:
            from PySide6.QtSvgWidgets import QSvgWidget

            gorsel = QSvgWidget()
            gorsel.load(QByteArray(self._export.qr_svg.encode("utf-8")))
            gorsel.setFixedSize(260, 260)
            gorsel.setObjectName("kurtarma_qr")
            lay.addWidget(gorsel)
        else:
            # QR üretilemedi (qrcode paketi yok). SESSİZ GEÇMİYOR: base32
            # tek başına yeterli ama kullanıcı eksik olanı bilmeli, yoksa
            # "QR nerede" sorusunu bir hata sanır.
            yok = QLabel(
                "QR üretilemedi (qrcode paketi yok).\n"
                "Yandaki metin tek başına yeterlidir.")
            yok.setObjectName("kurtarma_qr_yok")
            yok.setWordWrap(True)
            yok.setAlignment(Qt.AlignCenter)
            yok.setFixedSize(260, 260)
            yok.setStyleSheet(
                "border:1px dashed #9CA3AF; border-radius:8px; color:#6B7280;"
                "font-size:12px;")
            lay.addWidget(yok)

        lay.addStretch()
        return kutu

    def _base32_bloku(self) -> QWidget:
        kutu = QWidget()
        lay = QVBoxLayout(kutu)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        baslik = QLabel("Metin — elle yazmak için")
        baslik.setStyleSheet("font-size:12px; font-weight:600;")
        lay.addWidget(baslik)

        self._metin = QPlainTextEdit(self._export.base32_text)
        self._metin.setObjectName("kurtarma_base32")
        self._metin.setReadOnly(True)
        self._metin.setFixedHeight(260)
        self._metin.setStyleSheet(
            "QPlainTextEdit{background:#F9FAFB; border:1px solid #D1D5DB;"
            "border-radius:8px; padding:10px; font-family:Consolas,monospace;"
            "font-size:14px; letter-spacing:1px;}")
        lay.addWidget(self._metin)
        return kutu

    def _pano_satiri(self) -> QWidget:
        kutu = QWidget()
        lay = QHBoxLayout(kutu)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)

        self._btn_pano = QPushButton("📋  Panoya Kopyala")
        self._btn_pano.setObjectName("kurtarma_btn_pano")
        self._btn_pano.setCursor(Qt.PointingHandCursor)
        self._btn_pano.clicked.connect(self._on_panoya_kopyala)
        lay.addWidget(self._btn_pano)

        self._pano_durum = QLabel("")
        self._pano_durum.setObjectName("kurtarma_pano_durum")
        self._pano_durum.setStyleSheet("color:#B45309; font-size:12px;")
        lay.addWidget(self._pano_durum)
        lay.addStretch()
        return kutu

    def _onay_satiri(self) -> QCheckBox:
        self._onay = QCheckBox(ONAY_METNI)
        self._onay.setObjectName("kurtarma_onay")
        self._onay.setStyleSheet("font-size:13px;")
        self._onay.toggled.connect(self._on_onay_degisti)
        return self._onay

    def _dugmeler(self) -> QHBoxLayout:
        satir = QHBoxLayout()
        satir.addStretch()

        self._btn_tamam = QPushButton("Tamam")
        self._btn_tamam.setObjectName("kurtarma_btn_tamam")
        self._btn_tamam.setCursor(Qt.PointingHandCursor)
        # Başlangıçta PASİF — onay kutusu işaretlenmeden basılamaz.
        self._btn_tamam.setEnabled(False)
        self._btn_tamam.setDefault(True)
        self._btn_tamam.clicked.connect(self.accept)
        satir.addWidget(self._btn_tamam)
        return satir

    # ── Davranış ─────────────────────────────────────────────────────────

    def _on_onay_degisti(self, isaretli: bool) -> None:
        self._btn_tamam.setEnabled(isaretli)

    def _on_panoya_kopyala(self) -> None:
        """
        ÖNCE uyarı, sonra kopyalama.

        Kullanıcı vazgeçerse pano hiç yazılmıyor — uyarıyı kopyaladıktan
        sonra göstermek, uyarıyı bilgilendirme olmaktan çıkarıp bildirime
        çevirirdi.
        """
        yanit = QMessageBox.warning(
            self, "Panoya kopyalanacak",
            PANO_UYARISI.format(sn=self._pano_saniye),
            QMessageBox.Ok | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if yanit != QMessageBox.Ok:
            return

        from PySide6.QtGui import QGuiApplication

        pano = QGuiApplication.clipboard()
        if pano is None:  # pragma: no cover — başsız ortamda olabilir
            self._pano_durum.setText("Pano kullanılamıyor.")
            return
        pano.setText(self._export.base32_text)
        self._pano_geri_sayimi_baslat()

    def _pano_geri_sayimi_baslat(self) -> None:
        self._kalan = self._pano_saniye
        self._pano_durum_yaz()
        if self._pano_zamanlayici is None:
            self._pano_zamanlayici = QTimer(self)
            self._pano_zamanlayici.setInterval(1000)
            self._pano_zamanlayici.timeout.connect(self._pano_tik)
        self._pano_zamanlayici.start()

    def _pano_durum_yaz(self) -> None:
        self._pano_durum.setText(
            f"Kopyalandı — pano {self._kalan} sn sonra (ya da bu pencere "
            "kapanınca) temizlenecek.")

    def _pano_tik(self) -> None:
        self._kalan -= 1
        if self._kalan > 0:
            self._pano_durum_yaz()
            return
        self._panoyu_temizle()

    def _panoyu_temizle(self) -> None:
        """
        Panoyu YALNIZCA hâlâ bizim metnimizi tutuyorsa temizler.

        Kullanıcı bu arada başka bir şey kopyaladıysa onun verisini silmek
        bizim işimiz değil — ve sildiğimizde bunu fark etmez, veri kaybı
        gibi görünür.
        """
        if self._pano_zamanlayici is not None:
            self._pano_zamanlayici.stop()
        from PySide6.QtGui import QGuiApplication

        pano = QGuiApplication.clipboard()
        if pano is None:  # pragma: no cover
            return
        if pano.text() == self._export.base32_text:
            pano.clear()
            self._pano_durum.setText("Pano temizlendi.")
        else:
            self._pano_durum.setText(
                "Pano temizlenmedi — içinde artık başka bir şey var.")

    def closeEvent(self, event: Any) -> None:  # noqa: N802 — Qt adı
        """
        Kapanışta bekleyen pano temizliği hemen yapılıyor.

        Yapılmasaydı zamanlayıcı pencereyle birlikte ölür ve söz verilen
        temizlik SESSİZCE gerçekleşmezdi.
        """
        if self._pano_zamanlayici is not None and self._pano_zamanlayici.isActive():
            self._panoyu_temizle()
        super().closeEvent(event)

    def done(self, sonuc: int) -> None:  # noqa: D102 — Qt adı
        # `accept()`/`reject()` closeEvent'i her yolda tetiklemiyor;
        # temizlik burada da çağrılıyor ki Esc ve Tamam aynı davransın.
        if self._pano_zamanlayici is not None and self._pano_zamanlayici.isActive():
            self._panoyu_temizle()
        super().done(sonuc)
