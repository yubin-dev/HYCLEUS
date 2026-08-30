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


Pano KALDIRILDI — neden (B-091)
--------------------------------
Bu pencere önceden içeriği panoya kopyalayan bir düğme taşıyordu:
kopyalamadan ÖNCE uyarı gösteriyor, kopyalanan içeriği otomatik bir
geri-sayımla siliyordu. O temizleme HİÇBİR ZAMAN bir garanti değildi — pano
geçmişi tutan araçlar (Windows Win+V, üçüncü taraf pano yöneticileri)
değeri ZATEN almış olur, HYCLEUS'un sonrasında yaptığı hiçbir şey oraya
ULAŞAMAZ. Ekran yakalamanın aksine (bu uygulamanın `WDA_EXCLUDEFROMCAPTURE`
ile GERÇEKTEN kapatabildiği bir şey), pano geçmişi HYCLEUS'un kontrolü
ALTINDA değil — engelleyecek hiçbir API yok, yalnızca "olmayacağını umarak"
kopyalamak var. "Bilerek yapılan bir riskin engellenmeye çalışılmasından
iyi olduğu" gerekçesi, riskin TAMAMEN uygulama dışı iki katmana (işletim
sistemi pano geçmişi, üçüncü taraf araçlar) bağlı olduğu bu durumda
YETERSİZ kaldı — düğmenin kendisi "bu güvenli bir yol" izlenimi veriyordu.

Bunun yerine ekranda gösterme + QR + YAZDIRMA üçü GÜÇLENDİRİLDİ: pay artık
uygulamanın hiç dokunmadığı, tamamen kullanıcının OS düzeyinde denetlediği
iki kanaldan biriyle (kâğıt, ya da ekranda okuyup elle yazmak) fiziksel
dünyaya çıkıyor — hiçbiri HYCLEUS'un kontrolü dışında bir ARA katman
(pano) açmıyor.


Yazdırma — GERÇEK bir yol, yalnızca bir etiket değil
------------------------------------------------------
Önceki sürümde onay kutusu "Bu parçayı yazdırdım..." diyordu ama pencerede
YAZDIRACAK bir düğme YOKTU — kullanıcı ya ekran görüntüsü almak (ki bu
tam olarak `WARNING_TEXT`'in yasakladığı şey ve ekran yakalama koruması
zaten ENGELLEMEYE çalışıyor) ya da elle base32 metnini yazıcıya göndermenin
başka bir yolunu bulmak zorundaydı. Bu tutarsızlık kapatıldı: `_on_yazdir()`
gerçek bir `QPrinter`/`QPrintDialog` akışı açıyor ve `_yazdirilabilir_belge()`
QR görselini (aynı `self._export.qr_svg` — İKİNCİ bir üretim yolu YOK,
yalnızca var olan SVG'yi rasterize ediyor) ve base32 metnini içeren bir
`QTextDocument` kâğıda basıyor. Paylaşılan/ağ yazıcılarının kendi
kuyruğunda/belleğinde kopya bırakabileceği YAZDIRMA_UYARISI ile ayrıca
söyleniyor — panonun "sessiz" riskinin aksine bu risk KULLANICIYA açıkça
yazılıyor, gizlenmiyor.


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

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from CORE.recovery_share import RecoveryExport
from UI.main_window_palette import _DARK

_log = logging.getLogger(__name__)

#: Onay kutusunun metni. Rehber ve testler buradan okuyor.
ONAY_METNI = "Bu parçayı yazdırdım ve güvenli bir yere koydum"

#: Yazdır düğmesinin yanında HER ZAMAN görünen uyarı — panonun "sessiz"
#: riskinin aksine bu risk gizlenmiyor, ama YAZDIRMAYI da engellemiyor
#: (bir onay kutusu değil, yalnızca bir etiket — B-003'ün dersi burada da
#: geçerli: yazdırmadan önce zorunlu bir diyalog, kullanıcıyı bilgilendirmek
#: yerine bir düğmeye basmaya iter).
YAZDIRMA_UYARISI = (
    "Ağ üzerinde ya da paylaşılan bir yazıcı kullanıyorsanız, kurtarma "
    "parçası yazıcının kendi kuyruğunda/belleğinde kopya bırakabilir. "
    "Mümkünse bilgisayara doğrudan (USB) bağlı bir yazıcı kullanın."
)

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
        T: Çağıranın aktif tema token sözlüğü (`HycleusWindow._T`).
            Verilmezse varsayılan "mavi" koyu palete düşer.
    """

    def __init__(self, disa_aktarim: RecoveryExport, parent: Any = None, *,
                 T: dict[str, str] | None = None) -> None:
        super().__init__(parent)
        self._export = disa_aktarim
        self._T: dict[str, str] = T if T is not None else _DARK

        self.setWindowTitle("HYCLEUS — Kurtarma Parçası")
        self.setModal(True)
        self.setMinimumWidth(760)
        # B-055: önceden tamamen sabit (Tailwind-benzeri açık renkler),
        # tema preset'i hiç etkilemiyordu. Yeni bir token İCAT EDİLMEDİ.
        self.setStyleSheet(
            f"QDialog {{ background: {self._T['bg']}; color: {self._T['text']}; }}"
            f"QLabel {{ color: {self._T['text']}; }}"
            f"QCheckBox {{ color: {self._T['text']}; }}"
        )

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
        yerlesim.addWidget(self._yazdir_satiri())
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
            f"color:{self._T['green']}; font-size:12px;" if self._koruma_var
            else f"color:{self._T['yellow']}; font-size:12px; font-weight:600;")
        return etiket

    def _uyari_bloku(self) -> QWidget:
        """`WARNING_TEXT` — komut satırıyla AYNI cümleler, yeniden yazılmıyor."""
        etiket = QLabel(self._export.warning)
        etiket.setObjectName("kurtarma_uyari")
        etiket.setWordWrap(True)
        etiket.setTextInteractionFlags(Qt.TextSelectableByMouse)
        etiket.setStyleSheet(
            f"background:{self._T['red_tint']}; color:{self._T['red']};"
            f"border:1px solid {self._T['red']};"
            f"border-radius:8px; padding:10px 12px; font-size:12px;")
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
                f"border:1px dashed {self._T['border']}; border-radius:8px;"
                f"color:{self._T['subtext']}; font-size:12px;")
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
            f"QPlainTextEdit{{background:{self._T['search_bg']};"
            f"color:{self._T['text']}; border:1px solid {self._T['border']};"
            f"border-radius:8px; padding:10px; font-family:Consolas,monospace;"
            f"font-size:14px; letter-spacing:1px;}}")
        lay.addWidget(self._metin)
        return kutu

    def _yazdir_satiri(self) -> QWidget:
        kutu = QWidget()
        lay = QVBoxLayout(kutu)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)

        dugme_satiri = QHBoxLayout()
        dugme_satiri.setSpacing(10)

        self._btn_yazdir = QPushButton("🖨  Yazdır")
        self._btn_yazdir.setObjectName("kurtarma_btn_yazdir")
        self._btn_yazdir.setCursor(Qt.PointingHandCursor)
        self._btn_yazdir.clicked.connect(self._on_yazdir)
        dugme_satiri.addWidget(self._btn_yazdir)

        self._yazdir_durum = QLabel("")
        self._yazdir_durum.setObjectName("kurtarma_yazdir_durum")
        self._yazdir_durum.setStyleSheet(f"color:{self._T['yellow']}; font-size:12px;")
        dugme_satiri.addWidget(self._yazdir_durum)
        dugme_satiri.addStretch()
        lay.addLayout(dugme_satiri)

        uyari = QLabel(YAZDIRMA_UYARISI)
        uyari.setObjectName("kurtarma_yazdir_uyarisi")
        uyari.setWordWrap(True)
        uyari.setStyleSheet(f"color:{self._T['subtext']}; font-size:11px;")
        lay.addWidget(uyari)

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

    def _yazdirilabilir_belge(self) -> Any:
        """
        Yazdırma için bir `QTextDocument` kurar — uyarı metni + QR görseli
        (varsa) + base32 gövdesi.

        `self._export.qr_svg`'in KENDİSİNİ rasterize ediyor — İKİNCİ bir QR
        üretim yolu AÇMIYOR (`render_qr_svg`/`encode_share`/`build_export`
        burada da çağrılmıyor; bkz. modül docstring'indeki "TEK YOL" kuralı
        ve `tests/test_recovery_share_ui.py::test_modal_QR_uretmiyor_
        GOSTERIYOR`'un AST denetimi).
        """
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QImage, QPainter, QTextDocument

        belge = QTextDocument()
        parcalar = [
            "<h2>HYCLEUS — Kurtarma Parçası</h2>",
            "<pre style='white-space:pre-wrap; font-family:sans-serif; "
            f"font-size:11pt;'>{self._export.warning}</pre>",
        ]

        if self._export.qr_svg:
            from PySide6.QtSvg import QSvgRenderer

            olcek = 300
            gorsel = QImage(olcek, olcek, QImage.Format_ARGB32)
            gorsel.fill(0xFFFFFFFF)
            ressam = QPainter(gorsel)
            QSvgRenderer(QByteArray(self._export.qr_svg.encode("utf-8"))).render(ressam)
            ressam.end()
            belge.addResource(
                QTextDocument.ImageResource, QUrl("kurtarma://qr"), gorsel
            )
            parcalar.append(
                f'<p align="center"><img src="kurtarma://qr" '
                f'width="{olcek}" height="{olcek}"></p>'
            )

        parcalar.append(
            "<pre style='font-family:Consolas,monospace; font-size:13pt; "
            f"letter-spacing:2px;'>{self._export.base32_text}</pre>"
        )
        belge.setHtml("".join(parcalar))
        return belge

    def _on_yazdir(self) -> None:
        """
        Yazıcı seçim diyaloğunu açar; kullanıcı onaylarsa belgeyi basar.

        Onay diyaloğu ZATEN `QPrintDialog`'un kendisi — panonun tersine,
        yazdırmak KULLANICININ bilinçli bir eylemi (bir yazıcı seçmesi
        gerekiyor), ayrıca bir "emin misiniz" katmanı EKLEMİYORUZ (B-003'ün
        aynı dersi: gereksiz bir onay katmanı bilgilendirmiyor, yalnızca
        bir tıklamaya zorluyor).
        """
        from PySide6.QtPrintSupport import QPrinter, QPrintDialog

        yazici = QPrinter(QPrinter.HighResolution)
        dialog = QPrintDialog(yazici, self)
        if dialog.exec() != QDialog.Accepted:
            self._yazdir_durum.setText("Yazdırma iptal edildi.")
            return

        self._yazdirilabilir_belge().print_(yazici)
        self._yazdir_durum.setText("Yazdırma isteği gönderildi.")
