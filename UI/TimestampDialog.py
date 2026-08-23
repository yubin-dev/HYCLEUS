"""
HYCLEUS — Zaman Damgası Doğrulama Diyaloğu (adım 3.1)

`verify_timestamp()` adım 3.1b'den beri komut satırından çalışıyordu.
Bu diyalog aynı fonksiyonu arayüze bağlıyor — İKİNCİ bir doğrulama
uygulaması DEĞİL, aynı fonksiyonun ikinci bir yüzü.

Doğrulamanın kendisi burada YOK: sonuç dışarıdan geliyor
(`TimestampVerification`), metne çevirme işi `CORE/timestamp_report.py`'de.
Bu diyalogda yalnızca yerleşim var. Bölünme kasıtlı — bir Qt penceresinin
içine gömülmüş karar mantığı test edilemez ve bu depoda "aynı iş için
ikinci bir uygulama" beş kez kusur ürettti.

Neden ayrı bir pencere, durum çubuğunda bir satır değil
--------------------------------------------------------
Sonuç tek satıra sığmıyor ve sığdırılmamalı. "Damga geçerli" cümlesinin
yanında her seferinde İKİ sınır duruyor:

  1. Damgayı atan kurumun kimliği, doğrulanan dosyanın kendi içinden
     geldi (`anchor_trusted`).
  2. Doğrulanan şey damganın kendisi; dosyanın içeriğinin damgalanan
     parmak iziyle eşleştiği bu kontrolde SORULMUYOR.

Bunları bir tooltip'e ya da bir bildirime sıkıştırmak, kullanıcının
görmeyeceği yere koymak demekti — ve "geçerli" kelimesinin tek başına
kalması, bu ekranın verebileceği en yanıltıcı çıktı.

Neden iş parçacığı yok
----------------------
ÖLÇÜLDÜ: gerçek bir freetsa.org damgasının doğrulanması **3,3 ms**
sürüyor ve süre dosya boyutundan BAĞIMSIZ — `read_trailer()` ile
`read_aad()` yalnızca `seek` yapıyor, dosya baştan sona okunmuyor. Ağ
erişimi de yok. Bir iş parçacığı burada ölçülebilir hiçbir şey
kazandırmaz, karşılığında iptal/yaşam süresi yönetimi getirirdi
(`_ScanWorker`'ın taşıdığı yük).

Neden artık `QDialog` DEĞİL (slide-over turu)
-----------------------------------------------
Tasarım brief'i: "doğrulama ve ayar ekranları slide-over panel olarak
açılır, yeni pencere açmaz." Bu ekran kendi `QDialog` penceresini
AÇMIYOR artık — `main_window_files.py::_on_ctx_verify_timestamp()`
kurup `HycleusWindow._open_slide_over()`'a veriyor
(`UI/main_window_layout.py`). `QWidget`'a düşmek `exec()`/`accept()`'i
KALDIRDI; "Kapat" düğmesi artık `kapat_istendi` sinyalini yayıyor,
paneli kapatan taraf (`_open_slide_over`) buna otomatik bağlanıyor.
`setWindowTitle()`/`windowTitle()` bilerek KORUNDU — QWidget'ta da
çalışıyor ve testler bunu okuyor; panel başlığı ayrıca dışarıdan
(`_open_slide_over(baslik, ...)`) veriliyor, ikisi farklı amaçlara hizmet
ediyor.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from CORE.timestamp_report import (
    SEVIYE_BILGI,
    SEVIYE_DAMGASIZ,
    SEVIYE_GECERLI,
    SEVIYE_GECERSIZ,
    SEVIYE_OKUNAMADI,
    SEVIYE_UYARI,
    Aciklama,
    aciklama,
    detaylar,
    notlar,
    zaman_metni,
)
from CORE.timestamp_verify import TimestampVerification
from UI.dialog_kit import (
    rapor_stili,
    varsayilan_gorunum,
    ayrac as _sep,
    kutu as _kutu,
    sarmali as _sarmali,
)
from UI.main_window_palette import _DARK


def _seviye_gorunum(T: dict[str, str]) -> dict[str, tuple[str, str]]:
    """Seviye → (simge, renk). Renk kararı burada, ANLAM kararı
    `CORE/timestamp_report.py`'de — biri arayüz tercihi, diğeri değil.

    `okunamadi` ile `uyari` AYNI tonu (`T['yellow']`) paylaşıyor: kayıtlı
    token sözlüğünde tek bir "sarı/turuncu" var (B-055) — ikisini ayıran
    ayrı bir token icat etmek yerine simge farkına (ikisi de "⚠") ve metne
    bırakıldı, `CORE/timestamp_report.py`'nin ANLAM ayrımı bozulmuyor.
    """
    return {
        SEVIYE_GECERLI:   ("✔", T["green"]),
        SEVIYE_GECERSIZ:  ("✖", T["red"]),
        SEVIYE_DAMGASIZ:  ("🕓", T["subtext"]),
        SEVIYE_OKUNAMADI: ("⚠", T["yellow"]),
        SEVIYE_UYARI:     ("⚠", T["yellow"]),
        SEVIYE_BILGI:     ("ℹ", T["accent"]),
    }

class TimestampDialog(QWidget):
    """Bir dosyanın zaman damgası doğrulama sonucunu gösterir."""

    #: "Kapat" düğmesine basıldı — paneli kapatan taraf buna bağlanır
    #: (bkz. `LayoutMixin._open_slide_over`). Eskiden `QDialog.accept()`.
    kapat_istendi = Signal()

    def __init__(
        self,
        sonuc: TimestampVerification,
        dosya_adi: str,
        parent=None,
        *,
        sade: bool = False,
        T: dict[str, str] | None = None,
    ) -> None:
        """
        Args:
            sade: `True` ise yalnızca SONUÇ gösteriliyor — simge, başlık,
                tek cümlelik özet ve (varsa) öneri. Özet alanları, notlar
                ve teknik blok GİZLENİYOR.

                Gizleniyor, SİLİNMİYOR: bütün alanlar kuruluyor ve
                `_gelismis` listesinde duruyor, yalnızca görünürlükleri
                kapalı. Böylece "Basit" bir metin SEVİYESİ değil, aynı
                içeriğin bir GÖRÜNÜMÜ — ikinci bir açıklama kümesi
                yazılsaydı ikisi zamanla ayrışırdı.

                Öneri sade modda da GÖSTERİLİYOR ve bu bilinçli: `oneri`
                bir ayrıntı değil, sonucun eyleme dönüşen yarısı
                ("bu dosyayı tarih kanıtı olarak KULLANMAYIN" gibi).
                Gizlemek, sade modu varsayılandan daha TEHLİKELİ yapardı.
            T: Çağıranın aktif tema token sözlüğü (`HycleusWindow._T`).
                Verilmezse varsayılan "mavi" koyu palete düşer — yalnızca
                testlerin/bağımsız çağrıların çökmemesi için, üretimde
                çağıran (`main_window_files.py`) her zaman kendi `self._T`'ını
                geçiriyor.
        """
        super().__init__(parent)
        self._sade = sade
        self._T: dict[str, str] = T if T is not None else _DARK
        self._gelismis: list[QWidget] = []
        self._sonuc = sonuc
        self._dosya_adi = dosya_adi
        self._mesaj: Aciklama = aciklama(sonuc)
        self._notlar: list[Aciklama] = notlar(sonuc)
        self._detaylar: list[tuple[str, str]] = detaylar(sonuc)

        self.setObjectName("rapor_disi_govde")
        self.setWindowTitle(f"HYCLEUS — Damga Doğrulama · {dosya_adi}")
        self.setMinimumWidth(520)
        self.setStyleSheet(rapor_stili(self._T))
        self._build_ui()

    # ── Kurulum ───────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        dis = QVBoxLayout(self)
        dis.setContentsMargins(0, 0, 0, 0)
        dis.setSpacing(0)

        # Kaydırma: teknik ayrıntılar açıldığında ya da uzun bir zincirde
        # içerik ekrandan taşabilir.
        kaydir = QScrollArea()
        kaydir.setWidgetResizable(True)
        govde = QWidget()
        govde.setObjectName("govde")
        kaydir.setWidget(govde)
        dis.addWidget(kaydir, 1)

        yerlesim = QVBoxLayout(govde)
        yerlesim.setContentsMargins(24, 20, 24, 16)
        yerlesim.setSpacing(10)

        yerlesim.addWidget(self._baslik_bloku())
        yerlesim.addWidget(_sarmali(self._mesaj.ozet, "ozet"))

        if self._mesaj.oneri:
            yerlesim.addWidget(_kutu([
                _sarmali(f"→  {self._mesaj.oneri}", "oneri"),
            ]))

        ozet_alanlari = self._ozet_alanlari()
        if ozet_alanlari:
            self._gelismis += [_sep(), _kutu(ozet_alanlari)]

        for mesaj in self._notlar:
            self._gelismis.append(self._not_bloku(mesaj))

        self._gelismis += [_sep(), self._teknik_bloku()]
        for parca in self._gelismis:
            yerlesim.addWidget(parca)
            if self._sade:
                parca.setHidden(True)
        yerlesim.addStretch(1)

        dis.addWidget(self._alt_cubuk())

    def _baslik_bloku(self) -> QWidget:
        simge_metni, renk = _seviye_gorunum(self._T).get(
            self._mesaj.seviye, varsayilan_gorunum(self._T)
        )
        sarici = QWidget()
        satir = QHBoxLayout(sarici)
        satir.setContentsMargins(0, 0, 0, 0)
        satir.setSpacing(12)

        simge = QLabel(simge_metni)
        simge.setObjectName("simge")
        simge.setStyleSheet(f"color:{renk};")
        simge.setAlignment(Qt.AlignTop)
        satir.addWidget(simge)

        sutun = QVBoxLayout()
        sutun.setSpacing(2)
        baslik = _sarmali(self._mesaj.baslik, "baslik")
        baslik.setStyleSheet(f"color:{renk};")
        sutun.addWidget(baslik)
        sutun.addWidget(_sarmali(self._dosya_adi, "dosya"))
        satir.addLayout(sutun, 1)
        return sarici

    def _ozet_alanlari(self) -> list[QWidget]:
        """Kullanıcının kararını değiştirebilecek alanlar — yalnızca üçü.

        Seri numarası ve politika kodu buraya GİRMİYOR: doğru bilgi ama
        kullanıcı için gürültü. Teknik ayrıntılarda tam listesi var.
        """
        if not self._sonuc.valid:
            return []
        satirlar: list[tuple[str, str]] = [
            ("Damga zamanı", zaman_metni(self._sonuc.gen_time)),
        ]
        if self._sonuc.tsa_name:
            satirlar.append(("Damgayı atan kurum", self._sonuc.tsa_name))
        if self._sonuc.tsa_url:
            satirlar.append(("Kurumun adresi", self._sonuc.tsa_url))

        cikti: list[QWidget] = []
        for ad, deger in satirlar:
            cikti.append(_sarmali(ad, "alan_ad"))
            cikti.append(_sarmali(deger, "alan_dgr"))
        return cikti

    def _not_bloku(self, mesaj: Aciklama) -> QWidget:
        simge_metni, renk = _seviye_gorunum(self._T).get(
            mesaj.seviye, varsayilan_gorunum(self._T)
        )
        icerik: list[QWidget] = []
        baslik = _sarmali(f"{simge_metni}  {mesaj.baslik}", "not_bas")
        baslik.setStyleSheet(f"color:{renk};")
        icerik.append(baslik)
        icerik.append(_sarmali(mesaj.ozet, "not_gov"))
        if mesaj.oneri:
            icerik.append(_sarmali(f"→  {mesaj.oneri}", "not_gov"))
        return _kutu(icerik)

    def _teknik_bloku(self) -> QWidget:
        """Kapalı başlayan teknik ayrıntılar.

        Silinmiyor, bir kat aşağı konuyor: kullanıcı yöneticisine ya da
        bir denetçiye durumu iletecekse tam olarak bu alanlar gerekiyor —
        CLI'ın bastığı bilginin aynısı.
        """
        sarici = QWidget()
        sutun = QVBoxLayout(sarici)
        sutun.setContentsMargins(0, 0, 0, 0)
        sutun.setSpacing(8)

        self._teknik_alan = QTextEdit()
        self._teknik_alan.setObjectName("teknik")
        self._teknik_alan.setReadOnly(True)
        self._teknik_alan.setPlainText(self.teknik_metin())
        self._teknik_alan.setFixedHeight(150)
        self._teknik_alan.setVisible(False)

        dugmeler = QHBoxLayout()
        dugmeler.setSpacing(8)
        self._ac_kapa = QPushButton("▸  Teknik ayrıntılar")
        self._ac_kapa.setObjectName("flat_btn")
        self._ac_kapa.clicked.connect(self._teknik_degistir)
        dugmeler.addWidget(self._ac_kapa)

        kopyala = QPushButton("⧉  Kopyala")
        kopyala.setObjectName("flat_btn")
        kopyala.clicked.connect(self._kopyala)
        dugmeler.addWidget(kopyala)
        dugmeler.addStretch(1)

        sutun.addLayout(dugmeler)
        sutun.addWidget(self._teknik_alan)
        return sarici

    def _alt_cubuk(self) -> QWidget:
        sarici = QWidget()
        satir = QHBoxLayout(sarici)
        satir.setContentsMargins(24, 8, 24, 16)
        satir.addStretch(1)
        kapat = QPushButton("Kapat")
        kapat.setObjectName("primary_btn")
        kapat.setDefault(True)
        kapat.clicked.connect(self.kapat_istendi.emit)
        satir.addWidget(kapat)
        return sarici

    # ── Davranış ──────────────────────────────────────────────────────────────

    def teknik_metin(self) -> str:
        """Panoya kopyalanabilir tam rapor.

        Dosya adı BAŞA yazılıyor: kullanıcı bunu yöneticisine yapıştırdığında
        hangi dosyadan söz edildiği metnin içinde durmalı.
        """
        satirlar = [f"HYCLEUS damga doğrulama — {self._dosya_adi}", ""]
        satirlar += [f"{ad}: {deger}" for ad, deger in self._detaylar]
        return "\n".join(satirlar)

    def _teknik_degistir(self) -> None:
        acik = not self._teknik_alan.isVisible()
        self._teknik_alan.setVisible(acik)
        self._ac_kapa.setText(
            ("▾  Teknik ayrıntılar" if acik else "▸  Teknik ayrıntılar")
        )
        self.adjustSize()

    def _kopyala(self) -> None:
        pano = QApplication.clipboard()
        if pano is not None:  # pragma: no branch — başsız ortamda None olabilir
            pano.setText(self.teknik_metin())


__all__ = ["TimestampDialog"]
