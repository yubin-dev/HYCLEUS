"""
HYCLEUS — Güvenlik görünümü: üç doğrulama tek yerde

Kapattığı boşluk
----------------
Üç doğrulama vardı ve üçü de FARKLI bir yerde saklıydı:

    🕓 Damgayı Doğrula   dosya sağ tık menüsünde
    🔍 Yedek Doğrula     hamburger menüsünde
    🔗 Zinciri Doğrula   Yönetim Paneli'nde (yalnızca yönetici)

Bir denetçinin "bu kurulumu doğrula" işi üç ayrı menüyü bilmeyi
gerektiriyordu. Bu görünüm onları tek sayfada topluyor.


Eski giriş noktaları KALDIRILMADI
----------------------------------
Bilinçli. Sağ tık menüsündeki damga doğrulama, seçili dosya üzerinde
çalıştığı için oradaki bağlam bu sayfada yok; hamburger menüsündeki yedek
doğrulama da yerinde duruyor. Yani her iş artık İKİ giriş noktasına sahip.

Kural: **iki çağıran, tek gövde.** Bu sayfa hiçbir doğrulamayı kendisi
UYGULAMIYOR — ana pencerenin mevcut metotlarını çağırıyor:

    damga  → `HycleusWindow._on_ctx_verify_timestamp()`
    yedek  → `HycleusWindow._on_verify_backup()`
    zincir → `UI/security_actions.zinciri_dogrula()`

Üçüncüsü Yönetim Paneli'nden çıkarıldı çünkü panel yalnızca yöneticiye
açılıyor; gövdesi ortak bir yere taşındı ve panel de artık oradan
çağırıyor.

İkinci bir uygulama yazmak, bu deponun beş kez ürettiği kusurun altıncısı
olurdu (B-004/B-008, B-007, B-010, B-011, pay ayrıştırıcı).


Basit / Gelişmiş
----------------
Gelişmiş = diyalogların BUGÜNKÜ hâli. Yeni bir metin seviyesi
üretilmedi: sade mod aynı diyaloğun ayrıntı bloklarını GİZLİYOR
(`sade=True`), ikinci bir açıklama kümesi yazmıyor. İki metin kümesi
zamanla ayrışırdı ve hangisinin doğru olduğu belirsizleşirdi.

Tercih OTURUM İÇİ tutuluyor, kalıcı ayara YAZILMIYOR. Gerekçe: `settings`
tablosu kurulum geneli, kullanıcı başına değil. Kalıcı yazılsaydı bir
kullanıcının görünüm tercihi DİĞER kullanıcıların gördüğünü değiştirirdi
— bir tercih değil, bir hata olurdu. Kullanıcı başına ayar altyapısı yok
ve kozmetik bir anahtar için onu kurmak orantısız (bkz. B-045).

Eski giriş noktaları bu anahtardan ETKİLENMİYOR: sağ tık menüsü ve
hamburger menüsü bugünkü (gelişmiş) çıktısını vermeye devam ediyor.
Anahtar bu sayfanın görünüm tercihi; mevcut akışların davranışını
değiştirmek, "kaldırma" talimatının ruhuna aykırı olurdu.


Salt okunur rol — B-034
------------------------
Bu sayfa şu an salt okunur rolde GİZLİ ve bu, mevcut kısıtlamayla
tutarlılık için seçildi, bir karar olarak değil. B-034 "salt okunur rol
damgayı doğrulayamıyor" maddesini açık tutuyor ve önerdiği "daha ucuz
alternatif" tam olarak bu sayfa. Kararı kullanıcıya bırakıldı; ayrıntı
raporda ve `GUVENLIK_SALT_OKUNURA_ACIK` sabitinin yanında.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

_log = logging.getLogger("hycleus.guvenlik_view")

#: Güvenlik sayfası salt okunur role açık mı.
#:
#: `False` — MEVCUT kısıtlamayla tutarlı. Salt okunur rol bugün dosya sağ
#: tık menüsünü hiç açamıyor (`UI/main_window_files.py`) ve Yönetim
#: Paneli'ne giremiyor, yani hiçbir doğrulamaya erişemiyor. B-034 bunu bir
#: YETKİ KAYBI olarak kaydediyor: doğrulama saf bir okuma ve salt okunur
#: rol tipik olarak denetçiye veriliyor — doğrulamanın birincil kitlesi.
#:
#: B-034'ün bu turda düzeltilmemesinin sebebi ORTADAN KALKTI: oradaki
#: itiraz, sağ tık menüsünü açmanın yıkıcı maddeleri (İndir, İmha, Taşı)
#: sızdırma riskiydi. Bu sayfada yıkıcı madde YOK — üçü de okuma.
#:
#: Yine de `True` yapılmadı: karar kullanıcıya bırakıldı. Değiştirmek tek
#: satır ve `tests/test_guvenlik_view.py` mevcut davranışı sabitliyor.
GUVENLIK_SALT_OKUNURA_ACIK = False

#: Sayfa başlığı — kenar çubuğu düğmesi ve üst bar aynı metni kullanıyor.
SAYFA_ADI = "Güvenlik"


class GuvenlikView(QWidget):
    """Üç doğrulamanın toplandığı üst seviye görünüm."""

    def __init__(self, pencere: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._pencere = pencere
        #: Görünüm tercihi — OTURUM İÇİ. Gerekçe modül başlığında.
        self._gelismis = True
        self.setObjectName("guvenlik_view")
        self._build_ui()

    # ── Kurulum ──────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(14)

        baslik = QLabel("Güvenlik Doğrulamaları")
        baslik.setObjectName("guvenlik_baslik")
        baslik.setStyleSheet("font-size:15px; font-weight:bold;")
        lay.addWidget(baslik)

        aciklama = QLabel(
            "Bu üç kontrol hiçbir dosyayı değiştirmiyor; üçü de tek ekranda, "
            "ayrı pencere açmadan doğrulanır ve sonucu denetim kaydına yazar."
        )
        aciklama.setWordWrap(True)
        aciklama.setObjectName("guvenlik_aciklama")
        lay.addWidget(aciklama)

        lay.addWidget(self._mod_secici())
        lay.addWidget(self._ayrac())

        for kart in self._kartlar():
            lay.addWidget(kart)
        lay.addStretch(1)

    def _ayrac(self) -> QFrame:
        cizgi = QFrame()
        cizgi.setFrameShape(QFrame.HLine)
        cizgi.setFixedHeight(1)
        cizgi.setObjectName("guvenlik_ayrac")
        return cizgi

    def _mod_secici(self) -> QWidget:
        sarici = QWidget()
        satir = QHBoxLayout(sarici)
        satir.setContentsMargins(0, 0, 0, 0)
        satir.setSpacing(10)

        self._mod_kutusu = QCheckBox("Gelişmiş ayrıntı")
        self._mod_kutusu.setChecked(self._gelismis)
        self._mod_kutusu.setCursor(Qt.PointingHandCursor)
        self._mod_kutusu.setToolTip(
            "Açık: teknik ayrıntılar, notlar ve kapsam alanları gösterilir.\n"
            "Kapalı: yalnızca sonuç ve tek cümlelik açıklama."
        )
        self._mod_kutusu.toggled.connect(self._mod_degisti)
        satir.addWidget(self._mod_kutusu)

        self._mod_ipucu = QLabel()
        self._mod_ipucu.setObjectName("guvenlik_mod_ipucu")
        satir.addWidget(self._mod_ipucu)
        satir.addStretch(1)
        self._mod_ipucunu_guncelle()
        return sarici

    #: `(simge, başlık, açıklama, düğme metni, işleyici adı)`
    _KARTLAR = (
        ("🕓", "Damgayı Doğrula",
         "Bir `.hcl` dosyasının zaman damgasını çevrimdışı doğrular. "
         "Anahtar gerekmiyor.", "Dosya Seç…", "_damga_dogrula"),
        ("🔍", "Yedek Doğrula",
         "Bir yedek dizinindeki dosyaların eksiksiz ve bozulmamış "
         "olduğunu kontrol eder.", "Dizin Seç…", "_yedek_dogrula"),
        ("🔗", "Denetim Zincirini Doğrula",
         "Denetim kaydının hash zincirini ve dış çıpayı karşılaştırır.",
         "Doğrula", "_zincir_dogrula"),
    )

    def _kartlar(self) -> list[QWidget]:
        return [self._kart(*veri) for veri in self._KARTLAR]

    def _kart(self, simge: str, ad: str, aciklama: str,
              dugme: str, islem: str) -> QWidget:
        cerceve = QFrame()
        cerceve.setObjectName("guvenlik_kart")
        cerceve.setProperty("kart_adi", ad)
        satir = QHBoxLayout(cerceve)
        satir.setContentsMargins(14, 12, 14, 12)
        satir.setSpacing(14)

        etiket_simge = QLabel(simge)
        etiket_simge.setStyleSheet("font-size:20px;")
        etiket_simge.setAlignment(Qt.AlignTop)
        satir.addWidget(etiket_simge)

        sutun = QVBoxLayout()
        sutun.setSpacing(2)
        etiket_ad = QLabel(ad)
        etiket_ad.setStyleSheet("font-weight:600;")
        sutun.addWidget(etiket_ad)
        etiket_aciklama = QLabel(aciklama)
        etiket_aciklama.setWordWrap(True)
        etiket_aciklama.setObjectName("guvenlik_kart_aciklama")
        sutun.addWidget(etiket_aciklama)
        satir.addLayout(sutun, 1)

        btn = QPushButton(dugme)
        btn.setObjectName(f"guvenlik_btn_{islem.strip('_')}")
        btn.setCursor(Qt.PointingHandCursor)
        btn.setFixedWidth(130)
        btn.clicked.connect(getattr(self, islem))
        satir.addWidget(btn, 0, Qt.AlignTop)
        return cerceve

    # ── Davranış ─────────────────────────────────────────────────────────────

    def _mod_degisti(self, acik: bool) -> None:
        self._gelismis = acik
        self._mod_ipucunu_guncelle()
        _log.debug("guvenlik_mod  gelismis=%s", acik)

    def _mod_ipucunu_guncelle(self) -> None:
        self._mod_ipucu.setText(
            "— teknik ayrıntılar açık" if self._gelismis
            else "— yalnızca sonuç"
        )

    @property
    def sade(self) -> bool:
        """Diyaloglara geçirilen bayrak. `Gelişmiş` işaretliyse `False`."""
        return not self._gelismis

    # ── Üç doğrulama — GÖVDE BURADA DEĞİL ────────────────────────────────────

    def _damga_dogrula(self) -> None:
        """
        Dosya seçtirip ana pencerenin MEVCUT doğrulama akışını çağırır.

        Sağ tık menüsü aynı metodu satırdaki `file_id` ile çağırıyor.
        Burada satır yok, o yüzden dosya yolundan aranıyor: denetim
        kaydının `target_id` alanı iki yolda da dolsun diye. Bulunamazsa
        `None` geçiliyor — doğrulama yine çalışıyor, yalnızca kayıt
        dosyaya bağlanamıyor.
        """
        yol, _ = QFileDialog.getOpenFileName(
            self, "Damgası doğrulanacak dosya", str(self._baslangic_dizini()),
            "HYCLEUS dosyası (*.hcl);;Tüm dosyalar (*)")
        if not yol:
            return
        self._pencere._on_ctx_verify_timestamp(
            self._dosya_id(yol), yol, sade=self.sade)

    def _yedek_dogrula(self) -> None:
        """Ana pencerenin mevcut yedek doğrulama akışı — dizin seçimi onda."""
        self._pencere._on_verify_backup(sade=self.sade)

    def _zincir_dogrula(self) -> None:
        from UI.security_actions import zinciri_dogrula

        zinciri_dogrula(self, self._pencere._hwid, sade=self.sade)

    # ── Yardımcılar ──────────────────────────────────────────────────────────

    def _baslangic_dizini(self) -> Path:
        try:
            from CORE.paths import data_dir
            return data_dir() / "quarantine"
        except Exception:  # pragma: no cover — yol okunamazsa ev dizini
            return Path.home()

    def _dosya_id(self, yol: str) -> int | None:
        """Dosya yolundan `files.id` — bulunamazsa `None`."""
        try:
            from DB.db_manager import DBManager
            satir = DBManager().fetchone(
                "SELECT id FROM files WHERE filepath = ?", (yol,))
        except Exception as exc:  # pragma: no cover — kayıt aramasi engellemez
            _log.debug("dosya_id_bulunamadi  exc=%s", exc)
            return None
        return satir["id"] if satir else None


__all__ = ["GUVENLIK_SALT_OKUNURA_ACIK", "SAYFA_ADI", "GuvenlikView"]
