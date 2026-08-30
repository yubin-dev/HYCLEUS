"""
HYCLEUS — Doğrulama Merkezi: üç doğrulama + kurtarma parçası tek yerde

Mimari karar — GüvenlikView'ın YERİNE mi geçiyor, ayrı bir sayfa mı (B-093)
----------------------------------------------------------------------------
Bu sayfa eskiden "Güvenlik" adıyla ZATEN üç doğrulamayı topluyordu (aşağıya
bakın). Görev kurtarma parçası kartını da "mockup'taki gibi tek bir
Doğrulama Merkezi ekranında" istedi ve hangi mimarinin (mevcut sayfanın
YERİNE mi, ayrı bir kenar çubuğu öğesi mi) seçileceğini kararımıza bıraktı.

**Karar: bu sayfanın YERİNE geçiyor — AYNI dosya, AYNI sınıf, AYNI kenar
çubuğu yuvası, yalnızca `SAYFA_ADI` ve başlık metni "Doğrulama Merkezi"
olarak değişti. Ayrı bir sidebar öğesi AÇILMADI.**

Gerekçe:
  1. Bu sayfa zaten "birden fazla doğrulamayı tek ekranda topla" fikrinin
     ta kendisiydi — dördüncü bir kartla GENİŞLETMEK, aynı fikrin doğal
     devamı; YENİDEN İCAT etmek değil.
  2. Ayrı bir sayfa açmak, üç kartı (damga/yedek/zincir) İKİ yerde
     göstermek anlamına gelirdi — modülün kendi "iki çağıran, tek gövde"
     kuralının (aşağıya bakın) tam da ENGELLEMEYE çalıştığı ayrışma, bu
     sefer GÖVDE seviyesinde değil SAYFA seviyesinde.
  3. Kenar çubuğunda ikinci bir "doğrulama" girişi, kullanıcıya "hangisini
     açacağım" sorusunu sorup bu turun kapattığı boşluğu (üç ayrı menü)
     dördüncü bir yerde yeniden açardı.

Sınıf/dosya adı (`GuvenlikView`/`GuvenlikView.py`), özellik adları
(`_guvenlik_view`, `nav_guvenlik`, `_on_guvenlik_click`) BİLEREK
DEĞİŞTİRİLMEDİ — yalnızca KULLANICIYA GÖRÜNEN metin değişti. Aynı karar
B-089'da (Bekleyen Kayıtlar'ın kart listesine dönüşümü) verildi: dahili
adları değiştirmek, kullanıcı görmeyen bir yerde risk almak demek.


Kapattığı boşluk
----------------
Dört iş vardı ve dördü de FARKLI bir yerde saklıydı:

    🕓 Damgayı Doğrula      dosya sağ tık menüsünde
    🔍 Yedek Doğrula        hamburger menüsünde
    🔗 Zinciri Doğrula      Yönetim Paneli'nde (yalnızca yönetici)
    🔑 Kurtarma Parçası     Yönetim Paneli → Ayarlar'da (yalnızca yönetici)

Bir denetçinin "bu kurulumu doğrula" işi üç ayrı menüyü bilmeyi
gerektiriyordu; kurtarma parçasını almak içinse dördüncü bir menü. Bu
görünüm hepsini tek sayfada topluyor.


Eski giriş noktaları KALDIRILMADI
----------------------------------
Bilinçli. Sağ tık menüsündeki damga doğrulama, seçili dosya üzerinde
çalıştığı için oradaki bağlam bu sayfada yok; hamburger menüsündeki yedek
doğrulama da yerinde duruyor; Yönetim Paneli → Ayarlar'daki kurtarma
parçası düğmesi de. Yani her iş artık İKİ giriş noktasına sahip.

Kural: **iki çağıran, tek gövde.** Bu sayfa hiçbir doğrulamayı/eylemi
kendisi UYGULAMIYOR — ana pencerenin mevcut metotlarını ya da paylaşılan
`UI/security_actions.py` gövdesini çağırıyor:

    damga    → `HycleusWindow._on_ctx_verify_timestamp()`
    yedek    → `HycleusWindow._on_verify_backup()`
    zincir   → `UI/security_actions.zinciri_dogrula()`
    kurtarma → `UI/security_actions.kurtarma_parcasini_goster()`

Son ikisi Yönetim Paneli'nin/`AdminSettingsView`'in birer metoduydu çünkü
o sayfalar yalnızca yöneticiye açılıyor; gövdeleri ortak bir yere taşındı
ve o sayfalar da artık oradan çağırıyor.

İkinci bir uygulama yazmak, bu deponun beş kez ürettiği kusurun altıncısı
olurdu (B-004/B-008, B-007, B-010, B-011, pay ayrıştırıcı).


Kurtarma parçası kartı NEDEN kendi rol kapısını taşıyor
---------------------------------------------------------
Diğer üçü SAF OKUMA — hiçbir dosyayı/kasayı değiştirmiyor, bu yüzden bu
sayfa Salt Okunur DIŞINDA her role açık (aşağıdaki B-034 notuna bakın).
Kurtarma parçası FARKLI: SECURITY.md §4.4'ün "uygulamanın gösterdiği en
hassas ekran" dediği `RecoveryShareDialog`'u açıyor ve kasadaki anahtar
payını GÖSTERİYOR — salt okuma değil, sınıfı gereği yönetici-only.

Bu yüzden kart TÜM roller için sayfada durmuyor: `kurtarma_karti_goster()`
yalnızca `is_admin_role(pencere._role)` iken görünür kılıyor,
`main_window.py::_apply_role_restrictions()`'tan çağrılarak — TIPKI
`UI/PendingRegistrationsView.py::set_kullanici_adi_gizli()` gibi, rol
oturum SIRASINDA değişirse (ikinci bir yönetici oturumu, B-066) kart da
GERİ gizlenir. Görünürlük tek bir UX kolaylığı: `kurtarma_parcasini_
goster()`'in KENDİSİ `admin_common.yonetici_hala_yetkili()` ile AYNI
canlı-yetki kontrolünü ZATEN taşıyor — kart gizliyken bile doğrudan
çağrılsa (test, bir hata) reddedilir. "Görünmez ama yine de korumalı" —
`UI/UsbTokensView.py`/`PendingRegistrationsView.py`'nin "koşulsuz kurulma"
turlarında (B-084/B-085) kurulan İKİ KATMANLI desenin AYNISI.


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
#: sızdırma riskiydi. Bu sayfadaki ÜÇ DOĞRULAMADA yıkıcı madde YOK — üçü de
#: okuma. (B-093: dördüncü kart — kurtarma parçası — bu sabitten TAMAMEN
#: BAĞIMSIZ, KENDİ yönetici-only kapısını taşıyor; bkz. modül docstring'i
#: ve `kurtarma_karti_goster()`. Bu sabit `True` olsa bile kurtarma
#: parçası kartı Salt Okunur'a AÇILMAZ.)
#:
#: Yine de `True` yapılmadı: karar kullanıcıya bırakıldı. Değiştirmek tek
#: satır ve `tests/test_guvenlik_view.py` mevcut davranışı sabitliyor.
GUVENLIK_SALT_OKUNURA_ACIK = False

#: Sayfa başlığı — kenar çubuğu düğmesi ve üst bar aynı metni kullanıyor.
#: B-093: eskiden "Güvenlik" — dördüncü kart (kurtarma parçası) eklenince
#: mockup'taki adıyla değişti. Sınıf/dosya adı BİLEREK AYNI kaldı (modül
#: docstring'indeki mimari karar notuna bakın).
SAYFA_ADI = "Doğrulama Merkezi"


class GuvenlikView(QWidget):
    """Üç doğrulama ve kurtarma parçasının toplandığı üst seviye görünüm."""

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

        baslik = QLabel(SAYFA_ADI)
        baslik.setObjectName("guvenlik_baslik")
        baslik.setStyleSheet("font-size:15px; font-weight:bold;")
        lay.addWidget(baslik)

        aciklama = QLabel(
            "Üç doğrulama hiçbir dosyayı/kasayı değiştirmez; hepsi tek "
            "ekranda, ayrı pencere açmadan çalışır ve sonucu denetim "
            "kaydına yazar. Kurtarma parçası bir doğrulama değil, kasadaki "
            "anahtar payının dışa aktarımıdır — yalnızca yöneticiye açık."
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
    #:
    #: Sıra mockup'takiyle AYNI: üç doğrulama, sonra kurtarma parçası.
    #: Kurtarma parçası kartı `kurtarma_karti_goster()` ile ayrıca
    #: gizlenebiliyor (yönetici-only, bkz. modül docstring'i) — bu yüzden
    #: `_kartlar()` onun widget'ını `self._kart_kurtarma`'da AYRICA
    #: tutuyor, diğer üçü gibi listeye atıp unutmuyor.
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
        ("🔑", "Kurtarma Parçası",
         "Kasayı açan üçüncü payı üretir ve gösterir — PIN ister, hiçbir "
         "yere kaydedilmez. Yalnızca yönetici.",
         "Göster…", "_kurtarma_parcasi"),
    )

    def _kartlar(self) -> list[QWidget]:
        kartlar = [self._kart(*veri) for veri in self._KARTLAR]
        self._kart_kurtarma = kartlar[-1]
        # Varsayılan GİZLİ: `main_window.py::_apply_role_restrictions()`
        # ilk açılışta HEMEN çağrılıyor (bkz. `kurtarma_karti_goster()`
        # docstring'i), ama o çağrıya kadar geçen an için bile "görünür
        # kalsın, kapatan gelene kadar" yerine "kapalı kalsın, açan
        # gelene kadar" — yönetici-only bir eylem için DOĞRU varsayılan.
        self._kart_kurtarma.setVisible(False)
        return kartlar

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

    # ── Rol kapısı — yalnızca kurtarma parçası kartı ─────────────────────────

    def kurtarma_karti_goster(self, goster: bool) -> None:
        """
        Kurtarma Parçası kartının görünürlüğü — YALNIZCA yönetici.

        `main_window.py::_apply_role_restrictions()`'tan çağrılıyor,
        `UI/PendingRegistrationsView.py::set_kullanici_adi_gizli()` ile
        AYNI desen: rol oturum SIRASINDA düşerse (ikinci bir yönetici
        oturumu, B-066) kart da GERİ gizlenmeli — yalnızca sayfa AÇILIRKEN
        karar verip unutmak yetmez.

        Diğer üç kart bu çağrıdan ETKİLENMİYOR: onlar salt okuma, sayfanın
        KENDİSİ zaten Salt Okunur dışında her role açık (bkz.
        `GUVENLIK_SALT_OKUNURA_ACIK`, aşağıdaki B-034 notu).
        """
        self._kart_kurtarma.setVisible(goster)

    # ── Üç doğrulama + kurtarma parçası — GÖVDE BURADA DEĞİL ─────────────────

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

    def _kurtarma_parcasi(self) -> None:
        """
        Kurtarma parçasını üretir ve modalda gösterir — Yönetim Paneli →
        Ayarlar'daki "Kurtarma Parçasını Göster" düğmesiyle AYNI gövde.

        `sade` bayrağı BİLEREK geçilmiyor: diğer üç kartın aksine bu bir
        doğrulama değil, `RecoveryShareDialog`'un basit/gelişmiş kavramı
        yok — üretilen içerik (QR + base32 + uyarı) HER ZAMAN tam gösterilir.
        """
        from UI.security_actions import kurtarma_parcasini_goster

        kurtarma_parcasini_goster(self, self._pencere)

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
