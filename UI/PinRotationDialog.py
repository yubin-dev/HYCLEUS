"""
HYCLEUS — Zorunlu PIN yenileme diyaloğu (B-003)

PIN politikası 4'ten 6 haneye çıkarıldığında eski hesaplar olduğu yerde
bırakılmıştı. Bu diyalog, kısa PIN'le giriş yapan kullanıcıyı ana pencere
açılmadan önce durduruyor.

Karar mantığı burada YOK: doğrulama, kasa yeniden şifreleme, kayıt ve
denetim `CORE/pin_rotation.py`'de ve `UI/ProfileDialog.py` ile PAYLAŞILIYOR.
Burada olan yalnızca yerleşim ve "kapatılamaz" davranışı.


NEDEN ESKİ PIN TEKRAR SORULMUYOR
---------------------------------
Kullanıcı bu ekrana ancak PIN + TOTP doğrulamasını GEÇTİKTEN sonra
geliyor; eski PIN çağıranın elinde. Yeniden sormak güvenlik eklemiyor,
yalnızca bir yazım hatası ihtimali ve bir başarısızlık yolu ekliyor —
üstelik o hatanın sonucu, kullanıcının çıkamadığı bir ekranda takılı
kalması olurdu.


"KAPATILAMAZ" ÜÇ KATMANDA
--------------------------
Bir Qt diyaloğu üç ayrı yoldan kapanabiliyor ve üçü de ayrı ayrı
kapatılmak zorunda:

  1. `reject()`      — Esc tuşu ve `QDialog`'un varsayılan davranışı
  2. `closeEvent`    — pencere yöneticisinin kapatma düğmesi
  3. İptal düğmesi   — hiç eklenmiyor

Esc için AYRI bir `keyPressEvent` katmanı YOK ve bu bilinçli: `QDialog`
Esc'i zaten `reject()`'e yönlendiriyor, yani ikinci bir kanca hiçbir yeni
durumu kapatmıyordu. Mutasyon testinde ölçüldü — o katmanı kaldırmak
hiçbir davranışı değiştirmiyordu, yani bağımsız olarak gözlenemeyen bir
kodtu. Bağımsız gözlenemeyen koruma, zamanla "bu neden burada" diye
sorulan ölü koda dönüşür.

Ama ASIL KAPI bu diyalogda DEĞİL: `login_dialog._on_login()` yenileme
başarılı olmadıkça `accept()` çağırmıyor. Yani üç katman da aşılsa
kullanıcı içeri giremiyor. Diyaloğun kapatılamazlığı bir KULLANILABİLİRLİK
tercihi; güvenlik kararını veren yer giriş akışı.

Bu ayrım bilinçli: kapatılamaz bir pencere, kullanıcıyı uygulamayı
görev yöneticisinden öldürmeye iten bir tuzağa dönüşebilir. Uygulamadan
ÇIKMAK her zaman mümkün — engellenen tek şey, PIN yenilenmeden İÇERİ
GİRMEK.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from CORE.pin_policy import PIN_MIN_LEN
from CORE.pin_rotation import PinRotationError, rotate_pin
from UI.dialog_kit import RAPOR_STILI, ayrac, kutu, sarmali

_EK_STIL = """
QLineEdit {
    background: #313244; color: #cdd6f4;
    border: 1px solid #45475a; border-radius: 6px;
    padding: 8px 10px; font-size: 14px;
}
QLineEdit:focus { border-color: #89b4fa; }
QLabel#hata { color: #f38ba8; font-size: 12px; }
"""


class PinRotationDialog(QDialog):
    """Kısa PIN'i olan kullanıcıyı yenilemeye zorlar. İptal edilemez."""

    def __init__(
        self,
        *,
        db,
        hwid: str,
        mevcut_pin: str,
        user_id: int | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._db = db
        self._hwid = hwid
        self._mevcut_pin = mevcut_pin
        self._user_id = user_id
        #: Yenileme gerçekten yapıldı mı. Çağıran BUNA bakıyor —
        #: `exec()` dönüş değeri tek başına yeterli değil, çünkü bir
        #: pencere yöneticisi diyaloğu dışarıdan kapatabilir.
        self.rotated = False

        self.setWindowTitle("HYCLEUS — PIN Güncelleme Zorunlu")
        self.setMinimumWidth(460)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setModal(True)
        self.setStyleSheet(RAPOR_STILI + _EK_STIL)
        self._build_ui()

    # ── Kurulum ───────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        yerlesim = QVBoxLayout(self)
        yerlesim.setContentsMargins(24, 20, 24, 16)
        yerlesim.setSpacing(10)

        baslik = sarmali("🔒  PIN'inizi güncellemeniz gerekiyor", "baslik")
        baslik.setStyleSheet("color:#f9e2af;")
        yerlesim.addWidget(baslik)

        yerlesim.addWidget(sarmali(
            f"PIN'iniz {PIN_MIN_LEN} haneden kısa. Hesabınız, bu kural "
            f"yürürlüğe girmeden önce oluşturulmuş ve o günden beri eski "
            f"uzunlukta kaldı.",
            "ozet",
        ))
        yerlesim.addWidget(kutu([
            sarmali(
                "Kısa bir PIN deneme yanılmaya karşı belirgin biçimde daha "
                "zayıftır. Devam etmek için yeni bir PIN belirleyin — "
                f"en az {PIN_MIN_LEN} karakter.",
                "not_gov",
            ),
        ]))
        yerlesim.addWidget(ayrac())

        yerlesim.addWidget(sarmali("Yeni PIN", "alan_ad"))
        self._yeni = self._pin_alani()
        yerlesim.addWidget(self._yeni)

        yerlesim.addWidget(sarmali("Yeni PIN (tekrar)", "alan_ad"))
        self._yeni2 = self._pin_alani()
        yerlesim.addWidget(self._yeni2)

        self._hata = sarmali("", "hata")
        self._hata.setObjectName("hata")
        self._hata.setVisible(False)
        yerlesim.addWidget(self._hata)

        # İPTAL DÜĞMESİ YOK — bilerek. Gerekçe modül docstring'inde.
        satir = QHBoxLayout()
        satir.addStretch(1)
        self._kaydet = QPushButton("PIN'i Güncelle ve Devam Et")
        self._kaydet.setObjectName("primary_btn")
        self._kaydet.setDefault(True)
        self._kaydet.clicked.connect(self._on_kaydet)
        satir.addWidget(self._kaydet)
        sarici = QWidget()
        sarici.setLayout(satir)
        yerlesim.addWidget(sarici)

        self._yeni.setFocus()

    def _pin_alani(self) -> QLineEdit:
        alan = QLineEdit()
        alan.setEchoMode(QLineEdit.Password)
        alan.setMaxLength(64)
        alan.returnPressed.connect(self._on_kaydet)
        return alan

    # ── Kapatılamazlık ────────────────────────────────────────────────────────

    def reject(self) -> None:
        """Esc ve `QDialog`'un varsayılan iptali — yok sayılıyor."""
        self._goster("Devam etmek için PIN'inizi güncellemelisiniz.")

    def closeEvent(self, event) -> None:
        """Pencere yöneticisinin kapatma düğmesi — yok sayılıyor."""
        if self.rotated:
            event.accept()
            return
        event.ignore()
        self._goster("Devam etmek için PIN'inizi güncellemelisiniz.")

    # ── Davranış ──────────────────────────────────────────────────────────────

    def _goster(self, mesaj: str) -> None:
        self._hata.setText(mesaj)
        self._hata.setVisible(True)

    def _on_kaydet(self) -> None:
        yeni = self._yeni.text()
        yeni2 = self._yeni2.text()

        if yeni != yeni2:
            self._goster("PIN'ler eşleşmiyor.")
            self._yeni2.setFocus()
            return

        try:
            rotate_pin(
                self._db, self._hwid, self._mevcut_pin, yeni,
                user_id=self._user_id, zorunlu=True,
            )
        except PinRotationError as exc:
            self._goster(str(exc))
            self._yeni.setFocus()
            return

        # PIN artık DEĞİŞTİ — alanları hemen boşalt. Diyalog kapanana
        # kadar bellekte duran bir düz metin PIN, ekran görüntüsü ve
        # widget denetimi yüzeyine açık kalır.
        self._yeni.clear()
        self._yeni2.clear()
        self._mevcut_pin = ""
        self.rotated = True
        self.accept()


__all__ = ["PinRotationDialog"]
