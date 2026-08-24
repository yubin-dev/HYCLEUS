"""
HYCLEUS — yeni kayıt sonrası authenticator kurulum ekranı (B-059)

Neden bu modül var
------------------
Eskiden self-servis kayıt (`login_dialog.py`'nin "Kayıt Ol" sekmesi,
`RegisterDialog.py`) HİÇ TOTP sırrı üretmiyordu — yeni kullanıcı, onaydan
sonra, herkesin paylaştığı GLOBAL sırra güveniyordu (B-059'un asıl
hatası). `CORE.registration.register_new_user()` artık her kayıt için
kendi rastgele TOTP sırrını üretip HWID başına saklıyor
(`CORE.secret_store.store_totp_secret_for_hwid`) — ama bir sırrı
SAKLAMAK ile kullanıcıya GÖSTERMEK ayrı şeyler. Kullanıcı bu QR'ı
kaydolduğu ANDA görmeli: onaydan sonra bu pencereyi bir daha görmez,
authenticator uygulamasını o zamana kadar kurmuş olmalı.

İki çağıran (login_dialog.py'nin self-servis "Kayıt Ol" sekmesi,
RegisterDialog.py'nin yönetici-başlattığı kayıt) aynı QR/manuel-anahtar
gösterimini bağımsız olarak yeniden yazmasın diye TEK yerde — "iki
çağıran, tek gövde".
"""
from __future__ import annotations

from io import BytesIO

import pyotp
import qrcode
import qrcode.constants
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QMessageBox, QWidget

_APP_NAME = "HYCLEUS"


def _make_qr_pixmap(uri: str, size: int = 200) -> QPixmap:
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=4,
        border=2,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    px = QPixmap()
    px.loadFromData(buf.getvalue())
    return px.scaled(size, size)


def show_totp_enrollment_dialog(
    parent: QWidget | None, secret: str, username: str,
) -> None:
    """
    Yeni kayıt için authenticator kurulumunu QR + manuel anahtar olarak gösterir.

    Modal ve tek seferlik: kapatıldıktan sonra sır bir daha gösterilmez
    (kasada duruyor, ama arayüzde yeniden görüntülenmiyor — kayıt akışı
    "PIN'i bir daha göstermiyoruz" ilkesiyle tutarlı).
    """
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=_APP_NAME)
    box = QMessageBox(parent)
    box.setWindowTitle("Authenticator Kurulumu")
    box.setText(
        "Hesabınız oluşturuldu.\n\n"
        "Yönetici onayından SONRA giriş yapabilmek için authenticator "
        "uygulamanızı ŞİMDİ kurun — bu ekranı bir daha göremezsiniz.\n\n"
        f"Manuel anahtar: {secret}"
    )
    box.setIconPixmap(_make_qr_pixmap(uri))
    box.setStandardButtons(QMessageBox.Ok)
    box.exec()
