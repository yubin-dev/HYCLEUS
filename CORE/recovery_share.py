"""
HYCLEUS — Kurtarma parçasının (Shamir 3. payı) dışa aktarımı

Kurtarma parçası, 2-of-3 şemasının üçüncü payıdır. share_1 (vault) veya
share_2 (anahtar kasası) kaybedildiğinde, kalan pay + kurtarma parçası ile
master_key yeniden oluşturulur.

⚠️ SAKLAMA KURALI
-----------------
Kurtarma parçası SİSTEMDE HİÇBİR YERDE SAKLANMAZ. Ne veritabanına, ne bir
dosyaya, ne ayarlara, ne de log'a yazılır. Bir kez üretilip kullanıcıya
gösterilir ve bellekten temizlenir.

Kullanıcıya gösterilmesi gereken uyarı (WARNING_TEXT):
  Bu parçayı FİZİKSEL olarak güvenli bir yerde saklayın — kasa, banka
  kiralık kasası, yangına dayanıklı belge çantası. DİJİTAL OLARAK
  SAKLAMAYIN: ekran görüntüsü almayın, buluta yüklemeyin, parola
  yöneticisine koymayın, e-posta/mesajla göndermeyin.

Neden: kurtarma parçası, kalan tek payla birlikte master_key'i verir.
Diskte duran bir kurtarma parçası, 2-of-3 şemasını fiilen 1-of-2'ye
düşürür — çünkü diski okuyan saldırgan zaten share_1 veya share_2'ye
erişebilir durumdadır.

Biçimler
--------
Base32 metin  — elle yazılabilir/okunabilir; 4'lü gruplar hâlinde, büyük
                harf. RFC 4648 alfabesi (A-Z, 2-7) rakam/harf karışmasının
                en sık kaynaklarını dışarıda bırakır: 0 ile O, 1 ile I/L
                arasındaki belirsizlik oluşmaz çünkü 0, 1, 8, 9 rakamları
                alfabede yoktur. (Harf olarak I, O, L VARDIR — tümü büyük
                harf yazıldığı için rakamla karışmazlar.)
QR kod        — telefonla okumak yerine, kâğıda basılıp saklanmak için;
                elle yazım hatası riskini ortadan kaldırır.

Her iki biçim de AYNI payı taşır ve ikisi de tek başına yeterlidir.
"""
from __future__ import annotations

import base64
import io
import re
from dataclasses import dataclass

# Base32 gövdesi bu ön ekle etiketlenir — yanlış bir metnin PIN veya başka
# bir sır olduğunu erken anlamak için
_PREFIX = "HYCLEUS-R3"
_GROUP = 4

WARNING_TEXT = (
    "⚠️  KURTARMA PARÇASI — BİR KEZ GÖSTERİLİR\n"
    "\n"
    "Bu parçayı FİZİKSEL olarak güvenli bir yerde saklayın:\n"
    "  · kasa veya banka kiralık kasası\n"
    "  · yangına dayanıklı belge çantası\n"
    "  · vault'un bulunduğu bilgisayardan AYRI bir konum\n"
    "\n"
    "DİJİTAL OLARAK SAKLAMAYIN:\n"
    "  · ekran görüntüsü almayın\n"
    "  · buluta / not uygulamasına / parola yöneticisine koymayın\n"
    "  · e-posta veya mesajla göndermeyin\n"
    "\n"
    "Bu parça, kalan tek payla birlikte tüm dosyalarınızın anahtarını verir.\n"
    "Diskte duran bir kopyası, 2-of-3 korumasını fiilen 1-of-2'ye düşürür.\n"
    "\n"
    "HYCLEUS bu parçayı HİÇBİR YERDE saklamaz. Kaybederseniz yeniden\n"
    "üretilebilir — ama yalnızca diğer iki pay hâlâ elinizdeyken."
)


class RecoveryShareError(ValueError):
    """Kurtarma parçası çözümlenemediğinde fırlatılır."""


@dataclass
class RecoveryExport:
    """
    Dışa aktarılmış kurtarma parçası — yalnızca bellekte yaşar.

    Kullanım bittiğinde referansı bırakın:
        export = build_export(share_3)
        try:
            ...  # göster / yazdır
        finally:
            del export
    """

    base32_text: str
    qr_svg: str | None
    warning: str = WARNING_TEXT

    def printable(self) -> str:
        """Yazdırılabilir düz metin — uyarı + base32 gövdesi."""
        return f"{self.warning}\n\n{'-' * 60}\n{self.base32_text}\n{'-' * 60}\n"


def encode_share(share: str) -> str:
    """
    "3:<hex>" payını yazdırılabilir base32 metne çevirir.

    Çıktı: HYCLEUS-R3-XXXX-XXXX-... (büyük harf, 4'lü gruplar)
    Base32 alfabesi 0/1/8/I/O/L içermez; elle kopyalarken karışma riski düşük.
    """
    index, _hex = share.split(":", 1)
    if index != "3":
        raise RecoveryShareError(
            f"Kurtarma parçası 3 indisli olmalı, alınan: {index!r}"
        )
    raw = bytes.fromhex(share.split(":", 1)[1])
    body = base64.b32encode(raw).decode("ascii").rstrip("=")
    groups = [body[i : i + _GROUP] for i in range(0, len(body), _GROUP)]
    return f"{_PREFIX}-" + "-".join(groups)


def decode_share(text: str) -> str:
    """
    Base32 kurtarma metnini "3:<hex>" payına geri çevirir.

    Kullanıcı elle girer; bu yüzden esnek: boşluk, satır sonu, küçük harf ve
    eksik/fazla tire tolere edilir.

    Raises:
        RecoveryShareError — metin bir HYCLEUS kurtarma parçası değilse
    """
    if not text or not text.strip():
        raise RecoveryShareError("Kurtarma parçası boş.")

    cleaned = re.sub(r"[\s\-]+", "", text.strip()).upper()
    prefix = _PREFIX.replace("-", "")
    if not cleaned.startswith(prefix):
        raise RecoveryShareError(
            f"Metin bir HYCLEUS kurtarma parçasına benzemiyor "
            f"({_PREFIX}-... ile başlamalı)."
        )
    body = cleaned[len(prefix) :]

    padding = "=" * (-len(body) % 8)
    try:
        raw = base64.b32decode(body + padding, casefold=True)
    except Exception as exc:
        raise RecoveryShareError(
            "Kurtarma parçası çözümlenemedi — karakter hatası olabilir. "
            "Yazdığınız metni kontrol edin."
        ) from exc

    expected = 33  # ceil(257/8)
    if len(raw) != expected:
        raise RecoveryShareError(
            f"Kurtarma parçası {expected} byte olmalı, {len(raw)} byte çözüldü — "
            "metin eksik veya fazla."
        )
    return f"3:{raw.hex()}"


def render_qr_svg(text: str) -> str | None:
    """
    Kurtarma metnini SVG QR koduna çevirir.

    SVG seçildi çünkü kayıpsız ölçeklenir (yazdırma için önemli) ve düz
    metindir — ek görüntü kütüphanesi gerektirmez.

    qrcode paketi kurulu değilse None döner; base32 metin tek başına yeterli
    olduğundan bu ölümcül bir hata değildir.
    """
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        return None

    img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def build_export(share_3: str, *, with_qr: bool = True) -> RecoveryExport:
    """
    Kurtarma parçasını dışa aktarılabilir biçimlere çevirir.

    DİSKE HİÇBİR ŞEY YAZMAZ. Döndürülen nesne yalnızca bellekte yaşar;
    çağıran taraf gösterdikten sonra referansı bırakmalıdır.

    Args:
        share_3  — "3:<hex>" biçiminde kurtarma payı
        with_qr  — QR üretilsin mi (qrcode yoksa sessizce atlanır)
    """
    text = encode_share(share_3)
    return RecoveryExport(
        base32_text=text,
        qr_svg=render_qr_svg(text) if with_qr else None,
    )
