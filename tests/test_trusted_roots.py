"""
CORE.trusted_roots — kurumsal güvenilir kök deposu ve iki geçerlilik durumu.

Asıl ölçülen ayrım
------------------
`verify_timestamp()` 3.1b'den beri `valid` ile `anchor_trusted`'ı AYRI
tutuyor ama arayüzde ikisi aynı görünüyordu: kök verilemediği için her
sonuç `anchor_trusted=False` ile dönüyor ve başlık yine "Damga geçerli"
oluyordu. Bu paket üç durumun BİRBİRİNDEN AYRILDIĞINI ölçüyor:

    kök yok            → valid=True,  anchor_trusted=False → UYARILI GEÇERLİ
    doğru kök eklendi  → valid=True,  anchor_trusted=True  → TAM GEÇERLİ
    yanlış kök eklendi → valid=False, failed_check=trust_anchor → GEÇERSİZ

Üçüncü satır önemli: kök eklendiğinde eşleşmeyen bir damga artık "uyarılı
geçerli" DEĞİL, geçersiz. Yani kök eklemek sadece bir rozet açmıyor,
kararın kendisini sertleştiriyor.

Sertifikalar
------------
Gerçek X.509 üretiliyor (`cryptography` ile, testin içinde), sabit fixture
değil: depo DER'i ayrıştırıp konusunu okuyor ve sahte baytlarla o yol hiç
çalışmazdı. Damga doğrulaması için gerçek freetsa.org token'ı kullanan
testler `tests/test_timestamp_verify.py`'de; burada ölçülen şey KÖK
EŞLEŞMESİ ve onun rapor katmanına yansıması.
"""
from __future__ import annotations

import ast
import base64
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# QApplication kurulmadan ÖNCE, modül seviyesinde. Diğer Qt test
# dosyalarındaki desenin aynısı.
#
# Neden `setdefault` ve neden BURADA: bu dosya tek başına çalıştırıldığında
# (`pytest tests/test_trusted_roots.py`) değişken HİÇBİR yerde kurulmuyor —
# ölçüldü. Ekransız bir Linux'ta Qt varsayılan `xcb` eklentisini yükleyemez
# ve `qFatal` ile SÜRECİ ÖLDÜRÜR; ölçüldü, yakalanabilir bir istisna DEĞİL,
# yani aşağıdaki `try/except → pytest.skip` kurtarmaz.
#
# Tam pakette değişken başka bir modülün toplama anındaki yan etkisinden
# geliyor — yani bu dosya bugüne kadar KAZAYLA çalışıyordu.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from CORE import timestamp_report as tr
from CORE import trusted_roots as tk
from CORE.timestamp_verify import TimestampVerification
from CORE.trusted_roots import (
    EYLEM_EKLENDI,
    EYLEM_SILINDI,
    SETTING,
    TrustedRootError,
    der_coz,
    der_listesi,
    ekle,
    konu_metni,
    oku,
    sil,
)

KOK = Path(__file__).resolve().parent.parent


def _sertifika(konu: str = "HYCLEUS Test CA") -> tuple[bytes, bytes]:
    """Gerçek, kendinden imzalı bir X.509 üretir. `(der, pem)`."""
    anahtar = ec.generate_private_key(ec.SECP256R1())
    ad = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, konu)])
    simdi = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(ad).issuer_name(ad)
        .public_key(anahtar.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(simdi - timedelta(days=1))
        .not_valid_after(simdi + timedelta(days=365))
        .sign(anahtar, hashes.SHA256())
    )
    return (cert.public_bytes(serialization.Encoding.DER),
            cert.public_bytes(serialization.Encoding.PEM))


@pytest.fixture
def sertifika() -> tuple[bytes, bytes]:
    return _sertifika()


@pytest.fixture
def yonetici_db(db):  # type: ignore[no-untyped-def]
    """`audit_log.user_id` bir FK — satır olmadan kayıt sessizce düşer."""
    db.execute(
        "INSERT INTO users (id, username, password_hash, role, status, hwid)"
        " VALUES (5, 'yonetici', '', 'admin', 'approved', 'H')")
    return db


def _kayitlar(db, eylem: str) -> list[str]:  # type: ignore[no-untyped-def]
    return [r["detail"] for r in db.fetchall(
        "SELECT detail FROM audit_log WHERE action = ? ORDER BY id", (eylem,))]


# ══════════════════════════════════════════════════════════════════════════════
# 1. Ayrıştırma — CLI ile ORTAK tek uygulama
# ══════════════════════════════════════════════════════════════════════════════


def test_DER_ve_PEM_ayni_sonucu_veriyor(sertifika: tuple[bytes, bytes]) -> None:
    """
    PEM desteği şart: sertifikalar pratikte öyle dağıtılıyor. İkisi AYNI
    DER'e inmezse aynı kök iki farklı kayıt olurdu.
    """
    der, pem = sertifika
    assert der_coz(der) == der
    assert der_coz(pem) == der


@pytest.mark.parametrize("bozuk,parca", [
    (b"", "boş"),
    (b"bu bir sertifika degil", "geçerli bir sertifika değil"),
    (b"-----BEGIN CERTIFICATE-----\nCOP\n-----END CERTIFICATE-----\n", "PEM"),
])
def test_bozuk_girdi_TEMIZ_hata_veriyor(bozuk: bytes, parca: str) -> None:
    with pytest.raises(TrustedRootError, match=parca):
        der_coz(bozuk, kaynak="deneme.pem")


def test_rastgele_dosya_DEPOYA_ALINMIYOR() -> None:
    """
    Ayrıştırılmayan bir dosyayı depoya almak, hiçbir zaman eşleşmeyecek
    bir "güvenilir kök" satırı bırakırdı ve kullanıcı korunduğunu sanırdı.
    """
    with pytest.raises(TrustedRootError):
        der_coz(b"\x30\x82\x01\x00" + b"\x00" * 100, kaynak="sahte.der")


def test_boyut_siniri(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tk, "AZAMI_KOK", 16)
    with pytest.raises(TrustedRootError, match="çok büyük"):
        der_coz(b"x" * 100)


def test_konu_metni_okunuyor(sertifika: tuple[bytes, bytes]) -> None:
    assert konu_metni(sertifika[0]) == "HYCLEUS Test CA"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Depo
# ══════════════════════════════════════════════════════════════════════════════


def test_bos_depo_bos_liste(db) -> None:  # type: ignore[no-untyped-def]
    assert oku(db) == []
    assert der_listesi(db) == []


def test_ekle_oku_sil_turu(yonetici_db, sertifika) -> None:  # type: ignore[no-untyped-def]
    der, _ = sertifika
    kok = ekle(yonetici_db, der, ad="kurum.der", user_id=5)
    assert kok.konu == "HYCLEUS Test CA"
    assert der_listesi(yonetici_db) == [der]

    assert sil(yonetici_db, kok.parmak_izi, user_id=5) is True
    assert oku(yonetici_db) == []
    assert sil(yonetici_db, kok.parmak_izi, user_id=5) is False


def test_ayni_kok_IKI_KEZ_eklenmiyor(yonetici_db, sertifika) -> None:  # type: ignore[no-untyped-def]
    """
    Kimlik DER'in özeti, ADI değil. Aynı kök farklı adlarla iki kez
    listede görünseydi kullanıcı hangisini sileceğini bilemezdi.
    """
    der, pem = sertifika
    a = ekle(yonetici_db, der, ad="birinci.der", user_id=5)
    b = ekle(yonetici_db, pem, ad="ikinci.pem", user_id=5)
    assert a.parmak_izi == b.parmak_izi
    assert len(oku(yonetici_db)) == 1
    assert b.ad == "birinci.der", "ilk kayıt korunmalı"


def test_farkli_kokler_ayri_duruyor(yonetici_db) -> None:  # type: ignore[no-untyped-def]
    a, _ = _sertifika("Kurum A")
    b, _ = _sertifika("Kurum B")
    ekle(yonetici_db, a, ad="a.der", user_id=5)
    ekle(yonetici_db, b, ad="b.der", user_id=5)
    assert {k.konu for k in oku(yonetici_db)} == {"Kurum A", "Kurum B"}
    assert len(der_listesi(yonetici_db)) == 2


def test_adet_siniri(yonetici_db, sertifika, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(tk, "AZAMI_ADET", 1)
    ekle(yonetici_db, sertifika[0], ad="a.der", user_id=5)
    with pytest.raises(TrustedRootError, match="dolu"):
        ekle(yonetici_db, _sertifika("Baska")[0], ad="b.der", user_id=5)


def test_bozuk_ayar_satiri_COKERTMIYOR(db) -> None:  # type: ignore[no-untyped-def]
    """
    Bozuk bir ayar satırı doğrulamayı çökertmemeli. Sonuç kök
    doğrulanmamış bir "geçerli" olur — fail-safe, ama sessiz değil
    (log'a düşüyor).
    """
    for bozuk in ("{{{", '"liste degil"', '[{"der": "!!!gecersiz"}]'):
        db.set_setting(SETTING, bozuk)
        assert oku(db) == [], f"{bozuk!r} çökertti ya da veri üretti"


def test_depo_diske_YAZILIYOR(yonetici_db, sertifika) -> None:  # type: ignore[no-untyped-def]
    """Ayar satırı gerçekten settings tablosunda ve base64 taşıyor."""
    ekle(yonetici_db, sertifika[0], ad="k.der", user_id=5)
    ham = yonetici_db.get_setting(SETTING, "")
    kayitlar = json.loads(ham)
    assert len(kayitlar) == 1
    assert base64.b64decode(kayitlar[0]["der"]) == sertifika[0]


# ══════════════════════════════════════════════════════════════════════════════
# 3. Denetim kaydı
# ══════════════════════════════════════════════════════════════════════════════


def test_kok_ekleme_ve_silme_kayda_geciyor(yonetici_db, sertifika) -> None:  # type: ignore[no-untyped-def]
    """
    Kök eklemek, doğrulamanın CEVABINI değiştiren tek yönetici eylemi —
    kayda geçmemesi, güven listesinin sessizce değişebilmesi demek olurdu.
    """
    kok = ekle(yonetici_db, sertifika[0], ad="kurum.der", user_id=5)
    (detay,) = _kayitlar(yonetici_db, EYLEM_EKLENDI)
    assert "HYCLEUS Test CA" in detay
    assert kok.kisa_izi() in detay

    sil(yonetici_db, kok.parmak_izi, user_id=5)
    (detay,) = _kayitlar(yonetici_db, EYLEM_SILINDI)
    assert kok.kisa_izi() in detay
    assert "kalan=0" in detay


def test_kayit_hatasi_EKLEMEYI_engellemiyor(db, sertifika) -> None:  # type: ignore[no-untyped-def]
    """`pin_rotation`/`hclx` ile aynı karar: kayıt, sonucu engellemez."""
    class YarimDB:
        def get_setting(self, k, d=""):  # type: ignore[no-untyped-def]
            return db.get_setting(k, d)

        def set_setting(self, k, v):  # type: ignore[no-untyped-def]
            db.set_setting(k, v)

        def log(self, *a, **k):  # type: ignore[no-untyped-def]
            raise RuntimeError("denetim yazılamıyor")

    kok = ekle(YarimDB(), sertifika[0], ad="k.der", user_id=5)
    assert kok.konu == "HYCLEUS Test CA"
    assert len(oku(db)) == 1


# ══════════════════════════════════════════════════════════════════════════════
# 4. ÜÇ DURUMUN AYRIŞMASI — maddenin asıl testi
# ══════════════════════════════════════════════════════════════════════════════
#
# `verify_timestamp()`'in gerçek zinciriyle çalışan uçtan uca sürüm
# `tests/test_timestamp_verify.py`'de; burada rapor katmanının o üç
# sonucu AYRI anlattığı ölçülüyor.


def test_kok_YOKKEN_uyarili_gecerli() -> None:
    sonuc = TimestampVerification(valid=True, anchor_trusted=False)
    mesaj = tr.aciklama(sonuc)
    assert mesaj.seviye == tr.SEVIYE_UYARI, "kök doğrulanmadan yeşil onay verilmiş"
    assert "doğrulanmadı" in mesaj.baslik
    # Ne yapılacağı söylenmeli — kurumsal kullanımın istediği tam olarak bu.
    assert mesaj.oneri and "Ayarlar" in mesaj.oneri


def test_kok_EKLENDIGINDE_tam_gecerli() -> None:
    sonuc = TimestampVerification(valid=True, anchor_trusted=True)
    mesaj = tr.aciklama(sonuc)
    assert mesaj.seviye == tr.SEVIYE_GECERLI
    assert "doğrulandı" in mesaj.baslik
    assert mesaj.oneri is None, "tam geçerli sonuçta yapılacak bir şey yok"


def test_iki_durumun_BASLIKLARI_farkli() -> None:
    """
    Ayrımın kullanıcıya görünmesi başlığın kendisinden geliyor. İkisi aynı
    başlığı paylaşsaydı fark yalnızca alttaki nota kalırdı ve o notu
    okumayan kullanıcı ikisini aynı sanardı.
    """
    a = tr.aciklama(TimestampVerification(valid=True, anchor_trusted=False))
    b = tr.aciklama(TimestampVerification(valid=True, anchor_trusted=True))
    assert a.baslik != b.baslik
    assert a.seviye != b.seviye, "seviye aynıysa simge ve renk de aynı olur"


def test_YANLIS_kok_eklenirse_sonuc_GECERSIZ() -> None:
    """
    Kök eklemek sadece bir rozet açmıyor, kararı SERTLEŞTİRİYOR:
    eşleşmeyen bir zincir artık "uyarılı geçerli" değil, geçersiz.
    """
    sonuc = TimestampVerification(
        valid=False, failed_check="trust_anchor",
        reason="Zincirin kökü güvenilen kökler arasında değil.")
    mesaj = tr.aciklama(sonuc)
    assert mesaj.seviye == tr.SEVIYE_GECERSIZ
    assert mesaj is tr._ADIM["trust_anchor"]


def test_notlar_iki_durumda_da_DOGRU_seyi_soyluyor() -> None:
    guvenilir = tr.notlar(TimestampVerification(valid=True, anchor_trusted=True))
    uyarili = tr.notlar(TimestampVerification(valid=True, anchor_trusted=False))
    assert guvenilir[0].seviye == tr.SEVIYE_BILGI
    assert uyarili[0].seviye == tr.SEVIYE_UYARI
    # Uyarı, kullanıcıyı AYARA yönlendirmeli — eskiden yalnızca komut
    # satırındaki --trusted-root'tan söz ediyordu ve arayüzden ulaşılamazdı.
    assert "Ayarlar" in (uyarili[0].oneri or "")


# ══════════════════════════════════════════════════════════════════════════════
# 5. Uçtan uca: depo → doğrulama
# ══════════════════════════════════════════════════════════════════════════════


def test_depo_verify_timestamp_e_DOGRU_bicimde_gidiyor(yonetici_db, sertifika) -> None:  # type: ignore[no-untyped-def]
    """
    `der_listesi()` doğrudan `verify_timestamp(trusted_roots=...)`'a
    verilebilir olmalı: DER baytları, sarmalanmamış.
    """
    der, _ = sertifika
    ekle(yonetici_db, der, ad="k.der", user_id=5)
    liste = der_listesi(yonetici_db)
    assert liste == [der]
    assert all(isinstance(x, bytes) for x in liste)


def test_arayuz_depoyu_GERCEKTEN_kullaniyor() -> None:
    """
    Depo kurulup arayüze bağlanmazsa hiçbir şey değişmezdi — 3.1b'den beri
    durum tam olarak buydu.
    """
    kaynak = (KOK / "UI" / "main_window_files.py").read_text(encoding="utf-8")
    agac = ast.parse(kaynak)
    cagrilar = {
        (d.func.attr if isinstance(d.func, ast.Attribute) else
         d.func.id if isinstance(d.func, ast.Name) else "")
        for d in ast.walk(agac) if isinstance(d, ast.Call)
    }
    assert "der_listesi" in cagrilar, (
        "Arayüz kök deposunu okumuyor — doğrulama her zaman "
        "«kök doğrulanmadı» der."
    )
    # `verify_timestamp` çağrısı `trusted_roots` ANAHTAR KELİMESİYLE
    # yapılmalı; deposu okuyup vermemek en olası hata.
    verify = [d for d in ast.walk(agac) if isinstance(d, ast.Call)
              and isinstance(d.func, ast.Name) and d.func.id == "verify_timestamp"]
    assert verify, "verify_timestamp çağrısı bulunamadı"
    assert any(kw.arg == "trusted_roots" for d in verify for kw in d.keywords), (
        "verify_timestamp'e trusted_roots geçilmiyor — depo okunuyor ama "
        "kullanılmıyor."
    )


# ── GERÇEK damga ile uçtan uca ────────────────────────────────────────────────

_FIXTURE = KOK / "tests" / "data" / "freetsa_response.der"
_FIXTURE_PLAIN = b"HYCLEUS RFC 3161 test vektoru\n"


def _kok_der_cikar() -> bytes:
    """Fixture token'ındaki KENDİNDEN İMZALI sertifika — zincirin kökü."""
    from asn1crypto import tsp

    token = tsp.TimeStampResp.load(_FIXTURE.read_bytes())["time_stamp_token"]
    for sarmal in token["content"]["certificates"]:
        cert = sarmal.chosen
        if cert.subject == cert.issuer:
            return cert.dump()
    raise AssertionError("fixture'da kendinden imzalı kök yok")


@pytest.fixture
def damgali(tmp_path: Path) -> Path:
    """GERÇEK freetsa.org damgası taşıyan bir `.hcl`."""
    import hashlib

    from asn1crypto import tsp

    from CORE.crypto import encrypt_file, generate_key
    from CORE.timestamp import TimestampInfo, attach_trailer

    kaynak = tmp_path / "vektor.bin"
    kaynak.write_bytes(_FIXTURE_PLAIN)
    anahtar = generate_key()
    hcl, _sha, _aad = encrypt_file(kaynak, anahtar, 1, hwid="H", dst=tmp_path / "v.hcl")
    token = tsp.TimeStampResp.load(_FIXTURE.read_bytes())["time_stamp_token"].dump()
    attach_trailer(hcl, TimestampInfo(
        hash_algorithm="sha256",
        hashed_hex=hashlib.sha256(_FIXTURE_PLAIN).hexdigest(),
        tsa_url="https://freetsa.org/tsr",
        token_der=token,
    ))
    return hcl


def test_UCTAN_UCA_bilinmeyen_kok_uyarili_eklenen_kok_TAM(
    yonetici_db, damgali: Path,  # type: ignore[no-untyped-def]
) -> None:
    """
    Maddenin istediği test, GERÇEK bir damgayla ve gerçek zincir yürüyüşüyle.

    Rapor katmanını doğrudan besleyen testler yukarıda; bu, deponun
    `verify_timestamp()`'e kadar gerçekten ulaştığını ölçüyor.
    """
    from CORE.timestamp_verify import verify_timestamp

    # ── 1. Depo BOŞ → uyarılı geçerli ────────────────────────────────────
    once = verify_timestamp(damgali, trusted_roots=der_listesi(yonetici_db) or None)
    assert once.valid is True
    assert once.anchor_trusted is False
    assert tr.aciklama(once).seviye == tr.SEVIYE_UYARI

    # ── 2. YANLIŞ kök eklendi → geçersiz (karar sertleşiyor) ─────────────
    yabanci, _ = _sertifika("Alakasiz CA")
    ekle(yonetici_db, yabanci, ad="yabanci.der", user_id=5)
    yanlis = verify_timestamp(damgali, trusted_roots=der_listesi(yonetici_db))
    assert yanlis.valid is False
    assert yanlis.failed_check == "trust_anchor"
    assert tr.aciklama(yanlis).seviye == tr.SEVIYE_GECERSIZ

    # ── 3. DOĞRU kök de eklendi → tam geçerli ────────────────────────────
    ekle(yonetici_db, _kok_der_cikar(), ad="freetsa.der", user_id=5)
    sonra = verify_timestamp(damgali, trusted_roots=der_listesi(yonetici_db))
    assert sonra.valid is True
    assert sonra.anchor_trusted is True
    assert tr.aciklama(sonra).seviye == tr.SEVIYE_GECERLI
    assert "doğrulandı" in tr.aciklama(sonra).baslik

    # Aynı damga, aynı dosya — DEĞİŞEN tek şey depo.
    assert once.hashed_hex == sonra.hashed_hex
    assert once.gen_time == sonra.gen_time


def test_kok_SILININCE_uyariya_geri_donuyor(yonetici_db, damgali: Path) -> None:  # type: ignore[no-untyped-def]
    """Kaldırma da çalışmalı — yoksa liste tek yönlü bir kapı olurdu."""
    from CORE.timestamp_verify import verify_timestamp

    kok = ekle(yonetici_db, _kok_der_cikar(), ad="freetsa.der", user_id=5)
    assert verify_timestamp(
        damgali, trusted_roots=der_listesi(yonetici_db)).anchor_trusted is True

    sil(yonetici_db, kok.parmak_izi, user_id=5)
    sonra = verify_timestamp(
        damgali, trusted_roots=der_listesi(yonetici_db) or None)
    assert sonra.valid is True and sonra.anchor_trusted is False


def test_ayristirma_TEK_uygulama() -> None:
    """
    CLI kendi PEM/DER ayrıştırıcısını TUTMAMALI. İki kopya zamanla
    ayrışır ve aynı sertifika bir yerde kabul edilip ötekinde reddedilir —
    bu depoda o kusur beş kez üretildi.
    """
    kaynak = (KOK / "CORE" / "verify_timestamp_cli.py").read_text(encoding="utf-8")
    agac = ast.parse(kaynak)
    cagrilar = {
        (d.func.attr if isinstance(d.func, ast.Attribute) else
         d.func.id if isinstance(d.func, ast.Name) else "")
        for d in ast.walk(agac) if isinstance(d, ast.Call)
    }
    assert "der_coz" in cagrilar, "CLI ortak ayrıştırıcıyı kullanmıyor"
    assert "load_pem_x509_certificate" not in cagrilar, (
        "CLI kendi PEM ayrıştırıcısını geri getirmiş."
    )


def test_CLI_kok_deposunu_KULLANMIYOR() -> None:
    """
    Bilinçli ayrım: CLI'ı çalıştıran denetçi tam olarak bu makineyi
    denetliyor. Güven listesini denetlediği veritabanından okumak,
    sorunun cevabını sorunun kaynağına sordurmak olurdu.
    """
    kaynak = (KOK / "CORE" / "verify_timestamp_cli.py").read_text(encoding="utf-8")
    agac = ast.parse(kaynak)
    cagrilar = {
        (d.func.attr if isinstance(d.func, ast.Attribute) else
         d.func.id if isinstance(d.func, ast.Name) else "")
        for d in ast.walk(agac) if isinstance(d, ast.Call)
    }
    assert "der_listesi" not in cagrilar and "oku" not in cagrilar, (
        "CLI ayar deposundaki kökleri okuyor — gerekçesi "
        "CORE/trusted_roots.py docstring'inde, bu ayrım bilinçli."
    )


# ══════════════════════════════════════════════════════════════════════════════
# 6. Yönetim Paneli — kullanıcı kökü GERÇEKTEN ekleyebiliyor mu
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def qapp():  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QApplication
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


@pytest.fixture(autouse=True)
def _admin_panel_canli_usb(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """
    B-064/B-066: `AdminPanel` artık her yetkili işlemden (ör.
    `_on_tsa_kok_ekle`/`_on_tsa_kok_sil`) önce `get_usb_hwid()`'i canlı
    okuyor. Bu dosyadaki panel testleri hep `_panel()`'in kullandığı
    "H" HWID'ini varsayıyor (bkz. `yonetici_db` — aynı HWID'e onaylı bir
    yönetici satırı ekliyor); o USB'nin takılı kaldığını simüle ediyoruz.
    """
    import UI.AdminPanel as _ap

    monkeypatch.setattr(_ap, "get_usb_hwid", lambda: "H")


def _panel(qapp, request):  # type: ignore[no-untyped-def]
    """
    B-064/B-066: `AdminPanel` artık kendi `_yetki_timer`'ını (3 sn) her
    örnekte başlatıyor. Kapatılmadan bırakılırsa (sadece `.close()` yeterli
    değil — QTimer C++ tarafında canlı kalabiliyor) sonraki bir Qt event
    loop'unda (ör. başka bir dosyada `.exec()` çağrılınca) art arda birikmiş
    tüm bu zamanlayıcılar birden tetiklenip GERÇEK `get_usb_hwid()`/DB
    çağrılarıyla tüm test takımını kilitleyebiliyor — ölçüldü. `request`
    finalizer'ıyla test SONUCUNDAN bağımsız (assertion patlasa bile) durdurma
    garanti ediliyor.
    """
    from UI.AdminPanel import AdminPanel
    panel = AdminPanel("H", role="Yönetici")
    request.addfinalizer(panel._yetki_timer.stop)
    return panel


def test_panel_bos_depoyu_ANLASILIR_gosteriyor(qapp, yonetici_db, request) -> None:  # type: ignore[no-untyped-def]
    """
    Boş liste "hiçbir şey yok" gibi değil, "henüz eklenmemiş" diye
    görünmeli — boş bir kutu, kullanıcıya durumu söylemiyor.
    """
    panel = _panel(qapp, request)
    assert panel._tsa_liste.count() == 1
    assert "eklenmemiş" in panel._tsa_liste.item(0).text()
    assert not panel._btn_tsa_sil.isEnabled()


def test_panel_eklenen_koku_LISTELIYOR(qapp, yonetici_db, sertifika, request) -> None:  # type: ignore[no-untyped-def]
    ekle(yonetici_db, sertifika[0], ad="kurum.der", user_id=5)
    panel = _panel(qapp, request)
    assert panel._tsa_liste.count() == 1
    metin = panel._tsa_liste.item(0).text()
    assert "HYCLEUS Test CA" in metin
    # Parmak izi de görünmeli: aynı konuya sahip iki kök ayırt edilebilmeli.
    assert oku(yonetici_db)[0].kisa_izi() in metin


def test_panel_silme_dugmesi_KOK_SECILINCE_aciliyor(
    qapp, yonetici_db, sertifika, request,  # type: ignore[no-untyped-def]
) -> None:
    ekle(yonetici_db, sertifika[0], ad="kurum.der", user_id=5)
    panel = _panel(qapp, request)
    assert not panel._btn_tsa_sil.isEnabled()
    panel._tsa_liste.setCurrentRow(0)
    assert panel._btn_tsa_sil.isEnabled()


def test_panel_silmeyi_UYGULUYOR(qapp, yonetici_db, sertifika, monkeypatch, request) -> None:  # type: ignore[no-untyped-def]
    """Onay kutusu yamalı; silinen şeyin GERÇEKTEN depodan gittiği ölçülüyor."""
    from PySide6.QtWidgets import QMessageBox

    ekle(yonetici_db, sertifika[0], ad="kurum.der", user_id=5)
    panel = _panel(qapp, request)
    panel._tsa_liste.setCurrentRow(0)
    monkeypatch.setattr(QMessageBox, "question",
                        staticmethod(lambda *a, **k: QMessageBox.Yes))
    panel._on_tsa_kok_sil()
    assert oku(yonetici_db) == []
    assert "eklenmemiş" in panel._tsa_liste.item(0).text()


def test_panel_ONAY_verilmezse_silmiyor(qapp, yonetici_db, sertifika, monkeypatch, request) -> None:  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QMessageBox

    ekle(yonetici_db, sertifika[0], ad="kurum.der", user_id=5)
    panel = _panel(qapp, request)
    panel._tsa_liste.setCurrentRow(0)
    monkeypatch.setattr(QMessageBox, "question",
                        staticmethod(lambda *a, **k: QMessageBox.No))
    panel._on_tsa_kok_sil()
    assert len(oku(yonetici_db)) == 1, "onay verilmeden silinmiş"


def test_SECURITY_md_kok_deposunu_anlatiyor() -> None:
    """
    Ayar ADI belgede sabitten okunuyor, elle yazılmıyor: `SETTING`
    değişirse bu test düşer ve §4.9'u güncellemeye zorlar (B-017 sınıfı).
    """
    metin = (KOK / "SECURITY.md").read_text(encoding="utf-8")
    assert metin.count(SETTING) == 2, (
        f"§4.9 {SETTING!r} ayarını iki dilde de anmalı "
        f"(bulunan: {metin.count(SETTING)})."
    )
    # Kazanımın SINIRI da yazılmalı — depo şifresiz veritabanında.
    assert metin.count("B-044") == 2, "listenin makine dışına taşınmadığı yazılmalı"
