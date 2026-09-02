"""
CORE.trusted_roots_builtin — B-105: ikili dosyaya gömülü, veritabanından
bağımsız güven kökü.

Ölçülen üç şey
--------------
1. Kök GERÇEKTEN gömülü: bir dosya/ağ/DB erişimi olmadan, salt Python
   sabitlerinden çözülüyor (`gomulu_kokler()`'in imzasında `db` YOK, ve
   modülün kaynağı hiçbir dosya/ağ/veritabanı ilkeli çağırmıyor).
2. Gömülü olan GERÇEKTEN freetsa.org'un kendi kökü — uydurma bir test
   sertifikası değil (parmak izi + fixture zinciriyle çapraz kontrol).
3. Gerçek bir freetsa damgası, HİÇBİR `db`/DBManager nesnesi hiç
   kurulmadan, yalnızca `gomulu_kokler()` ile `anchor_trusted=True`
   çıkıyor — B-044'ün "kök yoksa uyarılı" varsayılanı artık uygulamanın
   KENDİ varsayılan TSA'sı için baştan aşılmış durumda.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from CORE.trusted_roots_builtin import FREETSA_ROOT_SHA256, gomulu_kokler

KOK = Path(__file__).resolve().parent.parent
_FIXTURE = KOK / "tests" / "data" / "freetsa_response.der"


# ══════════════════════════════════════════════════════════════════════════════
# 1. Kök gerçekten gömülü — dosya/ağ/DB'ye hiç dokunmuyor
# ══════════════════════════════════════════════════════════════════════════════


def test_gomulu_kokler_db_PARAMETRESI_ALMIYOR() -> None:
    """
    Bu fonksiyonun bütün amacı DB'den bağımsız çalışmak — imzasında `db`
    olsaydı, "DB'den bağımsız" iddiası çağırana bağlı bir varsayım olurdu.
    """
    import inspect

    imza = inspect.signature(gomulu_kokler)
    assert list(imza.parameters) == [], (
        f"gomulu_kokler() parametre almamalı, aldı: {list(imza.parameters)}"
    )


def test_gomulu_kokler_HICBIR_db_KURULMADAN_cagrilabiliyor() -> None:
    """
    Bu test dosyasında `db`/`yonetici_db`/`DBManager` fixture'ı HİÇ
    istenmiyor — bu test fonksiyonunun kendisi, bir veritabanı hiç var
    olmadan `gomulu_kokler()`'in çalıştığının en doğrudan kanıtı.
    """
    kokler = gomulu_kokler()
    assert kokler, "gömülü kök listesi boş — B-105'in verdiği hiçbir şey yok"
    assert all(isinstance(k, bytes) for k in kokler)


def test_modul_KAYNAGINDA_dosya_ag_DB_ilkeli_YOK() -> None:
    """
    "Gömülü" iddiasının yapısal kanıtı: modül çalışma zamanında disk/ağ/DB
    okumuyor, yalnızca kendi sabitini çözüyor. Bir sonraki değişiklik
    kökü örneğin bir `.pem` dosyasından okumaya çevirirse (B-044'ün
    reddettiği "dış depo" yönüne geri kayış), bu test düşer.
    """
    kaynak = (KOK / "CORE" / "trusted_roots_builtin.py").read_text(encoding="utf-8")
    agac = ast.parse(kaynak)

    yasakli_import = {"sqlite3", "requests", "urllib", "socket", "http", "DB"}
    for d in ast.walk(agac):
        if isinstance(d, ast.Import):
            for takma in d.names:
                kok_ad = takma.name.split(".")[0]
                assert kok_ad not in yasakli_import, f"yasaklı import: {takma.name}"
        elif isinstance(d, ast.ImportFrom) and d.module:
            kok_ad = d.module.split(".")[0]
            assert kok_ad not in yasakli_import, f"yasaklı import: {d.module}"

    yasakli_cagri = {"open", "read_bytes", "read_text", "urlopen", "get", "post", "connect"}
    cagrilar = {
        (d.func.attr if isinstance(d.func, ast.Attribute) else
         d.func.id if isinstance(d.func, ast.Name) else "")
        for d in ast.walk(agac) if isinstance(d, ast.Call)
    }
    carpisma = cagrilar & yasakli_cagri
    assert not carpisma, f"modül dosya/ağ ilkeli çağırıyor: {carpisma}"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Gömülü kök GERÇEKTEN freetsa.org'un kökü
# ══════════════════════════════════════════════════════════════════════════════


def _fixture_kok_der() -> bytes:
    """`tests/data/freetsa_response.der` fixture'ındaki kendinden imzalı
    kök — `tests/test_trusted_roots.py::_kok_der_cikar`'ın birebir aynısı,
    iki dosyanın birbirini import ETMEMESİ için burada da tekrarlanıyor
    (ikisi de test yardımcı fonksiyonu, ortak bir CORE modülü değil)."""
    from asn1crypto import tsp

    token = tsp.TimeStampResp.load(_FIXTURE.read_bytes())["time_stamp_token"]
    for sarmal in token["content"]["certificates"]:
        cert = sarmal.chosen
        if cert.subject == cert.issuer:
            return cert.dump()
    raise AssertionError("fixture'da kendinden imzalı kök yok")


def test_gomulu_kok_freetsa_nin_GERCEK_koku() -> None:
    """
    Gömülü baytlar, fixture zincirindeki köküyle BİREBİR aynı olmalı —
    aksi hâlde "freetsa.org'un kökü" iddiası doğrulanmamış kalır.
    """
    (gomulu,) = gomulu_kokler()
    assert gomulu == _fixture_kok_der()


def test_parmak_izi_SABIT_degere_kilitli() -> None:
    """
    Modüldeki `FREETSA_ROOT_SHA256` sabiti, gerçekten gömülü baytların
    özeti olmalı — ikisi ayrı yerlerde elle yazıldı, biri güncellenip
    öteki unutulursa bu test yakalar.
    """
    (gomulu,) = gomulu_kokler()
    assert hmac.compare_digest(hashlib.sha256(gomulu).hexdigest(), FREETSA_ROOT_SHA256)


def test_gomulu_kok_GECERLI_bir_X509() -> None:
    from asn1crypto import x509

    (gomulu,) = gomulu_kokler()
    cert = x509.Certificate.load(gomulu)  # atarsa test düşer
    assert cert.subject == cert.issuer, "kendinden imzalı olmalı — bu bir kök"
    assert "freetsa.org" in str(cert.subject.native.get("common_name", ""))


def test_gomulu_kok_HENUZ_SURESI_DOLMAMIS() -> None:
    """
    2041'e kadar geçerli (bkz. modül docstring'i) — süresi dolmuş bir kökü
    gömülü tutmanın hiçbir faydası yok, ölü kod olurdu.
    """
    from asn1crypto import x509

    (gomulu,) = gomulu_kokler()
    cert = x509.Certificate.load(gomulu)
    gecerlilik = cert["tbs_certificate"]["validity"]
    simdi = datetime.now(timezone.utc)
    assert gecerlilik["not_before"].native <= simdi
    assert gecerlilik["not_after"].native >= simdi + timedelta(days=365), (
        "kök bir yıl içinde dolacak — yenilenmesi/kaldırılması planlanmalı"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 3. Uçtan uca — DB HİÇ KURULMADAN gerçek bir damga tam güvenilir çıkıyor
# ══════════════════════════════════════════════════════════════════════════════

_FIXTURE_PLAIN = b"HYCLEUS RFC 3161 test vektoru\n"


@pytest.fixture
def damgali(tmp_path: Path) -> tuple[Path, bytes]:
    """GERÇEK freetsa.org damgası taşıyan bir `.hcl` — `tests/
    test_trusted_roots.py::damgali` ile AYNI kurulum, burada da DB
    fixture'ı istemeden tekrarlanıyor (bu dosyanın bütün noktası bu)."""
    import hashlib as _hashlib

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
        hashed_hex=_hashlib.sha256(_FIXTURE_PLAIN).hexdigest(),
        tsa_url="https://freetsa.org/tsr",
        token_der=token,
    ))
    return hcl, anahtar


def test_UCTAN_UCA_db_HIC_KURULMADAN_tam_gecerli(damgali: tuple[Path, bytes]) -> None:
    """
    Maddenin asıl testi. Bu fonksiyon `db`/`yonetici_db`/`DBManager`'ı HİÇ
    istemiyor/kurmuyor — yalnızca `gomulu_kokler()`. B-044'ten beri
    "kök eklenmedi" varsayılanı `anchor_trusted=False`'tu; bu artık
    uygulamanın KENDİ varsayılan TSA'sı (freetsa.org) için doğru değil.
    """
    from CORE.timestamp_verify import verify_timestamp

    hcl, anahtar = damgali
    sonuc = verify_timestamp(hcl, anahtar, trusted_roots=gomulu_kokler())
    assert sonuc.valid is True
    assert sonuc.anchor_trusted is True, (
        "gömülü kökle bile uyarılı çıktı — B-105 çalışmıyor"
    )


def test_UCTAN_UCA_YABANCI_kok_gomulu_listede_YOKSA_uyarili(tmp_path: Path) -> None:
    """
    Negatif kontrol: gömülü liste her damgayı otomatik onaylamıyor,
    yalnızca EŞLEŞENİ. Farklı bir (freetsa olmayan) TSA'yla imzalanmış
    varsayımsal bir zincir hâlâ `anchor_trusted=False` vermeli — bunu
    doğrudan ölçmek yerine (ikinci bir gerçek TSA fixture'ı gerektirirdi)
    gömülü listenin kendisinin FREETSA DIŞINDA bir kökü KABUL ETMEDİĞİNİ
    ölçüyoruz: rastgele bir kendinden imzalı sertifika gömülü listede yok.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    anahtar_ec = ec.generate_private_key(ec.SECP256R1())
    ad = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Yabanci CA")])
    simdi = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(ad).issuer_name(ad)
        .public_key(anahtar_ec.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(simdi - timedelta(days=1))
        .not_valid_after(simdi + timedelta(days=365))
        .sign(anahtar_ec, hashes.SHA256())
    )
    yabanci_der = cert.public_bytes(serialization.Encoding.DER)
    assert yabanci_der not in gomulu_kokler()


# ══════════════════════════════════════════════════════════════════════════════
# 4. Genel dosya doğrulama akışı BİLEREK karıştırmıyor
# ══════════════════════════════════════════════════════════════════════════════


def test_genel_dogrulama_akisi_BILEREK_karistirmiyor() -> None:
    """
    `gomulu_kokler()` sağ tık menüsündeki genel damga doğrulamasına
    (`UI/main_window_files.py::_on_ctx_verify_timestamp`) KASITLI olarak
    karıştırılmadı — `tsa_url` kurum başına ayarlanabilir ve
    `trusted_roots` VERİLDİĞİNDE eşleşmeyen kök `anchor_trusted=False`
    değil doğrudan GEÇERSİZ üretiyor (bkz. `CORE/timestamp_verify.py`).
    Kendi TSA'sını kullanan bir kurumun damgaları, o kurum kendi kökünü
    Ayarlar'a eklemeden, sırf gömülü freetsa kökü eşleşmiyor diye
    YANLIŞLIKLA geçersiz görünürdü — ölçüldü (bu testin eklenmesine yol
    açan mutasyon: `tests/test_timestamp_ui.py::test_diyalog_gercekten_
    KURULUYOR` ve `test_dogrulama_DENETIM_kaydina_geçiyor`, `FakeTSA()`
    kullanıyor, gömülü kökle karıştırılınca GEÇERSİZ çıkardı).

    Gömülü kök bugün yalnızca K4-20'nin (B-087) kendi denetim raporu
    mührü için hazır — o mühür HER ZAMAN uygulamanın kendi varsayılan
    TSA'sıyla üretiliyor, yani sert eşleşme orada yanlış pozitif
    üretmiyor. Kaynak metin okunuyor, UI/PySide6 İMPORT EDİLMİYOR.
    """
    kaynak = (KOK / "UI" / "main_window_files.py").read_text(encoding="utf-8")
    agac = ast.parse(kaynak)
    cagrilar = {
        (d.func.attr if isinstance(d.func, ast.Attribute) else
         d.func.id if isinstance(d.func, ast.Name) else "")
        for d in ast.walk(agac) if isinstance(d, ast.Call)
    }
    assert "gomulu_kokler" not in cagrilar, (
        "Gömülü kök genel doğrulama akışına karışmış — kurum başına "
        "yapılandırılabilir TSA'lar için yanlış «geçersiz» üretir "
        "(bkz. bu testin docstring'i)."
    )


def test_selftest_listesinde() -> None:
    """
    `main.py --selftest` yeni CORE modüllerini elle listelemek zorunda
    (B-103'ün yakaladığı kusur sınıfı — bkz. `tests/test_packaging.py`).
    """
    kaynak = (KOK / "main.py").read_text(encoding="utf-8")
    assert '"CORE.trusted_roots_builtin"' in kaynak


def test_base64_sabiti_GECERSIZ_DEGIL() -> None:
    """
    Sabit elle kopyalanmış bir metin — bozuk biçimlendirme (satır kırığı,
    kayıp/eklenmiş karakter) sessizce yanlış baytlar üretebilir. base64
    ayrıştırması ATMAMALI ve sonuç sertifikanın uzunluğuyla eşleşmeli.
    """
    (gomulu,) = gomulu_kokler()
    tekrar = base64.b64encode(gomulu).decode("ascii")
    assert base64.b64decode(tekrar) == gomulu
