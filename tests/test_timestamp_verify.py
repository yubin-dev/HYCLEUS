"""
CORE.timestamp_verify — çevrimdışı RFC 3161 doğrulama testleri.

Bu paketin ana iddiası tek cümle: **damga artık kanıt.** İddiayı üç ayrı
açıdan sınıyor:

  1. GERÇEK bir freetsa.org token'ı, gerçek bir `.hcl` dosyasının üzerinde,
     uçtan uca doğrulanıyor (`tests/data/freetsa_response.der`).
  2. Yerel bir otorite (`tests/tsa_fixtures.py`) gerçekten imzalayan
     token'lar üretiyor; bozma senaryoları ancak sertifikaları kendimiz
     üretirsek kurulabilir — süresi dolmuş sertifika, eksik EKU, kırık
     zincir, başka anahtarla imza.
  3. Doğrulamanın ağa ÇIKMADIĞI, soket katmanında kanıtlanıyor.

Ağ yok
------
`no_network` fixture'ı `socket.socket`'i patlatıyor ve doğrulama testlerinde
AUTOUSE. Yani "çevrimdışı çalışıyor" bir iddia değil, her testte uygulanan
bir kısıt: kod bir yerde ağa uzanırsa test çöker.
"""
from __future__ import annotations

import hashlib
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from asn1crypto import cms, core as asn1_core, tsp, x509 as asn1_x509
from tsa_fixtures import (
    DEFAULT_GEN_TIME,
    FakeTSA,
    build_authority,
    build_token,
    default_authority,
)

from CORE import crypto
from CORE.crypto import encrypt_file, generate_key
from CORE.timestamp import (
    TimestampInfo,
    attach_trailer,
    read_trailer,
    timestamp_file,
)
from CORE.timestamp_verify import verify_timestamp, verify_token

_USER_ID = 11
_HWID = "TEST-HWID-VERIFY"

_FIXTURE = Path(__file__).parent / "data" / "freetsa_response.der"
_FIXTURE_PLAIN = b"HYCLEUS RFC 3161 test vektoru\n"
_FIXTURE_DIGEST = hashlib.sha256(_FIXTURE_PLAIN).digest()


# ══════════════════════════════════════════════════════════════════════════════
# Fixture'lar
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture(autouse=True)
def _quarantine_to_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    out = tmp_path / "quarantine"
    out.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", out)
    return out


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    ÇEVRİMDIŞILIĞIN KANITI — soket açmayı tümüyle yasaklar.

    `requests.post`'u yamalamak yetmezdi: kod başka bir yoldan (urllib, ham
    soket, OCSP/CRL getirme) ağa çıkabilirdi. Soketi kesmek, hangi
    kütüphaneyi kullanırsa kullansın yakalar.
    """
    def _yasak(*args, **kwargs):
        raise AssertionError(
            "Doğrulama ağa çıkmaya çalıştı — çevrimdışı olması gerekiyor."
        )

    monkeypatch.setattr(socket, "socket", _yasak)
    monkeypatch.setattr(socket, "create_connection", _yasak)


@pytest.fixture
def key() -> bytes:
    return generate_key()


def _hcl(tmp_path: Path, key: bytes, content: bytes, name: str = "belge.bin") -> Path:
    src = tmp_path / name
    src.write_bytes(content)
    dst, _sha, _aad = encrypt_file(src, key, _USER_ID, hwid=_HWID)
    return dst


@pytest.fixture
def stamped(tmp_path: Path, key: bytes) -> Path:
    """Yerel otoritenin imzaladığı, damgalı bir .hcl dosyası."""
    path = _hcl(tmp_path, key, b"gizli rapor icerigi" * 100)
    timestamp_file(path, transport=FakeTSA())
    return path


@pytest.fixture
def real_stamped(tmp_path: Path, key: bytes) -> Path:
    """
    GERÇEK freetsa.org token'ı taşıyan bir .hcl dosyası.

    Düz metin, fixture üretilirken kullanılanın aynısı; dolayısıyla AAD'deki
    original_sha256 token'ın damgaladığı özetle birebir eşleşiyor. Bu, sahte
    hiçbir parçası olmayan tam bir uçtan uca senaryo.
    """
    path = _hcl(tmp_path, key, _FIXTURE_PLAIN, name="vektor.bin")
    token = tsp.TimeStampResp.load(_FIXTURE.read_bytes())["time_stamp_token"].dump()
    attach_trailer(path, TimestampInfo(
        hash_algorithm="sha256",
        hashed_hex=_FIXTURE_DIGEST.hex(),
        tsa_url="https://freetsa.org/tsr",
        token_der=token,
    ))
    return path


def _retrailer(path: Path, **degisiklik) -> None:
    """Fragmanı yeni değerlerle yeniden yazar (eskisini kırpar)."""
    mevcut = read_trailer(path)
    assert mevcut is not None
    ham = path.read_bytes()
    from CORE.timestamp import encode_trailer

    govde = ham[: len(ham) - len(encode_trailer(mevcut))]
    path.write_bytes(govde)
    attach_trailer(path, TimestampInfo(**{**mevcut.__dict__, **degisiklik}))


# ══════════════════════════════════════════════════════════════════════════════
# 1. Gerçek freetsa.org token'ı — uçtan uca
# ══════════════════════════════════════════════════════════════════════════════


def test_a_real_freetsa_stamp_verifies_end_to_end(real_stamped: Path) -> None:
    """
    ANA TEST: gerçek bir TSA'nın imzası, gerçek bir dosyanın üzerinde,
    ağsız doğrulanıyor.
    """
    sonuc = verify_timestamp(real_stamped)

    assert sonuc.valid, sonuc.reason
    assert sonuc.hashed_hex == _FIXTURE_DIGEST.hex()
    assert sonuc.gen_time == datetime(2026, 8, 13, 13, 54, 11, tzinfo=timezone.utc)
    assert "freetsa" in (sonuc.tsa_name or "").lower()
    assert sonuc.tsa_url == "https://freetsa.org/tsr"


def test_the_real_chain_is_walked_to_its_root(real_stamped: Path) -> None:
    sonuc = verify_timestamp(real_stamped)
    assert len(sonuc.chain_subjects) == 2
    assert sonuc.anchor_subject == sonuc.chain_subjects[-1]


def test_every_check_runs_on_the_real_token(real_stamped: Path) -> None:
    """Doğrulamanın kaç adımdan geçtiği görünür olmalı."""
    sonuc = verify_timestamp(real_stamped)
    assert set(sonuc.checks) >= {
        "parse", "signer_info", "signer_certificate", "content_type",
        "message_digest", "signature", "digest_match", "eku", "validity",
        "certificate_chain",
    }


def test_the_real_stamp_verifies_with_its_own_root_as_trust_anchor(
    real_stamped: Path,
) -> None:
    """
    Kök dışarıdan verildiğinde `anchor_trusted` True oluyor.

    Burada kök yine token'dan alınıyor — testin amacı güven KARARINI değil,
    karşılaştırma MEKANİZMASINI sınamak.
    """
    token = read_trailer(real_stamped).token_der  # type: ignore[union-attr]
    certs = cms.ContentInfo.load(token)["content"]["certificates"]
    kokler = [c.chosen.dump() for c in certs if c.chosen.ca]

    sonuc = verify_timestamp(real_stamped, trusted_roots=kokler)
    assert sonuc.valid and sonuc.anchor_trusted


# ══════════════════════════════════════════════════════════════════════════════
# 2. Çevrimdışılık
# ══════════════════════════════════════════════════════════════════════════════


def test_verification_opens_no_socket(stamped: Path) -> None:
    """
    `no_network` autouse olduğu için aslında BÜTÜN bu paket bunu sınıyor.
    Bu test niyeti açıkça yazıyor: soket yasağı yürürlükte ve doğrulama
    yine de geçiyor.
    """
    with pytest.raises(AssertionError, match="ağa çıkmaya"):
        socket.socket()

    assert verify_timestamp(stamped).valid


def test_verification_needs_no_key(stamped: Path) -> None:
    """Doğrulama anahtar istemiyor — özet AAD'de, AAD şifresiz."""
    assert verify_timestamp(stamped).valid


# ══════════════════════════════════════════════════════════════════════════════
# 3. Bozma senaryoları — token
# ══════════════════════════════════════════════════════════════════════════════


def test_a_tampered_token_is_rejected(stamped: Path) -> None:
    """Token'ın imzasını taşıyan byte'lar değişirse doğrulama düşmeli."""
    info = read_trailer(stamped)
    assert info is not None
    bozuk = bytearray(info.token_der)
    bozuk[-10] ^= 0xFF  # imza bölgesi
    _retrailer(stamped, token_der=bytes(bozuk))

    sonuc = verify_timestamp(stamped)
    assert not sonuc.valid
    assert sonuc.failed_check in ("signature", "parse")


def test_a_token_signed_by_another_key_is_rejected(tmp_path: Path, key: bytes) -> None:
    """
    Sertifika doğru görünse bile imza başka bir anahtardansa reddedilmeli.

    İkinci bir otorite kuruluyor; sertifikası ilkininkiyle aynı adları
    taşıyor ama anahtarı farklı.
    """
    path = _hcl(tmp_path, key, b"icerik")
    digest = bytes.fromhex(_aad_digest(path))

    yabanci = build_authority()
    attach_trailer(path, TimestampInfo(
        hash_algorithm="sha256", hashed_hex=digest.hex(),
        tsa_url="https://sahte/tsr",
        token_der=build_token(digest, 1, authority=yabanci),
    ))
    # Yabancı otoritenin kendi zinciri tutarlı olduğu için doğrulama GEÇER;
    # yakalanması gereken yer güven kökü. Kendi kökümüzü dayatınca düşmeli.
    assert verify_timestamp(path).valid
    sonuc = verify_timestamp(path, trusted_roots=[default_authority().ca_der])
    assert not sonuc.valid
    assert sonuc.failed_check == "trust_anchor"


def test_a_tampered_signing_certificate_is_rejected(tmp_path: Path, key: bytes) -> None:
    """
    İmzalama sertifikasının içeriği değişirse CA'nın onun üzerindeki
    imzası tutmaz.

    Sertifikanın adı (`common_name`) değiştiriliyor — DER geçerli kalıyor
    ama `tbs_certificate` artık CA'nın imzaladığı bayt dizisi değil.
    Rastgele bir byte çevirmek yerine ALANI hedeflemek gerekiyor; rastgele
    seçim kökün kendi imzasına düşebiliyor ve orası (aşağıdaki teste bakın)
    bilerek doğrulanmıyor.
    """
    path = _hcl(tmp_path, key, b"icerik")
    digest = bytes.fromhex(_aad_digest(path))

    içerik = cms.ContentInfo.load(build_token(digest, 1))
    certs = içerik["content"]["certificates"]
    imzalayan = next(c for c in certs if not c.chosen.ca)
    tbs = imzalayan.chosen["tbs_certificate"]
    for rdn in tbs["subject"].chosen:
        for tav in rdn:
            if tav["type"].native == "common_name":
                tav["value"] = asn1_x509.DirectoryString(
                    name="utf8_string", value="Sahte TSA"
                )

    attach_trailer(path, TimestampInfo(
        hash_algorithm="sha256", hashed_hex=digest.hex(),
        tsa_url="https://x/tsr", token_der=içerik.dump(force=True),
    ))

    sonuc = verify_timestamp(path)
    assert not sonuc.valid
    assert sonuc.failed_check in ("signature", "certificate_chain")


def test_a_self_signed_root_signature_is_not_verified() -> None:
    """
    KAYITA GEÇEN DAVRANIŞ: zincir yürüyüşü kendini imzalayan kökte duruyor
    ve kökün KENDİ imzasını doğrulamıyor.

    Bu bir eksik değil, standart PKI davranışı: kendini imzalayan bir
    sertifikanın imzası bir güven ifadesi taşımaz — onu doğrulamak yalnızca
    "kendi kendini onaylıyor" der. Kökün güvenilirliği `trusted_roots` ile,
    yani dosyanın DIŞINDAN kararlaştırılıyor.

    Test bunu düzeltmiyor, sabitliyor: biri kök doğrulamasını eklerse
    bilinçli bir karar olarak görünsün.
    """
    digest = hashlib.sha256(b"x").digest()
    token = bytearray(build_token(digest, 1))

    içerik = cms.ContentInfo.load(bytes(token))
    kök = next(c for c in içerik["content"]["certificates"] if c.chosen.ca)
    bozuk_imza = bytearray(kök.chosen["signature_value"].native)
    bozuk_imza[0] ^= 0xFF
    kök.chosen["signature_value"] = asn1_core.OctetBitString(bytes(bozuk_imza))

    sonuc = verify_token(içerik.dump(force=True), expected_digest=digest)
    assert sonuc.valid, "kökün kendi imzası bilerek doğrulanmıyor"


def test_a_broken_certificate_chain_is_rejected(tmp_path: Path, key: bytes) -> None:
    """
    TSA sertifikası, issuer alanının işaret ettiği CA tarafından
    imzalanmamışsa zincir doğrulaması düşmeli.
    """
    sahte_ca = build_authority()
    kirik = build_authority(
        sign_with_wrong_ca=(sahte_ca.ca_cert, sahte_ca.ca_key)
    )
    path = _hcl(tmp_path, key, b"icerik")
    digest = bytes.fromhex(_aad_digest(path))
    attach_trailer(path, TimestampInfo(
        hash_algorithm="sha256", hashed_hex=digest.hex(),
        tsa_url="https://x/tsr",
        token_der=build_token(digest, 1, authority=kirik),
    ))

    sonuc = verify_timestamp(path)
    assert not sonuc.valid
    assert sonuc.failed_check == "certificate_chain"


def test_the_tstinfo_cannot_be_swapped(tmp_path: Path, key: bytes) -> None:
    """
    `message-digest` imzalı özniteliği TSTInfo'yu imzaya bağlıyor.

    TSTInfo değiştirilirse (ör. tarih ileri alınırsa) imza aynı kalsa bile
    özet tutmaz.
    """
    path = _hcl(tmp_path, key, b"icerik")
    digest = bytes.fromhex(_aad_digest(path))
    token = build_token(digest, 1)

    içerik = cms.ContentInfo.load(token)
    signed = içerik["content"]
    sahte_tst = tsp.TSTInfo.load(signed["encap_content_info"]["content"].contents)
    sahte_tst["gen_time"] = datetime(2020, 1, 1, tzinfo=timezone.utc)
    signed["encap_content_info"]["content"] = cms.ParsableOctetString(sahte_tst.dump())

    attach_trailer(path, TimestampInfo(
        hash_algorithm="sha256", hashed_hex=digest.hex(),
        tsa_url="https://x/tsr", token_der=içerik.dump(),
    ))

    sonuc = verify_timestamp(path)
    assert not sonuc.valid
    assert sonuc.failed_check == "message_digest"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Sertifika kuralları
# ══════════════════════════════════════════════════════════════════════════════


def test_a_certificate_without_the_timestamping_eku_is_rejected() -> None:
    """RFC 3161 §2.3 — sıradan bir TLS sertifikası damga imzalayamaz."""
    digest = hashlib.sha256(b"x").digest()
    token = build_token(digest, 1, authority=build_authority(timestamping_eku=False))

    sonuc = verify_token(token, expected_digest=digest)
    assert not sonuc.valid
    assert sonuc.failed_check == "eku"
    assert "timeStamping" in (sonuc.reason or "")


def test_a_certificate_expired_at_stamping_time_is_rejected() -> None:
    """
    Sertifika, DAMGANIN ATILDIĞI anda geçerli olmalı.

    Geçerlilik penceresi genTime'dan önce bitiyor → damga geçersiz.
    """
    digest = hashlib.sha256(b"x").digest()
    süresi_dolmuş = build_authority(
        tsa_not_before=DEFAULT_GEN_TIME - timedelta(days=400),
        tsa_not_after=DEFAULT_GEN_TIME - timedelta(days=1),
    )
    sonuc = verify_token(
        build_token(digest, 1, authority=süresi_dolmuş), expected_digest=digest
    )
    assert not sonuc.valid
    assert sonuc.failed_check == "validity"


def test_a_certificate_that_expired_after_stamping_is_still_valid() -> None:
    """
    ÖNEMLİ AYRIM: bugün süresi dolmuş bir TSA sertifikası, o tarihte
    geçerliyken atılmış bir damgayı GEÇERSİZLEŞTİRMEZ.

    Zaman damgasının bütün anlamı bu — geçmişteki bir anı kanıtlıyor.
    Sertifikanın bugünkü durumuna bakmak, damgaları sertifika ömrüyle
    sınırlandırır ve özelliği işlevsiz kılardı.
    """
    digest = hashlib.sha256(b"x").digest()
    otorite = build_authority(
        tsa_not_before=DEFAULT_GEN_TIME - timedelta(days=10),
        tsa_not_after=DEFAULT_GEN_TIME + timedelta(days=10),
    )
    token = build_token(digest, 1, authority=otorite)

    assert verify_token(token, expected_digest=digest).valid

    # Bugünü zorlarsak düşüyor — varsayılanın genTime olması bilinçli.
    çok_sonra = verify_token(
        token, expected_digest=digest, at_time=DEFAULT_GEN_TIME + timedelta(days=365)
    )
    assert not çok_sonra.valid
    assert çok_sonra.failed_check == "validity"


def test_a_token_without_certificates_cannot_be_verified() -> None:
    digest = hashlib.sha256(b"x").digest()
    sonuc = verify_token(build_token(digest, 1, include_certs=False), expected_digest=digest)
    assert not sonuc.valid
    assert sonuc.failed_check == "signer_certificate"


def test_a_chain_that_stops_short_is_valid_but_unanchored() -> None:
    """
    Kök gömülü değilse zincir imzalama sertifikasında duruyor. Bu, imzanın
    geçersiz olduğu anlamına GELMEZ — ama güven kökü de yoktur.
    """
    digest = hashlib.sha256(b"x").digest()
    sonuc = verify_token(build_token(digest, 1, include_ca=False), expected_digest=digest)
    assert sonuc.valid
    assert sonuc.chain_subjects == ["HYCLEUS Test TSA"]
    assert sonuc.anchor_trusted is False

    dayatilmis = verify_token(
        build_token(digest, 1, include_ca=False),
        expected_digest=digest,
        trusted_roots=[default_authority().ca_der],
    )
    assert not dayatilmis.valid
    assert dayatilmis.failed_check == "trust_anchor"


def test_multiple_signers_are_rejected() -> None:
    """RFC 3161 tam olarak bir imzalayan bekliyor."""
    digest = hashlib.sha256(b"x").digest()
    sonuc = verify_token(build_token(digest, 1, signer_count=2), expected_digest=digest)
    assert not sonuc.valid
    assert sonuc.failed_check == "signer_info"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Dosya ↔ damga bağı
# ══════════════════════════════════════════════════════════════════════════════


def _aad_digest(path: Path) -> str:
    from CORE.timestamp import read_aad

    return str(read_aad(path)["original_sha256"])


def test_another_files_stamp_is_rejected(tmp_path: Path, key: bytes) -> None:
    """
    ASIL SENARYO: A dosyasının damgası B dosyasına kopyalanıyor.

    Token kriptografik olarak kusursuz; ama damgaladığı özet B'nin düz
    metnine ait değil. Reddedilmeli — yoksa herhangi bir içeriğe herhangi
    bir tarih iliştirilebilirdi.
    """
    a = _hcl(tmp_path, key, b"A dosyasinin icerigi", name="a.bin")
    b = _hcl(tmp_path, key, b"B dosyasinin icerigi", name="b.bin")
    timestamp_file(a, transport=FakeTSA())

    a_info = read_trailer(a)
    assert a_info is not None
    attach_trailer(b, a_info)  # A'nın damgası B'ye yapıştırılıyor

    sonuc = verify_timestamp(b)
    assert not sonuc.valid
    assert sonuc.failed_check == "trailer_aad_mismatch"
    assert "kopyalanmış olabilir" in (sonuc.reason or "")


def test_a_trailer_hash_that_lies_about_the_token_is_caught(
    tmp_path: Path, key: bytes
) -> None:
    """
    Fragmandaki `hashed_hex` AAD'ye uydurulsa bile token'daki imprint
    farklıysa yakalanmalı — iki alan birbirinden bağımsız kontrol ediliyor.
    """
    path = _hcl(tmp_path, key, b"gercek icerik")
    baska = hashlib.sha256(b"baska icerik").digest()
    attach_trailer(path, TimestampInfo(
        hash_algorithm="sha256",
        hashed_hex=_aad_digest(path),          # AAD ile uyumlu (yalan)
        tsa_url="https://x/tsr",
        token_der=build_token(baska, 1),       # ama token başkasını damgalamış
    ))

    sonuc = verify_timestamp(path)
    assert not sonuc.valid
    assert sonuc.failed_check == "digest_match"


def test_modifying_the_plaintext_breaks_the_stamp(tmp_path: Path, key: bytes) -> None:
    """
    Dosya yeniden şifrelenirse AAD'deki özet değişir ve eski damga artık
    eşleşmez.
    """
    path = _hcl(tmp_path, key, b"ilk surum")
    timestamp_file(path, transport=FakeTSA())
    info = read_trailer(path)
    assert info is not None

    yeni = _hcl(tmp_path, key, b"degistirilmis surum", name="v2.bin")
    attach_trailer(yeni, info)

    assert verify_timestamp(yeni).valid is False


def test_an_unstamped_file_reports_no_timestamp(tmp_path: Path, key: bytes) -> None:
    sonuc = verify_timestamp(_hcl(tmp_path, key, b"damgasiz"))
    assert not sonuc.valid
    assert sonuc.failed_check == "no_timestamp"
    assert "damgalı değil" in (sonuc.reason or "")


def test_a_stripped_trailer_is_indistinguishable_from_never_stamped(
    stamped: Path, tmp_path: Path, key: bytes
) -> None:
    """
    §4.9'daki DÜRÜST SINIR — bir iddia değil, kabul edilmiş davranış.

    Fragman silinince doğrulama "damgalı değil" diyor; "damgası silinmiş"
    DİYEMİYOR, çünkü dosyada bunu ayırt edecek bir şey kalmıyor.
    """
    from CORE.timestamp import encode_trailer

    info = read_trailer(stamped)
    assert info is not None
    ham = stamped.read_bytes()
    stamped.write_bytes(ham[: len(ham) - len(encode_trailer(info))])

    silinmis = verify_timestamp(stamped)
    hic = verify_timestamp(_hcl(tmp_path, key, b"hic damgalanmadi", name="c.bin"))
    assert silinmis.failed_check == hic.failed_check == "no_timestamp"


def test_a_non_hcl_file_reports_a_clear_error(tmp_path: Path) -> None:
    duz = tmp_path / "duz.txt"
    duz.write_bytes(b"bu bir hcl degil")
    sonuc = verify_timestamp(duz)
    assert not sonuc.valid
    assert sonuc.failed_check == "trailer"


# ══════════════════════════════════════════════════════════════════════════════
# 6. Sonuç nesnesi
# ══════════════════════════════════════════════════════════════════════════════


def test_summary_reads_clearly_when_valid(real_stamped: Path) -> None:
    özet = verify_timestamp(real_stamped).summary()
    assert özet.startswith("GEÇERLİ")
    assert "kök doğrulanmadı" in özet


def test_summary_reads_clearly_when_invalid(tmp_path: Path, key: bytes) -> None:
    özet = verify_timestamp(_hcl(tmp_path, key, b"x")).summary()
    assert özet.startswith("GEÇERSİZ")


def test_trust_is_reported_separately_from_validity(stamped: Path) -> None:
    """
    `valid` ile `anchor_trusted` AYRI alanlar. Tek bayrağa toplamak, kökün
    dosyadan geldiği gerçeğini gizlerdi.
    """
    sonuc = verify_timestamp(stamped)
    assert sonuc.valid is True
    assert sonuc.anchor_trusted is False
