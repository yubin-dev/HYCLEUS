"""
Testler için yerel, GERÇEKTEN İMZALAYAN bir Zaman Damgası Otoritesi.

Bu bir mock DEĞİL. Gerçek bir kök CA ve gerçek bir TSA imzalama sertifikası
üretiyor, TSTInfo'yu DER olarak kodluyor, imzalı öznitelikleri kuruyor ve
`cryptography` ile GERÇEK bir imza atıyor. Üretilen token, freetsa.org'un
verdiğiyle aynı yapıda ve aynı doğrulama yolundan geçiyor.

Neden imzasız bir sahte yetmedi
-------------------------------
Adım 1'de doğrulama yoktu, imzasız bir token yeterliydi. 3.1b imzayı
doğruluyor; imzasız bir sahte artık hiçbir şey sınamaz. Daha önemlisi:
bozma senaryolarını (yanlış EKU, süresi dolmuş sertifika, kırık zincir,
başka bir anahtarla imza) ancak sertifikaları kendimiz üretirsek
kurabiliriz. Gerçek freetsa.org token'ı sabit bir vektör olarak duruyor
ve o da ayrıca test ediliyor — ikisi birbirinin yerine değil, tamamlayıcısı.

Anahtarlar test başına değil MODÜL BAŞINA üretiliyor: RSA-2048 anahtar
üretimi yavaş ve her testte yenilemek paketi dakikalara çıkarırdı.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any

from asn1crypto import algos, cms, core, tsp, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)

#: Token'ların varsayılan damga zamanı — deterministik olsun diye sabit.
DEFAULT_GEN_TIME = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)

DEFAULT_POLICY = "1.2.3.4.1"


@dataclass(frozen=True)
class Authority:
    """Bir kök CA + ona bağlı bir TSA imzalama sertifikası."""

    ca_cert: x509.Certificate
    ca_key: Any
    tsa_cert: x509.Certificate
    tsa_key: Any

    @property
    def ca_der(self) -> bytes:
        return self.ca_cert.public_bytes(serialization.Encoding.DER)

    @property
    def ca_pem(self) -> bytes:
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HYCLEUS Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def build_authority(
    *,
    ca_cn: str = "HYCLEUS Test Root CA",
    tsa_cn: str = "HYCLEUS Test TSA",
    tsa_not_before: datetime | None = None,
    tsa_not_after: datetime | None = None,
    timestamping_eku: bool = True,
    tsa_key_type: str = "ec",
    sign_with_wrong_ca: Any = None,
) -> Authority:
    """
    Kök CA + TSA sertifikası üretir.

    Args:
        tsa_not_before / tsa_not_after: Geçerlilik penceresi. Süresi dolmuş
            sertifika senaryosunu kurmak için.
        timestamping_eku: False ise TSA sertifikası `timeStamping` EKU'suz
            üretilir — RFC 3161 §2.3 ihlali, doğrulama reddetmeli.
        tsa_key_type: "ec" ya da "rsa" — iki imza yolu da sınanabilsin.
        sign_with_wrong_ca: Verilirse TSA sertifikası bu (cert, key) ikilisiyle
            imzalanır ama issuer alanı yine `ca_cn`'i gösterir → kırık zincir.
    """
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = _name(ca_cn)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_EPOCH)
        .not_valid_after(_EPOCH + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    tsa_key = (
        ec.generate_private_key(ec.SECP256R1())
        if tsa_key_type == "ec"
        else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(tsa_cn))
        .issuer_name(ca_subject)
        .public_key(tsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(tsa_not_before or _EPOCH)
        .not_valid_after(tsa_not_after or (_EPOCH + timedelta(days=3650)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if timestamping_eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )

    imzalayan_key = sign_with_wrong_ca[1] if sign_with_wrong_ca else ca_key
    tsa_cert = builder.sign(imzalayan_key, hashes.SHA256())

    return Authority(ca_cert=ca_cert, ca_key=ca_key, tsa_cert=tsa_cert, tsa_key=tsa_key)


@lru_cache(maxsize=1)
def default_authority() -> Authority:
    """
    Testlerin çoğunun paylaştığı otorite.

    Önbellekli: RSA-2048 üretimi yavaş, her testte yenilemek paketi
    dakikalara çıkarırdı. Bozma senaryoları kendi otoritesini kuruyor.
    """
    return build_authority()


def _sign(key: Any, data: bytes) -> tuple[bytes, algos.SignedDigestAlgorithm]:
    """Veriyi imzalar; (imza, algoritma tanımlayıcısı) döndürür."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(hashes.SHA256())), algos.SignedDigestAlgorithm(
            {"algorithm": "sha256_ecdsa"}
        )
    from cryptography.hazmat.primitives.asymmetric import padding

    return key.sign(data, padding.PKCS1v15(), hashes.SHA256()), algos.SignedDigestAlgorithm(
        {"algorithm": "sha256_rsa"}
    )


def build_token(
    digest: bytes,
    nonce: int | None = None,
    *,
    authority: Authority | None = None,
    gen_time: datetime | None = None,
    policy: str = DEFAULT_POLICY,
    hash_algorithm: str = "sha256",
    include_certs: bool = True,
    include_ca: bool = True,
    serial_number: int = 1,
    signer_count: int = 1,
) -> bytes:
    """
    GERÇEKTEN İMZALI bir RFC 3161 TimeStampToken (ContentInfo DER) üretir.

    Args:
        include_certs: False ise hiç sertifika gömülmez — çevrimdışı
            doğrulamanın imkânsız olduğu senaryo.
        include_ca: False ise yalnızca imzalama sertifikası gömülür, kök
            yok — zincir tamamlanamaz.
        signer_count: 1 dışında bir değer RFC 3161 ihlali kurar.
    """
    auth = authority or default_authority()
    gen = gen_time or DEFAULT_GEN_TIME

    tst_fields: dict = {
        "version": "v1",
        "policy": policy,
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": hash_algorithm}),
            "hashed_message": digest,
        }),
        "serial_number": serial_number,
        "gen_time": gen,
    }
    if nonce is not None:
        tst_fields["nonce"] = core.Integer(nonce)
    tst_der = tsp.TSTInfo(tst_fields).dump()

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            "type": "content_type",
            "values": cms.SetOfContentType([cms.ContentType("tst_info")]),
        }),
        cms.CMSAttribute({
            "type": "signing_time",
            "values": cms.SetOfTime([cms.Time({"utc_time": gen})]),
        }),
        cms.CMSAttribute({
            "type": "message_digest",
            "values": cms.SetOfOctetString([
                core.OctetString(hashlib.sha256(tst_der).digest())
            ]),
        }),
    ])

    # RFC 5652 §5.4: imza, [0] IMPLICIT değil SET OF (0x31) kodlaması üzerinden.
    signature, sig_alg = _sign(auth.tsa_key, signed_attrs.untag().dump())

    tsa_asn1 = asn1_x509.Certificate.load(
        auth.tsa_cert.public_bytes(serialization.Encoding.DER)
    )
    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": tsa_asn1.issuer,
                "serial_number": tsa_asn1.serial_number,
            })
        }),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": sig_alg,
        "signature": signature,
    })

    certs: list = []
    if include_certs:
        certs.append(tsa_asn1)
        if include_ca:
            certs.append(
                asn1_x509.Certificate.load(
                    auth.ca_cert.public_bytes(serialization.Encoding.DER)
                )
            )

    signed_data: dict = {
        "version": "v3",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": cms.EncapsulatedContentInfo({
            "content_type": "tst_info",
            "content": cms.ParsableOctetString(tst_der),
        }),
        "signer_infos": [signer_info] * signer_count,
    }
    if certs:
        signed_data["certificates"] = certs

    return cms.ContentInfo({
        "content_type": "signed_data",
        "content": cms.SignedData(signed_data),
    }).dump()


def build_response(
    digest: bytes,
    nonce: int | None = None,
    *,
    status: str = "granted",
    **token_kwargs,
) -> bytes:
    """İmzalı token'ı bir TimeStampResp içine sarar."""
    return tsp.TimeStampResp({
        "status": tsp.PKIStatusInfo({"status": status}),
        "time_stamp_token": cms.ContentInfo.load(
            build_token(digest, nonce, **token_kwargs)
        ),
    }).dump()


class FakeTSA:
    """
    İsteği GERÇEKTEN ayrıştırıp ona uygun İMZALI yanıt üreten yerel TSA.

    `timestamp_file(transport=...)` imzasına uyuyor. Aldığı her isteği
    kaydediyor, böylece testler yalnızca sonuca değil GÖNDERİLENE de
    bakabiliyor.
    """

    def __init__(self, *, status: str = "granted", **token_kwargs) -> None:
        self.requests: list[tsp.TimeStampReq] = []
        self.urls: list[str] = []
        self.status = status
        self.token_kwargs = token_kwargs
        self.override_digest: bytes | None = None
        self.override_nonce: int | None = None

    def __call__(self, url: str, body: bytes, timeout: int) -> bytes:
        request = tsp.TimeStampReq.load(body)
        self.requests.append(request)
        self.urls.append(url)
        digest = self.override_digest or bytes(
            request["message_imprint"]["hashed_message"].native
        )
        nonce = (
            self.override_nonce
            if self.override_nonce is not None
            else request["nonce"].native
        )
        return build_response(
            digest, nonce, status=self.status, **self.token_kwargs
        )

    @property
    def last_digest(self) -> bytes:
        return bytes(self.requests[-1]["message_imprint"]["hashed_message"].native)
