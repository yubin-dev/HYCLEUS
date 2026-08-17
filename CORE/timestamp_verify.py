"""
HYCLEUS — RFC 3161 zaman damgası doğrulaması (adım 3.1b: çevrimdışı kanıt)

Bir `.hcl` dosyasının fragmanındaki token'ın imzasını, token'ın kendi
içinde taşıdığı sertifika zinciriyle doğrular. **Ağ erişimi yok** — hiçbir
yol dışarı çıkmıyor, doğrulama tamamen dosyadaki verilerle yapılıyor.

Bir önceki adım token'ı SAKLIYORDU, doğrulamıyordu. Bu adımla damga
"kayıt" olmaktan çıkıp "kanıt" hâline geliyor — aşağıdaki güven sınırı
kaydıyla.


Sertifika zinciri neden fragmanda AYRI bir alan DEĞİL
------------------------------------------------------
Plan bu adımda fragmana yeni bir sertifika alanı eklemeyi öngörüyordu.
Gerek kalmadı ve eklemek zararlı olurdu:

`build_request()` `certReq=True` gönderiyor (bir önceki adımda tam olarak
bu gerekçeyle: "token'ın kendi kendine yeter olması amaç"). RFC 3161 §2.4.2
uyarınca TSA, imzalama sertifikasını ve zincirini token'ın SignedData
yapısının `certificates` alanına koyuyor. `TimeStampResp` içinde token'dan
BAŞKA bir sertifika taşıyan alan yok — yani "yanıttaki zincir" ile
"token'daki zincir" AYNI şey. freetsa.org token'ı bunu doğruluyor:
imzalama sertifikası (EC, EKU = timeStamping) + kök CA (RSA), ikisi de
gömülü.

İkinci bir kopya saklamak yeni bir SORU üretirdi: iki liste birbirini
tutmazsa hangisi geçerli? Doğrulama zaten SignedData'nın içindekini
kullanmak zorunda, çünkü imza onun üzerinden hesaplanıyor. Fragmandaki
kopya en iyi ihtimalle ölü veri, en kötü ihtimalle yanıltıcı olurdu.

Fragman sürümü bu yüzden 0x01'de KALDI ve kap sürümü 0x02'de kaldı;
mevcut damgalı dosyalar dönüştürülmeden doğrulanıyor.

Bunun yerine güvence damgalama ANINDA veriliyor: `timestamp_file()` artık
token'ın imzalama sertifikasını gerçekten gömdüğünü kontrol ediyor. Zincir
olmadan yazılmış bir fragman, sonradan çevrimdışı doğrulanamayacak bir
fragman olurdu — hatayı aylar sonra değil, o anda vermek gerekiyor.


GÜVEN SINIRI — kök sertifika dosyadan geliyor
----------------------------------------------
Bu, doğrulamanın en önemli sınırı ve gizlenmemeli.

Doğrulanan şey zincirin İÇ TUTARLILIĞI: imzalama sertifikasının imzası
gerçekten zincirdeki CA'ya ait mi, token'ın imzası gerçekten o imzalama
sertifikasına ait mi, damgalanan özet gerçekten bu dosyanın düz metni mi.
Bunların hepsi kriptografik olarak doğrulanıyor.

Doğrulanmayan şey, zincirin ucundaki kökün GÜVENİLİR olup olmadığı. Kök,
doğrulanan dosyanın içinden geliyor. Fragmanı değiştirebilen biri kendi
kök CA'sını üretip kendi zamanını yazan tutarlı bir token üretebilir ve bu
fonksiyon ona GEÇERLİ der — çünkü matematiksel olarak geçerlidir.

Gerçek bir güven kararı, kökün DOSYADAN BAĞIMSIZ bir yerde tutulan bir
güven deposuyla karşılaştırılmasını gerektirir. `verify_timestamp()` bunun
için `trusted_roots` parametresi alıyor: verilirse zincirin kökü o kümeyle
eşleşmek ZORUNDA, verilmezse sonuç `anchor_trusted=False` ile dönüyor ve
CLI bunu ekrana yazıyor. Varsayılan sessizce "güvenli" demiyor.

Bu, §4.6'daki denetim çıpası ve §4.9'daki fragman silinebilirliği ile aynı
sınıftan bir sınır: kanıtı taşıyan şeyle kanıtı doğrulayan şey aynı yerde
duruyorsa, tek bir yazma yetkisi ikisini birden değiştirir.


Ne doğrulanıyor (sırayla)
-------------------------
1. Fragman var mı, çözülebiliyor mu
2. Token ayrıştırılabiliyor mu, tek bir SignerInfo taşıyor mu
3. SignerInfo'nun işaret ettiği sertifika token'da gömülü mü
4. `message-digest` imzalı özniteliği TSTInfo'nun özetiyle eşleşiyor mu
5. `content-type` imzalı özniteliği `id-ct-TSTInfo` mu
6. İmza, imzalama sertifikasının açık anahtarıyla doğrulanıyor mu
7. İmzalama sertifikası `timeStamping` EKU taşıyor mu (RFC 3161 §2.3)
8. Sertifikanın geçerlilik penceresi `genTime`'ı kapsıyor mu
9. Zincir: her sertifikanın imzası bir üsttekiyle doğrulanıyor mu
10. TSTInfo'daki özet, dosyanın AAD'sindeki `original_sha256` ile aynı mı
11. Fragmandaki `hashed_hex` token'la tutarlı mı

Hepsi geçerse `TimestampVerification.valid` True olur. Herhangi biri
düşerse hangi adımda düştüğü `reason` ve `failed_check` ile bildirilir —
"geçersiz" demek yetmez, NEDEN geçersiz olduğu eyleme dönüştürülebilir
olmalı.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from asn1crypto import cms, tsp, x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from CORE.timestamp import (
    TimestampError,
    TimestampInfo,
    read_aad,
    read_trailer,
    verify_merkle_path,
)

_log = logging.getLogger("hycleus.timestamp_verify")

#: RFC 3161 §2.3 — imzalama sertifikası bu EKU'yu taşımak ZORUNDA.
_EKU_TIMESTAMPING = "time_stamping"

#: id-ct-TSTInfo — `content-type` imzalı özniteliğinin taşıması gereken değer.
_CT_TSTINFO = "tst_info"

#: asn1crypto özet adı → cryptography hash nesnesi.
_HASHES: dict[str, Any] = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}

#: Zincir yürüyüşünde izin verilen en fazla adım. Kendini gösteren
#: sertifikalarla sonsuz döngü kurulabilir; sınır bunu kesiyor.
_MAX_CHAIN = 10


@dataclass(frozen=True)
class TimestampVerification:
    """
    Bir zaman damgası doğrulamasının sonucu.

    `valid` yalnızca KRİPTOGRAFİK geçerliliği anlatıyor. Zincirin kökünün
    güvenilir olup olmadığı AYRI bir alan (`anchor_trusted`) — ikisini tek
    bayrağa toplamak, modül docstring'indeki güven sınırını gizlerdi.
    """

    valid: bool
    reason: str | None = None
    failed_check: str | None = None
    gen_time: datetime | None = None
    hashed_hex: str | None = None
    tsa_url: str | None = None
    tsa_name: str | None = None
    serial_number: int | None = None
    policy: str | None = None
    anchor_trusted: bool = False
    anchor_subject: str | None = None
    chain_subjects: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """Tek satırlık insan okunur özet."""
        if not self.valid:
            return f"GEÇERSİZ — {self.reason}"
        güven = "güvenilir kök" if self.anchor_trusted else "kök doğrulanmadı"
        zaman = self.gen_time.isoformat() if self.gen_time else "?"
        return f"GEÇERLİ — {zaman} ({self.tsa_name or '?'}, {güven})"


class _Fail(Exception):
    """İç kontrol hatası — doğrulama sonucuna çevrilir."""

    def __init__(self, check: str, reason: str) -> None:
        super().__init__(reason)
        self.check = check
        self.reason = reason


# ══════════════════════════════════════════════════════════════════════════════
# Yardımcılar
# ══════════════════════════════════════════════════════════════════════════════


def _hash_for(name: str) -> Any:
    try:
        return _HASHES[name]()
    except KeyError:
        raise _Fail("hash_algorithm", f"Desteklenmeyen özet algoritması: {name}") from None


def _verify_signature(
    public_key: CertificatePublicKeyTypes,
    signature: bytes,
    data: bytes,
    algorithm: Any,
    *,
    check: str,
) -> None:
    """
    İmzayı `cryptography` ile doğrular — kripto ELLE YAZILMIYOR.

    asn1crypto yalnızca ASN.1'i çözüyor; imzanın matematiği kütüphaneye
    devrediliyor. Bir önceki turda bağımlılık gerekçesinde söylenen tam
    olarak buydu.
    """
    hash_algo = _hash_for(algorithm.hash_algo)
    kind = algorithm.signature_algo
    try:
        if kind == "ecdsa":
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise _Fail(check, "ECDSA imza ama anahtar EC değil.")
            public_key.verify(signature, data, ec.ECDSA(hash_algo))
        elif kind == "rsassa_pkcs1v15":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise _Fail(check, "RSA imza ama anahtar RSA değil.")
            public_key.verify(signature, data, padding.PKCS1v15(), hash_algo)
        elif kind == "rsassa_pss":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise _Fail(check, "RSA-PSS imza ama anahtar RSA değil.")
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hash_algo), salt_length=hash_algo.digest_size),
                hash_algo,
            )
        else:
            raise _Fail(check, f"Desteklenmeyen imza algoritması: {kind}")
    except InvalidSignature:
        raise _Fail(check, "İmza doğrulanamadı — token veya sertifika değiştirilmiş.") from None
    except UnsupportedAlgorithm as exc:
        raise _Fail(check, f"Algoritma bu ortamda desteklenmiyor: {exc}") from None


def _find_signer(
    certificates: Sequence[Any], sid: Any
) -> asn1_x509.Certificate:
    """SignerInfo'nun işaret ettiği sertifikayı gömülü zincirde bulur."""
    if sid.name == "issuer_and_serial_number":
        issuer = sid.chosen["issuer"]
        serial = sid.chosen["serial_number"].native
        for holder in certificates:
            cert = holder.chosen
            if cert.serial_number == serial and cert.issuer == issuer:
                return cert
        raise _Fail(
            "signer_certificate",
            f"İmzalayan sertifika token'da yok (seri {serial}) — "
            "TSA sertifikayı gömmemiş, çevrimdışı doğrulama mümkün değil.",
        )

    if sid.name == "subject_key_identifier":
        wanted = sid.chosen.native
        for holder in certificates:
            cert = holder.chosen
            if cert.key_identifier == wanted:
                return cert
        raise _Fail(
            "signer_certificate",
            "İmzalayan sertifika token'da yok (anahtar kimliğiyle arandı).",
        )

    raise _Fail("signer_certificate", f"Bilinmeyen SignerInfo kimliği: {sid.name}")


def _as_x509(cert: asn1_x509.Certificate) -> x509.Certificate:
    return x509.load_der_x509_certificate(cert.dump())


def _subject_of(cert: asn1_x509.Certificate) -> str:
    name = cert.subject.native
    return str(
        name.get("common_name")
        or name.get("organization_name")
        or cert.subject.human_friendly
    )


def _walk_chain(
    signer: asn1_x509.Certificate, certificates: Sequence[Any]
) -> list[asn1_x509.Certificate]:
    """
    İmzalayandan yukarı doğru zinciri kurar ve her adımın imzasını doğrular.

    Yalnızca TOKEN'DA GÖMÜLÜ sertifikalar kullanılıyor — ağ yok, sistem
    güven deposu yok. Zincir kendini imzalayan bir sertifikada ya da
    ebeveyni bulunamayan bir sertifikada duruyor.
    """
    chain = [signer]
    current = signer
    for _ in range(_MAX_CHAIN):
        if current.self_signed in ("yes", "maybe") and current.subject == current.issuer:
            break
        parent = None
        for holder in certificates:
            aday = holder.chosen
            if aday.subject == current.issuer and aday is not current:
                parent = aday
                break
        if parent is None:
            break

        child = _as_x509(current)
        _verify_signature(
            _as_x509(parent).public_key(),
            child.signature,
            child.tbs_certificate_bytes,
            _SigAlgShim(current["signature_algorithm"]),
            check="certificate_chain",
        )
        chain.append(parent)
        current = parent
    else:
        raise _Fail("certificate_chain", f"Zincir {_MAX_CHAIN} adımı aştı — döngü olabilir.")

    return chain


class _SigAlgShim:
    """
    asn1crypto'nun `SignedDigestAlgorithm`'ini `_verify_signature`'ın
    beklediği (signature_algo, hash_algo) yüzeyine indirger.
    """

    def __init__(self, algorithm: Any) -> None:
        self.signature_algo = algorithm.signature_algo
        self.hash_algo = algorithm.hash_algo


# ══════════════════════════════════════════════════════════════════════════════
# Doğrulama
# ══════════════════════════════════════════════════════════════════════════════


def verify_token(
    token_der: bytes,
    *,
    expected_digest: bytes | None = None,
    trusted_roots: Sequence[bytes] | None = None,
    at_time: datetime | None = None,
) -> TimestampVerification:
    """
    Ham bir RFC 3161 token'ını doğrular — dosyadan bağımsız.

    Args:
        token_der: `TimeStampToken` (ContentInfo/SignedData), DER.
        expected_digest: Verilirse TSTInfo'daki imprint bununla eşleşmeli.
        trusted_roots: Güvenilen kök sertifikaların DER listesi. Verilirse
            zincirin kökü bunlardan biri OLMAK ZORUNDA; verilmezse sonuç
            `anchor_trusted=False` ile döner (bkz. modül docstring'i,
            "GÜVEN SINIRI").
        at_time: Sertifika geçerlilik penceresinin karşılaştırılacağı an.
            Varsayılan `genTime` — damganın atıldığı andaki geçerlilik
            sorulmalı, bugünkü değil. Süresi dolmuş bir TSA sertifikası,
            o tarihte geçerliyken atılmış bir damgayı geçersizleştirmez.
    """
    kontroller: list[str] = []
    try:
        return _verify(
            token_der, expected_digest, trusted_roots, at_time, kontroller
        )
    except _Fail as exc:
        return TimestampVerification(
            valid=False, reason=exc.reason, failed_check=exc.check, checks=kontroller
        )
    except Exception as exc:  # ayrıştırma / beklenmeyen yapı
        _log.warning("token doğrulaması beklenmedik hatayla düştü: %s", exc)
        return TimestampVerification(
            valid=False,
            reason=f"Token ayrıştırılamadı: {exc}",
            failed_check="parse",
            checks=kontroller,
        )


def _verify(
    token_der: bytes,
    expected_digest: bytes | None,
    trusted_roots: Sequence[bytes] | None,
    at_time: datetime | None,
    kontroller: list[str],
) -> TimestampVerification:
    content = cms.ContentInfo.load(token_der)
    if content["content_type"].native != "signed_data":
        raise _Fail("parse", f"Token SignedData değil: {content['content_type'].native}")
    signed = content["content"]
    kontroller.append("parse")

    signer_infos = signed["signer_infos"]
    if len(signer_infos) != 1:
        raise _Fail(
            "signer_info",
            f"Token {len(signer_infos)} imzalayan taşıyor — RFC 3161 tam olarak bir tane bekliyor.",
        )
    si = signer_infos[0]
    kontroller.append("signer_info")

    certificates = list(signed["certificates"] or [])
    if not certificates:
        raise _Fail(
            "signer_certificate",
            "Token hiç sertifika taşımıyor — çevrimdışı doğrulama mümkün değil.",
        )
    signer = _find_signer(certificates, si["sid"])
    kontroller.append("signer_certificate")

    # ── İmzalı öznitelikler ────────────────────────────────────────────────
    signed_attrs = si["signed_attrs"]
    if not signed_attrs:
        raise _Fail("signed_attrs", "Token imzalı öznitelik taşımıyor.")
    attrs = {a["type"].native: a["values"] for a in signed_attrs}

    eci = signed["encap_content_info"]
    if eci["content_type"].native != _CT_TSTINFO:
        raise _Fail(
            "content_type",
            f"Kapsanan içerik TSTInfo değil: {eci['content_type'].native}",
        )
    # .contents ham octet'leri veriyor; yeniden dump etmek DER'i
    # değiştirebilir ve özet tutmazdı.
    tst_bytes = eci["content"].contents

    if "content_type" not in attrs or attrs["content_type"][0].native != _CT_TSTINFO:
        raise _Fail("content_type", "İmzalı `content-type` özniteliği TSTInfo değil.")
    kontroller.append("content_type")

    if "message_digest" not in attrs:
        raise _Fail("message_digest", "İmzalı `message-digest` özniteliği yok.")
    beklenen = hashlib.new(si["digest_algorithm"]["algorithm"].native, tst_bytes).digest()
    if attrs["message_digest"][0].native != beklenen:
        raise _Fail(
            "message_digest",
            "İmzalı `message-digest` TSTInfo ile eşleşmiyor — token içeriği değiştirilmiş.",
        )
    kontroller.append("message_digest")

    # ── Token imzası ───────────────────────────────────────────────────────
    # RFC 5652 §5.4: imza, signedAttrs'ın [0] IMPLICIT değil SET OF (0x31)
    # olarak yeniden kodlanmış hâli üzerinden hesaplanır.
    _verify_signature(
        _as_x509(signer).public_key(),
        si["signature"].native,
        signed_attrs.untag().dump(),
        _SigAlgShim(si["signature_algorithm"]),
        check="signature",
    )
    kontroller.append("signature")

    # ── TSTInfo ────────────────────────────────────────────────────────────
    tst = tsp.TSTInfo.load(tst_bytes)
    gen_time = tst["gen_time"].native
    imprint = bytes(tst["message_imprint"]["hashed_message"].native)

    if expected_digest is not None and imprint != expected_digest:
        raise _Fail(
            "digest_match",
            "Damgalanan özet bu dosyaya ait değil — "
            f"beklenen {expected_digest.hex()}, token {imprint.hex()}",
        )
    if expected_digest is not None:
        kontroller.append("digest_match")

    # ── Sertifika kullanımı ve geçerlilik ──────────────────────────────────
    eku = signer.extended_key_usage_value
    if eku is None or _EKU_TIMESTAMPING not in eku.native:
        raise _Fail(
            "eku",
            "İmzalama sertifikası `timeStamping` genişletilmiş anahtar "
            "kullanımı taşımıyor (RFC 3161 §2.3) — bu sertifika zaman "
            "damgası imzalamaya yetkili değil.",
        )
    kontroller.append("eku")

    an = at_time or gen_time
    if an.tzinfo is None:
        an = an.replace(tzinfo=timezone.utc)
    gecerlilik = signer["tbs_certificate"]["validity"]
    baslangic = gecerlilik["not_before"].native
    bitis = gecerlilik["not_after"].native
    if not (baslangic <= an <= bitis):
        raise _Fail(
            "validity",
            f"İmzalama sertifikası {an.isoformat()} anında geçerli değildi "
            f"({baslangic.isoformat()} – {bitis.isoformat()}).",
        )
    kontroller.append("validity")

    # ── Zincir ─────────────────────────────────────────────────────────────
    chain = _walk_chain(signer, certificates)
    kontroller.append("certificate_chain")
    anchor = chain[-1]

    anchor_trusted = False
    if trusted_roots:
        anchor_der = anchor.dump()
        anchor_trusted = any(anchor_der == kok for kok in trusted_roots)
        if not anchor_trusted:
            raise _Fail(
                "trust_anchor",
                f"Zincirin kökü ({_subject_of(anchor)}) güvenilen kökler "
                "arasında değil.",
            )
        kontroller.append("trust_anchor")

    return TimestampVerification(
        valid=True,
        gen_time=gen_time,
        hashed_hex=imprint.hex(),
        tsa_name=_subject_of(signer),
        serial_number=tst["serial_number"].native,
        policy=tst["policy"].native,
        anchor_trusted=anchor_trusted,
        anchor_subject=_subject_of(anchor),
        chain_subjects=[_subject_of(c) for c in chain],
        checks=kontroller,
    )


def verify_timestamp(
    path: Path | str,
    *,
    trusted_roots: Sequence[bytes] | None = None,
    at_time: datetime | None = None,
) -> TimestampVerification:
    """
    Bir `.hcl` dosyasının zaman damgasını ÇEVRİMDIŞI doğrular.

    Ağ erişimi YOK: token da, sertifika zinciri de, karşılaştırılan özet de
    dosyanın kendisinden geliyor.

    Anahtar da GEREKMİYOR — damgalanan özet AAD'de duruyor ve AAD şifresiz.
    Bunun sınırı damgalamadakiyle aynı: AAD'nin bütünlüğünü GCM tag'i
    koruyor ve onu kontrol etmek anahtar ister. Yani bu fonksiyon "AAD'nin
    iddia ettiği özet damgalanmış mı" sorusuna yanıt veriyor; "dosyanın
    içeriği gerçekten o özete mi sahip" sorusu `verify_file()`'ın işi.
    İkisi birlikte tam zinciri kuruyor ve CLI ikisini de çalıştırabiliyor.

    Returns:
        TimestampVerification — damgasız dosyada `valid=False`,
        `failed_check="no_timestamp"`.
    """
    path = Path(path)
    try:
        info: TimestampInfo | None = read_trailer(path)
    except TimestampError as exc:
        return TimestampVerification(
            valid=False, reason=str(exc), failed_check="trailer"
        )
    if info is None:
        return TimestampVerification(
            valid=False,
            reason=f"{path.name} damgalı değil (fragman yok ya da silinmiş).",
            failed_check="no_timestamp",
        )

    try:
        meta = read_aad(path)
    except TimestampError as exc:
        return TimestampVerification(
            valid=False, reason=str(exc), failed_check="aad", tsa_url=info.tsa_url
        )

    aad_hex = meta.get("original_sha256")
    if not aad_hex:
        return TimestampVerification(
            valid=False,
            reason="AAD'de original_sha256 yok — damga bir özete bağlanamıyor.",
            failed_check="aad",
            tsa_url=info.tsa_url,
        )

    # Fragmandaki özet ile AAD'deki özet ayrı ayrı tutuluyor; tutmazlarsa
    # token doğru olsa bile fragman bu dosyaya ait değildir.
    if info.hashed_hex != aad_hex:
        return TimestampVerification(
            valid=False,
            reason=(
                "Fragmandaki özet dosyanın AAD'siyle uyuşmuyor — "
                f"fragman {info.hashed_hex}, AAD {aad_hex}. "
                "Başka bir dosyanın damgası buraya kopyalanmış olabilir."
            ),
            failed_check="trailer_aad_mismatch",
            tsa_url=info.tsa_url,
        )

    try:
        beklenen = bytes.fromhex(aad_hex)
    except ValueError:
        return TimestampVerification(
            valid=False,
            reason=f"AAD'deki original_sha256 geçerli hex değil: {aad_hex!r}",
            failed_check="aad",
            tsa_url=info.tsa_url,
        )

    # ── Toplu damga (v2): token KÖKÜ imzalıyor, dosya köke YOLLA bağlanıyor ──
    #
    # Sıra önemli: yol ÖNCE doğrulanıyor. Token geçerli olsa bile yol
    # tutmuyorsa bu dosya o ağacın içinde değildir; "damga geçerli" demek
    # yanıltıcı olurdu. Tersi de geçerli — yol tutup token sahte olabilir,
    # o yüzden ikisi de zorunlu.
    kontroller: list[str] = []
    if info.batched:
        if not verify_merkle_path(info):
            return TimestampVerification(
                valid=False,
                reason=(
                    "Merkle yolu köke çıkmıyor — bu dosyanın özeti "
                    "damgalanan ağacın içinde değil. Yol ya da kök "
                    "değiştirilmiş olabilir."
                ),
                failed_check="merkle_path",
                hashed_hex=info.hashed_hex,
                tsa_url=info.tsa_url,
            )
        kontroller.append("merkle_path")
        # Token'dan beklenen imprint artık dosyanın özeti DEĞİL, kök.
        # `verify_merkle_path` True döndüyse kök zaten None olamaz; mypy'a
        # bunu göstermek için açık kontrol — `assert` yerine, çünkü -O ile
        # çalıştırıldığında assert'ler düşer.
        if info.merkle_root is None:  # pragma: no cover — batched garanti ediyor
            raise TimestampError("Merkle kökü yok — fragman tutarsız.")
        beklenen = info.merkle_root

    sonuc = verify_token(
        info.token_der,
        expected_digest=beklenen,
        trusted_roots=trusted_roots,
        at_time=at_time,
    )
    # TSA adresi fragmandan geliyor; token'ın içinde yok.
    #
    # `hashed_hex` de fragmandan geliyor: `verify_token()` oraya token'ın
    # imprint'ini yazıyor ve v2'de o KÖKTÜR, dosyanın özeti değil. Kökü
    # "dosyanın özeti" diye raporlamak, doğrulama çıktısını okuyan birini
    # yanıltırdı.
    ekler: dict[str, Any] = {"tsa_url": info.tsa_url}
    if info.batched:
        ekler["hashed_hex"] = info.hashed_hex
        ekler["checks"] = kontroller + list(sonuc.checks)
    return TimestampVerification(**{**sonuc.__dict__, **ekler})


__all__ = [
    "TimestampVerification",
    "verify_timestamp",
    "verify_token",
]
