"""
CORE.timestamp + CORE.crypto v2 kabı — RFC 3161 zaman damgası testleri.

Ağ kullanımı
------------
Damgalama akışının TAMAMI ağsız koşuyor. İki farklı sahte kaynak var ve
ikisi de gerçek DER üretiyor/okuyor — "mock" değiller, asn1crypto ile
kurulmuş gerçek ASN.1 yapıları:

  · `fake_tsa` — İSTENEN özet ve nonce için TimeStampResp kuruyor. Rastgele
    girdilerle akışın tamamını koşturmayı sağlıyor. İMZASIZ: bu adımda imza
    doğrulaması yok (bkz. CORE/timestamp.py, "Bu adımın KAPSAMI"), dolayısıyla
    imzasız bir token bu testler için yeterli. Sonraki adım imza doğrulamasını
    eklediğinde bu sahtenin gerçekten imzalaması gerekecek.
  · `tests/data/freetsa_response.der` — freetsa.org'dan alınmış GERÇEK bir
    yanıt (sertifika zinciriyle 4.6 KB). Ayrıştırıcının sentetik değil,
    sahadaki bir TSA'nın çıktısını okuduğunu kanıtlıyor.

Gerçek ağ çağrısı yalnızca `@pytest.mark.network` işaretli tek testte ve o
da varsayılan olarak atlanıyor: dış bir TSA'nın kesintisi HYCLEUS'un CI'ını
kırmamalı. Çalıştırmak için HYCLEUS_TSA_NETWORK=1.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest
from asn1crypto import algos, cms, core, tsp

from CORE import crypto, timestamp
from CORE.crypto import (
    VERSION_LEGACY,
    VERSION_TIMESTAMPED,
    AuthenticationError,
    decrypt_file,
    encrypt_file,
    generate_key,
    verify_file,
)
from CORE.timestamp import (
    DEFAULT_TSA_URL,
    TRAILER_VERSION,
    TimestampError,
    TimestampInfo,
    attach_trailer,
    build_request,
    decode_trailer,
    encode_trailer,
    parse_response,
    read_aad,
    read_trailer,
    timestamp_file,
    tsa_url,
)

_USER_ID = 7
_HWID = "TEST-HWID-TS"

_FIXTURE = Path(__file__).parent / "data" / "freetsa_response.der"

#: Fixture'ı üretirken kullanılan düz metin, özet ve nonce.
_FIXTURE_PLAIN = b"HYCLEUS RFC 3161 test vektoru\n"
_FIXTURE_DIGEST = hashlib.sha256(_FIXTURE_PLAIN).digest()
_FIXTURE_NONCE = 0x4859433145555301


# ══════════════════════════════════════════════════════════════════════════════
# Fixture'lar ve yardımcılar
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture(autouse=True)
def _quarantine_to_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    out = tmp_path / "quarantine"
    out.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", out)
    return out


@pytest.fixture
def key() -> bytes:
    return generate_key()


@pytest.fixture
def plain_bytes() -> bytes:
    """64 KB blok sınırını aşan deterministik içerik."""
    return bytes(range(256)) * 500  # 128 000 B


@pytest.fixture
def hcl(tmp_path: Path, key: bytes, plain_bytes: bytes) -> Path:
    """Şifrelenmiş, henüz damgalanmamış bir .hcl dosyası."""
    src = tmp_path / "rapor.bin"
    src.write_bytes(plain_bytes)
    dst, _sha, _aad = encrypt_file(src, key, _USER_ID, hwid=_HWID)
    return dst


def _make_response(
    digest: bytes,
    nonce: int,
    *,
    status: str = "granted",
    algorithm: str = "sha256",
) -> bytes:
    """
    Gerçek DER kodlu bir TimeStampResp üretir (imzasız — bkz. modül docstring).
    """
    tst = tsp.TSTInfo({
        "version": "v1",
        "policy": "1.2.3.4.1",
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": algorithm}),
            "hashed_message": digest,
        }),
        "serial_number": 1,
        "gen_time": datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc),
        "nonce": core.Integer(nonce),
    })
    signed = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": cms.EncapsulatedContentInfo({
            "content_type": "tst_info",
            "content": cms.ParsableOctetString(tst.dump()),
        }),
        "signer_infos": [],
    })
    return tsp.TimeStampResp({
        "status": tsp.PKIStatusInfo({"status": status}),
        "time_stamp_token": cms.ContentInfo({
            "content_type": "signed_data", "content": signed,
        }),
    }).dump()


class FakeTSA:
    """
    İsteği GERÇEKTEN ayrıştırıp ona uygun yanıt üreten sahte TSA.

    `timestamp_file(transport=...)` imzasına uyuyor. Aldığı her isteği
    kaydediyor, böylece testler yalnızca sonuca değil GÖNDERİLENE de
    bakabiliyor.
    """

    def __init__(self, **response_kwargs) -> None:
        self.requests: list[tsp.TimeStampReq] = []
        self.urls: list[str] = []
        self.response_kwargs = response_kwargs
        self.override_digest: bytes | None = None
        self.override_nonce: int | None = None

    def __call__(self, url: str, body: bytes, timeout: int) -> bytes:
        request = tsp.TimeStampReq.load(body)
        self.requests.append(request)
        self.urls.append(url)
        digest = self.override_digest or request["message_imprint"]["hashed_message"].native
        nonce = (
            self.override_nonce
            if self.override_nonce is not None
            else request["nonce"].native
        )
        return _make_response(bytes(digest), nonce, **self.response_kwargs)

    @property
    def last_digest(self) -> bytes:
        return bytes(self.requests[-1]["message_imprint"]["hashed_message"].native)


@pytest.fixture
def fake_tsa() -> FakeTSA:
    return FakeTSA()


def _downgrade_to_v1(path: Path) -> None:
    """Sürüm byte'ını 0x01 yapar — eski dosya taklidi.

    Sürüm byte'ı GCM tag'inin kapsamında olmadığı için bu, dosyayı
    bozmadan gerçek bir v1 dosyası üretiyor.
    """
    raw = bytearray(path.read_bytes())
    raw[4] = VERSION_LEGACY
    path.write_bytes(bytes(raw))


def _info(token: bytes = b"TOKEN", **kw) -> TimestampInfo:
    defaults = {
        "hash_algorithm": "sha256",
        "hashed_hex": "ab" * 32,
        "tsa_url": "https://tsa.example/tsr",
        "token_der": token,
    }
    defaults.update(kw)
    return TimestampInfo(**defaults)  # type: ignore[arg-type]


# ══════════════════════════════════════════════════════════════════════════════
# 1. Geriye uyumluluk — eski dosyalar okunmaya devam ediyor
# ══════════════════════════════════════════════════════════════════════════════


def test_new_files_are_written_as_version_2(hcl: Path) -> None:
    assert hcl.read_bytes()[4] == VERSION_TIMESTAMPED


def test_v1_file_still_decrypts_byte_identically(
    hcl: Path, key: bytes, plain_bytes: bytes
) -> None:
    """ASIL GERİYE UYUMLULUK TESTİ: 0x02 öncesi kasalar açılmaya devam etmeli."""
    _downgrade_to_v1(hcl)
    assert hcl.read_bytes()[4] == VERSION_LEGACY

    content, meta = decrypt_file(hcl, key, hwid=_HWID)
    assert content == plain_bytes
    assert meta["filename"] == "rapor.bin"


def test_v1_file_still_passes_verify_file(hcl: Path, key: bytes) -> None:
    _downgrade_to_v1(hcl)
    meta = verify_file(hcl, key, hwid=_HWID)
    assert meta["original_sha256"] == hashlib.sha256(
        (hcl.parent.parent / "rapor.bin").read_bytes()
    ).hexdigest()


def test_v2_without_trailer_decrypts(hcl: Path, key: bytes, plain_bytes: bytes) -> None:
    """Damga OPSİYONEL: fragmansız bir v2 dosyası tamamen geçerli."""
    assert read_trailer(hcl) is None
    content, _meta = decrypt_file(hcl, key, hwid=_HWID)
    assert content == plain_bytes


def test_unknown_version_is_still_rejected(hcl: Path, key: bytes) -> None:
    """Sürüm kümesi genişledi ama açık uçlu değil."""
    raw = bytearray(hcl.read_bytes())
    raw[4] = 9
    hcl.write_bytes(bytes(raw))
    with pytest.raises(ValueError, match="Desteklenmeyen versiyon: 9"):
        decrypt_file(hcl, key)
    with pytest.raises(ValueError, match="Desteklenmeyen versiyon: 9"):
        verify_file(hcl, key)


def test_v1_file_is_never_scanned_for_a_trailer(hcl: Path) -> None:
    """
    v1'de fragman aranmamalı — aranırsa ciphertext'in son byte'ları
    yanlışlıkla fragman sanılabilir ve gövde kırpılırdı.
    """
    _downgrade_to_v1(hcl)
    assert read_trailer(hcl) is None


# ══════════════════════════════════════════════════════════════════════════════
# 2. Fragman kodlaması
# ══════════════════════════════════════════════════════════════════════════════


def test_trailer_round_trips() -> None:
    info = _info(token=os.urandom(3000), hashed_hex="cd" * 32)
    assert decode_trailer(encode_trailer(info)) == info


def test_trailer_encoding_is_deterministic() -> None:
    info = _info()
    assert encode_trailer(info) == encode_trailer(info)


def test_trailer_declares_its_own_total_length() -> None:
    raw = encode_trailer(_info(token=b"x" * 100))
    (declared,) = struct.unpack(">I", raw[-8:-4])
    assert declared == len(raw)


def test_trailer_is_bracketed_by_the_magic() -> None:
    raw = encode_trailer(_info())
    assert raw[:4] == crypto.TRAILER_MAGIC
    assert raw[-4:] == crypto.TRAILER_MAGIC


def test_trailer_survives_unicode_in_the_url() -> None:
    info = _info(tsa_url="https://zaman-damgası.example/tsr")
    assert decode_trailer(encode_trailer(info)).tsa_url == info.tsa_url


def test_truncated_trailer_is_rejected() -> None:
    raw = encode_trailer(_info(token=b"y" * 500))
    with pytest.raises(TimestampError):
        decode_trailer(raw[:60] + raw[-4:])


def test_trailer_without_the_opening_magic_is_rejected() -> None:
    raw = bytearray(encode_trailer(_info()))
    raw[0] = ord("X")
    with pytest.raises(TimestampError, match="TRAILER_MAGIC ile başlamıyor"):
        decode_trailer(bytes(raw))


def test_trailer_without_the_closing_magic_is_rejected() -> None:
    raw = encode_trailer(_info())
    with pytest.raises(TimestampError, match="TRAILER_MAGIC ile bitmiyor"):
        decode_trailer(raw[:-4] + b"ZZZZ")


def test_unknown_trailer_version_is_rejected() -> None:
    """
    Fragman şeması kap sürümünden bağımsız evrilebilmeli; bilinmeyen bir
    şema sürümü sessizce yanlış ayrıştırılmak yerine hata vermeli.
    """
    raw = bytearray(encode_trailer(_info()))
    raw[4] = TRAILER_VERSION + 7
    with pytest.raises(TimestampError, match="Desteklenmeyen fragman sürümü"):
        decode_trailer(bytes(raw))


def test_extra_bytes_between_fields_and_footer_are_rejected() -> None:
    raw = encode_trailer(_info())
    tampered = raw[:-8] + b"ARTIK" + raw[-8:]
    with pytest.raises(TimestampError, match="artık veri"):
        decode_trailer(tampered)


def test_field_order_is_the_schema() -> None:
    """
    Alanların SIRASI şema olduğu için iki farklı alanın yer değiştirmesi
    fark edilmeli — burada url ile hash birbirine karışırsa hashed_hex
    64 karakterlik hex olmaktan çıkar.
    """
    info = decode_trailer(encode_trailer(_info(hashed_hex="ef" * 32)))
    assert len(info.hashed_hex) == 64
    assert info.tsa_url.startswith("https://")


# ══════════════════════════════════════════════════════════════════════════════
# 3. Fragman + GCM bir arada
# ══════════════════════════════════════════════════════════════════════════════


def test_stamped_file_still_decrypts_byte_identically(
    hcl: Path, key: bytes, plain_bytes: bytes, fake_tsa: FakeTSA
) -> None:
    """
    ASIL TEST: fragman eklemek GCM doğrulamasını ETKİLEMEMELİ.

    Bu tutmasaydı damgalanan her dosya bütünlük taramasında "bozuk"
    görünürdü — özelliğin kendisi bir veri kaybı alarmına dönüşürdü.
    """
    timestamp_file(hcl, transport=fake_tsa)
    content, meta = decrypt_file(hcl, key, hwid=_HWID)
    assert content == plain_bytes
    assert meta["filename"] == "rapor.bin"


def test_stamped_file_still_passes_verify_file(
    hcl: Path, key: bytes, fake_tsa: FakeTSA
) -> None:
    """Haftalık bütünlük taramasının kullandığı yol da bozulmamalı."""
    timestamp_file(hcl, transport=fake_tsa)
    assert verify_file(hcl, key, hwid=_HWID)["hwid"] == _HWID


def test_stamping_only_appends(hcl: Path, fake_tsa: FakeTSA) -> None:
    """Kabın geri kalanı byte-byte aynı kalmalı — yalnızca sona ekleniyor."""
    before = hcl.read_bytes()
    timestamp_file(hcl, transport=fake_tsa)
    after = hcl.read_bytes()
    assert after[: len(before)] == before
    assert len(after) > len(before)


def test_tampering_a_stamped_file_is_still_caught(
    hcl: Path, key: bytes, fake_tsa: FakeTSA
) -> None:
    """Fragman, ciphertext kurcalamasını gizlememelidir."""
    timestamp_file(hcl, transport=fake_tsa)
    raw = bytearray(hcl.read_bytes())
    raw[200] ^= 0xFF  # ciphertext bölgesinin içinde
    hcl.write_bytes(bytes(raw))
    with pytest.raises(AuthenticationError):
        verify_file(hcl, key, hwid=_HWID)


def test_stamping_upgrades_a_v1_file_to_v2(
    hcl: Path, key: bytes, plain_bytes: bytes, fake_tsa: FakeTSA
) -> None:
    """
    v1 dosya damgalanırsa sürüm byte'ı da yükselmeli; yoksa okuyucu
    fragmanı hiç aramaz ve artık byte'lar ciphertext sanılırdı.
    """
    _downgrade_to_v1(hcl)
    timestamp_file(hcl, transport=fake_tsa)

    assert hcl.read_bytes()[4] == VERSION_TIMESTAMPED
    assert read_trailer(hcl) is not None
    content, _meta = decrypt_file(hcl, key, hwid=_HWID)
    assert content == plain_bytes


def test_removing_the_trailer_leaves_a_valid_unstamped_file(
    hcl: Path, key: bytes, plain_bytes: bytes, fake_tsa: FakeTSA
) -> None:
    """
    DÜRÜST SINIRIN TESTİ — bir iddia değil, kabul edilmiş bir davranış.

    Fragman GCM tag'inin dışında olduğu için silinebilir ve dosya yine
    geçerli kalır. Bu bir açık: damga DOWNGRADE edilebilir. Test bunu
    düzeltmiyor, KAYITA GEÇİRİYOR — ileride fragman tag'e bağlanırsa bu
    test kırılacak ve değişiklik bilinçli bir karar olarak görünecek.
    """
    before = hcl.read_bytes()
    timestamp_file(hcl, transport=fake_tsa)
    hcl.write_bytes(before)  # fragmanı sil

    assert read_trailer(hcl) is None
    content, _meta = decrypt_file(hcl, key, hwid=_HWID)
    assert content == plain_bytes


def test_a_lone_trailing_magic_is_not_mistaken_for_a_trailer(hcl: Path) -> None:
    """
    Ciphertext'in sonu tesadüfen TRAILER_MAGIC olabilir. Tek başına magic
    fragman saymamalı — uzunluk alanının işaret ettiği yerde ikinci magic
    de bulunmalı.
    """
    hcl.write_bytes(hcl.read_bytes() + crypto.TRAILER_MAGIC)
    assert read_trailer(hcl) is None


def test_a_bogus_length_field_is_not_mistaken_for_a_trailer(hcl: Path) -> None:
    """Sondaki magic + tutarsız uzunluk: fragman YOK sayılmalı."""
    bogus = struct.pack(">I", 64) + crypto.TRAILER_MAGIC
    hcl.write_bytes(hcl.read_bytes() + bogus)
    assert read_trailer(hcl) is None


def test_a_length_pointing_into_the_header_is_rejected(hcl: Path) -> None:
    """Fragman gövdenin (ciphertext + tag) içine taşamaz."""
    size = hcl.stat().st_size + 8
    evil = struct.pack(">I", size) + crypto.TRAILER_MAGIC
    hcl.write_bytes(hcl.read_bytes() + evil)
    assert read_trailer(hcl) is None


# ══════════════════════════════════════════════════════════════════════════════
# 4. TSA isteğinin biçimi
# ══════════════════════════════════════════════════════════════════════════════


def test_request_uses_the_digest_verbatim_without_rehashing() -> None:
    """
    Kritik: message imprint, VERİLEN özet olmalı — özetin özeti değil.

    Bağımlılık seçiminin gerekçesi tam olarak buydu (bkz. CORE/timestamp.py):
    ham veriyi alıp kendi hash'leyen bir kütüphane bu testi geçemezdi.
    """
    digest = hashlib.sha256(b"belge icerigi").digest()
    der, _nonce = build_request(digest)

    request = tsp.TimeStampReq.load(der)
    assert bytes(request["message_imprint"]["hashed_message"].native) == digest
    assert (
        bytes(request["message_imprint"]["hashed_message"].native)
        != hashlib.sha256(digest).digest()
    )


def test_request_declares_sha256() -> None:
    der, _ = build_request(hashlib.sha256(b"x").digest())
    request = tsp.TimeStampReq.load(der)
    assert request["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha256"


def test_request_is_version_1_and_asks_for_the_certificate() -> None:
    der, _ = build_request(hashlib.sha256(b"x").digest())
    request = tsp.TimeStampReq.load(der)
    assert request["version"].native == "v1"
    # cert_req: token çevrimdışı doğrulanabilsin diye sertifika isteniyor
    assert request["cert_req"].native is True


def test_request_carries_a_nonce_and_returns_it() -> None:
    der, nonce = build_request(hashlib.sha256(b"x").digest())
    assert tsp.TimeStampReq.load(der)["nonce"].native == nonce


def test_nonce_differs_between_requests() -> None:
    digest = hashlib.sha256(b"x").digest()
    nonces = {build_request(digest)[1] for _ in range(20)}
    assert len(nonces) == 20


def test_request_der_is_reparseable_and_deterministic() -> None:
    digest = hashlib.sha256(b"x").digest()
    der, nonce = build_request(digest, nonce=42)
    assert build_request(digest, nonce=42)[0] == der
    assert tsp.TimeStampReq.load(der).dump() == der


def test_request_rejects_a_non_sha256_digest() -> None:
    with pytest.raises(TimestampError, match="32 byte olmalı"):
        build_request(hashlib.sha512(b"x").digest())


def test_post_sends_the_rfc3161_content_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    RFC 3161 §3.4: istek 'application/timestamp-query' ile gönderilmeli.
    Yanlış Content-Type ile çoğu TSA isteği reddeder.
    """
    import requests

    captured: dict = {}

    class _Response:
        status_code = 200
        content = b"DER"

    def _post(url, data=None, headers=None, timeout=None):
        captured.update(url=url, data=data, headers=headers, timeout=timeout)
        return _Response()

    monkeypatch.setattr(requests, "post", _post)
    body, _ = build_request(hashlib.sha256(b"x").digest())
    assert timestamp._http_post("https://tsa.example/tsr", body, 11) == b"DER"

    assert captured["headers"]["Content-Type"] == "application/timestamp-query"
    assert captured["headers"]["Accept"] == "application/timestamp-reply"
    assert captured["data"] == body
    assert captured["timeout"] == 11


def test_post_rejects_a_non_200_status(monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    class _Response:
        status_code = 503
        content = b""

    monkeypatch.setattr(requests, "post", lambda *a, **k: _Response())
    with pytest.raises(TimestampError, match="HTTP 503"):
        timestamp._http_post("https://tsa.example/tsr", b"x", 5)


def test_post_rejects_an_oversized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    class _Response:
        status_code = 200
        content = b"A" * (256 * 1024 + 1)

    monkeypatch.setattr(requests, "post", lambda *a, **k: _Response())
    with pytest.raises(TimestampError, match="çok büyük"):
        timestamp._http_post("https://tsa.example/tsr", b"x", 5)


# ══════════════════════════════════════════════════════════════════════════════
# 5. TSA yanıtının kontrolü
# ══════════════════════════════════════════════════════════════════════════════


def test_a_real_freetsa_response_is_accepted() -> None:
    """
    Sentetik değil, freetsa.org'dan alınmış GERÇEK bir yanıt.

    Ayrıştırıcının sahadaki bir TSA'nın çıktısıyla (sertifika zinciri,
    imzalı öznitelikler, gerçek policy OID'i) çalıştığını kanıtlıyor.
    """
    token = parse_response(
        _FIXTURE.read_bytes(), digest=_FIXTURE_DIGEST, nonce=_FIXTURE_NONCE
    )
    assert len(token) > 1000  # sertifika zinciri dahil

    info = cms.ContentInfo.load(token)["content"]["encap_content_info"]["content"].parsed
    assert bytes(info["message_imprint"]["hashed_message"].native) == _FIXTURE_DIGEST
    assert info["gen_time"].native.tzinfo is not None


def test_a_response_for_another_digest_is_rejected() -> None:
    """TSA bizim gönderdiğimizden başkasını damgaladıysa kabul edilmemeli."""
    with pytest.raises(TimestampError, match="başka bir özeti damgalamış"):
        parse_response(
            _FIXTURE.read_bytes(),
            digest=hashlib.sha256(b"baska belge").digest(),
            nonce=_FIXTURE_NONCE,
        )


def test_a_replayed_response_is_rejected() -> None:
    """Nonce eşleşmiyorsa yanıt bu isteğe ait değildir."""
    with pytest.raises(TimestampError, match="Nonce uyuşmuyor"):
        parse_response(_FIXTURE.read_bytes(), digest=_FIXTURE_DIGEST, nonce=1)


def test_granted_with_mods_is_accepted() -> None:
    digest = hashlib.sha256(b"x").digest()
    der = _make_response(digest, 5, status="granted_with_mods")
    assert parse_response(der, digest=digest, nonce=5)


@pytest.mark.parametrize("status", ["rejection", "waiting", "revocation_notification"])
def test_a_non_granted_status_is_rejected(status: str) -> None:
    digest = hashlib.sha256(b"x").digest()
    der = _make_response(digest, 5, status=status)
    with pytest.raises(TimestampError, match="TSA damgayı vermedi"):
        parse_response(der, digest=digest, nonce=5)


def test_granted_without_a_token_is_rejected() -> None:
    """
    "granted" diyip token göndermeyen bir TSA kabul edilmemeli.

    DER elle kuruluyor: RFC 3161'de timeStampToken opsiyonel olduğu için
    böyle bir yanıt protokol düzeyinde mümkün, ama asn1crypto'nun şeması
    alanı zorunlu sayıyor ve yanıt ayrıştırma aşamasında düşüyor. Hata
    mesajı bu yüzden genel ("ayrıştırılamadı") — reddedilmesi yeterli.

        TimeStampResp ::= SEQUENCE { status PKIStatusInfo, ... }
        PKIStatusInfo ::= SEQUENCE { status INTEGER (0 = granted), ... }
    """
    der = bytes.fromhex("30053003020100")
    with pytest.raises(TimestampError):
        parse_response(der, digest=b"\x00" * 32, nonce=5)


def test_a_response_with_a_different_hash_algorithm_is_rejected() -> None:
    """
    TSA sha512 ile damgalarsa özet uzunluğu da değişir; imprint kontrolü
    zaten düşer ama algoritma kontrolü hatayı doğru isimlendiriyor.
    """
    digest = hashlib.sha512(b"x").digest()
    der = _make_response(digest, 5, algorithm="sha512")
    with pytest.raises(TimestampError):
        parse_response(der, digest=digest, nonce=5)


def test_garbage_is_not_parsed_as_a_response() -> None:
    with pytest.raises(TimestampError, match="ayrıştırılamadı"):
        parse_response(b"bu DER degil", digest=b"\x00" * 32, nonce=1)


# ══════════════════════════════════════════════════════════════════════════════
# 6. Damgalama akışı uçtan uca
# ══════════════════════════════════════════════════════════════════════════════


def test_the_stamped_hash_is_the_plaintext_hash_not_the_ciphertext(
    hcl: Path, plain_bytes: bytes, fake_tsa: FakeTSA
) -> None:
    """
    GEREKSİNİM 3'ÜN TESTİ. Damgalanan özet düz metne ait olmalı; ne
    ciphertext'in, ne .hcl dosyasının, ne de özetin özeti.
    """
    timestamp_file(hcl, transport=fake_tsa)

    plaintext_hash = hashlib.sha256(plain_bytes).digest()
    assert fake_tsa.last_digest == plaintext_hash

    raw = hcl.read_bytes()
    assert fake_tsa.last_digest != hashlib.sha256(raw).digest()
    assert fake_tsa.last_digest != hashlib.sha256(raw[-4096:]).digest()
    assert fake_tsa.last_digest != hashlib.sha256(plaintext_hash).digest()

    assert read_trailer(hcl).hashed_hex == plaintext_hash.hex()  # type: ignore[union-attr]


def test_the_stamped_hash_comes_from_the_aad_not_a_recomputation(
    hcl: Path, fake_tsa: FakeTSA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Özet YENİDEN HESAPLANMAMALI: AAD'de hazır duruyor ve onu tekrar üretmek
    dosyayı çözmeyi gerektirirdi.

    Kanıt: AAD'deki original_sha256 elle değiştiriliyor (GCM tag'i bozulur
    ama damgalama anahtar kullanmadığı için oraya bakmıyor) ve TSA'ya
    giden özetin DEĞİŞTİĞİ görülüyor. Kod düz metni yeniden hash'leseydi
    gönderilen özet değişmezdi.
    """
    sahte = "11" * 32
    raw = hcl.read_bytes()
    aad = json.loads(raw[21 : 21 + struct.unpack(">I", raw[17:21])[0]].decode())
    gercek = aad["original_sha256"]
    hcl.write_bytes(raw.replace(gercek.encode(), sahte.encode()))

    timestamp_file(hcl, transport=fake_tsa)
    assert fake_tsa.last_digest.hex() == sahte
    assert fake_tsa.last_digest.hex() != gercek


def test_stamping_needs_no_key(hcl: Path, fake_tsa: FakeTSA) -> None:
    """
    Damgalama oturum anahtarı OLMADAN çalışıyor — düz metne hiç dokunulmuyor.
    `key` argümanı hiç verilmiyor ve akış tamamlanıyor.
    """
    info = timestamp_file(hcl, transport=fake_tsa)
    assert info.token_der
    assert read_trailer(hcl) == info


def test_stamping_records_the_tsa_url(hcl: Path, fake_tsa: FakeTSA) -> None:
    timestamp_file(hcl, url="https://tsa.kurum.example/tsr", transport=fake_tsa)
    assert fake_tsa.urls == ["https://tsa.kurum.example/tsr"]
    assert read_trailer(hcl).tsa_url == "https://tsa.kurum.example/tsr"  # type: ignore[union-attr]


def test_stamping_with_a_key_verifies_first(hcl: Path, key: bytes, fake_tsa: FakeTSA) -> None:
    info = timestamp_file(hcl, key=key, hwid=_HWID, transport=fake_tsa)
    assert info.hash_algorithm == "sha256"


def test_a_corrupt_file_is_not_stamped_when_a_key_is_given(
    hcl: Path, key: bytes, fake_tsa: FakeTSA
) -> None:
    """
    Bozuk bir dosyaya damga basmak, bozulmayı "o tarihte böyleydi" diye
    ONAYLAMAK olurdu. Anahtar verildiğinde doğrulama önce gelmeli.
    """
    raw = bytearray(hcl.read_bytes())
    raw[300] ^= 0xFF
    hcl.write_bytes(bytes(raw))
    before = hcl.read_bytes()

    with pytest.raises(AuthenticationError):
        timestamp_file(hcl, key=key, hwid=_HWID, transport=fake_tsa)

    assert fake_tsa.requests == []      # TSA'ya hiç gidilmedi
    assert hcl.read_bytes() == before   # dosyaya dokunulmadı


def test_double_stamping_is_refused(hcl: Path, fake_tsa: FakeTSA) -> None:
    timestamp_file(hcl, transport=fake_tsa)
    with pytest.raises(TimestampError, match="zaten damgalı"):
        timestamp_file(hcl, transport=fake_tsa)
    assert len(fake_tsa.requests) == 1


def test_a_file_without_original_sha256_cannot_be_stamped(
    tmp_path: Path, key: bytes, fake_tsa: FakeTSA
) -> None:
    """AAD'de özet yoksa damgalanacak bir şey yok — sessizce geçilmemeli."""
    src = tmp_path / "eski.bin"
    src.write_bytes(b"veri")
    dst, _sha, _aad = encrypt_file(src, key, _USER_ID, hwid=_HWID)

    raw = dst.read_bytes()
    (aad_len,) = struct.unpack(">I", raw[17:21])
    aad = json.loads(raw[21 : 21 + aad_len].decode())
    del aad["original_sha256"]
    yeni = json.dumps(aad, ensure_ascii=False, sort_keys=True).encode()
    dst.write_bytes(
        raw[:17] + struct.pack(">I", len(yeni)) + yeni + raw[21 + aad_len :]
    )

    with pytest.raises(TimestampError, match="original_sha256 yok"):
        timestamp_file(dst, transport=fake_tsa)


def test_a_tsa_failure_leaves_the_file_untouched(hcl: Path) -> None:
    """Ağ hatası dosyayı yarım bırakmamalı."""
    before = hcl.read_bytes()

    def _patlar(url: str, body: bytes, timeout: int) -> bytes:
        raise OSError("baglanti reddedildi")

    with pytest.raises(TimestampError, match="TSA'ya ulaşılamadı"):
        timestamp_file(hcl, transport=_patlar)

    assert hcl.read_bytes() == before
    assert read_trailer(hcl) is None


def test_a_dishonest_tsa_response_leaves_the_file_untouched(hcl: Path) -> None:
    """TSA başka bir özeti damgalarsa fragman YAZILMAMALI."""
    before = hcl.read_bytes()
    tsa = FakeTSA()
    tsa.override_digest = hashlib.sha256(b"tamamen baska").digest()

    with pytest.raises(TimestampError, match="başka bir özeti damgalamış"):
        timestamp_file(hcl, transport=tsa)

    assert hcl.read_bytes() == before
    assert read_trailer(hcl) is None


def test_no_temp_file_is_left_behind(hcl: Path, fake_tsa: FakeTSA) -> None:
    """
    Fragman atomik yazılıyor (geçici kopya + os.replace). Başarılı yolda
    geçici dosya kalmamalı.
    """
    timestamp_file(hcl, transport=fake_tsa)
    assert list(hcl.parent.glob("*-ts-tmp*")) == []
    assert [p.name for p in hcl.parent.iterdir()] == [hcl.name]


def test_an_interrupted_write_leaves_the_original_intact(
    hcl: Path, key: bytes, plain_bytes: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    ATOMİKLİĞİN TESTİ. Yazma son anda (os.replace) kesilirse orijinal dosya
    dokunulmamış kalmalı ve geçici dosya temizlenmeli.

    Yerinde append yapılsaydı bu senaryo dosyayı yarım fragmanla bırakır,
    artık byte'lar ciphertext sanılır ve GCM doğrulaması düşerdi — sağlam
    bir dosya "bozuk" damgası yerdi. Bu test tam olarak onu kovalıyor.
    """
    before = hcl.read_bytes()

    def _patlar(src, dst):
        raise OSError("disk dolu")

    monkeypatch.setattr(timestamp.os, "replace", _patlar)
    with pytest.raises(OSError, match="disk dolu"):
        attach_trailer(hcl, _info())

    assert hcl.read_bytes() == before
    assert list(hcl.parent.glob("*-ts-tmp*")) == []
    content, _meta = decrypt_file(hcl, key, hwid=_HWID)
    assert content == plain_bytes


# ══════════════════════════════════════════════════════════════════════════════
# 7. AAD okuma ve ayarlar
# ══════════════════════════════════════════════════════════════════════════════


def test_read_aad_needs_no_key(hcl: Path) -> None:
    meta = read_aad(hcl)
    assert meta["filename"] == "rapor.bin"
    assert meta["hwid"] == _HWID
    assert len(meta["original_sha256"]) == 64


def test_read_aad_rejects_a_foreign_file(tmp_path: Path) -> None:
    other = tmp_path / "duz.txt"
    other.write_bytes(b"bu bir hcl degil")
    with pytest.raises(TimestampError, match="Geçersiz HYCL"):
        read_aad(other)


def test_tsa_url_falls_back_to_the_default(db) -> None:
    assert tsa_url(db) == DEFAULT_TSA_URL


def test_tsa_url_comes_from_settings(db) -> None:
    db.set_setting("tsa_url", "https://tsa.kurum.example/tsr")
    assert tsa_url(db) == "https://tsa.kurum.example/tsr"


def test_a_blank_setting_falls_back_to_the_default(db) -> None:
    db.set_setting("tsa_url", "   ")
    assert tsa_url(db) == DEFAULT_TSA_URL


@pytest.mark.parametrize("kotu", ["file:///etc/passwd", "ftp://tsa/x", "tsa.example"])
def test_a_non_http_tsa_url_is_refused(db, kotu: str) -> None:
    """
    Ayar tablosuna yazılabilen bir adres, damgalamayı yerel bir dosya
    okuyucusuna çevirmemeli.
    """
    db.set_setting("tsa_url", kotu)
    with pytest.raises(TimestampError, match="http\\(s\\) olmalı"):
        tsa_url(db)


# ══════════════════════════════════════════════════════════════════════════════
# 8. Gerçek ağ — varsayılan olarak atlanır
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.network
@pytest.mark.skipif(
    os.environ.get("HYCLEUS_TSA_NETWORK") != "1",
    reason="Gerçek TSA çağrısı — çalıştırmak için HYCLEUS_TSA_NETWORK=1",
)
def test_real_tsa_round_trip(hcl: Path, key: bytes, plain_bytes: bytes) -> None:
    """
    freetsa.org'a gerçek çağrı: damgala, fragmanı oku, dosya hâlâ çözülsün.

    CI'da ÇALIŞMAZ — dış bir servisin kesintisi projenin CI'ını kırmamalı.
    Elle çalıştırılan bu test, sahte TSA'nın gerçeği doğru taklit ettiğini
    zaman zaman teyit etmek için var.
    """
    info = timestamp_file(hcl, url=DEFAULT_TSA_URL, key=key, hwid=_HWID)

    assert info.hashed_hex == hashlib.sha256(plain_bytes).hexdigest()
    assert len(info.token_der) > 1000
    assert read_trailer(hcl) == info

    content, _meta = decrypt_file(hcl, key, hwid=_HWID)
    assert content == plain_bytes
