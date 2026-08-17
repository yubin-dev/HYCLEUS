"""
HYCLEUS — toplu (Merkle) zaman damgası testleri

Bugüne kadar her dosya ayrı bir TSA çağrısı gerektiriyordu. Toplu damgada
N dosyanın özeti bir Merkle ağacına diziliyor, YALNIZCA kök damgalanıyor
ve her dosya kendi yolunu fragmanına yazıyor.

Ağacın kendisi `tests/test_merkle.py`'de sınanıyor. Buradaki testler
ENTEGRASYONU ölçüyor: fragman v2 doğru yazılıyor mu, doğrulama iki adımı
da yapıyor mu, ve — en önemlisi — ESKİ v1 fragmanları hâlâ okunuyor mu.

Ağ yok: `FakeTSA` isteği gerçekten ayrıştırıp gerçekten imzalı yanıt
üretiyor (bkz. tests/test_timestamp.py docstring'i).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from tsa_fixtures import FakeTSA, default_authority

from CORE import crypto, timestamp
from CORE.crypto import encrypt_file, generate_key
from CORE.merkle import build_leaves, build_tree, leaf_hash
from CORE.timestamp import (
    TRAILER_VERSION,
    TRAILER_VERSION_MERKLE,
    BatchResult,
    TimestampError,
    TimestampInfo,
    anchor_leaf_payload,
    current_anchor_hash,
    decode_proof,
    decode_trailer,
    encode_proof,
    encode_trailer,
    read_trailer,
    timestamp_batch,
    timestamp_file,
    verify_merkle_path,
)
from CORE.timestamp_verify import verify_timestamp

_USER_ID = 7
_HWID = "TEST-HWID-BATCH"

#: Sahte TSA'ların hepsi aynı yerel kök CA'yı kullanıyor.
_KOK = default_authority().ca_der


# ══════════════════════════════════════════════════════════════════════════════
# Fixture'lar
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
def tsa() -> FakeTSA:
    return FakeTSA()


def _hcl(tmp_path: Path, key: bytes, ad: str, icerik: bytes) -> Path:
    src = tmp_path / f"{ad}.bin"
    src.write_bytes(icerik)
    dst, _sha, _aad = encrypt_file(src, key, _USER_ID, hwid=_HWID)
    return dst


@pytest.fixture
def dosyalar(tmp_path: Path, key: bytes) -> list[Path]:
    """Beş ayrı .hcl — tek sayı bilerek: yükseltme yolunu da kapsıyor."""
    return [
        _hcl(tmp_path, key, f"belge{i}", f"icerik-{i}".encode() * 100)
        for i in range(5)
    ]


def _ozet(path: Path) -> str:
    """Dosyanın AAD'sindeki düz metin özeti (damgalanan değer)."""
    return str(timestamp.read_aad(path)["original_sha256"])


# ══════════════════════════════════════════════════════════════════════════════
# 1. Toplu damgalama — TEK TSA çağrısı
# ══════════════════════════════════════════════════════════════════════════════


def test_bes_dosya_tek_tsa_cagrisi(dosyalar: list[Path], tsa: FakeTSA) -> None:
    """ÖZELLİĞİN VARLIK SEBEBİ: N dosya, 1 çağrı."""
    sonuc = timestamp_batch(dosyalar, transport=tsa)

    assert len(tsa.requests) == 1, f"{len(tsa.requests)} çağrı yapıldı, 1 bekleniyordu"
    assert isinstance(sonuc, BatchResult)
    assert sonuc.leaf_count == 5
    assert sonuc.saved_calls == 4


def test_tsaya_gonderilen_KOK(dosyalar: list[Path], tsa: FakeTSA) -> None:
    """
    TSA'ya giden imprint kök olmalı — herhangi bir dosyanın özeti DEĞİL.

    Bu test olmadan "ilk dosyayı damgala, diğerlerine aynı token'ı yaz"
    gibi bir uygulama da geçerdi ve o damga diğer dosyaları hiç
    kanıtlamazdı.
    """
    sonuc = timestamp_batch(dosyalar, transport=tsa)

    gonderilen = bytes(
        tsa.requests[0]["message_imprint"]["hashed_message"].native
    )
    assert gonderilen == sonuc.root

    dosya_ozetleri = {bytes.fromhex(_ozet(p)) for p in dosyalar}
    assert gonderilen not in dosya_ozetleri


def test_her_dosya_kendi_yolunu_aliyor(dosyalar: list[Path], tsa: FakeTSA) -> None:
    sonuc = timestamp_batch(dosyalar, transport=tsa)

    for i, yol in enumerate(dosyalar):
        info = read_trailer(yol)
        assert info is not None
        assert info.batched is True
        assert info.leaf_index == i
        assert info.merkle_root == sonuc.root
        assert info.hashed_hex == _ozet(yol)
        assert verify_merkle_path(info), f"{yol.name} yolu köke çıkmıyor"


def test_hepsi_ayni_token_ve_koku_tasiyor(dosyalar: list[Path], tsa: FakeTSA) -> None:
    timestamp_batch(dosyalar, transport=tsa)
    infolar = [read_trailer(p) for p in dosyalar]
    assert len({i.token_der for i in infolar}) == 1
    assert len({i.merkle_root for i in infolar}) == 1
    # Ama özetler ve yollar FARKLI olmalı.
    assert len({i.hashed_hex for i in infolar}) == 5
    assert len({encode_proof(i.merkle_proof) for i in infolar}) == 5


def test_tek_dosyalik_toplu_damga_calisiyor(
    tmp_path: Path, key: bytes, tsa: FakeTSA
) -> None:
    """Tek yapraklı ağaç: kök = yaprak, yol boş. Özel durum olmamalı."""
    tek = _hcl(tmp_path, key, "tek", b"yalniz")
    sonuc = timestamp_batch([tek], transport=tsa)

    info = read_trailer(tek)
    assert info.batched is True
    assert info.merkle_proof.depth == 0
    assert sonuc.root == leaf_hash(bytes.fromhex(info.hashed_hex))
    assert verify_merkle_path(info)


def test_yol_boyutu_makul(tmp_path: Path, key: bytes, tsa: FakeTSA) -> None:
    """
    "Birkaç yüz byte" iddiası ölçülüyor.

    Token ~1-2 KB; yolun onun yanında küçük kalması özelliğin tüm
    ekonomisi. Ölçmeden yazılmış bir iddia olsaydı burada görünürdü.
    """
    coklu = [_hcl(tmp_path, key, f"d{i}", f"i{i}".encode()) for i in range(16)]
    timestamp_batch(coklu, transport=tsa)

    for yol in coklu:
        info = read_trailer(yol)
        assert len(encode_proof(info.merkle_proof)) <= 4 * 33  # log2(16) = 4


# ══════════════════════════════════════════════════════════════════════════════
# 2. Doğrulama — iki adım
# ══════════════════════════════════════════════════════════════════════════════


def test_toplu_damga_uctan_uca_dogrulaniyor(
    dosyalar: list[Path], tsa: FakeTSA
) -> None:
    """
    ASIL KABUL TESTİ: yol köke çıkıyor VE kök imzalı.

    `verify_timestamp` v2'yi tanımıyorsa burada düşer — token'ın imprint'i
    dosyanın özetiyle eşleşmiyor ve eski kod onu "tutarsız" sayardı.
    """
    timestamp_batch(dosyalar, transport=tsa)
    for yol in dosyalar:
        sonuc = verify_timestamp(yol, trusted_roots=[_KOK])
        assert sonuc.valid, f"{yol.name}: {sonuc.reason}"
        assert "merkle_path" in sonuc.checks
        assert sonuc.anchor_trusted is True


def test_dogrulama_dosyanin_KENDI_ozetini_raporluyor(
    dosyalar: list[Path], tsa: FakeTSA
) -> None:
    """
    Sonuçtaki `hashed_hex` KÖK değil, dosyanın özeti olmalı.

    Token'ın imprint'i kök; onu "dosyanın özeti" diye raporlamak
    doğrulama çıktısını okuyan birini yanıltırdı.
    """
    sonuc_batch = timestamp_batch(dosyalar, transport=tsa)
    for yol in dosyalar:
        v = verify_timestamp(yol, trusted_roots=[_KOK])
        assert v.hashed_hex == _ozet(yol)
        assert v.hashed_hex != sonuc_batch.root.hex()


def test_bozulmus_yol_reddediliyor(dosyalar: list[Path], tsa: FakeTSA) -> None:
    """Kardeş hash'i değiştirilirse yol köke çıkmamalı."""
    timestamp_batch(dosyalar, transport=tsa)
    hedef = dosyalar[1]
    info = read_trailer(hedef)

    bozuk_kardesler = list(info.merkle_proof.siblings)
    bozuk_kardesler[0] = bytes(32)
    bozuk = TimestampInfo(
        hash_algorithm=info.hash_algorithm,
        hashed_hex=info.hashed_hex,
        tsa_url=info.tsa_url,
        token_der=info.token_der,
        merkle_root=info.merkle_root,
        leaf_index=info.leaf_index,
        merkle_proof=type(info.merkle_proof)(
            leaf_index=info.leaf_index,
            siblings=tuple(bozuk_kardesler),
            right_flags=info.merkle_proof.right_flags,
        ),
    )
    assert verify_merkle_path(bozuk) is False

    _fragmani_degistir(hedef, bozuk)
    sonuc = verify_timestamp(hedef, trusted_roots=[_KOK])
    assert sonuc.valid is False
    assert sonuc.failed_check == "merkle_path"


def test_baska_agacin_koku_reddediliyor(
    tmp_path: Path, key: bytes, dosyalar: list[Path], tsa: FakeTSA
) -> None:
    """
    Yol tutuyor ama kök TSA'nın imzaladığı kök değil.

    İki adımın AYRI olmasının sebebi bu: yalnızca yolu doğrulamak
    yeterli olsaydı saldırgan kendi ağacını kurup kendi kökünü yazardı.
    """
    timestamp_batch(dosyalar, transport=tsa)
    hedef = dosyalar[0]
    info = read_trailer(hedef)

    # Aynı dosyayı içeren BAŞKA bir ağaç kur (farklı kardeşler).
    yukler = [bytes.fromhex(info.hashed_hex), hashlib.sha256(b"sahte").digest()]
    sahte_agac = build_tree(build_leaves(yukler))
    sahte = TimestampInfo(
        hash_algorithm=info.hash_algorithm,
        hashed_hex=info.hashed_hex,
        tsa_url=info.tsa_url,
        token_der=info.token_der,          # ESKİ token — eski kökü imzalıyor
        merkle_root=sahte_agac.root,
        leaf_index=0,
        merkle_proof=sahte_agac.proof(0),
    )
    # Yol kendi içinde tutarlı…
    assert verify_merkle_path(sahte) is True

    _fragmani_degistir(hedef, sahte)
    sonuc = verify_timestamp(hedef, trusted_roots=[_KOK])
    # …ama token o kökü imzalamamış.
    assert sonuc.valid is False
    assert sonuc.failed_check == "digest_match"


def _fragmani_degistir(path: Path, info: TimestampInfo) -> None:
    """Dosyadaki fragmanı yenisiyle değiştirir (saldırı taklidi)."""
    ham = path.read_bytes()
    eski = encode_trailer(read_trailer(path))
    assert ham.endswith(eski)
    path.write_bytes(ham[: -len(eski)] + encode_trailer(info))


# ══════════════════════════════════════════════════════════════════════════════
# 3. Bir dosya değişince diğerleri bozulmuyor
# ══════════════════════════════════════════════════════════════════════════════


def test_bir_dosya_degisince_digerleri_gecerli_kaliyor(
    tmp_path: Path, key: bytes, dosyalar: list[Path], tsa: FakeTSA
) -> None:
    """
    KULLANICININ İSTEDİĞİ GARANTİ — dosya düzeyinde.

    Paylaşılan tek bir token var; bir dosyanın bozulması diğerlerinin
    kanıtını ETKİLEMEMELİ. Merkle'ın tüm anlamı bu: yapraklar birbirinden
    bağımsız.
    """
    timestamp_batch(dosyalar, transport=tsa)

    kurban = dosyalar[2]
    ham = bytearray(kurban.read_bytes())
    ham[-200] ^= 0xFF                      # fragmanın içinde bir byte boz
    kurban.write_bytes(bytes(ham))

    for yol in dosyalar:
        sonuc = verify_timestamp(yol, trusted_roots=[_KOK])
        if yol == kurban:
            assert sonuc.valid is False
        else:
            assert sonuc.valid is True, f"{yol.name} yan etkiden bozuldu: {sonuc.reason}"


def test_bir_dosyanin_icerigi_degisince_yalnizca_o_dusuyor(
    tmp_path: Path, key: bytes, dosyalar: list[Path], tsa: FakeTSA
) -> None:
    """
    İçerik değişimi (fragman değil): AAD'deki özet artık yolla
    uyuşmamalı, ama diğer dosyalar etkilenmemeli.
    """
    timestamp_batch(dosyalar, transport=tsa)

    kurban = dosyalar[3]
    info = read_trailer(kurban)
    sahte = TimestampInfo(
        hash_algorithm=info.hash_algorithm,
        hashed_hex=hashlib.sha256(b"baska icerik").hexdigest(),
        tsa_url=info.tsa_url,
        token_der=info.token_der,
        merkle_root=info.merkle_root,
        leaf_index=info.leaf_index,
        merkle_proof=info.merkle_proof,
    )
    _fragmani_degistir(kurban, sahte)

    assert verify_timestamp(kurban, trusted_roots=[_KOK]).valid is False
    for yol in dosyalar:
        if yol != kurban:
            assert verify_timestamp(yol, trusted_roots=[_KOK]).valid is True


# ══════════════════════════════════════════════════════════════════════════════
# 4. Denetim çıpası aynı ağaçta
# ══════════════════════════════════════════════════════════════════════════════


def test_cipa_agaca_giriyor(dosyalar: list[Path], tsa: FakeTSA) -> None:
    """
    İKİ ÖZELLİK TEK DAMGADA — kullanıcının 4. maddesi.

    Çıpa yaprağı eklendiğinde ağaçta bir yaprak daha oluyor ve kök
    değişiyor; yani token gerçekten çıpayı da kapsıyor.
    """
    cipa = "a" * 64
    cipasiz = timestamp_batch(dosyalar, transport=FakeTSA())

    # Aynı dosyalarla ama çıpalı yeniden kur (fragmanları temizle).
    for yol in dosyalar:
        _fragmani_sil(yol)

    cipali = timestamp_batch(dosyalar, transport=tsa, anchor_hash=cipa)

    assert cipali.leaf_count == cipasiz.leaf_count + 1
    assert cipali.root != cipasiz.root
    assert cipali.anchor_hash == cipa


def test_cipa_yuku_HAM_HASH_DEGIL() -> None:
    """
    TİP KARIŞIKLIĞINA KARŞI — ve yük taşıyan kısmın hangisi olduğu.

    Çıpanın ham byte'ları doğrudan yaprak yükü yapılsaydı, bir çıpa
    yaprağı ile bir dosya yaprağı birebir aynı görünürdü: ikisi de 32
    baytlık ham özet. Elinde çıpa hash'i olan biri onu "şu dosyanın
    özeti" diye sunabilirdi — kripto kırmadan.

    Ölçüm sonucu: ayrımı SHA-256 SARMALAMASI sağlıyor, etiket değil.
    Yalnızca `ANCHOR_LEAF_LABEL`'ı kaldıran mutasyon hiçbir testi
    bozmuyor ve bu `anchor_leaf_payload` docstring'inde yazılı. Bu test
    o yüzden etiketi değil, SARMALAMAYI sabitliyor — kırılması gereken
    şey bu.
    """
    ortak = "b" * 64
    cipa_yuku = anchor_leaf_payload(ortak)
    ham = bytes.fromhex(ortak)

    assert cipa_yuku != ham, "çıpa yükü ham hash — tip karışıklığı açık"
    assert len(cipa_yuku) == 32
    assert leaf_hash(cipa_yuku) != leaf_hash(ham)
    # Sarmalama gerçekten SHA-256 mı (kimlik fonksiyonu değil).
    assert cipa_yuku == hashlib.sha256(
        timestamp.ANCHOR_LEAF_LABEL + ortak.encode()
    ).digest()


def test_cipali_agacta_dosya_yollari_hala_dogru(
    dosyalar: list[Path], tsa: FakeTSA
) -> None:
    """Çıpa yaprağı eklemek dosya yollarını bozmamalı."""
    timestamp_batch(dosyalar, transport=tsa, anchor_hash="c" * 64)
    for yol in dosyalar:
        assert verify_timestamp(yol, trusted_roots=[_KOK]).valid


def test_cipa_yapragi_da_koke_cikiyor(dosyalar: list[Path], tsa: FakeTSA) -> None:
    """
    Çıpanın kendisi de kanıtlanabilmeli — yoksa ağaca eklemenin anlamı
    yok. Çıpa yaprağı SON indiste ve ağacı yeniden kurarak yolu
    hesaplanabiliyor.
    """
    cipa = "d" * 64
    sonuc = timestamp_batch(dosyalar, transport=tsa, anchor_hash=cipa)

    yukler = [bytes.fromhex(_ozet(p)) for p in dosyalar]
    yukler.append(anchor_leaf_payload(cipa))
    yapraklar = build_leaves(yukler)
    agac = build_tree(yapraklar)

    assert agac.root == sonuc.root
    from CORE.merkle import verify_proof

    son = len(yapraklar) - 1
    assert verify_proof(yapraklar[son], agac.proof(son), sonuc.root)


def test_current_anchor_hash_son_kaydi_okuyor(tmp_path: Path) -> None:
    cipa_dosyasi = tmp_path / "anchor.log"
    assert current_anchor_hash(cipa_dosyasi) is None

    cipa_dosyasi.write_text(
        json.dumps({"last_hash": "ilk"}) + "\n"
        + json.dumps({"last_hash": "son"}) + "\n",
        encoding="utf-8",
    )
    assert current_anchor_hash(cipa_dosyasi) == "son"


# ══════════════════════════════════════════════════════════════════════════════
# 5. GERİYE DÖNÜK UYUMLULUK — v1 fragmanları hâlâ okunuyor
# ══════════════════════════════════════════════════════════════════════════════


def test_tekil_damga_HALA_v1_uretiyor(
    tmp_path: Path, key: bytes, tsa: FakeTSA
) -> None:
    """
    `timestamp_file()` Merkle'sız kalmalı ve byte düzeyinde v1 yazmalı.

    Toplu kipi eklerken tekil kipi sessizce v2'ye çevirmek, mevcut
    dosyaları okuyan hiçbir şeyi bozmasa bile gereksiz bir format
    değişikliği olurdu.
    """
    tek = _hcl(tmp_path, key, "eski", b"tekil")
    timestamp_file(tek, transport=tsa)

    ham = tek.read_bytes()
    info = read_trailer(tek)
    assert info.batched is False
    assert info.trailer_version == TRAILER_VERSION
    # Fragmanın 5. byte'ı sürüm — v1 olmalı.
    fragman = encode_trailer(info)
    assert fragman[4] == 1
    assert ham.endswith(fragman)


def test_v1_fragman_kodlamasi_DEGISMEDI() -> None:
    """
    Merkle alanları eklenmesine rağmen v1 çıktısı byte-byte aynı.

    Beklenen byte'lar burada ELLE kuruluyor — `encode_trailer`'ın kendi
    çıktısıyla karşılaştırmak, ikisi birlikte kayarsa hiçbir şey
    söylemezdi.
    """
    import struct

    from CORE.crypto import TRAILER_MAGIC

    info = TimestampInfo(
        hash_algorithm="sha256",
        hashed_hex="ab" * 32,
        tsa_url="https://tsa.example/tsr",
        token_der=b"TOKEN-DER-BYTES",
    )

    def _put(raw: bytes) -> bytes:
        return struct.pack(">I", len(raw)) + raw

    govde = (
        TRAILER_MAGIC
        + bytes([1])
        + _put(b"sha256")
        + _put(b"ab" * 32)
        + _put(b"https://tsa.example/tsr")
        + _put(b"TOKEN-DER-BYTES")
    )
    beklenen = govde + struct.pack(">I", len(govde) + 8) + TRAILER_MAGIC
    assert encode_trailer(info) == beklenen


def test_v1_fragman_okunuyor(tmp_path: Path, key: bytes, tsa: FakeTSA) -> None:
    """Tekil damgalı bir dosya, Merkle kodu eklendikten sonra da okunmalı."""
    tek = _hcl(tmp_path, key, "eski", b"tekil")
    timestamp_file(tek, transport=tsa)

    info = read_trailer(tek)
    assert info is not None
    assert info.merkle_root is None
    assert info.leaf_index is None
    assert info.merkle_proof is None
    assert verify_merkle_path(info) is True  # yol yok → doğrulanacak şey yok


def test_v1_dosyasi_HALA_dogrulaniyor(
    tmp_path: Path, key: bytes, tsa: FakeTSA
) -> None:
    """Uçtan uca: eski akış Merkle'dan hiç etkilenmemeli."""
    tek = _hcl(tmp_path, key, "eski", b"tekil")
    timestamp_file(tek, transport=tsa)

    sonuc = verify_timestamp(tek, trusted_roots=[_KOK])
    assert sonuc.valid is True
    assert "merkle_path" not in sonuc.checks


def test_v1_ve_v2_yan_yana_yasayabiliyor(
    tmp_path: Path, key: bytes
) -> None:
    """
    Aynı depoda hem v1 hem v2 damgalı dosya bulunabilir ve ikisi de
    doğrulanır. Geçiş dönemi tam olarak böyle görünecek.
    """
    tsa1, tsa2 = FakeTSA(), FakeTSA()
    eski = _hcl(tmp_path, key, "eski", b"tekil")
    timestamp_file(eski, transport=tsa1)

    yeniler = [_hcl(tmp_path, key, f"yeni{i}", f"y{i}".encode()) for i in range(3)]
    timestamp_batch(yeniler, transport=tsa2)

    assert read_trailer(eski).trailer_version == TRAILER_VERSION
    assert verify_timestamp(eski, trusted_roots=[_KOK]).valid
    for yol in yeniler:
        assert read_trailer(yol).trailer_version == TRAILER_VERSION_MERKLE
        assert verify_timestamp(yol, trusted_roots=[_KOK]).valid


def test_bilinmeyen_fragman_surumu_reddediliyor() -> None:
    """v3 gelirse sessizce yanlış okunmamalı."""
    info = TimestampInfo(
        hash_algorithm="sha256",
        hashed_hex="cd" * 32,
        tsa_url="https://x/y",
        token_der=b"T",
    )
    ham = bytearray(encode_trailer(info))
    ham[4] = 9
    with pytest.raises(TimestampError, match="Desteklenmeyen fragman sürümü"):
        decode_trailer(bytes(ham))


# ══════════════════════════════════════════════════════════════════════════════
# 6. Kodlama / çözme birebir
# ══════════════════════════════════════════════════════════════════════════════


def test_v2_fragman_gidip_geliyor(dosyalar: list[Path], tsa: FakeTSA) -> None:
    timestamp_batch(dosyalar, transport=tsa)
    for yol in dosyalar:
        info = read_trailer(yol)
        assert decode_trailer(encode_trailer(info)) == info


def test_yol_kodlamasi_gidip_geliyor() -> None:
    agac = build_tree(build_leaves([hashlib.sha256(bytes([i])).digest()
                                    for i in range(9)]))
    for i in range(9):
        yol = agac.proof(i)
        assert decode_proof(encode_proof(yol), leaf_index=i) == yol


def test_bozuk_yol_blobu_reddediliyor() -> None:
    with pytest.raises(TimestampError, match="bölünmüyor"):
        decode_proof(b"\x01" + b"\x00" * 10, leaf_index=0)


def test_gecersiz_yon_bytei_reddediliyor() -> None:
    """
    Yön yalnızca 0x00/0x01 olabilir. 0x02 sessizce "sol" sayılsaydı
    farklı bloblar aynı yolu üretir ve fragman tekil olmazdı.
    """
    with pytest.raises(TimestampError, match="geçersiz yön"):
        decode_proof(b"\x02" + b"\x00" * 32, leaf_index=0)


def test_merkle_alanlari_ya_hep_ya_hic() -> None:
    with pytest.raises(TimestampError, match="birlikte dolu ya birlikte boş"):
        TimestampInfo(
            hash_algorithm="sha256",
            hashed_hex="ef" * 32,
            tsa_url="https://x/y",
            token_der=b"T",
            merkle_root=b"\x00" * 32,   # indis ve yol yok
        )


def test_kok_32_byte_olmali() -> None:
    from CORE.merkle import MerkleProof

    with pytest.raises(TimestampError, match="32 byte olmalı"):
        TimestampInfo(
            hash_algorithm="sha256",
            hashed_hex="ef" * 32,
            tsa_url="https://x/y",
            token_der=b"T",
            merkle_root=b"kisa",
            leaf_index=0,
            merkle_proof=MerkleProof(leaf_index=0, siblings=(), right_flags=()),
        )


# ══════════════════════════════════════════════════════════════════════════════
# 7. Girdi doğrulaması
# ══════════════════════════════════════════════════════════════════════════════


def test_bos_liste_reddediliyor(tsa: FakeTSA) -> None:
    with pytest.raises(TimestampError, match="en az bir dosya"):
        timestamp_batch([], transport=tsa)
    assert not tsa.requests, "boş listede TSA'ya gidildi"


def test_zaten_damgali_dosya_reddediliyor(
    tmp_path: Path, key: bytes, dosyalar: list[Path], tsa: FakeTSA
) -> None:
    timestamp_file(dosyalar[0], transport=FakeTSA())
    with pytest.raises(TimestampError, match="zaten damgalı"):
        timestamp_batch(dosyalar, transport=tsa)
    assert not tsa.requests, "reddedilen turda TSA'ya gidildi"


def test_ayni_dosya_iki_kez_reddediliyor(
    dosyalar: list[Path], tsa: FakeTSA
) -> None:
    """
    Aynı dosya iki yaprağa girerse ikinci fragman yazımı birinciyi ezer
    ve dosya yanlış indisli bir yol taşır — sessizce bozuk bir damga.
    """
    with pytest.raises(TimestampError, match="birden çok kez"):
        timestamp_batch([dosyalar[0], dosyalar[1], dosyalar[0]], transport=tsa)
    assert not tsa.requests


def test_ozetsiz_dosya_reddediliyor(
    tmp_path: Path, key: bytes, dosyalar: list[Path], tsa: FakeTSA, monkeypatch
) -> None:
    """AAD'de original_sha256 yoksa tur hiç başlamamalı."""
    monkeypatch.setattr(timestamp, "read_aad", lambda p: {})
    with pytest.raises(TimestampError, match="original_sha256 yok"):
        timestamp_batch(dosyalar, transport=tsa)
    assert not tsa.requests


def test_tsa_reddederse_hicbir_fragman_yazilmiyor(dosyalar: list[Path]) -> None:
    """
    Damga alınamadıysa dosyalara dokunulmamalı.

    Yarım bir tur, damgasız dosyaları "damgalı" göstermezdi ama fragman
    yazma sırası TSA'dan SONRA olduğu için bu garanti kod düzeninden
    geliyor; test onu sabitliyor.
    """
    red = FakeTSA(status="rejection")
    onceki = {p: p.read_bytes() for p in dosyalar}

    with pytest.raises(TimestampError, match="TSA damgayı vermedi"):
        timestamp_batch(dosyalar, transport=red)

    for yol in dosyalar:
        assert yol.read_bytes() == onceki[yol]
        assert read_trailer(yol) is None


def _fragmani_sil(path: Path) -> None:
    """Fragmanı dosyadan çıkarır — testlerin yeniden damgalayabilmesi için."""
    info = read_trailer(path)
    if info is None:
        return
    ham = path.read_bytes()
    path.write_bytes(ham[: -len(encode_trailer(info))])
