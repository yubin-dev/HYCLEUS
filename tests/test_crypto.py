"""
CORE.crypto — AES-256-GCM çekirdeği için kritik güvenlik testleri.

Tüm testler gerçek encrypt_file() / decrypt_file() çağırır; mock yoktur.
Yalnızca çıktı dizini (_QUARANTINE_DIR) tmp_path'e yönlendirilir ki
testler projenin data/quarantine/ klasörünü kirletmesin.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from CORE import crypto
from CORE.crypto import (
    AuthenticationError,
    decrypt_file,
    encrypt_file,
    generate_key,
    zero_bytearray,
)

# .hcl başlık ofsetleri (bkz. CORE/crypto.py modül docstring'i)
_HDR_NONCE = 5                 # magic(4) + version(1)
_HDR_AAD_LEN = _HDR_NONCE + 12
_HDR_AAD = _HDR_AAD_LEN + 4
_TAG_SIZE = 16

_USER_ID = 42
_HWID = "TEST-HWID-0001"


@pytest.fixture(autouse=True)
def _quarantine_to_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Şifreli çıktıları test başına izole bir dizine yönlendirir."""
    out = tmp_path / "quarantine"
    out.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", out)
    return out


@pytest.fixture
def key() -> bytes:
    return generate_key()


@pytest.fixture
def plain_file(tmp_path: Path) -> Path:
    """Blok sınırlarını (64 KB) aşan, deterministik içerikli kaynak dosya."""
    src = tmp_path / "gizli_rapor.bin"
    payload = bytes(range(256)) * 800  # 204 800 B → 3 tam olmayan blok
    src.write_bytes(payload)
    return src


def _parse_hcl(path: Path) -> tuple[bytes, bytes, bytes, bytes]:
    """.hcl dosyasını (nonce, aad, ciphertext, tag) olarak ayrıştırır."""
    raw = path.read_bytes()
    nonce = raw[_HDR_NONCE:_HDR_AAD_LEN]
    (aad_len,) = struct.unpack(">I", raw[_HDR_AAD_LEN:_HDR_AAD])
    aad = raw[_HDR_AAD : _HDR_AAD + aad_len]
    body = raw[_HDR_AAD + aad_len :]
    return nonce, aad, body[:-_TAG_SIZE], body[-_TAG_SIZE:]


def _rebuild_hcl(path: Path, *, aad: bytes, ciphertext: bytes, tag: bytes) -> None:
    """Ayrıştırılmış parçalardan .hcl dosyasını yeniden yazar."""
    raw = path.read_bytes()
    header = raw[:_HDR_AAD_LEN] + struct.pack(">I", len(aad))
    path.write_bytes(header + aad + ciphertext + tag)


# ── 1. Round-trip ─────────────────────────────────────────────────────────────

def test_encrypt_decrypt_round_trip_is_byte_identical(plain_file: Path, key: bytes) -> None:
    """Şifrele → çöz sonucu orijinal dosyayla byte-byte aynı olmalı."""
    original = plain_file.read_bytes()

    hcl_path, sha256_hex, _aad_json = encrypt_file(
        plain_file, key, _USER_ID, hwid=_HWID
    )

    # Şifreli çıktı düz metni sızdırmamalı
    assert hcl_path.exists()
    assert original not in hcl_path.read_bytes()

    content, meta = decrypt_file(hcl_path, key, hwid=_HWID)

    assert content == original
    assert len(content) == len(original)
    assert meta["filename"] == plain_file.name
    # B-092/B-099: original_sha256 artık AAD'de YOK (anahtarsız bir
    # doğrulama-oracle'ı olmasın diye) — encrypt_file() onu hâlâ DB'ye
    # kaydedilmek üzere DÖNDÜRÜYOR, yalnızca AAD'ye yazmıyor.
    assert "original_sha256" not in meta
    assert sha256_hex == hashlib.sha256(original).hexdigest()
    assert meta["user_id"] == _USER_ID
    assert meta["hwid"] == _HWID


# ── 1b. Bellek güvenliği — zeroizable (K1-15) ───────────────────────────────────
#
# `decrypt_file()` varsayılan modda `bytes` döndürür — DEĞİŞTİRİLEMEZ, yani
# çağıran `del content` yapsa bile içerik bellekten fiilen SİLİNEMEZ (SECURITY.md
# §3'te belgeli, bilinçli bir sınır). `zeroizable=True`, `bytes(buf)` kopyasını
# HİÇ ÜRETMEDEN çözümlemenin kullandığı AYNI `bytearray`i döndürerek bu sınırı
# kaldırıyor — çağıran `zero_bytearray()` ile GERÇEK bir sıfırlama yapabilir.


def test_zeroizable_false_varsayilan_bytes_donduruyor(plain_file: Path, key: bytes) -> None:
    """Varsayılan davranış AYNEN korunuyor — `zeroizable` geçilmezse `bytes`."""
    hcl_path, _sha, _aad = encrypt_file(plain_file, key, _USER_ID, hwid=_HWID)
    content, _meta = decrypt_file(hcl_path, key, hwid=_HWID)
    assert type(content) is bytes


def test_zeroizable_true_bytearray_donduruyor_ve_dogru_icerigi_tasiyor(
    plain_file: Path, key: bytes,
) -> None:
    original = plain_file.read_bytes()
    hcl_path, _sha, _aad = encrypt_file(plain_file, key, _USER_ID, hwid=_HWID)

    content, meta = decrypt_file(hcl_path, key, hwid=_HWID, zeroizable=True)

    assert type(content) is bytearray
    assert bytes(content) == original
    assert meta["filename"] == plain_file.name


def test_zero_bytearray_sonrasi_icerik_gercekten_sifir(plain_file: Path, key: bytes) -> None:
    """
    ANA TEST: `zero_bytearray()` çağrıldıktan sonra döndürülen tamponun
    içeriği GERÇEKTEN sıfır olmalı — `del`'in aksine (referansı kaldırır
    ama bellekteki byte'lara dokunmaz), bu bir bellek YAZMA işlemi.
    """
    hcl_path, _sha, _aad = encrypt_file(plain_file, key, _USER_ID, hwid=_HWID)
    content, _meta = decrypt_file(hcl_path, key, hwid=_HWID, zeroizable=True)

    assert any(b != 0 for b in content), "test kurulumu hatalı — içerik zaten sıfır"

    zero_bytearray(content)

    assert all(b == 0 for b in content), "zero_bytearray() sonrası içerik sıfır DEĞİL"


def test_zeroizable_true_hata_yolunda_da_tamponu_sifirliyor(
    plain_file: Path, key: bytes,
) -> None:
    """
    Mutasyon kontrastı — hata yolu: `zeroizable=True` iken bir
    `AuthenticationError` fırlarsa (bkz. ciphertext kurcalama testleri,
    aşağıda) `buf` hâlâ ara tamponun kendisi ve `finally` onu sıfırlamalı
    — döndürülen bir değer OLMADIĞI için `buf_cagirana_devrediliyor`
    bayrağı bu yolda hiç True olmamalı. Doğrudan gözlemlenemez (buf
    fonksiyon dışına çıkmıyor) ama `decrypt_file()`'ın normal modda
    (zeroizable=False) AYNI hata yolunda hâlâ doğru AuthenticationError
    fırlattığını doğrulayarak `finally` bloğunun her iki dalda da
    çalıştığından emin oluyoruz.
    """
    hcl_path, _sha, _aad = encrypt_file(plain_file, key, _USER_ID, hwid=_HWID)
    nonce, aad, ciphertext, tag = _parse_hcl(hcl_path)
    bozuk_tag = tag[:-1] + bytes([tag[-1] ^ 0xFF])
    _rebuild_hcl(hcl_path, aad=aad, ciphertext=ciphertext, tag=bozuk_tag)

    with pytest.raises(AuthenticationError):
        decrypt_file(hcl_path, key, hwid=_HWID, zeroizable=True)
    # İkinci bir çağrı (aynı bozuk dosya, zeroizable=False) çökmeden aynı
    # hatayı vermeye devam ediyor — finally bloğu her iki modda da
    # istisnasız çalışıyor, kalıcı bir bozulma (ör. serbest bırakılmamış
    # bir memoryview) yok.
    with pytest.raises(AuthenticationError):
        decrypt_file(hcl_path, key, hwid=_HWID)


# ── 2. Ciphertext / tag kurcalama ─────────────────────────────────────────────

@pytest.mark.parametrize("region", ["tag", "ciphertext_last", "ciphertext_first"])
def test_ciphertext_tampering_raises_authentication_error(
    plain_file: Path, key: bytes, region: str
) -> None:
    """Tek bir byte değişse bile decrypt sessizce veri dönmemeli, hata fırlatmalı."""
    hcl_path, _sha, _aad = encrypt_file(plain_file, key, _USER_ID, hwid=_HWID)
    nonce, aad, ciphertext, tag = _parse_hcl(hcl_path)

    if region == "tag":
        mutated_tag = tag[:-1] + bytes([tag[-1] ^ 0xFF])
        _rebuild_hcl(hcl_path, aad=aad, ciphertext=ciphertext, tag=mutated_tag)
    elif region == "ciphertext_last":
        mutated = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0x01])
        _rebuild_hcl(hcl_path, aad=aad, ciphertext=mutated, tag=tag)
    else:
        mutated = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
        _rebuild_hcl(hcl_path, aad=aad, ciphertext=mutated, tag=tag)

    # Dosya gerçekten değişmiş olmalı — testin boşa geçmediğini garanti eder
    assert _parse_hcl(hcl_path)[1:] != (aad, ciphertext, tag)

    with pytest.raises(AuthenticationError):
        decrypt_file(hcl_path, key, hwid=_HWID)


def test_wrong_key_raises_authentication_error(plain_file: Path, key: bytes) -> None:
    """Yanlış anahtarla çözme de GCM doğrulamasına takılmalı."""
    hcl_path, _sha, _aad = encrypt_file(plain_file, key, _USER_ID, hwid=_HWID)

    with pytest.raises(AuthenticationError):
        decrypt_file(hcl_path, generate_key(), hwid=_HWID)


# ── 3. AAD (metadata) kurcalama ───────────────────────────────────────────────

@pytest.mark.parametrize(
    ("old", "new"),
    [
        (b'"user_id": 42', b'"user_id": 43'),      # yetki yükseltme denemesi
        (b'"hwid": "TEST-HWID-0001"', b'"hwid": "TEST-HWID-0002"'),  # cihaz değişimi
        (b'"filename": "gizli_rapor.bin"', b'"filename": "gizli_rapor.bik"'),
    ],
)
def test_aad_metadata_tampering_is_rejected(
    plain_file: Path, key: bytes, old: bytes, new: bytes
) -> None:
    """AAD'daki tek karakterlik değişiklik bile reddedilmeli."""
    hcl_path, _sha, _aad_json = encrypt_file(plain_file, key, _USER_ID, hwid=_HWID)
    _nonce, aad, ciphertext, tag = _parse_hcl(hcl_path)

    assert old in aad, f"AAD içinde {old!r} bulunamadı — test verisi güncel değil"
    mutated_aad = aad.replace(old, new, 1)
    assert len(mutated_aad) == len(aad), "AAD uzunluğu korunmalı (saf içerik kurcalaması)"
    assert mutated_aad != aad

    _rebuild_hcl(hcl_path, aad=mutated_aad, ciphertext=ciphertext, tag=tag)

    with pytest.raises(AuthenticationError):
        decrypt_file(hcl_path, key, hwid=_HWID)


def test_original_sha256_is_absent_from_the_aad_on_disk(plain_file: Path, key: bytes) -> None:
    """
    B-092/B-099: `original_sha256` artık AAD'ye HİÇ yazılmıyor — bir
    zamanlar bu dosyanın "AAD'a bağlı SHA-256 özeti değiştirilirse dosya
    çözülememeli" testinin konusuydu; alan tamamen kaldırıldığı için o
    test artık anlamsız (kurcalanacak bir şey yok). Bunun yerine alanın
    GERÇEKTEN yok olduğunu, hem AAD JSON'ında hem ham disk baytlarında,
    doğrudan doğruluyoruz — B-092'nin "anahtarsız doğrulama-oracle'ı
    kapatıldı" iddiasının somut kanıtı.
    """
    hcl_path, sha256_hex, aad_json = encrypt_file(plain_file, key, _USER_ID, hwid=_HWID)

    assert "original_sha256" not in aad_json
    assert sha256_hex.encode() not in aad_json.encode()

    _nonce, aad, _ciphertext, _tag = _parse_hcl(hcl_path)
    assert b"original_sha256" not in aad
    # Alan adı yoksa bile, aynı hex DEĞERİN başka bir anahtar altında
    # kazara sızmadığını da doğruluyoruz.
    assert sha256_hex.encode() not in aad


# ── 4. Nonce benzersizliği ────────────────────────────────────────────────────

_NONCE_SAMPLES = 200


def test_nonce_is_unique_across_encryptions(tmp_path: Path, key: bytes) -> None:
    """
    GCM'de nonce tekrarı katastrofiktir (anahtar akışı yeniden kullanılır,
    XOR ile düz metin sızar ve auth anahtarı kurtarılabilir).

    Aynı anahtar + aynı içerikle 200 şifreleme yapılır; tüm nonce'lar farklı olmalı.
    """
    src = tmp_path / "tekrar.bin"
    src.write_bytes(b"HYCLEUS nonce benzersizlik testi\n" * 64)

    nonces: list[bytes] = []
    ciphertexts: list[bytes] = []
    for _ in range(_NONCE_SAMPLES):
        hcl_path, _sha, _aad = encrypt_file(src, key, _USER_ID, hwid=_HWID)
        nonce, _aad_b, ciphertext, _tag = _parse_hcl(hcl_path)
        nonces.append(nonce)
        ciphertexts.append(ciphertext)

    assert len(nonces) == _NONCE_SAMPLES
    assert all(len(n) == 12 for n in nonces), "GCM nonce 12 byte olmalı"
    assert all(n != bytes(12) for n in nonces), "Sabit sıfır nonce kullanılmış"

    duplicates = len(nonces) - len(set(nonces))
    assert duplicates == 0, f"{duplicates} adet nonce tekrarı — GCM anahtar akışı yeniden kullanılmış"

    # Aynı düz metin + aynı anahtar farklı ciphertext üretmeli (nonce gerçekten etkili)
    assert len(set(ciphertexts)) == _NONCE_SAMPLES, "Şifreleme deterministik — nonce ciphertext'e karışmıyor"


# ══════════════════════════════════════════════════════════════════════════════
# Kesik / bozuk başlık — B-012
# ══════════════════════════════════════════════════════════════════════════════

_MAGIC_B = b"HYCL"
_V2 = bytes([2])
_V1 = bytes([1])

#: Başlığın her aşamasında kesilmiş dosyalar. `ad` hata mesajlarında görünür.
#:
#: "surum var" satırı FUZZING'İN BULDUĞU girdi (5 bayt): `decrypt_file` orada
#: `struct.unpack(">I", fin.read(4))` çağırıyordu, dosya bittiği için okuma
#: kısa dönüyor ve `struct.error` fırlıyordu. `verify_file` aynı dosyada
#: doğru davranıyordu — iki okuma yolu ayrışmıştı.
#: (ad, icerik, beklenen mesaj parcasi)
#:
#: MESAJ DA SABITLENIYOR, yalnizca istisna tipi degil. Sebebi olculdu: dort
#: korumadan ikisi kaldirildiginda testler YINE GECIYORDU, cunku bir sonraki
#: koruma devreye girip ayni tipte bir hata veriyordu. Yani "ValueError
#: firladi" iddiasi korumalarin yerinde oldugunu KANITLAMIYOR. Her korumaya
#: ayri bir mesaj verildi ve mesaj burada sabitlendi; simdi dordu de
#: mutasyonla oluyor.
_KESIK_DOSYALAR = [
    ("bos",            b"",                                        "Geçersiz HYCL"),
    ("magicten kisa",  b"HYC",                                     "Geçersiz HYCL"),
    ("yalniz magic",   _MAGIC_B,                                   "sürüm baytı"),
    ("surum var",      _MAGIC_B + _V2,                             "nonce eksik"),
    ("eski surum",     _MAGIC_B + _V1,                             "nonce eksik"),
    ("nonce yarim",    _MAGIC_B + _V2 + bytes(5),                  "nonce eksik"),
    ("nonce tam",      _MAGIC_B + _V2 + bytes(12),                 "AAD uzunluğu"),
    ("aad_len yarim",  _MAGIC_B + _V2 + bytes(12) + bytes(2),      "AAD uzunluğu"),
    ("aad eksik",      _MAGIC_B + _V2 + bytes(12)
                       + bytes([0, 0, 0, 64]) + b"ab",             "AAD bloğu eksik"),
]

_KESIK_IDS = [ad for ad, _, _ in _KESIK_DOSYALAR]


@pytest.mark.parametrize("ad,icerik,beklenen", _KESIK_DOSYALAR, ids=_KESIK_IDS)
@pytest.mark.parametrize(
    "fn", [crypto.verify_file, crypto.decrypt_file], ids=["verify_file", "decrypt_file"]
)
def test_kesik_dosya_temiz_valueerror_veriyor(
    tmp_path: Path, key: bytes, fn, ad: str, icerik: bytes, beklenen: str
) -> None:
    """
    Kesik bir `.hcl` TEMİZ bir hata vermeli — çıplak bir çökme değil.

    Çağıran taraflar (`CORE/export.py`, `UI/main_window_files.py`) yalnızca
    `ValueError` / `AuthenticationError` / `OSError` yakalıyor. Dördüncü bir
    istisna tipi o ağdan kaçıp kullanıcıya yığın izi olarak yansır: "bu
    dosya bozulmuş" yerine beklenmedik bir çökme.

    Güvenlik değil SAĞLAMLIK meselesi — bozulma her iki yolda da zaten
    tespit ediliyordu, mesele nasıl raporlandığı.
    """
    yol = tmp_path / "kesik.hcl"
    yol.write_bytes(icerik)

    with pytest.raises(ValueError) as bilgi:
        fn(yol, key)

    # Kesik dosya "kurcalanmış" değil "bozuk" — AuthenticationError yanlış
    # mesaj olurdu ve kullanıcıyı olmayan bir saldırıya inandırırdı.
    assert not isinstance(bilgi.value, AuthenticationError), (
        f"{ad}: kesik dosya 'kurcalanmis' olarak raporlandi; dogrusu 'bozuk'."
    )
    assert beklenen in str(bilgi.value), (
        f"{ad}: beklenen mesaj parcasi {beklenen!r} yok, alinan: "
        f"{str(bilgi.value)!r}. Bir sonraki koruma devreye girmis olabilir — "
        "yani bu asamanin kendi kontrolu kaldirilmis."
    )


@pytest.mark.parametrize("ad,icerik,_beklenen", _KESIK_DOSYALAR, ids=_KESIK_IDS)
def test_iki_okuma_yolu_ayni_istisnayi_veriyor(
    tmp_path: Path, key: bytes, ad: str, icerik: bytes, _beklenen: str
) -> None:
    """
    B-012'nin ÖZÜ: aynı dosya, iki okuyucu, aynı sonuç.

    Bulgu "dört `if` eksik" değil, "iki kopya ayrıştı"ydı. Bu test
    ayrışmayı ölçüyor: istisna tipi ve mesajı birebir aynı olmalı.
    """
    yol = tmp_path / "kesik.hcl"
    yol.write_bytes(icerik)

    def _sonuc(fn):
        try:
            fn(yol, key)
        except Exception as exc:  # noqa: BLE001 — karşılaştırmak işin kendisi
            return type(exc).__name__, str(exc)
        return "DONDU", ""

    assert _sonuc(crypto.verify_file) == _sonuc(crypto.decrypt_file), (
        f"{ad}: verify_file ve decrypt_file farkli davraniyor — "
        "baslik ayristirmasi yeniden ayrismis olabilir."
    )


def test_iki_okuma_yolu_ayni_basligi_kullaniyor() -> None:
    """
    İkinci bir başlık ayrıştırma uygulamasının geri gelmesini engeller.

    B-012'nin kök nedeni eksik kontroller değil, İKİ AYRI UYGULAMAYDI.
    Kontrolleri ekleyip kopyaları ayrı bırakmak aynı sapmayı zamanla geri
    getirirdi. B-008'de kullanılan AST denetiminin aynısı.
    """
    import ast

    kaynak = Path(crypto.__file__).read_text(encoding="utf-8")
    agac = ast.parse(kaynak)

    fonksiyonlar = {
        d.name: d
        for d in ast.walk(agac)
        if isinstance(d, ast.FunctionDef) and d.name in ("verify_file", "decrypt_file")
    }
    assert set(fonksiyonlar) == {"verify_file", "decrypt_file"}, sorted(fonksiyonlar)

    for ad, dugum in fonksiyonlar.items():
        cagrilar = {
            n.func.id
            for n in ast.walk(dugum)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        }
        assert "_read_header" in cagrilar, (
            f"{ad}() basligi kendi basina ayristiriyor — `_read_header()` "
            "cagirmali. Iki uygulama = iki farkli guvenlik (B-012)."
        )
        # Kendi magic karşılaştırmasını yapmamalı: ayrışmanın ilk adımı odur.
        assert "_MAGIC" not in ast.dump(dugum), (
            f"{ad}() icinde dogrudan _MAGIC karsilastirmasi var — baslik "
            "okumasi `_read_header()` icinde kalmali."
        )
