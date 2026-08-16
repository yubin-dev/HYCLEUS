"""
CORE.vault_manager — Shamir Secret Sharing (2-of-2) testleri.

Mevcut şema 2-of-2'dir: master_key iki paya bölünür
  · share_1 → vault dosyası içinde şifreli
  · share_2 → DB usb_tokens tablosunda
Eşik = 2 olduğundan "eşikten az pay" = tek pay.

Testler gerçek _sss_split / _sss_recover / reconstruct_key çağırır; mock yoktur.
DB veya dosya sistemi kullanılmaz — saf kripto katmanı sınanır.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

import pytest

from CORE import vault_manager
from CORE.vault_manager import (
    _FILE_ATTRIBUTE_READONLY,
    _SSS_PRIME,
    _SSS_SHARE_HEX_LEN,
    _sss_recover,
    _sss_split,
    reconstruct_key,
)

_KEY_SIZE = 32
_INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF


def _recover_or_none(share_1: str, share_2: str) -> bytes | None:
    """Kurtarmayı dener; hata fırlarsa None döner (ikisi de kabul edilebilir sonuç)."""
    try:
        return reconstruct_key(share_1, share_2)
    except (ValueError, OverflowError):
        return None


# ── 5. Shamir böl / kurtar ────────────────────────────────────────────────────

def test_shamir_split_produces_three_shares() -> None:
    """2-of-3: her bölme 1, 2, 3 indisli üç pay üretmeli."""
    shares = _sss_split(secrets.token_bytes(_KEY_SIZE))

    assert len(shares) == 3
    for i, share in enumerate(shares, start=1):
        assert share.startswith(f"{i}:")
        assert len(share.split(":", 1)[1]) == _SSS_SHARE_HEX_LEN
    assert len(set(shares)) == 3, "paylar birbirinden farklı olmalı"


def test_shamir_split_and_recover_round_trip() -> None:
    """Eşik sayıda (2) pay orijinal master_key'i tam olarak geri vermeli."""
    for _ in range(50):  # rastgele polinom katsayısı — tek koşu yeterli kanıt değil
        secret = secrets.token_bytes(_KEY_SIZE)
        share_1, share_2, _share_3 = _sss_split(secret)

        assert reconstruct_key(share_1, share_2) == secret
        assert _sss_recover(share_1, share_2) == secret


@pytest.mark.parametrize("combo", [(0, 1), (0, 2), (1, 2)])
def test_any_two_of_three_shares_recover_the_key(combo: tuple[int, int]) -> None:
    """
    Üç paydan HERHANGİ İKİSİ anahtarı doğru kurtarmalı: (1,2) (1,3) (2,3).

    Bu 2-of-3 şemasının tanımı — biri bile çalışmazsa kurtarma akışı çöker.
    """
    a, b = combo
    for _ in range(25):
        secret = secrets.token_bytes(_KEY_SIZE)
        shares = _sss_split(secret)

        assert reconstruct_key(shares[a], shares[b]) == secret
        # Sıra önemsiz olmalı
        assert reconstruct_key(shares[b], shares[a]) == secret


def test_shamir_shares_do_not_leak_the_secret() -> None:
    """Payların ham değeri gizli anahtarı doğrudan içermemeli."""
    secret = secrets.token_bytes(_KEY_SIZE)
    shares = _sss_split(secret)

    hex_secret = secret.hex()
    for share in shares:
        assert hex_secret not in share
    assert len(set(shares)) == 3


def test_derived_third_share_matches_split_output() -> None:
    """
    share_1 + share_2'den türetilen f(3), split'in ürettiği share_3 ile aynı olmalı.

    Geriye dönük uyumluluğun temeli: 2-of-2 döneminde oluşturulmuş vault'lar
    yeniden anahtarlanmadan 2-of-3'e yükseltilebilir.
    """
    for _ in range(50):
        secret = secrets.token_bytes(_KEY_SIZE)
        share_1, share_2, share_3 = _sss_split(secret)

        assert vault_manager._sss_derive_share(share_1, share_2, 3) == share_3
        # Türetilmiş pay gerçekten kurtarabilmeli
        assert reconstruct_key(share_1, share_3) == secret
        assert reconstruct_key(share_2, share_3) == secret


def test_any_share_can_be_derived_from_the_other_two() -> None:
    """Herhangi iki paydan üçüncüsü türetilebilmeli — kurtarma yollarının hepsi açık."""
    secret = secrets.token_bytes(_KEY_SIZE)
    s1, s2, s3 = _sss_split(secret)

    assert vault_manager._sss_derive_share(s2, s3, 1) == s1
    assert vault_manager._sss_derive_share(s1, s3, 2) == s2
    assert vault_manager._sss_derive_share(s1, s2, 3) == s3


def test_share_parsing_rejects_malformed_input() -> None:
    """Bozuk pay girdisi net hata vermeli — kurtarma akışında elle girilir."""
    for bad in ("", "abc", "9:" + "ab" * 33, "x:" + "ab" * 33, "1:zzzz"):
        with pytest.raises(ValueError):
            vault_manager._parse_share(bad)


def test_shamir_single_share_cannot_recover_secret() -> None:
    """
    Eşikten az pay (1 adet) asla orijinal anahtarı vermemeli.

    Tek pay elinde olan saldırganın deneyebilecekleri:
      · aynı payı iki kez kullanmak
      · payın indisini değiştirip ikinci payı taklit etmek
      · ikinci pay yerine rastgele değer denemek
    Hiçbiri orijinal anahtarla eşleşmemeli (ya hata ya yanlış veri).
    """
    secret = secrets.token_bytes(_KEY_SIZE)
    share_1, share_2, share_3 = _sss_split(secret)
    y1_hex = share_1.split(":", 1)[1]
    y2_hex = share_2.split(":", 1)[1]

    # (a) Payın kendi ham değeri gizli anahtar değil
    for share in (share_1, share_2, share_3):
        assert bytes.fromhex(share.split(":", 1)[1])[-_KEY_SIZE:] != secret

    # (b) Aynı pay iki kez — indis doğrulaması reddetmeli (üçü için de)
    for share in (share_1, share_2, share_3):
        with pytest.raises(ValueError, match="indisli"):
            reconstruct_key(share, share)

    # (c) share_1'i "2:" olarak etiketleyip ikinci pay gibi kullanmak
    forged = _recover_or_none(share_1, f"2:{y1_hex}")
    assert forged != secret

    # (d) share_2'yi "1:" olarak etiketlemek
    forged = _recover_or_none(f"1:{y2_hex}", share_2)
    assert forged != secret

    # (e) İkinci pay yerine rastgele denemeler
    fmt = f"{{:0{_SSS_SHARE_HEX_LEN}x}}"
    for _ in range(200):
        guess = fmt.format(secrets.randbelow(_SSS_PRIME))
        assert _recover_or_none(share_1, f"2:{guess}") != secret


def test_shamir_share_1_is_information_theoretically_hiding() -> None:
    """
    Aynı gizli anahtar defalarca bölündüğünde share_1 her seferinde farklı olmalı.

    Sabit veya öngörülebilir share_1, tek payın gizli hakkında bilgi
    sızdırdığı anlamına gelir (SSS'in temel garantisi ihlal edilir).
    """
    secret = secrets.token_bytes(_KEY_SIZE)
    first_shares = {_sss_split(secret)[0] for _ in range(200)}

    assert len(first_shares) == 200, "share_1 tekrar ediyor — polinom katsayısı rastgele değil"


def test_single_share_reveals_nothing_about_the_secret() -> None:
    """
    Tek pay bilgi-teorik olarak hiçbir şey vermemeli.

    Aynı payı üreten iki farklı gizli anahtar bulunabildiği sürece, tek pay
    elindeki saldırgan hangi anahtarın doğru olduğunu ayırt edemez. Bunu
    şöyle gösteriyoruz: verilen bir share_1 değeri için HER olası gizli
    anahtara uyan bir polinom vardır (a1 = y1 - s).
    """
    secret = secrets.token_bytes(_KEY_SIZE)
    share_1, _s2, _s3 = _sss_split(secret)
    _idx, y1 = vault_manager._parse_share(share_1)

    # Tamamen farklı 100 "aday" anahtarın her biri bu share_1 ile tutarlı
    for _ in range(100):
        aday = int.from_bytes(secrets.token_bytes(_KEY_SIZE), "big")
        a1 = (y1 - aday) % vault_manager._SSS_PRIME
        # f(1) = aday + a1 == y1  → yani bu share_1 o adayla da uyumlu
        assert (aday + a1) % vault_manager._SSS_PRIME == y1


# ── Platform guard (kernel32 bağlaması) ───────────────────────────────────────

def test_kernel32_binding_matches_platform(tmp_path: Path) -> None:
    """
    _k32 platform guard'ının her iki tarafını da doğrular.

    Windows : _k32 gerçek kernel32'ye bağlı olmalı ve readonly biti
              GERÇEKTEN uygulanmalı (yalnızca "None değil" kontrolü yetmez —
              guard'ın no-op'a düşüp sessizce koruma kaybettirmediğini kanıtlar).
    Diğer   : _k32 None olmalı, yardımcılar patlamadan no-op geçmeli.

    Bu test CI matrisinin iki ayağında farklı dalları çalıştırır; ikisi birden
    yeşilse guard doğru davranıyor demektir.
    """
    target = tmp_path / "vault.hclv"
    target.write_bytes(b"vault icerigi")

    if sys.platform != "win32":
        assert vault_manager._k32 is None, "Windows dışında kernel32 bağlanmamalı"

        # Yardımcılar sessizce no-op olmalı — istisna fırlatmamalı
        vault_manager._set_readonly(target)
        vault_manager._clear_readonly(target)
        with vault_manager._writable(target):
            target.write_bytes(b"guncellendi")
        assert target.read_bytes() == b"guncellendi"
        return

    # ── Windows ayağı ────────────────────────────────────────────────────────
    assert vault_manager._k32 is not None, "Windows'ta kernel32'ye bağlanmalıydı"

    attrs = vault_manager._k32.GetFileAttributesW(str(target))
    assert attrs != _INVALID_FILE_ATTRIBUTES, "GetFileAttributesW çağrısı başarısız"
    assert not attrs & _FILE_ATTRIBUTE_READONLY

    try:
        # readonly biti gerçekten uygulanıyor mu
        vault_manager._set_readonly(target)
        assert vault_manager._k32.GetFileAttributesW(str(target)) & _FILE_ATTRIBUTE_READONLY
        with pytest.raises(PermissionError):
            target.write_bytes(b"izinsiz yazma")

        # _writable bağlamı içinde yazılabilir, çıkışta koruma geri gelmeli
        with vault_manager._writable(target):
            target.write_bytes(b"yetkili yazma")
        assert vault_manager._k32.GetFileAttributesW(str(target)) & _FILE_ATTRIBUTE_READONLY
        vault_manager._clear_readonly(target)
        assert target.read_bytes() == b"yetkili yazma"

        assert not vault_manager._k32.GetFileAttributesW(str(target)) & _FILE_ATTRIBUTE_READONLY
    finally:
        # tmp_path temizliği readonly dosyada takılmasın
        vault_manager._clear_readonly(target)


# ══════════════════════════════════════════════════════════════════════════════
# B-021 — taşan interpolasyon sonucu
# ══════════════════════════════════════════════════════════════════════════════

def _tasiran_paylar(kaydirma: int = 0) -> tuple[str, str]:
    """
    Interpolasyonu [2**256, asal) aralığına düşüren iki pay üretir.

    f(x) = s + x  polinomu, s = 2**256 + kaydirma. `s` asaldan küçük
    (asal = 2**256 + 297) ama 32 bayta SIĞMIYOR. Paylar f(1) ve f(2).

    Bu girdi rastgele bulunamaz: aralık asalın 297/2**256'sı kadar. Fuzzer
    da bulamadı — `tests/fuzz/fuzz_shamir.py` tohum korpusunda elle kuruyor.
    """
    s = 2**256 + kaydirma
    return (
        vault_manager._fmt_share(1, (s + 1) % vault_manager._SSS_PRIME),
        vault_manager._fmt_share(2, (s + 2) % vault_manager._SSS_PRIME),
    )


@pytest.mark.parametrize("kaydirma", [0, 1, 148, 296])
def test_tasan_paylar_valueerror_veriyor(kaydirma: int) -> None:
    """
    GERÇEK BİR HATANIN TESTİ (B-021, fuzzing ile bulundu).

    Lagrange sonucu 32 bayta sığmadığında `to_bytes()` `OverflowError`
    fırlatıyordu. `reconstruct_key()` yalnızca `ValueError` vaat ediyor ve
    kurtarma akışı (`CORE/recover_vault.py`) ile arayüz onu yakalıyor —
    `OverflowError` o ağdan kaçıp çıplak bir yığın izi olarak yansıyordu.

    Kurtarma parçası kullanıcının ELLE YAZDIĞI tek kripto girdisi olduğu
    için erişilebilir bir yoldu.
    """
    a, b = _tasiran_paylar(kaydirma)

    with pytest.raises(ValueError) as bilgi:
        vault_manager.reconstruct_key(a, b)

    assert not isinstance(bilgi.value, OverflowError), "hâlâ OverflowError"
    assert isinstance(bilgi.value.__cause__, OverflowError), (
        "asıl sebep zincirde korunmalı — hata ayıklarken gerekiyor"
    )


def test_tasan_pay_mesaji_kullaniciya_yol_gosteriyor() -> None:
    """
    Mesaj İÇERİK olarak da doğru olmalı.

    Kullanıcı buraya zaten kasasına giremediği için geliyor. "Bir şey
    patladı" demek onu bir adım ileri götürmez; "parçayı kontrol edin"
    götürür. Düzeltmenin değeri istisna tipinde değil, burada.
    """
    a, b = _tasiran_paylar()
    with pytest.raises(ValueError) as bilgi:
        vault_manager.reconstruct_key(a, b)

    mesaj = str(bilgi.value)
    assert "kurtarma parçası" in mesaj.lower(), mesaj
    assert any(k in mesaj.lower() for k in ("kontrol", "yeniden dene")), mesaj
    # İç ayrıntı sızmamalı: kullanıcı 'to_bytes' ya da 'OverflowError' görmemeli.
    assert "to_bytes" not in mesaj and "OverflowError" not in mesaj, mesaj


def test_gecerli_paylar_etkilenmedi() -> None:
    """
    Düzeltme normal yolu bozmamalı — 2-of-3 üç kombinasyonda da çalışmalı.

    Bu test olmadan `to_bytes`'ı tümüyle kaldırmak da testleri geçirirdi.
    """
    sir = bytes(range(32))
    p1, p2, p3 = vault_manager._sss_split(sir)
    for x, y in ((p1, p2), (p1, p3), (p2, p3), (p3, p1)):
        assert vault_manager.reconstruct_key(x, y) == sir


def test_sinirin_hemen_altindaki_sir_calisiyor() -> None:
    """
    Sınır durumu: 2**256 - 1 tam olarak 32 bayta sığıyor, reddedilmemeli.

    Kontrolün fazla geniş olup geçerli bir anahtarı reddetmediğini gösterir —
    bu, kullanıcıyı kendi kasasından kilitleyecek türden bir hata olurdu.
    """
    s = 2**256 - 1
    a = vault_manager._fmt_share(1, (s + 1) % vault_manager._SSS_PRIME)
    b = vault_manager._fmt_share(2, (s + 2) % vault_manager._SSS_PRIME)
    assert vault_manager.reconstruct_key(a, b) == s.to_bytes(32, "big")
