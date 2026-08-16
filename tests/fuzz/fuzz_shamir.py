#!/usr/bin/env python3
"""
Fuzz hedefi — Shamir 2-of-3 paylaşımı ve kurtarma parçası kodlaması.

Neden bu hedef
--------------
Kurtarma parçası (share 3) **kullanıcının elle yazdığı** tek kripto
girdisi: kâğıda basılıyor, sonra tekrar klavyeden giriliyor
(`CORE/recovery_share.py` docstring'i "esnek: boşluk, satır sonu, küçük
harf ve eksik/fazla tire tolere edilir" diyor). Yani ayrıştırıcı bilerek
hoşgörülü ve hoşgörülü ayrıştırıcılar sürprizlerin yaşadığı yerdir.

İkinci sebep: `reconstruct_key()` bu payları alıp doğrudan bir master key
üretiyor. Kurtarma akışı (`CORE/recover_vault.py`) o anahtarla kasayı
açmaya çalışıyor. Ayrıştırma katmanından geçen her şey kriptonun kalbine
giriyor.

Aranan sözleşmeler
------------------
    decode_share()      → RecoveryShareError (ValueError alt sınıfı)
    _parse_share()      → ValueError
    reconstruct_key()   → ValueError ("paylar geçersiz formattaysa veya
                          aynı indisliyse")

Ayrıca DEĞİŞMEZLER sınanıyor:
    · split → herhangi iki payla recover == orijinal sır (üç kombinasyon)
    · encode → decode roundtrip aynı payı vermeli
    · aynı indisli iki pay reddedilmeli (eşik gerçekten 2 mi)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import BilinenIhlal, Tuketici, cagir, enstrumante, main  # noqa: E402

# Enstrümantasyon bloğu — bkz. fuzz_crypto.py'deki aynı yorum ve
# harness.enstrumante docstring'i. Bu olmadan kapsam güdümlü değil.
with enstrumante():  # noqa: E402
    from CORE.recovery_share import (
        RecoveryShareError,
        decode_share,
        encode_share,
    )
    from CORE.vault_manager import (
        _parse_share,
        _sss_split,
        reconstruct_key,
    )

IZINLI_PAY: tuple[type[BaseException], ...] = (ValueError,)
IZINLI_KODLAMA: tuple[type[BaseException], ...] = (RecoveryShareError, ValueError)

#: Bilinen ve düzeltilmemiş ihlal YOK.
#:
#: Bir zamanlar B-021 vardı: `reconstruct_key()` Lagrange sonucu
#: [2**256, asal) aralığına düştüğünde `to_bytes(32)` ile `OverflowError`
#: fırlatıyordu. Bu harness'ın tohum korpusu bulmuştu (rastgele
#: bulunamazdı — aralık asalın 297/2**256'sı kadar).
#:
#: Düzeltildi: `_sss_recover()` artık yakalayıp kullanıcıya "kurtarma
#: parçasını kontrol edin" diyen bir `ValueError`'a çeviriyor.
#: `_tasan_pay_tohumu()` tohum korpusunda KALIYOR — düzeltilmiş bir yolu
#: fuzz'lamayı bırakmak, düzeltmenin geri alınmasını görünmez kılardı.
BILINEN: tuple[BilinenIhlal, ...] = ()


def _tasan_pay_tohumu() -> bytes:
    """
    B-021'i tetikleyen girdiyi ELLE kurar.

    Rastgele bir sürücü bunu bulamaz: Lagrange sonucunun [2**256, asal)
    aralığına düşmesi gerekiyor ve o aralık asalın 297/2**256'sı kadar.
    Yani "fuzz'ladık, bulamadı" ile "fuzz'ladık, yok" arasındaki farkı
    kapatmak için tohum korpusu şart.

    Kurulum: f(x) = s + x, s = 2**256 (asaldan küçük ama 32 bayta sığmıyor).
    Paylar f(1) ve f(2); interpolasyon s'i geri veriyor ve `to_bytes(32)`
    OverflowError fırlatıyor.

    Bayt düzeni `_pay_metni`'nin kip 2 dalını hedefliyor:
        [kip: %3==2][indis baytı][33 bayt y]  ×2
    """
    s = 2**256
    parcalar = bytearray()
    for indis in (0, 1):                       # → 1 + indis  = pay 1 ve 2
        parcalar += b"\x02"                    # kip 2
        parcalar += bytes([indis])
        parcalar += (s + indis + 1).to_bytes(33, "big")
    return bytes(parcalar)


#: Hedefe özel tohum korpusu.
TOHUMLAR: tuple[bytes, ...] = (
    _tasan_pay_tohumu(),
    b"\x02\x00" + b"\x00" * 33 + b"\x02\x00" + b"\x00" * 33,  # aynı indis, sıfır y
    b"\x01\x03",              # biçime yakın ama indis aralık dışı
    b"\x00" + b":" * 48,      # yalnızca ayraç
)


def _pay_metni(t: Tuketici) -> str:
    """
    Fuzzer baytlarından bir "pay" dizesi üretir.

    Üç kip: tamamen serbest metin, biçime YAKIN metin, ve geçerli bir pay.
    İkincisi en verimlisi — `_parse_share`'ı ilk kontrolün ötesine taşıyor.
    """
    kip = t.tamsayi(3)
    if kip == 0:
        return t.bayt(48).decode("latin-1")
    if kip == 1:
        indis = t.bayt(1)[0] % 6          # bazen geçerli (1-3), bazen değil
        golge = t.bayt(33).hex()
        kes = t.bayt(1)[0] % (len(golge) + 1)
        return f"{indis}:{golge[:kes]}"
    return f"{1 + t.bayt(1)[0] % 3}:{t.bayt(33).hex()}"


def one_input(data: bytes) -> None:
    t = Tuketici(data)

    # ── 1. Pay ayrıştırıcısı ─────────────────────────────────────────────────
    a, b = _pay_metni(t), _pay_metni(t)
    cagir("_parse_share", IZINLI_PAY, data, lambda: _parse_share(a))
    cagir("reconstruct_key", IZINLI_PAY, data, lambda: reconstruct_key(a, b))

    # ── 2. Kurtarma parçası kodlaması ────────────────────────────────────────
    metin = t.bayt(72).decode("latin-1")
    cagir("decode_share", IZINLI_KODLAMA, data, lambda: decode_share(metin))

    # Sözdizimsel olarak doğru bir HYCLEUS metniyle de dene: ön ek doğruysa
    # ayrıştırıcı base32 çözmeye kadar iniyor.
    govde = t.bayt(56).hex().upper().replace("0", "A").replace("1", "B")
    cagir(
        "decode_share(HYCLEUS-R3)", IZINLI_KODLAMA, data,
        lambda: decode_share("HYCLEUS-R3-" + govde),
    )

    # ── 3. Değişmezler: gerçek bir sırla tam tur ─────────────────────────────
    sir = t.bayt(32)
    paylar = cagir("_sss_split", IZINLI_PAY, data, lambda: _sss_split(sir))
    if paylar is None:
        return
    p1, p2, p3 = paylar  # type: ignore[misc]

    for x, y in ((p1, p2), (p1, p3), (p2, p3), (p2, p1), (p3, p1), (p3, p2)):
        geri = cagir(
            "reconstruct_key(gecerli)", IZINLI_PAY, data,
            lambda x=x, y=y: reconstruct_key(x, y),  # type: ignore[misc]
        )
        assert geri == sir, (
            f"2-of-3 kurtarma başarısız: {x[:6]}… + {y[:6]}… -> "
            f"{geri!r} != {sir!r}"
        )

    # Aynı indisli iki pay REDDEDİLMELİ — eşik gerçekten 2 mi?
    for tek in (p1, p2, p3):
        try:
            reconstruct_key(tek, tek)
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"Aynı pay iki kez verildi ve kabul edildi: {tek[:8]}… "
                "— eşik fiilen 1'e düşmüş olur."
            )

    # encode → decode roundtrip (yalnızca 3 indisli pay kodlanabiliyor).
    kodlu = cagir("encode_share", IZINLI_KODLAMA, data, lambda: encode_share(p3))
    if kodlu is not None:
        geri = cagir(
            "decode_share(roundtrip)", IZINLI_KODLAMA, data,
            lambda: decode_share(str(kodlu)),
        )
        assert geri == p3, f"roundtrip bozuldu: {geri!r} != {p3!r}"


if __name__ == "__main__":
    raise SystemExit(
        main(one_input, ad="shamir", bilinen=BILINEN, tohumlar=TOHUMLAR)
    )
