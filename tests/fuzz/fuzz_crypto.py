#!/usr/bin/env python3
"""
Fuzz hedefi — `.hcl` kabı: `decrypt_file` / `verify_file` / `encrypt_file`.

Neden bu üçü
------------
Bunlar HYCLEUS'un GÜVENİLMEYEN VERİ okuduğu tek yer. Bir `.hcl` dosyası
diskte duruyor; bozulabilir, kısmen yazılmış olabilir, ya da birileri
kasten değiştirmiş olabilir (SECURITY.md §1: diske erişebilen bir saldırgan
güven sınırının dışında değil). Kabı okuyan kod, ne gelirse gelsin
BELGELENMİŞ bir istisnayla dönmeli.

Aranan şey çökme değil, sözleşme ihlali
---------------------------------------
`decrypt_file()` docstring'i şunu vaat ediyor:

    ValueError          — bozuk başlık veya desteklenmeyen versiyon
    AuthenticationError — ciphertext, anahtar veya AAD değiştirilmiş
    OSError             — dosya okuma hatası

Çağıran taraflar (`CORE/export.py`, `UI/main_window_files.py`) tam olarak
bu üçünü yakalıyor. Dördüncü bir istisna tipi o ağdan kaçar ve kullanıcıya
"bu dosya bozulmuş" yerine çıplak bir çökme olarak yansır.

Beş kip
-------
Rastgele baytları doğrudan dosyaya yazmak sığ bir fuzz olurdu: girdilerin
neredeyse tamamı ilk dört baytta "geçersiz format" deyip dönerdi. Bu yüzden
harness girdiyi YAPILANDIRILMIŞ biçimde kullanıyor — sihirli sayıyı,
başlığı, hatta gerçek bir şifrelemeyi kendisi kuruyor ve fuzzer'ın
baytlarını alanların içine dolduruyor.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import BilinenIhlal, Tuketici, cagir, enstrumante, main  # noqa: E402

# `enstrumante()` bloğu ŞART: atheris Python kodunu kendiliğinden izlemiyor.
# Bu blok olmadan libFuzzer çalışır ama geri bildirim almaz — hızlı rastgele
# fuzzing olur, kapsam güdümlü olmaz. Bkz. harness.enstrumante docstring'i;
# gerçek bir koşuda 1 milyon girdi, 0 yeni korpus birimi üretildi.
with enstrumante():  # noqa: E402
    from CORE.crypto import (
        AuthenticationError,
        decrypt_file,
        encrypt_file,
        verify_file,
    )

#: `decrypt_file` / `verify_file` docstring'lerinin vaat ettiği küme.
IZINLI: tuple[type[BaseException], ...] = (ValueError, AuthenticationError, OSError)

#: Sabit anahtar: fuzzer'ın anahtar üretmesine gerek yok, aradığımız şey
#: anahtar kalitesi değil ayrıştırma davranışı. Sabit olması koşumu da
#: tekrarlanabilir kılıyor.
ANAHTAR = bytes(range(32))

#: Bilinen ve düzeltilmemiş ihlal YOK.
#:
#: Bir zamanlar iki tane vardı ve ikisi de B-012'ydi: `decrypt_file` başlığı
#: kendi başına ayrıştırıyor, `verify_file`'ın dört uzunluk kontrolünün
#: hiçbirini yapmıyordu. Kesik dosyada `IndexError`, beş baytlık dosyada
#: `struct.error` fırlatıyordu; ikincisini bu harness buldu.
#:
#: Düzeltildi: iki yol da `CORE.crypto._read_header()` çağırıyor. Liste
#: boşaldı ve `tests/test_fuzz_harness.py` boş listede de anlamlı: artık
#: HERHANGİ bir sözleşme ihlali hata sayılıyor.
BILINEN: tuple[BilinenIhlal, ...] = ()


#: Hedefe özel tohum korpusu — libFuzzer'ın "seed corpus"unun karşılığı.
#: İlk bayt kip seçici (`t.tamsayi(5)`), gerisi o kipin yükü.
TOHUMLAR: tuple[bytes, ...] = (
    b"\x00HYCL",              # kip 0, ham: tam 4 bayt → B-012
    b"\x00HYCL\x02",          # kip 0, sürüm var, gerisi yok
    b"\x00HYC",               # sihirli sayıdan da kısa
    b"\x01",                  # kip 1: "HYCL" + hiçbir şey
    b"\x02" + b"\x02" + b"\x00" * 12 + b"\x00\x00\x00\x00",  # kip 2, boş AAD
)


def _yaz(dizin: Path, icerik: bytes) -> Path:
    yol = dizin / "girdi.hcl"
    yol.write_bytes(icerik)
    return yol


def _basliklı_kap(t: Tuketici) -> bytes:
    """
    Sihirli sayısı ve başlığı DOĞRU, gerisi fuzzer'dan gelen bir kap.

    Bu kip olmadan fuzzer başlığın ötesine neredeyse hiç geçemez.
    """
    versiyon = t.bayt(1)
    nonce = t.bayt(12)
    aad_boy = t.bayt(4)
    (ilan_edilen,) = (int.from_bytes(aad_boy, "big"),)
    # AAD'nin ilan edilen uzunluğu bilerek TUTARSIZ olabiliyor: tutarlı
    # olduğu durumları da üretmek için gerçek uzunluğu bazen kullanıyoruz.
    gercek = t.kalan()
    if ilan_edilen % 3 == 0:
        aad_boy = len(gercek[:64]).to_bytes(4, "big")
    return b"HYCL" + versiyon + nonce + aad_boy + gercek


def _gercek_dosya_mutasyonu(dizin: Path, t: Tuketici) -> Path | None:
    """
    GERÇEKTEN şifrelenmiş bir dosya üretip tek bir baytını bozar.

    En değerli kip: dosya her alanında geçerli, yalnızca bir yeri yanlış.
    Beklenen sonuç `AuthenticationError` (GCM tag tutmaz) ya da başlık
    alanı bozulduysa `ValueError` — üçüncü bir şey olmamalı.
    """
    kaynak = dizin / "duz.txt"
    kaynak.write_bytes(t.bayt(64))
    try:
        hedef, _sha, _ts = encrypt_file(
            kaynak, ANAHTAR, user_id=1, hwid="FUZZ-HWID",
            dst=dizin / "sifreli.hcl",
        )
    except Exception:  # noqa: BLE001 — şifreleme kipi bu kipin konusu değil
        return None

    ham = bytearray(Path(hedef).read_bytes())
    if not ham:
        return None
    ofset = int.from_bytes(t.bayt(4), "big") % len(ham)
    ham[ofset] ^= t.bayt(1)[0] or 0xFF
    Path(hedef).write_bytes(bytes(ham))
    return Path(hedef)


def one_input(data: bytes) -> None:
    t = Tuketici(data)
    kip = t.tamsayi(5)

    with tempfile.TemporaryDirectory(prefix="hycleus-fuzz-") as td:
        dizin = Path(td)

        if kip == 0:
            # Ham baytlar. Sığ ama B-012'yi bulan kip bu.
            yol = _yaz(dizin, t.kalan())
        elif kip == 1:
            yol = _yaz(dizin, b"HYCL" + t.kalan())
        elif kip == 2:
            yol = _yaz(dizin, _basliklı_kap(t))
        elif kip == 3:
            # Fragman (zaman damgası) alanını taklit et — v2 kabında
            # gövdenin nerede bittiğini bu belirliyor.
            govde = _basliklı_kap(t)
            uzunluk = t.bayt(4)
            yol = _yaz(dizin, govde + b"HTST" + t.kalan() + uzunluk + b"HTST")
        else:
            mutant = _gercek_dosya_mutasyonu(dizin, t)
            if mutant is None:
                return
            yol = mutant

        # HWID bazen veriliyor, bazen değil: AAD/HWID karşılaştırma dalı
        # yalnızca verildiğinde çalışıyor.
        hwid = "FUZZ-HWID" if t.bayt(1)[0] & 1 else None

        cagir("verify_file", IZINLI, data, lambda: verify_file(yol, ANAHTAR, hwid=hwid))

        sonuc = cagir(
            "decrypt_file", IZINLI, data,
            lambda: decrypt_file(yol, ANAHTAR, hwid=hwid),
        )
        if sonuc is not None:
            duz, meta = sonuc  # type: ignore[misc]
            # Çözme başardıysa iki değişmez tutmalı.
            assert isinstance(duz, bytes), type(duz)
            assert isinstance(meta, dict), type(meta)
            del duz


def _kendi_kendini_sina() -> None:
    """
    Harness'ın GERÇEKTEN bir şey ürettiğini gösteren küçük duman testi.

    `python tests/fuzz/fuzz_crypto.py --yerel` çalıştırıldığında bu
    fonksiyon çağrılmıyor; yalnızca elle kontrol için duruyor.
    """
    one_input(b"")
    one_input(b"HYCL")
    one_input(bytes(range(256)))


if __name__ == "__main__":
    os.environ.setdefault("HYCLEUS_DEV_MODE", "0")
    raise SystemExit(
        main(one_input, ad="crypto", bilinen=BILINEN, tohumlar=TOHUMLAR)
    )
