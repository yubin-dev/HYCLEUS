#!/usr/bin/env python3
"""
Fuzz hedefi — `.hclx` teslim paketi: `create_package`/`open_package`.

Neden bu hedef, NOT-WIRED olmasına rağmen
------------------------------------------
`CORE/hclx.py`'nin kendi modül docstring'i EXPERIMENTAL/NOT-WIRED diyor —
`create_package()`/`open_package()`'ı bugün üretimde hiçbir menü, CLI ya
da zamanlanmış iş çağırmıyor (BACKLOG B-043, `tests/
test_deneysel_bagli_degil.py`). Ama ikisi de GÜVENİLMEYEN VERİ ayrıştırıyor
— `open_package()`, alıcının makinesinde duran, düzenlenebilir bir dosyayı
okuyor — ve bağlı olmamak bu ayrıştırıcının güvenli olduğu anlamına
gelmiyor. Fuzzing yapmak üretime bağlama kararını DEĞİŞTİRMİYOR: modül
hâlâ NOT-WIRED (bkz. SECURITY.md §4.14, BACKLOG B-109).

Aranan sözleşme
----------------
Modülün TEK istisna tipi `HclxError` (`ValueError`'ın bir varyantı değil,
doğrudan `Exception`'dan türüyor). `read_manifest()`, `pencere_durumu()`,
`open_package()` ve `create_package()`'ın dördü de yalnızca `HclxError`
fırlatabileceklerini belgeliyor — `open_package()` içeride `decrypt_file()`
'in üç istisnasını (`ValueError`, `AuthenticationError`, `OSError`) da
yakalayıp `HclxError`'a çeviriyor, yani dışarı hiçbiri sızmamalı.

Dört kip
--------
Rastgele baytları doğrudan dosyaya yazmak sığ bir fuzz olurdu — girdilerin
neredeyse tamamı ilk altı baytta "magic tutmuyor" deyip dönerdi. Bu yüzden:

  · kip 0-2: ham/yarı yapılandırılmış baytlar — `read_manifest()`'in
    biçim kontrollerini (magic, sürüm, uzunluk, JSON) hedefliyor.
  · kip 3: `create_package()`'ın kendi girdi doğrulaması — anahtar boyu,
    boş dosya listesi, geçersiz pencere.
  · kip 4-5: GERÇEKTEN üretilmiş bir paket — `fuzz_crypto.py`'deki
    `_gercek_dosya_mutasyonu` ile aynı fikir: kip 4 hiç dokunmadan tam bir
    tur (DEĞİŞMEZ: dosyalar aynen geri gelmeli), kip 5 tek bir baytı bozar.

Ayrıca `pencere_durumu()` doğrudan, elle kurulmuş bozuk tarih dizeleriyle
de deneniyor — `_coz_damga()`'nın kendi `HclxError` sözleşmesini hedefler.
"""
from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import BilinenIhlal, Tuketici, cagir, enstrumante, main  # noqa: E402

# Enstrümantasyon bloğu — bkz. fuzz_crypto.py'deki aynı yorum ve
# harness.enstrumante docstring'i. Bu olmadan kapsam güdümlü değil.
with enstrumante():  # noqa: E402
    from CORE.hclx import (
        MAGIC,
        HclxError,
        Manifest,
        create_package,
        open_package,
        pencere_durumu,
        read_manifest,
    )

#: `read_manifest`/`pencere_durumu`/`open_package`/`create_package`'ın
#: dördünün de belgelenmiş TEK istisnası.
IZINLI: tuple[type[BaseException], ...] = (HclxError,)

#: Sabit anahtar — aradığımız şey ayrıştırma davranışı, anahtar kalitesi
#: değil. Sabit olması koşumu da tekrarlanabilir kılıyor.
ANAHTAR = bytes(range(32))

#: Bilinen ve düzeltilmemiş ihlal YOK.
BILINEN: tuple[BilinenIhlal, ...] = ()

#: Hedefe özel tohum korpusu.
TOHUMLAR: tuple[bytes, ...] = (
    b"",
    b"HYCLX",                                    # magic'ten 1 bayt kısa
    MAGIC,                                        # yalnızca magic
    MAGIC + b"\x01",                              # sürüm var, uzunluk yok
    MAGIC + b"\x01" + b"\x00\x00\x00\x00",        # boş manifesto, boş gövde
    MAGIC + b"\x63" + b"\x00\x00\x00\x00",        # desteklenmeyen sürüm
    MAGIC + b"\x01" + b"\xff\xff\xff\xff",        # devasa manifesto iddiası
)


def _yaz(dizin: Path, icerik: bytes) -> Path:
    yol = dizin / "girdi.hclx"
    yol.write_bytes(icerik)
    return yol


def _basliklı_paket(t: Tuketici) -> bytes:
    """
    Magic'i DOĞRU, sürüm ve uzunluk alanı fuzzer'dan gelen bir kap.

    Bu kip olmadan fuzzer başlığın ötesine neredeyse hiç geçemez.
    """
    surum = t.bayt(1)
    uzunluk_ham = t.bayt(4)
    gercek = t.kalan()
    ilan_edilen = int.from_bytes(uzunluk_ham, "big")
    # Uzunluk alanı bilerek bazen TUTARLI: manifestonun JSON olarak
    # ayrıştığı, "format" kontrolünün ötesine geçen daha derin bir yola
    # giden tek yol bu.
    if ilan_edilen % 4 == 0:
        uzunluk_ham = min(len(gercek), 200).to_bytes(4, "big")
    return MAGIC + surum + uzunluk_ham + gercek


def _dosyalar(dizin: Path, t: Tuketici) -> list[Path | str]:
    n = 1 + t.tamsayi(3)
    yollar: list[Path | str] = []
    for i in range(n):
        p = dizin / f"belge{i}.txt"
        p.write_bytes(t.bayt(1 + t.tamsayi(48)))
        yollar.append(p)
    return yollar


def _gercek_paket(dizin: Path, t: Tuketici) -> Path | None:
    """
    GERÇEKTEN üretilmiş bir `.hclx`. Şifreleme kipi bu kipin konusu değil —
    üretim başarısız olursa (nadiren, örn. rastgele not dizesiyle ilgisiz
    bir sebep) sessizce vazgeçiyoruz.
    """
    yollar = _dosyalar(dizin, t)
    hedef = dizin / "gercek.hclx"
    try:
        create_package(
            yollar, ANAHTAR, user_id=1, hwid="FUZZ-HWID", dst=hedef,
            gecerlilik_saat=1 + t.tamsayi(200),
            note=t.bayt(8).decode("latin-1"),
        )
    except Exception:  # noqa: BLE001 — üretim kipi bu kipin konusu değil
        return None
    return hedef


def one_input(data: bytes) -> None:
    t = Tuketici(data)
    kip = t.tamsayi(6)

    with tempfile.TemporaryDirectory(prefix="hycleus-fuzz-") as td:
        dizin = Path(td)
        yol: Path | None = None

        if kip == 0:
            yol = _yaz(dizin, t.kalan())
        elif kip == 1:
            yol = _yaz(dizin, MAGIC + t.kalan())
        elif kip == 2:
            yol = _yaz(dizin, _basliklı_paket(t))
        elif kip == 3:
            # create_package'ın kendi girdi doğrulaması — anahtar boyu,
            # boş dosya listesi, sıfır/negatif pencere.
            anahtar = t.bayt(t.tamsayi(40))
            yollar = _dosyalar(dizin, t) if t.bayt(1)[0] & 1 else []
            saat = t.tamsayi(400) - 100
            cagir(
                "create_package", IZINLI, data,
                lambda: create_package(
                    yollar, anahtar, user_id=1, hwid="FUZZ-HWID",
                    dst=dizin / "cikti.hclx", gecerlilik_saat=saat,
                ),
            )
        else:
            uretilen = _gercek_paket(dizin, t)
            if uretilen is not None:
                if kip == 5:
                    # Tek bayt bozuluyor — gerisi tamamen geçerli. En
                    # değerli kip: her alan geçerli, yalnızca bir yeri
                    # yanlış.
                    ham = bytearray(uretilen.read_bytes())
                    if ham:
                        ofset = int.from_bytes(t.bayt(4), "big") % len(ham)
                        ham[ofset] ^= t.bayt(1)[0] or 0xFF
                        uretilen.write_bytes(bytes(ham))
                    yol = uretilen
                else:
                    # kip == 4 — DEĞİŞMEZ: tamamen geçerli bir paket,
                    # doğru anahtar ve hwid'le, dosyaları AYNEN geri
                    # vermeli.
                    dosyalar = cagir(
                        "open_package(gercek)", IZINLI, data,
                        lambda: open_package(uretilen, ANAHTAR, hwid="FUZZ-HWID"),
                    )
                    if dosyalar is not None:
                        for pd in dosyalar:  # type: ignore[union-attr]
                            assert hashlib.sha256(pd.veri).hexdigest() == pd.sha256, (
                                f"özet tutmuyor: {pd.ad}"
                            )

        if yol is not None:
            cagir("read_manifest", IZINLI, data, lambda: read_manifest(yol))

            anahtar2 = ANAHTAR if t.bayt(1)[0] & 1 else t.bayt(32)
            hwid = "FUZZ-HWID" if t.bayt(1)[0] & 1 else None
            cagir(
                "open_package", IZINLI, data,
                lambda: open_package(yol, anahtar2, hwid=hwid),
            )

        # pencere_durumu doğrudan — created_at/valid_from/valid_until
        # BİLEREK bozuk dizeler olabilir; `_coz_damga()`'nın kendi
        # HclxError sözleşmesini hedefliyor.
        manifest = Manifest(
            package_id="fuzz", created_at="x",
            valid_from=t.bayt(10).decode("latin-1"),
            valid_until=t.bayt(10).decode("latin-1"),
            sender_user_id=None, sender_hwid="FUZZ-HWID",
            payload_sha256="0" * 64,
        )
        cagir("pencere_durumu", IZINLI, data, lambda: pencere_durumu(manifest))


def _kendi_kendini_sina() -> None:
    """
    Harness'ın GERÇEKTEN bir şey ürettiğini gösteren küçük duman testi.

    `python tests/fuzz/fuzz_hclx.py --yerel` çalıştırıldığında bu fonksiyon
    çağrılmıyor; yalnızca elle kontrol için duruyor.
    """
    one_input(b"")
    one_input(b"\x04" + bytes(range(200)))


if __name__ == "__main__":
    raise SystemExit(
        main(one_input, ad="hclx", bilinen=BILINEN, tohumlar=TOHUMLAR)
    )
