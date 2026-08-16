"""
HYCLEUS — fuzz koşum altyapısı.

Ne yapıyor
----------
Her fuzz hedefi tek bir `one_input(data: bytes) -> None` fonksiyonu yazıyor.
Bu modül onu iki şekilde koşturabiliyor:

  1. **atheris** kuruluysa — libFuzzer, kapsam güdümlü, `.github/workflows/fuzz.yml`
  2. **kuruluysa bile istenmezse / kurulu değilse** — buradaki basit rastgele
     sürücü: tohumlu, tekrarlanabilir, her platformda çalışır

İkinci mod bir "yedek plan" değil, kasıtlı bir tasarım. atheris Windows'ta
YOK ve Python sürüm desteği geride kalıyor; harness'ların kendisi ise her
geliştiricinin makinesinde ve normal CI'da çalışabilmeli. Yoksa yalnızca
elle tetiklenen bir iş akışında koşan kod yazmış oluruz ve o kod ilk
kırıldığında kimse fark etmez.

Sözleşme ihlali nedir
---------------------
Fuzzing'in burada aradığı şey çökme değil, **belgelenmiş istisna
sözleşmesinin dışına çıkan bir istisna**. `decrypt_file()` docstring'i
"ValueError, AuthenticationError, OSError" diyorsa ve fonksiyon
`IndexError` fırlatıyorsa, çağıran taraftaki `except ValueError` ağı onu
kaçırır ve kullanıcı çıplak bir çökme görür.

Her hedef `SOZLESME` sözlüğünde hangi çağrının hangi istisnaları
fırlatabileceğini yazıyor; `cagir()` bunun dışındaki her şeyi
`SozlesmeIhlali` olarak yükseltiyor.

Bilinen ihlaller
----------------
Bugün ihlal ÜRETEN çağrılar var ve düzeltilmedi (kapsam dışı). Onlar
`BILINEN` listesinde, backlog numarasıyla birlikte duruyor:
`tests/test_fuzz_harness.py` bilinenleri geçiriyor, YENİ bir ihlal
gördüğünde kırılıyor. Yani liste hem bir kayıt hem bir kapı.
"""
from __future__ import annotations

import argparse
import os
import random
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

KOK = Path(__file__).resolve().parent.parent.parent
if str(KOK) not in sys.path:
    sys.path.insert(0, str(KOK))


class SozlesmeIhlali(AssertionError):
    """Belgelenmiş istisna kümesinin dışında bir istisna sızdı."""

    def __init__(self, cagri: str, exc: BaseException, girdi: bytes) -> None:
        self.cagri = cagri
        self.exc = exc
        self.girdi = girdi
        super().__init__(
            f"{cagri} -> {type(exc).__name__}: {exc}\n"
            f"  girdi ({len(girdi)} byte): {girdi[:96]!r}"
        )

    @property
    def anahtar(self) -> tuple[str, str]:
        """`BILINEN` listesiyle karşılaştırma anahtarı."""
        return (self.cagri, type(self.exc).__name__)


@dataclass
class BilinenIhlal:
    """Kayıtlı, henüz düzeltilmemiş bir sözleşme ihlali."""

    cagri: str
    istisna: str
    backlog: str
    aciklama: str

    @property
    def anahtar(self) -> tuple[str, str]:
        return (self.cagri, self.istisna)


def cagir(
    cagri: str,
    izinli: tuple[type[BaseException], ...],
    girdi: bytes,
    fn: Callable[[], object],
) -> object | None:
    """
    `fn()` çalıştırır; `izinli` dışındaki istisnaları ihlal olarak yükseltir.

    `KeyboardInterrupt` / `SystemExit` dokunulmadan geçer — fuzzer'ı
    durdurabilmek gerekiyor.
    """
    try:
        return fn()
    except izinli:
        return None
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # noqa: BLE001 — yakalamak işin ta kendisi
        raise SozlesmeIhlali(cagri, exc, girdi) from exc


# ══════════════════════════════════════════════════════════════════════════════
# Girdi tüketici — atheris.FuzzedDataProvider'ın küçük, bağımsız karşılığı
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Tuketici:
    """
    Bir bayt dizisini yapılandırılmış parçalara bölen ufak yardımcı.

    Neden atheris.FuzzedDataProvider kullanılmıyor: harness'ların atheris
    OLMADAN da çalışması gerekiyor (bkz. modül docstring'i). Arayüz bilerek
    dar tutuldu; ihtiyaç büyürse atheris varken onu kullanan bir uyarlayıcı
    yazmak kolay.

    Veri bittiğinde sıfır/boş döner — asla istisna fırlatmaz. Fuzzer kısa
    girdiler üretiyor ve harness'ın onlarda da bir şey denemesi gerekiyor.
    """

    veri: bytes
    _i: int = field(default=0, repr=False)

    def bayt(self, n: int) -> bytes:
        parca = self.veri[self._i : self._i + n]
        self._i += n
        return parca.ljust(n, b"\x00") if len(parca) < n else parca

    def kalan(self) -> bytes:
        parca = self.veri[self._i :]
        self._i = len(self.veri)
        return parca

    def tamsayi(self, ust: int) -> int:
        """[0, ust) aralığında bir sayı. `ust <= 1` ise 0."""
        if ust <= 1:
            return 0
        if ust <= 256:
            return self.bayt(1)[0] % ust
        return int.from_bytes(self.bayt(4), "big") % ust

    def secim(self, secenekler: list) -> object:
        return secenekler[self.tamsayi(len(secenekler))] if secenekler else None


# ══════════════════════════════════════════════════════════════════════════════
# Rastgele sürücü — atheris olmadan
# ══════════════════════════════════════════════════════════════════════════════

#: Kip seçici ilk baytı yiyor. Kenar durumlar bu yüzden her kip ön ekiyle
#: ayrı ayrı denenmeli — yoksa `b"HYCL"` girdisi hiçbir zaman "ham baytları
#: dosyaya yaz" kipine ulaşmaz ve elle yazılmış kenar durum boşa gider.
#: Bu tam olarak bir kez oldu: harness ilk yazıldığında bilinen iki ihlalin
#: ikisini de bulamadı, çünkü hepsi yanlış kipe düşüyordu.
_KIP_ON_EKLERI = tuple(bytes([k]) for k in range(8))

#: Fuzzer'ın kendi başına bulması zor olan sınır durumları. Rastgele bir
#: sürücü 0 baytlık girdiyi ya da tam olarak sihirli sayı kadar uzunluğu
#: makul bir sürede üretemez; bunlar elle veriliyor.
KENAR_DURUMLAR: tuple[bytes, ...] = (
    b"",
    b"\x00",
    b"\xff",
    b"HYCL",                      # yalnızca sihirli sayı — B-012'nin girdisi
    b"HYCL\x01",
    b"HYCL\x02",
    b"HYCL\x63",                  # desteklenmeyen versiyon
    b"HYCL\x02" + b"\x00" * 12,   # nonce var, uzunluk alanı yok
    b"HYCL\x02" + b"\x00" * 12 + b"\xff\xff\xff\xff",  # devasa AAD iddiası
    b"HYCL\x02" + b"\x00" * 12 + b"\x00\x00\x00\x00",  # boş AAD, gövde yok
    b"\x00" * 64,
    b"\xff" * 64,
    bytes(range(256)),
)


def rastgele_girdiler(
    tohum: int,
    adet: int,
    azami_boy: int = 512,
    tohumlar: tuple[bytes, ...] = (),
) -> Iterator[bytes]:
    """
    Sırayla: hedefe özel tohum korpusu → kenar durumlar (her kiple) → rastgele.

    `tohumlar`, hedef modülün kendi yazdığı girdiler. Rastgele bir sürücünün
    ASLA bulamayacağı durumlar için: örneğin Shamir'de interpolasyonu
    [2**256, asal) aralığına düşüren paylar — rastgele bulma olasılığı
    297/2**256. Bunlar libFuzzer'ın "seed corpus"unun karşılığı.
    """
    yield from tohumlar
    for kenar in KENAR_DURUMLAR:
        yield kenar
        for on_ek in _KIP_ON_EKLERI:
            yield on_ek + kenar

    rng = random.Random(tohum)
    for _ in range(max(0, adet)):
        boy = rng.randrange(0, azami_boy)
        yield bytes(rng.randrange(256) for _ in range(boy))


def yerel_kos(
    one_input: Callable[[bytes], None],
    *,
    tohum: int = 0,
    adet: int = 2_000,
    bilinen: tuple[BilinenIhlal, ...] = (),
    tohumlar: tuple[bytes, ...] = (),
) -> tuple[list[SozlesmeIhlali], set[tuple[str, str]]]:
    """
    atheris olmadan koşum. Bilinen ihlalleri yutar, yenileri döndürür.

    Returns:
        (yeni_ihlaller, gorulen_anahtarlar)

        İkinci değer BİLİNENLER DAHİL görülen her ihlal anahtarı. Testler
        bunu, `BILINEN` listesindeki maddelere GERÇEKTEN ulaşıldığını
        doğrulamak için kullanıyor: ulaşılamayan bir "bilinen ihlal"
        kaydı, harness'ın o yola hiç girmediğini gizler.
    """
    bilinen_anahtarlar = {b.anahtar for b in bilinen}
    yeni: list[SozlesmeIhlali] = []
    gorulen: set[tuple[str, str]] = set()

    for girdi in rastgele_girdiler(tohum, adet, tohumlar=tohumlar):
        try:
            one_input(girdi)
        except SozlesmeIhlali as ihlal:
            gorulen.add(ihlal.anahtar)
            if ihlal.anahtar in bilinen_anahtarlar:
                continue
            if any(y.anahtar == ihlal.anahtar for y in yeni):
                continue
            yeni.append(ihlal)
        except (KeyboardInterrupt, SystemExit):
            raise
    return yeni, gorulen


# ══════════════════════════════════════════════════════════════════════════════
# Giriş noktası — her hedef modülün main()'i buraya bağlanıyor
# ══════════════════════════════════════════════════════════════════════════════

def main(
    one_input: Callable[[bytes], None],
    *,
    ad: str,
    bilinen: tuple[BilinenIhlal, ...] = (),
    tohumlar: tuple[bytes, ...] = (),
    argv: list[str] | None = None,
) -> int:
    """
    Hedefi çalıştırır. atheris varsa libFuzzer, yoksa yerel sürücü.

    `HYCLEUS_FUZZ_LOCAL=1` atheris kurulu olsa bile yerel sürücüyü zorlar —
    iş akışını yerelde denemek için.
    """
    ayristirici = argparse.ArgumentParser(prog=f"fuzz:{ad}", add_help=False)
    ayristirici.add_argument("--yerel", action="store_true")
    ayristirici.add_argument("--tohum", type=int, default=0)
    ayristirici.add_argument("--adet", type=int, default=2_000)
    secenek, kalan = ayristirici.parse_known_args(argv)

    zorla_yerel = secenek.yerel or os.environ.get("HYCLEUS_FUZZ_LOCAL") == "1"

    if not zorla_yerel:
        try:
            import atheris  # type: ignore[import-not-found]
        except ImportError:
            print(
                f"[{ad}] atheris kurulu değil — yerel rastgele sürücüye "
                "düşülüyor. Kapsam güdümlü koşum için Linux + "
                "`pip install atheris` gerekiyor.",
                file=sys.stderr,
            )
        else:
            atheris.Setup([sys.argv[0], *kalan], one_input)
            atheris.Fuzz()
            return 0  # Fuzz() normalde dönmez

    print(f"[{ad}] yerel sürücü: tohum={secenek.tohum} adet={secenek.adet}")
    yeni, _gorulen = yerel_kos(
        one_input, tohum=secenek.tohum, adet=secenek.adet,
        bilinen=bilinen, tohumlar=tohumlar,
    )
    if not yeni:
        print(f"[{ad}] yeni sözleşme ihlali yok "
              f"({len(bilinen)} bilinen ihlal atlandı).")
        return 0
    print(f"[{ad}] {len(yeni)} YENİ sözleşme ihlali:", file=sys.stderr)
    for ihlal in yeni:
        print(f"  · {ihlal}", file=sys.stderr)
    return 1
