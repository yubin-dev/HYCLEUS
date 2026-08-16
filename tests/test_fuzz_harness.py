"""
Fuzz harness'larının kendisinin testleri.

Neden normal test paketinde
---------------------------
Asıl fuzzing elle tetiklenen bir iş akışında koşuyor (`.github/workflows/
fuzz.yml`) çünkü uzun sürüyor. Ama elle tetiklenen bir iş akışında yaşayan
kod, kırıldığında kimsenin fark etmediği koddur: bir `import` değişir,
harness altı ay boyunca hiç çalışmaz ve kimse bilmez.

Bu yüzden harness'lar her koşuda, kısa bir korpusla burada da çalışıyor.
Amaç yeni hata bulmak değil — o iş fuzzer'ın — **harness'ın çalışır
durumda olduğunu** ve bilinen bulguların hâlâ orada olduğunu doğrulamak.

En önemli test
--------------
`test_bilinen_ihlallere_gercekten_ulasiliyor`. Bir "bilinen ihlal" kaydı,
o yola gerçekten girilebildiğini varsayar. Girilemiyorsa liste bir kayıt
değil, bir masal olur: harness hiçbir şey bulamaz, testler yeşil kalır ve
"fuzz'ladık" demiş oluruz.

Bu tam olarak bir kez oldu. Harness ilk yazıldığında kip seçici girdinin
ilk baytını yiyordu; elle yazılmış kenar durumların hiçbiri hedeflediği
kipe ulaşmıyordu ve iki bilinen ihlalin ikisi de bulunamıyordu. Test
eklendikten sonra hata görüldü ve tohum korpusu eklendi.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

_FUZZ_DIZINI = Path(__file__).resolve().parent / "fuzz"
if str(_FUZZ_DIZINI) not in sys.path:
    sys.path.insert(0, str(_FUZZ_DIZINI))

from harness import (  # noqa: E402
    KENAR_DURUMLAR,
    BilinenIhlal,
    Tuketici,
    cagir,
    rastgele_girdiler,
    yerel_kos,
)

#: Testlerde koşulan rastgele girdi sayısı. Asıl fuzzing bunun milyon
#: katını yapıyor; buradaki sayı "harness ayakta mı" sorusuna yetecek
#: kadar küçük tutuldu (tüm modül ~10 sn).
_ADET = 120

HEDEFLER = ("fuzz_crypto", "fuzz_shamir")


@pytest.fixture(scope="module", params=HEDEFLER)
def hedef(request):
    return importlib.import_module(request.param)


# ══════════════════════════════════════════════════════════════════════════════
# Harness altyapısı
# ══════════════════════════════════════════════════════════════════════════════

def test_tuketici_veri_bitince_sifir_doner() -> None:
    """
    Fuzzer kısa girdiler üretiyor; tüketici bunlarda çökmemeli.

    Çökerse fuzzer'ın bulduğu her kısa girdi, hedefteki bir hata değil
    harness'taki bir hata olarak raporlanır ve sinyal gürültüye boğulur.
    """
    t = Tuketici(b"")
    assert t.bayt(4) == b"\x00\x00\x00\x00"
    assert t.kalan() == b""
    assert t.tamsayi(5) == 0
    assert t.tamsayi(0) == 0
    assert t.tamsayi(1) == 0

    t2 = Tuketici(b"\x07")
    assert t2.tamsayi(5) == 2
    assert t2.bayt(2) == b"\x00\x00"          # veri bitti, sıfırla dolduruldu


def test_cagir_izinli_istisnayi_yutar_digerini_yukseltir() -> None:
    from harness import SozlesmeIhlali

    assert cagir("x", (ValueError,), b"", lambda: 42) == 42
    assert cagir("x", (ValueError,), b"", _raise(ValueError("ok"))) is None

    with pytest.raises(SozlesmeIhlali) as bilgi:
        cagir("x", (ValueError,), b"abc", _raise(TypeError("beklenmedik")))
    assert bilgi.value.anahtar == ("x", "TypeError")
    assert "abc" in str(bilgi.value)


def test_cagir_kesintiyi_gecirir() -> None:
    """Fuzzer durdurulabilmeli — KeyboardInterrupt yutulmamalı."""
    with pytest.raises(KeyboardInterrupt):
        cagir("x", (Exception,), b"", _raise(KeyboardInterrupt()))


def test_kenar_durumlar_her_kiple_deneniyor() -> None:
    """
    Kip ön eki olmadan elle yazılmış kenar durumlar hedefe ulaşmıyor.

    Bu, harness'ın ilk sürümündeki hatanın regresyon testi.
    """
    girdiler = list(rastgele_girdiler(0, 0))
    assert b"HYCL" in girdiler, "çıplak kenar durum yok"
    assert b"\x00HYCL" in girdiler, "kip 0 ön ekli kenar durum yok"
    # Her kenar durum için: kendisi + 8 ön ek
    assert len(girdiler) == len(KENAR_DURUMLAR) * 9


def _raise(exc: BaseException):
    def _fn():
        raise exc
    return _fn


# ══════════════════════════════════════════════════════════════════════════════
# Hedefler
# ══════════════════════════════════════════════════════════════════════════════

def test_hedef_arayuzu_tam(hedef) -> None:
    """Her hedef modül aynı sözleşmeyi sunmalı."""
    assert callable(hedef.one_input)
    assert isinstance(hedef.BILINEN, tuple)
    assert isinstance(hedef.TOHUMLAR, tuple)
    for kayit in hedef.BILINEN:
        assert isinstance(kayit, BilinenIhlal)
        assert kayit.backlog.startswith("B-"), kayit
        assert len(kayit.aciklama) > 40, f"{kayit.cagri}: gerekçe çok kısa"


def test_yeni_sozlesme_ihlali_yok(hedef) -> None:
    """
    Kısa korpusta BİLİNENLERİN DIŞINDA bir istisna sızmamalı.

    Kırılırsa iki ihtimal var ve ikisi de ilgilenmeye değer:
      · gerçekten yeni bir hata girdi, ya da
      · bilinen bir hata düzeltildi ama listeden kaldırılmadı (o durumda
        aşağıdaki test kırılır, bu değil).
    """
    yeni, _gorulen = yerel_kos(
        hedef.one_input, adet=_ADET,
        bilinen=hedef.BILINEN, tohumlar=hedef.TOHUMLAR,
    )
    assert not yeni, (
        f"{hedef.__name__}: {len(yeni)} yeni sözleşme ihlali\n"
        + "\n".join(f"  · {i}" for i in yeni)
    )


def test_bilinen_ihlallere_gercekten_ulasiliyor(hedef) -> None:
    """
    Listedeki her bilinen ihlal, korpusta GERÇEKTEN üretilebilmeli.

    Bu testin iki yönü var:

      · Bugün — harness'ın o kod yoluna girebildiğini kanıtlıyor. Ulaşamayan
        bir harness hiçbir şey bulamaz ama yeşil görünür.
      · Yarın — biri B-012 ya da B-021'i düzelttiğinde bu test kırılır ve
        "artık ulaşılamıyor, listeden çıkar" der. Yani düzeltmenin backlog'a
        yansımasını test hatırlatıyor.
    """
    _yeni, gorulen = yerel_kos(
        hedef.one_input, adet=_ADET,
        bilinen=hedef.BILINEN, tohumlar=hedef.TOHUMLAR,
    )
    ulasilamayan = [k for k in hedef.BILINEN if k.anahtar not in gorulen]
    assert not ulasilamayan, (
        f"{hedef.__name__}: bu bilinen ihlallere ulaşılamadı — "
        "ya düzeltildiler (listeden çıkarın) ya da harness o yola artık "
        "girmiyor (tohum korpusuna bakın):\n"
        + "\n".join(f"  · {k.cagri} -> {k.istisna}  [{k.backlog}]"
                    for k in ulasilamayan)
    )


def test_bos_girdi_cokmuyor(hedef) -> None:
    """En kısa girdi. Harness burada çökerse fuzzer ilk adımda ölür."""
    hedef.one_input(b"")
