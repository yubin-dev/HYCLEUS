"""
SECURITY.md ve README.md — İngilizce ve Türkçe bölümler AYRIŞMASIN.

Neden bu dosya var
------------------
Her iki belge de aynı içeriği iki dilde anlatıyor ve iki bölüm ELLE
tutuluyor. Elle tutulan iki kopya ayrışır; ayrışma da SESSİZDİR — hiçbir
test, hiçbir linter iki dilin farklı şey söylediğini fark etmez.

B-017 tam olarak bu sınıftandı: sürüm dizesi beş yerde elle yazılıydı ve
beşi farklı şey söylüyordu (etiket `v2.1.2`, SECURITY.md `v2.1.0`, README
rozeti `2.0`, Hakkında kutusu `v1.6`, İletişim `v1.5`). O bulgu KOD ile
BELGE arasındaki ayrışmaydı ve `tests/test_version.py` onu kapattı.

Buradaki eksen FARKLI ve o test tarafından kapsanmıyor: aynı belgenin İKİ
DİLİ arasındaki ayrışma. İki dosyada da sürümler kodla uyumlu olabilir ama
Türkçe bölüm bir CVE'den, bir bölümden ya da bir komut seçeneğinden hiç
söz etmiyor olabilir.

Bu neden ÖNEMLİ
---------------
SECURITY.md bir güvenlik taahhüdü ve §6.3 bildirimcilerden "etkilenen
sürüm" istiyor. Bir bildirimci Türkçe bölümü okuyup eksik bir sürüm
aralığı görürse yanlış bilgi verir — ve bunu kimse fark etmez, çünkü
İngilizce bölüm doğrudur.

Aynısı komutlar için de geçerli: `docs/kullanici-rehberi.md` turunda
ölçüldü ki bir belgede yazan yanlış komut, panikleyen bir kullanıcıyı
`--reset`'e götürebiliyor.

Yöntem — bilerek BASİT
----------------------
Anlamsal karşılaştırma YOK. Karşılaştırılan şeyler dilden BAĞIMSIZ olarak
aynı kalması gerekenler: başlık sayıları, başlık numaraları (`4.1`),
paragraf atıfları (`§4.6`), sürüm dizeleri (`v2.2`), ISO tarihler, kod
bloğu ve tablo satırı sayıları, ve komut/bayrak/dosya yolu belirteçleri.

Metin İÇERİĞİ karşılaştırılmıyor — çeviri zaten farklı olmalı. Kod
blokları da birebir karşılaştırılmıyor: ölçüldü, yer tutucular ve yorumlar
bilerek çevrilmiş (`<file>` → `<dosya>`). Karşılaştırılan, o blokların
SAYISI ve içlerinden çıkan komut belirteçleri.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pytest

KOK = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Belge:
    """İki dilli bir belge ve bölümlerinin başladığı satırlar."""

    ad: str
    en_bas: str
    tr_bas: str

    @property
    def yol(self) -> Path:
        return KOK / self.ad

    def __str__(self) -> str:      # pytest kimliği okunur olsun
        return self.ad


BELGELER = (
    Belge("SECURITY.md", "# Security Policy", "# Güvenlik Politikası"),
    Belge("README.md", "## 🇬🇧 English", "## 🇹🇷 Türkçe"),
)

#: Komut satırı belirteçleri: depo içi yollar ve uzun bayraklar.
#: Bir bayrak yalnızca bir dilde yazılıysa, o dili okuyan kullanıcı
#: çalışmayan bir komut dener.
_ARAC = re.compile(r"(?:CORE|DB|UI|packaging|tests|docs)[/\\][\w./\\-]+|--[a-z][a-z0-9-]*")
_SURUM = re.compile(r"\bv\d+\.\d+(?:\.\d+)?\b")
_TARIH = re.compile(r"\b20\d{2}-\d{2}-\d{2}\b")
_PARAGRAF = re.compile(r"§\d+(?:\.\d+)?")
#: `### 4.1 Başlık` → "4.1";  `## 6. Başlık` → "6"
_BASLIK_NO = re.compile(r"^#{2,4}\s+(\d+(?:\.\d+)?)\.?\s", re.M)


def _temiz(metin: str) -> str:
    """Markdown bağlantı HEDEFLERİNİ atar.

    Gerekçe ölçüldü: `[Türkçe sürüm aşağıda](#güvenlik-politikası--hycleus)`
    içindeki çapa, başlıktaki uzun tirenin slug'a çevrilmesinden doğan bir
    `--` taşıyor ve bayrak tarayıcısı onu `--hycleus` diye okuyordu —
    yalnızca İngilizce bölümde olduğu için de sahte bir "fark" üretiyordu.

    Bağlantı METNİ korunuyor; atılan yalnızca parantez içindeki hedef.
    """
    return re.sub(r"\]\([^)]*\)", "]()", metin)


def _bolumler(belge: Belge) -> tuple[str, str]:
    """Belgeyi (İngilizce, Türkçe) diye ikiye böler; ikisi de temizlenmiş."""
    ham = belge.yol.read_text(encoding="utf-8")
    i = ham.index(belge.en_bas)
    j = ham.index(belge.tr_bas)
    assert i < j, f"{belge}: Türkçe bölüm İngilizce'den önce başlıyor"
    return _temiz(ham[i:j]), _temiz(ham[j:])


def _sayi(metin: str, desen: str) -> int:
    return len(re.findall(desen, metin, re.M))


def _fark(en: Counter[str], tr: Counter[str]) -> str:
    """İki sayaç arasındaki farkın okunur dökümü."""
    satirlar = []
    for anahtar in sorted(set(en) | set(tr)):
        if en[anahtar] != tr[anahtar]:
            satirlar.append(f"    {anahtar!r}: EN={en[anahtar]} TR={tr[anahtar]}")
    return "\n".join(satirlar)


# ══════════════════════════════════════════════════════════════════════════════
# 0. Denetimin KENDİSİ çalışıyor mu
# ══════════════════════════════════════════════════════════════════════════════
#
# Bölücü bozulursa (başlık yeniden yazılır, emoji değişir) aşağıdaki bütün
# karşılaştırmalar boş metinler üzerinde yapılır ve HEPSİ kendiliğinden
# geçer. Bu depoda o sınıftan bir kaza yaşandı; bu blok onu kapatıyor.


@pytest.mark.parametrize("belge", BELGELER, ids=str)
def test_iki_dil_bolumu_de_bulunuyor(belge: Belge) -> None:
    en, tr = _bolumler(belge)
    assert len(en) > 2000, f"{belge}: İngilizce bölüm şüpheli kısa ({len(en)})"
    assert len(tr) > 2000, f"{belge}: Türkçe bölüm şüpheli kısa ({len(tr)})"


@pytest.mark.parametrize("belge", BELGELER, ids=str)
def test_tarayicilar_gercekten_bir_sey_buluyor(belge: Belge) -> None:
    """Boş küme dönen bir tarayıcı, her karşılaştırmayı sessizce geçirir."""
    en, _tr = _bolumler(belge)
    assert _sayi(en, r"^### "), f"{belge}: hiç alt başlık bulunamadı"

    # `_ARAC` İKİ şey arıyor: depo içi yollar VE uzun bayraklar. Yalnızca
    # "boş değil" demek yetmiyor — mutasyon testinde ölçüldü: desenin YOL
    # yarısını körleştirmek testi düşürmedi, çünkü bayraklar hâlâ
    # eşleşiyordu. İki tür de ayrı ayrı denetleniyor.
    belirtecler = _ARAC.findall(en)
    assert any(b.startswith("--") for b in belirtecler), (
        f"{belge}: hiç bayrak belirteci bulunamadı — tarayıcının bayrak "
        "yarısı kör olabilir"
    )
    assert any(not b.startswith("--") for b in belirtecler), (
        f"{belge}: hiç dosya yolu belirteci bulunamadı — tarayıcının yol "
        "yarısı kör olabilir"
    )


def test_paragraf_ve_surum_tarayicilari_SECURITY_de_calisiyor() -> None:
    """
    `§` ve sürüm taraması yalnızca SECURITY.md'de anlamlı; README'de bu
    işaretler zaten yok. Tarayıcının kör olmadığını orada ölçüyoruz —
    yoksa "iki dilde de 0 bulundu, eşit" diye geçerdi.
    """
    en, _tr = _bolumler(BELGELER[0])
    assert len(_PARAGRAF.findall(en)) > 20
    assert len(_SURUM.findall(en)) > 5
    assert len(_TARIH.findall(en)) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# 1. Yapı — başlıklar
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("belge", BELGELER, ids=str)
@pytest.mark.parametrize("seviye", ["## ", "### ", "#### "])
def test_baslik_sayilari_esit(belge: Belge, seviye: str) -> None:
    """
    Bir bölüm yalnızca bir dile eklenirse diğer dilin okuru onu HİÇ
    görmez — ve iki bölümü yan yana koyan kimse olmadığı için fark
    edilmez.
    """
    en, tr = _bolumler(belge)
    desen = "^" + seviye.strip() + " "
    n_en, n_tr = _sayi(en, desen), _sayi(tr, desen)
    assert n_en == n_tr, (
        f"{belge}: `{seviye.strip()}` başlık sayısı ayrışmış — "
        f"EN={n_en}, TR={n_tr}"
    )


@pytest.mark.parametrize("belge", BELGELER, ids=str)
def test_baslik_NUMARALARI_ayni_sirada(belge: Belge) -> None:
    """
    Sayı eşitliği yetmez: `4.7` silinip `4.13` eklenirse sayı aynı kalır
    ama numaralandırma ayrışır ve `§4.7` atıfları Türkçe tarafta hiçbir
    yere gitmez.

    Sıra da karşılaştırılıyor — yeniden sıralanmış bir bölüm, atıfları
    yanlış hedefe yönlendirir.
    """
    en, tr = _bolumler(belge)
    no_en = _BASLIK_NO.findall(en)
    no_tr = _BASLIK_NO.findall(tr)
    assert no_en == no_tr, (
        f"{belge}: başlık numaraları ayrışmış.\n"
        f"  EN: {no_en}\n  TR: {no_tr}\n"
        f"  yalnızca EN'de: {sorted(set(no_en) - set(no_tr))}\n"
        f"  yalnızca TR'de: {sorted(set(no_tr) - set(no_en))}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2. Atıflar ve sürümler — B-017'nin ekseni
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("belge", BELGELER, ids=str)
def test_paragraf_atiflari_esit(belge: Belge) -> None:
    """
    `§4.6` gibi atıflar dilden bağımsız. Bir dilde 8, diğerinde 6 kez
    geçiyorsa Türkçe okur iki çapraz bağlantıyı kaybetmiş demektir —
    güvenlik belgesinde bir bölümün diğerine bağlanması içeriğin
    parçasıdır, süs değil.
    """
    en, tr = _bolumler(belge)
    ce, ct = Counter(_PARAGRAF.findall(en)), Counter(_PARAGRAF.findall(tr))
    assert ce == ct, f"{belge}: § atıfları ayrışmış:\n{_fark(ce, ct)}"


@pytest.mark.parametrize("belge", BELGELER, ids=str)
def test_surum_atiflari_esit(belge: Belge) -> None:
    """
    B-017'nin doğrudan karşılığı, ama İKİ DİL ekseninde.

    `tests/test_version.py` belgelerin KOD ile uyumunu denetliyor; bir
    sürüm dizesi yalnızca İngilizce bölümde güncellenirse o test yine
    yeşil kalır (aradığı dize belgede VAR). Ayrışmayı yalnızca bu
    karşılaştırma görür.
    """
    en, tr = _bolumler(belge)
    ce, ct = Counter(_SURUM.findall(en)), Counter(_SURUM.findall(tr))
    assert ce == ct, (
        f"{belge}: sürüm atıfları iki dilde ayrışmış (B-017 sınıfı):\n"
        f"{_fark(ce, ct)}"
    )


@pytest.mark.parametrize("belge", BELGELER, ids=str)
def test_tarih_atiflari_esit(belge: Belge) -> None:
    """
    Tarihler ölçüm kayıtlarına bağlı ("2026-08-16'da ölçüldü"). Bir
    dilde güncellenip diğerinde bırakılırsa iki belge farklı bir olayı
    anlatır.
    """
    en, tr = _bolumler(belge)
    ce, ct = Counter(_TARIH.findall(en)), Counter(_TARIH.findall(tr))
    assert ce == ct, f"{belge}: tarih atıfları ayrışmış:\n{_fark(ce, ct)}"


@pytest.mark.parametrize("belge", BELGELER, ids=str)
def test_komut_ve_bayraklar_esit(belge: Belge) -> None:
    """
    Bir bayrak ya da betik yolu yalnızca bir dilde yazılıysa, öteki dili
    okuyan kullanıcı çalışmayan bir komut dener.

    `docs/kullanici-rehberi.md` turunda ölçüldü: bir belgede yazan yanlış
    komut, panikleyen bir kullanıcıyı `setup_usb.py --reset`'e — yani
    kalıcı veri kaybına — götürebiliyor.
    """
    en, tr = _bolumler(belge)
    ce, ct = Counter(_ARAC.findall(en)), Counter(_ARAC.findall(tr))
    assert ce == ct, (
        f"{belge}: komut/bayrak/yol belirteçleri ayrışmış:\n{_fark(ce, ct)}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 3. Blok yapısı
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("belge", BELGELER, ids=str)
def test_kod_blogu_sayisi_esit(belge: Belge) -> None:
    """
    Blokların İÇERİĞİ karşılaştırılmıyor — ölçüldü, yer tutucular ve
    yorumlar bilerek çevrilmiş (`<file>` → `<dosya>`). Ama SAYILARI
    eşit olmalı: eksik bir blok, o dilde eksik bir örnek demek.
    """
    en, tr = _bolumler(belge)
    n_en, n_tr = _sayi(en, r"^```") // 2, _sayi(tr, r"^```") // 2
    assert n_en == n_tr, (
        f"{belge}: kod bloğu sayısı ayrışmış — EN={n_en}, TR={n_tr}"
    )


@pytest.mark.parametrize("belge", BELGELER, ids=str)
def test_kod_bloklari_kapali(belge: Belge) -> None:
    """Tek sayıda ``` bir bloğun kapanmadığını gösterir; sayfanın kalanı bozulur."""
    for etiket, metin in zip(("EN", "TR"), _bolumler(belge)):
        assert _sayi(metin, r"^```") % 2 == 0, (
            f"{belge} / {etiket}: kapanmamış kod bloğu var"
        )


@pytest.mark.parametrize("belge", BELGELER, ids=str)
def test_tablo_satiri_sayisi_esit(belge: Belge) -> None:
    """
    Her iki belgede de özellik/zayıflık tabloları var. Bir satır yalnızca
    bir dile eklenirse o özellik diğer dilde hiç anlatılmamış olur.
    """
    en, tr = _bolumler(belge)
    n_en, n_tr = _sayi(en, r"^\|"), _sayi(tr, r"^\|")
    assert n_en == n_tr, (
        f"{belge}: tablo satırı sayısı ayrışmış — EN={n_en}, TR={n_tr}"
    )
