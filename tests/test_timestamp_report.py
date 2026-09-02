"""
CORE.timestamp_report — doğrulama sonucunun insan diline çevrilmesi.

Bu paketin ana iddiası: **arayüz, doğrulamanın söyleyebileceği HER ŞEYİ
söyleyebiliyor ve hiçbirini olduğundan fazla söylemiyor.**

İki ayrı riski kapatıyor:

  1. EKSİKLİK — `timestamp_verify.py`'ye yeni bir hata yolu eklendiğinde
     arayüzün sessizce "sebep bilinmiyor"a düşmesi. Denetim, doğrulayıcıyı
     AST ile tarayıp ürettiği her `failed_check` için karşılık olmasını
     şart koşuyor.
  2. FAZLA SÖYLEME — "damga geçerli" mesajının "dosya değiştirilmemiş"
     anlamına gelmesi. `verify_timestamp()` bunu doğrulamıyor; testler
     metnin de bunu iddia etmediğini sabitliyor.

Denetim neden AST
-----------------
Bu depoda düz metin denetimi dört kez yanlış yere takıldı; sonuncusu
`assert "upx=True" in metin`'in dosyanın kendi AÇIKLAMASINA eşleşmesiydi
(B-024). Burada risk aynı biçimde mevcut: hem `timestamp_verify.py`'nin
hem `timestamp_report.py`'nin docstring'i `failed_check` adlarını
sayıyor. Ayrı bir test, tarayıcının metne değil koda baktığını
sabitliyor.
"""
from __future__ import annotations

import ast
import hashlib
import re
import socket
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import pytest
from asn1crypto import tsp
from tsa_fixtures import FakeTSA

from CORE import crypto, timestamp_report as tr
from CORE.crypto import encrypt_file, generate_key
from CORE.timestamp import TimestampInfo, attach_trailer, timestamp_file
from CORE.timestamp_verify import TimestampVerification, verify_timestamp

_USER_ID = 31
_HWID = "TEST-HWID-REPORT"

_DOGRULAYICI = Path(__file__).parent.parent / "CORE" / "timestamp_verify.py"
_FIXTURE = Path(__file__).parent / "data" / "freetsa_response.der"
_FIXTURE_PLAIN = b"HYCLEUS RFC 3161 test vektoru\n"

#: `timestamp_verify.py`'nin ürettiği hata kodu sayısının ALT SINIRI.
#:
#: Tarayıcı bozulup boş küme döndürürse "her kod için karşılık var"
#: iddiası KENDİLİĞİNDEN doğru olurdu — hiç kod yoksa hepsi karşılanmış
#: sayılır. Bu sınır o sessiz geçişi engelliyor. Ölçüldüğünde 18 kod
#: vardı; sınır, kod silmeyi yasaklamayacak kadar altında.
_ASGARI_KOD = 15

#: `ozet`/`baslik` metinlerinde GEÇMEMESİ gereken terimler.
#:
#: Hepsi doğrulayıcının `reason` alanında geçen ve orada YERİNDE olan
#: terimler — CLI'ın kitlesi onları okuyabiliyor. Arayüzün kitlesi
#: okuyamıyor; sadeleştirmenin ölçülebilir tanımı bu liste.
_JARGON = (
    "tstinfo", "signeddata", "signerinfo", "signedattrs", "asn.1",
    "x.509", "eku", "oid", "sha-256", "sha256", "gcm", "aad", "merkle",
    "message-digest", "content-type", "imprint", "nonce", "fragman",
    "token", "octet", "pkcs", "ecdsa", "rsa",
)

#: Türkçe bir sözcükle ÇAKIŞAN kısaltmalar — büyük harf duyarlı aranıyor.
#:
#: `DER` bir kodlama biçiminin adı ama `der` Türkçe bir fiil ("bu ekran
#: ona da 'geçerli' der"). Küçük harfe indirip aramak o cümleyi düşürürdü;
#: terimi listeden tümüyle atmak ise gerçek bir sızıntıyı görmezden
#: gelmek olurdu. Kısaltmalar metne kısaltma olarak, yani büyük harfle
#: girer.
_KISALTMA = ("DER",)


def _kucult(metin: str) -> str:
    """Türkçe duyarlı küçültme — `.lower()` YETMİYOR.

    `"İÇERİĞİNİN".lower()` her `İ` için `i` + BİRLEŞEN NOKTA (U+0307)
    üretiyor ve `"içeriğinin"` ile eşleşmiyor. B-028'de ölçülen tuzağın
    aynısı; bu testler metindeki büyük harfli VURGUYU arıyor, yani
    doğrudan onun üstüne basıyorlar.

    Karşılaştırmanın iki tarafı da bundan geçmeli: birleşen işaretler
    atıldığı için `ğ→g`, `ş→s` de oluyor.
    """
    ham = metin.replace("İ", "i").replace("ı", "i").lower()
    ayrik = unicodedata.normalize("NFKD", ham)
    return "".join(c for c in ayrik if not unicodedata.combining(c))


def _jargon_kacaklari(metin: str) -> list[str]:
    """Metinde SÖZCÜK olarak geçen teknik terimler.

    Alt dize araması YETMİYOR: `"rsa"` Türkçe `"varsa"` sözcüğüne
    eşleşiyor ve öneri metinlerinin çoğunda "varsa yedekteki kopya" geçiyor.
    Sözcük sınırı, terimi arayan denetimin Türkçeye takılmasını engelliyor.
    """
    kucuk = _kucult(metin)
    kacak = [
        terim for terim in _JARGON
        if re.search(rf"(?<!\w){re.escape(terim)}(?!\w)", kucuk)
    ]
    kacak += [
        kisa for kisa in _KISALTMA
        if re.search(rf"(?<!\w){re.escape(kisa)}(?!\w)", metin)
    ]
    return kacak


# ══════════════════════════════════════════════════════════════════════════════
# Fixture'lar
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture(autouse=True)
def _quarantine_to_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    out = tmp_path / "quarantine"
    out.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", out)
    return out


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bu katman da ağa çıkmamalı — doğrulamadan miras alınan kısıt."""
    def _yasak(*args, **kwargs):
        raise AssertionError("Rapor katmanı ağa çıkmaya çalıştı.")

    monkeypatch.setattr(socket, "socket", _yasak)
    monkeypatch.setattr(socket, "create_connection", _yasak)


@pytest.fixture
def key() -> bytes:
    return generate_key()


def _hcl(tmp_path: Path, key: bytes, content: bytes, name: str = "belge.bin") -> Path:
    src = tmp_path / name
    src.write_bytes(content)
    dst, _sha, _aad = encrypt_file(src, key, _USER_ID, hwid=_HWID)
    return dst


@pytest.fixture
def stamped(tmp_path: Path, key: bytes) -> Path:
    """Yerel otoritenin imzaladığı, damgalı bir .hcl dosyası."""
    path = _hcl(tmp_path, key, b"rapor icerigi " * 200)
    timestamp_file(path, key, transport=FakeTSA())
    return path


@pytest.fixture
def unstamped(tmp_path: Path, key: bytes) -> Path:
    return _hcl(tmp_path, key, b"damgasiz icerik", name="damgasiz.bin")


# ══════════════════════════════════════════════════════════════════════════════
# 1. Denetim — doğrulayıcının her hata yolu karşılanıyor mu
# ══════════════════════════════════════════════════════════════════════════════


def _hata_kodlari(kaynak: str) -> set[str]:
    """
    Bir modülün ürettiği `failed_check` değerlerini AST ile toplar.

    Üç şekli birden arıyor, çünkü doğrulayıcı üçünü de kullanıyor:

        _Fail("eku", ...)                 ilk konumsal argüman
        TimestampVerification(failed_check="aad", ...)
        _verify_signature(..., check="signature")

    Üçüncüsü olmadan tarama EKSİK kalırdı: `_verify_signature` içindeki
    `_Fail(check, ...)` bir değişken alıyor, sabit değil — kodun kendisi
    çağrı yerinde duruyor.
    """
    bulunan: set[str] = set()
    for dugum in ast.walk(ast.parse(kaynak)):
        if not isinstance(dugum, ast.Call):
            continue
        hedef = dugum.func
        if (
            isinstance(hedef, ast.Name)
            and hedef.id == "_Fail"
            and dugum.args
            and isinstance(dugum.args[0], ast.Constant)
            and isinstance(dugum.args[0].value, str)
        ):
            bulunan.add(dugum.args[0].value)
        for anahtar in dugum.keywords:
            if anahtar.arg in ("failed_check", "check") and isinstance(
                anahtar.value, ast.Constant
            ) and isinstance(anahtar.value.value, str):
                bulunan.add(anahtar.value.value)
    return bulunan


def test_tarayici_gercekten_kod_buluyor() -> None:
    """
    Boş küme dönerse eksiksizlik testi KENDİLİĞİNDEN geçerdi.

    Bu depoda tam olarak bu sınıftan bir hata çıktı: bir denetim testi,
    kuralı ihlal eden kodu göremediği için sessizce geçiyordu.
    """
    kodlar = _hata_kodlari(_DOGRULAYICI.read_text(encoding="utf-8"))
    assert len(kodlar) >= _ASGARI_KOD, (
        f"Doğrulayıcıda yalnızca {len(kodlar)} hata kodu bulundu "
        f"({sorted(kodlar)}). Tarayıcı bozulmuş olabilir."
    )


def test_tarayici_ACIKLAMA_metnine_takilmiyor() -> None:
    """
    Tarama koda bakıyor, kodu ANLATAN metne değil.

    `assert "upx=True" in metin`'in dosyanın kendi yorumuna eşleşmesi
    (B-024) bu deponun dördüncü metin-denetimi kazasıydı. Buradaki risk
    somut: hem doğrulayıcının hem rapor modülünün docstring'i hata
    kodlarını adlarıyla sayıyor.
    """
    sahte = '''
"""Bu modül _Fail("uydurma_kod", ...) üretiyor ve failed_check="ikinci_uydurma"
yazıyor — ama yalnızca ANLATIYOR, çağırmıyor."""
# _Fail("ucuncu_uydurma", "yorumdaki kod")
BELGE = 'failed_check="dorduncu_uydurma"'
'''
    assert _hata_kodlari(sahte) == set()


def test_dogrulayicinin_HER_hata_kodunun_bir_karsiligi_var() -> None:
    """
    Denetimin kendisi: yeni bir hata yolu, karşılığı yazılmadan eklenemez.

    Bu olmadan yeni bir `failed_check` sessizce `BILINMEYEN`'e düşerdi —
    yani doğrulamanın en çok işe yarayacağı anda arayüz en az şeyi
    söylerdi. CLI bundan etkilenmezdi (`reason`'ı olduğu gibi basıyor),
    bu yüzden hata uzun süre fark edilmezdi.
    """
    kodlar = _hata_kodlari(_DOGRULAYICI.read_text(encoding="utf-8"))
    eksik = sorted(kodlar - set(tr._ADIM))
    assert not eksik, (
        f"CORE/timestamp_verify.py şu hata kodlarını üretiyor ama "
        f"CORE/timestamp_report.py karşılıklarını bilmiyor: {eksik}"
    )


def test_karsiligi_olup_artik_uretilmeyen_kod_yok() -> None:
    """
    Ters yön: ölü kayıt, yeniden adlandırmayı gizleyebilir.

    Bir kod `eku` → `key_usage` diye yeniden adlandırılırsa yalnızca ileri
    yön denetlenirse eski kayıt tabloda kalır ve yeni kodun karşılığı
    yokmuş gibi görünmez — çünkü toplam sayı aynıdır.
    """
    kodlar = _hata_kodlari(_DOGRULAYICI.read_text(encoding="utf-8"))
    fazla = sorted(set(tr._ADIM) - kodlar)
    assert not fazla, (
        f"Bu kodların karşılığı yazılı ama doğrulayıcı artık üretmiyor "
        f"(yeniden adlandırılmış olabilir): {fazla}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2. Metinlerin kalitesi
# ══════════════════════════════════════════════════════════════════════════════


def _tum_aciklamalar() -> list[tr.Aciklama]:
    return [*tr._ADIM.values(), tr.BILINMEYEN,
            tr._GECERLI_GUVENILIR, tr._GECERLI_KOK_DOGRULANMADI]


@pytest.mark.parametrize("mesaj", _tum_aciklamalar(), ids=lambda a: a.baslik[:30])
def test_her_mesajin_basligi_ve_ozeti_dolu(mesaj: tr.Aciklama) -> None:
    assert mesaj.baslik.strip()
    assert len(mesaj.ozet.strip()) > 40, "Özet bir cümleden kısa olmamalı."
    assert mesaj.seviye in {
        tr.SEVIYE_GECERLI, tr.SEVIYE_GECERSIZ,
        tr.SEVIYE_DAMGASIZ, tr.SEVIYE_OKUNAMADI,
        # `uyari` bir BAŞLIK seviyesi olarak da kullanılıyor: "geçerli ama
        # kök doğrulanmadı". Ayrı seviye olması kurumsal kök deposunun
        # asıl talebi — iki durum aynı yeşil onayı paylaşmamalı.
        tr.SEVIYE_UYARI,
    }


@pytest.mark.parametrize("mesaj", _tum_aciklamalar(), ids=lambda a: a.baslik[:30])
def test_basarisiz_her_sonuc_kullaniciya_YAPILACAK_bir_sey_soyluyor(
    mesaj: tr.Aciklama,
) -> None:
    """
    "Geçersiz" demek yetmez; ne yapılacağı söylenmeli.

    Doğrulayıcının kendi docstring'indeki kural bu: "hangi adımda düştüğü
    eyleme dönüştürülebilir olmalı." Geçerli sonuç istisna — orada
    yapılacak bir şey yok.
    """
    if mesaj.seviye == tr.SEVIYE_GECERLI:
        assert mesaj.oneri is None
    else:
        assert mesaj.oneri and mesaj.oneri.strip()


@pytest.mark.parametrize("mesaj", _tum_aciklamalar(), ids=lambda a: a.baslik[:30])
def test_metinler_teknik_terim_TASIMIYOR(mesaj: tr.Aciklama) -> None:
    """
    Sadeleştirmenin ölçülebilir tanımı.

    Kullanıcının ekranında "TSTInfo" ya da "EKU" görünüyorsa bu modül
    işini yapmamış demektir; CLI zaten o dili konuşuyor.
    """
    kacak = _jargon_kacaklari(f"{mesaj.baslik} {mesaj.ozet} {mesaj.oneri or ''}")
    assert not kacak, f"{mesaj.baslik!r} teknik terim taşıyor: {kacak}"


def test_jargon_denetimi_TURKCE_soze_takilmiyor() -> None:
    """
    Denetimin kendisinin denetimi.

    İlk hâli alt dize arıyordu ve `"rsa"` terimi `"varsa yedekteki kopya"`
    cümlesine eşleşip on iki mesajı birden yanlışlıkla düşürdü. Sözcük
    sınırı bunu çözdü; bu test çözümün geri alınmasını engelliyor —
    aksi hâlde denetim gürültü üretir ve gürültü üreten denetim
    gevşetilir.
    """
    assert _jargon_kacaklari("Varsa yedekteki kopyayla karşılaştırın.") == []
    assert _jargon_kacaklari("Gönderdiğiniz belge") == []
    # `der` Türkçe bir fiil; kısaltma olarak DEĞİL, sözcük olarak geçiyor.
    assert _jargon_kacaklari("Bu ekran ona da 'geçerli' der.") == []
    # Ama gerçek terim hâlâ yakalanıyor:
    assert _jargon_kacaklari("İmza RSA anahtarıyla atılmış.") == ["rsa"]
    assert _jargon_kacaklari("TSTInfo çözülemedi") == ["tstinfo"]
    assert _jargon_kacaklari("Sertifika DER biçiminde olmalı.") == ["DER"]


def test_gecerli_mesaji_dosya_degismedi_IDDIASINDA_bulunmuyor() -> None:
    """
    Fazla söylemenin en olası biçimi.

    B-092/B-099: `verify_timestamp()` artık dosyanın GERÇEK içeriğini de
    (anahtarla) doğruluyor — ama bu hâlâ "dosya HİÇ değiştirilmemiş"
    demek DEĞİL, yalnızca "bu doğrulama anında içerik damgalanan özete
    sahipti" demek. Bir belge damgalandıktan SONRA yeniden şifrelenip
    yeni (geçerli) bir damga alabilir; "değiştirilmemiş" gibi kesin bir
    iddia hâlâ doğrulamanın söylemediği bir şey olurdu.
    """
    metin = _kucult(
        f"{tr._GECERLI_GUVENILIR.baslik} {tr._GECERLI_GUVENILIR.ozet} "
        f"{tr._GECERLI_KOK_DOGRULANMADI.baslik} {tr._GECERLI_KOK_DOGRULANMADI.ozet}"
    )
    for iddia in ("değiştirilmemiş", "bozulmamış", "el değmemiş"):
        assert _kucult(iddia) not in metin, (
            f"Geçerli mesajı {iddia!r} diyor — doğrulama bunu kontrol etmiyor."
        )


def test_damgasiz_dosyanin_bozuk_OLMADIGI_acikca_yaziyor() -> None:
    """
    Damgasızlık bir hata değil bir eksiklik; kullanıcı bunu karıştırmamalı.
    """
    assert "GELMEZ" in tr._ADIM["no_timestamp"].ozet
    assert tr._ADIM["no_timestamp"].seviye == tr.SEVIYE_DAMGASIZ


def test_okunamadi_ile_gecersiz_AYRI_seviyeler() -> None:
    """
    "Kontrol edemedim" ile "damga sahte" aynı şey değil.

    İkisini tek kırmızıya toplamak, aktarımda zarar görmüş sağlam bir
    dosyayı kurcalanmış gibi gösterirdi.
    """
    assert tr._ADIM["parse"].seviye == tr.SEVIYE_OKUNAMADI
    assert tr._ADIM["signature"].seviye == tr.SEVIYE_GECERSIZ
    assert tr.SEVIYE_OKUNAMADI != tr.SEVIYE_GECERSIZ


# ══════════════════════════════════════════════════════════════════════════════
# 3. aciklama() — sonuçtan mesaja
# ══════════════════════════════════════════════════════════════════════════════


def test_gercek_bir_damga_gecerli_okunuyor(tmp_path: Path, key: bytes) -> None:
    """GERÇEK freetsa.org damgası, uçtan uca, rapor katmanı dahil."""
    path = _hcl(tmp_path, key, _FIXTURE_PLAIN, name="vektor.bin")
    token = tsp.TimeStampResp.load(_FIXTURE.read_bytes())["time_stamp_token"].dump()
    attach_trailer(path, TimestampInfo(
        hash_algorithm="sha256",
        hashed_hex=hashlib.sha256(_FIXTURE_PLAIN).hexdigest(),
        tsa_url="https://freetsa.org/tsr",
        token_der=token,
    ))

    # Kök VERİLMEDEN: kriptografik olarak geçerli ama güven kökü dosyanın
    # kendisinden geldi — başlık ve seviye bunu söylemeli.
    mesaj = tr.aciklama(verify_timestamp(path, key))
    assert mesaj.seviye == tr.SEVIYE_UYARI
    assert mesaj.baslik == "Damga geçerli — ama damgayı atan kurum doğrulanmadı"


def test_damgasiz_dosya_hata_DEGIL_eksiklik_olarak_bildiriliyor(
    unstamped: Path, key: bytes,
) -> None:
    mesaj = tr.aciklama(verify_timestamp(unstamped, key))
    assert mesaj.seviye == tr.SEVIYE_DAMGASIZ
    assert "yok" in mesaj.baslik.lower()


def test_baska_bir_dosyanin_damgasi_ACIKCA_soyleniyor(
    tmp_path: Path, key: bytes,
) -> None:
    """Fragman bir dosyadan diğerine kopyalanırsa kullanıcı bunu anlamalı."""
    kaynak = _hcl(tmp_path, key, b"birinci belge" * 50, name="bir.bin")
    timestamp_file(kaynak, key, transport=FakeTSA())
    hedef = _hcl(tmp_path, key, b"ikinci belge" * 50, name="iki.bin")

    from CORE.timestamp import encode_trailer, read_trailer
    fragman = read_trailer(kaynak)
    assert fragman is not None
    hedef.write_bytes(hedef.read_bytes() + encode_trailer(fragman))

    sonuc = verify_timestamp(hedef, key)
    assert not sonuc.valid
    mesaj = tr.aciklama(sonuc)
    assert mesaj.seviye == tr.SEVIYE_GECERSIZ
    assert "bu dosyaya ait değil" in mesaj.baslik.lower()


def test_bozulmus_damga_gecersiz_okunuyor(stamped: Path, key: bytes) -> None:
    ham = bytearray(stamped.read_bytes())
    # Fragmanın ortasındaki bir byte'ı çevir — imza tutmaz.
    ham[-200] ^= 0xFF
    stamped.write_bytes(bytes(ham))

    sonuc = verify_timestamp(stamped, key)
    assert not sonuc.valid
    mesaj = tr.aciklama(sonuc)
    assert mesaj.seviye in (tr.SEVIYE_GECERSIZ, tr.SEVIYE_OKUNAMADI)
    assert mesaj is not tr.BILINMEYEN, (
        "Gerçek bir bozulma tanınmayan koda düştü — tablo eksik."
    )


def test_taninmayan_kod_COKMEDEN_bilinmeyene_dusuyor() -> None:
    sonuc = TimestampVerification(
        valid=False, reason="?", failed_check="gelecekteki_kontrol"
    )
    assert tr.aciklama(sonuc) is tr.BILINMEYEN


def test_kodu_olmayan_basarisizlik_de_bilinmeyene_dusuyor() -> None:
    """`failed_check=None` bugün üretilmiyor; arayüz yine de çökmemeli."""
    assert tr.aciklama(TimestampVerification(valid=False)) is tr.BILINMEYEN


def test_gecerli_sonucta_failed_check_yok_sayiliyor() -> None:
    """
    `valid=True` ile birlikte gelen bir `failed_check`, geçerliliği
    bozmamalı — karar `valid` alanının.
    """
    sonuc = TimestampVerification(valid=True, failed_check="eku")
    assert tr.aciklama(sonuc) is tr._GECERLI_KOK_DOGRULANMADI
    guvenilir = TimestampVerification(valid=True, failed_check="eku",
                                      anchor_trusted=True)
    assert tr.aciklama(guvenilir).seviye == tr.SEVIYE_GECERLI


# ══════════════════════════════════════════════════════════════════════════════
# 4. notlar() — geçerli sonuca eşlik eden sınırlar
# ══════════════════════════════════════════════════════════════════════════════


def test_gecersiz_sonucta_not_YOK() -> None:
    """Hata mesajının yanına eklenen "ayrıca" maddeleri asıl mesajı zayıflatır."""
    assert tr.notlar(TimestampVerification(valid=False, failed_check="eku")) == []


def test_kok_dogrulanmadiginda_UYARI_veriliyor(stamped: Path, key: bytes) -> None:
    """
    Güvenilir kök verilmeden yapılan doğrulama "geçerli" diyor — ve bu
    ekranın ne anlama GELMEDİĞİNİ söylemesi gerekiyor.
    """
    sonuc = verify_timestamp(stamped, key)
    assert sonuc.valid and not sonuc.anchor_trusted

    uyarilar = [n for n in tr.notlar(sonuc) if n.seviye == tr.SEVIYE_UYARI]
    assert len(uyarilar) == 1
    assert _kucult("kendi içinden") in _kucult(uyarilar[0].ozet)
    assert uyarilar[0].oneri


def test_kok_dogrulandiginda_uyari_yerine_BILGI(stamped: Path, key: bytes) -> None:
    from tsa_fixtures import default_authority

    sonuc = verify_timestamp(stamped, key, trusted_roots=[default_authority().ca_der])
    assert sonuc.valid and sonuc.anchor_trusted

    notlar = tr.notlar(sonuc)
    assert not [n for n in notlar if n.seviye == tr.SEVIYE_UYARI]
    assert [n for n in notlar if n.seviye == tr.SEVIYE_BILGI]


def test_kontrolun_KAPSAMI_her_gecerli_sonucta_yaziyor(stamped: Path, key: bytes) -> None:
    """
    B-092/B-099: eskiden "içeriğin parmak iziyle eşleştiği burada kontrol
    EDİLMİYOR" denirdi — artık ediliyor (bkz. `CORE/timestamp_report.py`
    "DOĞRULUK, SADELİKTEN ÖNCE GELİR"). Bu notun görevi de o yüzden
    DEĞİŞTİ: artık "kontrol edilmiyor" demiyor, "birlikte doğrulandı"
    diyor — ama hâlâ HER geçerli sonuçta (kök güvenilir olsun ya da
    olmasın) görünmesi gerekiyor, çünkü kullanıcının doğrulamanın tam
    olarak neyi kapsadığını her seferinde görmesi önemli.
    """
    from tsa_fixtures import default_authority

    for kokler in (None, [default_authority().ca_der]):
        sonuc = verify_timestamp(stamped, key, trusted_roots=kokler)
        kapsam = [n for n in tr.notlar(sonuc) if "kapsıyor" in n.baslik]
        assert len(kapsam) == 1, f"trusted_roots={kokler is not None} için kapsam notu yok"
        assert _kucult("içeriği") in _kucult(kapsam[0].ozet)


def test_uyari_metni_de_teknik_terim_tasimiyor(stamped: Path, key: bytes) -> None:
    for mesaj in tr.notlar(verify_timestamp(stamped, key)):
        metin = f"{mesaj.baslik} {mesaj.ozet} {mesaj.oneri or ''}"
        # --trusted-root bir komut satırı seçeneği: teknik ama EYLEM.
        kacak = _jargon_kacaklari(metin.replace("--trusted-root", ""))
        assert not kacak, f"{mesaj.baslik!r} teknik terim taşıyor: {kacak}"


# ══════════════════════════════════════════════════════════════════════════════
# 5. detaylar() ve zaman_metni()
# ══════════════════════════════════════════════════════════════════════════════


def test_bos_alanlar_detaylara_GIRMIYOR() -> None:
    """"Politika: None" satırı bilgi değil gürültü."""
    satirlar = tr.detaylar(TimestampVerification(valid=False, failed_check="aad"))
    assert all(deger for _ad, deger in satirlar)
    assert not any(ad == "Politika" for ad, _ in satirlar)


def test_detaylar_dusen_kontrolu_ve_teknik_nedeni_TASIYOR(
    unstamped: Path, key: bytes,
) -> None:
    """
    Sadeleştirme, teknik bilgiyi SİLMEK değil bir kat aşağı koymak.

    Kullanıcı yöneticisine bir şey iletecekse tam olarak bunlar gerekiyor.
    """
    satirlar = dict(tr.detaylar(verify_timestamp(unstamped, key)))
    assert satirlar["Düşen kontrol"] == "no_timestamp"
    assert satirlar["Teknik neden"]


def test_gecerli_damganin_detaylari_TSA_bilgisini_veriyor(
    stamped: Path, key: bytes,
) -> None:
    satirlar = dict(tr.detaylar(verify_timestamp(stamped, key)))
    assert satirlar["Damgayı atan"]
    assert satirlar["Seri numarası"]
    assert satirlar["Zincirin kökü"]


def test_zaman_UTC_olarak_ve_cevrilmeden_gosteriliyor() -> None:
    """
    Yerel saate çevirmek, makinenin saat dilimi yanlışsa kaydedilenden
    başka bir tarih göstermeye açık olurdu. Damganın hukuki değeri
    evrensel ana bağlı.
    """
    an = datetime(2026, 8, 19, 12, 34, 56, tzinfo=timezone.utc)
    assert tr.zaman_metni(an) == "19.08.2026 12:34:56 UTC"


def test_zamansiz_sonuc_cizgi_donuyor() -> None:
    assert tr.zaman_metni(None) == "—"
