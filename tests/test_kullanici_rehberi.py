"""
docs/kullanici-rehberi.md — rehberin söylediği şeyler HÂLÂ DOĞRU mu.

Bu rehberin kitlesi, bir şeyi kaybetmiş ve panikleyen bir kullanıcı. O
anda yazdığı komutu sorgulayacak durumda değil. Yani buradaki bir
yanlışlık, sıradan bir belge hatası değil:

  · Var olmayan bir komut → kullanıcı çaresiz kalır, kendi çözümünü
    aramaya başlar ve büyük ihtimalle `--reset`'i bulur.
  · Var olmayan bir seçenek numarası → yanlış dalı seçer.
  · Değişmiş bir durum adı → tablodan okuduğu şey ekrandakiyle
    eşleşmez ve tabloya güvenmeyi bırakır.

Belgeler kod okuyamaz; ayrışmaları SESSİZDİR. Bu depoda aynı sınıftan
bir bulgu zaten var (B-017: sürüm dizesi beş yerde, beşi farklı).

Denetim, rehberdeki komutları argparse tanımlarıyla, durum adlarını
`IntegrityStatus` ile, menü etiketlerini arayüz kaynağıyla
KARŞILAŞTIRIYOR — hiçbirini elle tekrar yazmıyor.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from CORE.integrity import IntegrityStatus

KOK = Path(__file__).parent.parent
REHBER = KOK / "docs" / "kullanici-rehberi.md"

#: Rehberde `python CORE/<betik>.py --<secenek>` biçimindeki her çağrı.
_KOMUT = re.compile(r"python\s+CORE/(\w+)\.py([^\n`]*)")
_SECENEK = re.compile(r"--[a-z][a-z-]*")


def _metin() -> str:
    return REHBER.read_text(encoding="utf-8")


def _argparse_secenekleri(betik: Path) -> set[str]:
    """Bir betiğin `add_argument()` ile tanımladığı uzun seçenekler."""
    bulunan: set[str] = set()
    for dugum in ast.walk(ast.parse(betik.read_text(encoding="utf-8"))):
        if (
            isinstance(dugum, ast.Call)
            and isinstance(dugum.func, ast.Attribute)
            and dugum.func.attr == "add_argument"
        ):
            for arg in dugum.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.startswith("--"):
                        bulunan.add(arg.value)
    return bulunan


def _rehberdeki_komutlar() -> list[tuple[str, set[str]]]:
    """`(betik_adi, {seçenekler})` — rehberde geçen her komut satırı."""
    cikti: list[tuple[str, set[str]]] = []
    for betik, kuyruk in _KOMUT.findall(_metin()):
        cikti.append((betik, set(_SECENEK.findall(kuyruk))))
    return cikti


# ══════════════════════════════════════════════════════════════════════════════
# 1. Komutlar gerçek mi
# ══════════════════════════════════════════════════════════════════════════════


def test_rehber_var():
    assert REHBER.is_file(), "docs/kullanici-rehberi.md kayıp"


def test_tarayici_gercekten_komut_buluyor():
    """
    Boş liste dönerse aşağıdaki denetim kendiliğinden geçerdi — ve rehber
    tümüyle yanlış komutlarla dolu olsa bile testler yeşil kalırdı.
    """
    komutlar = _rehberdeki_komutlar()
    assert len(komutlar) >= 5, f"Yalnızca {len(komutlar)} komut bulundu"
    assert {b for b, _ in komutlar} >= {
        "recover_vault", "backup_cli", "setup_usb",
    }


def test_rehberdeki_HER_betik_var():
    for betik, _ in _rehberdeki_komutlar():
        assert (KOK / "CORE" / f"{betik}.py").is_file(), (
            f"Rehber var olmayan CORE/{betik}.py betiğini gösteriyor"
        )


def test_rehberdeki_HER_secenek_gercek():
    """
    Bir seçenek yeniden adlandırılırsa rehber kullanıcıyı "unrecognized
    arguments" hatasına götürür — tam da yardıma en çok ihtiyaç duyduğu
    anda.
    """
    for betik, secenekler in _rehberdeki_komutlar():
        gercek = _argparse_secenekleri(KOK / "CORE" / f"{betik}.py")
        eksik = sorted(secenekler - gercek)
        assert not eksik, (
            f"Rehber CORE/{betik}.py için olmayan seçenek(ler) gösteriyor: "
            f"{eksik}. Betiğin tanıdıkları: {sorted(gercek)}"
        )


@pytest.mark.parametrize(
    "betik,secenek",
    [
        ("recover_vault", "--recover"),
        ("recover_vault", "--export"),
        ("recover_vault", "--status"),
        ("backup_cli", "--restore"),
        ("backup_cli", "--dest"),
    ],
)
def test_cozum_yollari_rehberde_ANLATILIYOR(betik: str, secenek: str):
    """
    Ters yön: araç var ama rehber ondan söz etmiyorsa kullanıcı onu
    bulamaz. Kurtarma yolunun bulunamaması, olmamasıyla aynı şeydir.
    """
    komutlar = _rehberdeki_komutlar()
    assert any(b == betik and secenek in s for b, s in komutlar), (
        f"CORE/{betik}.py {secenek} rehberde hiç geçmiyor"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2. `--reset` uyarısı
# ══════════════════════════════════════════════════════════════════════════════


def test_reset_uyarisi_rehberin_BASINDA():
    """
    Kullanıcının okumayı bırakacağı yerden önce görmesi gerekiyor.

    Uyarı sona konursa, panikleyen bir kullanıcı ona hiç ulaşmadan bir
    çözüm denemeye başlar.
    """
    metin = _metin()
    yer = metin.index("--reset")
    assert yer < len(metin) * 0.15, (
        "`--reset` uyarısı rehberin ilk %15'inde değil"
    )


def test_reset_hala_var_yoksa_uyari_ANLAMSIZ():
    """
    Uyarı bir komutu hedefliyor; komut kalkarsa uyarı da güncellenmeli.
    Var olmayan bir tehlikeyi anlatan bir uyarı, gerçek uyarıların
    inandırıcılığını düşürür.
    """
    assert "--reset" in _argparse_secenekleri(KOK / "CORE" / "setup_usb.py")


def test_SIFIRLA_onay_kelimesi_koddakiyle_ayni():
    """
    Rehber "SIFIRLA yazmayın" diyor. Kod başka bir kelime isterse
    kullanıcı uyarıyı kendi ekranında TANIYAMAZ.
    """
    kod = (KOK / "CORE" / "setup_usb.py").read_text(encoding="utf-8")
    assert '"SIFIRLA"' in kod
    assert "SIFIRLA" in _metin()


def test_her_senaryo_YAPMA_listesiyle_basliyor():
    """
    Kullanıcının isteği açıktı: "yapma" listesi net ve ÖNCE gelsin.

    Her senaryo başlığından sonra, ilk alt başlık yasak listesi olmalı;
    çözüm ondan sonra gelmeli.
    """
    metin = _metin()
    senaryolar = re.findall(r"^## \d+\. .+$", metin, re.M)
    assert len(senaryolar) == 4, f"Dört senaryo bekleniyordu: {senaryolar}"

    for baslik in senaryolar:
        govde = metin.split(baslik, 1)[1]
        sonraki_alt = re.search(r"^### (.+)$", govde, re.M)
        assert sonraki_alt is not None, f"{baslik} alt başlık taşımıyor"
        assert "⛔" in sonraki_alt.group(1), (
            f"{baslik} yasak listesiyle başlamıyor: {sonraki_alt.group(1)!r}"
        )


@pytest.mark.parametrize("senaryo", ["1.", "2.", "3.", "4."])
def test_her_senaryoda_reset_uyarisi_TEKRARLANIYOR(senaryo: str):
    """
    Kullanıcı rehberi baştan okumayabilir; doğrudan kendi senaryosuna
    atlayabilir. Uyarı yalnızca girişte durursa o kullanıcı görmez.
    """
    metin = _metin()
    bas = metin.index(f"\n## {senaryo} ")
    son = metin.find("\n## ", bas + 1)
    govde = metin[bas: son if son > 0 else len(metin)]
    assert "--reset" in govde, f"{senaryo} senaryosunda `--reset` uyarısı yok"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Ekranda görünen değerler
# ══════════════════════════════════════════════════════════════════════════════


def test_butunluk_durumlarinin_HEPSI_tabloda():
    """
    Kullanıcı ekranda ham durum adını görüyor (`tag_mismatch` gibi).
    Tabloda olmayan bir durum, kullanıcının çözemeyeceği bir kelimedir.
    """
    metin = _metin()
    eksik = [d.value for d in IntegrityStatus if f"`{d.value}`" not in metin]
    assert not eksik, f"Bu durumlar rehberde açıklanmamış: {eksik}"


def test_tabloda_UYDURMA_durum_yok():
    """
    Ters yön: rehberin açıkladığı ama artık üretilmeyen bir durum,
    kullanıcıyı olmayan bir şeyi aramaya iter.
    """
    gercek = {d.value for d in IntegrityStatus}
    # Tablodaki tek kelimelik kod biçimli hücreler.
    tablodakiler = set(re.findall(r"^\| `([a-z_]+)` \|", _metin(), re.M))
    assert tablodakiler <= gercek, (
        f"Rehberde artık üretilmeyen durum(lar) var: {sorted(tablodakiler - gercek)}"
    )


@pytest.mark.parametrize("etiket", ["📋  Denetim Günlüğü", "🔍  Yedek Doğrula…"])
def test_rehberdeki_menu_etiketleri_arayuzde_VAR(etiket: str):
    """
    Rehber kullanıcıya "menüden şunu seç" diyor. Etiket değişirse
    kullanıcı menüde o yazıyı bulamaz.

    Rehberde etiketler tek boşlukla yazılı (okunurluk); arayüzde iki
    boşluk var. Karşılaştırma boşluk sayısına duyarsız.
    """
    arayuz = (KOK / "UI" / "main_window.py").read_text(encoding="utf-8")
    assert etiket in arayuz, f"Arayüzde {etiket!r} menü maddesi yok"
    sade = re.sub(r"\s+", " ", etiket)
    assert sade in re.sub(r"\s+", " ", _metin()), (
        f"Rehber {sade!r} menü maddesinden söz etmiyor"
    )


def test_PIN_alt_siniri_koddakiyle_ayni():
    """Rehber "en az 6 hane" diyor; politika değişirse yanıltır."""
    from CORE.pin_policy import PIN_MIN_LEN

    assert f"en az {PIN_MIN_LEN} hane" in _metin().lower()


def test_kilitlenme_sureleri_koddakiyle_ayni():
    """
    Rehber "30 saniye → 1 dakika → 2 dakika → 5 dakika" diyor. Bu sayılar
    `BACKOFF_SECONDS`'tan geliyor; değişirse kullanıcı yanlış bekler.
    """
    from CORE.rate_limit import BACKOFF_SECONDS, MAX_ATTEMPTS

    assert BACKOFF_SECONDS == (30, 60, 120, 300), (
        "Kilit süreleri değişmiş — docs/kullanici-rehberi.md güncellenmeli"
    )
    assert f"{MAX_ATTEMPTS} yanlış deneme" in _metin()


def test_kurtarma_parcasi_oneki_koddakiyle_ayni():
    """
    Rehber kullanıcıya kâğıdın `HYCLEUS-R3-` ile başladığını söylüyor.
    Önek değişirse kullanıcı elindeki kâğıdın doğru kâğıt olduğunu
    anlayamaz.
    """
    from CORE.recovery_share import _PREFIX

    assert f"{_PREFIX}-" in _metin(), (
        f"Rehberdeki kurtarma parçası öneki koddaki {_PREFIX!r} ile uyuşmuyor"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 4. Rehber, sunmadığı şeyi VAAT ETMİYOR
# ══════════════════════════════════════════════════════════════════════════════


def test_kayip_USB_icin_calismayan_bir_yol_ONERILMIYOR():
    """
    `--recover` takılı ve KAYITLI bir USB istiyor (`_require_hwid()`).
    USB fiziksel olarak kaybolduysa araç hiç başlamıyor.

    Rehberin o senaryoda `--recover` önermesi, kullanıcıyı çalışmayan bir
    komuta ve oradan da büyük ihtimalle `--reset`'e yönlendirirdi. Bu
    test, sınırın rehberde AÇIKÇA yazılı kalmasını sağlıyor.
    """
    kod = (KOK / "CORE" / "recover_vault.py").read_text(encoding="utf-8")
    assert "USB tespit edilemedi" in kod, (
        "recover_vault.py artık USB'siz çalışıyor olabilir — rehberdeki "
        "sınır notu gözden geçirilmeli."
    )

    metin = _metin()
    bas = metin.index("\n## 1. ")
    govde = metin[bas: metin.index("\n## 2. ")]
    assert "USB tespit edilemedi" in govde, (
        "Rehber, USB'siz kurtarmanın çalışmadığını göstermiyor"
    )
    assert "yöneticinize" in govde.lower()
