"""
Sürüm dizesinin tek kaynaktan geldiğini denetleyen testler — B-017.

Neden bir test gerekiyor
------------------------
Sürüm beş yerde elle yazılıydı ve beşi farklı şeyler söylüyordu (etiket
v2.1.2, SECURITY.md v2.1.0, README rozeti 2.0, Hakkında kutusu v1.6,
İletişim kutusu v1.5). Hiçbiri çalışma zamanını etkilemiyordu, bu yüzden
yıllarca fark edilmeden durdu.

Kodu tek kaynağa bağlamak (`CORE/version.py`) yarısını çözüyor: Python
tarafı artık ayrışamaz. Ama BELGELER kod okuyamıyor — SECURITY.md ve README
elle güncelleniyor ve ayrışmaları yine sessiz olurdu. Bu testler o boşluğu
kapatıyor: belgedeki dizeler koddaki sabitlerle karşılaştırılıyor.

Yani buradaki asıl iş, düzeltmeyi değil DÜZELTMENİN KALICILIĞINI
denetlemek.
"""
from __future__ import annotations

import ast
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from CORE import version
from CORE.version import SON_YAYIN, __version__, gelistirme_surumu_mu, surum_etiketi

KOK = Path(__file__).resolve().parent.parent


# ══════════════════════════════════════════════════════════════════════════════
# Modülün kendisi
# ══════════════════════════════════════════════════════════════════════════════

def test_surum_dizeleri_makul() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+(\.dev)?", __version__), __version__
    assert re.fullmatch(r"\d+\.\d+\.\d+", SON_YAYIN), SON_YAYIN


def test_surum_etiketi_bicimi() -> None:
    assert surum_etiketi() == f"HYCLEUS v{__version__}"


def test_gelistirme_bayragi_surumle_tutarli() -> None:
    assert gelistirme_surumu_mu() == ("dev" in __version__)


def test_calisan_surum_son_yayindan_geride_degil() -> None:
    """
    `__version__` >= `SON_YAYIN` olmalı.

    Tersi, yayınlanmış bir sürümden eski bir ağaç çalıştırıyoruz demek
    olurdu — ya da (çok daha olası) `SON_YAYIN` güncellenirken
    `__version__` unutulmuş demek. B-017'nin tam olarak bu türden bir
    unutmadan doğduğunu hatırlayın.
    """
    def _parcala(s: str) -> tuple[int, ...]:
        return tuple(int(x) for x in s.split(".dev")[0].split("."))

    assert _parcala(__version__) >= _parcala(SON_YAYIN), (
        f"__version__={__version__} < SON_YAYIN={SON_YAYIN}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# Arayüz — elle yazılmış sürüm dizesi kalmamalı
# ══════════════════════════════════════════════════════════════════════════════

#: Bu dosyalarda sürüm dizesi elle yazılıydı; artık koddan okunmalı.
_UI_DOSYALARI = ("UI/ContactDialog.py", "UI/main_window.py")


@pytest.mark.parametrize("goreli", _UI_DOSYALARI)
def test_arayuzde_elle_yazilmis_surum_yok(goreli: str) -> None:
    """
    `HYCLEUS v1.5` gibi sabit bir dize geri gelirse yakala.

    Deseni bilerek geniş: `HYCLEUS v<rakam>` biçiminde HERHANGİ bir sabit
    dize hata. Doğrusu `surum_etiketi()` çağırmak.
    """
    kaynak = (KOK / goreli).read_text(encoding="utf-8")
    kacaklar = re.findall(r"[\"']HYCLEUS v\d[^\"']*[\"']", kaynak)
    assert not kacaklar, (
        f"{goreli}: elle yazılmış sürüm dizesi var: {kacaklar}. "
        "`CORE.version.surum_etiketi()` kullanın (B-017)."
    )


@pytest.mark.parametrize("goreli", _UI_DOSYALARI)
def test_arayuz_surum_modulunu_kullaniyor(goreli: str) -> None:
    """Dize yokluğu yetmez — kaynağın gerçekten kullanıldığı da gösterilmeli."""
    agac = ast.parse((KOK / goreli).read_text(encoding="utf-8"))
    ithaller = {
        alias.name
        for n in ast.walk(agac)
        if isinstance(n, ast.ImportFrom) and n.module == "CORE.version"
        for alias in n.names
    }
    assert "surum_etiketi" in ithaller, (
        f"{goreli}: `CORE.version` içe aktarılmamış."
    )


def test_hakkinda_kutusu_dogru_semayi_soyluyor() -> None:
    """
    Hakkında kutusu "2-of-2" diyordu; şema v2.1'den beri 2-of-3.

    Sürümle aynı sınıftan bir hata: kullanıcıya gösterilen, kimsenin
    bakmadığı ve koddan kopmuş bir dize.
    """
    kaynak = (KOK / "UI/main_window.py").read_text(encoding="utf-8")
    assert "2-of-3" in kaynak, "Hakkında kutusunda şema bilgisi yok"
    assert "2-of-2" not in kaynak, "Hakkında kutusu hâlâ 2-of-2 diyor"


# ══════════════════════════════════════════════════════════════════════════════
# Belgeler — koddan okuyamıyorlar, o yüzden karşılaştırılıyorlar
# ══════════════════════════════════════════════════════════════════════════════

def test_security_md_calisan_surumu_dogru_yaziyor() -> None:
    metin = (KOK / "SECURITY.md").read_text(encoding="utf-8")
    for etiket in ("**Applies to:** v", "**Kapsam:** v"):
        i = metin.index(etiket)
        satir = metin[i : metin.index("\n", i)]
        assert f"v{__version__}" in satir, (
            f"SECURITY.md {etiket!r} satırı eskimiş: {satir!r} — "
            f"beklenen v{__version__}"
        )


def test_security_md_desteklenen_surumu_dogru_yaziyor() -> None:
    metin = (KOK / "SECURITY.md").read_text(encoding="utf-8")
    for etiket in ("**Supported version:**", "**Desteklenen sürüm:**"):
        i = metin.index(etiket)
        parca = metin[i : i + 200]
        assert f"v{SON_YAYIN}" in parca, (
            f"SECURITY.md {etiket!r} bölümü eskimiş — beklenen v{SON_YAYIN}"
        )


def test_readme_rozeti_guncel() -> None:
    metin = (KOK / "README.md").read_text(encoding="utf-8")
    eslesme = re.search(r"badge/Version-([^-]+)-", metin)
    assert eslesme, "README'de sürüm rozeti bulunamadı"
    assert eslesme.group(1) == __version__, (
        f"README rozeti {eslesme.group(1)!r}, kod {__version__!r} diyor."
    )


def test_eski_surum_atiflari_tarih_olarak_kaldi() -> None:
    """
    SECURITY.md'deki "v2.1.0'a kadar ..." cümleleri TARİHSEL — değişmemeli.

    Toplu bir arayıp-değiştirme onları da bozardı ve belge geçmişi hakkında
    yalan söylemeye başlardı. Bu test o farkı koruyor.
    """
    metin = (KOK / "SECURITY.md").read_text(encoding="utf-8")
    assert "Until v2.1.0 the login path did **not** check the flag" in metin
    assert "v2.1.0'a kadar giriş yolu bayrağı **kontrol etmiyordu**" in metin


# ══════════════════════════════════════════════════════════════════════════════
# git etiketi
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(shutil.which("git") is None, reason="git yok")
def test_son_yayin_git_etiketiyle_uyusuyor() -> None:
    """
    `SON_YAYIN` gerçekten en son etiket mi?

    Sürüm yükseltmenin 3. adımı (`SON_YAYIN`'ı çek) unutulursa burada
    yakalanır. Depo etiketsizse ya da git yoksa atlanır — CI'ın sığ
    klonunda etiket olmayabilir.
    """
    try:
        cikti = subprocess.run(
            ["git", "tag", "--list", "v*"],
            cwd=KOK, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"git çalıştırılamadı: {exc}")

    etiketler = [t.strip().lstrip("v") for t in cikti.stdout.split() if t.strip()]
    if not etiketler:
        pytest.skip("depoda etiket yok (sığ klon olabilir)")

    def _parcala(s: str) -> tuple[int, ...]:
        try:
            return tuple(int(x) for x in s.split("."))
        except ValueError:
            return (0,)

    en_yeni = max(etiketler, key=_parcala)
    assert SON_YAYIN == en_yeni, (
        f"CORE/version.py SON_YAYIN={SON_YAYIN} ama en son etiket v{en_yeni}. "
        "Sürüm yükseltmenin 3. adımı atlanmış olabilir "
        "(bkz. CORE/version.py docstring'i)."
    )


def test_version_modulu_hicbir_seye_bagimli_degil() -> None:
    """
    `CORE/version.py` import etmemeli.

    Sürüm bilgisi en alt katman: her yerden (UI, CORE, betikler) okunacak.
    Bir bağımlılık eklenirse döngüsel import riski doğar ve o gün dize
    yeniden elle yazılmaya başlanır.
    """
    agac = ast.parse(Path(version.__file__).read_text(encoding="utf-8"))
    ithaller = [
        n for n in ast.walk(agac)
        if isinstance(n, (ast.Import, ast.ImportFrom))
        and not (isinstance(n, ast.ImportFrom) and n.module == "__future__")
    ]
    assert not ithaller, f"CORE/version.py import ediyor: {ast.dump(ithaller[0])}"
