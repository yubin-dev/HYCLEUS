"""
Statik analiz araçlarının GERÇEKTEN çalıştığını doğrulayan testler.

Neden bu dosya var
------------------
`bandit` ve `semgrep` CI'da yeşil geçtiğinde bu iki anlama gelebilir:

    1. Kod temiz.
    2. Araç hiçbir şey denetlemiyor.

İkincisi sessizdir ve gerçekten olur: yanlış bir `skips` girdisi, bozuk bir
`paths` filtresi, YAML sözdizimi hatası, yanlış hedef dizin — hepsi "0 bulgu"
üretir. Bir güvenlik kapısının en kötü hâli, kapalı görünen açık bir kapıdır.

Buradaki testler kapıyı iterek deniyor: bilerek güvensiz kanarya dosyaları
üzerinde her kuralın tetiklendiğini doğruluyorlar. Kanarya tetiklenmiyorsa
tarama sonucunun bir anlamı yok.

Araç kurulu değilse testler ATLANIR. CI'da ikisi de kurulu
(`requirements-dev.txt`), yani orada gerçekten çalışıyorlar.

Windows notu
------------
semgrep 1.173 kural dosyasını `Path.read_text()` ile, yani yerel kod
sayfasıyla okuyor. Türkçe karakter içeren bir kural dosyası cp1254/cp1252
altında `UnicodeDecodeError` ile çöküyor. Bu yüzden semgrep'i çağıran her
yer `PYTHONUTF8=1` geçiyor — CI adımı da dahil. Bkz. BACKLOG.md / B-020.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

KOK = Path(__file__).resolve().parent.parent
KANARYA = KOK / "tests" / "canary_semgrep"
KURALLAR = KOK / ".semgrep" / "hycleus.yml"

#: Ana taramanın hedefleri — CI adımıyla aynı liste olmalı.
HEDEFLER = ["CORE", "DB", "UI", "main.py", ".github"]


def _utf8_env() -> dict[str, str]:
    """semgrep'in kural dosyasını UTF-8 okumasını garanti eden ortam."""
    ortam = dict(os.environ)
    ortam["PYTHONUTF8"] = "1"
    ortam["SEMGREP_SEND_METRICS"] = "off"
    return ortam


def _calistir(argv: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv, cwd=KOK, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=900, **kw,
    )


# ══════════════════════════════════════════════════════════════════════════════
# bandit
# ══════════════════════════════════════════════════════════════════════════════

bandit_gerekli = pytest.mark.skipif(
    shutil.which("bandit") is None, reason="bandit kurulu değil"
)


@pytest.fixture(scope="module")
def bandit_kanarya(tmp_path_factory) -> Path:
    """
    bandit'in yakalaması BEKLENEN desenler.

    Hiçbiri `pyproject.toml`'daki `skips` listesinde değil — yani bu dosya
    yapılandırmanın her şeyi susturmadığının kanıtı.
    """
    yol = tmp_path_factory.mktemp("bandit_kanarya") / "kanarya.py"
    yol.write_text(
        "import hashlib\n"
        "import pickle\n"
        "import subprocess\n"
        "\n"
        "def a(s):\n"
        "    return eval(s)                       # B307\n"
        "\n"
        "def b(cmd):\n"
        "    subprocess.run(cmd, shell=True)      # B602\n"
        "\n"
        "def c(x):\n"
        "    return hashlib.md5(x).hexdigest()    # B324\n"
        "\n"
        "def d(blob):\n"
        "    return pickle.loads(blob)            # B301\n"
        "\n"
        # B105 bandit'in kelime listesine bakıyor ('password', 'secret',
        # 'token'...); Türkçe bir ad yakalanmaz.
        "password = 'hunter2'                     # B105\n",
        encoding="utf-8",
    )
    return yol


@bandit_gerekli
def test_bandit_yapilandirmasi_kanaryayi_yakaliyor(bandit_kanarya: Path) -> None:
    """
    Proje yapılandırmasıyla bile tehlikeli desenler kapıyı geçemiyor.

    Neden `-f json`, `-f custom` değil
    ----------------------------------
    İlk sürüm `-f custom --msg-template "{test_id}"` kullanıyordu ve GitHub'ın
    Windows koşucusunda kırıldı. Sebep bandit 1.9'daki bir hata:
    `formatters/custom.py` şablonda YALNIZCA `{test_id}` istense bile
    `tag_mapper`'ın TÜM girdilerini hevesle hesaplıyor — `relpath` dahil.
    `os.path.relpath` ise sürücü sınırında `ValueError` fırlatıyor:

        ValueError: path is on mount 'C:', start on mount 'D:'

    GitHub Windows koşucusunda çalışma alanı `D:\\a\\...`, TEMP ise
    `C:\\Users\\runneradmin\\...`. Yani `tmp_path`'e yazılan her kanarya
    farklı sürücüde kalıyor ve bandit boş çıktıyla, sıfırdan farklı bir kod
    döndürüyor: "hiçbir bulgu yok" ile "araç çöktü" ayırt edilemez hâle
    geliyor.

    `-f json` bu biçimlendiriciye hiç uğramıyor ve sürücü varsayımı
    taşımıyor. Bulgu `subst X:` ile yerel olarak birebir üretildi.
    """
    import json

    sonuc = _calistir([
        "bandit", "-c", str(KOK / "pyproject.toml"),
        "-q", "-f", "json", str(bandit_kanarya),
    ])
    assert sonuc.stdout.strip(), (
        "bandit çıktı üretmedi — araç çöktü mü?\n"
        f"exit={sonuc.returncode}\nstderr:\n{sonuc.stderr}"
    )
    veri = json.loads(sonuc.stdout)
    assert not veri.get("errors"), veri["errors"]
    assert sonuc.returncode != 0, (
        "bandit kanarya dosyasında hiçbir şey bulmadı — yapılandırma her "
        f"şeyi susturuyor olabilir.\nstdout:\n{sonuc.stdout}\n{sonuc.stderr}"
    )

    yakalanan = {b["test_id"] for b in veri["results"]}
    for beklenen in ("B307", "B602", "B324", "B301", "B105"):
        assert beklenen in yakalanan, (
            f"{beklenen} yakalanmadı. Yakalananlar: {sorted(yakalanan)}"
        )


@bandit_gerekli
def test_bandit_gercek_kod_tabaninda_temiz() -> None:
    """CI adımının aynısı. Kırılırsa yeni bir bulgu girmiş demektir."""
    sonuc = _calistir([
        "bandit", "-c", str(KOK / "pyproject.toml"), "-q", "-r",
        "CORE", "DB", "UI", "main.py",
    ])
    assert sonuc.returncode == 0, (
        "bandit yeni bir bulgu buldu. Ya düzeltin, ya satıra gerekçeli "
        f"`# nosec <ID>` ekleyin.\n{sonuc.stdout}\n{sonuc.stderr}"
    )


def test_bandit_skips_listesi_belgeli() -> None:
    """
    `skips` içindeki her ID'nin yanında yazılı bir gerekçe olmalı.

    Gerekçesiz bir skip, "bu bulguyu inceledim" ile "bu bulguyu susturdum"
    arasındaki farkı yok eder. Yapılandırma dosyasındaki yorum bloğu bu
    ayrımı taşıyan tek şey.
    """
    metin = (KOK / "pyproject.toml").read_text(encoding="utf-8")
    cfg = tomllib.loads(metin)
    skips = cfg["tool"]["bandit"]["skips"]
    assert skips, "skips listesi boş — test anlamsızlaştı"

    # Gerekçeler `[tool.bandit]` bloğunun yorumlarında; TOML onları atıyor,
    # bu yüzden ham metinde arıyoruz.
    blok = metin[metin.index("[tool.bandit]"):]
    for kimlik in skips:
        assert f"#   {kimlik} ·" in blok, (
            f"{kimlik} susturulmuş ama pyproject.toml'da gerekçesi yok. "
            "Her skip için '#   <ID> · <adet>× · <gerekçe>' satırı bekleniyor."
        )


def test_nosec_isaretleri_gerekceli() -> None:
    """
    Depodaki her `# nosec`, aynı satırda ya da hemen üstünde bir açıklama
    taşımalı. Çıplak bir `# nosec` gelecekteki okura hiçbir şey söylemez.
    """
    ciplak: list[str] = []
    for yol in list(KOK.glob("CORE/*.py")) + list(KOK.glob("DB/*.py")) \
            + list(KOK.glob("UI/*.py")) + [KOK / "main.py"]:
        satirlar = yol.read_text(encoding="utf-8").splitlines()
        for i, satir in enumerate(satirlar):
            if "# nosec" not in satir:
                continue
            # Aynı satırda başka bir açıklama var mı, ya da üstteki satır
            # yorum mu?
            onceki = satirlar[i - 1].strip() if i else ""
            satir_ici = satir.split("# nosec")[0].count("#") > 0
            if not (satir_ici or onceki.startswith("#")):
                ciplak.append(f"{yol.relative_to(KOK)}:{i + 1}")
    assert not ciplak, (
        "Gerekçesiz `# nosec` işaretleri:\n  " + "\n  ".join(ciplak)
    )


# ══════════════════════════════════════════════════════════════════════════════
# semgrep
# ══════════════════════════════════════════════════════════════════════════════

semgrep_gerekli = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep kurulu değil"
)


def _yerel_kural_kimlikleri() -> list[str]:
    """`.semgrep/hycleus.yml` içindeki kural ID'leri — YAML'siz, ham metinden."""
    metin = KURALLAR.read_text(encoding="utf-8")
    return [
        satir.split("- id:", 1)[1].strip()
        for satir in metin.splitlines()
        if satir.strip().startswith("- id:")
    ]


def test_yerel_kural_dosyasi_utf8_ve_kurallari_var() -> None:
    """Kural dosyası okunabiliyor ve boş değil — semgrep olmadan da çalışır."""
    kimlikler = _yerel_kural_kimlikleri()
    assert len(kimlikler) >= 5, f"Beklenenden az kural: {kimlikler}"
    assert all(k.startswith("hycleus-") for k in kimlikler), kimlikler


def test_her_kuralin_kanaryasi_var() -> None:
    """
    Kural dosyasındaki her ID, kanarya dosyasında adıyla anılmalı.

    Bu, semgrep kurulu olmasa da çalışan ucuz bir kapı: yeni bir kural
    eklenip kanaryası unutulursa burada yakalanır.
    """
    kanarya_metni = "\n".join(
        p.read_text(encoding="utf-8") for p in KANARYA.rglob("*.py")
    )
    eksik = [k for k in _yerel_kural_kimlikleri() if k not in kanarya_metni]
    assert not eksik, (
        "Şu kuralların kanaryası yok (kanarya dosyasında ID'si geçmiyor): "
        f"{eksik}. tests/canary_semgrep/README.md'ye bakın."
    )


@semgrep_gerekli
def test_yerel_kurallarin_hepsi_kanaryada_tetikleniyor() -> None:
    """
    Asıl kanıt: her yerel kural gerçekten eşleşiyor mu?

    Bir kural yazım hatası yüzünden hiç eşleşmiyorsa, koruduğunu sandığımız
    şey korunmuyor ve tarama yine yeşil çıkıyor.
    """
    import json

    sonuc = _calistir(
        [
            "semgrep", "scan", "--config", str(KURALLAR),
            "--metrics=off", "--no-git-ignore", "--json", "--quiet",
            str(KANARYA),
        ],
        env=_utf8_env(),
    )
    assert sonuc.stdout.strip(), f"semgrep çıktı vermedi:\n{sonuc.stderr}"
    veri = json.loads(sonuc.stdout)
    assert not veri.get("errors"), veri["errors"]

    tetiklenen = {r["check_id"].rsplit(".", 1)[-1] for r in veri["results"]}
    eksik = [k for k in _yerel_kural_kimlikleri() if k not in tetiklenen]
    assert not eksik, (
        f"Bu kurallar kanaryada TETİKLENMEDİ: {eksik}\n"
        f"Tetiklenenler: {sorted(tetiklenen)}\n"
        "Kural ölü olabilir — desenini ya da paths filtresini kontrol edin."
    )


@semgrep_gerekli
def test_semgrep_gercek_kod_tabaninda_temiz() -> None:
    """CI adımının aynısı, yalnızca yerel kurallarla (ağ gerektirmez)."""
    sonuc = _calistir(
        [
            "semgrep", "scan", "--config", str(KURALLAR),
            "--metrics=off", "--error", "--quiet", *HEDEFLER,
        ],
        env=_utf8_env(),
    )
    assert sonuc.returncode == 0, (
        "Yerel semgrep kuralları yeni bir bulgu buldu:\n"
        f"{sonuc.stdout}\n{sonuc.stderr}"
    )


@semgrep_gerekli
@pytest.mark.skipif(sys.platform != "win32", reason="yalnızca Windows'ta anlamlı")
def test_windows_pythonutf8_olmadan_kural_dosyasi_okunamiyor() -> None:
    """
    Yukarıdaki `PYTHONUTF8=1`'in gerçekten gerekli olduğunu sabitler.

    Bu test bir gün KIRILIRSA iyi haber demektir: semgrep kural dosyasını
    UTF-8 okumaya başlamış olur ve `PYTHONUTF8=1` her yerden kaldırılabilir
    (CI adımı, bu dosyadaki `_utf8_env`, BACKLOG B-020).
    """
    ortam = dict(os.environ)
    ortam["PYTHONUTF8"] = "0"

    # `--quiet` BİLEREK yok: çöküş geri izini bastırıyor ve test hatayı
    # göremeden "sorun kalmamış" sanıyor. Bu tuzağa bir kez düşüldü.
    sonuc = _calistir(
        ["semgrep", "scan", "--config", str(KURALLAR), "--metrics=off",
         "--no-git-ignore", str(KANARYA)],
        env=ortam,
    )
    ciktilar = sonuc.stdout + sonuc.stderr
    if sonuc.returncode == 0 or "UnicodeDecodeError" not in ciktilar:
        pytest.skip(
            "semgrep artık kural dosyasını yerel kod sayfasıyla okumuyor — "
            "B-020 kapatılabilir, PYTHONUTF8=1 her yerden kalkabilir."
        )
    # Buraya gelindiyse çöküş hâlâ var; PYTHONUTF8=1 ile GEÇTİĞİNİ de
    # göstermek gerekiyor, yoksa suçlu ortam değişkeni olmayabilir.
    duzeltilmis = _calistir(
        ["semgrep", "scan", "--config", str(KURALLAR), "--metrics=off",
         "--no-git-ignore", "--quiet", str(KANARYA)],
        env=_utf8_env(),
    )
    assert "UnicodeDecodeError" not in (duzeltilmis.stdout + duzeltilmis.stderr), (
        "PYTHONUTF8=1 çöküşü engellemiyor — gerekçe yanlış, yeniden bakılmalı."
    )
