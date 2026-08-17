"""
Antivirüs arka uçları — Defender / ClamAV.

Bu testlerin hiçbiri makinede Defender ya da ClamAV KURULU OLMASINI
gerektirmez: tek alt süreç dikişi (`scanner_backends.run_tool`) yerine
sahte bir çalıştırıcı konuyor. Ölçülen şey de zaten kurulum değil, iki
motorun ARASINDAKİ FARKLAR:

    · çıkış kodu eşlemesi — Defender'da 2 = tehdit, ClamAV'da 2 = HATA
    · `--fdpass` yalnızca daemon istemcisine ekleniyor mu
    · daemon kapalıyken `clamscan`'e düşülüyor mu
    · imza adı çıktıdan doğru ayrıştırılıyor mu
    · platform kapıları (Linux'ta Defender yok, Windows'ta ClamAV yok)

Böylece testler hem Windows'ta hem CI'ın Ubuntu ayağında aynı şeyi ölçüyor.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from CORE import scanner_backends as sb
from CORE.scanner_backends import (
    ClamAVBackend,
    DefenderBackend,
    ScannerBackend,
    parse_threat,
    select_backend,
)

SHA = "a" * 64
YOL = Path("/kasa/ornek.hcl")


# ── Sahte çalıştırıcı ─────────────────────────────────────────────────────────

class SahteKosu:
    """`run_tool` yerine geçer; çağrıları kaydeder, sırayla cevap döndürür."""

    def __init__(self, *cevaplar: tuple[int, str, str] | Exception) -> None:
        self.cevaplar = list(cevaplar)
        self.cagrilar: list[list[str]] = []

    def __call__(self, argv: list[str], timeout: int = 0) -> subprocess.CompletedProcess[str]:
        self.cagrilar.append(list(argv))
        cevap = self.cevaplar.pop(0) if self.cevaplar else (0, "", "")
        if isinstance(cevap, Exception):
            raise cevap
        rc, out, err = cevap
        return subprocess.CompletedProcess(argv, rc, out, err)


@pytest.fixture
def kosu(monkeypatch):
    def kur(*cevaplar):
        sahte = SahteKosu(*cevaplar)
        monkeypatch.setattr(sb, "run_tool", sahte)
        return sahte
    return kur


@pytest.fixture(autouse=True)
def _onbellek_temiz():
    """Arka uç seçimi süreç ömrü boyunca önbellekli — testler arasında sızmasın."""
    sb.reset_backend_cache()
    yield
    sb.reset_backend_cache()


def clam(*araclar: str) -> ClamAVBackend:
    """Kurulu ClamAV araçlarını sabitleyen arka uç (PATH'e bakmaz)."""
    return ClamAVBackend(araclar or ("/usr/bin/clamscan",))


def defender(tmp_path: Path) -> DefenderBackend:
    exe = tmp_path / "MpCmdRun.exe"
    exe.write_bytes(b"")
    return DefenderBackend(exe)


# ── Protokol ──────────────────────────────────────────────────────────────────

def test_iki_arka_uc_da_ScannerBackend_protokolunu_karsiliyor():
    assert isinstance(DefenderBackend(), ScannerBackend)
    assert isinstance(ClamAVBackend(), ScannerBackend)


def test_arka_uclarin_ad_ve_denetim_eylemi_farkli():
    """Karantina JSON'u ve denetim kaydı hangi motorun konuştuğunu söylemeli."""
    assert DefenderBackend().ad != ClamAVBackend().ad
    assert DefenderBackend().audit_action != ClamAVBackend().audit_action


# ── ClamAV: çıkış kodu eşlemesi ───────────────────────────────────────────────

def test_clamav_rc0_temiz(kosu):
    kosu((0, "/kasa/ornek.hcl: OK", ""))
    sonuc = clam().scan(YOL, SHA)
    assert sonuc is not None
    assert (sonuc.verdict, sonuc.mock, sonuc.engine) == ("clean", False, "clamav")
    assert sonuc.sha256 == SHA


def test_clamav_rc1_zararli_ve_imza_adi(kosu):
    kosu((1, "/kasa/ornek.hcl: Eicar-Test-Signature FOUND", ""))
    sonuc = clam().scan(YOL, SHA)
    assert sonuc is not None
    assert sonuc.verdict == "malicious"
    assert sonuc.malicious == 1
    assert sonuc.threat == "Eicar-Test-Signature"


def test_clamav_rc2_HATA_demek_zararli_DEGIL(kosu):
    """
    Bu testin tek işi bir kopyala-yapıştır hatasını yakalamak.

    Defender'da rc=2 "tehdit bulundu" anlamına geliyor ve `_scan_via_defender`
    tam olarak öyle yazılmış. Aynı tabloyu ClamAV'a taşımak, imza veritabanı
    bozuk ya da dosya okunamıyor olan HER taramayı "zararlı" diye raporlardı —
    kullanıcıya sahte bulaşma uyarısı.
    """
    kosu((2, "", "ERROR: Can't open file or directory"))
    assert clam().scan(YOL, SHA) is None


def test_defender_rc2_zararli(tmp_path, kosu, monkeypatch):
    """Aynı kodun Defender'daki TERS anlamı — ikisi yan yana sabitleniyor."""
    monkeypatch.setattr(sb.sys, "platform", "win32")
    kosu((2, "Threat detected", ""))
    sonuc = defender(tmp_path).scan(YOL, SHA)
    assert sonuc is not None
    assert sonuc.verdict == "malicious"
    assert sonuc.engine == "windows_defender"


def test_defender_rc1_bilinmiyor(tmp_path, kosu, monkeypatch):
    """ClamAV'ın "tehdit" kodu Defender'da bir şey ifade etmemeli."""
    monkeypatch.setattr(sb.sys, "platform", "win32")
    kosu((1, "", "something"))
    assert defender(tmp_path).scan(YOL, SHA) is None


def test_clamav_bilinmeyen_rc_None(kosu):
    kosu((57, "", ""))
    assert clam().scan(YOL, SHA) is None


# ── ClamAV: argüman kurulumu ──────────────────────────────────────────────────

def test_clamdscan_fdpass_aliyor(kosu):
    """
    `clamd` ayrı bir kullanıcı olarak çalışıyor ve kasa dizinini okuyamıyor;
    --fdpass olmadan her tarama "Access denied" ile hataya düşer.
    """
    sahte = kosu((0, "", ""))
    clam("/usr/bin/clamdscan").scan(YOL, SHA)
    assert "--fdpass" in sahte.cagrilar[0]


def test_clamscan_fdpass_ALMIYOR(kosu):
    """`clamscan` bu bayrağı tanımıyor — eklenirse tarama hemen hataya düşer."""
    sahte = kosu((0, "", ""))
    clam("/usr/bin/clamscan").scan(YOL, SHA)
    assert "--fdpass" not in sahte.cagrilar[0]


def test_arac_tam_yolla_cagriliyor(kosu):
    """bandit B607 depo genelinde açık: argv[0] mutlak yol olmalı."""
    sahte = kosu((0, "", ""))
    clam("/usr/local/bin/clamscan").scan(YOL, SHA)
    assert sahte.cagrilar[0][0] == "/usr/local/bin/clamscan"


def test_dosya_yolu_argvnin_sonunda_ve_ayri_bir_oge(kosu):
    """Shell yok, boşluklu/garip adlar tek argüman olarak geçmeli."""
    sahte = kosu((0, "", ""))
    tuhaf = Path("/kasa/boşluk ve 'tırnak'.hcl")
    clam().scan(tuhaf, SHA)
    assert sahte.cagrilar[0][-1] == str(tuhaf)


# ── ClamAV: daemon kapalıyken düşüş ───────────────────────────────────────────

def test_daemon_kapaliysa_clamscane_dusuluyor(kosu):
    """
    Kurulu ama başlatılmamış clamav-daemon olağan bir durum
    (`apt install clamav-daemon` sonrası servis çalışmıyor olabilir).
    O hâlde tarama tamamen düşmemeli, yavaş yola geçmeli.
    """
    sahte = kosu(
        (2, "", "ERROR: Could not connect to clamd on /var/run/clamav/clamd.ctl"),
        (1, "/kasa/ornek.hcl: Win.Test.EICAR_HDB-1 FOUND", ""),
    )
    sonuc = clam("/usr/bin/clamdscan", "/usr/bin/clamscan").scan(YOL, SHA)
    assert sonuc is not None
    assert sonuc.verdict == "malicious"
    assert sonuc.threat == "Win.Test.EICAR_HDB-1"
    assert len(sahte.cagrilar) == 2
    assert sahte.cagrilar[1][0].endswith("clamscan")


def test_gercek_tarama_hatasi_ikinci_araci_DENEMIYOR(kosu):
    """
    Düşüş yalnızca "daemon'a ulaşamadım"a özgü. Her rc=2'de ikinci aracı
    denemek, okunamayan bir dosyayı iki kez taramak demekti — ve `clamscan`
    soğuk başlangıcı saniyeler sürüyor.
    """
    sahte = kosu((2, "", "ERROR: Can't access file /kasa/ornek.hcl"))
    assert clam("/usr/bin/clamdscan", "/usr/bin/clamscan").scan(YOL, SHA) is None
    assert len(sahte.cagrilar) == 1


def test_ikinci_arac_yoksa_dusus_denenmiyor(kosu):
    sahte = kosu((2, "", "ERROR: Could not connect to clamd"))
    assert clam("/usr/bin/clamdscan").scan(YOL, SHA) is None
    assert len(sahte.cagrilar) == 1


# ── Hata yolları ──────────────────────────────────────────────────────────────

def test_zaman_asimi_None_dondurur_yukselmez(kosu):
    kosu(subprocess.TimeoutExpired(cmd="clamscan", timeout=120))
    assert clam().scan(YOL, SHA) is None


def test_beklenmeyen_istisna_None_dondurur(kosu):
    """Tarayıcının çökmesi dosya yükleme akışını düşürmemeli."""
    kosu(OSError("çalıştırılabilir bozuk"))
    assert clam().scan(YOL, SHA) is None


def test_arac_yoksa_scan_hic_calistirmiyor(kosu):
    sahte = kosu((0, "", ""))
    assert ClamAVBackend(araclar=[]).scan(YOL, SHA) is None
    assert sahte.cagrilar == []


# ── İmza adı ayrıştırma ───────────────────────────────────────────────────────

def test_imza_adi_iki_nokta_iceren_yolda_dogru_ayriliyor():
    """Bilinen yol öneki kesilerek ayrılıyor — yoldaki ':' önemsiz."""
    yol = "/kasa/a:b.hcl"
    assert parse_threat(f"{yol}: Eicar-Test-Signature FOUND", yol) == "Eicar-Test-Signature"


def test_yol_eslesmedidiginde_SONDAKI_ayiricidan_boluniyor():
    """
    Yedek yol: ClamAV bildirdiği yolu bizim verdiğimizden farklı
    normalize edebiliyor (ör. `clamd` sembolik bağı çözerek raporlar).
    O zaman önek kesilemiyor ve satır ayırıcıdan bölünmek zorunda.

    Bölme SONDAKİ ': ' üzerinden (`rpartition`): dosya adının kendisi
    ': ' içerebilir, imza adı içeremez. Baştan bölmek burada
    'final.hcl: Eicar-Test-Signature' verirdi.

    Not: `partition`/`rpartition` farkı YALNIZCA bu dalda görünür —
    önek eşleştiğinde iki uygulama da doğru cevabı veriyor. Bu testin
    var olma sebebi tam olarak o.
    """
    cikti = "/gercek/rapor: final.hcl: Eicar-Test-Signature FOUND"
    assert parse_threat(cikti, "/baglanti/rapor: final.hcl") == "Eicar-Test-Signature"


def test_imza_adi_bosluk_iceriyorsa_korunuyor():
    yol = "/kasa/x.hcl"
    assert parse_threat(f"{yol}: Foo Bar Variant FOUND", yol) == "Foo Bar Variant"


def test_temiz_ciktida_imza_yok():
    assert parse_threat("/kasa/x.hcl: OK", "/kasa/x.hcl") is None


def test_ozet_satirlari_arasindan_bulgu_satiri_seciliyor():
    cikti = (
        "----------- SCAN SUMMARY -----------\n"
        "/kasa/x.hcl: Eicar-Test-Signature FOUND\n"
        "Infected files: 1\n"
    )
    assert parse_threat(cikti, "/kasa/x.hcl") == "Eicar-Test-Signature"


# ── Platform kapıları ve seçim ────────────────────────────────────────────────

def test_defender_linuxta_kullanilamaz(tmp_path, monkeypatch):
    """Yol var gibi görünse bile: MpCmdRun.exe Linux'ta çalıştırılamaz."""
    monkeypatch.setattr(sb.sys, "platform", "linux")
    assert defender(tmp_path).available() is False


def test_defender_windowsta_dosya_yoksa_kullanilamaz(tmp_path, monkeypatch):
    monkeypatch.setattr(sb.sys, "platform", "win32")
    assert DefenderBackend(tmp_path / "yok.exe").available() is False


def test_clamav_windowsta_kullanilamaz(monkeypatch):
    monkeypatch.setattr(sb.sys, "platform", "win32")
    assert clam().available() is False


def test_clamav_linuxta_arac_varsa_kullanilabilir(monkeypatch):
    monkeypatch.setattr(sb.sys, "platform", "linux")
    assert clam().available() is True


def test_clamav_araclari_PATHten_tam_yolla_cozuluyor(monkeypatch):
    monkeypatch.setattr(sb.shutil, "which",
                        lambda ad: f"/usr/bin/{ad}" if ad == "clamscan" else None)
    assert ClamAVBackend().tools() == ["/usr/bin/clamscan"]


def test_clamdscan_clamscanden_once_deneniyor(monkeypatch):
    """Daemon istemcisi hızlı olan; sıralama tercih sırası."""
    monkeypatch.setattr(sb.shutil, "which", lambda ad: f"/usr/bin/{ad}")
    assert ClamAVBackend().tools() == ["/usr/bin/clamdscan", "/usr/bin/clamscan"]


def test_linuxta_clamav_secilir(monkeypatch):
    monkeypatch.setattr(sb.sys, "platform", "linux")
    monkeypatch.setattr(sb.shutil, "which", lambda ad: f"/usr/bin/{ad}")
    assert select_backend().ad == "clamav"


def test_windowsta_defender_secilir(tmp_path, monkeypatch):
    exe = tmp_path / "MpCmdRun.exe"
    exe.write_bytes(b"")
    monkeypatch.setattr(sb.sys, "platform", "win32")
    monkeypatch.setattr(sb, "MPCMDRUN", exe)
    assert select_backend().ad == "windows_defender"


def test_hicbir_motor_yokken_platformun_motoru_adlandiriliyor(monkeypatch):
    """
    Motor kurulu değilken de bir arka uç dönüyor: sonuç mock olacak ama
    denetim kaydı platformun OLMASI GEREKEN motorunu adlandırsın. Windows'ta
    bu, değişiklik öncesiyle bire bir aynı davranış (`windows_defender`).
    """
    monkeypatch.setattr(sb.shutil, "which", lambda ad: None)

    monkeypatch.setattr(sb.sys, "platform", "linux")
    sb.reset_backend_cache()
    assert select_backend().ad == "clamav"

    monkeypatch.setattr(sb.sys, "platform", "win32")
    monkeypatch.setattr(sb.DefenderBackend, "available", lambda self: False)
    sb.reset_backend_cache()
    assert select_backend().ad == "windows_defender"


# ── Gerçek ClamAV — kuruluysa ─────────────────────────────────────────────────
#
# Yukarıdaki testlerin hepsi `run_tool`'u sahteliyor, yani ölçtükleri şey
# BİZİM VARSAYIMIMIZ: "clamscan temizde 0, bulguda 1 döner", "bulgu satırı
# `<yol>: <imza> FOUND` biçimindedir". Varsayım yanlışsa test de onunla
# birlikte yanlış olur ve sessizce yeşil kalır.
#
# Aşağıdaki iki test o boşluğu kapatıyor: ClamAV KURULUYSA gerçek aracı
# çağırıyorlar. Kurulu değilse atlanıyorlar — yani bugün Windows'ta ve
# ClamAV'sız CI'da skip, ilk gerçek Linux kurulumunda kendiliğinden ölçüm.
# BACKLOG.md / B-023 bu maddeyi kapatma zamanını bu testler haber verecek.
#
# EICAR imzası parçalı yazılıyor: bu dosyanın kendisi bir depo taramasında
# "zararlı" diye işaretlenmesin diye. Test dışında hiçbir yerde birleşmiyor.

_EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-"
    "ANTIVIRUS-TEST-FILE!$H+H*"
)

_gercek_clamscan = shutil.which("clamscan")
_clamav_yok = pytest.mark.skipif(
    _gercek_clamscan is None,
    reason="clamscan kurulu değil — B-023 ölçümü burada yapılamaz",
)


@_clamav_yok
def test_GERCEK_clamscan_temiz_dosyada_rc0(tmp_path):
    hedef = tmp_path / "temiz.hcl"
    hedef.write_bytes(b"zararsiz icerik\n")
    sonuc = ClamAVBackend([_gercek_clamscan]).scan(hedef, SHA)
    assert sonuc is not None, "clamscan çalıştı ama sonuç None — eşleme yanlış"
    assert sonuc.verdict == "clean"


@_clamav_yok
def test_GERCEK_clamscan_EICARda_zararli_ve_imza_adi_okunuyor(tmp_path):
    """Çıkış kodu eşlemesini VE `parse_threat`'i aynı anda ölçer."""
    hedef = tmp_path / "eicar.hcl"
    hedef.write_text(_EICAR, encoding="ascii")
    sonuc = ClamAVBackend([_gercek_clamscan]).scan(hedef, SHA)
    assert sonuc is not None
    assert sonuc.verdict == "malicious"
    assert sonuc.threat, "bulgu satırı ayrıştırılamadı — çıktı biçimi değişmiş olabilir"
    assert "EICAR" in sonuc.threat.upper()


def test_secim_onbellekleniyor(monkeypatch):
    """Her taramada PATH taramak/stat atmak gereksiz."""
    sayac = {"n": 0}

    def sayan(ad):
        sayac["n"] += 1
        return None

    monkeypatch.setattr(sb.shutil, "which", sayan)
    monkeypatch.setattr(sb.sys, "platform", "linux")
    ilk = select_backend()
    once = sayac["n"]
    assert select_backend() is ilk
    assert sayac["n"] == once
