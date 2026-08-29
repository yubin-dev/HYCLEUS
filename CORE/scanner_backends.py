"""
HYCLEUS — antivirüs tarama arka uçları.

Neden bu dosya var
------------------
`CORE/scanner.py` tek bir motora — Windows Defender'ın `MpCmdRun.exe`'sine —
sabitlenmişti. Linux'ta o yol hiç var olmadığı için her tarama sessizce
"mock" sonuç döndürüyordu: dosya yüklenir, tabloda tarama sütunu boş kalır,
kimse bir şeyin taranmadığını fark etmez.

Bu modül tarama motorunu yerinden söküyor. `scanner.py` artık hangi motorun
çalıştığını bilmiyor; yalnızca `select_backend()` ile platformun uygun
arka ucunu alıp `scan()` çağırıyor. Veritabanı yazma ve denetim kaydı
`scanner.py`'de kalıyor — arka uçlar veritabanını hiç görmüyor.

Motorlar arasındaki en tehlikeli fark ÇIKIŞ KODLARI
---------------------------------------------------
    MpCmdRun.exe   0 = temiz    2 = TEHDİT BULUNDU    diğer = hata
    clamscan       0 = temiz    1 = TEHDİT BULUNDU    2 = HATA

İkisinde de `2` var ve ANLAMLARI TERS. Defender'ın tablosunu ClamAV'a
uygulamak her tarama hatasını "zararlı" diye raporlardı; tersi ise gerçek
bir bulaşmayı "hata" sayıp mock'a düşerdi. Bu yüzden eşleme her arka ucun
kendi `scan()`'inde, yan yana yorumla duruyor.

Kapsam
------
ClamAV arka ucu Linux için yazıldı ve orada test edildi. Windows dışındaki
her platformda etkin — macOS'ta `clamscan` kuruluysa çalışır, çünkü komut
satırı arayüzü aynı; ama macOS'ta ÖLÇÜLMEDİ. Bugünkü davranış (her zaman
mock) zaten bundan kötü olduğu için kapıyı kapatmanın anlamı yok.
"""
from __future__ import annotations

import hashlib
import logging
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

_log = logging.getLogger("hycleus.scanner")

#: Windows Defender komut satırı istemcisi. Konumu sabittir (sistem bileşeni).
MPCMDRUN = Path(r"C:\Program Files\Windows Defender\MpCmdRun.exe")

#: Tarama zaman aşımı. ClamAV'ın `clamscan`'i ilk çağrıda ~200 MB imza
#: veritabanını belleğe alıyor; soğuk başlangıç birkaç saniye sürebiliyor.
#: CI'daki `timeout-minutes` ilkesiyle aynı ölçek mantığı: tipik bir taramanın
#: birkaç katı, ama sınırsız değil — bkz. .github/workflows/ci.yml'nin kendi
#: gerekçesi ("sessiz bir bekleme, açık bir başarısızlıktan her zaman kötüdür").
SCAN_TIMEOUT = 120

#: `run_tool()`'un zaman aşımından SONRA süreci `kill()` edip son çıkış
#: durumunu beklerken tanıdığı tavan — bkz. `run_tool()` docstring'i.
KILL_GRACE = 5

#: ClamAV araçları, TERCİH SIRASIYLA. `clamdscan` çalışan bir daemon'a
#: konuşur (imza veritabanı zaten yüklü, tarama milisaniyeler); `clamscan`
#: her çağrıda imzaları baştan okur ama hiçbir servise ihtiyaç duymaz.
CLAM_ARACLARI: tuple[str, ...] = ("clamdscan", "clamscan")

#: `clamdscan`'in "daemon'a ulaşamadım" hatasını tanıyan işaretler.
#: Yanlış eşleşmenin bedeli yalnızca gereksiz bir `clamscan` denemesi —
#: yani hata yönü GÜVENLİ tarafa bakıyor, bu yüzden gevşek tutuldu.
_CLAMD_ULASILAMIYOR = ("could not connect", "can't connect", "cant connect")

_CHUNK = 65536


# ── Sonuç ─────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Tek bir taramanın sonucu.

    `engine` ve `threat` alanları ClamAV ile birlikte eklendi ve VARSAYILANLI:
    eski çağrı yerleri (hepsi anahtar kelimeli) değişmeden derlenir.

    `engine` denetim kaydına ve karantina JSON'una yazılır. Onsuz bir ClamAV
    bulgusu veritabanına `"source": "windows_defender"` diye düşerdi — sessiz
    bir yalan, ve sonradan "bunu hangi motor buldu" sorusu cevapsız kalırdı.
    """
    sha256:        str
    malicious:     int
    suspicious:    int
    harmless:      int
    undetected:    int
    engines_total: int
    verdict:       str            # "clean" | "suspicious" | "malicious" | "unknown" | "timeout"
    mock:          bool
    engine:        str = "mock"
    threat:        str | None = None   # imza adı — yalnızca ClamAV doldurur


def mock_result(sha256: str, engine: str = "mock") -> ScanResult:
    """Tarama YAPILAMADI. `verdict="unknown"` — "temiz" ile karıştırılmamalı."""
    return ScanResult(
        sha256=sha256, malicious=0, suspicious=0,
        harmless=0, undetected=0, engines_total=0,
        verdict="unknown", mock=True, engine=engine,
    )


def clean_result(sha256: str, engine: str) -> ScanResult:
    return ScanResult(
        sha256=sha256, malicious=0, suspicious=0,
        harmless=1, undetected=0, engines_total=1,
        verdict="clean", mock=False, engine=engine,
    )


def malicious_result(sha256: str, engine: str, threat: str | None = None) -> ScanResult:
    return ScanResult(
        sha256=sha256, malicious=1, suspicious=0,
        harmless=0, undetected=0, engines_total=1,
        verdict="malicious", mock=False, engine=engine, threat=threat,
    )


def timeout_result(sha256: str, engine: str) -> ScanResult:
    """
    Tarama SÜRESİ DOLDU — `mock_result()`'tan bilerek AYRI.

    `mock`, motorun HİÇ ÇALIŞMADIĞI (kurulu değil, bulunamadı) anlamına
    gelir; zaman aşımı motorun ÇALIŞTIĞI ama bitiremediği anlamına gelir —
    ikisi UI'da ve denetim kaydında AYNI görünürse (`unknown`/mock), "bu
    dosya hiç taranmadı, muhtemelen zararsız" ile "bu dosya taranmaya
    çalışıldı ve karar VERİLEMEDİ, elle incelenmeli" birbirine karışır.
    `mock=False`: gerçek bir deneme yapıldı, sonuç eksik değil BELİRSİZ.
    """
    return ScanResult(
        sha256=sha256, malicious=0, suspicious=0,
        harmless=0, undetected=0, engines_total=0,
        verdict="timeout", mock=False, engine=engine,
    )


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Alt süreç dikişi ──────────────────────────────────────────────────────────

def run_tool(argv: list[str], timeout: int = SCAN_TIMEOUT) -> subprocess.CompletedProcess[str]:
    """Tarayıcıyı çalıştırır — worker havuzunu KESİN bir tavanla korur.

    Testlerin monkeypatch'lediği TEK nokta burası: böylece çıkış kodu eşlemesi
    ve argüman kurulumu, makinede Defender/ClamAV kurulu olmadan da ölçülebilir.

    `errors="replace"`: ClamAV çıktısı imza adlarında ASCII dışı bayt
    taşıyabiliyor; bir kod çözme hatası taramayı düşürmemeli.

    NEDEN `subprocess.run(..., timeout=...)` DEĞİL — büyük arşiv dosyaları
    -----------------------------------------------------------------------
    `subprocess.run()`'ın kendi zaman aşımı görünüşte yeterliydi ama
    CPython'un Windows dalında bir tuzak var: `communicate(timeout=...)`
    zaman aşımına uğrayınca `kill()` çağrılıyor, ama HEMEN ARDINDAN
    SINIRSIZ (timeout'suz) İKİNCİ bir `communicate()` daha yapılıyor
    (çıktıyı toplamak için). `MpCmdRun.exe` büyük bir arşivi taranırken bir
    alt/yardımcı süreç doğurup stdout/stderr pipe tanıtıcısını ona
    devredebilir — `kill()` yalnızca MpCmdRun.exe'nin kendisini öldürür,
    torun süreç pipe'ı elinde tutmaya devam eder, pipe hiç kapanmaz ve o
    ikinci `communicate()` SONSUZA KADAR bekler. Sonuç: `timeout=120`
    parametresi VARDI ama küçük/orta dosyalarda işe yarayıp büyük arşivlerde
    worker thread'ini (dolayısıyla `QThreadPool`'daki bir işçi yuvasını)
    kilitli bırakabiliyordu — CI'nin "sessiz bir bekleme, açık bir
    başarısızlıktan her zaman kötüdür" dersinin aynısı, bu kez bir GitHub
    Actions işi değil bir Qt worker thread'i için.

    Çözüm: `Popen` ile elle kurulum, zaman aşımında `kill()` sonrası ikinci
    bir `communicate()` YOK — yalnızca sürecin kendi çıkış durumunu kısa,
    sabit bir tavanla (`KILL_GRACE`) bekliyoruz. `wait()` pipe'ların
    kapanmasına değil sürecin kendi sonlanmasına bakıyor, bu yüzden pipe'ı
    açık tutan bir torun süreç onu ETKİLEMİYOR — `kill()` MpCmdRun.exe'yi
    öldürdüğü anda `wait()` hemen dönüyor. Çıktı okunmuyor (zaten zaman
    aşımı sonucu için gerekmiyor), ama işçi thread'i GARANTİLİ olarak
    `timeout + KILL_GRACE` saniye içinde serbest kalıyor.
    """
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=KILL_GRACE)
        except subprocess.TimeoutExpired:
            # KILL_GRACE içinde bile dönmedi — yine de burada beklemeyi
            # bırakıyoruz; worker'ı kilitli tutmaktansa bir zombi/artakalan
            # süreç bırakmak tercih edilen taraf (bkz. docstring).
            pass
        raise
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)


# ── Arka uç arayüzü ───────────────────────────────────────────────────────────

@runtime_checkable
class ScannerBackend(Protocol):
    """Bir antivirüs motorunun HYCLEUS'a görünen yüzü."""

    #: Karantina JSON'undaki `source` alanı.
    ad: str
    #: Denetim zincirine yazılan eylem adı.
    audit_action: str

    def available(self) -> bool:
        """Motor bu makinede gerçekten çalıştırılabilir mi."""
        ...

    def scan(self, path: Path, sha256: str) -> ScanResult | None:
        """Dosyayı tarar. `None` = tarama yapılamadı; çağıran mock'a düşer."""
        ...


# ── Windows Defender ──────────────────────────────────────────────────────────

class DefenderBackend:
    """`MpCmdRun.exe -Scan -ScanType 3 -File <yol>`.

    Davranışı taşımadan önceki `scanner._scan_via_defender` ile bire bir aynı;
    tek fark, varlık denetiminin modül yükleme anından `available()`'a taşınmış
    olması. Import anında yapılan denetim Linux'ta her açılışta yanıltıcı bir
    "defender_not_found" uyarısı basıyordu.
    """

    ad = "windows_defender"
    audit_action = "defender_scan"

    def __init__(self, yol: Path | None = None) -> None:
        # Varsayılan argüman olarak `MPCMDRUN` yazılsaydı değer SINIF TANIM
        # ANINDA bağlanır ve testte modül sabitini değiştirmek işe yaramazdı.
        self._yol = yol if yol is not None else MPCMDRUN

    def available(self) -> bool:
        if sys.platform != "win32":
            return False
        return self._yol.exists()

    def scan(self, path: Path, sha256: str) -> ScanResult | None:
        if not self.available():
            return None
        argv = [str(self._yol), "-Scan", "-ScanType", "3", "-File", str(path)]
        try:
            proc = run_tool(argv)
        except subprocess.TimeoutExpired:
            _log.warning("defender_timeout  file=%s  timeout=%ds", path.name, SCAN_TIMEOUT)
            return timeout_result(sha256, self.ad)
        except Exception as exc:  # noqa: BLE001 — tarayıcı yükleme akışını düşürmemeli
            _log.warning("defender_error  %s", exc)
            return None

        _log.info("defender_scan  rc=%d  file=%s  out=%s",
                  proc.returncode, path.name, (proc.stdout or "").strip()[:200])

        # DİKKAT: burada 2 = TEHDİT. ClamAV'da 2 = HATA. Bkz. modül docstring'i.
        if proc.returncode == 0:
            return clean_result(sha256, self.ad)
        if proc.returncode == 2:
            _log.warning("defender_threat  file=%s  out=%s",
                         path.name, (proc.stdout or "").strip()[:200])
            return malicious_result(sha256, self.ad)
        _log.warning("defender_rc_unknown  rc=%d  file=%s  stderr=%s",
                     proc.returncode, path.name, (proc.stderr or "").strip()[:200])
        return None


# ── ClamAV ────────────────────────────────────────────────────────────────────

def parse_threat(stdout: str, path: str) -> str | None:
    """ClamAV çıktısından imza adını çıkarır.

    Bulgu satırının biçimi: ``<yol>: <imza> FOUND``

    Ayırma SONDAKİ ``": "`` üzerinden (`rpartition`) yapılıyor, baştaki
    üzerinden değil: Linux dosya adları iki nokta içerebiliyor ve
    ``/kasa/a:b.hcl: Eicar-Test-Signature FOUND`` satırını baştan bölmek
    imza adı yerine ``b.hcl`` verirdi. İmza adlarında ``": "`` geçmez.
    """
    onek = f"{path}: "
    for ham in stdout.splitlines():
        satir = ham.strip()
        if not satir.endswith(" FOUND"):
            continue
        govde = satir[: -len(" FOUND")]
        if govde.startswith(onek):
            return govde[len(onek):].strip() or None
        _, ayirac, kalan = govde.rpartition(": ")
        return (kalan if ayirac else govde).strip() or None
    return None


class ClamAVBackend:
    """`clamdscan`/`clamscan` ile tarama — Linux tarafının Defender karşılığı.

    Araç seçimi
    -----------
    Önce `clamdscan` denenir (daemon imzaları bellekte tutuyor, tarama çok
    daha hızlı). Daemon çalışmıyorsa — kurulu ama `systemctl start
    clamav-daemon` yapılmamış bir makinede olağan durum — `clamscan`'e
    düşülür. Bu düşüş SESSİZ DEĞİL, `clamd_unreachable` olarak loglanır.

    `--fdpass` neden var
    --------------------
    `clamd` genelde ayrı bir `clamav` kullanıcısı olarak çalışır ve HYCLEUS'un
    kasa dizinini okuma izni yoktur. `--fdpass` dosyayı adıyla vermek yerine
    AÇIK DOSYA TANITICISINI daemon'a geçirir; izin denetimi HYCLEUS'un kendi
    kimliğiyle yapılır. Onsuz her tarama "Access denied" ile hataya düşerdi.
    `clamscan` aynı süreçte çalıştığı için bu bayrağa ihtiyaç duymaz — ve
    o bayrağı tanımaz, bu yüzden yalnızca daemon istemcisine ekleniyor.
    """

    ad = "clamav"
    audit_action = "clamav_scan"

    def __init__(self, araclar: Sequence[str] | None = None) -> None:
        #: `None` → PATH'ten çözülür. Test için doğrudan verilebilir.
        self._sabit_araclar = list(araclar) if araclar is not None else None

    def tools(self) -> list[str]:
        """Kurulu ClamAV araçlarının TAM yolları, tercih sırasıyla.

        `shutil.which` mutlak yol döndürür — bandit B607 (kısmi çalıştırılabilir
        yolu) bu yüzden gerçekten karşılanıyor, susturularak değil. Tam yolu
        sabit yazmak yanlış olurdu: konum dağıtıma göre değişiyor
        (/usr/bin, /usr/local/bin, /opt/homebrew/bin).
        """
        if self._sabit_araclar is not None:
            return list(self._sabit_araclar)
        return [yol for arac_adi in CLAM_ARACLARI if (yol := shutil.which(arac_adi))]

    def available(self) -> bool:
        if sys.platform == "win32":
            return False
        return bool(self.tools())

    @staticmethod
    def argv_for(arac: str, path: Path) -> list[str]:
        argv = [arac, "--no-summary"]
        if "clamdscan" in Path(arac).name:
            argv.append("--fdpass")
        argv.append(str(path))
        return argv

    def scan(self, path: Path, sha256: str) -> ScanResult | None:
        araclar = self.tools()
        if not araclar:
            return None
        for sira, arac in enumerate(araclar):
            sonuc, daemon_yok = self._tek_arac(arac, path, sha256)
            if sonuc is not None:
                return sonuc
            if daemon_yok and sira + 1 < len(araclar):
                _log.warning("clamd_unreachable  arac=%s — bir sonraki araca düşülüyor", arac)
                continue
            return None
        return None

    def _tek_arac(self, arac: str, path: Path, sha256: str) -> tuple[ScanResult | None, bool]:
        """Tek bir ClamAV aracını çalıştırır.

        Dönüş: (sonuç ya da None, "daemon'a ulaşılamadı mı").
        İkinci alan yalnızca bir sonraki araca düşülüp düşülmeyeceğini belirler.
        """
        argv = self.argv_for(arac, path)
        try:
            proc = run_tool(argv)
        except subprocess.TimeoutExpired:
            _log.warning("clamav_timeout  arac=%s  file=%s  timeout=%ds",
                         Path(arac).name, path.name, SCAN_TIMEOUT)
            return timeout_result(sha256, self.ad), False
        except Exception as exc:  # noqa: BLE001 — tarayıcı yükleme akışını düşürmemeli
            _log.warning("clamav_error  arac=%s  %s", Path(arac).name, exc)
            return None, False

        cikti = (proc.stdout or "").strip()
        hata  = (proc.stderr or "").strip()
        _log.info("clamav_scan  arac=%s  rc=%d  file=%s  out=%s",
                  Path(arac).name, proc.returncode, path.name, cikti[:200])

        # DİKKAT: burada 1 = TEHDİT, 2 = HATA. Defender'da 2 = TEHDİT idi.
        if proc.returncode == 0:
            return clean_result(sha256, self.ad), False
        if proc.returncode == 1:
            tehdit = parse_threat(cikti, str(path))
            _log.warning("clamav_threat  file=%s  threat=%s", path.name, tehdit)
            return malicious_result(sha256, self.ad, tehdit), False

        birlesik = f"{cikti}\n{hata}".lower()
        daemon_yok = proc.returncode == 2 and any(m in birlesik for m in _CLAMD_ULASILAMIYOR)
        if not daemon_yok:
            _log.warning("clamav_rc_unknown  arac=%s  rc=%d  file=%s  stderr=%s",
                         Path(arac).name, proc.returncode, path.name, hata[:200])
        return None, daemon_yok


# ── Seçim ─────────────────────────────────────────────────────────────────────

#: Deneme sırası. Her arka uç kendi platform kapısını `available()` içinde
#: tuttuğu için burada ayrıca platform dallanması YOK.
BACKEND_SINIFLARI: tuple[type[ScannerBackend], ...] = (DefenderBackend, ClamAVBackend)

_secili: ScannerBackend | None = None


def _platform_varsayilani() -> ScannerBackend:
    """Hiçbir motor kurulu değilken bile bir arka uç döndürülür.

    Sonuç mock olacak, ama denetim kaydı ve karantina JSON'u platformun
    OLMASI GEREKEN motorunu adlandırır. Windows'ta Defender kurulu değilken
    kaydın `windows_defender` kalması, bu değişiklikten önceki davranışın
    aynısı — Windows tarafında hiçbir alan değişmiyor.
    """
    return DefenderBackend() if sys.platform == "win32" else ClamAVBackend()


def select_backend() -> ScannerBackend:
    """Bu makinede kullanılacak arka ucu döndürür (süreç ömrü boyunca önbellekli)."""
    global _secili
    if _secili is None:
        _secili = _sec()
        _log.info("scanner_backend  engine=%s  available=%s  platform=%s",
                  _secili.ad, _secili.available(), sys.platform)
    return _secili


def _sec() -> ScannerBackend:
    for sinif in BACKEND_SINIFLARI:
        aday = sinif()
        if aday.available():
            return aday
    return _platform_varsayilani()


def reset_backend_cache() -> None:
    """Önbelleği boşaltır. Testler için; üretimde çağıran yok."""
    global _secili
    _secili = None
