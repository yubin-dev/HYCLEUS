"""
HYCLEUS — Linux'a özgü platform davranışları (10 senaryo).

Bu dosya, AV motoru seçiminin platforma göre değiştiğini (Windows →
Defender, diğerleri → ClamAV, bkz. `CORE/scanner_backends.py`) kök neden
alarak açılan bir tur: "platforma göre davranış değişiyorsa, o davranış
HER platformda ayrıca test edilmeli" ilkesiyle, daha önce yalnızca
Windows tarafında dolaylı/mock testlerle örtülen ya da hiç test
edilmeyen Linux'a özgü yolları hedefliyor.

Platform bağımlı testler `@pytest.mark.skipif(platform.system() !=
"Linux", ...)` ile işaretli — CI'ın Windows ayağında sessizce atlanırlar,
Linux ayağında (ya da bu makinede) gerçekten çalışırlar. Bazı testler
ayrıca gerçek bir araç/donanımın (ClamAV, fiziksel bir USB aygıtı)
VARLIĞINA bağlı — o testler ayrı bir ikinci skipif ile korunuyor, aracın
yokluğu KIRMIZI bir test değil, açıkça gerekçeli bir "skip" üretir (bkz.
`tests/test_scanner_backends.py`'nin aynı deseni, `_clamav_yok`).

DÜRÜST NOT — iki backlog atfı üzerine
--------------------------------------------------------------------
Bu dosyayı isteyen turda, dosya kilitleme testi "B-107" ve klasör/dosya
izin mirası testi "B-123" ile eşleştirilmek istendi. Bu depodaki gerçek
BACKLOG.md kayıtları o numaraları FARKLI konulara veriyor:

  · B-107 = Kurumsal Referans Kodu girişine hız sınırı (rate limit),
    dosya kilitlemeyle hiçbir ilgisi yok.
  · B-123 = Klasör hiyerarşisi UI'da yalnızca kök seviyeyi gösteriyordu
    (kozmetik/UI bulgusu) — `CORE/folders.py` hiçbir dosya sistemi
    izni/miras mantığı TAŞIMIYOR: klasörler yalnızca DB satırları
    (`folder_id`), gerçek dosyalar hep aynı `safezone`/`vault`
    dizininde duruyor.

Yanlış bir eşleşmeyi doğrulamak yerine burada GERÇEK koda bakıldı:
dosya kilitleme `CORE/checkout.py` (`_pid_alive`, `acquire_lock`,
`release_stale_locks`, `file_locks` tablosu) içinde; dosya sistemi izin
mantığının TEK gerçek karşılığı `CORE/safezone.py::safezone_dir()`'ın
`0o700` dizin izni (SafeZone). Testler bu gerçek hedeflere yazıldı,
docstring'lerinde bu düzeltme açıkça not edildi — bkz. B-112/B-114
turunun "önce bağımsız doğrula, sonra düzelt" ilkesiyle tutarlı.
"""
from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from CORE import scanner_backends as sb
from CORE import tpm_sealing
from CORE.checkout import acquire_lock, release_stale_locks
from CORE.scanner import scan_file
from CORE.safezone import _DIR_MODE, safezone_dir

_LINUX = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Linux'a özgü davranış — diğer platformlarda anlamsız/farklı",
)

# EICAR imzası parçalı yazılıyor — bkz. tests/test_scanner_backends.py'nin
# aynı gerekçesi: bu dosyanın kendisi bir depo taramasında "zararlı" diye
# işaretlenmesin diye. Test dışında hiçbir yerde birleşmiyor.
_EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-"
    "ANTIVIRUS-TEST-FILE!$H+H*"
)

_gercek_clamscan = shutil.which("clamscan") or shutil.which("clamdscan")
_clamav_yok = pytest.mark.skipif(
    _gercek_clamscan is None,
    reason="ClamAV (clamscan/clamdscan) bu makinede kurulu değil",
)


def _gercek_usb_var_mi() -> bool:
    """`/sys/block` altında `usb` aktarımlı en az bir blok aygıt var mı."""
    kok = Path("/sys/block")
    if not kok.is_dir():
        return False
    for aygit in kok.iterdir():
        try:
            if "usb" in os.path.realpath(str(aygit)):
                return True
        except OSError:
            continue
    return False


_gercek_usb_yok = pytest.mark.skipif(
    not _gercek_usb_var_mi(),
    reason="bu makineye takılı gerçek bir USB blok aygıtı bulunamadı",
)


@pytest.fixture(autouse=True)
def _onbellek_temiz():
    sb.reset_backend_cache()
    yield
    sb.reset_backend_cache()


# ── 1) ClamAV kurulu değilken scan_file() "unknown" verdict ─────────────────


@_LINUX
def test_1_clamav_kurulu_degilken_scan_file_unknown_dondurur(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Hiçbir ClamAV aracı PATH'te bulunamazsa `scan_file()` çökmemeli ve
    "temiz" ile KARIŞTIRILAMAYACAK bir sonuç (`verdict="unknown"`,
    `mock=True`) döndürmeli — bkz. `CORE/scanner_backends.py::mock_result()`
    docstring'i: "Tarama YAPILAMADI, temiz DEĞİL".

    `shutil.which` sahtelenerek ClamAV'ın gerçekten kurulu olup olmadığından
    BAĞIMSIZ, deterministik biçimde "hiç araç yok" senaryosu üretiliyor —
    bu makinede ClamAV kurulu olsa bile test aynı şekilde çalışır.
    """
    monkeypatch.setattr(sb.sys, "platform", "linux")
    monkeypatch.setattr(sb.shutil, "which", lambda ad: None)

    hedef = tmp_path / "herhangi_bir_belge.hcl"
    hedef.write_bytes(b"icerik onemli degil\n")

    sonuc = scan_file(hedef)

    assert sonuc.verdict == "unknown"
    assert sonuc.mock is True
    assert sonuc.malicious == 0
    assert sonuc.engine == "clamav"  # platform varsayılanı adlandırılıyor


# ── 2) ClamAV kuruluyken gerçek EICAR dosyası tehdit olarak yakalanıyor ─────


@_LINUX
@_clamav_yok
def test_2_gercek_clamav_eicar_dosyasini_zararli_olarak_yakaliyor(
    tmp_path: Path,
) -> None:
    """
    Uçtan uca: `scan_file()` (yalnızca arka uç değil, `sha256_of` +
    `select_backend` + günlükleme dahil TÜM üst katman) gerçek `clamscan`/
    `clamdscan` ile çağrılınca EICAR test imzasını GERÇEKTEN tehdit olarak
    işaretlemeli. `tests/test_scanner_backends.py`'nin aynı-isimli testi
    yalnızca `ClamAVBackend.scan()`'i doğruluyor; burası bir katman yukarı,
    `CORE/scanner.py::scan_file()` genel arayüzünü ölçüyor.
    """
    hedef = tmp_path / "eicar_test.hcl"
    hedef.write_text(_EICAR, encoding="ascii")

    sonuc = scan_file(hedef)

    assert sonuc.mock is False
    assert sonuc.verdict == "malicious"
    assert sonuc.malicious == 1
    assert sonuc.threat, "imza adı ayrıştırılamadı"
    assert "EICAR" in sonuc.threat.upper()


# ── 3) Linux HWID probe gerçek USB cihazından doğru okuyor ──────────────────


@_LINUX
@_gercek_usb_yok
def test_3_linux_hwid_probe_gercek_usb_aygitindan_okuyor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    B-112/B-114'ün gerçek-donanım doğrulamasını KALICI bir teste çeviriyor:
    bu makineye takılı GERÇEK bir USB aygıtı varken `read_linux()` en az
    bir `UsbIdentity` döndürmeli VE `get_usb_hwid()` (DEV_MODE kapalıyken,
    `wmi` sahte biçimde erişilemez kılınarak Windows dallarının hiç
    devreye girmediği garanti edilerek) bu okumadan TÜREYEN, boş olmayan
    bir hwid vermeli — iki fonksiyonun birbirinden BAĞIMSIZ okuduğu aynı
    donanımın TUTARLI bir kimlik ürettiğini kanıtlıyor.
    """
    from CORE import hwid_probe, usb_manager

    monkeypatch.setattr(usb_manager, "DEV_MODE", False)
    monkeypatch.setitem(sys.modules, "wmi", None)

    aygitlar = hwid_probe.read_linux()
    assert aygitlar, "gerçek USB aygıtı beklendi ama read_linux() boş liste döndü"
    assert any(a.descriptor_serial for a in aygitlar), (
        "hiçbir aygıtta seri numarası yok — hwid_manager buradan hwid üretemez"
    )

    hwid = usb_manager.get_usb_hwid()
    assert hwid, "gerçek USB takılıyken get_usb_hwid() None/boş döndü"

    seriler = {a.descriptor_serial for a in aygitlar if a.descriptor_serial}
    assert any(
        usb_manager._sanitize_hwid(s) == hwid for s in seriler
    ), "get_usb_hwid()'in döndürdüğü değer, read_linux()'un okuduğu SERİLERDEN hiçbiriyle eşleşmiyor"


# ── 4) mkstemp 0600 + private tmp dizini (MC-M075/076/077'nin GERÇEK karşılığı) ──


@_LINUX
def test_4_gecici_tarama_dosyalari_0600_ve_sistem_tmp_dizininde(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    MC-Kataloğu MC-M075/076/077 ("mkstemp yerine open()", "izin 0644",
    "paylaşılan /tmp") `CORE/vault_manager.py`'de "kapsam dışı" işaretlendi
    çünkü o modül HİÇ temp dosyası kullanmıyor. Ama `CORE/scanner_backends.
    py::run_tool()` GERÇEKTEN `tempfile.mkstemp()` kullanıyor (bkz. o
    fonksiyonun docstring'i, "DOSYA İZİNLERİ" bölümü) — burası MC
    kataloğunun o üç mutasyonunun GERÇEK karşılığı.

    `_gecici_dosyayi_kullaniciya_kisitla()`'ya bir casus takılıyor: dosya
    Windows dışında NO-OP olduğu için (bkz. o fonksiyonun docstring'i)
    korumanın TAMAMI mkstemp'in kendi varsayılan izninde — tam da bu
    testin doğruladığı şey.
    """
    yakalanan: list[str] = []
    gercek = sb._gecici_dosyayi_kullaniciya_kisitla

    def casus(yol: str) -> None:
        yakalanan.append(yol)
        gercek(yol)

    monkeypatch.setattr(sb, "_gecici_dosyayi_kullaniciya_kisitla", casus)

    sonuc = sb.run_tool([sys.executable, "-c", "print('merhaba')"])

    assert sonuc.returncode == 0
    assert len(yakalanan) == 2, "hem stdout hem stderr geçici dosyası beklenirdi"
    for yol in yakalanan:
        # Dosya `run_tool()`'un `finally` bloğunda zaten silindiği için izin
        # KONTROLÜ casusun İÇİNDE (dosya hâlâ varken) yapılmalı — burada
        # doğrudan os.stat çağırmak yerine casusun kendisi içinde ölçülüyor.
        assert Path(yol).parent == Path(tempfile.gettempdir()), (
            "geçici tarama dosyası sistemin varsayılan tmp dizini DIŞINDA"
        )


@_LINUX
def test_4b_mkstemp_varsayilan_izni_0600(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    4. testin tamamlayıcısı: izin bitlerinin GERÇEKTEN 0600 olduğunu,
    dosya silinmeden ÖNCE (casus içinde) doğrudan ölçer.
    """
    izinler: list[int] = []
    gercek = sb._gecici_dosyayi_kullaniciya_kisitla

    def casus(yol: str) -> None:
        # Kısıtlama NO-OP olmadan (Windows dışı) ÖNCE ölçülüyor — mkstemp'in
        # KENDİ ürettiği izin bu, kısıtlama fonksiyonunun bir etkisi değil.
        mod = stat.S_IMODE(os.stat(yol).st_mode)
        izinler.append(mod)
        gercek(yol)

    monkeypatch.setattr(sb, "_gecici_dosyayi_kullaniciya_kisitla", casus)
    sb.run_tool([sys.executable, "-c", "pass"])

    assert izinler, "casus hiç çağrılmadı"
    for mod in izinler:
        assert mod == 0o600, f"mkstemp izni 0600 değil: {oct(mod)}"


# ── 5) Linux path ayırıcısıyla B-117 regresyon yapmıyor ─────────────────────


@_LINUX
def test_5_hwid_probe_tek_cagiran_guardi_linuxta_posix_ayiricisiyla_calisir() -> None:
    """
    B-117: `test_okuyucular_yalnizca_usb_manager_uzerinden_uretime_bagli`
    Windows'ta `str(Path)`'in `\\` ayırıcı kullanması yüzünden sabit
    kodlanmış `"CORE/usb_manager.py"` (`/` ayırıcı) ile birebir string
    karşılaştırması KIRILIYORDU; düzeltme `.relative_to(kok).as_posix()`
    oldu. Linux zaten `/` kullandığı için bu regresyon burada asla
    DOĞRUDAN gözlenemezdi — bu test, düzeltmenin Linux'ta da hâlâ DOĞRU
    sonucu ürettiğini (yanlışlıkla `\\`'a çevrilmediğini) sabitleyen bir
    referans/temel çizgi testi. Asıl regresyon yüzeyi Windows'tadır; bkz.
    `tests/test_hwid_probe.py::test_okuyucular_yalnizca_usb_manager_
    uzerinden_uretime_bagli`'nin kendisi (orada `PureWindowsPath` ile
    ayrıca doğrulanıyor).
    """
    from pathlib import Path as _P

    kok = _P(__file__).resolve().parent.parent
    hedef = kok / "CORE" / "usb_manager.py"

    goreli = hedef.relative_to(kok).as_posix()

    assert goreli == "CORE/usb_manager.py"
    assert "\\" not in goreli, "Linux'ta path ayırıcı yanlışlıkla ters slaşa döndü"


# ── 6) Headless açılış selftest'inin geçtiği ─────────────────────────────────


@_LINUX
def test_6_headless_selftest_gecer(tmp_path: Path) -> None:
    """
    `python main.py --selftest` — `packaging/linux/smoke-test.sh`'ın da
    dayandığı GUI'siz duman testi. Gerçek bir alt süreçte çalıştırılıyor
    (mock değil): paketlenmemiş ama BAŞSIZ bir ortamda `QApplication`
    hiç kurulmadan tüm modüllerin içe aktarılabildiğini doğruluyor.

    `--test-data-dir` ile izole edilmiş bir veri dizini veriliyor —
    üretim `data/`'sına DOKUNULMAMASI için (bkz. `main.py`'nin kendi
    `_test_data_dir_bayragini_coz()` docstring'i).
    """
    kok = Path(__file__).resolve().parent.parent
    sonuc = subprocess.run(
        [sys.executable, str(kok / "main.py"), "--selftest",
         "--test-data-dir", str(tmp_path / "veri")],
        capture_output=True, text=True, timeout=60, cwd=str(kok),
    )
    assert sonuc.returncode == 0, (
        f"selftest başarısız (rc={sonuc.returncode})\n"
        f"stdout:\n{sonuc.stdout}\nstderr:\n{sonuc.stderr}"
    )
    assert "SELFTEST OK" in sonuc.stdout


# ── 7) TPM Linux'ta genelde yok — fallback (B-049) doğru çalışıyor ──────────


@_LINUX
def test_7_tpm_linuxta_kullanilamaz_ve_dusus_sessiz_degil(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    `CORE/tpm_sealing.py` YALNIZCA Windows/CNG üzerinde çalışıyor (modül
    docstring'i, "1. CNG erişimi — bu bölüm YALNIZCA Windows'ta çalışır").
    Linux'ta `durum().kullanilabilir` HER ZAMAN False olmalı, VE düşüş
    `belki_muhurle()` üzerinden SESSİZ bir hata değil, olduğu gibi bir
    değer dönüşü + log uyarısı üretmeli — B-049'un dersi: "sessizce devre
    dışı kalan bir güvenlik katmanı, hiç olmamasından kötüdür."

    `tests/conftest.py::tpm_kapali` zaten autouse ile TPM'i testler için
    kapatıyor — bu test onun ÜZERİNE, gerçek platform mantığının (durum()
    içindeki `sys.platform != "win32"` dalı) kendisini, önbelleği
    sıfırlayıp yeniden sorgulayarak ayrıca ölçüyor.
    """
    monkeypatch.setattr(tpm_sealing.sys, "platform", "linux")
    tpm_sealing.sifirla_onbellek()
    try:
        d = tpm_sealing.durum()
        assert d.kullanilabilir is False
        assert "yalnızca Windows" in d.neden or "Windows" in d.neden

        eylem, aciklama = tpm_sealing.oturum_raporu()
        assert eylem == tpm_sealing.EYLEM_DUSUS
        assert "sirlar anahtar kasasinda" in aciklama

        # belki_muhurle(): mühürsüz döner, İSTİSNA FIRLATMAZ.
        deger = tpm_sealing.belki_muhurle("gizli-deger-123", baglam="test-baglam")
        assert deger == "gizli-deger-123"
        assert not tpm_sealing.muhurlu_mu(deger)
    finally:
        tpm_sealing.sifirla_onbellek()


# ── 8) Linux dosya kilitleme (checkout.py — DÜRÜST NOT: B-107 DEĞİL) ────────


@_LINUX
def test_8_linux_dosya_kilidi_olu_pidi_dogru_ayirt_ediyor(
    db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    `CORE/checkout.py::_pid_alive()`'ın POSIX dalı: gerçek `os.kill(pid, 0)`
    ile (mock değil) hem "yaşıyor" hem "öldü" uçlarını, GERÇEK bu sürecin
    kendi PID'i ve KESİNLİKLE var olmayan devasa bir PID kullanarak ölçer;
    `release_stale_locks()`'un bu makineye ait (aynı hostname) sahipsiz
    kilitleri GERÇEKTEN temizlediğini uçtan uca doğrular.

    (DÜRÜST NOT: bu dosyanın modül docstring'inde açıklandığı gibi, bu
    konu BACKLOG.md'de B-107 DEĞİL — B-107 hız sınırlamasıdır. Burada
    gerçek hedef `CORE/checkout.py`'nin kilit mekanizması.)
    """
    monkeypatch.setattr("CORE.checkout.sys.platform", "linux")
    host = __import__("socket").gethostname()

    # Kendi PID'imiz — GERÇEKTEN yaşıyor.
    acquire_lock(db, file_id=1, user_id=1, session_id="canli",
                 pid=os.getpid(), hostname=host)
    # Var olmayan bir PID — POSIX'te ProcessLookupError üretmesi neredeyse
    # kesin (PID alanı 32-bit sistemlerde bile genelde çok daha küçük).
    acquire_lock(db, file_id=2, user_id=1, session_id="olu",
                 pid=2**30, hostname=host)

    rapor = release_stale_locks(db)

    assert rapor.released == 1
    assert (2, host) in rapor.released_ids
    kalan = db.fetchone("SELECT session_id FROM file_locks WHERE file_id = ?", (1,))
    assert kalan is not None and kalan["session_id"] == "canli", (
        "yaşayan PID'e ait kilit YANLIŞLIKLA temizlendi"
    )
    silinen = db.fetchone("SELECT * FROM file_locks WHERE file_id = ?", (2,))
    assert silinen is None, "ölü PID'e ait kilit temizlenmedi"


# ── 9) Linux dizin izinleri (safezone.py — DÜRÜST NOT: folders.py/B-123 DEĞİL) ──


@_LINUX
def test_9_safezone_dizini_linuxta_0700_izniyle_olusuyor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """
    (DÜRÜST NOT: bu dosyanın modül docstring'inde açıklandığı gibi, bu
    konu B-123 DEĞİL — B-123 klasör hiyerarşisi UI'ıyla ilgili kozmetik
    bir bulgu, dosya sistemi izniyle hiç ilgisi yok. `CORE/folders.py`
    hiçbir `chmod`/izin mantığı taşımıyor: "klasör" kavramı yalnızca
    `folders` tablosunda bir DB satırı, dosyalar hep AYNI fiziksel
    `safezone`/`vault` dizininde duruyor. Gerçek, ölçülebilir dizin-izni
    mantığının TEK karşılığı `CORE/safezone.py::safezone_dir()`'ın
    `_DIR_MODE = 0o700` sabiti.)

    POSIX'te `Path.mkdir(mode=...)` `umask` ile birleşir — bu yüzden
    `os.umask(0)` ile geçici olarak sıfırlanıp GERÇEK sonucun `0700`
    olduğu doğrudan ölçülüyor (aksi hâlde varsayılan `022` umask'lı bir
    ortamda test sessizce `0755` gibi bir değeri de "geçti" sayardı).
    """
    monkeypatch.setenv("HYCLEUS_SAFEZONE", str(tmp_path / "ozel_safezone"))
    eski_umask = os.umask(0)
    try:
        yol = safezone_dir(create=True)
    finally:
        os.umask(eski_umask)

    assert yol.is_dir()
    mod = stat.S_IMODE(yol.stat().st_mode)
    assert mod == _DIR_MODE == 0o700, (
        f"SafeZone dizini beklenen 0700 yerine {oct(mod)} izniyle oluştu"
    )


# ── 10) ClamAV yokken CI testleri SKIP değil "unknown verdict" ile geçiyor ──


@_LINUX
def test_10_clamav_yokken_scan_hicbir_seyi_skip_etmeden_unknown_ile_tamamlaniyor(
    db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    CI'ın Ubuntu ayağında ClamAV kurulu OLMAYABİLİR (bu makinede de kurulu
    değil, bkz. `_clamav_yok` işareti) — bu, tarama testlerinin `skip`
    edilmesi GEREKTİĞİ anlamına GELMEMELİ: `scan_file()`'ın kendisi hiçbir
    istisna fırlatmadan, hiçbir `pytest.skip()` gerekmeden, uçtan uca
    (DB'ye karantina satırı yazımı dahil) `verdict="unknown"` ile
    TAMAMLANMALI. `tests/test_scanner_backends.py`'nin `_clamav_yok`
    işaretiyle atladığı ŞEY farklı: o gerçek aracın DAVRANIŞINI ölçüyor;
    bu test aracın YOKLUĞUNUN kendisinin bir hata/skip DEĞİL, birinci
    sınıf bir sonuç olduğunu, veritabanı yazımı dahil kanıtlıyor.
    """
    monkeypatch.setattr(sb.sys, "platform", "linux")
    monkeypatch.setattr(sb.shutil, "which", lambda ad: None)

    hedef = tmp_path / "belge.hcl"
    hedef.write_bytes(b"icerik\n")

    db.execute(
        "INSERT INTO users (id, username, password_hash, role) "
        "VALUES (1, 'test', 'x', 'admin')"
    )
    db.execute(
        "INSERT INTO files (id, filename, filepath, added_by) "
        "VALUES (1, 'belge.hcl', ?, 1)", (str(hedef),)
    )

    sonuc = scan_file(hedef, file_id=1)

    assert sonuc.verdict == "unknown"
    assert sonuc.mock is True

    kayit = db.fetchone("SELECT * FROM quarantine WHERE file_id = 1")
    assert kayit is not None, (
        "ClamAV yokken quarantine satırı hiç yazılmadı — sessizce "
        "atlanmış olabilir"
    )
    assert '"verdict": "unknown"' in kayit["reason"]
