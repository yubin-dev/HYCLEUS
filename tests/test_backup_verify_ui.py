"""
Yedek doğrulamanın ARAYÜZ tarafı.

`tests/test_backup.py` doğrulamanın DOĞRU olduğunu sınıyor. Burada
sınanan şey, sonucun kullanıcıya EKSİKSİZ ulaştığı.

Bu paketin ana iddiası tek cümle: **`VerifyReport`'un söyleyebileceği
her sorun ekrana çıkıyor.**

Neden en önemli iddia bu
------------------------
`VerifyReport` altı ayrı yoldan "bir şey yanlış" diyebiliyor: `missing`,
`corrupt`, `auth_failed`, `manifest_mismatch`, `error`, `cancelled`.
Arayüz bunlardan birini atlarsa kullanıcı sorunu HİÇ görmez ve yedeği
sağlam sanar — bir doğrulama ekranının verebileceği en kötü çıktı.

Atlama kolay: `manifest_mismatch` tek bir `bool` ve listeleri çizen
döngüye girmiyor. Bu yüzden iki denetim var:

  1. Davranışsal — HER alanı dolu bir rapor kurulup diyalogdaki metinde
     her birinin göründüğü doğrulanıyor.
  2. Yapısal — `dataclasses.fields()` ile alanlar sayılıyor; yeni bir
     alan eklendiğinde "bunu nasıl göstereceğiz" kararı verilene kadar
     test düşüyor.

Üçüncü bir denetim CLI'ı da aynı kaynağa bağlıyor: `--verify` çıktısı da
her problem alanına dokunmak zorunda. İki yüzey, tek gerçek kaynağı
(`VerifyReport`) paylaşıyor.
"""
from __future__ import annotations

import ast
import dataclasses
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QLabel, QWidget

    from UI.BackupVerifyDialog import (
        DURUM_IPTAL,
        DURUM_KUSURLU,
        DURUM_OKUNAMADI,
        DURUM_SAGLAM,
        BackupVerifyDialog,
        _DURUM_GORUNUM,
        _LISTE_SINIRI,
        durum_of,
    )
    from UI.main_window_open import BackupMixin
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE import crypto
from CORE.backup import VerifyReport, create_backup, verify_backup
from CORE.crypto import encrypt_file, generate_key

_USER = 3
_HWID = "TEST-HWID-BKUI"

_CLI = Path(__file__).parent.parent / "CORE" / "backup_cli.py"

#: `VerifyReport`'un SORUN taşımayan alanları.
#:
#: Bunlar gösterilmek zorunda değil çünkü tek başlarına bir problem
#: bildirmiyorlar: `ok` bir özet, `checked`/`total`/`deep` ise kapsam
#: bilgisi (diyalog yine de gösteriyor, ama zorunluluk buradan gelmiyor).
_SORUNSUZ_ALANLAR = frozenset({"ok", "checked", "total", "deep"})


# ══════════════════════════════════════════════════════════════════════════════
# Fixture'lar
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


@pytest.fixture(autouse=True)
def _diyalog_engelle(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    gosterilen: list[tuple[str, str]] = []

    def _yakala(tur: str):
        def _f(_parent, baslik, metin, *a, **kw):
            gosterilen.append((tur, f"{baslik}: {metin}"))
            return 0
        return _f

    from PySide6.QtWidgets import QMessageBox

    for ad in ("warning", "critical", "information", "question"):
        monkeypatch.setattr(QMessageBox, ad, staticmethod(_yakala(ad)))
    return gosterilen


@pytest.fixture(autouse=True)
def _diyalogu_acma(monkeypatch: pytest.MonkeyPatch) -> list[BackupVerifyDialog]:
    """Diyalog KURULSUN ama modal döngüye girmesin."""
    acilanlar: list[BackupVerifyDialog] = []

    def _exec(self):
        acilanlar.append(self)
        return 1

    monkeypatch.setattr(BackupVerifyDialog, "exec", _exec)
    return acilanlar


@pytest.fixture
def key() -> bytes:
    return generate_key()


@pytest.fixture
def vault(tmp_path: Path, key: bytes, monkeypatch: pytest.MonkeyPatch) -> Path:
    q = tmp_path / "quarantine"
    q.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", q)
    for ad, icerik in (("a.txt", b"bir\n" * 40), ("b.txt", b"iki\n" * 30)):
        src = tmp_path / ad
        src.write_bytes(icerik)
        encrypt_file(src, key, _USER, hwid=_HWID)
        src.unlink()
    return q


@pytest.fixture
def yedek(db, vault: Path, tmp_path: Path, key: bytes) -> Path:
    db.execute(
        "INSERT INTO users (id, username, password_hash, role, status, hwid)"
        " VALUES (3, 'u', '', 'admin', 'approved', ?)", (_HWID,))
    rapor = create_backup(
        db, tmp_path / "yedek", key, vault_dir=vault, user_id=_USER, hwid=_HWID)
    return rapor.path


def _her_sorunu_tasiyan_rapor() -> VerifyReport:
    """`VerifyReport`'un söyleyebileceği HER sorunu aynı anda taşıyan rapor.

    Gerçekte hepsi bir arada olmaz (`error` diğerlerini engeller) ama
    denetimin amacı gerçekçilik değil KAPSAMA: her alanın ekrana bir yolu
    olduğunu tek diyalogda ölçmek.
    """
    return VerifyReport(
        ok=False,
        checked=4,
        total=7,
        deep=True,
        missing=["EKSIK-DOSYA.hcl"],
        corrupt=["BOZUK-DOSYA.hcl"],
        auth_failed=["MUHRU-TUTMAYAN.hcl"],
        extra=["FAZLADAN-DOSYA.hcl"],
        manifest_mismatch=True,
        error="MANIFESTO-OKUNAMADI-HATASI",
        cancelled=True,
    )


class _Sahne(BackupMixin, QWidget):
    """`BackupMixin._on_verify_backup`'ın dokunduğu asgari yüzey."""

    def __init__(self, key: bytes) -> None:
        super().__init__()
        self._key = key
        self._hwid = _HWID
        self._user_id = _USER


@pytest.fixture
def sahne(qapp, key: bytes) -> _Sahne:
    return _Sahne(key)


@pytest.fixture(autouse=True)
def kayitlar(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict]]:
    toplanan: list[tuple[str, dict]] = []

    class _SahteDB:
        def log(self, action: str, **kw) -> None:
            toplanan.append((action, kw))

    import UI.main_window_open as mwo
    monkeypatch.setattr(mwo, "DBManager", _SahteDB)
    return toplanan


@pytest.fixture
def dizin_sec(monkeypatch: pytest.MonkeyPatch):
    """`QFileDialog.getExistingDirectory`'yi sabitler."""
    def _kur(yol: str | Path | None):
        from PySide6.QtWidgets import QFileDialog
        monkeypatch.setattr(
            QFileDialog, "getExistingDirectory",
            staticmethod(lambda *a, **kw: str(yol) if yol else ""),
        )
    return _kur


@pytest.fixture(autouse=True)
def _ilerleme_engelle(monkeypatch: pytest.MonkeyPatch):
    """`QProgressDialog`'u modal olmayan bir sahteyle değiştirir.

    Gerçeği offscreen'de de modal ve `processEvents()` ile birlikte
    testi asabiliyor. Sahte, `wasCanceled()`'ı kontrol edilebilir
    yapıyor — iptal yolunun sınanması buna bağlı.
    """
    class _SahteIlerleme:
        iptal = False
        kurulan: list[_SahteIlerleme] = []

        def __init__(self, *a, **kw) -> None:
            self.adimlar: list[str] = []
            _SahteIlerleme.kurulan.append(self)

        def setWindowTitle(self, *a): pass
        def setMinimumDuration(self, *a): pass
        def setValue(self, *a): pass
        def setMaximum(self, *a): pass
        def setLabelText(self, metin): self.adimlar.append(metin)
        def close(self): pass
        def wasCanceled(self) -> bool: return _SahteIlerleme.iptal

    _SahteIlerleme.iptal = False
    _SahteIlerleme.kurulan = []
    import PySide6.QtWidgets as qtw
    monkeypatch.setattr(qtw, "QProgressDialog", _SahteIlerleme)
    return _SahteIlerleme


def _metinler(dlg: QWidget) -> str:
    """Diyalogdaki GÖRÜNEN etiketlerin metni, tek dize.

    Teknik blok (`QTextEdit`) BİLEREK dışarıda: tam listenin orada olması
    gerekiyor, denetimin ölçtüğü şey kullanıcının doğrudan gördüğü yüzey.
    """
    return "\n".join(lbl.text() for lbl in dlg.findChildren(QLabel))


# ══════════════════════════════════════════════════════════════════════════════
# 1. Eksiksizlik — her sorun ekrana çıkıyor mu
# ══════════════════════════════════════════════════════════════════════════════


def test_HER_sorun_alani_ekranda_gorunuyor(qapp) -> None:
    """
    Davranışsal denetim: altı problem alanının hepsi tek diyalogda.

    Bir alanı çizmeyi unutmak, kullanıcının o sorunu HİÇ görmemesi
    demek — ve "sağlam" sanması.
    """
    dlg = BackupVerifyDialog(_her_sorunu_tasiyan_rapor(), Path("/yedek/2026"))
    metin = _metinler(dlg)

    for beklenen in (
        "EKSIK-DOSYA.hcl",
        "BOZUK-DOSYA.hcl",
        "MUHRU-TUTMAYAN.hcl",
        "FAZLADAN-DOSYA.hcl",
        "MANIFESTO-OKUNAMADI-HATASI",
    ):
        assert beklenen in metin, f"{beklenen!r} ekranda yok"

    assert "İçerik listesi uyuşmuyor" in metin, "manifest_mismatch gösterilmiyor"
    assert "yarıda kesildi" in metin, "cancelled gösterilmiyor"
    # `error`'ın ham metni `summary()` satırında da geçiyor; kutunun
    # kendisinin durduğunu AYRICA sınamak gerekiyor, yoksa kutuyu silmek
    # fark edilmez (mutasyon testinde tam olarak bu hayatta kaldı).
    assert "sağlam olup olmadığı SÖYLENEMEZ" in metin, "error kutusu yok"


def test_yeni_bir_rapor_alani_KARAR_verilmeden_eklenemez() -> None:
    """
    Yapısal tripwire.

    `VerifyReport`'a bir alan eklendiğinde bu test düşer ve ekleyen kişi
    iki şeyden birini yapmak zorunda kalır: alanı diyaloga bağlamak ya da
    `_SORUNSUZ_ALANLAR`'a gerekçesiyle yazmak. Sessiz üçüncü seçenek
    (hiçbir şey yapmamak) kapalı.
    """
    alanlar = {f.name for f in dataclasses.fields(VerifyReport)}
    sorun_alanlari = alanlar - _SORUNSUZ_ALANLAR
    assert sorun_alanlari == {
        "missing", "corrupt", "auth_failed", "extra",
        "manifest_mismatch", "error", "cancelled",
    }, (
        "VerifyReport'un alanları değişmiş. Yeni alanı diyaloga bağlayın "
        "ya da neden sorun taşımadığını _SORUNSUZ_ALANLAR'a yazın."
    )


def _nitelikler(kaynak: str, kok: ast.AST | None = None, ad: str = "rapor") -> set[str]:
    """`<ad>.X` biçimindeki nitelik erişimlerini AST ile toplar."""
    agac = kok if kok is not None else ast.parse(kaynak)
    return {
        d.attr for d in ast.walk(agac)
        if isinstance(d, ast.Attribute)
        and isinstance(d.value, ast.Name)
        and d.value.id == ad
    }


def _summary_alanlari() -> set[str]:
    """`VerifyReport.summary()`'nin okuduğu alanlar.

    CLI, raporu satır satır basmıyor: önce `rapor.summary()` yazıyor.
    Yani `summary()`'nin değindiği her alan, doğrudan okunmasa bile
    komut satırı kullanıcısına ULAŞIYOR. Denetim bunu saymazsa yanlış
    alarm verir — ilk yazımda tam olarak bu oldu, `error` "eksik"
    raporlandı.
    """
    kaynak = (Path(__file__).parent.parent / "CORE" / "backup.py").read_text(
        encoding="utf-8")
    for dugum in ast.walk(ast.parse(kaynak)):
        if isinstance(dugum, ast.ClassDef) and dugum.name == "VerifyReport":
            for uye in dugum.body:
                if isinstance(uye, ast.FunctionDef) and uye.name == "summary":
                    return _nitelikler("", kok=uye, ad="self")
    raise AssertionError("VerifyReport.summary() bulunamadı — denetim kör.")


def test_CLI_de_her_sorun_alanina_dokunuyor() -> None:
    """
    Aynı sözleşme komut satırı için de geçerli.

    İki yüzey aynı `VerifyReport`'u okuyor; birine eklenip diğerine
    eklenmeyen bir alan, o yüzeyde sessiz bir kör nokta demek. AST ile
    erişimler toplanıyor — metin araması bu dosyanın kendi yorumlarına
    da eşleşirdi.
    """
    dokunulan = _nitelikler(_CLI.read_text(encoding="utf-8")) | _summary_alanlari()
    alanlar = {f.name for f in dataclasses.fields(VerifyReport)}
    eksik = sorted((alanlar - _SORUNSUZ_ALANLAR) - dokunulan)
    assert not eksik, (
        "Bu rapor alanları komut satırında hiç görünmüyor — ne "
        f"`_cmd_verify` okuyor ne de `summary()` değiniyor: {eksik}"
    )


def test_summary_taramasi_gercekten_alan_buluyor() -> None:
    """
    Boş küme dönerse CLI denetimi kendiliğinden sıkılaşır DEĞİL — gevşer:
    `summary()` alanları düşerse `_cmd_verify`'ın doğrudan okumadığı her
    alan "eksik" görünür. Yani bu tarama bozulursa yanlış alarm başlar.
    """
    alanlar = _summary_alanlari()
    assert {"ok", "error", "cancelled", "missing"} <= alanlar, (
        f"summary() taraması eksik okudu: {sorted(alanlar)}"
    )


def test_denetim_taramasi_gercekten_alan_buluyor() -> None:
    """Boş küme dönerse yukarıdaki denetimler kendiliğinden geçerdi."""
    assert len(dataclasses.fields(VerifyReport)) >= 9


# ══════════════════════════════════════════════════════════════════════════════
# 2. Durum kararı
# ══════════════════════════════════════════════════════════════════════════════


def test_saglam_yedek_saglam_okunuyor(qapp, yedek: Path, key: bytes) -> None:
    rapor = verify_backup(yedek, key=key, hwid=_HWID)
    assert rapor.ok
    dlg = BackupVerifyDialog(rapor, yedek)
    assert durum_of(rapor) == DURUM_SAGLAM
    assert "Yedek sağlam" in _metinler(dlg)


def test_eksik_dosya_kusurlu_okunuyor(qapp, yedek: Path, key: bytes) -> None:
    kurban = next((yedek / "files").glob("*.hcl"))
    kurban.unlink()

    rapor = verify_backup(yedek, key=key, hwid=_HWID)
    dlg = BackupVerifyDialog(rapor, yedek)
    metin = _metinler(dlg)
    assert durum_of(rapor) == DURUM_KUSURLU
    assert "Yedekte sorun var" in metin
    assert kurban.name in metin


def test_okunamayan_yedek_BOZUK_denmiyor(qapp, tmp_path: Path) -> None:
    """
    "Manifestoyu açamadım" ile "yedek bozuk" farklı şeyler.

    İkisini tek kırmızıya toplamak, yanlış dizini seçen kullanıcıya
    yedeğinin bozulduğunu söylerdi.
    """
    bos = tmp_path / "yedek-degil"
    bos.mkdir()
    rapor = verify_backup(bos)
    assert rapor.error
    assert durum_of(rapor) == DURUM_OKUNAMADI
    assert "Yedek okunamadı" in _metinler(BackupVerifyDialog(rapor, bos))


def test_iptal_ne_saglam_ne_kusurlu(qapp) -> None:
    rapor = VerifyReport(ok=False, cancelled=True, checked=2, total=90)
    assert durum_of(rapor) == DURUM_IPTAL
    metin = _metinler(BackupVerifyDialog(rapor, Path("/y")))
    assert "Doğrulama tamamlanmadı" in metin
    assert "Yedek sağlam" not in metin
    assert "Yedekte sorun var" not in metin


def test_okuma_hatasi_iptalden_ONCE_geliyor(qapp) -> None:
    """
    Manifesto okunamadıysa diğer alanların hepsi boştur ve o boşluk
    "sorun yok" gibi okunurdu. Sıra bu yüzden sabitleniyor.
    """
    assert durum_of(VerifyReport(
        ok=False, error="açılamadı", cancelled=True)) == DURUM_OKUNAMADI


def test_dort_durum_dort_ayri_renk() -> None:
    renkler = [_DURUM_GORUNUM[d][1] for d in
               (DURUM_SAGLAM, DURUM_KUSURLU, DURUM_OKUNAMADI, DURUM_IPTAL)]
    assert len(set(renkler)) == 4, f"Renkler ayrışmıyor: {renkler}"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Kapsam ve liste davranışı
# ══════════════════════════════════════════════════════════════════════════════


def test_kac_dosyaya_bakildigi_yaziyor(qapp) -> None:
    """"Sağlam" cevabı, kaç dosyaya bakıldığı bilinmeden okunamaz."""
    dlg = BackupVerifyDialog(VerifyReport(ok=True, checked=12, total=12), Path("/y"))
    assert "12 / 12" in _metinler(dlg)


def test_kontrol_derinligi_yaziyor(qapp) -> None:
    """
    Kapsam ALANINDAKİ değer sınanıyor, ekranda "hızlı" sözcüğünün bir
    yerde geçmesi değil.

    İlk yazımda gevşek arama yapıyordu ve "derinlik alanı her zaman TAM
    diyor" mutasyonu HAYATTA KALDI: sözcük, aşağıdaki bilgi kutusundan
    geliyordu. Alanın kendisi yanlış olsa bile test geçiyordu.
    """
    def _alan(deep: bool) -> str:
        dlg = BackupVerifyDialog(
            VerifyReport(ok=True, checked=1, total=1, deep=deep), Path("/y"))
        etiketler = [lbl.text() for lbl in dlg.findChildren(QLabel)]
        i = etiketler.index("Kontrol derinliği")
        return etiketler[i + 1]

    assert _alan(deep=False) == "Yalnızca boyut ve özet (hızlı)"
    assert _alan(deep=True) == "Bütünlük mührü dahil (tam)"

    # Sığ kontrolde eksik kalanın ne olduğu ayrıca, kutu olarak söyleniyor.
    hizli = _metinler(BackupVerifyDialog(
        VerifyReport(ok=True, checked=1, total=1, deep=False), Path("/y")))
    assert "Bu hızlı bir kontroldü" in hizli
    assert "bütünlük mühürleri açılmadı" in hizli


def test_uzun_liste_ekranda_kisaliyor_metinde_TAM(qapp) -> None:
    """
    Ekranda sınır var, panoya kopyalanan metinde YOK.

    Kullanıcı raporu yöneticisine iletecekse eksik bir liste işe yaramaz.
    """
    adlar = [f"dosya-{i:03d}.hcl" for i in range(_LISTE_SINIRI + 15)]
    dlg = BackupVerifyDialog(VerifyReport(ok=False, missing=adlar), Path("/y"))

    ekran = _metinler(dlg)
    assert adlar[0] in ekran
    assert adlar[-1] not in ekran
    assert f"{len(adlar) - _LISTE_SINIRI} tane daha" in ekran

    tam = dlg.teknik_metin()
    assert all(ad in tam for ad in adlar)


def test_fazladan_dosya_HATA_olarak_gosterilmiyor(qapp) -> None:
    """Manifestoda olmayan dosya bir bilgi; kırmızı olması yanıltırdı."""
    dlg = BackupVerifyDialog(
        VerifyReport(ok=True, checked=2, total=2, extra=["elle-kopya.hcl"]),
        Path("/y"))
    metin = _metinler(dlg)
    # Adı GÖRÜNÜYOR — "3 fazladan dosya var" cümlesi, hangileri olduğunu
    # sormaktan başka bir şey bırakmazdı.
    assert "elle-kopya.hcl" in metin
    # Ama hata değil: karar hâlâ "sağlam".
    assert "Bir hata değil" in metin
    assert "Yedek sağlam" in metin


def test_kopyalanan_metin_dizin_yolunu_tasiyor(qapp) -> None:
    dlg = BackupVerifyDialog(VerifyReport(ok=True, checked=1, total=1),
                             Path("/yedekler/2026-08-20"))
    assert "2026-08-20" in dlg.teknik_metin()


def test_teknik_blok_KAPALI_basliyor(qapp) -> None:
    dlg = BackupVerifyDialog(VerifyReport(ok=True), Path("/y"))
    assert not dlg._teknik_alan.isVisible()


# ══════════════════════════════════════════════════════════════════════════════
# 4. Menü akışı
# ══════════════════════════════════════════════════════════════════════════════


def test_akis_DERIN_dogrulama_yapiyor(
    sahne, yedek: Path, dizin_sec, _diyalogu_acma,
) -> None:
    """
    Arayüzde anahtar zaten elde; sığ modu varsayılan yapmak bedava olan
    bir kontrolü kullanıcıdan saklamak olurdu.
    """
    dizin_sec(yedek)
    sahne._on_verify_backup()

    assert len(_diyalogu_acma) == 1
    rapor = _diyalogu_acma[0]._rapor
    assert rapor.deep is True
    assert rapor.ok is True


def test_dizin_secilmezse_hicbir_sey_olmuyor(
    sahne, dizin_sec, _diyalogu_acma, kayitlar,
) -> None:
    dizin_sec(None)
    sahne._on_verify_backup()
    assert not _diyalogu_acma
    assert not kayitlar


def test_ilerleme_her_dosya_icin_bildiriliyor(
    sahne, yedek: Path, dizin_sec, _ilerleme_engelle,
) -> None:
    dizin_sec(yedek)
    sahne._on_verify_backup()
    assert _ilerleme_engelle.kurulan
    assert len(_ilerleme_engelle.kurulan[0].adimlar) == 2


def test_IPTAL_gercekten_taramayi_durduruyor(
    sahne, yedek: Path, dizin_sec, _ilerleme_engelle, _diyalogu_acma,
) -> None:
    """
    İptal düğmesinin çalışmaması, olmamasından kötüdür: kullanıcı bastığı
    hâlde on dakika bekler.
    """
    _ilerleme_engelle.iptal = True
    dizin_sec(yedek)
    sahne._on_verify_backup()

    rapor = _diyalogu_acma[0]._rapor
    assert rapor.cancelled is True
    assert rapor.ok is False
    assert rapor.checked == 0


def test_beklenmedik_hata_arayuzu_COKERTMIYOR(
    sahne, yedek: Path, dizin_sec, monkeypatch, _diyalog_engelle, _diyalogu_acma,
) -> None:
    def _patla(*a, **kw):
        raise OSError("disk okunamadı")

    import CORE.backup as cb
    monkeypatch.setattr(cb, "verify_backup", _patla)

    dizin_sec(yedek)
    sahne._on_verify_backup()
    assert _diyalog_engelle and "disk okunamadı" in _diyalog_engelle[0][1]
    assert not _diyalogu_acma


def test_dogrulama_DENETIM_kaydina_geciyor(
    sahne, yedek: Path, dizin_sec, kayitlar, _diyalogu_acma,
) -> None:
    dizin_sec(yedek)
    sahne._on_verify_backup()

    assert [ad for ad, _ in kayitlar] == ["backup_verified"]
    detay = kayitlar[0][1]["detail"]
    assert "ok=True" in detay and "deep=True" in detay
    assert "checked=2/2" in detay


def test_denetim_kaydi_dusse_bile_sonuc_gosteriliyor(
    sahne, yedek: Path, dizin_sec, monkeypatch, _diyalogu_acma,
) -> None:
    class _KirikDB:
        def log(self, *a, **kw):
            raise RuntimeError("db kilitli")

    import UI.main_window_open as mwo
    monkeypatch.setattr(mwo, "DBManager", _KirikDB)

    dizin_sec(yedek)
    sahne._on_verify_backup()
    assert len(_diyalogu_acma) == 1


# ══════════════════════════════════════════════════════════════════════════════
# 5. Menü maddesi gerçekten BAĞLI mı
# ══════════════════════════════════════════════════════════════════════════════

_MADDE = "🔍  Yedek Doğrula…"


def test_menude_madde_var_ve_akisi_tetikliyor(
    qapp, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Maddeyi eklemek ama gönderim satırını unutmak, bu deponun bildiği bir
    kusur. Menüde görünen ama hiçbir şey yapmayan bir madde, olmayan bir
    maddeden kötüdür.
    """
    from PySide6.QtWidgets import QMenu, QPushButton

    from UI.main_window import HycleusWindow

    gorulen: list[str] = []

    class _SahteMenu(QMenu):
        def exec(self, *a, **kw):
            gorulen.extend(e.text() for e in self.actions() if not e.isSeparator())
            for eylem in self.actions():
                if eylem.text() == _MADDE:
                    return eylem
            return None

    import UI.main_window as mw
    monkeypatch.setattr(mw, "QMenu", _SahteMenu)

    class _Sahne2(QWidget):
        _on_hamburger_menu = HycleusWindow._on_hamburger_menu

        def __init__(self) -> None:
            super().__init__()
            self._T = {
                "topbar": "#fff", "text": "#000", "border": "#ccc",
                "accent_tint": "#eff6ff", "tint_text": "#111827",
            }
            self._btn_view = QPushButton(self)
            self.cagrildi = 0

        def _on_verify_backup(self) -> None:
            self.cagrildi += 1

    s = _Sahne2()
    s._on_hamburger_menu()
    assert _MADDE in gorulen, f"Menüde yok. Görülenler: {gorulen}"
    assert s.cagrildi == 1


def test_GERI_YUKLEME_menude_YOK(qapp, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Bilinçli karar, sabitleniyor.

    Geri yüklemenin tipik senaryosu "disk gitti, yeni makine" ve o
    makinede arayüz zaten açılmıyor (takılı + kayıtlı USB ve bir vault
    dosyası gerekiyor, ikisi de yok). Menüye eklemek, çalışmayacağı anda
    çalışacakmış izlenimi verirdi.
    """
    from PySide6.QtWidgets import QMenu, QPushButton

    from UI.main_window import HycleusWindow

    gorulen: list[str] = []

    class _SahteMenu(QMenu):
        def exec(self, *a, **kw):
            gorulen.extend(e.text() for e in self.actions() if not e.isSeparator())
            return None

    import UI.main_window as mw
    monkeypatch.setattr(mw, "QMenu", _SahteMenu)

    class _Sahne3(QWidget):
        _on_hamburger_menu = HycleusWindow._on_hamburger_menu

        def __init__(self) -> None:
            super().__init__()
            self._T = {
                "topbar": "#fff", "text": "#000", "border": "#ccc",
                "accent_tint": "#eff6ff", "tint_text": "#111827",
            }
            self._btn_view = QPushButton(self)

    _Sahne3()._on_hamburger_menu()
    assert not [m for m in gorulen if "Geri Yükle" in m or "Geri yükle" in m]
