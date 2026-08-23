"""
Damga doğrulamanın ARAYÜZ tarafı (adım 3.1).

`tests/test_timestamp_verify.py` doğrulamanın DOĞRU olduğunu,
`tests/test_timestamp_report.py` sonucun DOĞRU ANLATILDIĞINI sınıyor.
Burada sınanan şey BAĞLANTI: menüdeki maddenin gerçekten o doğrulamayı
çağırdığı ve sonucun kullanıcıya eksiksiz ulaştığı.

Üç şeyin kanıtı
---------------
1. Arayüz İKİNCİ bir doğrulama yazmıyor — `verify_timestamp()` çağrılıyor,
   ve çağrıldığı gözleniyor.
2. Diyalog, sonucun kullanıcı için önemli HER parçasını gösteriyor:
   karar, güven sınırı ve kapsam sınırı. Bunlardan biri düşerse ekran
   "geçerli" der ve ne anlama geldiğini söylemez.
3. Ham hata kodu (`no_timestamp`, `eku`) kullanıcıya GÖRÜNEN yüzeyde
   çıkmıyor; teknik bloğa iniyor.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from asn1crypto import tsp
from tsa_fixtures import FakeTSA, default_authority

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QLabel, QWidget

    from UI.main_window_files import FileActionsMixin
    from UI.main_window_palette import _DARK
    from UI.TimestampDialog import _seviye_gorunum, TimestampDialog
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE import crypto, timestamp_report as tr
from CORE.crypto import encrypt_file, generate_key
from CORE.timestamp import TimestampInfo, attach_trailer, timestamp_file
from CORE.timestamp_verify import TimestampVerification, verify_timestamp

#: Testler tek bir sabit paletle çalışıyor — B-055'ten sonra görünüm
#: T'ye göre değişiyor ama "her seviyenin bir görünümü var mı" sorusu
#: hangi preset seçili olduğundan bağımsız.
_SEVIYE_GORUNUM = _seviye_gorunum(_DARK)

_USER = 41
_HWID = "TEST-HWID-TS-UI"
_FIXTURE = Path(__file__).parent / "data" / "freetsa_response.der"
_FIXTURE_PLAIN = b"HYCLEUS RFC 3161 test vektoru\n"


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
def _quarantine_to_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    out = tmp_path / "quarantine"
    out.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", out)
    return out


@pytest.fixture(autouse=True)
def _diyalog_engelle(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """
    Modal `QMessageBox`'ları yakalar — açılmalarına izin verilmez.

    Offscreen platformda bile modaldır ve tıklayacak kimse olmadığı için
    sonsuza kadar bloklar (`tests/test_checkout_ui.py`'de ölçüldü).
    """
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
def _diyalogu_acma(monkeypatch: pytest.MonkeyPatch) -> list[TimestampDialog]:
    """
    `HycleusWindow._open_slide_over()`'ı yakalar (slide-over turu — eskiden
    `TimestampDialog.exec()` yamalıydı, artık `.exec()` yok çünkü diyalog
    `QDialog` değil `QWidget`).

    İçeriğin gerçekten kurulmuş olması önemli: kurulum sırasında düşen bir
    hata (eksik alan, None erişimi) ancak böyle yakalanır — panele hiç
    erişilmeseydi test asılmazdı ama hata da sessizce kaybolurdu.
    """
    acilanlar: list[TimestampDialog] = []

    def _ac(self, baslik, icerik):
        acilanlar.append(icerik)

    monkeypatch.setattr(_Sahne, "_open_slide_over", _ac)
    return acilanlar


@pytest.fixture
def key() -> bytes:
    return generate_key()


def _hcl(tmp_path: Path, key: bytes, icerik: bytes, ad: str = "belge.bin") -> Path:
    src = tmp_path / ad
    src.write_bytes(icerik)
    dst, _s, _a = encrypt_file(src, key, _USER, hwid=_HWID)
    return dst


@pytest.fixture
def stamped(tmp_path: Path, key: bytes) -> Path:
    path = _hcl(tmp_path, key, b"damgali rapor " * 100)
    timestamp_file(path, transport=FakeTSA())
    return path


@pytest.fixture
def unstamped(tmp_path: Path, key: bytes) -> Path:
    return _hcl(tmp_path, key, b"damgasiz rapor", ad="damgasiz.bin")


class _Sahne(FileActionsMixin, QWidget):
    """`FileActionsMixin._on_ctx_verify_timestamp`'in dokunduğu asgari yüzey."""

    def __init__(self) -> None:
        super().__init__()
        self._hwid = _HWID
        self._role = "Yönetici"
        self._T = _DARK

    def _open_slide_over(self, baslik: str, icerik) -> None:  # pragma: no cover — fixture değiştirir
        """Gerçek mekanizma `UI/main_window_layout.py::LayoutMixin`'de —
        burada YOK, çünkü bu sahne yalnızca `_on_ctx_verify_timestamp`'in
        dokunduğu yüzeyi taşıyor. `_diyalogu_acma` fixture'ı bunu yamalıyor."""
        raise NotImplementedError


@pytest.fixture
def sahne(qapp) -> _Sahne:
    return _Sahne()


@pytest.fixture(autouse=True)
def kayitlar(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict]]:
    """`DBManager` yerine denetim kayıtlarını toplayan bir sahte."""
    toplanan: list[tuple[str, dict]] = []

    class _SahteDB:
        def log(self, action: str, **kw) -> None:
            toplanan.append((action, kw))

    import UI.main_window_files as mwf
    monkeypatch.setattr(mwf, "DBManager", _SahteDB)
    return toplanan


def _etiket_metinleri(dlg: QWidget) -> list[str]:
    """Diyalogdaki GÖRÜNEN etiketlerin metni.

    `QTextEdit` (teknik blok) BİLEREK dışarıda: ham hata kodlarının orada
    olması gerekiyor, kullanıcının doğrudan gördüğü yüzeyde olmaması.
    """
    return [lbl.text() for lbl in dlg.findChildren(QLabel)]


# ══════════════════════════════════════════════════════════════════════════════
# 1. Diyalog — sonucu eksiksiz gösteriyor mu
# ══════════════════════════════════════════════════════════════════════════════


def test_gecerli_damga_diyalogda_gecerli_okunuyor(qapp, stamped: Path) -> None:
    dlg = TimestampDialog(verify_timestamp(stamped), stamped.name)
    metinler = _etiket_metinleri(dlg)
    # Kök deposu boşken başlık "geçerli" DEĞİL, "geçerli ama kök
    # doğrulanmadı" — ayrım kullanıcıya görünür olmalı.
    assert "Damga geçerli — ama damgayı atan kurum doğrulanmadı" in metinler
    assert stamped.name in metinler


def test_gercek_freetsa_damgasi_arayuzde_de_gecerli(
    qapp, tmp_path: Path, key: bytes,
) -> None:
    """GERÇEK bir damga, doğrulamadan diyaloğa kadar uçtan uca."""
    path = _hcl(tmp_path, key, _FIXTURE_PLAIN, ad="vektor.bin")
    token = tsp.TimeStampResp.load(_FIXTURE.read_bytes())["time_stamp_token"].dump()
    attach_trailer(path, TimestampInfo(
        hash_algorithm="sha256",
        hashed_hex=hashlib.sha256(_FIXTURE_PLAIN).hexdigest(),
        tsa_url="https://freetsa.org/tsr",
        token_der=token,
    ))
    dlg = TimestampDialog(verify_timestamp(path), path.name)
    metinler = " ".join(_etiket_metinleri(dlg))
    assert "Damga geçerli" in metinler
    assert "freetsa" in metinler


def test_damga_zamani_ve_TSA_adi_gosteriliyor(qapp, stamped: Path) -> None:
    """Kullanıcının sorduğu ilk iki soru: ne zaman, kim."""
    sonuc = verify_timestamp(stamped)
    dlg = TimestampDialog(sonuc, stamped.name)
    metinler = _etiket_metinleri(dlg)
    assert "Damga zamanı" in metinler
    assert tr.zaman_metni(sonuc.gen_time) in metinler
    assert sonuc.tsa_name in metinler


def test_kok_dogrulanmadi_UYARISI_diyalogda_gorunuyor(qapp, stamped: Path) -> None:
    """
    Bu, diyaloğun en kolay kaybedeceği parça ve kaybederse ekranın
    çıktısı yanıltıcı olur: "geçerli" der, neyin geçerli olmadığını
    söylemez.
    """
    sonuc = verify_timestamp(stamped)
    assert sonuc.valid and not sonuc.anchor_trusted

    metinler = " ".join(_etiket_metinleri(TimestampDialog(sonuc, stamped.name)))
    assert "Damgayı atan kurum doğrulanmadı" in metinler
    assert "kendi içinden" in metinler.lower() or "KENDİ İÇİNDEN" in metinler


def test_kok_dogrulandiginda_uyari_kalkiyor(qapp, stamped: Path) -> None:
    sonuc = verify_timestamp(stamped, trusted_roots=[default_authority().ca_der])
    metinler = " ".join(_etiket_metinleri(TimestampDialog(sonuc, stamped.name)))
    assert "Damgayı atan kurum doğrulandı" in metinler
    assert "doğrulanmadı" not in metinler


def test_KAPSAM_siniri_her_gecerli_sonucta_gorunuyor(qapp, stamped: Path) -> None:
    """
    "Damga geçerli" ile "dosya değiştirilmemiş" aynı şey değil ve ekran
    bunu söylemek zorunda.
    """
    metinler = " ".join(_etiket_metinleri(
        TimestampDialog(verify_timestamp(stamped), stamped.name)
    ))
    assert "Bu kontrol neyi kapsıyor" in metinler


def test_damgasiz_dosya_hata_gibi_GORUNMUYOR(qapp, unstamped: Path) -> None:
    sonuc = verify_timestamp(unstamped)
    dlg = TimestampDialog(sonuc, unstamped.name)
    assert dlg._mesaj.seviye == tr.SEVIYE_DAMGASIZ
    metinler = " ".join(_etiket_metinleri(dlg))
    assert "Bu dosyada zaman damgası yok" in metinler
    # Damgasız dosyada güven/kapsam notu ANLAMSIZ olurdu — doğrulanmış
    # bir şey yok.
    assert "Bu kontrol neyi kapsıyor" not in metinler


@pytest.mark.parametrize("bozuk", ["damgasiz", "gecersiz"])
def test_basarisiz_sonucta_BOS_alan_kutusu_cizilmiyor(
    qapp, unstamped: Path, bozuk: str,
) -> None:
    """
    "Damga zamanı: —" satırı bilgi değil gürültü.

    `_ozet_alanlari()` yalnızca geçerli sonuçta çiziliyor. Bu korumayı
    kaldırmak, "Bu dosyada zaman damgası yok" başlığının hemen altına
    boş bir zaman alanı koyardı — kullanıcıyı bir damga varmış gibi
    düşündüren tam olarak bu tür bir çelişki.

    Mutasyon testinde HAYATTA KALAN tek mutasyon buydu; test o boşluğu
    kapatmak için yazıldı.
    """
    if bozuk == "damgasiz":
        sonuc = verify_timestamp(unstamped)
    else:
        sonuc = TimestampVerification(
            valid=False, reason="imza tutmuyor", failed_check="signature"
        )
    metinler = _etiket_metinleri(TimestampDialog(sonuc, "belge.hcl"))
    assert "Damga zamanı" not in metinler
    assert tr.zaman_metni(None) not in metinler


def test_ham_hata_kodu_kullaniciya_GORUNMUYOR(qapp, unstamped: Path) -> None:
    """
    `no_timestamp` bir program sabiti, bir cümle değil. Teknik blokta
    olmalı, başlıkta değil.
    """
    dlg = TimestampDialog(verify_timestamp(unstamped), unstamped.name)
    for metin in _etiket_metinleri(dlg):
        assert "no_timestamp" not in metin
    assert "no_timestamp" in dlg.teknik_metin()


# ══════════════════════════════════════════════════════════════════════════════
# 2. Teknik blok
# ══════════════════════════════════════════════════════════════════════════════


def test_teknik_ayrintilar_KAPALI_basliyor(qapp, stamped: Path) -> None:
    dlg = TimestampDialog(verify_timestamp(stamped), stamped.name)
    assert not dlg._teknik_alan.isVisible()


def test_teknik_ayrintilar_acilip_kapaniyor(qapp, stamped: Path) -> None:
    dlg = TimestampDialog(verify_timestamp(stamped), stamped.name)
    dlg.show()
    dlg._teknik_degistir()
    assert dlg._teknik_alan.isVisible()
    assert "▾" in dlg._ac_kapa.text()
    dlg._teknik_degistir()
    assert not dlg._teknik_alan.isVisible()
    dlg.close()


def test_kopyalanan_metin_DOSYA_ADINI_tasiyor(qapp, stamped: Path) -> None:
    """
    Kullanıcı bunu yöneticisine yapıştıracak; hangi dosya olduğu metnin
    içinde durmalı, yoksa ekran görüntüsüne bağımlı kalır.
    """
    dlg = TimestampDialog(verify_timestamp(stamped), stamped.name)
    metin = dlg.teknik_metin()
    assert stamped.name in metin
    assert "Damgayı atan" in metin


def test_teknik_metin_CLI_ile_ayni_alanlari_veriyor(qapp, unstamped: Path) -> None:
    """
    Sadeleştirme bilgiyi SİLMEK değil bir kat aşağı koymak. Düşen kontrol
    ve teknik neden — CLI'ın bastığı iki alan — burada da var.
    """
    sonuc = verify_timestamp(unstamped)
    metin = TimestampDialog(sonuc, unstamped.name).teknik_metin()
    assert sonuc.failed_check in metin
    assert sonuc.reason in metin


# ══════════════════════════════════════════════════════════════════════════════
# 3. Denetim — her seviyenin bir görünümü var
# ══════════════════════════════════════════════════════════════════════════════


def test_her_SEVIYE_icin_bir_gorunum_tanimli() -> None:
    """
    Yeni bir seviye eklenirse diyalog sessizce gri noktaya düşerdi —
    yani anlam ayrımı arayüzde kaybolurdu. `CORE/timestamp_report.py`
    tarafındaki eksiksizlik denetiminin arayüz karşılığı.
    """
    seviyeler = {
        deger for ad, deger in vars(tr).items()
        if ad.startswith("SEVIYE_") and isinstance(deger, str)
    }
    eksik = sorted(seviyeler - set(_SEVIYE_GORUNUM))
    assert not eksik, f"Bu seviyelerin arayüz görünümü yok: {eksik}"


def test_gorunumu_olup_artik_kullanilmayan_seviye_yok() -> None:
    seviyeler = {
        deger for ad, deger in vars(tr).items()
        if ad.startswith("SEVIYE_") and isinstance(deger, str)
    }
    fazla = sorted(set(_SEVIYE_GORUNUM) - seviyeler)
    assert not fazla, f"Bu seviyeler artık üretilmiyor: {fazla}"


def test_gecerli_ile_gecersiz_AYNI_renkte_degil() -> None:
    """Renk, metni okumadan verilen ilk karar."""
    renkler = {
        s: _SEVIYE_GORUNUM[s][1]
        for s in (tr.SEVIYE_GECERLI, tr.SEVIYE_GECERSIZ,
                  tr.SEVIYE_OKUNAMADI, tr.SEVIYE_DAMGASIZ)
    }
    assert len(set(renkler.values())) == 4, f"Renkler ayrışmıyor: {renkler}"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Menü bağlantısı
# ══════════════════════════════════════════════════════════════════════════════


def test_menu_maddesi_DOGRULAMAYI_cagiriyor(
    sahne, stamped: Path, monkeypatch: pytest.MonkeyPatch, _diyalogu_acma,
) -> None:
    """
    Arayüz ikinci bir doğrulama yazmıyor — CLI'ın çağırdığı fonksiyonun
    aynısını çağırıyor ve doğru yolla çağırıyor.
    """
    cagrilar: list[Path] = []
    gercek = verify_timestamp

    def _izle(path, **kw):
        cagrilar.append(Path(path))
        return gercek(path, **kw)

    import CORE.timestamp_verify as tv
    monkeypatch.setattr(tv, "verify_timestamp", _izle)

    sahne._on_ctx_verify_timestamp(7, str(stamped))
    assert cagrilar == [stamped]
    assert len(_diyalogu_acma) == 1


def test_diyalog_gercekten_KURULUYOR(sahne, stamped: Path, _diyalogu_acma) -> None:
    """
    `exec()` yamalı ama kurulum yamalı değil: eksik bir alan ya da None
    erişimi burada patlar.
    """
    sahne._on_ctx_verify_timestamp(7, str(stamped))
    dlg = _diyalogu_acma[0]
    assert dlg._mesaj.seviye == tr.SEVIYE_UYARI      # kök deposu boş
    assert dlg.windowTitle().endswith(stamped.name)


def test_yolsuz_dosyada_uyari_veriliyor(
    sahne, _diyalog_engelle, _diyalogu_acma,
) -> None:
    sahne._on_ctx_verify_timestamp(7, None)
    assert _diyalog_engelle and "Dosya yolu bulunamadı" in _diyalog_engelle[0][1]
    assert not _diyalogu_acma


def test_olmayan_dosyada_uyari_veriliyor(
    sahne, tmp_path: Path, _diyalog_engelle, _diyalogu_acma,
) -> None:
    sahne._on_ctx_verify_timestamp(7, str(tmp_path / "yok.hcl"))
    assert _diyalog_engelle and "Dosya bulunamadı" in _diyalog_engelle[0][1]
    assert not _diyalogu_acma


def test_beklenmedik_hata_arayuzu_COKERTMIYOR(
    sahne, stamped: Path, monkeypatch: pytest.MonkeyPatch,
    _diyalog_engelle, _diyalogu_acma,
) -> None:
    """
    `verify_timestamp()` beklenen hataları sonuca çeviriyor; buraya
    yalnızca okuma hatası gibi öngörülmeyen bir şey düşer. Yakalanmazsa
    pencere kapanırdı.
    """
    def _patla(*a, **kw):
        raise OSError("disk okunamadı")

    import CORE.timestamp_verify as tv
    monkeypatch.setattr(tv, "verify_timestamp", _patla)

    sahne._on_ctx_verify_timestamp(7, str(stamped))
    assert _diyalog_engelle and "disk okunamadı" in _diyalog_engelle[0][1]
    assert not _diyalogu_acma


def test_dogrulama_DENETIM_kaydina_gecıyor(
    sahne, stamped: Path, kayitlar, _diyalogu_acma,
) -> None:
    """
    Doğrulama bir kanıt sorgusudur; kimin ne zaman sorduğu, sonucun
    kendisi kadar kayda değer.
    """
    sahne._on_ctx_verify_timestamp(7, str(stamped))
    eylemler = [ad for ad, _ in kayitlar]
    assert "timestamp_verified" in eylemler
    detay = dict(kayitlar[0][1])["detail"]
    assert "valid=True" in detay
    assert "anchor_trusted=False" in detay


def test_denetim_kaydi_dusse_bile_sonuc_GOSTERILIYOR(
    sahne, stamped: Path, monkeypatch: pytest.MonkeyPatch, _diyalogu_acma,
) -> None:
    """
    Kayıt yan iş; kullanıcının sorusunu yanıtsız bırakamaz.
    """
    class _KirikDB:
        def log(self, *a, **kw):
            raise RuntimeError("db kilitli")

    import UI.main_window_files as mwf
    monkeypatch.setattr(mwf, "DBManager", _KirikDB)

    sahne._on_ctx_verify_timestamp(7, str(stamped))
    assert len(_diyalogu_acma) == 1


# ══════════════════════════════════════════════════════════════════════════════
# 5. Sağ tık menüsü — madde gerçekten BAĞLI mı
# ══════════════════════════════════════════════════════════════════════════════
#
# Yukarıdaki testler işleyiciyi doğrudan çağırıyor. Menüyü atlamak, bu
# deponun tam olarak bildiği bir kusuru gözden kaçırırdı: maddeyi eklemek
# ama gönderim (`elif action == ...`) satırını unutmak. Menüde görünen ama
# hiçbir şey yapmayan bir madde, olmayan bir maddeden kötüdür.

_TS_MADDE = "🕓  Damgayı Doğrula"


class _MenuluSahne(FileActionsMixin, QWidget):
    """`_on_context_menu`'nun dokunduğu asgari yüzey."""

    def __init__(self, rol: str, etiket: str, dosya_yolu: str) -> None:
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

        super().__init__()
        self._hwid = _HWID
        self._role = rol
        self._checkouts: dict[int, object] = {}
        self._T = {
            "topbar": "#fff", "text": "#000", "border": "#ccc",
            "accent_tint": "#eff6ff", "tint_text": "#111827",
        }
        self._table = QTableWidget(1, 1, self)
        oge = QTableWidgetItem("belge")
        oge.setData(Qt.UserRole, 7)
        oge.setData(Qt.UserRole + 2, etiket)
        oge.setData(Qt.UserRole + 3, dosya_yolu)
        self._table.setItem(0, 0, oge)
        self.dogrulanan: list[tuple[int | None, str | None]] = []

    def _on_ctx_verify_timestamp(self, file_id, filepath) -> None:
        self.dogrulanan.append((file_id, filepath))


def _menuden_sec(
    sahne: _MenuluSahne, madde: str, monkeypatch: pytest.MonkeyPatch
) -> list[str]:
    """Menüyü açar, adı verilen maddeyi seçer; menüdeki tüm başlıkları döner.

    `exec()` devre dışı bırakılmak ZORUNDA: offscreen platformda bile
    modaldır ve tıklayacak kimse olmadığı için test asılır (ölçüldü —
    ilk yazımda 120 sn zaman aşımına gitti).

    Yöntem ALT SINIF, `monkeypatch.setattr(QMenu, "exec", ...)` DEĞİL:
    Shiboken tipinde sınıf özniteliğine yazmak sessizce etkisiz kalıyor
    ve gerçek modal menü yine açılıyor. Ölçüldü; ikisi de denendi.
    """
    from PySide6.QtCore import QPoint
    from PySide6.QtWidgets import QMenu

    gorulen: list[str] = []

    class _SahteMenu(QMenu):
        def exec(self, *a, **kw):
            gorulen.extend(e.text() for e in self.actions() if not e.isSeparator())
            for eylem in self.actions():
                if eylem.text() == madde:
                    return eylem
            return None

    import UI.main_window_files as mwf
    monkeypatch.setattr(mwf, "QMenu", _SahteMenu)
    sahne._on_context_menu(QPoint(1, 1))
    return gorulen


@pytest.mark.parametrize("etiket", ["Genel", "Kritik", "Karantina", "Imha"])
def test_madde_HER_etikette_var_ve_dogrulamayi_tetikliyor(
    qapp, stamped: Path, etiket: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    İmha Odası dahil: bir dosyanın "şu tarihte vardı" kanıtına en çok
    ihtiyaç duyulan an, silinmek üzere olduğu andır.
    """
    sahne = _MenuluSahne("Yönetici", etiket, str(stamped))
    gorulen = _menuden_sec(sahne, _TS_MADDE, monkeypatch)
    assert _TS_MADDE in gorulen, f"{etiket} etiketinde madde yok"
    assert sahne.dogrulanan == [(7, str(stamped))]


def test_SALT_OKUNUR_rol_menuyu_hic_acmiyor(
    qapp, stamped: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    MEVCUT davranış, bilerek değiştirilmedi: sağ tık menüsünün tamamı
    salt okunur rolde kapalı ve damga doğrulama da onunla birlikte
    kapalı kalıyor.

    Doğrulama bir OKUMA — kapalı olması tartışılır. Ama menüyü bu rol
    için açmak, yıkıcı maddelerin sızmadığını ayrıca kanıtlamayı
    gerektirir ve bu deponun beş kez yakaladığı kusur sınıfı tam olarak
    budur (B-007: dört görünümden ikisi filtresizdi). Kapsam dışı
    tutuldu ve BACKLOG'a B-034 olarak yazıldı.

    Bu test kararı sabitliyor: davranış değişirse burası düşer ve
    değişikliğin bilinçli olması gerekir.
    """
    sahne = _MenuluSahne("Salt Okunur", "Genel", str(stamped))
    gorulen = _menuden_sec(sahne, _TS_MADDE, monkeypatch)
    assert gorulen == []
    assert sahne.dogrulanan == []
