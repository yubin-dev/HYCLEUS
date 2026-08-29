"""
UI.GuvenlikView — üç doğrulamanın toplandığı üst seviye görünüm.

Asıl ölçülen şey: İKİ ÇAĞIRAN, TEK GÖVDE
-----------------------------------------
Eski giriş noktaları (sağ tık menüsü, hamburger, Yönetim Paneli)
KALDIRILMADI. Yani her doğrulama artık iki yerden çağrılıyor ve bu
deponun beş kez ürettiği kusurun (aynı iş için iki uygulama —
B-004/B-008, B-007, B-010, B-011, pay ayrıştırıcı) tam giriş koşulu.

Bu paket iki şeyi ayrı ayrı ölçüyor:

  · YAPISAL — `GuvenlikView` hiçbir doğrulamayı kendisi uygulamıyor;
    AST denetimi ikinci bir uygulamayı yakalıyor.
  · DAVRANIŞSAL — aynı dosya iki giriş noktasından doğrulandığında
    BİREBİR aynı sonuç nesnesi üretiliyor. Yapısal denetim tek başına
    yetmez: doğru fonksiyonu yanlış argümanla çağırmak da ayrışmadır.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

# QApplication kurulmadan ÖNCE, modül seviyesinde. Diğer Qt test
# dosyalarındaki desenin aynısı.
#
# Neden `setdefault` ve neden BURADA: bu dosya tek başına çalıştırıldığında
# (`pytest tests/test_trusted_roots.py`) değişken HİÇBİR yerde kurulmuyor —
# ölçüldü. Ekransız bir Linux'ta Qt varsayılan `xcb` eklentisini yükleyemez
# ve `qFatal` ile SÜRECİ ÖLDÜRÜR; ölçüldü, yakalanabilir bir istisna DEĞİL,
# yani aşağıdaki `try/except → pytest.skip` kurtarmaz.
#
# Tam pakette değişken başka bir modülün toplama anındaki yan etkisinden
# geliyor — yani bu dosya bugüne kadar KAZAYLA çalışıyordu.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from CORE.crypto import encrypt_file, generate_key
from CORE.timestamp import timestamp_file

# Qt ve UI içe aktarmaları TEK korumanın altında — diğer yedi UI test
# dosyasındaki desenin birebir aynısı.
#
# `importorskip("PySide6")` YETMİYOR: paket kurulu olsa bile alt modüller
# sistem kütüphanelerine bağlı (libEGL.so.1, libxkbcommon) ve çıplak bir
# Linux runner'ında import ImportError veriyor. Modül seviyesinde patlayan
# bir import pytest'te ATLAMA değil TOPLAMA HATASI olur (çıkış kodu 2) ve
# oturumu `Interrupted` ile bitirir — paketin geri kalanı hiç koşmaz.
#
# Bu dosya tam olarak böyle kırdı: run 32526378278, ubuntu-latest, pytest
# adımı 3 saniyede düştü, JUnit çıktısı 935 bayt. Aynı hata 297327f'te de
# yaşanmıştı (bkz. test_lock_overlay.py). B-047.
#
# Yukarıdaki `setdefault` bunun YERİNE GEÇMEZ: o, Qt yüklenebildiğinde
# hangi platformun seçileceğini belirler; bu blok Qt HİÇ yüklenemediğinde
# toplamanın çökmesini engelliyor. İki ayrı arıza, iki ayrı önlem.
try:
    from PySide6.QtWidgets import QApplication, QLabel, QWidget

    from UI.GuvenlikView import (
        GUVENLIK_SALT_OKUNURA_ACIK,
        SAYFA_ADI,
        GuvenlikView,
    )
    from UI.main_window_files import FileActionsMixin
    from UI.main_window_palette import _DARK
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

KOK = Path(__file__).resolve().parent.parent

_HWID = "GUV-TEST-HWID"
_USER = 3


@pytest.fixture
def qapp():  # type: ignore[no-untyped-def]
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


@pytest.fixture(autouse=True)
def _karantina(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "quarantine"
    out.mkdir(parents=True, exist_ok=True)
    import CORE.crypto as c
    monkeypatch.setattr(c, "_QUARANTINE_DIR", out, raising=False)


@pytest.fixture(autouse=True)
def _sahte_db(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict]]:
    """Denetim kayıtlarını toplayan sahte `DBManager` (test_timestamp_ui deseni)."""
    toplanan: list[tuple[str, dict]] = []

    class _SahteDB:
        def log(self, action: str, **kw) -> None:  # type: ignore[no-untyped-def]
            toplanan.append((action, kw))

        def fetchone(self, *a, **k):  # type: ignore[no-untyped-def]
            return None

    import UI.main_window_files as mwf
    monkeypatch.setattr(mwf, "DBManager", _SahteDB)
    return toplanan


class _Pencere(FileActionsMixin, QWidget):
    """`_on_ctx_verify_timestamp`'in dokunduğu asgari pencere yüzeyi."""

    def __init__(self) -> None:
        super().__init__()
        self._hwid = _HWID
        self._role = "Yönetici"
        self._T = _DARK
        self.yedek_cagrilari: list[dict] = []

    def _on_verify_backup(self, *, sade: bool = False) -> None:
        self.yedek_cagrilari.append({"sade": sade})

    def _open_slide_over(self, baslik: str, icerik) -> None:  # pragma: no cover — fixture değiştirir
        """Gerçek mekanizma `UI/main_window_layout.py::LayoutMixin`'de —
        `acilan` fixture'ı bunu yamalıyor."""
        raise NotImplementedError


@pytest.fixture
def pencere(qapp) -> _Pencere:  # type: ignore[no-untyped-def]
    return _Pencere()


@pytest.fixture
def gorunum(pencere: _Pencere) -> GuvenlikView:
    return GuvenlikView(pencere)


@pytest.fixture
def damgali(tmp_path: Path) -> Path:
    from tests.test_timestamp_ui import FakeTSA

    src = tmp_path / "belge.bin"
    src.write_bytes(b"damgali rapor " * 100)
    dst, _s, _a = encrypt_file(src, generate_key(), _USER, hwid=_HWID)
    timestamp_file(dst, transport=FakeTSA())
    return dst


@pytest.fixture
def acilan(monkeypatch: pytest.MonkeyPatch) -> list:  # type: ignore[type-arg]
    """
    `_Pencere._open_slide_over()` yamalı — açılan içerikler toplanıyor
    (slide-over turu — eskiden `TimestampDialog.exec` yamalıydı, artık
    `.exec()` yok çünkü diyalog `QDialog` değil `QWidget`).
    """
    from UI.TimestampDialog import TimestampDialog

    kutu: list[TimestampDialog] = []

    def _ac(self, baslik, icerik):  # type: ignore[no-untyped-def]
        kutu.append(icerik)

    monkeypatch.setattr(_Pencere, "_open_slide_over", _ac)
    return kutu


def _kaynak(yol: str) -> str:
    return (KOK / yol).read_text(encoding="utf-8")


def _cagri_adlari(kaynak: str, fonksiyon: str | None = None) -> set[str]:
    """Kaynaktaki (ya da tek bir fonksiyondaki) çağrı adları."""
    agac: ast.AST = ast.parse(kaynak)
    if fonksiyon:
        adaylar = [n for n in ast.walk(agac)
                   if isinstance(n, ast.FunctionDef) and n.name == fonksiyon]
        assert adaylar, f"{fonksiyon} bulunamadı"
        agac = adaylar[0]
    return {
        (d.func.attr if isinstance(d.func, ast.Attribute) else
         d.func.id if isinstance(d.func, ast.Name) else "")
        for d in ast.walk(agac) if isinstance(d, ast.Call)
    }


# ══════════════════════════════════════════════════════════════════════════════
# 1. Görünüm kuruluyor mu
# ══════════════════════════════════════════════════════════════════════════════


def test_uc_dogrulama_da_sayfada(gorunum: GuvenlikView) -> None:
    metinler = [lbl.text() for lbl in gorunum.findChildren(QLabel)]
    for ad in ("Damgayı Doğrula", "Yedek Doğrula", "Denetim Zincirini Doğrula"):
        assert ad in metinler, f"{ad} sayfada yok"


def test_uc_dugme_de_var(gorunum: GuvenlikView) -> None:
    from PySide6.QtWidgets import QPushButton

    adlar = {b.objectName() for b in gorunum.findChildren(QPushButton)}
    assert {"guvenlik_btn_damga_dogrula", "guvenlik_btn_yedek_dogrula",
            "guvenlik_btn_zincir_dogrula"} <= adlar


# ══════════════════════════════════════════════════════════════════════════════
# 2. TEK GÖVDE — yapısal
# ══════════════════════════════════════════════════════════════════════════════


def test_gorunum_dogrulamayi_KENDISI_uygulamiyor() -> None:
    """
    En önemli denetim. `GuvenlikView` bir doğrulama çağırırsa, o çağrı
    eski giriş noktasındakinden ayrı bir yol olurdu ve ikisi zamanla
    farklı davranırdı.
    """
    cagrilar = _cagri_adlari(_kaynak("UI/GuvenlikView.py"))
    yasak = {"verify_timestamp", "verify_backup", "zincir_raporu",
             "TimestampDialog", "BackupVerifyDialog"}
    assert not (cagrilar & yasak), (
        f"GuvenlikView doğrulamayı kendisi uyguluyor: {cagrilar & yasak}"
    )


def test_damga_ayni_metodu_cagiriyor() -> None:
    """Sağ tık menüsünün çağırdığı metodun AYNISI."""
    assert "_on_ctx_verify_timestamp" in _cagri_adlari(
        _kaynak("UI/GuvenlikView.py"), "_damga_dogrula")
    # Karşı taraf: menü de aynı metodu çağırıyor mu (kör denetim olmasın).
    assert "_on_ctx_verify_timestamp" in _cagri_adlari(
        _kaynak("UI/main_window_files.py"))


def test_yedek_ayni_metodu_cagiriyor() -> None:
    assert "_on_verify_backup" in _cagri_adlari(
        _kaynak("UI/GuvenlikView.py"), "_yedek_dogrula")
    assert "_on_verify_backup" in _cagri_adlari(_kaynak("UI/main_window.py"))


def test_zincir_gövdesi_AdminPanel_den_CIKARILDI() -> None:
    """
    Zincir doğrulaması Yönetim Paneli'nin metoduydu ve panel yalnızca
    yöneticiye açılıyor. Güvenlik sekmesinden çağrılabilmesi için gövde
    ortak bir yere taşındı; panel de artık oradan çağırıyor.
    """
    panel = _cagri_adlari(_kaynak("UI/AdminPanel.py"), "_on_verify_chain")
    assert panel == {"zinciri_dogrula"}, (
        f"AdminPanel zinciri hâlâ kendisi doğruluyor: {panel}"
    )
    assert "zinciri_dogrula" in _cagri_adlari(
        _kaynak("UI/GuvenlikView.py"), "_zincir_dogrula")

    # `zincir_raporu` YALNIZCA ortak gövdede çağrılmalı.
    for dosya in ("UI/AdminPanel.py", "UI/GuvenlikView.py"):
        assert "zincir_raporu" not in _cagri_adlari(_kaynak(dosya)), (
            f"{dosya} ikinci bir zincir doğrulaması kuruyor"
        )
    assert "zincir_raporu" in _cagri_adlari(_kaynak("UI/security_actions.py"))


def test_denetimler_GERCEKTEN_cagri_buluyor() -> None:
    """Boş küme dönen bir tarayıcı yukarıdakileri sessizce geçirirdi (B-024)."""
    cagrilar = _cagri_adlari(_kaynak("UI/GuvenlikView.py"))
    assert len(cagrilar) > 10, "tarayıcı kör"
    assert "getOpenFileName" in cagrilar


# ══════════════════════════════════════════════════════════════════════════════
# 3. TEK GÖVDE — davranışsal
# ══════════════════════════════════════════════════════════════════════════════
#
# Yapısal denetim "doğru fonksiyon çağrılıyor" diyor; bu blok "aynı
# cevabı veriyor" diyor. İkisi farklı sorular: doğru fonksiyonu yanlış
# argümanla çağırmak da ayrışmadır.


def test_iki_giris_noktasi_AYNI_sonucu_veriyor(
    pencere: _Pencere, gorunum: GuvenlikView, damgali: Path,
    acilan: list, monkeypatch: pytest.MonkeyPatch,  # type: ignore[type-arg]
) -> None:
    # ── Eski yol: sağ tık menüsü ─────────────────────────────────────────
    pencere._on_ctx_verify_timestamp(7, str(damgali))
    menuden = acilan[-1]._sonuc

    # ── Yeni yol: Güvenlik sekmesi (dosya seçici yamalı) ─────────────────
    monkeypatch.setattr(
        "UI.GuvenlikView.QFileDialog.getOpenFileName",
        staticmethod(lambda *a, **k: (str(damgali), "")))
    gorunum._damga_dogrula()
    sekmeden = acilan[-1]._sonuc

    assert len(acilan) == 2
    # `checks` bir liste; dataclass karşılaştırması onu da kapsıyor.
    assert menuden == sekmeden, "iki giriş noktası farklı sonuç üretti"
    assert menuden.valid == sekmeden.valid
    assert menuden.hashed_hex == sekmeden.hashed_hex
    assert menuden.anchor_trusted == sekmeden.anchor_trusted


def test_iki_giris_noktasi_da_DENETIM_kaydi_dusuyor(
    pencere: _Pencere, gorunum: GuvenlikView, damgali: Path,
    acilan: list, monkeypatch: pytest.MonkeyPatch,  # type: ignore[type-arg]
    _sahte_db: list,  # type: ignore[type-arg]
) -> None:
    """Kayıt giriş noktasına göre değişmemeli — aynı gövde, aynı kayıt."""
    pencere._on_ctx_verify_timestamp(7, str(damgali))
    monkeypatch.setattr(
        "UI.GuvenlikView.QFileDialog.getOpenFileName",
        staticmethod(lambda *a, **k: (str(damgali), "")))
    gorunum._damga_dogrula()

    eylemler = [ad for ad, _ in _sahte_db]
    assert eylemler == ["timestamp_verified", "timestamp_verified"]
    # İçerik de aynı olmalı — `target_id` dışında (menüde satır var,
    # sekmede yolla aranıyor ve bu testte DB sahte, yani None).
    a, b = (kw["detail"] for _ad, kw in _sahte_db)
    assert a == b


def test_dosya_secilmezse_HICBIR_SEY_olmuyor(
    gorunum: GuvenlikView, acilan: list, monkeypatch: pytest.MonkeyPatch,  # type: ignore[type-arg]
) -> None:
    """
    İptal SESSİZ olmalı — ne doğrulama diyaloğu ne de uyarı.

    İkinci kısım mutasyonla ölçüldü: erken `return` kaldırıldığında boş
    yol ana pencereye geçiyor ve o da "Dosya yolu bulunamadı" uyarısı
    açıyor. Yani kullanıcı dosya seçiciyi iptal ettiğinde bir hata kutusu
    görüyordu; "diyalog açılmadı" kontrolü bunu kaçırıyordu.
    """
    from PySide6.QtWidgets import QMessageBox

    uyarilar: list[str] = []
    monkeypatch.setattr(QMessageBox, "warning",
                        staticmethod(lambda *a, **k: uyarilar.append(a[2] if len(a) > 2 else "")))
    monkeypatch.setattr(
        "UI.GuvenlikView.QFileDialog.getOpenFileName",
        staticmethod(lambda *a, **k: ("", "")))
    gorunum._damga_dogrula()
    assert not acilan
    assert not uyarilar, f"iptal edilince uyarı çıktı: {uyarilar}"


def test_yedek_dogrulama_pencereye_DEVREDILIYOR(
    pencere: _Pencere, gorunum: GuvenlikView,
) -> None:
    gorunum._yedek_dogrula()
    assert pencere.yedek_cagrilari == [{"sade": False}]


# ══════════════════════════════════════════════════════════════════════════════
# 4. Basit / Gelişmiş
# ══════════════════════════════════════════════════════════════════════════════


def test_zincir_cagrisi_sade_bayragini_TASIYOR(
    gorunum: GuvenlikView, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Üçüncü doğrulamada da anahtar geçiyor mu — diğer ikisi ayrı ölçülüyor."""
    cagrilar: list[dict] = []
    monkeypatch.setattr("UI.security_actions.zinciri_dogrula",
                        lambda *a, **k: cagrilar.append(k))
    gorunum._zincir_dogrula()
    gorunum._mod_kutusu.setChecked(False)
    gorunum._zincir_dogrula()
    assert [c["sade"] for c in cagrilar] == [False, True]


def test_varsayilan_GELISMIS(gorunum: GuvenlikView) -> None:
    """
    Varsayılan, diyalogların BUGÜNKÜ hâli. Basit'i varsayılan yapmak,
    mevcut kullanıcıların gördüğü bilgiyi habersiz azaltırdı.
    """
    assert gorunum._gelismis is True
    assert gorunum.sade is False
    assert gorunum._mod_kutusu.isChecked()


def test_toggle_sade_bayragini_ceviriyor(gorunum: GuvenlikView) -> None:
    gorunum._mod_kutusu.setChecked(False)
    assert gorunum.sade is True
    gorunum._mod_kutusu.setChecked(True)
    assert gorunum.sade is False


def test_toggle_OTURUM_boyunca_hatirlaniyor(
    pencere: _Pencere, gorunum: GuvenlikView,
) -> None:
    """
    Tercih görünümün üzerinde duruyor; art arda çağrılarda korunuyor.
    Kalıcı ayara YAZILMIYOR — gerekçe modül başlığında (settings tablosu
    kurulum geneli, kullanıcı başına değil).
    """
    gorunum._mod_kutusu.setChecked(False)
    gorunum._yedek_dogrula()
    gorunum._yedek_dogrula()
    assert pencere.yedek_cagrilari == [{"sade": True}, {"sade": True}]
    assert gorunum.sade is True


def test_toggle_ipucu_metni_degisiyor(gorunum: GuvenlikView) -> None:
    """Anahtarın ne yaptığı, yalnızca kutucuğun adından anlaşılmamalı."""
    acik = gorunum._mod_ipucu.text()
    gorunum._mod_kutusu.setChecked(False)
    assert gorunum._mod_ipucu.text() != acik
    assert "yalnızca sonuç" in gorunum._mod_ipucu.text()


def test_sade_mod_diyalogda_AYRINTILARI_gizliyor(
    gorunum: GuvenlikView, damgali: Path, acilan: list,  # type: ignore[type-arg]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    `setHidden` kullanılıyor, `isVisible` DEĞİL: gösterilmemiş bir
    diyaloğun çocukları için `isVisible()` her zaman False ve o kontrol
    hiçbir şey ölçmezdi (bu depoda ölçüldü, B-003 turu).
    """
    monkeypatch.setattr(
        "UI.GuvenlikView.QFileDialog.getOpenFileName",
        staticmethod(lambda *a, **k: (str(damgali), "")))

    gorunum._mod_kutusu.setChecked(False)
    gorunum._damga_dogrula()
    sade_dlg = acilan[-1]
    assert sade_dlg._sade is True
    assert sade_dlg._gelismis, "gizlenecek blok bulunamadı — denetim kör"
    assert all(w.isHidden() for w in sade_dlg._gelismis)

    gorunum._mod_kutusu.setChecked(True)
    gorunum._damga_dogrula()
    tam_dlg = acilan[-1]
    assert tam_dlg._sade is False
    assert not any(w.isHidden() for w in tam_dlg._gelismis)


def test_sade_modda_SONUC_ve_OZET_duruyor(
    gorunum: GuvenlikView, damgali: Path, acilan: list,  # type: ignore[type-arg]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Basit mod bilgi SAKLAMIYOR — sonucu ve tek cümlelik özeti veriyor."""
    monkeypatch.setattr(
        "UI.GuvenlikView.QFileDialog.getOpenFileName",
        staticmethod(lambda *a, **k: (str(damgali), "")))
    gorunum._mod_kutusu.setChecked(False)
    gorunum._damga_dogrula()
    dlg = acilan[-1]

    gorunen = [lbl.text() for lbl in dlg.findChildren(QLabel)
               if not lbl.isHidden()]
    assert dlg._mesaj.baslik in gorunen
    assert dlg._mesaj.ozet in gorunen


def test_yedek_diyalogu_da_sade_modu_UYGULUYOR(qapp) -> None:  # type: ignore[no-untyped-def]
    """
    Damga diyaloğu ayrı ölçülüyor; yedek diyaloğunun aynı kuralı
    uyguladığı BURADA. İkisinden birinin anahtarı yok sayması, aynı
    sayfadan açılan iki pencerenin farklı davranması demek olurdu.
    """
    from CORE.backup import VerifyReport
    from UI.BackupVerifyDialog import BackupVerifyDialog

    rapor = VerifyReport(ok=True)
    sade = BackupVerifyDialog(rapor, Path("yedek"), sade=True)
    assert sade._gelismis, "gizlenecek blok yok — denetim kör"
    assert all(w.isHidden() for w in sade._gelismis)

    tam = BackupVerifyDialog(rapor, Path("yedek"), sade=False)
    assert not any(w.isHidden() for w in tam._gelismis)


def test_sade_modda_ONERI_de_duruyor() -> None:
    """
    BİLİNÇLİ sapma ve raporlandı: `oneri` bir ayrıntı değil, sonucun
    eyleme dönüşen yarısı ("bu dosyayı tarih kanıtı olarak KULLANMAYIN").
    Gizlemek sade modu varsayılandan daha TEHLİKELİ yapardı.
    """
    from CORE.timestamp_verify import TimestampVerification
    from UI.TimestampDialog import TimestampDialog

    sonuc = TimestampVerification(valid=False, failed_check="signature",
                                  reason="imza tutmuyor")
    dlg = TimestampDialog(sonuc, "belge.hcl", sade=True)
    assert dlg._mesaj.oneri, "bu senaryoda öneri olmalı — test kör"
    gorunen = [lbl.text() for lbl in dlg.findChildren(QLabel)
               if not lbl.isHidden()]
    assert any(dlg._mesaj.oneri in m for m in gorunen), (
        "sade modda öneri gizlenmiş — sade mod varsayılandan tehlikeli olur"
    )


def test_ESKI_giris_noktalari_GELISMIS_kaliyor(
    pencere: _Pencere, damgali: Path, acilan: list,  # type: ignore[type-arg]
) -> None:
    """
    Anahtar Güvenlik sayfasının görünüm tercihi; sağ tık menüsünün
    çıktısını DEĞİŞTİRMİYOR. "Mevcut giriş noktalarını kaldırma"
    talimatı, onları sessizce değiştirmemeyi de kapsıyor.
    """
    pencere._on_ctx_verify_timestamp(7, str(damgali))
    assert acilan[-1]._sade is False


# ══════════════════════════════════════════════════════════════════════════════
# 5. Rol kapısı — B-034, KARAR VERİLMEDİ
# ══════════════════════════════════════════════════════════════════════════════


def test_salt_okunura_KAPALI_sabitleniyor() -> None:
    """
    Bugünkü davranışı SABİTLİYOR, savunmuyor.

    Güvenlik sayfası salt okunur rolde gizli ve bu, mevcut kısıtlamayla
    tutarlılık için seçildi (B-034 açık kalmaya devam ediyor). Kullanıcı
    açılmasına karar verirse bu test düşer — yani değişiklik bilinçli
    olmak zorunda, tam olarak B-034'ün kendi test notundaki gerekçeyle.
    """
    assert GUVENLIK_SALT_OKUNURA_ACIK is False


def test_rol_kapisi_TEK_sabitten_okunuyor() -> None:
    """
    Kapıyı açmak TEK satır olmalı. İki yerde ayrı ayrı karar verilseydi,
    biri açılıp öteki kapalı kalırdı — bu deponun tanıdık kusuru.
    """
    kaynak = _kaynak("UI/main_window.py")
    agac = ast.parse(kaynak)
    # Metin sayımı DEĞİL — yorumlar ve import satırı da eşleşirdi (B-024).
    okumalar = [n for n in ast.walk(agac) if isinstance(n, ast.Name)
                and n.id == "GUVENLIK_SALT_OKUNURA_ACIK"]
    assert len(okumalar) == 1, (
        f"sabit {len(okumalar)} yerde okunuyor — karar tek yerde olmalı"
    )
    (fn,) = [n for n in ast.walk(agac)
             if isinstance(n, ast.FunctionDef) and n.name == "_apply_role_restrictions"]
    adlar = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert "GUVENLIK_SALT_OKUNURA_ACIK" in adlar


def test_B_034_notu_hala_duruyor() -> None:
    """
    Karar kullanıcıya bırakıldı; B-034 kapanmadı. Madde silinirse bu
    sayfanın rol kapısının gerekçesi de kaybolur.
    """
    backlog = _kaynak("BACKLOG.md")
    assert "## B-034" in backlog
    assert "UI/GuvenlikView.py" in backlog, (
        "B-034 notu bu turda eklenen sayfanın MODÜL YOLUNA atıf vermiyor — "
        "okuyan kişi kodun nerede olduğunu bulamaz"
    )
    assert "GUVENLIK_SALT_OKUNURA_ACIK" in backlog, (
        "notta kapının nasıl açılacağı yazmıyor"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 6. Sayfa geçişi
# ══════════════════════════════════════════════════════════════════════════════


def test_sayfa_adi_tek_kaynaktan() -> None:
    """Kenar çubuğu düğmesi ve üst bar aynı sabiti kullanmalı."""
    layout = _kaynak("UI/main_window_layout.py")
    pencere = _kaynak("UI/main_window.py")
    assert "_GUVENLIK_SAYFA_ADI" in layout and "_GUVENLIK_SAYFA_ADI" in pencere
    assert SAYFA_ADI == "Güvenlik"


def test_yigin_UC_sayfali() -> None:
    """
    `QStackedWidget` — ayrı pencere DEĞİL. Tablo ve arama durumu yerinde
    kalıyor; ayrı pencere olsaydı durum ya kopyalanır ya kaybolurdu.

    2026-08-29: üçüncü sayfa (`UI/AuditLogView.py`, eskiden
    `AuditLogDialog` — modal'dan tam sayfaya taşındı) eklendi; bu test
    ikiden üçe güncellendi (bkz. `tests/test_audit_log_view.py` için
    AuditLogView'a ÖZGÜ testler).

    2026-08-30: dördüncü sayfa (`UI/ProfileView.py`, eskiden
    `ProfileDialog` — modal'dan tam sayfaya taşındı) eklendi; üçten
    dörde güncellendi (bkz. `tests/test_profile_view.py` için
    ProfileView'a ÖZGÜ testler).
    """
    layout = _kaynak("UI/main_window_layout.py")
    cagrilar = _cagri_adlari(layout, "_make_govde_yigini")
    assert {"QStackedWidget", "GuvenlikView", "AuditLogView", "ProfileView"} <= cagrilar

    # Sayfaların GERÇEKTEN eklendiği ölçülüyor. Mutasyonla görüldü:
    # `GuvenlikView` kurulup yığına EKLENMEZSE yukarıdaki çağrı denetimi
    # yine geçiyordu — sayfa nesnesi var, sayfa yok.
    agac = ast.parse(layout)
    (fn,) = [n for n in ast.walk(agac)
             if isinstance(n, ast.FunctionDef) and n.name == "_make_govde_yigini"]
    eklemeler = [
        d for d in ast.walk(fn)
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
        and d.func.attr == "addWidget"
        and isinstance(d.func.value, ast.Attribute)
        and d.func.value.attr == "_govde_yigini"
    ]
    assert len(eklemeler) == 4, (
        f"yığına {len(eklemeler)} sayfa ekleniyor, 4 bekleniyordu"
    )


def test_gecis_eylem_barini_gizleyip_geri_getiriyor() -> None:
    """
    Güvenlik sayfasında "Dosya Ekle" düğmesinin karşılığı yok; görünür
    bırakmak, tıklandığında geri dönmeyen bir düğme demek olurdu.
    """
    kaynak = _kaynak("UI/main_window.py")
    agac = ast.parse(kaynak)
    (guv,) = [n for n in ast.walk(agac)
              if isinstance(n, ast.FunctionDef) and n.name == "_on_guvenlik_click"]
    (dosya,) = [n for n in ast.walk(agac)
                if isinstance(n, ast.FunctionDef) and n.name == "_on_sidebar_click"]

    def _gizleme_degerleri(fn: ast.FunctionDef) -> set[bool]:
        return {
            d.args[0].value
            for d in ast.walk(fn)
            if isinstance(d, ast.Call)
            and isinstance(d.func, ast.Attribute)
            and d.func.attr == "setVisible"
            and isinstance(d.func.value, ast.Attribute)
            and d.func.value.attr == "_action_bar"
            and d.args and isinstance(d.args[0], ast.Constant)
        }

    assert _gizleme_degerleri(guv) == {False}, "Güvenlik'e geçerken bar gizlenmiyor"
    assert _gizleme_degerleri(dosya) == {True}, "dosya görünümünde bar geri gelmiyor"
