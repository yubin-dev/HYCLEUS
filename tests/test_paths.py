"""
CORE.paths — data dizini çözümlemesi.

Bu modülün hiç testi yoktu ve üç satırdı; AppImage ayağı eklenince
kritikleşti. Sebep: veri dizini kararı bir uygulama açılışında BİR KEZ ve
IMPORT ANINDA veriliyor. `_USB_IDS_FILE`, `_TOTP_FILE`, `_DEFAULT_DB_PATH`,
`_VAULT_DIR`, `_PIN_FILE` — hepsi modül seviyesinde `data_dir()` çağırıyor.
Yanlış bir cevabı sonradan düzeltme şansı yok; kasa yanlış yerde açılır.

AppImage'ın özelliği, o yanlışın SESSİZ olması: bağlama noktası salt okunur
ve her çalıştırmada değişiyor, yani uygulama ya yazamadığı için düşer ya da
(yazabildiği bir yer bulursa) verileri bir daha bulunamayacak bir yere
koyar.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from CORE import paths
from CORE.paths import APP_DIRNAME, APPIMAGE_ENV, XDG_DATA_HOME, data_dir, running_in_appimage


@pytest.fixture(autouse=True)
def _temiz_ortam(monkeypatch):
    """Gerçek ortamdaki XDG/APPIMAGE değişkenleri testlere sızmasın."""
    monkeypatch.delenv(APPIMAGE_ENV, raising=False)
    monkeypatch.delenv(XDG_DATA_HOME, raising=False)


def _dondur(monkeypatch, exe: Path) -> None:
    """PyInstaller yapısı taklidi."""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))


# ── Geliştirme ────────────────────────────────────────────────────────────────

def test_gelistirmede_proje_kokundeki_data():
    monkeypatch_yok = not hasattr(sys, "frozen")
    assert monkeypatch_yok, "test ortamı donmuş görünüyor"
    assert data_dir() == Path(paths.__file__).parent.parent / "data"


def test_gelistirmede_APPIMAGE_degiskeni_YOK_SAYILIYOR(monkeypatch):
    """
    Donmamış bir süreçte `APPIMAGE` tanımlıysa bu miras alınmış bir
    değişkendir (AppImage içinden başlatılan bir terminal gibi) — kendi
    kaynak ağacımızdan çalışıyoruz demektir.
    """
    monkeypatch.setenv(APPIMAGE_ENV, "/opt/HYCLEUS.AppImage")
    assert data_dir() == Path(paths.__file__).parent.parent / "data"


# ── Windows EXE — DEĞİŞMEMELİ ─────────────────────────────────────────────────

def test_donmus_yapida_EXE_yanindaki_data(monkeypatch, tmp_path):
    """Windows davranışı. AppImage ayağı bunu değiştirmemeli."""
    exe = tmp_path / "HYCLEUS.exe"
    _dondur(monkeypatch, exe)
    assert data_dir() == tmp_path / "data"


def test_donmus_ama_AppImage_degilse_yine_EXE_yani(monkeypatch, tmp_path):
    """Linux'ta AppImage dışı bir PyInstaller yapısı da eski kuralı izler."""
    _dondur(monkeypatch, tmp_path / "HYCLEUS")
    assert data_dir() == tmp_path / "data"


# ── AppImage ──────────────────────────────────────────────────────────────────

def test_appimagede_XDG_DATA_HOME_kullaniliyor(monkeypatch, tmp_path):
    _dondur(monkeypatch, Path("/tmp/.mount_abc123/usr/bin/HYCLEUS"))
    monkeypatch.setenv(APPIMAGE_ENV, "/opt/HYCLEUS.AppImage")
    monkeypatch.setenv(XDG_DATA_HOME, str(tmp_path / "xdg"))
    assert data_dir() == tmp_path / "xdg" / APP_DIRNAME


def test_appimagede_veri_baglama_noktasinin_DISINDA(monkeypatch, tmp_path):
    """
    Asıl mesele bu: bağlama noktası salt okunur ve her çalıştırmada
    değişiyor. Veri oraya giderse ya yazılamaz ya da bir daha bulunamaz.
    """
    baglama = Path("/tmp/.mount_XyZ999")
    _dondur(monkeypatch, baglama / "usr" / "bin" / "HYCLEUS")
    monkeypatch.setenv(APPIMAGE_ENV, "/opt/HYCLEUS.AppImage")
    monkeypatch.setenv(XDG_DATA_HOME, str(tmp_path / "xdg"))

    sonuc = data_dir()
    assert baglama not in sonuc.parents
    assert sonuc != baglama


def test_appimagede_XDG_yoksa_local_share(monkeypatch, tmp_path):
    _dondur(monkeypatch, Path("/tmp/.mount_abc/usr/bin/HYCLEUS"))
    monkeypatch.setenv(APPIMAGE_ENV, "/opt/HYCLEUS.AppImage")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "ev"))
    assert data_dir() == tmp_path / "ev" / ".local" / "share" / APP_DIRNAME


def test_goreli_XDG_DATA_HOME_yok_sayiliyor(monkeypatch, tmp_path):
    """
    XDG spesifikasyonu: mutlak olmayan değer YOK SAYILMALI. Kabul etmek,
    kasa verisini o anki çalışma dizinine yazmak olurdu — uygulamanın
    nereden başlatıldığına göre değişen bir kasa konumu.
    """
    _dondur(monkeypatch, Path("/tmp/.mount_abc/usr/bin/HYCLEUS"))
    monkeypatch.setenv(APPIMAGE_ENV, "/opt/HYCLEUS.AppImage")
    monkeypatch.setenv(XDG_DATA_HOME, "goreli/yol")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "ev"))
    assert data_dir() == tmp_path / "ev" / ".local" / "share" / APP_DIRNAME


def test_bos_XDG_DATA_HOME_yok_sayiliyor(monkeypatch, tmp_path):
    _dondur(monkeypatch, Path("/tmp/.mount_abc/usr/bin/HYCLEUS"))
    monkeypatch.setenv(APPIMAGE_ENV, "/opt/HYCLEUS.AppImage")
    monkeypatch.setenv(XDG_DATA_HOME, "")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "ev"))
    assert data_dir() == tmp_path / "ev" / ".local" / "share" / APP_DIRNAME


# ── running_in_appimage ───────────────────────────────────────────────────────

def test_running_in_appimage_degiskene_bakiyor(monkeypatch):
    assert running_in_appimage() is False
    monkeypatch.setenv(APPIMAGE_ENV, "/opt/HYCLEUS.AppImage")
    assert running_in_appimage() is True


def test_bos_APPIMAGE_degeri_sayilmiyor(monkeypatch):
    """Değişkenin tanımlı ama boş olması "AppImage'dayız" demek değil."""
    monkeypatch.setenv(APPIMAGE_ENV, "")
    assert running_in_appimage() is False


# ── Yol her zaman mutlak ──────────────────────────────────────────────────────

@pytest.mark.parametrize("appimage", [False, True])
def test_sonuc_her_zaman_mutlak(monkeypatch, tmp_path, appimage):
    """
    Göreli bir data dizini, uygulamanın hangi dizinden başlatıldığına göre
    değişen bir kasa demek olurdu.
    """
    _dondur(monkeypatch, tmp_path / "HYCLEUS")
    if appimage:
        monkeypatch.setenv(APPIMAGE_ENV, "/opt/HYCLEUS.AppImage")
        monkeypatch.setenv(XDG_DATA_HOME, str(tmp_path / "xdg"))
    assert data_dir().is_absolute()
