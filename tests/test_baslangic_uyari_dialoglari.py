"""
HYCLEUS — açılış uyarı diyaloglarının metni (B-120)

Bulgu: "Denetim Çıpası Kopyaları Uyuşmuyor" ve "Kurtarma Parçası Alınmamış"
uyarıları kullanıcıyı gereksiz korkutuyordu — "bu bir erişim engeli değildir"
cümlesi metnin SONUNDA, teknik `last_hash` gibi alanlar ise doğrudan ana
metnin İÇİNDE duruyordu.

Bu dosya `main.py`'deki iki yardımcıyı (`_cipa_kopyalari_uyari_dialogu()`,
`_kurtarma_parcasi_uyari_dialogu()`) DOĞRUDAN çağırıp döndürdükleri
`QMessageBox`'ın METNİNİ doğruluyor — `main()`'in kendisi (QApplication/USB/
login akışı) hiç çalıştırılmıyor, yalnızca bu iki saf-fonksiyon.

Not: `main.py`'nin geri kalanı (B-015 yedek hatırlatması gibi) bu deponun
yerleşik kuralı gereği AST üzerinden denetleniyor (bkz.
`tests/test_backup_reminder.py`'nin "GÖSTERİM" bölümü) — bu iki yardımcı
GERÇEKTEN bir QMessageBox nesnesi döndürdüğü ve yan etkisi olmadığı için
(exec() ÇAĞIRMIYORLAR) doğrudan çağırmak daha basit ve daha güçlü bir kanıt.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication

    import main
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

_ERISIM_ENGELI_DEGIL = "Bu bir erişim engeli değildir"


@pytest.fixture
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


# ── Denetim Çıpası Kopyaları Uyuşmuyor ────────────────────────────────────────


def test_cipa_dialogu_baslik_dogru(qapp) -> None:
    kutu = main._cipa_kopyalari_uyari_dialogu("özet metni")
    assert kutu.windowTitle() == "Denetim Çıpası Kopyaları Uyuşmuyor"


def test_cipa_dialogu_erisim_engeli_cumlesi_EN_BASTA(qapp) -> None:
    """Kullanıcıyı ÖNCE sakinleştirmeli, teknik ayrıntıya sonra geçmeli."""
    kutu = main._cipa_kopyalari_uyari_dialogu("özet metni")
    metin = kutu.text()
    assert metin.startswith(_ERISIM_ENGELI_DEGIL), (
        f"'{_ERISIM_ENGELI_DEGIL}' cümlesi metnin EN BAŞINDA olmalı, "
        f"bulunduğu yer: {metin.find(_ERISIM_ENGELI_DEGIL)}"
    )


def test_cipa_dialogu_teknik_ozet_ana_metinde_DEGIL_ayrintida(qapp) -> None:
    """`last_hash` gibi teknik alanları taşıyan özet ana metne GÖMÜLMEMELİ —
    `setDetailedText()` arkasında, Qt'nin "Ayrıntıları Göster..." düğmesiyle
    açılmalı."""
    ozet = "last_hash: yerel 'aaaa', USB 'bbbb'; entry_count: yerel 1, USB 2"
    kutu = main._cipa_kopyalari_uyari_dialogu(ozet)
    assert ozet not in kutu.text()
    assert kutu.detailedText() == ozet


def test_cipa_dialogu_kurcalama_kelimesi_gecer(qapp) -> None:
    """Kısaltma bilgi kaybına yol açmamalı — "kurcalama" hâlâ ana metinde."""
    kutu = main._cipa_kopyalari_uyari_dialogu("özet metni")
    assert "kurcalama" in kutu.text()


# ── Kurtarma Parçası Alınmamış ─────────────────────────────────────────────────


def test_kurtarma_dialogu_baslik_dogru(qapp) -> None:
    kutu = main._kurtarma_parcasi_uyari_dialogu()
    assert kutu.windowTitle() == "Kurtarma Parçası Alınmamış"


def test_kurtarma_dialogu_erisim_engeli_cumlesi_EN_BASTA(qapp) -> None:
    kutu = main._kurtarma_parcasi_uyari_dialogu()
    metin = kutu.text()
    assert metin.startswith(_ERISIM_ENGELI_DEGIL), (
        f"'{_ERISIM_ENGELI_DEGIL}' cümlesi metnin EN BAŞINDA olmalı, "
        f"bulunduğu yer: {metin.find(_ERISIM_ENGELI_DEGIL)}"
    )


def test_kurtarma_dialogu_export_komutu_hala_gorunur(qapp) -> None:
    """Bu kutuda gizlenecek teknik/hash bilgisi yok — eylem talimatı
    (`--export`) doğrudan ana metinde kalmalı, ayrıntı arkasına GİZLENMEMELİ."""
    kutu = main._kurtarma_parcasi_uyari_dialogu()
    assert "python CORE/recover_vault.py --export" in kutu.text()
    assert kutu.detailedText() == ""
