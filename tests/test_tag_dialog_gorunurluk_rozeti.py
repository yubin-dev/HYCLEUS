"""
HYCLEUS — Etiket Ata: satır başına görünürlük rozeti (`UI/TagDialog.py`)

Mevcut "Mahrem (gizli)" checkbox mantığına (yalnızca Yönetici gizli
etiketleri görebilir/oluşturabilir — `TagDialog._load_tags`'teki
`tag["is_private"] and not self._is_admin` filtresi) DOKUNULMADI. Bu
paket yalnızca yeni, görsel rozetin (`_gorunurluk_rozeti`) doğru metni/
rengi ürettiğini ölçüyor: gizli bir etiket "Yalnızca Yönetici", normal
bir etiket "Herkes" göstermeli.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QLabel

    from UI.main_window_palette import _DARK
    from UI.TagDialog import TagDialog, _gorunurluk_rozeti
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


def _rozetleri_bul(dlg: TagDialog) -> list[QLabel]:
    return dlg.findChildren(QLabel, "etiket_gorunurluk_rozeti")


# ══════════════════════════════════════════════════════════════════════════════
# 1. Saf birim — `_gorunurluk_rozeti` doğru metni/rengi üretiyor mu
# ══════════════════════════════════════════════════════════════════════════════


def test_mahrem_rozeti_YALNIZCA_YONETICI_gosterir(qapp):
    rozet = _gorunurluk_rozeti(True, _DARK)
    assert rozet.text() == "Yalnızca Yönetici"
    assert rozet.property("mahrem") is True


def test_normal_rozeti_HERKES_gosterir(qapp):
    rozet = _gorunurluk_rozeti(False, _DARK)
    assert rozet.text() == "Herkes"
    assert rozet.property("mahrem") is False


def test_iki_rozet_FARKLI_renkte(qapp):
    """Mutasyon kanıtı yerine geçen ayrım testi: mahrem/normal rozetleri
    aynı stylesheet'i üretmemeli, yoksa görsel ayrım yok demektir."""
    mahrem = _gorunurluk_rozeti(True, _DARK)
    normal = _gorunurluk_rozeti(False, _DARK)
    assert mahrem.styleSheet() != normal.styleSheet()


def test_rozet_YENI_renk_icat_etmiyor_T_token_kullaniyor(qapp):
    """Renk kaynağı `self._T` (B-055 deseni) — rozetin ürettiği stylesheet
    T'nin KENDİ token değerlerini (hardcode edilmiş hex değil) içermeli."""
    mahrem = _gorunurluk_rozeti(True, _DARK)
    normal = _gorunurluk_rozeti(False, _DARK)
    assert _DARK["red"] in mahrem.styleSheet()
    assert _DARK["red_tint"] in mahrem.styleSheet()
    assert _DARK["green"] in normal.styleSheet()
    assert _DARK["green_tint"] in normal.styleSheet()


# ══════════════════════════════════════════════════════════════════════════════
# 2. Uçtan uca — gerçek TagDialog, gerçek etiket listesi
# ══════════════════════════════════════════════════════════════════════════════


def test_diyalogda_gizli_etiket_YALNIZCA_YONETICI_rozetiyle_gorunur(qapp, db):
    db.execute(
        "INSERT INTO tags (name, color, is_private) VALUES ('Gizli-Proje', '#f00', 1)"
    )
    dlg = TagDialog(file_id=1, role="Yönetici", T=_DARK)
    try:
        rozetler = {r.text(): r for r in _rozetleri_bul(dlg)}
        assert "Yalnızca Yönetici" in rozetler
        assert rozetler["Yalnızca Yönetici"].property("mahrem") is True
    finally:
        dlg.close()


def test_diyalogda_normal_etiket_HERKES_rozetiyle_gorunur(qapp, db):
    db.execute(
        "INSERT INTO tags (name, color, is_private) VALUES ('Genel-Etiket', '#0f0', 0)"
    )
    dlg = TagDialog(file_id=1, role="Yönetici", T=_DARK)
    try:
        rozetler = {r.text(): r for r in _rozetleri_bul(dlg)}
        assert "Herkes" in rozetler
        assert rozetler["Herkes"].property("mahrem") is False
    finally:
        dlg.close()


def test_diyalogda_karisik_liste_HER_SATIR_dogru_rozeti_tasir(qapp, db):
    """Aynı diyalogda hem gizli hem normal etiket varken satırlar
    KARIŞMIYOR — her satırın rozeti KENDİ `is_private` değerini
    yansıtıyor (indeks kaymasına karşı kanıt)."""
    db.execute("INSERT INTO tags (name, color, is_private) VALUES ('Herkese-Acik', '#0f0', 0)")
    db.execute("INSERT INTO tags (name, color, is_private) VALUES ('Sadece-Yonetici', '#f00', 1)")
    dlg = TagDialog(file_id=1, role="Yönetici", T=_DARK)
    try:
        rozet_metinleri = sorted(r.text() for r in _rozetleri_bul(dlg))
        assert rozet_metinleri == ["Herkes", "Yalnızca Yönetici"]
    finally:
        dlg.close()


def test_gizli_etiket_normal_kullaniciya_HIC_GOSTERILMIYOR(qapp, db):
    """Mevcut yetki mantığı (satırın kendisi filtreleniyor, sadece rozeti
    değil) DEĞİŞMEDİ — normal kullanıcı gizli etiketin satırını hiç
    görmüyor, dolayısıyla rozetini de görmüyor."""
    db.execute(
        "INSERT INTO tags (name, color, is_private) VALUES ('Gizli-Proje', '#f00', 1)"
    )
    dlg = TagDialog(file_id=1, role="Kullanıcı", T=_DARK)
    try:
        rozet_metinleri = [r.text() for r in _rozetleri_bul(dlg)]
        assert "Yalnızca Yönetici" not in rozet_metinleri
    finally:
        dlg.close()
