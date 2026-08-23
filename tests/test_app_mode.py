"""
CORE.app_mode — Bireysel/Kurumsal görünüm modu

Bu modül YALNIZCA bir UI filtresi taşıdığını iddia ediyor; bu paket
tam olarak onu ölçüyor:

  1. get/set çift yönlü çalışıyor, `settings` tablosuna yazıyor.
  2. Bozuk/tanınmayan bir değer sessizce KURUMSAL'a düşüyor (hiçbir şeyi
     gizlememe yönünde bir varsayılan — güvenli taraf).
  3. Modül hiçbir RBAC ilkel'ini (CORE.roles, CORE.vault_manager) İTHAL
     ETMİYOR — "yalnızca görünürlük" iddiasının statik kanıtı.
  4. Migration 22 var olan VE yeni veritabanlarında varsayılanı yazıyor.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from CORE import app_mode as AM
from DB.db_manager import DBManager

KOK = Path(__file__).resolve().parent.parent


@pytest.fixture
def gercek_db(tmp_path: Path):
    DBManager._instance = None  # type: ignore[attr-defined]
    db = DBManager(tmp_path / "mod.db")
    db.connect(hwid="TEST-HWID-MODE")
    yield db
    db.close()
    DBManager._instance = None  # type: ignore[attr-defined]


# ══════════════════════════════════════════════════════════════════════════════
# 1. get/set
# ══════════════════════════════════════════════════════════════════════════════


def test_yeni_kurulum_varsayilan_KURUMSAL(gercek_db) -> None:
    """Migration 22 varsayılanı yazıyor: hiçbir şey gizlenmemiş başlar."""
    assert AM.get_app_mode(gercek_db) == AM.KURUMSAL


def test_set_sonra_get_AYNI_degeri_donuyor(gercek_db) -> None:
    AM.set_app_mode(gercek_db, AM.BIREYSEL)
    assert AM.get_app_mode(gercek_db) == AM.BIREYSEL

    AM.set_app_mode(gercek_db, AM.KURUMSAL)
    assert AM.get_app_mode(gercek_db) == AM.KURUMSAL


def test_set_settings_tablosuna_yaziyor(gercek_db) -> None:
    AM.set_app_mode(gercek_db, AM.BIREYSEL)
    row = gercek_db.fetchone(
        "SELECT value FROM settings WHERE key = ?", (AM.APP_MODE_SETTING,)
    )
    assert row is not None and row["value"] == AM.BIREYSEL


def test_set_gecersiz_mod_reddediliyor(gercek_db) -> None:
    with pytest.raises(ValueError):
        AM.set_app_mode(gercek_db, "yarim-zamanli")
    # Reddedilen bir yazma, mevcut değeri BOZMAMALI.
    assert AM.get_app_mode(gercek_db) == AM.KURUMSAL


def test_bozuk_deger_KURUMSALA_duser(gercek_db) -> None:
    """Elle/dış müdahaleyle yazılmış tanınmayan bir değer — güvenli tarafa düş."""
    gercek_db.set_setting(AM.APP_MODE_SETTING, "cop-veri")
    assert AM.get_app_mode(gercek_db) == AM.KURUMSAL


def test_set_denetim_kaydina_dusuyor(gercek_db) -> None:
    AM.set_app_mode(gercek_db, AM.BIREYSEL, hwid="ABC-123")
    row = gercek_db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'app_mode_changed'"
        " ORDER BY id DESC LIMIT 1"
    )
    assert row is not None
    assert "value=bireysel" in row["detail"]
    assert "hwid=ABC-123" in row["detail"]


# ══════════════════════════════════════════════════════════════════════════════
# 2. "Yalnızca görünürlük, RBAC değil" — statik kanıt
# ══════════════════════════════════════════════════════════════════════════════


def test_modul_RBAC_ithal_ETMIYOR() -> None:
    """
    CORE/app_mode.py'nin kendi iddiası: mod, yetkiye karışmıyor.

    AST ile ölçülüyor (yorum satırına güvenmek yerine): modül
    CORE.roles ya da CORE.vault_manager'dan HİÇBİR ŞEY içe aktarmamalı.
    İthalat olsaydı, "yalnızca UI filtresi" iddiası doğrulanamaz olurdu.
    """
    kaynak = (KOK / "CORE" / "app_mode.py").read_text(encoding="utf-8")
    agac = ast.parse(kaynak)
    yasakli = {"CORE.roles", "CORE.vault_manager"}
    for dugum in ast.walk(agac):
        if isinstance(dugum, ast.ImportFrom) and dugum.module in yasakli:
            pytest.fail(f"CORE/app_mode.py {dugum.module}'dan içe aktarıyor")
        if isinstance(dugum, ast.Import):
            for takma in dugum.names:
                assert takma.name not in yasakli, (
                    f"CORE/app_mode.py {takma.name}'ı içe aktarıyor"
                )


def test_is_bireysel_yardimcisi() -> None:
    assert AM.is_bireysel(AM.BIREYSEL) is True
    assert AM.is_bireysel(AM.KURUMSAL) is False
