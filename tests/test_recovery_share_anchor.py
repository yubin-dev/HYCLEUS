"""
UI.security_actions.kurtarma_parcasini_goster() — B-104: kurtarma parçasının
her görüntülenmesi, silinemez bir uyarı olarak denetim çıpasına (B-090'ın
yerel + USB çift-yazımı) anında kazınıyor.

Bu dosya `tests/test_audit_chain.py`'nin `verify_anchor_replicas()` testleriyle
AYNI deseni izliyor (bkz. `test_verify_anchor_replicas_catches_local_copy_
tampered`) — tek fark, çıpayı elle `write_anchor()` çağırarak değil, GERÇEK
`kurtarma_parcasini_goster()`'i (mocked yalnızca Qt diyalogları/rol kapısı)
uçtan uca çalıştırarak üretmek.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from CORE import vault_manager
from CORE.audit_chain import anchor_path, read_anchors, verify_anchor_replicas
from CORE.paths import TEST_DATA_DIR_ENV
from CORE.vault_manager import create_vault

# QApplication kurulmadan ÖNCE (B-046).
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Qt ve UI TEK korumanın altında (B-047) — çıplak bir Linux koşucusunda
# PySide6/UI import hatası ImportError verir; bu OLMADAN pytest TOPLAMA
# HATASIYLA durur (çıkış kodu 2) ve paketin geri kalanı hiç koşmaz.
try:
    from PySide6.QtWidgets import QApplication

    from UI import admin_common, security_actions
    from UI.security_actions import EYLEM_KURTARMA_GORUNTULENDI, kurtarma_parcasini_goster
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

#: `db` fixture (tests/conftest.py) HER ZAMAN bu hwid'le bağlanıyor —
#: `write_anchor()`'ın Katman-1 çapraz-doğrulaması (`_usb_hwid_dogrulanmis_mi`,
#: bkz. o fonksiyonun docstring'i) `source` bir DBManager'sa doğrudan
#: `source._hwid` ile `get_usb_hwid()`'in bulduğu hwid'i karşılaştırıyor —
#: ikisi UYUŞMAZSA USB kopyası (haklı olarak) YAZILMAZ. Vault'u ve sahte
#: USB'yi de AYNI hwid'le kurmak bu üçünü hizalıyor.
_HWID = "TEST-HWID-DB"
_PIN = "cipa-pin-12345"
_ROLE = "Yönetici"


@pytest.fixture(scope="module")
def qapp():  # type: ignore[no-untyped-def]
    yield QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _cipa_izolasyonu(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`anchor_path()`'in GERÇEK `data/` dizinine değil `tmp_path`'e
    yazmasını sağlar (B-067) — bu OLMADAN `_kaydet_ve_cipaya_kazi()`'nin
    `write_anchor()` çağrısı (path= VERMİYOR, bilerek — üretimdeki tek
    çağrı yeriyle AYNI, bkz. o fonksiyonun docstring'i) depodaki gerçek
    `data/audit_anchor.log`'a yazardı."""
    monkeypatch.setenv(TEST_DATA_DIR_ENV, str(tmp_path / "data"))


@pytest.fixture
def vault(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    create_vault(_HWID, _PIN, _ROLE)
    return _HWID


@pytest.fixture
def usb_takili(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, vault: str) -> Path:
    """
    "USB takılı" durumunu simüle eder — `tests/test_audit_chain.py::
    sahte_usb_anchor` ile AYNI desen. `usb_tokens` satırı burada AYRICA
    eklenmiyor: `create_vault()` (yukarıdaki `vault` fixture'ı) zaten
    GERÇEK bir satır yazdı.
    """
    from CORE import usb_manager

    kok = tmp_path / "sahte_usb_koku"
    kok.mkdir()
    monkeypatch.setattr(usb_manager, "get_usb_hwid", lambda: vault)
    monkeypatch.setattr(usb_manager, "get_usb_mount_root", lambda hwid: kok)
    return kok


def _usb_capa_yolu(kok: Path) -> Path:
    return kok / "HYCLEUS" / "audit_anchor.log"


class _SahteDiyalog:
    """`RecoveryShareDialog` yerine — gerçek bir pencere AÇMADAN `.exec()`'i yutar."""

    def __init__(self, *args, **kwargs) -> None:
        pass

    def exec(self) -> None:
        return None


def _goster(monkeypatch: pytest.MonkeyPatch, vault: str) -> None:
    """`kurtarma_parcasini_goster()`'i GERÇEK gövdesiyle çalıştırır —
    yalnızca Qt diyalogları ve canlı-yetki kapısı sahtelendi."""
    monkeypatch.setattr(admin_common, "yonetici_hala_yetkili", lambda *a, **k: True)
    monkeypatch.setattr(
        security_actions, "QInputDialog",
        SimpleNamespace(getText=lambda *a, **k: (_PIN, True)),
    )
    # İKİNCİ (ve sonraki) görüntülemede has_recovery_share() True döner ve
    # gövde "aynı payı yeniden mi göstereyim" diye SORAR — gerçek bir
    # QMessageBox.question() burada kullanıcı TIKLAMADIĞI için SONSUZA
    # KADAR BLOKLAR (ölçüldü: pytest-timeout ilk denemede bunu yakaladı).
    # Sabit Yes yanıtı — testin sorduğu soru zaten "kaç kez görüntülense
    # de her seferinde çıpalanıyor mu", bu onayın KENDİSİ değil.
    monkeypatch.setattr(
        security_actions, "QMessageBox",
        SimpleNamespace(
            question=lambda *a, **k: security_actions.QMessageBox.Yes,
            critical=lambda *a, **k: None,
            Yes=security_actions.QMessageBox.Yes,
            No=security_actions.QMessageBox.No,
        ),
    )
    monkeypatch.setattr(
        "UI.RecoveryShareDialog.RecoveryShareDialog", _SahteDiyalog
    )
    pencere = SimpleNamespace(_hwid=vault, _T=lambda s: s)
    kurtarma_parcasini_goster(None, pencere)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Görüntüleme → audit_log VE her iki çıpa kopyası
# ══════════════════════════════════════════════════════════════════════════════


def test_viewing_the_share_is_written_to_the_audit_log(
    qapp, db, vault: str, usb_takili: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _goster(monkeypatch, vault)

    satir = db.fetchone(
        "SELECT * FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1",
        (EYLEM_KURTARMA_GORUNTULENDI,),
    )
    assert satir is not None, "kurtarma parçası görüntülemesi audit_log'a düşmedi"
    assert satir["entry_hash"], "kayıt hash zincirine katılmamış (unhashed)"
    assert vault in (satir["detail"] or "")


def test_viewing_the_share_anchors_the_local_copy(
    qapp, db, vault: str, usb_takili: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _goster(monkeypatch, vault)

    kayitlar = read_anchors(anchor_path())
    assert kayitlar, "yerel çıpa dosyası hiç yazılmadı"
    assert kayitlar[-1]["reason"] == EYLEM_KURTARMA_GORUNTULENDI


def test_viewing_the_share_ALSO_anchors_the_usb_copy(
    qapp, db, vault: str, usb_takili: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ASIL TEST — iki kopyaya da (B-090). USB olmadan bu bir çıpa DEĞİL,
    tek bir dosyanın kendi zinciri; ikinci, FİZİKSEL SÖKÜLEBİLİR kopya
    olmadan sessizce silinip değiştirilebilir."""
    _goster(monkeypatch, vault)

    usb_capa = _usb_capa_yolu(usb_takili)
    assert usb_capa.is_file(), "USB kopyası hiç yazılmadı"
    kayitlar = read_anchors(usb_capa)
    assert kayitlar[-1]["reason"] == EYLEM_KURTARMA_GORUNTULENDI

    sonuc = verify_anchor_replicas(
        local_path=anchor_path(), usb_path=usb_capa,
    )
    assert sonuc, sonuc.problems


def test_viewing_the_share_twice_anchors_twice(
    qapp, db, vault: str, usb_takili: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Her görüntüleme AYRI bir çıpa satırı — biri diğerinin yerine geçmiyor."""
    _goster(monkeypatch, vault)
    _goster(monkeypatch, vault)

    yerel = read_anchors(anchor_path())
    usb = read_anchors(_usb_capa_yolu(usb_takili))
    assert len(yerel) == 2
    assert len(usb) == 2
    assert all(k["reason"] == EYLEM_KURTARMA_GORUNTULENDI for k in yerel)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Yalnızca yerel kopyanın kurcalanması — USB'yle karşılaştırınca yakalanıyor
# ══════════════════════════════════════════════════════════════════════════════


def _yerel_capa_satirini_degistir(yol: Path, index: int, **degisiklikler: object) -> None:
    """B-090'ın kendi testlerindeki (`tests/test_audit_chain.py::
    _usb_capa_satirini_degistir`) BİREBİR karşılığı — bu sefer YEREL dosya."""
    satirlar = yol.read_text(encoding="utf-8").splitlines()
    kayit = json.loads(satirlar[index])
    kayit.update(degisiklikler)
    satirlar[index] = json.dumps(kayit, sort_keys=True, separators=(",", ":"))
    yol.write_text("\n".join(satirlar) + "\n", encoding="utf-8")


def test_tampering_only_the_local_copy_is_caught_against_the_usb_copy(
    qapp, db, vault: str, usb_takili: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    ASIL TEST — B-090'daki `test_verify_anchor_replicas_catches_local_copy_
    tampered` ile AYNI desen, GERÇEK `kurtarma_parcasini_goster()` çağrısı
    ÜRETTİĞİ çıpayla: saldırgan diski okuyup YEREL kopyayı değiştirebilir
    (`entry_count`'u sahteliyoruz), USB'ye DOKUNMUYOR — USB'yle
    karşılaştırma bunu YAKALAMALI.
    """
    _goster(monkeypatch, vault)

    yerel_capa = anchor_path()
    _yerel_capa_satirini_degistir(yerel_capa, 0, entry_count=999999)

    sonuc = verify_anchor_replicas(
        local_path=yerel_capa, usb_path=_usb_capa_yolu(usb_takili),
    )
    assert not sonuc, "yerel kurcalama YAKALANMALIYDI"
    assert any("entry_count" in p and "Satır 1" in p for p in sonuc.problems)


def test_an_untampered_anchor_pair_reports_ok(
    qapp, db, vault: str, usb_takili: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negatif kontrol — dokunulmamış çift SAĞLAM raporlanmalı, testin
    kendisi yanlış alarm üretmiyor."""
    _goster(monkeypatch, vault)

    sonuc = verify_anchor_replicas(
        local_path=anchor_path(), usb_path=_usb_capa_yolu(usb_takili),
    )
    assert sonuc
    assert sonuc.problems == []
