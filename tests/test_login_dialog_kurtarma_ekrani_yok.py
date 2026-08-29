"""
B-069 (nihai, 2026-08-29) — mockup'ın "Kurtarma parçasıyla gir" ekranı
GERÇEK `LoginDialog`'a hiç eklenmemiş: DAVRANIŞSAL kanıt, İKİNCİL koruma.

2026-08-29 (devam) — kapsam netleştirildi
-------------------------------------------
Bu dosyanın testi TEK BAŞINA yeterli bir koruma DEĞİL: yalnızca
`LoginDialog._stack`'in sayfa sayısını kilitliyor, yani yalnızca giriş
akışının KENDİSİNE eklenecek bir sayfayı yakalar. Kurtarma yeteneğini
`UI/RecoveryEntryDialog.py` gibi AYRI bir dosyaya yazıp `main_window.py`'de
bir menü öğesiyle ya da `AdminPanel.py`'de bir düğmeyle bağlayan bir
değişiklik bu testin GÖRÜŞ ALANI DIŞINDA kalır — `_stack` hiç
büyümeden.

ASIL/BİRİNCİL koruma artık `tests/test_kurtarma_usb_kapisi.py`'nin 3.
bölümü: `UI/` ağacının TAMAMINI (alt dizinler dahil, `rglob`) tarayıp
`recover_master_key`/`decode_share`'in GERÇEK çağrı/ithal hedeflerini
arıyor — dosyaya-özgü DEĞİL, wiring'e (menü/düğme/doğrudan çağrı)
BAKMAKSIZIN. Bu, gerçekten kanıtlandı: `UI/ProfileDialog.py`'ye (giriş
akışıyla hiçbir ilgisi olmayan bir dosya) geçici bir `recover_master_key`
ithali eklenip o tarama çalıştırıldı — YAKALADI (`UI/ProfileDialog.py:20`).

Bu dosyanın testi KALDIRILMADI — login akışına özgü, ucuz, ikinci bir
savunma katmanı olarak duruyor (B-024'ün "birden fazla bağımsız kontrol"
dersiyle tutarlı), ama artık TEK koruma OLDUĞU varsayılmamalı.

Bu dosya AYRICA kasıtlı olarak AYRI: `tests/test_kurtarma_usb_kapisi.py`
modül seviyesinde Qt/UI ithal ETMİYOR ve bu depoda `tests/test_
layering.py` her test modülünün ya Qt/UI'dan TAMAMEN bağımsız kalmasını
ya da modül seviyesindeki ithalini `try/except ImportError: pytest.skip(
..., allow_module_level=True)` ile KORUMASINI zorunlu kılıyor —
korumasız bir modül-seviyesi Qt ithali, Qt kurulu olmayan bir ortamda
(çıplak bir Linux runner'ı) TÜM test paketini toplama hatasıyla durdurur.
Bu dosya o korumayı diğer yedi UI test dosyasıyla AYNI desenle uyguluyor.

Karar ve tam gerekçe: `BACKLOG.md` **B-069** ("nihai" ve "devam" bölümleri).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication

    from UI.login_dialog import LoginDialog
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from CORE import vault_manager

_HWID = "KURTARMA-EKRAN-TEST"
_PIN = "gizli-pin-777"


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


@pytest.fixture
def kasa_dizini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(vault_manager, "_VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(vault_manager, "_VAULT_PATH_LEGACY", tmp_path / ".hcl_vault")
    return tmp_path


@pytest.fixture
def totp_gecerli(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    `LoginDialog(first_run=False)` bir TOTP sırrı bekliyor (bkz.
    `tests/test_kayit_ekrani.py`'nin aynı fikstürü) — `_stack` (Giriş
    Yap + Kayıt Ol) yalnızca bu dalda kuruluyor (`_first_run=False` ->
    `_build_main_ui()`); `first_run=True` dalı ayrı bir kurulum
    sihirbazı inşa ediyor (`_build_setup_ui()`, `_stack` hiç YOK).
    """
    import UI.login_dialog as ld

    monkeypatch.setattr(ld, "_load_secret", lambda: "A" * 32)


def test_login_dialog_TAM_IKI_sayfali_UCUNCU_kurtarma_sayfasi_YOK(
    qapp, db, kasa_dizini: Path, totp_gecerli: None,
) -> None:
    """
    DAVRANIŞSAL kanıt: gerçek `LoginDialog._stack` — Giriş Yap + Kayıt
    Ol, tam iki sayfa (`UI/login_dialog.py:583-587`). Üçüncü bir
    "Kurtarma ile Gir" sayfası eklenirse bu sayı üçe çıkar ve bu test
    kırılır — yalnızca metin taraması değil, gerçek widget ağacı
    üzerinden.

    Mutasyon kanıtı (2026-08-29, geçici — geri alındı): `login_dialog.
    py`'deki `self._stack.addWidget(...)` çağrılarına üçüncü bir
    `QWidget()` eklenip bu test çalıştırıldı, `AssertionError: 3 == 2`
    ile BAŞARISIZ oldu; düzeltme geri konunca tekrar yeşile döndü.
    """
    dlg = LoginDialog(hwid=_HWID, first_run=False, use_vault=True)
    try:
        assert dlg._stack.count() == 2, (
            f"LoginDialog._stack {dlg._stack.count()} sayfa içeriyor, 2 "
            "bekleniyordu — üçüncü sayfa B-069'un wontfix kararını bozan "
            "bir 'Kurtarma ile Gir' ekranı olabilir"
        )
    finally:
        dlg.deleteLater()
