"""HYCLEUS — ContactDialog "Auth Kodu Paylaş" özelliğinin kaldırılması (B-062)

Bulgu: `UI/ContactDialog.py`'nin "Auth Kodu Paylaş" sekmesi TÜM onaylı
kullanıcıların adını/rolünü listeliyor ve seçilenlerden biri için
`auth_codes` tablosuna 8 haneli bir kod yazıyordu — ama bu kod repo
genelinde HİÇBİR YERDE okunup doğrulanmıyordu (login akışının hiçbir dalı
bu tabloya bakmıyor). Yarım/ölü bir özellikti, üstelik rol kontrolsüzdü
(Standart/Salt Okunur dahil herhangi bir oturum erişebiliyordu — hem bilgi
ifşası hem de kod üretimi).

Karar (kullanıcıyla birlikte verildi): canlı bir özelliğe rol kapısı
eklemek yerine ölü özelliğin TAMAMI kaldırıldı. Bu paket "referans yok"
testleriyle bunu doğruluyor: ne UI kodunda ne DB şemasında Auth Kodu
Paylaş'a ait hiçbir iz kalmamalı.
"""
from __future__ import annotations

import ast
import os
import sqlite3
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication

    from UI.ContactDialog import ContactDialog
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

from DB import migrations as M

KOK = Path(__file__).resolve().parent.parent


@pytest.fixture
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc})")
    yield app


# ══════════════════════════════════════════════════════════════════════════════
# 1. UI tarafı — hiçbir Auth Kodu Paylaş kalıntısı yok
# ══════════════════════════════════════════════════════════════════════════════

_KALINTI_ISIMLERI = (
    "_tab_auth", "_make_auth_page", "_load_users", "_on_user_selected",
    "_on_generate_code", "_on_copy_code", "_user_list", "_btn_gen",
    "_code_lbl", "_mail_lbl", "_btn_copy_code", "is_admin_role",
    "_switch_tab", "_stack", "QStackedWidget", "QListWidget",
)


def test_contact_dialog_KAYNAGINDA_auth_kodu_kalintisi_yok():
    """Yalnızca kodun GÖVDESİ taranıyor — modül docstring'i hariç, çünkü
    orası özelliğin NEDEN kaldırıldığını anlatmak için `auth_codes`/
    "Auth Kodu Paylaş" gibi terimleri BİLEREK içeriyor (tarihsel kayıt)."""
    agac = ast.parse((KOK / "UI/ContactDialog.py").read_text(encoding="utf-8"))
    govde_baslangic = agac.body[1].lineno - 1  # docstring'den SONRAKİ ilk satır
    satirlar = (KOK / "UI/ContactDialog.py").read_text(encoding="utf-8").splitlines()
    govde = "\n".join(satirlar[govde_baslangic:])

    bulunan = [ad for ad in _KALINTI_ISIMLERI if ad in govde]
    assert not bulunan, f"ContactDialog.py'nin gövdesi hâlâ şunları içeriyor: {bulunan}"
    assert "auth_codes" not in govde, "ContactDialog.py'nin gövdesi hâlâ auth_codes'a değiniyor"


def test_contact_dialog_TEK_SAYFALI_role_parametresi_almiyor():
    """Sekme yapısı kaldırıldığı için `role` parametresi de anlamsızlaştı —
    tek sayfalı dialog hiçbir zaman ayrıcalıklı içerik göstermiyor."""
    agac = ast.parse((KOK / "UI/ContactDialog.py").read_text(encoding="utf-8"))
    init = next(
        n for n in ast.walk(agac)
        if isinstance(n, ast.FunctionDef) and n.name == "__init__"
    )
    tum_parametreler = {a.arg for a in init.args.args + init.args.kwonlyargs}
    assert "role" not in tum_parametreler


def test_cagiran_dosyalar_role_GECMIYOR():
    """main_window.py ve ProfileView.py `ContactDialog(self)`'i eskisi
    gibi çağırıyor — B-062 turunda geçici olarak eklenen `role=` argümanı
    özellik tamamen kaldırıldığı için geri alındı."""
    for goreli in ("UI/main_window.py", "UI/ProfileView.py"):
        kaynak = (KOK / goreli).read_text(encoding="utf-8")
        assert "ContactDialog(self, role=" not in kaynak, (
            f"{goreli}: hâlâ ContactDialog'a role geçiyor"
        )


def test_contact_dialog_ACILIYOR_ve_tek_sayfa(qapp):
    """Uçtan uca: dialog hatasız açılıyor ve yalnızca İletişim içeriğini
    gösteriyor (sekme çubuğu yok)."""
    dlg = ContactDialog()
    try:
        assert not hasattr(dlg, "_stack")
        assert not hasattr(dlg, "_tab_auth")
        assert hasattr(dlg, "_report_title")
    finally:
        dlg.close()


# ══════════════════════════════════════════════════════════════════════════════
# 2. DB tarafı — auth_codes tablosu göçten sonra yok
# ══════════════════════════════════════════════════════════════════════════════


def test_migrasyon_24_auth_codes_tablosunu_kaldiriyor():
    conn = sqlite3.connect(":memory:")
    try:
        M.sifirdan_kur(conn)
        tablolar = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert "auth_codes" not in tablolar, (
            "Migration 24'ten sonra auth_codes hâlâ mevcut"
        )
    finally:
        conn.close()


def test_gercek_db_de_auth_codes_yok(db):
    """`DBManager`'ın gerçek `_apply_schema()` + `senkronize()` yolu da
    aynı sonucu üretmeli — kayıt defteriyle gerçek yol arasında sapma
    olmadığının kanıtı (bkz. test_migrations.py'nin ana eşdeğerlik testi)."""
    tablolar = {
        r[0] for r in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert "auth_codes" not in tablolar
