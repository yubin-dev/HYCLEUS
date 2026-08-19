"""
CORE.roles — rol adının tek karar noktası (B-028 / B-030).

Bu modülün tek işi bir dizeyi karara çevirmek, dolayısıyla testlerin çoğu
GİRDİ ÇEŞİTLİLİĞİ üzerine. Kritik girdiler uydurma değil, depodan ve
ölçümden geliyor:

    "Yönetici"     arayüzün yazdığı kanonik ad
    "Yonetici"     CORE/recover_vault.py:175'in varsayılanı (ASCII)
    "YÖNETİCİ"     Türkçe büyük harf — `.lower()` bunu BOZUYOR
    "admin"        users.role sütunu, ve eski main_window_table listesi
    "Salt_Okunur"  main_window.py'nin `_` → boşluk normalizasyonu
"""
from __future__ import annotations

import pytest

from CORE.roles import (
    DB_ADMIN,
    DB_USER,
    GORUNEN_AD,
    ROL_SALT_OKUNUR,
    ROL_STANDART,
    ROL_YONETICI,
    can_write,
    db_role,
    display_role,
    is_admin_role,
    is_readonly_role,
    normalize_role,
)

# ── Yönetici yazımları ────────────────────────────────────────────────────────

YONETICI_YAZIMLARI = [
    "Yönetici",        # arayüzün kanonik yazdığı
    "yönetici",
    "YÖNETİCİ",        # Türkçe büyük harf — .lower() burada kırılıyor
    "Yonetici",        # recover_vault.py:175 varsayılanı
    "yonetici",
    "YONETICI",
    "  Yönetici  ",    # kenar boşluğu
    "admin",           # users.role sütunu
    "ADMIN",
    "Administrator",
]


@pytest.mark.parametrize("yazim", YONETICI_YAZIMLARI)
def test_yonetici_yazimlarinin_hepsi_taniniyor(yazim: str):
    assert normalize_role(yazim) == ROL_YONETICI
    assert is_admin_role(yazim) is True
    assert is_readonly_role(yazim) is False
    assert db_role(yazim) == DB_ADMIN


def test_turkce_buyuk_harf_lower_ile_CALISMAZDI():
    """
    Bu testin tek işi düzeltmenin NEDEN gerektiğini sabitlemek.

    ÖLÇÜLDÜ: `"YÖNETİCİ".lower()` on karakter üretiyor, sekiz değil —
    `İ` (U+0130) küçük harfi `i` + U+0307 BİRLEŞEN NOKTA. Yani eski
    `.strip().lower() == "yönetici"` karşılaştırması bu girdide False
    dönüyordu. Regresyon burada yakalanır.
    """
    assert "YÖNETİCİ".lower() != "yönetici"
    assert len("YÖNETİCİ".lower()) == 10
    # Yeni yol aynı girdide doğru cevabı veriyor.
    assert is_admin_role("YÖNETİCİ") is True


# ── Salt Okunur ───────────────────────────────────────────────────────────────

SALT_OKUNUR_YAZIMLARI = [
    "Salt Okunur", "salt okunur", "SALT OKUNUR",
    "Salt_Okunur",     # main_window.py:191 bunu ele alıyordu
    "salt-okunur",
    "SaltOkunur",
    "readonly", "read only",
]


@pytest.mark.parametrize("yazim", SALT_OKUNUR_YAZIMLARI)
def test_salt_okunur_yazimlari(yazim: str):
    assert normalize_role(yazim) == ROL_SALT_OKUNUR
    assert is_readonly_role(yazim) is True
    assert is_admin_role(yazim) is False
    assert can_write(yazim) is False
    assert db_role(yazim) == DB_USER


# ── Standart ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("yazim", ["Standart", "standart", "STANDART",
                                   "user", "USER", "Personel", "kullanıcı"])
def test_standart_yazimlari(yazim: str):
    assert normalize_role(yazim) == ROL_STANDART
    assert is_admin_role(yazim) is False
    assert is_readonly_role(yazim) is False
    assert can_write(yazim) is True
    assert db_role(yazim) == DB_USER


# ── Bilinmeyen / boş ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("yazim", [None, "", "   ", "Müdür", "root", "sudo", "xyz"])
def test_bilinmeyen_rol_en_dar_yetkiye_dusuyor(yazim):
    """
    Yön ÖNEMLİ: bilinmeyen bir rol yetki KAZANMAMALI. Ters yönde bir hata
    (bilinmeyeni yönetici saymak) sessiz bir yetki genişlemesi olurdu.
    """
    assert normalize_role(yazim) == ""
    assert is_admin_role(yazim) is False
    assert db_role(yazim) == DB_USER
    assert can_write(yazim) is False


def test_bilinmeyen_rol_salt_okunur_da_SAYILMIYOR():
    """
    `is_readonly_role` bir GÖRÜNÜM kararı; bilinmeyeni salt-okunur saymak
    yazmayı engellemekle kalmaz, arayüzü "salt okunur" diye etiketlerdi.
    Yazma engeli `can_write`'ın işi ve o zaten False dönüyor.
    """
    assert is_readonly_role("Müdür") is False
    assert can_write("Müdür") is False


# ── can_write yön denetimi ────────────────────────────────────────────────────

def test_can_write_bilinmeyeni_ESKISINDEN_dar_tutuyor():
    """
    Eski kod `can_write = not is_readonly` diyordu, yani bilinmeyen bir rol
    YAZABİLİYORDU. Yeni hâli yalnızca tanınan iki role izin veriyor.
    Kanonik üç rol için davranış AYNI — bu, saf-refactor kuralının bilerek
    yapılmış tek istisnası ve yönü daraltma yönünde.
    """
    assert can_write("Yönetici") is True
    assert can_write("Standart") is True
    assert can_write("Salt Okunur") is False
    assert can_write("bilinmeyen") is False


# ── display_role ──────────────────────────────────────────────────────────────

def test_display_role_kanonik_adi_veriyor():
    assert display_role("yonetici") == "Yönetici"
    assert display_role("YONETICI") == "Yönetici"
    assert display_role("salt-okunur") == "Salt Okunur"


def test_display_role_taninmayani_oldugu_gibi_donduruyor():
    """Bilinmeyen rolü boş dizeye çevirmek arayüzde bilgi kaybı olurdu."""
    assert display_role("Müdür") == "Müdür"
    assert display_role(None) == ""


def test_gorunen_ad_secilebilir_rollerin_hepsini_kapsiyor():
    from CORE.roles import SECILEBILIR_ROLLER
    assert set(SECILEBILIR_ROLLER) == set(GORUNEN_AD)


# ── Kanonik değerlerin kendisi de girdi olarak geçerli ────────────────────────

@pytest.mark.parametrize("kanonik", [ROL_YONETICI, ROL_STANDART, ROL_SALT_OKUNUR])
def test_normalize_idempotent(kanonik: str):
    """
    `normalize_role(normalize_role(x)) == normalize_role(x)`.
    Kanonik değer bir yere yazılıp geri okunduğunda tekrar normalize
    edilecek; ikinci geçiş onu bozmamalı.
    """
    assert normalize_role(kanonik) == kanonik


@pytest.mark.parametrize("gorunen", list(GORUNEN_AD.values()))
def test_gorunen_adlar_geri_normalize_oluyor(gorunen: str):
    """display_role() çıktısı normalize_role() girdisi olarak geçerli olmalı."""
    assert normalize_role(gorunen) in GORUNEN_AD


# ── db_role: B-030 ────────────────────────────────────────────────────────────

def test_db_role_yalnizca_iki_deger_uretiyor():
    """`users.role` sütununda CHECK(role IN ('admin','user')) var."""
    girdiler = YONETICI_YAZIMLARI + SALT_OKUNUR_YAZIMLARI + ["Standart", "", None, "xyz"]
    assert {db_role(g) for g in girdiler} <= {DB_ADMIN, DB_USER}


# ── Kurtarma zinciri: B-028'in erişilebilir kusuru ────────────────────────────

def test_kurtarma_zinciri_hangi_yazim_saklanmis_olursa_olsun_yonetici():
    """
    B-028'in ASIL senaryosu.

    `recover_vault` rolü KASAYA yazıyor, giriş akışı da kasadan okuyup
    doğrudan `HycleusWindow(role=...)`'a veriyor. Yani kasada duran dize
    ne ise, yetki kararı onun üzerinden veriliyor.

    Eski davranış: kasada `Yonetici` (ASCII) varsa `== "Yönetici"`
    karşılaştırmalarının 11'i de False dönüyordu — yönetici sessizce
    düşüyordu. Aşağıdaki yazımların HEPSİ tanınmalı; hangisinin
    saklandığı, kurtarmayı kimin ne zaman yaptığına bağlı.
    """
    kasada_olabilecekler = [
        "Yönetici",   # arayüzden kurulmuş kasa
        "Yonetici",   # recover_vault.py'nin eski ASCII varsayılanı
        "YÖNETİCİ",   # kullanıcı büyük harfle yazmış
        "YONETICI",
        "admin",      # elle/betikle kurulmuş kasa
    ]
    for saklanan in kasada_olabilecekler:
        assert is_admin_role(saklanan) is True, f"{saklanan!r} yönetici sayılmadı"
        assert db_role(saklanan) == DB_ADMIN


def test_recover_vault_kanonik_yaziyor():
    """
    Yazma tarafı: `recover_vault` artık ham girdiyi değil kanonik yazımı
    saklıyor, yani yeni kasalarda sorun hiç doğmuyor.

    AST ile denetleniyor — kaynak metni değil, `display_role()` çağrısının
    gerçekten `input()` sonucuna uygulandığı.
    """
    import ast
    from pathlib import Path

    kaynak = (Path(__file__).resolve().parent.parent / "CORE" / "recover_vault.py")
    agac = ast.parse(kaynak.read_text(encoding="utf-8"))

    display_cagrilari = [
        d for d in ast.walk(agac)
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
        and d.func.id == "display_role"
    ]
    assert display_cagrilari, "recover_vault.py rolü kanonikleştirmiyor"

    # Ham `input()` sonucu DOĞRUDAN role atanmamalı.
    for dugum in ast.walk(agac):
        if not (isinstance(dugum, ast.Assign) and len(dugum.targets) == 1):
            continue
        hedef = dugum.targets[0]
        if not (isinstance(hedef, ast.Name) and hedef.id == "role"):
            continue
        icinde_input = any(
            isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "input"
            for c in ast.walk(dugum.value)
        )
        assert not icinde_input, (
            "recover_vault.py: `role` doğrudan input()'tan atanıyor — "
            "display_role() ile kanonikleştirilmeli (B-028)"
        )


def test_db_role_eski_satir_ici_ifadeyle_ayni_sonucu_veriyor():
    """
    login_dialog:904 ve RegisterDialog:385 şunu yapıyordu:
        "admin" if role == "Yönetici" else "user"
    Kanonik girdilerde yeni fonksiyon aynı cevabı vermeli — saf refactor.
    """
    for rol in ("Yönetici", "Standart", "Salt Okunur"):
        eski = DB_ADMIN if rol == "Yönetici" else DB_USER
        assert db_role(rol) == eski
