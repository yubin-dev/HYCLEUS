"""
HYCLEUS — yedekleme hatırlatması testleri (B-015)

Yedekleme özelliği vardı ama hatırlatması yoktu. Buradaki testler iki şeyi
ayırıyor:

  · KARAR   — "uyarılmalı mı, hangi cümleyle" (CORE, bu dosya)
  · GÖSTERİM — diyaloğu açmak (main.py, AST ile denetleniyor)

En kritik ayrım `HEDEF_ERISILEMIYOR` ile `HIC_YEDEK_YOK`: harici disk
takılı değilse yedek YOK değil, GÖRÜNMÜYOR. İkisini aynı cümleye
indirgemek kullanıcıyı ya gereksiz bir tura sokar ya da uyarıyı görmezden
gelmeye alıştırır.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from CORE.backup_reminder import (
    ERTELEME_AYARI,
    ESIK_AYARI,
    HEDEF_AYARI,
    LAST_BACKUP_SETTING,
    VARSAYILAN_ESIK_GUN,
    YedekDurum,
    ertele,
    esik_gun,
    son_yedek,
    yedek_alindi,
    yedek_durumu,
)
from CORE.scheduled_checks import TS_FORMAT

_SIMDI = datetime(2026, 8, 17, 9, 0, 0, tzinfo=timezone.utc)


def _gun_once(n: int) -> str:
    return (_SIMDI - timedelta(days=n)).strftime(TS_FORMAT)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Temel kapı
# ══════════════════════════════════════════════════════════════════════════════


def test_hic_yedek_yoksa_uyariliyor(db):
    d = yedek_durumu(db, simdi=_SIMDI)
    assert d.durum is YedekDurum.HIC_YEDEK_YOK
    assert d.uyarilmali is True
    assert d.gecen_gun is None
    assert "hiç yedek almadınız" in d.mesaj()


def test_yeni_yedek_uyari_uretmiyor(db):
    db.set_setting(LAST_BACKUP_SETTING, _gun_once(1))
    d = yedek_durumu(db, simdi=_SIMDI)
    assert d.durum is YedekDurum.GUNCEL
    assert d.uyarilmali is False
    assert d.mesaj() == ""


@pytest.mark.parametrize(
    "gun_delta,beklenen",
    # `VARSAYILAN_ESIK_GUN`'a GÖRELİ — sabit gün sayıları DEĞİL, çünkü
    # varsayılan değişince (B-108: 7 → 15) bu test kırılmamalı.
    [(-VARSAYILAN_ESIK_GUN, False), (-1, False), (0, True), (23, True)],
)
def test_esik_siniri(db, gun_delta, beklenen):
    db.set_setting(LAST_BACKUP_SETTING, _gun_once(VARSAYILAN_ESIK_GUN + gun_delta))
    d = yedek_durumu(db, simdi=_SIMDI)
    assert d.uyarilmali is beklenen


def test_eski_yedek_gun_sayisini_soyluyor(db):
    gun = VARSAYILAN_ESIK_GUN + 5
    db.set_setting(LAST_BACKUP_SETTING, _gun_once(gun))
    d = yedek_durumu(db, simdi=_SIMDI)
    assert d.durum is YedekDurum.ESKI
    assert d.gecen_gun == gun
    assert f"{gun} gün" in d.mesaj()


# ══════════════════════════════════════════════════════════════════════════════
# 2. Eşik ayarı
# ══════════════════════════════════════════════════════════════════════════════


def test_esik_sifir_hatirlatmayi_kapatiyor(db):
    """`0` kapatmanın AÇIK yolu — hareketsizlik kilidi ayarıyla aynı kalıp."""
    db.set_setting(ESIK_AYARI, "0")
    d = yedek_durumu(db, simdi=_SIMDI)   # hiç yedek yok, normalde uyarırdı
    assert d.durum is YedekDurum.KAPALI
    assert d.uyarilmali is False


def test_ozel_esik_uygulaniyor(db):
    db.set_setting(ESIK_AYARI, "30")
    db.set_setting(LAST_BACKUP_SETTING, _gun_once(20))
    assert yedek_durumu(db, simdi=_SIMDI).uyarilmali is False
    db.set_setting(LAST_BACKUP_SETTING, _gun_once(31))
    assert yedek_durumu(db, simdi=_SIMDI).uyarilmali is True


@pytest.mark.parametrize("bozuk", ["abc", "", "7.5", "  "])
def test_bozuk_esik_varsayilana_dusuyor(db, bozuk):
    db.set_setting(ESIK_AYARI, bozuk)
    assert esik_gun(db) == VARSAYILAN_ESIK_GUN


def test_negatif_esik_KAPATMIYOR(db):
    """
    YÖN KRİTİK: `-3` büyük ihtimalle bir hata, "hatırlatma yok" değil.

    Sessizce kapatmak kullanıcıyı yedeksiz bırakırdı. Kapatmanın belgeli
    yolu `0` ve o çalışıyor.
    """
    db.set_setting(ESIK_AYARI, "-3")
    assert esik_gun(db) == VARSAYILAN_ESIK_GUN
    assert yedek_durumu(db, simdi=_SIMDI).uyarilmali is True


# ══════════════════════════════════════════════════════════════════════════════
# 3. Erteleme
# ══════════════════════════════════════════════════════════════════════════════


def test_erteleme_uyariyi_susturuyor(db):
    db.set_setting(LAST_BACKUP_SETTING, _gun_once(30))
    assert yedek_durumu(db, simdi=_SIMDI).uyarilmali is True

    ertele(db, zaman=_gun_once(1))
    assert yedek_durumu(db, simdi=_SIMDI).uyarilmali is False


def test_erteleme_suresiz_DEGIL(db):
    """
    Erteleme bir eşik süresi kadar. Süresiz olsaydı tek bir "sonra"
    tıklaması hatırlatmayı kalıcı olarak kapatırdı ve kullanıcı bunu
    seçtiğini bilmezdi.
    """
    db.set_setting(LAST_BACKUP_SETTING, _gun_once(60))
    ertele(db, zaman=_gun_once(VARSAYILAN_ESIK_GUN + 1))
    assert yedek_durumu(db, simdi=_SIMDI).uyarilmali is True


def test_yedek_alinca_erteleme_siliniyor(db):
    """
    Kullanıcı "sonra" dedikten sonra gerçekten yedek aldıysa, o erteleme
    bir sonraki döngüyü bastırmamalı.
    """
    ertele(db, zaman=_gun_once(1))
    yedek_alindi(db, zaman=_gun_once(0))
    assert db.get_setting(ERTELEME_AYARI, "") == ""


# ══════════════════════════════════════════════════════════════════════════════
# 4. Hedef erişilemiyor — "yedek yok" ile AYNI ŞEY DEĞİL
# ══════════════════════════════════════════════════════════════════════════════


def test_erisilemeyen_hedef_ayri_durum(db, tmp_path: Path):
    """
    B-015'in notunda özellikle istenen ayrım.

    Harici disk takılı değilken "hiç yedek yok" demek yanlış: yedek var,
    biz göremiyoruz.
    """
    db.set_setting(HEDEF_AYARI, str(tmp_path / "takili-degil"))
    db.set_setting(LAST_BACKUP_SETTING, _gun_once(1))   # yedek YENİ

    d = yedek_durumu(db, simdi=_SIMDI)
    assert d.durum is YedekDurum.HEDEF_ERISILEMIYOR
    assert d.uyarilmali is True
    assert "kaybolduğu anlamına GELMEZ" in d.mesaj()
    assert "hiç yedek almadınız" not in d.mesaj()


def test_erisilebilir_hedef_normal_akisa_donuyor(db, tmp_path: Path):
    db.set_setting(HEDEF_AYARI, str(tmp_path))
    db.set_setting(LAST_BACKUP_SETTING, _gun_once(1))
    assert yedek_durumu(db, simdi=_SIMDI).durum is YedekDurum.GUNCEL


def test_hedef_ayarsizsa_dosya_sistemine_bakilmiyor(db):
    """Hedef ayarlı değilse erişilebilirlik kontrolü hiç yapılmamalı."""
    db.set_setting(LAST_BACKUP_SETTING, _gun_once(1))
    d = yedek_durumu(db, simdi=_SIMDI)
    assert d.durum is YedekDurum.GUNCEL
    assert d.hedef is None


def test_hedef_erisilemiyorsa_esik_kapaliysa_yine_sessiz(db, tmp_path: Path):
    """Eşik 0 her şeyi kapatmalı — disk uyarısını da."""
    db.set_setting(ESIK_AYARI, "0")
    db.set_setting(HEDEF_AYARI, str(tmp_path / "yok"))
    assert yedek_durumu(db, simdi=_SIMDI).uyarilmali is False


# ══════════════════════════════════════════════════════════════════════════════
# 5. create_backup damgayı gerçekten yazıyor mu
# ══════════════════════════════════════════════════════════════════════════════


def test_create_backup_damgayi_yaziyor(db, tmp_path: Path):
    """
    ASIL BAĞLANTI. Damga yazılmazsa hatırlatma her açılışta tekrar eder ve
    kullanıcı onu görmezden gelmeye alışır — uyarının kendisi işe yaramaz
    hâle gelir.
    """
    from CORE.backup import create_backup

    assert son_yedek(db) is None
    vault = tmp_path / "vault"
    vault.mkdir()
    create_backup(db, tmp_path / "yedek", b"k" * 32, vault_dir=vault)

    assert son_yedek(db) is not None
    assert yedek_durumu(db).durum is YedekDurum.GUNCEL


def test_create_backup_damgasi_raporun_zamaniyla_ayni(db, tmp_path: Path):
    """Damga yedeğin BİTİŞ anı olmalı, "şimdi" değil."""
    from CORE.backup import create_backup

    vault = tmp_path / "vault"
    vault.mkdir()
    rapor = create_backup(db, tmp_path / "yedek", b"k" * 32, vault_dir=vault)
    assert db.get_setting(LAST_BACKUP_SETTING, "") == rapor.created_at


def test_damga_yazimi_yedegi_dusurmuyor(db, tmp_path: Path, monkeypatch):
    """
    Hatırlatma bir kolaylık; yedeğin kendisini riske atmamalı.

    Denetim kaydıyla aynı kural: `db.log` başarısız olsa da yedek duruyor.
    """
    import CORE.backup_reminder as br
    from CORE.backup import create_backup

    def _patla(*a, **k):
        raise RuntimeError("settings yazılamadı")

    monkeypatch.setattr(br, "yedek_alindi", _patla)
    vault = tmp_path / "vault"
    vault.mkdir()

    rapor = create_backup(db, tmp_path / "yedek", b"k" * 32, vault_dir=vault)
    assert rapor.path.exists()


# ══════════════════════════════════════════════════════════════════════════════
# 6. Katman ve bağlantı denetimleri
# ══════════════════════════════════════════════════════════════════════════════


def test_karar_katmani_qt_bilmiyor():
    """CORE diyalog açamaz — karar ile gösterim ayrı."""
    import ast
    from pathlib import Path as _P

    kaynak = _P(__file__).resolve().parent.parent / "CORE" / "backup_reminder.py"
    agac = ast.parse(kaynak.read_text(encoding="utf-8"))
    icebaktir = {
        (d.module or "")
        for d in ast.walk(agac)
        if isinstance(d, ast.ImportFrom)
    } | {
        a.name for d in ast.walk(agac) if isinstance(d, ast.Import) for a in d.names
    }
    assert not any("PySide6" in m or "Qt" in m for m in icebaktir)


def test_main_hatirlatmayi_gosteriyor():
    """
    `main.py` kararı sorup göstermeli.

    Çağrı düşerse hiçbir şey patlamaz — uyarı sessizce kaybolur. B-015'in
    ilk hâli tam olarak buydu: mekanizma var, tetikleyicisi yok.
    """
    import ast
    from pathlib import Path as _P

    kaynak = _P(__file__).resolve().parent.parent / "main.py"
    cagrilar = {
        d.func.id
        for d in ast.walk(ast.parse(kaynak.read_text(encoding="utf-8")))
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
    }
    assert "yedek_durumu" in cagrilar, "main.py yedek durumunu hiç sormuyor"
    assert "ertele" in cagrilar, "\"sonra sorma\" seçeneği bağlanmamış"
    assert "is_admin_role" in cagrilar, (
        "B-108: main.py rol kontrolü yapmıyor — uyarı her role gösterilir"
    )


def test_yedek_hatirlatmasi_YALNIZCA_yonetici_KOSULUNDA_gosteriliyor():
    """
    B-108 — asıl istenen: `is_admin_role(role)` yalnızca dosyanın BİR
    YERİNDE çağrılmış olması yetmez, yedekleme uyarısını AÇAN `if`'in
    KOŞULUNUN parçası olmalı. Aksi hâlde rol kontrolü ölü kod olur ve
    Standart kullanıcı uyarıyı görmeye/erteleyebilmeye devam eder — B-108'in
    kapatmak istediği tam boşluk (yönetici olmayan biri ertelerse asıl
    ilgilenmesi gereken yönetici uyarıyı bir daha hiç görmeyebilirdi).
    """
    import ast
    from pathlib import Path as _P

    kaynak = _P(__file__).resolve().parent.parent / "main.py"
    agac = ast.parse(kaynak.read_text(encoding="utf-8"))

    hedef_if = None
    for node in ast.walk(agac):
        if isinstance(node, ast.If):
            test_cagrilar = {
                d.func.id for d in ast.walk(node.test)
                if isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
            }
            if "is_admin_role" in test_cagrilar:
                hedef_if = node
                break

    assert hedef_if is not None, "is_admin_role() hiçbir if koşulunda kullanılmıyor"
    assert isinstance(hedef_if.test, ast.BoolOp) and isinstance(hedef_if.test.op, ast.And), (
        "is_admin_role() `and` DIŞINDA bir bağlaçla kullanılmış (ör. `or`) — "
        "bu, kontrolü etkisiz kılar: koşul is_admin_role() YANLIŞ olsa bile "
        "diğer taraf tek başına True'ysa uyarı yine gösterilir"
    )

    govde_cagrilar = {
        (d.func.attr if isinstance(d.func, ast.Attribute) else
         d.func.id if isinstance(d.func, ast.Name) else "")
        for govde_dugumu in hedef_if.body
        for d in ast.walk(govde_dugumu)
        if isinstance(d, ast.Call)
    }
    assert "QMessageBox" in govde_cagrilar, (
        "is_admin_role() bir if'te ama o if'in gövdesi yedekleme uyarısı "
        "diyaloğunu AÇMIYOR — rol kontrolü yanlış koşula bağlanmış olabilir"
    )


def test_create_backup_hatirlatmayi_guncelliyor():
    """
    Damga `create_backup()` içinde yazılmalı, arayüzde değil.

    Arayüze bırakılsaydı `CORE/backup_cli.py` üzerinden alınan yedekler
    hatırlatmayı susturmazdı — ikisi de aynı fonksiyonu çağırıyor.
    """
    import inspect

    from CORE.backup import create_backup

    assert "yedek_alindi" in inspect.getsource(create_backup)
