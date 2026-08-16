"""
HYCLEUS — "son çalışma zamanı + kapı" yardımcısı testleri (④ grubu)

Desen `CORE/integrity.py` içinde bulunmuştu; bu modül onu tek yere
topluyor. Buradaki testler yardımcının kendisini sınıyor — `integrity`'nin
davranışının DEĞİŞMEDİĞİ ise kendi test dosyasında, dokunulmadan duran
51 testle kanıtlanıyor.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from CORE.scheduled_checks import (
    TS_FORMAT,
    ZamanKapisi,
    simdi_damgasi,
    utcnow,
)

_SIMDI = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def kapi() -> ZamanKapisi:
    return ZamanKapisi("test_son_calisma", timedelta(days=7), "test işi")


def _damga(dt: datetime) -> str:
    return dt.strftime(TS_FORMAT)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Kapı mantığı
# ══════════════════════════════════════════════════════════════════════════════


def test_hic_calismadiysa_vakti_gelmis_sayiliyor(db, kapi):
    assert kapi.hic_calismadi_mi(db) is True
    assert kapi.son_calisma(db) is None
    assert kapi.vakti_geldi_mi(db) is True


@pytest.mark.parametrize(
    "gun,beklenen",
    [(0, False), (1, False), (6, False), (7, True), (8, True), (400, True)],
)
def test_aralik_siniri(db, kapi, gun, beklenen):
    """Sınır KAPSAYICI: tam 7 gün dolduğunda kapı açılıyor."""
    kapi.isaretle(db, zaman=_damga(_SIMDI))
    assert kapi.vakti_geldi_mi(db, simdi=_SIMDI + timedelta(days=gun)) is beklenen


def test_gecen_gun_tam_gun_veriyor(db, kapi):
    kapi.isaretle(db, zaman=_damga(_SIMDI))
    simdi = _SIMDI + timedelta(days=12, hours=23)
    assert kapi.gecen_gun(db, simdi=simdi) == 12
    assert kapi.gecen_gun(db, simdi=_SIMDI) == 0


def test_hic_calismadiysa_gecen_gun_none(db, kapi):
    assert kapi.gecen_gun(db) is None
    assert kapi.gecen_sure(db) is None


# ══════════════════════════════════════════════════════════════════════════════
# 2. Bozuk damga — yön önemli
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "bozuk",
    ["bozuk-zaman", "2026-13-45T99:99:99Z", "1755000000", "   ", "2026-08-16"],
)
def test_bozuk_damga_kapiyi_ACIYOR(db, kapi, bozuk):
    """
    YÖN KRİTİK: bozuk damga "hiç çalışmadı" sayılıyor, "az önce çalıştı"
    değil.

    Ters yön işi SÜRESİZ olarak susturur ve sessiz kalan bir bütünlük
    taraması hiç olmayanla aynı şeydir. Bu testin parametreleri, birinin
    "bozuksa çalıştırmayalım" diye düşünüp yönü çevirmesine karşı.
    """
    db.set_setting(kapi.anahtar, bozuk)
    assert kapi.son_calisma(db) is None
    assert kapi.vakti_geldi_mi(db) is True
    assert kapi.hic_calismadi_mi(db) is True


# ══════════════════════════════════════════════════════════════════════════════
# 3. İşaretleme
# ══════════════════════════════════════════════════════════════════════════════


def test_isaretle_kapiyi_kapatiyor(db, kapi):
    assert kapi.vakti_geldi_mi(db) is True
    kapi.isaretle(db)
    assert kapi.vakti_geldi_mi(db) is False
    assert kapi.hic_calismadi_mi(db) is False


def test_isaretle_yazdigi_damgayi_donduruyor(db, kapi):
    damga = kapi.isaretle(db)
    assert db.get_setting(kapi.anahtar, "") == damga
    assert datetime.strptime(damga, TS_FORMAT)


def test_isaretle_acik_zaman_kabul_ediyor(db, kapi):
    """
    `integrity` tamamlanan taramanın kendi `finished_at`'ini yazıyor —
    "şimdi"yi değil. Fark, uzun süren bir taramada taramanın BİTİŞ anını
    kaydetmek demek.
    """
    kapi.isaretle(db, zaman=_damga(_SIMDI))
    assert kapi.son_calisma(db) == _SIMDI


def test_sifirla_kapiyi_geri_aciyor(db, kapi):
    kapi.isaretle(db)
    kapi.sifirla(db)
    assert kapi.hic_calismadi_mi(db) is True


def test_iki_kapi_birbirine_karismiyor(db):
    a = ZamanKapisi("kapi_a", timedelta(days=1))
    b = ZamanKapisi("kapi_b", timedelta(days=1))
    a.isaretle(db)
    assert a.hic_calismadi_mi(db) is False
    assert b.hic_calismadi_mi(db) is True


# ══════════════════════════════════════════════════════════════════════════════
# 4. Saat enjeksiyonu — paylaşılan yardımcı çağıranın testini bozmamalı
# ══════════════════════════════════════════════════════════════════════════════


def test_simdi_parametresi_modul_saatini_eziyor(db, kapi, monkeypatch):
    """
    `simdi` verildiğinde modülün kendi saati KULLANILMAMALI.

    Bu, yardımcının var olma biçiminin gerekçesi: `CORE/integrity.py`'nin
    testleri o modülün `_utcnow`'unu monkeypatch'liyor. Kapı kendi saatini
    dayatsaydı o yama sessizce etkisiz kalır ve `integrity`'nin haftalık
    kapı testleri yanlış şeyi ölçmeye başlardı.
    """
    import CORE.scheduled_checks as sc

    monkeypatch.setattr(sc, "utcnow", lambda: _SIMDI + timedelta(days=999))
    kapi.isaretle(db, zaman=_damga(_SIMDI))

    # Açıkça verilen saat kazanmalı — 3 gün geçmiş, kapı kapalı.
    assert kapi.vakti_geldi_mi(db, simdi=_SIMDI + timedelta(days=3)) is False
    # Verilmezse modül saati kullanılır — 999 gün geçmiş, kapı açık.
    assert kapi.vakti_geldi_mi(db) is True


def test_utcnow_utc_dondururuyor():
    assert utcnow().tzinfo is timezone.utc


def test_simdi_damgasi_ayristirilabilir():
    assert datetime.strptime(simdi_damgasi(), TS_FORMAT)


# ══════════════════════════════════════════════════════════════════════════════
# 5. integrity gerçekten bu yardımcıyı kullanıyor mu
# ══════════════════════════════════════════════════════════════════════════════


def test_integrity_kapisi_ayni_anahtari_kullaniyor(db):
    """
    Yardımcı çıkarıldı ama `integrity` eski kodunu koruyup yanına
    kullanılmayan bir kapı eklerse kimse fark etmezdi.
    """
    from CORE import integrity

    assert integrity._SWEEP_KAPISI.anahtar == integrity.LAST_SWEEP_SETTING
    assert integrity._SWEEP_KAPISI.aralik == timedelta(
        days=integrity.SWEEP_INTERVAL_DAYS
    )


def test_integrity_kendi_damga_ayristirmasini_tutmuyor(db):
    """
    İkinci bir uygulamanın geri gelmesine karşı (B-008 dersi).

    `last_sweep_at()` kendi `strptime`'ını yeniden yazarsa iki ayrıştırıcı
    olur ve biri düzeltilince diğeri geride kalır.
    """
    import ast
    import inspect

    from CORE import integrity

    for ad in ("last_sweep_at", "sweep_due"):
        kaynak = inspect.getsource(getattr(integrity, ad))
        agac = ast.parse(kaynak.strip())
        cagrilar = {
            d.func.attr
            for d in ast.walk(agac)
            if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
        }
        assert "strptime" not in cagrilar, f"{ad} kendi ayrıştırmasını yapıyor"


def test_integrity_damgasi_yardimci_uzerinden_yaziliyor(db, monkeypatch):
    """
    `maybe_run_weekly_sweep()` damgayı `isaretle()` ile yazmalı.

    Doğrudan `set_setting` çağrısı da çalışırdı ama yardımcıyı yalnızca
    okuma tarafında kullanmak, yazma tarafını sessizce ayrıştırırdı.
    """
    import inspect

    from CORE import integrity

    kaynak = inspect.getsource(integrity.maybe_run_weekly_sweep)
    assert "_SWEEP_KAPISI.isaretle" in kaynak
    assert "set_setting" not in kaynak
