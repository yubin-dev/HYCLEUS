"""HYCLEUS — Kurumsal Referans ID (CORE/referans_id.py)

Üç şeyi ölçer: (1) üretecin biçimi ve pratik çakışmasızlığı — yalnızca
tek bir değer hiç saklanmadığı için gerçek bir "kayıt karşılaştırması"
yok, üretecin KENDİSİNİN yeterince geniş bir rastgele uzaydan seçtiğini
büyük örneklemle kanıtlıyoruz; (2) `settings` tablosuna gerçekten
kalıcı yazıldığını (yeni sütun/migrasyon YOK — bkz. modül docstring'i);
(3) `get_referans_id` hiç üretilmemişken `None` döndüğünü.
"""
from __future__ import annotations

import re

from CORE.referans_id import (
    REFERANS_ID_SETTING,
    generate_referans_id,
    get_referans_id,
    set_referans_id,
)

_BICIM = re.compile(r"^KRM-[A-Z2-9]{8}$")


def test_bicim_KRM_onekli_ve_karisan_karakterler_yok():
    for _ in range(200):
        rid = generate_referans_id()
        assert _BICIM.match(rid), f"beklenmeyen biçim: {rid}"
        # 0/O/1/I/L karışabilir diye alfabeden ELENDİ (bkz. modül docstring'i).
        for karisan in "0O1IL":
            assert karisan not in rid, f"{rid} içinde karışabilir karakter var: {karisan}"


def test_cakisma_yok_buyuk_orneklemde():
    """20.000 üretimde tek bir çakışma bile olmamalı.

    32^8 ≈ 1.1×10^12 olasılık uzayında, 20.000 örneklik bir doğum günü
    hesabı beklenen çakışma sayısını ~10^-4 mertebesine indiriyor — yani
    bu testin gerçekten YEŞİL çıkması, üretecin pratikte çakışmasız
    olduğunun istatistiksel kanıtı (bkz. modül docstring'i, "matematiksel
    garanti değil" notu).
    """
    uretilenler = [generate_referans_id() for _ in range(20_000)]
    assert len(set(uretilenler)) == len(uretilenler), "çakışma bulundu"


def test_settings_tablosuna_kalici_yaziyor_yeni_sutun_yok(db):
    """Yeni migrasyon/sütun YOK iddiasının davranışsal kanıtı.

    `settings` zaten var olan genel key-value tablosu — `set_referans_id`
    yalnızca oraya bir satır ekliyor, `users` şemasına hiç dokunmuyor.
    """
    assert get_referans_id(db) is None

    rid = generate_referans_id()
    set_referans_id(db, rid)

    assert get_referans_id(db) == rid
    satir = db.fetchone(
        "SELECT value FROM settings WHERE key = ?", (REFERANS_ID_SETTING,)
    )
    assert satir is not None
    assert satir["value"] == rid

    # users şeması hâlâ gerçek beşli — referans_id orada YOK.
    kolonlar = {r["name"] for r in db.fetchall("PRAGMA table_info(users)")}
    assert "referans_id" not in kolonlar
    assert "referans" not in kolonlar


def test_referans_id_hic_uretilmemisse_None():
    class _SahteDB:
        def get_setting(self, key: str, default: str = "") -> str:
            return default

    assert get_referans_id(_SahteDB()) is None
