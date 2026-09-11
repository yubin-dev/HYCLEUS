"""
CORE.usb_tokens — token_kayitlarini_getir()'in LIKE deseni HWID çarpışması.

B-136: `role_detail`/`last_login` alt sorguları `a.detail LIKE 'hwid=' ||
u.hwid || '%'` deseniyle arıyordu — u.hwid ham hâliyle bir LIKE deseninin
PARÇASI olarak kullanılıyordu, parametreli bir DEĞER olarak değil.
`CORE/usb_manager.py::_sanitize_hwid()` HWID'de `_`'a BİLEREK izin veriyor
(yalnızca `%` temizleniyor) ama `_`, SQL LIKE'ın "herhangi BİR karakter"
joker'i — yani alt çizgili bir HWID, tamamen farklı bir HWID'in denetim
kayıtlarıyla (rol/son giriş) YANLIŞLIKLA eşleşebiliyordu.
"""
from __future__ import annotations

from CORE.usb_tokens import token_kayitlarini_getir


def _token_ekle(db, hwid: str, token_id: str) -> None:
    db.execute(
        "INSERT INTO usb_tokens (hwid, share_2, token_id, blacklisted) VALUES (?, ?, ?, 0)",
        (hwid, "share-2-degeri", token_id),
    )


def test_alt_cizgili_hwid_baska_bir_hwidin_denetim_kaydiyla_CARPISMIYOR(db) -> None:
    """
    `USB_001` (alt çizgili) ve `USBX001` (aynı konumda alt çizgi YERİNE
    harf) — ikisi de gerçek, birbirinden bağımsız iki token. `USB_001`
    sorgulanınca yalnızca KENDİ rolü/son girişi dönmeli; `_`'ın joker
    olarak yorumlanması `USBX001`'in kaydını da eşleştirmemeli.

    Mutasyon-kanıt: SQL'deki `REPLACE(u.hwid, '_', '\\_') ... ESCAPE '\\'`
    kaldırılıp eski `'hwid=' || u.hwid || '%'` deseni geri konursa bu test
    KIRMIZIYA düşer — `USB_001` sorgusu `USBX001`'in rolünü de görür
    (ölçüldü: düzeltmeden önce gerçekten böyleydi).
    """
    hwid_dogru = "USB_001"
    hwid_carpisan = "USBX001"

    _token_ekle(db, hwid_dogru, "TOKEN-DOGRU")
    _token_ekle(db, hwid_carpisan, "TOKEN-CARPISAN")

    # hwid_carpisan HEM rol atandı HEM giriş yaptı; hwid_dogru'nun rol
    # kaydı VAR ama hiç giriş yapmadı — last_login çarpışması da ayrı
    # ölçülsün diye bilerek asimetrik.
    db.log("usb_setup_complete", detail=f"hwid={hwid_dogru} role=admin")
    db.log("usb_setup_complete", detail=f"hwid={hwid_carpisan} role=readonly")
    db.log("usb_auth_success", detail=f"hwid={hwid_carpisan} role=readonly")

    kayit = token_kayitlarini_getir(db, hwid=hwid_dogru)

    assert len(kayit) == 1
    assert kayit[0].role == "admin", (
        f"'{hwid_dogru}' sorgusu '{hwid_carpisan}'in rolünü görüyor "
        f"(role={kayit[0].role!r}) — '_' joker olarak yorumlanmış olabilir"
    )
    assert kayit[0].last_login == "", (
        f"'{hwid_dogru}' hiç giriş yapmadı ama '{hwid_carpisan}'in "
        "last_login'i sızmış görünüyor"
    )


def test_carpisan_hwidin_kendi_sorgusu_kendi_kaydini_hala_goruyor(db) -> None:
    """Escape'in yan etkisi olmasın: `USBX001`'in KENDİ sorgusu kendi
    kaydını hâlâ (yanlışlıkla değil, doğru şekilde) görmeli."""
    hwid_dogru = "USB_001"
    hwid_carpisan = "USBX001"

    _token_ekle(db, hwid_dogru, "TOKEN-DOGRU")
    _token_ekle(db, hwid_carpisan, "TOKEN-CARPISAN")

    db.log("usb_setup_complete", detail=f"hwid={hwid_dogru} role=admin")
    db.log("usb_setup_complete", detail=f"hwid={hwid_carpisan} role=readonly")

    kayit = token_kayitlarini_getir(db, hwid=hwid_carpisan)
    assert len(kayit) == 1
    assert kayit[0].role == "readonly"


def test_tum_kayitlar_modu_da_carpismiyor(db) -> None:
    """`hwid=None` (tüm token'lar, USB Yönetim Paneli) modunda da her
    satırın KENDİ rolü dönmeli — filtre yokluğu escape'i atlatmamalı."""
    hwid_a = "USB_001"
    hwid_b = "USBX001"

    _token_ekle(db, hwid_a, "TOKEN-A")
    _token_ekle(db, hwid_b, "TOKEN-B")

    db.log("usb_setup_complete", detail=f"hwid={hwid_a} role=admin")
    db.log("usb_setup_complete", detail=f"hwid={hwid_b} role=readonly")

    tumu = {k.hwid: k.role for k in token_kayitlarini_getir(db)}
    assert tumu[hwid_a] == "admin"
    assert tumu[hwid_b] == "readonly"
