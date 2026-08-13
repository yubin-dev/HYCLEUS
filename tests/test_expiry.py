"""
HYCLEUS — İmha Odası geri sayım testleri

Bu matematik daha önce `_tick_expiry` içinde, tablo hücresi
güncellemeleriyle iç içeydi; sınamak için bir QTableWidget ve çalışan bir
olay döngüsü gerekiyordu. Artık saniye saniye sınanabiliyor.

Zaman sahte: her fonksiyon `now` parametresi alıyor.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from CORE.expiry import (
    CRITICAL_SECONDS,
    DEFAULT_TTL_HOURS,
    TTL_SETTING,
    WARNING_SECONDS,
    banner_for,
    countdown_for,
    expiry_from_now,
    format_countdown,
    format_expires_at,
    is_expired,
    parse_expires_at,
    remaining_seconds,
    ttl_hours,
    urgency,
)

_ŞİMDİ = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)


def _sonra(**kwargs) -> str:
    return format_expires_at(_ŞİMDİ + timedelta(**kwargs))


# ══════════════════════════════════════════════════════════════════════════════
# 1. Ayrıştırma
# ══════════════════════════════════════════════════════════════════════════════


def test_parse_round_trips():
    assert parse_expires_at(format_expires_at(_ŞİMDİ)) == _ŞİMDİ


def test_parse_returns_utc_aware_datetime():
    assert parse_expires_at("2026-08-13T12:00:00Z").tzinfo is timezone.utc


@pytest.mark.parametrize("deger", [None, "", "yarin", "2026-13-45T99:99:99Z", "123"])
def test_parse_rejects_unusable_values(deger):
    assert parse_expires_at(deger) is None


def test_unset_expiry_is_not_expired():
    """
    Süresi belirlenmemiş dosya İMHA EDİLMEMELİ.

    Saklama süresi süpürmesi bilerek `expires_at = NULL` yazıyor (sayaç
    kurmak onaysız imha olurdu — CORE/disposal.py). None'ı "dolmuş" saymak
    tam da o korumayı deler.
    """
    assert is_expired(None) is False
    assert is_expired("") is False
    assert remaining_seconds(None) is None


# ══════════════════════════════════════════════════════════════════════════════
# 2. Kalan süre ve dolma
# ══════════════════════════════════════════════════════════════════════════════


def test_remaining_counts_down():
    assert remaining_seconds(_sonra(hours=1), now=_ŞİMDİ) == pytest.approx(3600)
    assert remaining_seconds(_sonra(minutes=5), now=_ŞİMDİ) == pytest.approx(300)


def test_remaining_goes_negative_after_expiry():
    """
    Negatif değer KIRPILMAZ — "tam şu an doldu" ile "üç gün önce doldu"
    ayırt edilebilir kalmalı.
    """
    assert remaining_seconds(_sonra(hours=-3), now=_ŞİMDİ) == pytest.approx(-10800)


def test_expiry_boundary_is_inclusive():
    """Kalan tam 0 ise DOLMUŞ — arayüzdeki `remaining <= 0` ile aynı."""
    assert is_expired(_sonra(seconds=1), now=_ŞİMDİ) is False
    assert is_expired(format_expires_at(_ŞİMDİ), now=_ŞİMDİ) is True
    assert is_expired(_sonra(seconds=-1), now=_ŞİMDİ) is True


# ══════════════════════════════════════════════════════════════════════════════
# 3. Biçimlendirme
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(("saniye", "beklenen"), [
    (0,        "00:00:00"),
    (1,        "00:00:01"),
    (59,       "00:00:59"),
    (60,       "00:01:00"),
    (3599,     "00:59:59"),
    (3600,     "01:00:00"),
    (86399,    "23:59:59"),
    (86400,    "24:00:00"),
    (360000,   "100:00:00"),
])
def test_countdown_format(saniye: int, beklenen: str):
    assert format_countdown(saniye) == beklenen


def test_countdown_does_not_wrap_past_24_hours():
    """
    Saat alanı taşmamalı.

    %H kullanılsaydı 24 saat 00:00:00 görünürdü — kullanıcı "hemen
    silinecek" sanırdı.
    """
    assert format_countdown(25 * 3600) == "25:00:00"


def test_countdown_clamps_negative_to_zero():
    assert format_countdown(-500) == "00:00:00"


def test_countdown_truncates_fractional_seconds():
    assert format_countdown(59.9) == "00:00:59"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Aciliyet eşikleri
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(("saniye", "beklenen"), [
    (0,                       "red"),
    (1,                       "red"),
    (CRITICAL_SECONDS - 1,    "red"),
    (CRITICAL_SECONDS,        "yellow"),
    (WARNING_SECONDS - 1,     "yellow"),
    (WARNING_SECONDS,         "green"),
    (86400,                   "green"),
])
def test_urgency_thresholds(saniye: int, beklenen: str):
    """Eşikler birebir sabitleniyor — 600 kırmızı DEĞİL, sarı."""
    assert urgency(saniye) == beklenen


def test_urgency_returns_a_name_not_a_colour_code():
    """
    CORE renk KODU döndürmemeli — somut ton temaya bağlı.

    Kod dönseydi CORE koyu/açık tema bilgisi taşımak zorunda kalırdı.
    """
    for saniye in (0, 1000, 100000):
        assert not urgency(saniye).startswith("#")


# ══════════════════════════════════════════════════════════════════════════════
# 5. Satır durumu
# ══════════════════════════════════════════════════════════════════════════════


def test_countdown_row_for_a_live_file():
    satir = countdown_for(_sonra(minutes=30), now=_ŞİMDİ)
    assert satir.expired is False
    assert satir.unset is False
    assert satir.text() == "00:30:00"
    assert satir.urgency() == "yellow"


def test_countdown_row_for_an_unset_file():
    satir = countdown_for(None, now=_ŞİMDİ)
    assert satir.unset is True
    assert satir.expired is False
    assert satir.text() == "—"
    assert satir.urgency() is None


def test_countdown_row_for_an_expired_file():
    satir = countdown_for(_sonra(minutes=-1), now=_ŞİMDİ)
    assert satir.expired is True
    assert satir.urgency() == "red"


# ══════════════════════════════════════════════════════════════════════════════
# 6. Özet bant — üç hâl
# ══════════════════════════════════════════════════════════════════════════════


def test_banner_shows_the_soonest_expiry():
    bant = banner_for([3600.0, 300.0, 7200.0])
    assert bant.soonest == pytest.approx(300.0)
    assert bant.text() == "⏱  En yakın imha: 00:05:00"
    assert bant.urgency() == "red"


def test_banner_says_empty_when_there_are_no_rows():
    bant = banner_for([])
    assert bant.empty is True
    assert bant.text() == "İmha Odası boş"
    assert bant.urgency() is None


def test_banner_distinguishes_empty_from_unset():
    """
    "Boş" ile "süresiz dosyalar var" AYRI.

    İkisi de sayaç göstermiyor ama kullanıcıya söyledikleri farklı: biri
    "burada bir şey yok", diğeri "burada dosya var ama silinmeyecek".
    """
    bos = banner_for([])
    suresiz = banner_for([None, None])

    assert bos.text() == "İmha Odası boş"
    assert suresiz.text() == "Süre belirlenmemiş dosyalar"
    assert suresiz.empty is False


def test_banner_ignores_unset_rows_when_picking_the_soonest():
    bant = banner_for([None, 900.0, None])
    assert bant.soonest == pytest.approx(900.0)


def test_banner_row_count_overrides_list_length():
    """Süresi dolmuş satırlar listeden düşer ama tablo boş olmayabilir."""
    bant = banner_for([], row_count=3)
    assert bant.empty is False
    assert bant.text() == "Süre belirlenmemiş dosyalar"


# ══════════════════════════════════════════════════════════════════════════════
# 7. TTL ayarı
# ══════════════════════════════════════════════════════════════════════════════


def test_ttl_default_is_24_hours(db):
    assert ttl_hours(db) == DEFAULT_TTL_HOURS == 24


def test_ttl_reads_the_setting(db):
    db.set_setting(TTL_SETTING, "6")
    assert ttl_hours(db) == 6


@pytest.mark.parametrize("bozuk", ["", "alti", "6 saat"])
def test_ttl_falls_back_when_the_setting_is_unusable(db, bozuk: str):
    """
    Bozuk ayar sayacı kurmayı ENGELLEMEMELİ.

    Engelleseydi tek bir yazım hatası İmha Odası'nı çalışmaz hâle
    getirirdi; varsayılana düşmek doğru davranış.
    """
    db.set_setting(TTL_SETTING, bozuk)
    assert ttl_hours(db) == DEFAULT_TTL_HOURS


def test_expiry_from_now_uses_the_configured_ttl(db):
    db.set_setting(TTL_SETTING, "6")
    assert expiry_from_now(db, now=_ŞİMDİ) == _sonra(hours=6)


def test_expiry_from_now_uses_the_default_without_a_setting(db):
    assert expiry_from_now(db, now=_ŞİMDİ) == _sonra(hours=24)


def test_expiry_from_now_output_parses_back(db):
    üretilen = expiry_from_now(db, now=_ŞİMDİ)
    assert parse_expires_at(üretilen) == _ŞİMDİ + timedelta(hours=24)
