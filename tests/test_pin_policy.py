"""
CORE.pin_policy — PIN uzunluk politikası testleri.

PIN belirleme akışları Qt diyaloglarının içinde olduğu için doğrulama mantığı
pin_policy'de toplandı; buradaki testler o mantığı ve onu kullanan gerçek CLI
kurulum akışını (setup_usb._prompt_pin) sınar.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from CORE import setup_usb
from CORE.pin_policy import LOGIN_MIN_LEN, PIN_MIN_LEN, validate_new_pin


def test_policy_minimum_is_six() -> None:
    assert PIN_MIN_LEN == 6


@pytest.mark.parametrize("pin", ["", "1", "12", "123", "1234", "12345"])
def test_new_pin_shorter_than_six_is_rejected(pin: str) -> None:
    """5 ve altı karakter reddedilmeli — asıl regresyon koruması bu."""
    error = validate_new_pin(pin)
    assert error is not None, f"{len(pin)} karakterlik PIN kabul edildi: {pin!r}"
    assert "6" in error, "hata mesajı yeni minimumu söylemeli"


@pytest.mark.parametrize("pin", ["123456", "1234567", "a" * 32, "uzun bir parola cümlesi"])
def test_new_pin_of_six_or_more_is_accepted(pin: str) -> None:
    assert validate_new_pin(pin) is None, f"geçerli PIN reddedildi: {pin!r}"


def test_boundary_five_rejected_six_accepted() -> None:
    """Sınır tam olarak 6'da olmalı."""
    assert validate_new_pin("12345") is not None
    assert validate_new_pin("123456") is None


# ── Geriye dönük uyumluluk ────────────────────────────────────────────────────

def test_login_floor_stays_below_new_policy() -> None:
    """
    Giriş eşiği yeni politikanın altında kalmalı.

    Politika 6'ya çıkarılmadan önce kaydolmuş 4-5 haneli PIN sahipleri, doğru
    PIN'leriyle giriş yapabilmeli. Bu iki sabit eşitlenirse o kullanıcılar
    sessizce kilitlenir.
    """
    assert LOGIN_MIN_LEN == 4
    assert LOGIN_MIN_LEN < PIN_MIN_LEN


def test_SECURITY_md_giris_esigini_DOGRU_yaziyor() -> None:
    """
    SECURITY.md §5 köprüyü sayıyla anlatıyor (`LOGIN_MIN_LEN = 4`) ve o
    sayı elle yazılmış — B-017'nin sınıfı.

    Burada durmasının somut sebebi B-040: köprü kaldırıldığında bu sabit
    DEĞİŞECEK. Değiştiği gün bu test düşer ve belgeyi güncellemeye
    zorlar; olmasaydı SECURITY.md sessizce "4 hane hâlâ kabul ediliyor"
    demeye devam ederdi — bir güvenlik belgesinin verebileceği en kötü
    yanlış bilgi, artık doğru olmayan bir zayıflık itirafıdır: okuyucu
    onu düzeltilmiş sanmaz, hâlâ açık sanır ve yanlış yere bakar.

    İki dil de denetleniyor: yalnızca birinin güncellenmesi tam olarak
    `tests/test_belge_dil_paritesi.py`'nin kapatmadığı boşluk — o test
    iki dilin BİRBİRİYLE tutarlılığına bakıyor, KOD ile değil.
    """
    metin = (Path(__file__).resolve().parent.parent / "SECURITY.md").read_text(
        encoding="utf-8"
    )
    beklenen = f"`LOGIN_MIN_LEN = {LOGIN_MIN_LEN}`"
    assert metin.count(beklenen) == 2, (
        f"SECURITY.md {beklenen!r} ifadesini iki dilde de taşımalı "
        f"(bulunan: {metin.count(beklenen)}). Köprü değiştiyse §5'teki "
        "iki satır da güncellenmeli — bkz. BACKLOG.md / B-040."
    )


# ── Gerçek akış: CLI kurulum ──────────────────────────────────────────────────

def test_prompt_pin_rejects_five_chars_then_accepts_six(monkeypatch, capsys) -> None:
    """
    setup_usb._prompt_pin gerçek döngüsü: 5 haneli PIN reddedilip tekrar sorulmalı,
    6 haneli kabul edilmeli.
    """
    answers = iter(["12345", "123456", "123456"])  # 5 hane → red; 6 hane + onay
    monkeypatch.setattr(setup_usb.getpass, "getpass", lambda _prompt: next(answers))

    result = setup_usb._prompt_pin()

    assert result == "123456"
    assert "en az 6" in capsys.readouterr().err.lower()


def test_prompt_pin_accepts_six_chars_immediately(monkeypatch) -> None:
    answers = iter(["abcdef", "abcdef"])
    monkeypatch.setattr(setup_usb.getpass, "getpass", lambda _prompt: next(answers))

    assert setup_usb._prompt_pin() == "abcdef"


def test_prompt_pin_still_enforces_confirmation(monkeypatch) -> None:
    """Uzunluk kontrolü değişti diye eşleşme kontrolü kaybolmamalı."""
    answers = iter(["123456", "654321", "abcdef", "abcdef"])
    monkeypatch.setattr(setup_usb.getpass, "getpass", lambda _prompt: next(answers))

    assert setup_usb._prompt_pin() == "abcdef"
