"""
CORE.totp_guard — TOTP replay-önleme (B-141).

`pyotp.TOTP(secret).verify(code, valid_window=1)` bir kodu KENDİ 30
saniyelik adımının dışında da (önceki/sonraki adım) kabul ediyor — yani
aynı kod, yakalanıp tekrar gönderilirse birden fazla kez kabul
edilebiliyordu. `verify_totp_no_replay()` bunu hwid başına "son kabul
edilen adım"ı DB'de tutarak kapatıyor.

Gerçek `pyotp` kullanılıyor, mock yok — yalnızca "şimdi" `simdi=` ile
sabit bir referans ana bağlanıyor (üretim çağrıları bunu hiç geçmiyor,
gerçek `time.time()` kullanıyor); `verify_totp_no_replay`'in kendisi de
`simdi`'yi AYNI referans olarak `pyotp.verify(..., for_time=...)`'e
geçiriyor, yani hem kod üretimi hem doğrulama AYNI (sabit) ana göre.
"""
from __future__ import annotations

import pyotp

from CORE.totp_guard import verify_totp_no_replay

_SECRET = pyotp.random_base32()
_HWID = "TOTP-GUARD-TEST-HWID"
_SIMDI = 1_800_000_000.0  # sabit referans an — testler arası tutarlı


def _kod_uret(delta_adim: int = 0) -> str:
    return pyotp.TOTP(_SECRET).at(_SIMDI + delta_adim * 30)


def test_gecerli_kod_ilk_seferinde_kabul_edilir(db) -> None:
    assert verify_totp_no_replay(_SECRET, _kod_uret(), _HWID, db=db, simdi=_SIMDI) is True


def test_ayni_kod_ikinci_kez_REDDEDILIR(db) -> None:
    """
    B-141'in kalbi: `valid_window=1` kodu ~90 saniye geçerli tutuyor —
    bu pencerede yakalanıp AYNEN tekrar gönderilen bir kod, yalnızca
    `pyotp.verify()`'e güvenilseydi ikinci kez de kabul edilirdi.

    Mutasyon-kanıt: `verify_totp_no_replay()`'deki `son_adim is not None
    and adim <= son_adim` kontrolü kaldırılırsa (ya da `if False:`'a
    çevrilirse) bu test KIRMIZIYA düşer — ikinci çağrı da True döner.
    """
    kod = _kod_uret()
    assert verify_totp_no_replay(_SECRET, kod, _HWID, db=db, simdi=_SIMDI) is True
    assert verify_totp_no_replay(_SECRET, kod, _HWID, db=db, simdi=_SIMDI) is False, (
        "aynı TOTP kodu ikinci kez de kabul edildi — replay engellenmiyor"
    )


def test_replay_bir_sonraki_adimda_tekrar_denense_bile_REDDEDILIR(db) -> None:
    """
    Yalnızca "aynı anda tekrar" değil: bir adımın kodu kabul edildikten
    SONRA, zaman biraz ilerlese bile (kodun kendi `valid_window=1`
    penceresi hâlâ AÇIKKEN) AYNI kodun tekrar sunulması reddedilmeli —
    saldırganın kodu yakalayıp birkaç saniye/onlarca saniye SONRA
    kullanmaya çalıştığı gerçekçi senaryo.
    """
    kod = _kod_uret()
    assert verify_totp_no_replay(_SECRET, kod, _HWID, db=db, simdi=_SIMDI) is True
    # 15 saniye sonra (hâlâ AYNI 30sn'lik adım içinde) aynı kod tekrar
    # denensin.
    assert verify_totp_no_replay(_SECRET, kod, _HWID, db=db, simdi=_SIMDI + 15) is False


def test_sonraki_adimin_FARKLI_kodu_hala_kabul_edilir(db) -> None:
    """Replay-önleme MEŞRU ilerlemeyi engellememeli: bir adımın kodu
    kabul edildikten sonra, SONRAKİ adımın (farklı) kodu hâlâ geçmeli."""
    assert verify_totp_no_replay(_SECRET, _kod_uret(0), _HWID, db=db, simdi=_SIMDI) is True
    assert verify_totp_no_replay(
        _SECRET, _kod_uret(1), _HWID, db=db, simdi=_SIMDI + 30
    ) is True


def test_yanlis_kod_reddedilir_ve_replay_kaydina_islenmez(db) -> None:
    assert verify_totp_no_replay(_SECRET, "000000", _HWID, db=db, simdi=_SIMDI) is False
    # Reddedilen bir deneme "son adım"ı KİRLETMEMELİ — hemen ardından
    # gelen GERÇEK kod yine kabul edilmeli.
    assert verify_totp_no_replay(_SECRET, _kod_uret(), _HWID, db=db, simdi=_SIMDI) is True


def test_farkli_hwidler_birbirinden_bagimsiz(db) -> None:
    """Bir HWID'in kullandığı adım, BAŞKA bir HWID'i etkilememeli."""
    kod = _kod_uret()
    assert verify_totp_no_replay(_SECRET, kod, "HWID-A", db=db, simdi=_SIMDI) is True
    assert verify_totp_no_replay(_SECRET, kod, "HWID-B", db=db, simdi=_SIMDI) is True
