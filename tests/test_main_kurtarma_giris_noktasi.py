"""
HYCLEUS — main.py'nin paketlenmiş kurtarma giriş noktaları (B-037)

`_erken_komut()`'un --recover/--takeover/--export dalı `CORE/recover_
vault.py::main()`'e DEVREDİYOR, mantığı KOPYALAMIYOR — bu testler
devretmenin kendisini doğruluyor (hangi bayrak hangi çağrıyı
tetikliyor, `SystemExit` kodu nasıl geri dönüyor). `recover_vault.py`'nin
kendi CLI davranışı (`_cmd_export`/`_cmd_recover`/`_cmd_takeover`/
`_cmd_status`) zaten `tests/test_recover_cli.py`'de kapsamlı test
ediliyor — burada TEKRAR EDİLMİYOR.

--status BİLEREK bu kümede YOK: istenen kapsam yalnızca --recover/
--takeover/--export idi.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    import main
except ImportError as exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({exc}) — testler atlanıyor",
        allow_module_level=True,
    )


def test_erken_komut_bilinmeyen_bayrakla_None_donup_normal_acilisa_devam_eder() -> None:
    assert main._erken_komut([]) is None
    assert main._erken_komut(["--bilinmeyen-bayrak"]) is None


def test_kurtarma_bayraklari_kumesi_tam_olarak_istenen_ucu_iceriyor() -> None:
    """--status BİLEREK YOK — istenen kapsam yalnızca bu üçüydü."""
    assert main._KURTARMA_BAYRAKLARI == frozenset(
        {"--recover", "--takeover", "--export"}
    )


@pytest.mark.parametrize("bayrak", ["--recover", "--takeover", "--export"])
def test_erken_komut_kurtarma_bayraklari_recover_vault_main_e_devrediyor(
    bayrak: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Her üç bayrak da GUI'yi hiç açmadan `CORE.recover_vault.main()`'e
    ulaşmalı — kurtarma mantığının KENDİSİ burada test edilmiyor, yalnızca
    devretme."""
    cagrildi: list[bool] = []

    def sahte_main() -> None:
        cagrildi.append(True)

    monkeypatch.setattr("CORE.recover_vault.main", sahte_main)
    kod = main._erken_komut([bayrak])
    assert cagrildi == [True], f"{bayrak} recover_vault.main()'i çağırmadı"
    assert kod == 0


def test_erken_komut_recover_vault_SystemExit_kodunu_aynen_donduruyor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_cmd_recover()`/`_cmd_export()`/`_cmd_takeover()` bir hatada
    `sys.exit(1)` çağırıyor (`_abort()`, bkz. recover_vault.py) — bu kod
    main()'in kendi `sys.exit(kod)`'una AYNEN taşınmalı."""
    def sahte_main() -> None:
        raise SystemExit(2)

    monkeypatch.setattr("CORE.recover_vault.main", sahte_main)
    assert main._erken_komut(["--recover"]) == 2


def test_erken_komut_recover_vault_argumansiz_SystemExit_0_a_esitleniyor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`sys.exit()` (argümansız) -> `.code` `None` — Python'ın kendi
    kuralıyla AYNI: süreç 0 ile çıkar."""
    def sahte_main() -> None:
        raise SystemExit()

    monkeypatch.setattr("CORE.recover_vault.main", sahte_main)
    assert main._erken_komut(["--recover"]) == 0


def test_erken_komut_recover_vault_metin_kodu_1_e_esitleniyor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`sys.exit("hata mesajı")` -> `.code` bir STRING (int DEĞİL);
    Python'ın kendi tercümanı bunu stderr'e yazıp çıkış kodu 1 ile
    çıkıyor — `_erken_komut()` AYNI davranışı taklit etmeli."""
    def sahte_main() -> None:
        raise SystemExit("hata")

    monkeypatch.setattr("CORE.recover_vault.main", sahte_main)
    assert main._erken_komut(["--recover"]) == 1


@pytest.mark.parametrize("bayrak", ["-h", "--help"])
def test_erken_komut_YARDIM_bayraklari_da_recover_vault_main_e_devrediyor(
    bayrak: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kalıcı regresyon kanıtı: `_KURTARMA_BAYRAKLARI`'na dahil edilmeden
    önce ÖLÇÜLDÜ — `-h`/`--help` `_erken_komut()`'un HİÇBİR dalıyla
    eşleşmiyordu, `None` dönüp normal GUI açılışına devam ediyordu
    (gerçek `HYCLEUS-Kurtarma.exe --help` çalıştırıldığında 30 sn ASILI
    KALDI, USB bulunamayınca açılan bir QMessageBox'ı bekleyerek —
    `--selftest`in başta kaçındığı TAM AYNI duvar). `-h`/`--help` de
    artık aynı devretme dalına giriyor; help METNİNİN KENDİSİ
    `argparse`'ın kendi `-h` işleyişinden geliyor, burada üretilmiyor."""
    cagrildi: list[bool] = []

    def sahte_main() -> None:
        cagrildi.append(True)

    monkeypatch.setattr("CORE.recover_vault.main", sahte_main)
    kod = main._erken_komut([bayrak])
    assert cagrildi == [True], f"{bayrak} recover_vault.main()'i çağırmadı"
    assert kod == 0


def test_erken_komut_recover_vault_normal_tamamlanirsa_0_donuyor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`recover_vault.main()` hiç `SystemExit` fırlatmadan normal
    dönerse (ör. kullanıcı bir onay isteminde HAYIR dedi, `_cmd_*` fonksiyonu
    sessizce `return` etti) `_erken_komut()` yine de 0 dönmeli — GUI
    normal açılışa DEVAM ETMEMELİ, süreç burada temiz çıkmalı."""
    def sahte_main() -> None:
        return None

    monkeypatch.setattr("CORE.recover_vault.main", sahte_main)
    assert main._erken_komut(["--export"]) == 0
