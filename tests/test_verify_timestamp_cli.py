"""
CORE/verify_timestamp_cli.py — komut satırı doğrulayıcısının testleri.

`main()` doğrudan çağrılıyor (alt süreç değil): çıkış kodu ve stdout,
`capsys` ile okunabiliyor ve testler hızlı kalıyor. Alt süreç yalnızca
`__main__` yolunun gerçekten çalıştığını kanıtlamak için bir kez
kullanılıyor.

Bu araç bir DENETİM aracı: çıktısı bir denetim dosyasına yapıştırılıyor ve
çıkış kodu bir betik tarafından okunuyor. Dolayısıyla test edilen şey
yalnızca "doğru mu çalışıyor" değil, "doğru ŞEYİ mi söylüyor" — özellikle
kök doğrulanmadığında bunu açıkça yazıp yazmadığı.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest
from tsa_fixtures import FakeTSA, build_authority, build_token, default_authority

from CORE import crypto
from CORE.crypto import encrypt_file, generate_key
from CORE.timestamp import TimestampInfo, attach_trailer, timestamp_file
from CORE.verify_timestamp_cli import main

_USER_ID = 3
_HWID = "TEST-HWID-CLI"
_SCRIPT = Path(__file__).resolve().parent.parent / "CORE" / "verify_timestamp_cli.py"


@pytest.fixture(autouse=True)
def _quarantine_to_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    out = tmp_path / "quarantine"
    out.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", out)
    return out


@pytest.fixture
def key() -> bytes:
    return generate_key()


def _hcl(tmp_path: Path, key: bytes, content: bytes = b"denetim belgesi") -> Path:
    src = tmp_path / "belge.bin"
    src.write_bytes(content)
    dst, _sha, _aad = encrypt_file(src, key, _USER_ID, hwid=_HWID)
    return dst


@pytest.fixture
def stamped(tmp_path: Path, key: bytes) -> Path:
    path = _hcl(tmp_path, key)
    timestamp_file(path, key, transport=FakeTSA())
    return path


@pytest.fixture
def key_file(tmp_path: Path, key: bytes) -> Path:
    """
    Ham 32 baytlık anahtarı bir dosyaya yazar — B-092/B-099'dan beri
    `--key-file` ZORUNLU (bkz. `CORE/verify_timestamp_cli.py` modül
    docstring'i).
    """
    yol = tmp_path / "anahtar.bin"
    yol.write_bytes(key)
    return yol


# ══════════════════════════════════════════════════════════════════════════════
# Çıkış kodları
# ══════════════════════════════════════════════════════════════════════════════


def test_a_valid_stamp_exits_zero(
    stamped: Path, key_file: Path, capsys: pytest.CaptureFixture
) -> None:
    assert main(["--verify-timestamp", str(stamped), "--key-file", str(key_file)]) == 0
    assert "GECERLI" in capsys.readouterr().out


def test_an_unstamped_file_exits_one(
    tmp_path: Path, key: bytes, key_file: Path, capsys: pytest.CaptureFixture
) -> None:
    assert main(
        ["--verify-timestamp", str(_hcl(tmp_path, key)), "--key-file", str(key_file)]
    ) == 1
    çıktı = capsys.readouterr().out
    assert "GECERSIZ" in çıktı
    assert "damgalı değil" in çıktı


def test_a_missing_file_exits_one(
    tmp_path: Path, key_file: Path, capsys: pytest.CaptureFixture
) -> None:
    assert main(
        ["--verify-timestamp", str(tmp_path / "yok.hcl"), "--key-file", str(key_file)]
    ) == 1
    assert "bulunamadi" in capsys.readouterr().err


def test_a_non_hcl_file_exits_one(
    tmp_path: Path, key_file: Path, capsys: pytest.CaptureFixture
) -> None:
    duz = tmp_path / "duz.txt"
    duz.write_bytes(b"hcl degil")
    assert main(["--verify-timestamp", str(duz), "--key-file", str(key_file)]) == 1


def test_key_file_is_required(
    stamped: Path, capsys: pytest.CaptureFixture
) -> None:
    """
    B-092/B-099: `--key-file` artık ZORUNLU — argparse eksikse kullanım
    hatasıyla (çıkış kodu 2) düşmeli, sessizce anahtarsız devam ETMEMELİ.
    """
    with pytest.raises(SystemExit) as exc:
        main(["--verify-timestamp", str(stamped)])
    assert exc.value.code == 2
    assert "--key-file" in capsys.readouterr().err


def test_key_file_of_the_wrong_size_is_refused(
    stamped: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Ham 32 bayt bekleniyor — hex/base64 kodlu bir metin DEĞİL."""
    yanlis = tmp_path / "yanlis-boyut.bin"
    yanlis.write_bytes(b"cok-kisa")

    with pytest.raises(SystemExit) as exc:
        main(["--verify-timestamp", str(stamped), "--key-file", str(yanlis)])
    assert exc.value.code == 1
    assert "32 bayt olmalı" in capsys.readouterr().err


# ══════════════════════════════════════════════════════════════════════════════
# Çıktının içeriği
# ══════════════════════════════════════════════════════════════════════════════


def test_the_output_names_the_time_the_tsa_and_the_digest(
    stamped: Path, key_file: Path, capsys: pytest.CaptureFixture
) -> None:
    main(["--verify-timestamp", str(stamped), "--key-file", str(key_file)])
    çıktı = capsys.readouterr().out
    assert "Damga zamani" in çıktı
    assert "HYCLEUS Test TSA" in çıktı
    assert "2026-08-13T12:00:00" in çıktı
    assert "Seri no" in çıktı


def test_an_unverified_root_is_stated_loudly(
    stamped: Path, key_file: Path, capsys: pytest.CaptureFixture
) -> None:
    """
    ARACIN EN ÖNEMLİ ÇIKTISI. "GECERLI" demek, kökün güvenilir olduğunu
    söylemiyor — ve araç bunu her seferinde yazmak zorunda. Yazmazsa
    kullanıcı, hak etmediği bir güvence okur.
    """
    main(["--verify-timestamp", str(stamped), "--key-file", str(key_file)])
    çıktı = capsys.readouterr().out
    assert "UYARI" in çıktı
    assert "DOGRULANMADI" in çıktı
    assert "--trusted-root" in çıktı


def test_a_trusted_root_replaces_the_warning(
    stamped: Path, key_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    kok = tmp_path / "ca.der"
    kok.write_bytes(default_authority().ca_der)

    assert main([
        "--verify-timestamp", str(stamped), "--key-file", str(key_file),
        "--trusted-root", str(kok),
    ]) == 0
    çıktı = capsys.readouterr().out
    assert "Kok GUVENILIR" in çıktı
    assert "UYARI" not in çıktı


def test_a_pem_trusted_root_is_accepted(
    stamped: Path, key_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Sertifikalar pratikte PEM olarak dağıtılıyor; DER dayatmak aracı kullanılmaz yapardı."""
    kok = tmp_path / "ca.pem"
    kok.write_bytes(default_authority().ca_pem)

    assert main([
        "--verify-timestamp", str(stamped), "--key-file", str(key_file),
        "--trusted-root", str(kok),
    ]) == 0
    assert "Kok GUVENILIR" in capsys.readouterr().out


def test_a_wrong_trusted_root_fails_with_a_reason(
    stamped: Path, key_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    kok = tmp_path / "baska.der"
    kok.write_bytes(build_authority().ca_der)

    assert main([
        "--verify-timestamp", str(stamped), "--key-file", str(key_file),
        "--trusted-root", str(kok),
    ]) == 1
    çıktı = capsys.readouterr().out
    assert "GECERSIZ" in çıktı
    assert "trust_anchor" in çıktı


def test_show_chain_prints_the_chain(
    stamped: Path, key_file: Path, capsys: pytest.CaptureFixture
) -> None:
    main(["--verify-timestamp", str(stamped), "--key-file", str(key_file), "--show-chain"])
    çıktı = capsys.readouterr().out
    assert "Sertifika zinciri" in çıktı
    assert "HYCLEUS Test TSA" in çıktı
    assert "HYCLEUS Test Root CA" in çıktı


def test_quiet_prints_one_line(
    stamped: Path, key_file: Path, capsys: pytest.CaptureFixture
) -> None:
    main(["--verify-timestamp", str(stamped), "--key-file", str(key_file), "--quiet"])
    satırlar = capsys.readouterr().out.strip().splitlines()
    assert len(satırlar) == 1
    assert satırlar[0].startswith(stamped.name)


def test_the_failure_reason_is_actionable(
    tmp_path: Path, key: bytes, key_file: Path, capsys: pytest.CaptureFixture
) -> None:
    """
    "GECERSIZ" tek başına işe yaramaz; hangi adımda düştüğü yazmalı.
    """
    path = _hcl(tmp_path, key)
    from CORE.timestamp import file_digest

    başka = hashlib.sha256(b"baska icerik").digest()
    attach_trailer(path, TimestampInfo(
        hash_algorithm="sha256",
        hashed_hex=file_digest(path, key=key, hwid=_HWID),
        tsa_url="https://x/tsr",
        token_der=build_token(başka, 1),
    ))

    assert main(["--verify-timestamp", str(path), "--key-file", str(key_file)]) == 1
    çıktı = capsys.readouterr().out
    assert "Adim  : digest_match" in çıktı
    assert "Gecen :" in çıktı  # nereye kadar geldiği de görünmeli


def test_an_unreadable_trusted_root_exits_one(
    stamped: Path, key_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    with pytest.raises(SystemExit) as exc:
        main([
            "--verify-timestamp", str(stamped), "--key-file", str(key_file),
            "--trusted-root", str(tmp_path / "yok.der"),
        ])
    assert exc.value.code == 1
    assert "okunamadi" in capsys.readouterr().err


# ══════════════════════════════════════════════════════════════════════════════
# Gerçek süreç
# ══════════════════════════════════════════════════════════════════════════════


def test_the_script_runs_as_a_real_process(stamped: Path, key_file: Path) -> None:
    """
    `python CORE/verify_timestamp_cli.py ...` gerçekten çalışıyor mu.

    `main()`'i doğrudan çağırmak sys.path bootstrap'ını ve `__main__`
    bloğunu atlar; araç asıl bu şekilde kullanılacak.
    """
    sonuc = subprocess.run(
        [sys.executable, str(_SCRIPT), "--verify-timestamp", str(stamped),
         "--key-file", str(key_file), "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert sonuc.returncode == 0, sonuc.stderr
    assert "GE" in sonuc.stdout  # GEÇERLİ (kodlama ortamdan bağımsız olsun)


def test_the_output_survives_a_non_utf8_console(stamped: Path, key_file: Path) -> None:
    """
    GERÇEK BİR HATANIN TESTİ.

    Windows konsolunda (cp1254) zincir ağacının çizgi karakterleri ve
    doğrulama mesajlarındaki Türkçe harfler UnicodeEncodeError veriyordu:
    araç doğru sonucu HESAPLAYIP onu yazdırırken çöküyordu. `capsys` bunu
    yakalayamaz — gerçek bir akış kodlaması gerekiyor.

    Bu yüzden alt süreç, cp1252 dayatılarak ve `--show-chain` ile
    çalıştırılıyor: hem ağaç karakterleri hem Türkçe metin yolda.

    Düzeltmenin kendisi artık `CORE.console.ensure_utf8_console()`; bu test
    onun BU ARAÇTA etkili olduğunu sınıyor. Yardımcının kendi testleri
    tests/test_console.py içinde.
    """
    import os

    ortam = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    sonuc = subprocess.run(
        [sys.executable, str(_SCRIPT), "--verify-timestamp", str(stamped),
         "--key-file", str(key_file), "--show-chain"],
        capture_output=True, env=ortam,
    )
    assert sonuc.returncode == 0, sonuc.stderr.decode("utf-8", "replace")
    assert b"Traceback" not in sonuc.stderr
    assert b"GECERLI" in sonuc.stdout


def test_an_invalid_result_also_prints_on_a_non_utf8_console(
    tmp_path: Path, key: bytes, key_file: Path
) -> None:
    """Hata yolundaki Türkçe metin ('damgalı değil') de çökmemeli."""
    import os

    ortam = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    sonuc = subprocess.run(
        [sys.executable, str(_SCRIPT), "--verify-timestamp", str(_hcl(tmp_path, key)),
         "--key-file", str(key_file)],
        capture_output=True, env=ortam,
    )
    assert sonuc.returncode == 1
    assert b"Traceback" not in sonuc.stderr
    assert b"GECERSIZ" in sonuc.stdout


def test_the_process_exit_code_signals_failure(
    tmp_path: Path, key: bytes, key_file: Path
) -> None:
    """Bir denetim betiği sonucu çıkış kodundan okuyabilmeli."""
    sonuc = subprocess.run(
        [sys.executable, str(_SCRIPT), "--verify-timestamp", str(_hcl(tmp_path, key)),
         "--key-file", str(key_file), "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert sonuc.returncode == 1
