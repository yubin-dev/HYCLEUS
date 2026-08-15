"""
CORE/backup_cli.py — yedek doğrulama / geri yükleme aracının testleri.

Bu araç bir FELAKET aracı: tipik kullanım anı "disk gitti, yeni makine".
Dolayısıyla test edilmesi gereken şey yalnızca doğru çalışması değil,
doğru ŞEYİ söylemesi ve çıkış koduyla doğru sinyali vermesi — bir
yedekleme betiği sonucu koddan okuyacak.

Anahtar isteyen yollar (`--deep`, `--restore`) USB + PIN istiyor;
testlerde `_load_key` yamalanıyor. Anahtarsız yollar (`--info`,
`--verify`) hiç dokunmuyor ve bu ayrım ayrıca sınanıyor.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from CORE import backup_cli, crypto
from CORE.backup import MANIFEST_NAME, METADATA_NAME, create_backup
from CORE.crypto import encrypt_file, generate_key

_USER = 3
_HWID = "TEST-HWID-CLI"
_SCRIPT = Path(__file__).resolve().parent.parent / "CORE" / "backup_cli.py"


@pytest.fixture
def key() -> bytes:
    return generate_key()


@pytest.fixture
def yedek(tmp_path: Path, key: bytes, db, monkeypatch: pytest.MonkeyPatch) -> Path:
    q = tmp_path / "quarantine"
    q.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", q)
    for ad in ("a.txt", "b.txt"):
        src = tmp_path / ad
        src.write_bytes(f"{ad} icerigi".encode() * 20)
        encrypt_file(src, key, _USER, hwid=_HWID)
        src.unlink()
    return create_backup(
        db, tmp_path / "yedek", key, vault_dir=q, user_id=_USER, hwid=_HWID
    ).path


@pytest.fixture
def anahtar_ver(monkeypatch: pytest.MonkeyPatch, key: bytes):
    """USB + PIN akışını atlayıp anahtarı doğrudan verir."""
    monkeypatch.setattr(backup_cli, "_load_key", lambda: (key, _HWID))
    return key


@pytest.fixture
def usb_yok(monkeypatch: pytest.MonkeyPatch):
    """
    Anahtar alınamadığı durum.

    `_load_key` yamalanmıyor; onun yerine USB okuyucusu None döndürüyor,
    yani gerçek hata yolu koşuyor.
    """
    import CORE.usb_manager as um

    monkeypatch.setattr(um, "get_usb_hwid", lambda: None)


# ══════════════════════════════════════════════════════════════════════════════
# 1. --info
# ══════════════════════════════════════════════════════════════════════════════


def test_info_summarises_the_manifest(yedek, capsys) -> None:
    assert backup_cli.main(["--info", str(yedek)]) == 0
    cikti = capsys.readouterr().out
    assert "HYCLEUS-BACKUP-V1" in cikti
    assert "2 adet" in cikti


def test_info_needs_no_key(yedek, usb_yok, capsys) -> None:
    """
    `--info` USB'ye ve keyring'e HİÇ dokunmamalı: bir yedeğin ne olduğuna
    bakmak için kasayı açmak gerekmiyor.
    """
    assert backup_cli.main(["--info", str(yedek)]) == 0


def test_info_on_a_missing_backup_exits_one(tmp_path, capsys) -> None:
    assert backup_cli.main(["--info", str(tmp_path / "yok")]) == 1
    assert "Manifesto bulunamadı" in capsys.readouterr().err


# ══════════════════════════════════════════════════════════════════════════════
# 2. --verify
# ══════════════════════════════════════════════════════════════════════════════


def test_verify_reports_a_healthy_backup(yedek, capsys) -> None:
    assert backup_cli.main(["--verify", str(yedek)]) == 0
    cikti = capsys.readouterr().out
    assert "SAĞLAM" in cikti
    assert "--deep" in cikti, "sığ doğrulamanın sınırı söylenmeli"


def test_shallow_verify_needs_no_key(yedek, usb_yok) -> None:
    """
    Anahtarsız doğrulama, zamanlanmış bir yedekleme betiğinden
    çağrılabilmeli — bu yüzden USB yokken de çalışmalı.
    """
    assert backup_cli.main(["--verify", str(yedek)]) == 0


def test_verify_exits_one_on_a_missing_file(yedek, capsys) -> None:
    """Çıkış kodu önemli: bir betik sonucu buradan okuyacak."""
    next((yedek / "files").glob("*.hcl")).unlink()
    assert backup_cli.main(["--verify", str(yedek)]) == 1
    cikti = capsys.readouterr().out
    assert "KUSURLU" in cikti and "EKSIK" in cikti


def test_verify_names_the_broken_files(yedek, capsys) -> None:
    kurban = next((yedek / "files").glob("*.hcl"))
    kurban.write_bytes(b"bozuk")
    backup_cli.main(["--verify", str(yedek)])
    assert kurban.name in capsys.readouterr().out


def test_deep_verify_uses_the_key(yedek, anahtar_ver, capsys) -> None:
    assert backup_cli.main(["--verify", str(yedek), "--deep"]) == 0
    cikti = capsys.readouterr().out
    assert "GCM doğrulaması dahil" in cikti
    assert "--deep" not in cikti.split("SAĞLAM")[-1], "zaten derin, öneri çıkmamalı"


def test_deep_verify_without_a_usb_fails_clearly(yedek, usb_yok, capsys) -> None:
    assert backup_cli.main(["--verify", str(yedek), "--deep"]) == 1
    assert "USB" in capsys.readouterr().err


def test_a_tampered_manifest_is_reported(yedek, anahtar_ver, capsys) -> None:
    manifest = json.loads((yedek / MANIFEST_NAME).read_text(encoding="utf-8"))
    manifest["entries"] = manifest["entries"][:1]
    (yedek / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")

    assert backup_cli.main(["--verify", str(yedek), "--deep"]) == 1
    assert "UYUSMUYOR" in capsys.readouterr().out


# ══════════════════════════════════════════════════════════════════════════════
# 3. --restore
# ══════════════════════════════════════════════════════════════════════════════


def test_restore_writes_to_the_destination(yedek, anahtar_ver, tmp_path, capsys) -> None:
    hedef = tmp_path / "geri"
    assert backup_cli.main(["--restore", str(yedek), "--dest", str(hedef)]) == 0

    assert len(list((hedef / "files").glob("*.hcl"))) == 2
    cikti = capsys.readouterr().out
    assert "AYRI bir konuma" in cikti
    assert "DOKUNULMADI" in cikti


def test_restore_requires_dest(yedek, capsys) -> None:
    assert backup_cli.main(["--restore", str(yedek)]) == 1
    assert "--dest" in capsys.readouterr().err


def test_restore_refuses_a_corrupt_backup(yedek, anahtar_ver, tmp_path, capsys) -> None:
    """
    Doğrulama geri yüklemenin ÖNKOŞULU. Bu araç geri alınamaz bir işlem
    yapıyor; kusurlu veriyle yapmamalı.
    """
    next((yedek / "files").glob("*.hcl")).unlink()
    hedef = tmp_path / "geri"

    assert backup_cli.main(["--restore", str(yedek), "--dest", str(hedef)]) == 1
    assert "doğrulanamadı" in capsys.readouterr().err
    assert not hedef.exists()


def test_restore_refuses_a_non_empty_dest(yedek, anahtar_ver, tmp_path, capsys) -> None:
    hedef = tmp_path / "dolu"
    hedef.mkdir()
    (hedef / "onemli.txt").write_bytes(b"kaybolmamali")

    assert backup_cli.main(["--restore", str(yedek), "--dest", str(hedef)]) == 1
    assert "boş değil" in capsys.readouterr().err
    assert (hedef / "onemli.txt").read_bytes() == b"kaybolmamali"


def test_overwrite_is_explicit(yedek, anahtar_ver, tmp_path) -> None:
    hedef = tmp_path / "dolu"
    hedef.mkdir()
    (hedef / "eski.txt").write_bytes(b"x")
    assert backup_cli.main(
        ["--restore", str(yedek), "--dest", str(hedef), "--overwrite"]) == 0


def test_restore_does_not_touch_the_source_backup(
    yedek, anahtar_ver, tmp_path
) -> None:
    once = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(yedek.rglob("*")) if p.is_file()}
    backup_cli.main(["--restore", str(yedek), "--dest", str(tmp_path / "geri")])
    sonra = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(yedek.rglob("*")) if p.is_file()}
    assert once == sonra


# ══════════════════════════════════════════════════════════════════════════════
# 4. Gerçek süreç
# ══════════════════════════════════════════════════════════════════════════════


def test_the_script_runs_as_a_real_process(yedek) -> None:
    """
    `python CORE/backup_cli.py --info ...` gerçekten çalışıyor mu.

    `main()`'i doğrudan çağırmak sys.path bootstrap'ını ve `__main__`
    bloğunu atlar; araç asıl bu şekilde kullanılacak.
    """
    sonuc = subprocess.run(
        [sys.executable, str(_SCRIPT), "--info", str(yedek)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert sonuc.returncode == 0, sonuc.stderr
    assert "HYCLEUS-BACKUP-V1" in sonuc.stdout


def test_the_output_survives_a_non_utf8_console(yedek) -> None:
    """
    Bu oturumda üç kez çıkan hata sınıfı — çıktıdaki Türkçe harfler
    cp1252 konsolunda UnicodeEncodeError verirdi. `ensure_utf8_console()`
    çağrılıyor; geri alınırsa bu test kırılır.
    """
    ortam = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    sonuc = subprocess.run(
        [sys.executable, str(_SCRIPT), "--verify", str(yedek)],
        capture_output=True, env=ortam,
    )
    assert sonuc.returncode == 0
    assert b"Traceback" not in sonuc.stderr


def test_a_broken_backup_exits_nonzero_as_a_process(yedek, tmp_path) -> None:
    """Bir yedekleme betiği sonucu çıkış kodundan okuyabilmeli."""
    (yedek / METADATA_NAME).unlink()
    sonuc = subprocess.run(
        [sys.executable, str(_SCRIPT), "--verify", str(yedek)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert sonuc.returncode == 1
