"""HYCLEUS — Windows Defender tarama modülü"""
from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger("hycleus.scanner")

_MPCMDRUN = Path(r"C:\Program Files\Windows Defender\MpCmdRun.exe")
_SCAN_TIMEOUT = 120   # saniye
_CHUNK        = 65536

# MpCmdRun.exe varlık testi — modül yüklenirken logla
if _MPCMDRUN.exists():
    _DEFENDER_AVAILABLE = True
    _log.info("defender_found  path=%s", _MPCMDRUN)
else:
    _DEFENDER_AVAILABLE = False
    _log.warning("defender_not_found  path=%s  — mock döndürülecek", _MPCMDRUN)


@dataclass
class ScanResult:
    sha256:        str
    malicious:     int
    suspicious:    int
    harmless:      int
    undetected:    int
    engines_total: int
    verdict:       str   # "clean" | "suspicious" | "malicious" | "unknown"
    mock:          bool


# Hash ------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


# Yardımcılar -----------------------------------------------------------------

def _mock(sha256: str) -> ScanResult:
    return ScanResult(
        sha256=sha256, malicious=0, suspicious=0,
        harmless=0, undetected=0, engines_total=0,
        verdict="unknown", mock=True,
    )


def _clean(sha256: str) -> ScanResult:
    return ScanResult(
        sha256=sha256, malicious=0, suspicious=0,
        harmless=1, undetected=0, engines_total=1,
        verdict="clean", mock=False,
    )


def _malicious(sha256: str) -> ScanResult:
    return ScanResult(
        sha256=sha256, malicious=1, suspicious=0,
        harmless=0, undetected=0, engines_total=1,
        verdict="malicious", mock=False,
    )


# Windows Defender ------------------------------------------------------------

def _scan_via_defender(path: Path, sha256: str) -> ScanResult | None:
    """MpCmdRun.exe -Scan -ScanType 3 -File <path> ile tarar.
    rc=0 → clean, rc=2 → malicious, diğerleri → None (mock'a düşer).
    MpCmdRun.exe yoksa None döner.
    """
    if not _DEFENDER_AVAILABLE:
        return None
    try:
        proc = subprocess.run(
            [str(_MPCMDRUN), "-Scan", "-ScanType", "3", "-File", str(path)],
            capture_output=True,
            text=True,
            timeout=_SCAN_TIMEOUT,
        )
        _log.info(
            "defender_scan  rc=%d  file=%s  out=%s",
            proc.returncode, path.name,
            proc.stdout.strip()[:200],
        )
        if proc.returncode == 0:
            return _clean(sha256)
        if proc.returncode == 2:
            _log.warning("defender_threat  file=%s  out=%s",
                         path.name, proc.stdout.strip()[:200])
            return _malicious(sha256)
        _log.warning("defender_rc_unknown  rc=%d  file=%s  stderr=%s",
                     proc.returncode, path.name, proc.stderr.strip()[:200])
        return None
    except subprocess.TimeoutExpired:
        _log.warning("defender_timeout  file=%s", path.name)
        return None
    except Exception as exc:
        _log.warning("defender_error  %s", exc)
        return None


# DB kaydı --------------------------------------------------------------------

def _save_to_db(file_id: int, result: ScanResult) -> None:
    from DB.db_manager import DBManager
    db = DBManager()
    reason = json.dumps({
        "source":        "windows_defender",
        "sha256":        result.sha256,
        "verdict":       result.verdict,
        "malicious":     result.malicious,
        "suspicious":    result.suspicious,
        "engines_total": result.engines_total,
        "mock":          result.mock,
    }, ensure_ascii=False)

    existing = db.fetchone(
        "SELECT id FROM quarantine WHERE file_id = ?", (file_id,)
    )
    if existing:
        db.execute(
            "UPDATE quarantine SET reason = ? WHERE file_id = ?",
            (reason, file_id),
        )
    else:
        db.execute(
            "INSERT INTO quarantine (file_id, reason) VALUES (?, ?)",
            (file_id, reason),
        )
    db.log(
        "defender_scan",
        target_type="file",
        target_id=file_id,
        detail=f"verdict={result.verdict} mock={result.mock}",
    )


# Genel arayüz ----------------------------------------------------------------

def scan_file(path: "Path | str", file_id: int | None = None) -> ScanResult:
    """Windows Defender ile dosya tarar.

    MpCmdRun.exe bulunamazsa veya tarama başarısız olursa mock ScanResult döner.
    file_id verilirse sonuç quarantine tablosuna kaydedilir.
    """
    path = Path(path)
    sha  = _sha256(path)
    _log.info("scan_start  file=%s  size=%d  sha256=%.16s",
              path.name, path.stat().st_size, sha)

    result = _scan_via_defender(path, sha) or _mock(sha)

    _log.info("scan_result  file=%s  verdict=%s  mal=%d  mock=%s",
              path.name, result.verdict, result.malicious, result.mock)

    if file_id is not None:
        try:
            _save_to_db(file_id, result)
        except Exception:
            _log.exception("scan_db_error  file_id=%d", file_id)

    return result


def scan_by_hash(sha256: str, file_id: int | None = None) -> ScanResult:
    """Hash ile tarama — Defender dosya içeriğine ihtiyaç duyar, mock döner.

    Karantina gibi orijinal dosyanın erişilebilir olmadığı durumlar için
    arayüz bütünlüğü amacıyla tutulmuştur.
    """
    _log.info("scan_by_hash  sha256=%.16s — dosya yok, mock döndürülüyor", sha256)
    result = _mock(sha256)
    if file_id is not None:
        try:
            _save_to_db(file_id, result)
        except Exception:
            pass
    return result
