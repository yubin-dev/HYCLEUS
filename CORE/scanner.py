import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

import requests

_VT_BASE = "https://www.virustotal.com/api/v3"
_ENV_FILE = Path(__file__).parent.parent / ".env"
_CHUNK    = 65536


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


# ------------------------------------------------------------------
# .env okuyucu
# ------------------------------------------------------------------

def _load_api_key() -> str | None:
    key = os.getenv("VT_API_KEY")
    if key:
        return key
    if not _ENV_FILE.exists():
        return None
    for raw in _ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip() == "VT_API_KEY":
            return v.strip().strip('"').strip("'")
    return None


# ------------------------------------------------------------------
# Hash
# ------------------------------------------------------------------

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------
# VirusTotal sorgusu
# ------------------------------------------------------------------

def _mock(sha256: str) -> ScanResult:
    return ScanResult(
        sha256=sha256, malicious=0, suspicious=0,
        harmless=0, undetected=0, engines_total=0,
        verdict="unknown", mock=True,
    )


def _query_vt(sha256: str, api_key: str) -> ScanResult:
    try:
        resp = requests.get(
            f"{_VT_BASE}/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
    except Exception:
        return _mock(sha256)

    if resp.status_code == 404:
        # VT'de kayıt yok — temiz ya da hiç analiz edilmemiş
        return ScanResult(
            sha256=sha256, malicious=0, suspicious=0,
            harmless=0, undetected=0, engines_total=0,
            verdict="unknown", mock=False,
        )
    if resp.status_code == 429:
        # Rate limit aşıldı
        return _mock(sha256)
    try:
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    except Exception:
        return _mock(sha256)

    mal  = stats.get("malicious",  0)
    sus  = stats.get("suspicious", 0)
    har  = stats.get("harmless",   0)
    undet = stats.get("undetected", 0)
    total = mal + sus + har + undet + stats.get("timeout", 0) + stats.get("failure", 0)

    if mal > 0:
        verdict = "malicious"
    elif sus > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return ScanResult(
        sha256=sha256, malicious=mal, suspicious=sus,
        harmless=har, undetected=undet, engines_total=total,
        verdict=verdict, mock=False,
    )


# ------------------------------------------------------------------
# DB kaydı
# ------------------------------------------------------------------

def _save_to_db(file_id: int, result: ScanResult) -> None:
    from DB.db_manager import DBManager
    db = DBManager()
    reason = json.dumps({
        "source":        "virustotal",
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
        "vt_scan",
        target_type="file",
        target_id=file_id,
        detail=f"verdict={result.verdict} mock={result.mock}",
    )


# ------------------------------------------------------------------
# Genel arayüz
# ------------------------------------------------------------------

def scan_file(path: "Path | str", file_id: int | None = None) -> ScanResult:
    """SHA-256 hesaplar, VirusTotal Public API'yi sorgular.

    API anahtarı yoksa, 429 veya bağlantı hatası olursa mock sonuç döner.
    file_id verilirse sonuç quarantine tablosuna kaydedilir.
    """
    path = Path(path)
    sha  = _sha256(path)

    api_key = _load_api_key()
    result  = _query_vt(sha, api_key) if api_key else _mock(sha)

    if file_id is not None:
        try:
            _save_to_db(file_id, result)
        except Exception:
            pass  # DB kaydı başarısız olsa da result dönsün

    return result
