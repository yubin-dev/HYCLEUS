"""HYCLEUS — antivirüs tarama akışı (motordan bağımsız).

Tarama motorları `CORE/scanner_backends.py` içinde. Bu dosya artık hangi
motorun çalıştığını bilmiyor: `select_backend()` platformun uygun arka ucunu
veriyor (Windows → Defender, diğerleri → ClamAV), buradaki iş yalnızca
hash almak, sonucu karantina tablosuna yazmak ve denetim zincirine
kaydetmek.

Genel arayüz (`scan_file`, `scan_by_hash`, `ScanResult`) değişmedi; UI
tarafındaki çağrı yerleri olduğu gibi çalışıyor.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from CORE.console import ensure_utf8_console
from CORE.scanner_backends import (
    ScannerBackend,
    ScanResult,
    mock_result,
    select_backend,
    sha256_of,
)

_log = logging.getLogger("hycleus.scanner")


# DB kaydı --------------------------------------------------------------------

def _save_to_db(file_id: int, result: ScanResult, audit_action: str) -> None:
    import sqlite3 as _sqlite3

    from CORE.audit_chain import append_entry
    from DB.db_manager import DBManager

    # Thread-safe: singleton'ın connection'ını paylaşmak yerine
    # her scan thread'i kendi bağlantısını açar.
    db_path = str(DBManager()._db_path)
    reason = json.dumps({
        "source":        result.engine,
        "sha256":        result.sha256,
        "verdict":       result.verdict,
        "malicious":     result.malicious,
        "suspicious":    result.suspicious,
        "engines_total": result.engines_total,
        "mock":          result.mock,
        "threat":        result.threat,
    }, ensure_ascii=False)

    conn = _sqlite3.connect(db_path)
    conn.row_factory = _sqlite3.Row
    try:
        existing = conn.execute(
            "SELECT id FROM quarantine WHERE file_id = ?", (file_id,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE quarantine SET reason = ? WHERE file_id = ?",
                (reason, file_id),
            )
        else:
            conn.execute(
                "INSERT INTO quarantine (file_id, reason) VALUES (?, ?)",
                (file_id, reason),
            )
        conn.commit()

        # Denetim kaydı hash zincirine eklenir (bkz. CORE/audit_chain.py).
        # Düz INSERT bırakılsaydı satır hash'siz kalır ve doğrulama onu
        # "unhashed" olarak — yani zincirde bir delik olarak — raporlardı.
        #
        # Karantina yazmasından SONRA ve ayrı bir transaction'da: append_entry
        # kendi BEGIN IMMEDIATE'ini açıyor, araya sıkıştırılsaydı buradaki
        # yarım işi erkenden commit ederdi.
        #
        # Eylem adı arka uçtan geliyor: bir ClamAV bulgusunu "defender_scan"
        # diye kaydetmek denetim kaydını yanlış yapardı.
        append_entry(
            conn,
            audit_action,
            target_type="file",
            target_id=file_id,
            detail=f"verdict={result.verdict} mock={result.mock} engine={result.engine}",
        )
    finally:
        conn.close()


# Genel arayüz ----------------------------------------------------------------

def scan_file(path: "Path | str", file_id: int | None = None) -> ScanResult:
    """Platformun antivirüs motoruyla dosya tarar.

    Motor bulunamazsa veya tarama başarısız olursa mock ScanResult döner
    (`verdict="unknown"` — "temiz" DEĞİL).
    file_id verilirse sonuç quarantine tablosuna kaydedilir.
    """
    # resolve(): tarayıcıya MUTLAK yol verilir. Göreli bir yol `-` ile
    # başlasaydı clamscan onu seçenek sanabilirdi; mutlak yol her zaman
    # ayırıcıyla başladığı için o kapı kapanıyor.
    path = Path(path).resolve()
    sha  = sha256_of(path)
    _log.info("scan_start  file=%s  size=%d  sha256=%.16s",
              path.name, path.stat().st_size, sha)

    backend = select_backend()
    result  = backend.scan(path, sha) or mock_result(sha, engine=backend.ad)

    _log.info("scan_result  file=%s  engine=%s  verdict=%s  mal=%d  mock=%s",
              path.name, result.engine, result.verdict, result.malicious, result.mock)

    if file_id is not None:
        try:
            _save_to_db(file_id, result, backend.audit_action)
        except Exception:
            _log.exception("scan_db_error  file_id=%d", file_id)

    return result


def scan_by_hash(sha256: str, file_id: int | None = None) -> ScanResult:
    """Hash ile tarama — motorlar dosya içeriğine ihtiyaç duyar, mock döner.

    Karantina gibi orijinal dosyanın erişilebilir olmadığı durumlar için
    arayüz bütünlüğü amacıyla tutulmuştur.
    """
    backend = select_backend()
    _log.info("scan_by_hash  sha256=%.16s — dosya yok, mock döndürülüyor", sha256)
    result = mock_result(sha256, engine=backend.ad)
    if file_id is not None:
        try:
            _save_to_db(file_id, result, backend.audit_action)
        except Exception:
            pass
    return result


# Tanılama --------------------------------------------------------------------

def _rapor(backend: ScannerBackend) -> list[str]:
    satirlar = [
        f"Platform      : {sys.platform}",
        f"Seçilen motor : {backend.ad}",
        f"Kullanılabilir: {'evet' if backend.available() else 'HAYIR — mock döner'}",
        f"Denetim eylemi: {backend.audit_action}",
    ]
    araclar = getattr(backend, "tools", None)
    if callable(araclar):
        bulunan = araclar()
        satirlar.append("ClamAV araçları: " + (", ".join(bulunan) if bulunan else "yok"))
    return satirlar


def main(argv: list[str] | None = None) -> int:
    """`python -m CORE.scanner [dosya]` — hangi motorun seçildiğini gösterir.

    Linux'ta "neden hiçbir şey taranmıyor" sorusunu kurulum yapmadan
    cevaplayabilmek için: motor bulundu mu, hangi araç, hangi yol.
    """
    # Çıktı Türkçe: cp1254/cp1252 konsolunda düzeltilmezse ya bozuk yazılır
    # ya da UnicodeEncodeError ile çöker. Bkz. CORE/console.py, B-013.
    ensure_utf8_console()

    args = list(sys.argv if argv is None else argv)[1:]
    backend = select_backend()
    for satir in _rapor(backend):
        print(satir)

    if not args:
        return 0

    hedef = Path(args[0])
    if not hedef.is_file():
        print(f"\nDosya bulunamadı: {hedef}")
        return 1

    sonuc = scan_file(hedef)
    print(f"\nDosya   : {hedef}")
    print(f"SHA-256 : {sonuc.sha256}")
    print(f"Karar   : {sonuc.verdict}  (mock={sonuc.mock}, motor={sonuc.engine})")
    if sonuc.threat:
        print(f"İmza    : {sonuc.threat}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
