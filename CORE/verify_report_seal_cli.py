"""
HYCLEUS — denetim raporu PDF muhru dogrulama araci (K4-20, B-087/B-106)

Kullanim:
    python CORE/verify_report_seal_cli.py --pdf rapor.pdf
    python CORE/verify_report_seal_cli.py --pdf rapor.pdf --token rapor.pdf.tsr
    python CORE/verify_report_seal_cli.py --pdf rapor.pdf --trusted-root ca.der

Cikis kodlari:
    0  muhur gecerli
    1  muhur gecersiz, yok ya da dosya okunamadi
    2  kullanim hatasi (argparse)

NEDEN AYRI BIR ARAC — verify_timestamp_cli.py YETMEZ
------------------------------------------------------
`verify_timestamp_cli.py` bir `.hcl` KASA DOSYASI icin yazildi: dogrulama
`--key-file`'in isaret ettigi vault anahtariyla dosyayi COZUYOR, cunku
damgalanan ozet SIFRELI icerigin ALTINDAKI duz metnin ozeti (bkz. o
modulun docstring'i, B-092/B-099). Denetim raporu PDF'i hic sifrelenmis
DEGIL - disari verilen, ucuncu bir taraf tarafindan (denetci, hukukcu,
HYCLEUS hic kurulu olmayan bir makine) okunmasi beklenen duz bir dosya.
Vault anahtari YOK, DB YOK, HYCLEUS kurulu bile olmasi GEREKMIYOR - bu
aracin butun amaci bu. Ayrıstirma/dogrulama govdesi ORTAK
(`CORE.timestamp_verify.verify_token()`), ikinci bir kripto
implementasyonu YAZILMADI.

VARSAYILAN GUVEN KOKU verify_timestamp_cli.py'DEN FARKLI, BILEREK
--------------------------------------------------------------------
`verify_timestamp_cli.py` --trusted-root VERILMEZSE kok GUVENILMEZ sayar:
o aracin dogruladigi dosya HERHANGI bir TSA ile damgalanmis olabilir,
varsayilan bir kok tanimlamak yanlis bir "guvenilir" iddiasi olurdu.
Bu aracin dogruladigi mühür ISE HER ZAMAN uygulamanin kendi varsayilan
TSA'siyla (freetsa.org) uretiliyor - `CORE.audit_report.export_sealed_pdf()`
`CORE.timestamp.DEFAULT_TSA_URL`'i SABIT kullaniyor, `tsa_url(db)` ayarini
DEGIL (gerekce o fonksiyonun docstring'inde). O yuzden varsayilan guven
koku B-105'in ikili dosyaya gomdugu ayni kok
(`CORE.trusted_roots_builtin.gomulu_kokler()`) - DB YOK, dosya YOK,
sadece ikili dosyanin kendisi. `--trusted-root` yine de veriliyorsa
gomulu kokun YERINE gecer (testlerin gercek olmayan bir TSA'yla uctan uca
calisabilmesi icin).
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from CORE.audit_report import tsr_path_for  # noqa: E402
from CORE.console import ensure_utf8_console  # noqa: E402
from CORE.timestamp_verify import (  # noqa: E402
    TimestampVerification,
    verify_token,
)
from CORE.trusted_roots_builtin import gomulu_kokler  # noqa: E402

_SEP = "=" * 68


def _load_roots(paths: list[str]) -> list[bytes]:
    """Guvenilen kok sertifikalari diskten okur — AYRISTIRMA burada
    DEGIL, `CORE/trusted_roots.der_coz()` yapiyor (bkz. `verify_timestamp_
    cli.py::_load_roots`, BIREBIR ayni gerekce/desen)."""
    from CORE.trusted_roots import TrustedRootError, der_coz

    roots: list[bytes] = []
    for raw_path in paths:
        path = Path(raw_path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            print(f"Hata: guvenilen kok okunamadi ({path}): {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        try:
            roots.append(der_coz(data, kaynak=path.name))
        except TrustedRootError as exc:
            print(f"Hata: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
    return roots


def _report(pdf: Path, token_path: Path, result: TimestampVerification) -> None:
    print(_SEP)
    print(f"  {pdf.name}")
    print(f"  muhur: {token_path.name}")
    print(_SEP)

    if not result.valid:
        print("\n  SONUC: GECERSIZ\n")
        print(f"  Neden : {result.reason}")
        if result.failed_check:
            print(f"  Adim  : {result.failed_check}")
        print()
        return

    print("\n  SONUC: GECERLI\n")
    print(f"  Damga zamani : {result.gen_time.isoformat() if result.gen_time else '?'}")
    print(f"  TSA          : {result.tsa_name}")
    print(f"  Seri no      : {result.serial_number}")
    print(f"  PDF SHA-256  : {result.hashed_hex}")
    print()
    if result.anchor_trusted:
        print(f"  Kok GUVENILIR: {result.anchor_subject}")
    else:
        print(f"  UYARI: zincirin koku ({result.anchor_subject}) DOGRULANMADI.")
        print("         --trusted-root ile dosyadan bagimsiz bir kok verin.")
    print()


def main(argv: list[str] | None = None) -> int:
    ensure_utf8_console()
    p = argparse.ArgumentParser(
        prog="verify_report_seal_cli.py",
        description=(
            "HYCLEUS denetim raporu (PDF) RFC 3161 muhur dogrulayicisi. "
            "Vault anahtari/DB gerektirmez — PDF sifreli degil, dogrulama "
            "yalnizca dosyanin kendi SHA-256'siyla yapilir."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--pdf", metavar="DOSYA", required=True,
        help="Dogrulanacak muhurlu PDF raporu",
    )
    p.add_argument(
        "--token", metavar="TSR",
        help="Muhur token dosyasi (varsayilan: <--pdf>.tsr)",
    )
    p.add_argument(
        "--trusted-root", metavar="SERTIFIKA", action="append", default=[],
        help=(
            "Guvenilen kok sertifika (DER ya da PEM). Birden fazla kez "
            "verilebilir. Verilmezse B-105'in ikili dosyaya gomulu "
            "freetsa.org koku kullanilir (bkz. modul docstring'i)."
        ),
    )
    p.add_argument("--quiet", action="store_true", help="Yalnizca tek satirlik ozet yazdir")
    args = p.parse_args(argv)

    pdf = Path(args.pdf)
    if not pdf.is_file():
        print(f"Hata: PDF bulunamadi: {pdf}", file=sys.stderr)
        return 1

    token_path = Path(args.token) if args.token else tsr_path_for(pdf)
    if not token_path.is_file():
        print(f"Hata: muhur dosyasi bulunamadi: {token_path}", file=sys.stderr)
        return 1

    roots = _load_roots(args.trusted_root) if args.trusted_root else gomulu_kokler()

    digest = hashlib.sha256(pdf.read_bytes()).digest()
    token_der = token_path.read_bytes()
    result = verify_token(token_der, expected_digest=digest, trusted_roots=roots)

    if args.quiet:
        print(f"{pdf.name}: {result.summary()}")
    else:
        _report(pdf, token_path, result)

    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
