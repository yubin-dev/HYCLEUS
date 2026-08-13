"""
HYCLEUS — Zaman damgasi dogrulama araci (komut satiri)

Kullanim:
    python CORE/verify_timestamp_cli.py --verify-timestamp <dosya.hcl>
    python CORE/verify_timestamp_cli.py --verify-timestamp <dosya> --trusted-root ca.der
    python CORE/verify_timestamp_cli.py --verify-timestamp <dosya> --show-chain

Cikis kodlari:
    0  damga gecerli
    1  damga gecersiz, damgasiz ya da dosya okunamadi
    2  kullanim hatasi (argparse)

NEDEN CLI
---------
Uc gerekce, ucu de recover_vault.py'dekiyle ayni aileden:

  1. Dogrulama, uygulamanin CALISMADIGI durumlarda gerekir. Bir zaman
     damgasinin isi "bu icerik su tarihte vardi" demek ve bu iddia cogu
     zaman HYCLEUS'un disinda, bir denetci ya da hukukcu karsisinda
     sinaniyor. Grafik arayuz takili ve KAYITLI bir USB istiyor; damga
     dogrulamasi ise ne anahtar ne USB istiyor - tamamen cevrimdisi ve
     dosyanin kendisiyle yapiliyor. Bunu UI'a hapsetmek, tam ihtiyac
     duyuldugu anda ulasilamaz yapardi.
  2. Cikis kodu var. Bir betik ya da denetim otomasyonu sonucu okuyabilir;
     bir diyalog kutusu okuyamaz.
  3. Cikti metin. Bir denetim dosyasina yapistirilabilir.

Arayuz dugmesi bunun yerine gecmiyor, ustune geliyor - ve o sonraki adim.

GUVEN SINIRI
------------
`--trusted-root` VERILMEZSE zincirin kokunun guvenilir oldugu
DOGRULANMAZ; kok, dogrulanan dosyanin icinden gelir. Cikti bunu her
seferinde acikca yaziyor. Ayrintili gerekce CORE/timestamp_verify.py
modul docstring'inde.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from CORE.timestamp_verify import (  # noqa: E402
    TimestampVerification,
    verify_timestamp,
)

_SEP = "=" * 68


def _load_roots(paths: list[str]) -> list[bytes]:
    """
    Guvenilen kok sertifikalari diskten okur (DER ya da PEM).

    PEM destegi var cunku sertifikalar pratikte oyle dagitiliyor; disariya
    "once DER'e cevir" demek, araci kullanilmaz yapardi.
    """
    roots: list[bytes] = []
    for raw_path in paths:
        path = Path(raw_path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            print(f"Hata: guvenilen kok okunamadi ({path}): {exc}", file=sys.stderr)
            raise SystemExit(1) from exc

        if b"-----BEGIN CERTIFICATE-----" in data:
            from cryptography import x509

            try:
                cert = x509.load_pem_x509_certificate(data)
            except ValueError as exc:
                print(f"Hata: PEM ayristirilamadi ({path}): {exc}", file=sys.stderr)
                raise SystemExit(1) from exc
            from cryptography.hazmat.primitives.serialization import Encoding

            roots.append(cert.public_bytes(Encoding.DER))
        else:
            roots.append(data)
    return roots


def _report(path: Path, result: TimestampVerification, *, show_chain: bool) -> None:
    print(_SEP)
    print(f"  {path.name}")
    print(_SEP)

    if not result.valid:
        print("\n  SONUC: GECERSIZ\n")
        print(f"  Neden : {result.reason}")
        if result.failed_check:
            print(f"  Adim  : {result.failed_check}")
        if result.checks:
            print(f"  Gecen : {', '.join(result.checks)}")
        print()
        return

    print("\n  SONUC: GECERLI\n")
    print(f"  Damga zamani : {result.gen_time.isoformat() if result.gen_time else '?'}")
    print(f"  TSA          : {result.tsa_name}")
    if result.tsa_url:
        print(f"  Adres        : {result.tsa_url}")
    print(f"  Seri no      : {result.serial_number}")
    print(f"  Politika     : {result.policy}")
    print(f"  Damgali ozet : {result.hashed_hex}")

    if show_chain:
        print("\n  Sertifika zinciri:")
        for i, subject in enumerate(result.chain_subjects):
            print(f"    {'  ' * i}{'└─ ' if i else ''}{subject}")

    print()
    if result.anchor_trusted:
        print(f"  Kok GUVENILIR: {result.anchor_subject}")
    else:
        # Bu uyari, --trusted-root verilmediginde HER ZAMAN goruunur.
        # Aracin "GECERLI" demesinin ne anlama GELMEDIGINI soylemek,
        # ne anlama geldigini soylemek kadar onemli.
        print(f"  UYARI: zincirin koku ({result.anchor_subject}) DOGRULANMADI.")
        print("         Kok sertifika, dogrulanan dosyanin icinden geldi.")
        print("         Gercek bir guven karari icin kokun dosyadan bagimsiz")
        print("         bir kaynakla karsilastirilmasi gerekir:")
        print("           --trusted-root <ca.der|ca.pem>")
    print()


def _force_utf8() -> None:
    """
    Cikti akislarini UTF-8'e sabitler.

    Windows konsolunda Python yerel kod sayfasini (cp1252/cp1254) seciyor;
    zincir agacindaki cizgi karakterleri ve dogrulama mesajlarindaki Turkce
    harfler UnicodeEncodeError ile dusuyor. Arac dogru sonucu hesaplayip
    onu YAZDIRIRKEN cokuyordu.

    errors="replace": kodlamayi gercekten yapamayan bir konsolda '?' yazmak,
    denetim aracini tamamen kirmaktan iyidir.
    """
    for akis in (sys.stdout, sys.stderr):
        if hasattr(akis, "reconfigure"):
            akis.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    p = argparse.ArgumentParser(
        prog="verify_timestamp_cli.py",
        description=(
            "HYCLEUS RFC 3161 zaman damgasi dogrulayici. "
            "Tamamen cevrimdisi calisir: ag, anahtar ve USB gerektirmez."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--verify-timestamp",
        metavar="DOSYA",
        required=True,
        help="Dogrulanacak .hcl dosyasi",
    )
    p.add_argument(
        "--trusted-root",
        metavar="SERTIFIKA",
        action="append",
        default=[],
        help=(
            "Guvenilen kok sertifika (DER ya da PEM). Birden fazla kez "
            "verilebilir. Verilmezse kokun guvenilirligi DOGRULANMAZ."
        ),
    )
    p.add_argument(
        "--show-chain",
        action="store_true",
        help="Sertifika zincirini yazdir",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Yalnizca tek satirlik ozet yazdir",
    )
    args = p.parse_args(argv)

    path = Path(args.verify_timestamp)
    if not path.is_file():
        print(f"Hata: dosya bulunamadi: {path}", file=sys.stderr)
        return 1

    roots = _load_roots(args.trusted_root) if args.trusted_root else None
    result = verify_timestamp(path, trusted_roots=roots)

    if args.quiet:
        print(f"{path.name}: {result.summary()}")
    else:
        _report(path, result, show_chain=args.show_chain)

    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
