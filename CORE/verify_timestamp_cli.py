"""
HYCLEUS — Zaman damgasi dogrulama araci (komut satiri)

Kullanim:
    python CORE/verify_timestamp_cli.py --verify-timestamp <dosya.hcl> --key-file <anahtar.bin>
    python CORE/verify_timestamp_cli.py --verify-timestamp <dosya> --key-file <anahtar.bin> --trusted-root ca.der
    python CORE/verify_timestamp_cli.py --verify-timestamp <dosya> --key-file <anahtar.bin> --show-chain

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
     sinaniyor. Grafik arayuz KAYITLI bir USB istiyor; bu arac ise ag
     ISTEMIYOR - tamamen cevrimdisi ve dosyanin kendisiyle yapiliyor.
     Bunu UI'a hapsetmek, tam ihtiyac duyuldugu anda ulasilamaz yapardi.
  2. Cikis kodu var. Bir betik ya da denetim otomasyonu sonucu okuyabilir;
     bir diyalog kutusu okuyamaz.
  3. Cikti metin. Bir denetim dosyasina yapistirilabilir.

ANAHTAR ARTIK ZORUNLU (B-092/B-099)
------------------------------------
Bu arac eskiden "ne anahtar ne USB istemiyor" diye tanitiliyordu - bu
ARTIK DOGRU DEGIL, bilerek terk edildi. Gerekce CORE/timestamp_verify.py
modul docstring'inde ayrintili: anahtarsiz dogrulama, yalniz bir `.hcl`
KOPYASINA erisen (DB'ye/kimlige erisimi OLMAYAN) biri icin, kasayi hic
acmadan bir aday belgeyi kesin dogrulukla eslestirebilecegi bir
DOGRULAMA-ORACLE'I anlamina geliyordu. Kapatmanin bedeli acikca budur:
bu arac artik yalniz kasaya erisimi (anahtar) olan biri tarafindan
calistirilabilir - "USB takmadan, PIN girmeden, dosyayi disari cikarip
herkesin dogrulayabilecegi bir kanit" ozelligi KALICI olarak gitti.
`--key-file`, HYCLEUS'un `open_vault()`dan aldigi HAM 32 baytlik AES
anahtarini (hex DEGIL) okuyan bir dosya yoluna isaret etmeli.

GERIYE DONUK ONARILMIYOR: bu karardan ONCE sifrelenmis `.hcl` dosyalari
da anahtar gerektiriyor artik - yeniden sifrelenmedikce (ayri bir
migrasyon isi, BACKLOG.md B-100) anahtarsiz dogrulama YETENEGI hicbir
mevcut dosya icin geri gelmiyor.

Arayuz dugmesi (adim 3.1, "Damgayi Dogrula") bunun YERINE gecmiyor,
ustune geliyor. Ayni `verify_timestamp()` fonksiyonunu cagiriyor; fark
yalnizca sonucun anlatilisinda. Buradaki cikti teknik kalmali - kitlesi
denetci ve hukukcu. Sade Turkce karsiligi CORE/timestamp_report.py'de ve
oradaki tablo, bu modulun urettigi HER `failed_check` degerini karsilamak
zorunda (tests/test_timestamp_report.py denetliyor).

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

from CORE.console import ensure_utf8_console  # noqa: E402
from CORE.timestamp_verify import (  # noqa: E402
    TimestampVerification,
    verify_timestamp,
)

_SEP = "=" * 68


def _load_roots(paths: list[str]) -> list[bytes]:
    """
    Guvenilen kok sertifikalari diskten okur (DER ya da PEM).

    AYRISTIRMA burada DEGIL: `CORE/trusted_roots.der_coz()` yapiyor.
    Iki kopya olsaydi (biri burada, biri AdminPanel'in kok deposunda)
    zamanla ayrisirlardi ve ayni sertifika bir yerde kabul edilip
    otekinde reddedilirdi. Bu depoda o kusur bes kez uretildi.

    Bu CLI, AdminPanel'deki KOK DEPOSUNU BILEREK KULLANMIYOR: araci
    calistiran denetci tam olarak bu makineyi denetliyor ve guven
    listesini denetledigi veritabanindan okumak, sorunun cevabini
    sorunun kaynagina sordurmak olurdu. Gerekce
    `CORE/trusted_roots.py` docstring'inde.
    """
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


def _load_key(raw_path: str) -> bytes:
    """
    Ham 32 baytlık AES anahtarını diskten okur (hex/base64 DEĞİL, ham byte).

    HYCLEUS'un `open_vault()`dan aldığı anahtarla AYNI biçim. Bu CLI'ın
    kendisi vault'a erişemez (USB/PIN istemiyor, bilerek) — anahtarı
    NASIL bir dosyaya çıkaracağı çağıranın işi; bu yalnızca okuyor.
    """
    path = Path(raw_path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"Hata: anahtar dosyası okunamadı ({path}): {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    if len(data) != 32:
        print(
            f"Hata: anahtar dosyası 32 bayt olmalı, {len(data)} bayt "
            f"okundu ({path}). Ham AES anahtarı bekleniyor — hex/base64 "
            "kodlu bir metin DEĞİL.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return data


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


def main(argv: list[str] | None = None) -> int:
    # Ilk satir, herhangi bir print()'ten once: zincir agacinin cizgi
    # karakterleri ve Turkce mesajlar yerel kod sayfasinda dusuyor.
    # Gerekce ve kod sayfasi tablosu CORE/console.py'de.
    ensure_utf8_console()
    p = argparse.ArgumentParser(
        prog="verify_timestamp_cli.py",
        description=(
            "HYCLEUS RFC 3161 zaman damgasi dogrulayici. "
            "Ag gerektirmez, tamamen cevrimdisi calisir — ama ARTIK "
            "ANAHTAR ISTIYOR (--key-file): B-092/B-099, anahtarsiz "
            "dogrulama bir icerik-dogrulama-oracle'i olustugu icin "
            "kalici olarak kaldirildi. Bkz. CORE/timestamp_verify.py "
            "modul docstring'i."
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
        "--key-file",
        metavar="ANAHTAR",
        required=True,
        help=(
            "Ham 32 baytlik AES anahtari (hex/base64 DEGIL) taşıyan dosya "
            "— open_vault()'un dondurdugu anahtarla ayni bicim. ARTIK "
            "ZORUNLU: bu arac anahtarsiz calismiyor (B-092/B-099)."
        ),
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

    key = _load_key(args.key_file)
    roots = _load_roots(args.trusted_root) if args.trusted_root else None
    result = verify_timestamp(path, key, trusted_roots=roots)

    if args.quiet:
        print(f"{path.name}: {result.summary()}")
    else:
        _report(path, result, show_chain=args.show_chain)

    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
