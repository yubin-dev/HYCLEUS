"""
HYCLEUS — Kurtarma parcasi araci (komut satiri)

Kullanim:
    python CORE/recover_vault.py --export
    python CORE/recover_vault.py --recover
    python CORE/recover_vault.py --status

  --export   Kurtarma parcasini uretir ve BIR KEZ gosterir (base32 + QR).
             Vault yeniden anahtarlanmaz; mevcut paylar hic degismez.
  --recover  Kurtarma parcasi + kalan bir pay ile master_key'i geri getirir.
  --status   Bu cihazin kurtarma parcasi alinmis mi, gosterir.

NEDEN CLI, NEDEN UI DEGIL
-------------------------
Kurtarma tam olarak normal akisin bozuldugu anda gerekir. Grafik arayuz
acilabilmek icin takili ve KAYITLI bir USB istiyor (main.py, HWID yoksa
sys.exit). Yani "USB'yi kaybettim" senaryosunda UI hic acilmiyor - kurtarma
akisini oraya koymak, tam ihtiyac duyuldugu anda ulasilamaz yapardi.

Ayrica CLI, parcayi getpass ile gizli okur; pano ve ekran goruntusu yuzeyi
GUI'ye gore dardir. Depo zaten bu deseni kullaniyor (CORE/setup_usb.py).
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).parent.parent))

from CORE.recovery_share import (  # noqa: E402
    RecoveryShareError,
    build_export,
    decode_share,
)
from CORE.usb_manager import get_usb_hwid  # noqa: E402
from CORE.vault_manager import (  # noqa: E402
    export_recovery_share,
    has_recovery_share,
    recover_master_key,
)
from DB.db_manager import DBManager  # noqa: E402

_SEP = "=" * 68


def _abort(msg: str) -> NoReturn:
    print(f"\nHata: {msg}", file=sys.stderr)
    sys.exit(1)


def _require_hwid() -> str:
    hwid = get_usb_hwid()
    if hwid is None:
        _abort(
            "USB tespit edilemedi.\n"
            "  --recover icin share_2 anahtar kasasindan okunur; kasa kaydi\n"
            "  HWID'e bagli oldugu icin kayitli USB takili olmalidir."
        )
    return hwid


def _prompt_pin(prompt: str = "  PIN: ") -> str:
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\nIptal edildi.")
        sys.exit(0)


def _show_export(share_3: str, qr_path: Path | None) -> None:
    """Kurtarma parcasini bir kez gosterir; hicbir seyi kalici yazmaz."""
    export = build_export(share_3)
    try:
        print(f"\n{_SEP}")
        print(export.warning)
        print(_SEP)
        print("\nKURTARMA PARCASI (base32):\n")
        print(f"  {export.base32_text}\n")

        if qr_path is not None and export.qr_svg is not None:
            # QR yalnizca kullanici ACIKCA bir yol verdiginde yazilir;
            # varsayilan davranis hicbir seyi diske yazmamaktir.
            qr_path.write_text(export.qr_svg, encoding="utf-8")
            print(f"  QR kodu yazildi: {qr_path}")
            print("  Bunu YAZDIRIN ve dosyayi silin - diskte birakmayin.\n")
        elif export.qr_svg is not None:
            print("  (QR kodu icin: --qr-out <dosya.svg>)\n")

        print(_SEP)
        print("Bu parca bir daha gosterilmeyecek. Yazdirdiniz mi / kaydettiniz mi?")
        print(_SEP)
    finally:
        del export  # bellekten birak


def _cmd_export(args: argparse.Namespace) -> None:
    hwid = _require_hwid()
    print(f"\nHWID: {hwid}")
    if has_recovery_share(hwid):
        print("\n  ! Bu cihaz icin daha once kurtarma parcasi alinmis.")
        print("    Yeniden gostermek vault'u degistirmez - ayni parca uretilir.")
        if input("    Devam edilsin mi? [e/H] ").strip().lower() not in ("e", "evet"):
            print("Iptal edildi.")
            return

    pin = _prompt_pin("  Vault PIN'i: ")
    try:
        share_3 = export_recovery_share(hwid, pin)
    except Exception as exc:
        _abort(f"Kurtarma parcasi uretilemedi: {exc}")

    try:
        _show_export(share_3, Path(args.qr_out) if args.qr_out else None)
    finally:
        del share_3


def _cmd_recover(args: argparse.Namespace) -> None:
    hwid = _require_hwid()
    print(f"\nHWID: {hwid}")
    print("\nKurtarma parcasini girin (HYCLEUS-R3-... ile baslar).")
    print("Bosluk / satir sonu / kucuk harf farketmez.\n")

    raw = _prompt_pin("  Kurtarma parcasi: ")
    try:
        share_3 = decode_share(raw)
    except RecoveryShareError as exc:
        _abort(str(exc))

    print("\nKalan pay hangisi?")
    print("  1) Vault dosyam duruyor, PIN'imi biliyorum  (share_2 kayip)")
    print("  2) Vault dosyam yok/bozuk                   (share_1 kayip)")
    secim = input("  Secim [1/2]: ").strip()

    pin = _prompt_pin("  Vault PIN'i: ") if secim == "1" else None

    try:
        master_key = recover_master_key(hwid, recovery_share=share_3, pin=pin)
    except Exception as exc:
        _abort(
            f"Kurtarma basarisiz: {exc}\n"
            "  Kurtarma parcasi bu cihaza ait olmayabilir ya da kalan pay okunamiyor."
        )

    try:
        print(f"\n{_SEP}")
        print("MASTER KEY KURTARILDI")
        print(f"  uzunluk    : {len(master_key)} byte")
        print(f"  SHA-256 ozeti: {__import__('hashlib').sha256(master_key).hexdigest()}")
        print(_SEP)
        print(
            "\nAnahtar yalnizca dogrulama icin gosterildi; hicbir yere yazilmadi.\n"
            "Vault'u yeniden kurmak icin:\n"
            "  python CORE/setup_usb.py --role <rol> --reset\n"
            "komutunu calistirin, ardindan dosyalariniza erisebilirsiniz."
        )
    finally:
        del master_key


def _cmd_status(_args: argparse.Namespace) -> None:
    hwid = _require_hwid()
    var = has_recovery_share(hwid)
    print(f"\nHWID: {hwid}")
    print(f"Kurtarma parcasi: {'ALINMIS' if var else 'ALINMAMIS'}")
    if not var:
        print(
            "\n  ! Bu vault su an 2-of-2 gibi davraniyor: share_1 (vault) veya\n"
            "    share_2 (anahtar kasasi) kaybolursa dosyalariniza BIR DAHA\n"
            "    ERISEMEZSINIZ.\n"
            "\n    Kurtarma parcasini alin:\n"
            "      python CORE/recover_vault.py --export"
        )


def main() -> None:
    p = argparse.ArgumentParser(
        prog="recover_vault.py",
        description="HYCLEUS kurtarma parcasi araci (Shamir 2-of-3, 3. pay).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--export", action="store_true", help="Kurtarma parcasini goster")
    g.add_argument("--recover", action="store_true", help="Kurtarma parcasi ile anahtari geri getir")
    g.add_argument("--status", action="store_true", help="Kurtarma parcasi alinmis mi")
    p.add_argument("--qr-out", metavar="DOSYA", help="QR kodunu bu SVG dosyasina yaz")
    args = p.parse_args()

    hwid = get_usb_hwid()
    try:
        DBManager().connect(hwid=hwid, key=None)
    except Exception as exc:
        _abort(f"Veritabani acilamadi: {exc}")

    if args.export:
        _cmd_export(args)
    elif args.recover:
        _cmd_recover(args)
    else:
        _cmd_status(args)


if __name__ == "__main__":
    main()
