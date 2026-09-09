"""
HYCLEUS — Kurtarma parcasi araci (komut satiri)

Kullanim:
    python CORE/recover_vault.py --export
    python CORE/recover_vault.py --recover
    python CORE/recover_vault.py --status
    python CORE/recover_vault.py --takeover

  --export    Kurtarma parcasini uretir ve BIR KEZ gosterir (base32 + QR).
              Vault yeniden anahtarlanmaz; mevcut paylar hic degismez.
  --recover   Kurtarma parcasi + kalan bir pay ile master_key'i geri getirir
              (AYNI USB icin — kasa/anahtar kasasi kayboldugunda).
  --status    Bu cihazin kurtarma parcasi alinmis mi, gosterir.
  --takeover  Kayip/bozuk bir USB'nin hesabini, bu makinede takili YENI
              (FARKLI donanim kimligine sahip) bir USB'ye devreder — bkz.
              CORE/usb_takeover.py. --recover'dan FARKLI: --recover ayni
              HWID icin calisir, --takeover GERCEKTEN farkli bir HWID'e
              gecer ve `users` tablosundaki hesabi ona baglar (yeni bir
              kullanici URETMEZ, var olanin hwid'ini gunceller).

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

from CORE.console import ensure_utf8_console  # noqa: E402
from CORE.recovery_share import (  # noqa: E402
    RecoveryShareError,
    build_export,
    decode_share,
)
from CORE.pin_policy import validate_new_pin  # noqa: E402
from CORE.roles import display_role  # noqa: E402
from CORE.usb_manager import get_usb_hwid  # noqa: E402
from CORE.usb_takeover import TakeoverError, takeover_usb  # noqa: E402
from CORE.vault_manager import (  # noqa: E402
    export_recovery_share,
    has_recovery_share,
    recover_master_key,
    reprovision_vault,
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
        import hashlib

        print(f"\n{_SEP}")
        print("MASTER KEY KURTARILDI")
        print(f"  uzunluk      : {len(master_key)} byte")
        print(f"  SHA-256 ozeti: {hashlib.sha256(master_key).hexdigest()}")
        print(_SEP)

        print(
            "\nSIMDI VAULT'U YENIDEN KURABILIRIZ.\n"
            "\n  · master_key KORUNUR   -> mevcut .hcl dosyalariniz acilmaya devam eder\n"
            "  · polinom KORUNUR      -> elinizdeki BASILI KURTARMA PARCASI gecerli kalir\n"
            "  · yeni PIN belirlenir ve share_2 bu cihazin kasasina yazilir\n"
        )
        if input("  Vault yeniden kurulsun mu? [e/H] ").strip().lower() not in ("e", "evet"):
            print(
                "\nAtlandi. UYARI: setup_usb.py --reset KULLANMAYIN -\n"
                "o komut YENI bir master_key uretir ve mevcut .hcl dosyalariniz\n"
                "kalici olarak acilamaz hale gelir."
            )
            return

        # KANONİK biçimde yazılıyor (B-028). Eski hâli ham girdiyi ve
        # ASCII varsayılan "Yonetici"yi doğrudan kasaya koyuyordu; giriş
        # akışı kasadan normalize etmeden okuduğu için kurtarma sonrası
        # yönetici sessizce yönetici olmayan gibi davranılıyordu.
        # `display_role()` tanınan rolü kanonik yazımına çeviriyor,
        # tanınmayanı olduğu gibi bırakıyor.
        ham_rol = input("  Rol (orn. Yonetici): ").strip() or "Yonetici"
        role = display_role(ham_rol)
        yeni_pin = _prompt_pin("  Yeni PIN: ")
        pin_hatasi = validate_new_pin(yeni_pin)
        if pin_hatasi:
            _abort(pin_hatasi)
        if _prompt_pin("  Yeni PIN (tekrar): ") != yeni_pin:
            _abort("PIN'ler eslesmiyor.")

        try:
            path = reprovision_vault(
                hwid, yeni_pin, role,
                master_key=master_key,
                recovery_share=share_3,
            )
        except Exception as exc:
            _abort(f"Yeniden kurulum basarisiz: {exc}")

        print(f"\n{_SEP}")
        print("VAULT YENIDEN KURULDU")
        print(f"  konum : {path}")
        print(f"  HWID  : {hwid}")
        print(_SEP)
        print(
            "\n  · Mevcut .hcl dosyalariniz ayni anahtarla acilir.\n"
            "  · Elinizdeki basili kurtarma parcasi HALA GECERLI - saklamaya devam edin.\n"
            "  · Yeni PIN'inizle normal sekilde giris yapabilirsiniz."
        )
    finally:
        del master_key


def _cmd_takeover(_args: argparse.Namespace) -> None:
    """
    Kayip/bozuk bir USB'nin hesabini bu makinede takili YENI (farkli
    HWID'e sahip) bir USB'ye devreder — bkz. CORE/usb_takeover.py.

    --recover'dan FARKI: --recover AYNI USB (ayni HWID) icin calisir —
    kasa/anahtar kasasi kaybolmus ama fiziksel USB hala elde senaryosu.
    Bu komut GERCEKTEN farkli bir USB'ye (farkli HWID) gecer VE `users`
    tablosundaki hesabi ona baglar — eski satiri COGALTMAZ, VAR OLANI
    gunceller.
    """
    print(f"\n{_SEP}")
    print("USB DEVRALMA — kayip/bozuk bir hesabi YENI bu USB'ye tasir")
    print(_SEP)
    print(
        "\nBu islem GERI ALINAMAZ: eski USB (bulunsa/onarilsa bile) "
        "islemden\nsonra BIR DAHA ACILAMAZ. Devam etmeden once elinizde "
        "GECERLI bir\nkurtarma parcasi (HYCLEUS-R3-...) oldugundan emin "
        "olun.\n"
    )

    yeni_hwid = _require_hwid()
    print(f"Yeni (bu makinedeki) USB: {yeni_hwid}")

    kullanici_adi = input("\nDevralinacak kullanici adi: ").strip()
    db = DBManager()
    satir = db.fetchone(
        "SELECT hwid FROM users WHERE username = ?", (kullanici_adi,)
    )
    if satir is None:
        _abort(f"'{kullanici_adi}' adinda bir kullanici bulunamadi.")
    eski_hwid = satir["hwid"]
    if not eski_hwid:
        _abort(f"'{kullanici_adi}' bir HWID'e bagli degil (DEV_MODE kaydi olabilir).")
    print(f"Eski (kayip) USB: {eski_hwid}")

    print("\nKurtarma parcasini girin (HYCLEUS-R3-... ile baslar).")
    print("Bosluk / satir sonu / kucuk harf farketmez.\n")
    raw = _prompt_pin("  Kurtarma parcasi: ")
    try:
        share_3 = decode_share(raw)
    except RecoveryShareError as exc:
        _abort(str(exc))

    print("\nEski vault DOSYASI hala bu makinede duruyor mu?")
    print("  (USB'nin KENDISI kayip olsa da, vault dosyasi bu makinenin")
    print("  diskindedir — USB'ye degil, buraya bakin.)")
    print("  1) Evet, PIN'imi de biliyorum  (share_1 yoluyla kurtarma)")
    print("  2) Hayir / bilmiyorum          (share_2 - anahtar kasasi - yoluyla)")
    secim = input("  Secim [1/2]: ").strip()
    eski_pin = _prompt_pin("  Eski PIN: ") if secim == "1" else None

    yeni_pin = _prompt_pin("  Yeni PIN: ")
    pin_hatasi = validate_new_pin(yeni_pin)
    if pin_hatasi:
        _abort(pin_hatasi)
    if _prompt_pin("  Yeni PIN (tekrar): ") != yeni_pin:
        _abort("PIN'ler eslesmiyor.")

    print(f"\n{_SEP}")
    print("SON UYARI:")
    print(f"  · '{kullanici_adi}' hesabi ARTIK YALNIZCA bu yeni USB'yle acilabilecek.")
    print(f"  · Eski USB ({eski_hwid}) bulunsa/onarilsa bile BIR DAHA ACILAMAYACAK.")
    print(_SEP)
    if input("\nDevam edilsin mi? [e/H] ").strip().lower() not in ("e", "evet"):
        print("Iptal edildi. Hicbir sey degistirilmedi.")
        return

    try:
        sonuc = takeover_usb(
            db, old_hwid=eski_hwid, new_hwid=yeni_hwid, recovery_share=share_3,
            new_pin=yeni_pin, old_pin=eski_pin,
        )
    except TakeoverError as exc:
        _abort(str(exc))
    except Exception as exc:
        _abort(
            f"Devralma basarisiz: {exc}\n"
            "  Kurtarma parcasi bu hesaba ait olmayabilir, PIN yanlis "
            "olabilir ya da kalan pay okunamiyor. HICBIR sey degismedi."
        )

    print(f"\n{_SEP}")
    print("USB DEVRALINDI")
    print(f"  kullanici : {sonuc.username}")
    print(f"  rol       : {sonuc.role}")
    print(f"  yeni HWID : {yeni_hwid}")
    print(_SEP)
    print(
        "\n  · Artik normal sekilde bu USB + yeni PIN + mevcut authenticator\n"
        "    uygulamanizla (TOTP sirri TASINDI, yeniden kurulum GEREKMEZ)\n"
        "    giris yapabilirsiniz.\n"
        "  · Elinizdeki basili kurtarma parcasi HALA GECERLI — saklamaya devam edin.\n"
        "  · Eski USB artik hicbir sekilde acilamaz."
    )


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
    # Ilk satir, herhangi bir print()'ten once. Bu aracin ciktisi BUGUN
    # cp1252'de kodlanabiliyor (tek ASCII disi karakteri `·`), yani cagri
    # ONLEYICI: kural "ASCII disi cikti ureten her CLI" diyor ve tek bir
    # Turkce harf eklendiginde bu arac da duserdi. Bkz. CORE/console.py.
    ensure_utf8_console()

    p = argparse.ArgumentParser(
        prog="recover_vault.py",
        description="HYCLEUS kurtarma parcasi araci (Shamir 2-of-3, 3. pay).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--export", action="store_true", help="Kurtarma parcasini goster")
    g.add_argument("--recover", action="store_true", help="Kurtarma parcasi ile anahtari geri getir (AYNI USB)")
    g.add_argument("--status", action="store_true", help="Kurtarma parcasi alinmis mi")
    g.add_argument("--takeover", action="store_true", help="Kayip USB'yi YENI bir USB'ye devret (FARKLI HWID)")
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
    elif args.takeover:
        _cmd_takeover(args)
    else:
        _cmd_status(args)


if __name__ == "__main__":
    main()
