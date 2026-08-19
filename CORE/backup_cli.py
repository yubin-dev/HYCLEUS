"""
HYCLEUS — Yedek dogrulama ve geri yukleme araci (komut satiri)

Kullanim:
    python CORE/backup_cli.py --verify  <yedek_dizini>
    python CORE/backup_cli.py --restore <yedek_dizini> --dest <bos_dizin>
    python CORE/backup_cli.py --info    <yedek_dizini>

Cikis kodlari:
    0  islem basarili / yedek saglam
    1  yedek kusurlu, geri yukleme yapilmadi, ya da okuma hatasi
    2  kullanim hatasi (argparse)


NEDEN GERI YUKLEME CLI, YEDEKLEME UI
------------------------------------
2.1'deki (Shamir kurtarma) karar ayni gerekceyle verilmisti ve burada
ikiye AYRILIYOR, cunku iki islemin calistigi durumlar farkli:

  · YEDEKLEME rutin bir istir ve calisan bir oturum gerektirir zaten
    (metadata'yi sifrelemek icin oturum anahtari lazim). Grafik arayuz
    o sirada aciktir. Bulunamayan bir yedekleme ozelligi, olmayan bir
    yedekleme ozelligidir - bu yuzden UI'da, menude.

  · GERI YUKLEME bir felaket islemidir ve tipik senaryosu "disk gitti,
    yeni makine". O makinede grafik arayuz ACILMAZ: main.py takili ve
    KAYITLI bir USB ile data/vaults/<hwid>.hclv istiyor, ikisi de yok.
    Geri yuklemeyi UI'a koymak, tam ihtiyac duyuldugu anda ulasilamaz
    yapardi - recover_vault.py'nin var olma sebebinin aynisi.

DOGRULAMA ikisinde de var - arayuzde "Yedek Dogrula..." menu maddesi
(UI/BackupVerifyDialog.py) ayni `verify_backup()` fonksiyonunu cagiriyor.
Ikinci bir uygulama DEGIL.

Buradaki hali KALKMIYOR ve kalkmamali: cikis kodu var, yani bir betik ya
da zamanlanmis bir is sonucu okuyabilir; bir diyalog kutusu okuyamaz.
Ayrica anahtarsiz calisabildigi icin (bkz. CORE/backup.py,
verify_backup) bir yedegin saglamligini kontrol etmek kasayi acmayi
gerektirmiyor.

Iki yuzey arasindaki tek fark VARSAYILAN DERINLIK. Burada derin mod
opsiyonel (`--deep`), cunku anahtar USB + PIN istiyor ve bunu her
kontrolde istemek araci kullanilmaz yapardi. Arayuzde anahtar zaten
oturumda, yani derin mod bedava - orada varsayilan.

ANAHTAR NEREDEN GELIYOR
-----------------------
Derin dogrulama ve geri yukleme oturum anahtarini istiyor. Arac onu
vault'tan aciyor: USB HWID + PIN. Yani bu arac calisan bir anahtar
gerektiriyor - anahtar da kaybolduysa once recover_vault.py, sonra bu.
Gerekce CORE/backup.py "KARAR 3" bolumunde.
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from CORE.backup import (  # noqa: E402
    BackupError,
    read_manifest,
    restore_backup,
    verify_backup,
)
from CORE.console import ensure_utf8_console  # noqa: E402

_SEP = "=" * 68


def _abort(msg: str) -> int:
    print(f"\nHata: {msg}", file=sys.stderr)
    return 1


def _load_key() -> tuple[bytes, str | None]:
    """
    Oturum anahtarini vault'tan acar (USB HWID + PIN).

    Ice aktarmalar fonksiyon icinde: --info ve anahtarsiz --verify
    yollarinin USB ve keyring'e hic dokunmamasi icin.
    """
    from CORE.usb_manager import get_usb_hwid
    from CORE.vault_manager import open_vault
    from DB.db_manager import DBManager

    hwid = get_usb_hwid()
    if hwid is None:
        raise BackupError(
            "Yetkili USB cihazi bulunamadi.\n"
            "       Derin dogrulama ve geri yukleme oturum anahtarini ister."
        )
    # open_vault() usb_tokens tablosunu okuyor; baglanti kurulmus olmali.
    try:
        DBManager().connect(hwid=hwid, key=None)
    except Exception as exc:
        raise BackupError(f"Veritabani acilamadi: {exc}") from exc

    pin = getpass.getpass("PIN: ")
    try:
        _role, key = open_vault(hwid, pin)
    except Exception as exc:
        raise BackupError(f"Vault acilamadi: {exc}") from exc
    return key, hwid


def _cmd_info(backup_dir: Path) -> int:
    try:
        manifest = read_manifest(backup_dir)
    except BackupError as exc:
        return _abort(str(exc))

    mb = manifest.get("total_bytes", 0) / 1024 / 1024
    print(_SEP)
    print(f"  {backup_dir}")
    print(_SEP)
    print(f"\n  Bicim      : {manifest.get('format')}")
    print(f"  Olusturuldu: {manifest.get('created_at')}")
    print(f"  HWID       : {manifest.get('hwid')}")
    print(f"  Dosya      : {manifest.get('file_count')} adet, {mb:.1f} MB")
    print("\n  Dogrulamak icin:")
    print(f"    python CORE/backup_cli.py --verify {backup_dir}\n")
    return 0


def _cmd_verify(backup_dir: Path, *, deep: bool) -> int:
    key = hwid = None
    if deep:
        try:
            key, hwid = _load_key()
        except BackupError as exc:
            return _abort(str(exc))

    rapor = verify_backup(backup_dir, key=key, hwid=hwid)

    print(_SEP)
    print(f"  {backup_dir}")
    print(_SEP)
    print(f"\n  {rapor.summary()}\n")

    for baslik, liste in (
        ("EKSIK", rapor.missing),
        ("BOZUK", rapor.corrupt),
        ("DOGRULANAMADI", rapor.auth_failed),
    ):
        if liste:
            print(f"  {baslik} ({len(liste)}):")
            for ad in liste[:20]:
                print(f"    - {ad}")
            if len(liste) > 20:
                print(f"    ... ve {len(liste) - 20} tane daha")
            print()

    if rapor.manifest_mismatch:
        print("  UYARI: duz metin manifesto, sifreli kopyayla UYUSMUYOR.")
        print("         Manifesto degistirilmis olabilir.\n")
    if rapor.extra:
        print(f"  Bilgi: manifestoda olmayan {len(rapor.extra)} fazladan dosya var.\n")
    if not deep and rapor.ok:
        print("  Not: bu yalnizca ozet kontrolu. GCM dogrulamasi icin --deep ekleyin.\n")

    return 0 if rapor.ok else 1


def _cmd_restore(backup_dir: Path, dest: Path, *, overwrite: bool) -> int:
    try:
        key, hwid = _load_key()
    except BackupError as exc:
        return _abort(str(exc))

    print("\nYedek dogrulaniyor (geri yukleme oncesi)...")
    try:
        rapor = restore_backup(
            backup_dir, dest, key, hwid=hwid, overwrite=overwrite,
            on_progress=lambda i, n, ad: print(f"  [{i}/{n}] {ad}"),
        )
    except BackupError as exc:
        return _abort(str(exc))

    print(f"\n  {rapor.summary()}\n")
    print("  Geri yukleme AYRI bir konuma yapildi; canli kasaya ve")
    print("  veritabanina DOKUNULMADI. Icerigi inceleyip yerine kendiniz")
    print("  tasiyin.\n")
    if rapor.reference_written:
        print("  Yalnizca okuma icin cikarilanlar (canli veritabanina")
        print(f"  yazilmaz): {', '.join(rapor.reference_written)}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    ensure_utf8_console()

    p = argparse.ArgumentParser(
        prog="backup_cli.py",
        description=(
            "HYCLEUS yedek dogrulama ve geri yukleme. Yedek ALMAK icin "
            "uygulama menusunu kullanin."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--verify", metavar="DIZIN", help="Yedegi dogrula (geri yuklemeden)")
    g.add_argument("--restore", metavar="DIZIN", help="Yedegi geri yukle")
    g.add_argument("--info", metavar="DIZIN", help="Manifestoyu ozetle")
    p.add_argument("--dest", metavar="DIZIN", help="--restore hedefi (bos olmali)")
    p.add_argument("--deep", action="store_true",
                   help="--verify: GCM dogrulamasi da yap (PIN ister)")
    p.add_argument("--overwrite", action="store_true",
                   help="--restore: dolu bir hedefe yazmaya izin ver")
    args = p.parse_args(argv)

    if args.info:
        return _cmd_info(Path(args.info))
    if args.verify:
        return _cmd_verify(Path(args.verify), deep=args.deep)

    if not args.dest:
        return _abort("--restore icin --dest zorunlu (bos bir dizin secin).")
    return _cmd_restore(Path(args.restore), Path(args.dest), overwrite=args.overwrite)


if __name__ == "__main__":
    raise SystemExit(main())
