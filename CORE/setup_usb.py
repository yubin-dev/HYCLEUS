"""
HYCLEUS — USB vault kurulum araci (komut satiri)

Kullanim:
    python CORE/setup_usb.py --role yonetici
    python CORE/setup_usb.py --role standart --reset
    DEV_MODE=true python CORE/setup_usb.py --role kullanici

Yapilan islemler:
    1. USB cihazinin takili olup olmadigini kontrol eder
    2. HWID okur
    3. PIN girisi alir (getpass ile gizli, onaylamali)
    4. create_vault(hwid, pin, role) cagirir
    5. DB'ye audit kaydi duser
    6. Basari mesaji gosterir

--reset kullanilirsa:
    - Mevcut vault dosyasi silinir (per-HWID ve eski tek-dosya yolu)
    - DB'deki usb_tokens kaydi silinir
    - Ardindan normal kurulum yapilir
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import NoReturn

# Proje kokunu sys.path'e ekle — CORE/ icerisinden calistirildiginda
# 'from DB.db_manager import ...' gibi importlarin calismasi icin gerekli
sys.path.insert(0, str(Path(__file__).parent.parent))

from CORE.pin_policy import PIN_MAX_LEN, validate_new_pin  # noqa: E402
from CORE.usb_manager import get_usb_hwid                    # noqa: E402
from CORE.vault_manager import (  # noqa: E402
    create_vault,
    delete_usb_token,
    read_vault_role,
)
from DB.db_manager import DBManager                           # noqa: E402

# Alt sinir artik validate_new_pin() icinde; ust sinir yalnizca CLI'da uygulaniyor
_PIN_MAX = PIN_MAX_LEN

_DATA_DIR          = Path(__file__).parent.parent / "data"
_VAULT_FILE        = _DATA_DIR / ".hcl_vault"           # eski tek-dosya yolu
_VAULT_DIR         = _DATA_DIR / "vaults"               # per-HWID klasörü


# ── Yardimci fonksiyonlar ─────────────────────────────────────────────────────

def _abort(msg: str) -> NoReturn:
    """Hata mesaji yazip cikis yapar."""
    print(f"\nHata: {msg}", file=sys.stderr)
    sys.exit(1)


def _warn(msg: str) -> None:
    print(f"  ! {msg}", file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="setup_usb.py",
        description="HYCLEUS USB vault ilk kurulumunu gerceklestirir.",
        epilog=(
            "Ornekler:\n"
            "  python CORE/setup_usb.py --role yonetici\n"
            "  python CORE/setup_usb.py --role standart --reset"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--role",
        required=True,
        metavar="ROL",
        help="Vault'a kaydedilecek rol (ornek: yonetici, standart, salt okunur)",
    )
    p.add_argument(
        "--reset",
        action="store_true",
        default=False,
        help=(
            "Mevcut vault ve DB kaydini silerek yeniden kurulum yapar. "
            "Bu HWID icin tum vault + usb_tokens satiri kalici olarak silinir."
        ),
    )
    return p


def _clear_readonly(path: Path) -> None:
    """Windows readonly özniteliğini kaldırır (FILE_ATTRIBUTE_NORMAL = 0x80)."""
    import ctypes
    ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x80)


def _do_reset(hwid: str, db: DBManager) -> None:
    """Vault dosyasini ve DB usb_tokens kaydini siler."""
    deleted: list[str] = []

    # Per-HWID vault
    per_hwid = _VAULT_DIR / f"{hwid}.hclv"
    if per_hwid.exists():
        _clear_readonly(per_hwid)
        per_hwid.unlink()
        deleted.append(str(per_hwid))

    # Eski tek-dosya vault
    if _VAULT_FILE.exists():
        _clear_readonly(_VAULT_FILE)
        _VAULT_FILE.unlink()
        deleted.append(str(_VAULT_FILE))

    # DB kaydi + anahtar kasasindaki share_2 birlikte silinir
    delete_usb_token(hwid)
    db.log("usb_reset", detail=f"hwid={hwid} deleted_files={len(deleted)}")

    if deleted:
        for p in deleted:
            print(f"  Silindi (vault) : {p}")
    else:
        print("  Vault dosyasi zaten mevcut degildi.")
    print(f"  usb_tokens kaydi silindi  hwid={hwid}")


def _prompt_pin() -> str:
    """
    PIN'i getpass ile gizli olarak alir, uzunluk ve esleme dogrulamasi yapar.
    Kullanici dogru giris yapana kadar dongu devam eder.
    """
    while True:
        try:
            pin = getpass.getpass("  PIN girin        : ")
        except (EOFError, KeyboardInterrupt):
            print("\nIptal edildi.")
            sys.exit(0)

        pin_error = validate_new_pin(pin)
        if pin_error:
            _warn(pin_error)
            continue
        if len(pin) > _PIN_MAX:
            _warn(f"PIN en fazla {_PIN_MAX} karakter olabilir.")
            continue

        try:
            confirm = getpass.getpass("  PIN (tekrar)     : ")
        except (EOFError, KeyboardInterrupt):
            print("\nIptal edildi.")
            sys.exit(0)

        if pin != confirm:
            _warn("PIN'ler eslesmiyor, tekrar deneyin.\n")
            continue

        return pin


# ── Ana fonksiyon ─────────────────────────────────────────────────────────────

def main() -> None:
    args = _build_parser().parse_args()
    role: str  = args.role.strip()
    do_reset   = args.reset

    if not role:
        _abort("--role bos olamaz.")

    # ── 1. USB kontrolu ───────────────────────────────────────────────────────
    print("USB cihazi araniyor...")
    hwid = get_usb_hwid()

    if hwid is None:
        _abort(
            "Takili USB cihazi bulunamadi.\n"
            "       Lutfen yetkili USB cihazini takin ve tekrar calistirin."
        )

    print(f"  USB bulundu  : {hwid}")
    print(f"  Rol          : {role}")
    if do_reset:
        print("  Mod          : RESET")

    # ── 2. DB baglantisi ──────────────────────────────────────────────────────
    db = DBManager()
    db.connect(hwid=hwid)

    # ── 3. Reset akisi ────────────────────────────────────────────────────────
    if do_reset:
        # Sahiplik kaniti: mevcut PIN dogrulanmadan reset reddedilir
        print("\nMevcut PIN dogrulamasi (sahiplik kaniti):")
        try:
            current_pin = getpass.getpass("  Mevcut PIN : ")
        except (EOFError, KeyboardInterrupt):
            print("\nIptal edildi.")
            sys.exit(0)
        try:
            read_vault_role(hwid, current_pin)
        except Exception:
            _abort("PIN hatali — reset reddedildi.")

        print()
        print("=" * 68)
        print("DIKKAT — RESET YENI BIR MASTER KEY URETIR")
        print("=" * 68)
        print(
            "Bu islem yalnizca vault dosyasini degil, SIFRELEME ANAHTARINI da\n"
            "yeniler. Sonuclari:\n"
            "\n"
            "  · Mevcut .hcl dosyalariniz ESKI anahtarla sifrelenmistir ve bir\n"
            "    daha ACILAMAZ. Bu geri alinamaz bir veri kaybidir.\n"
            "  · Elinizdeki BASILI KURTARMA PARCASI gecersizlesir; reset sonrasi\n"
            "    yenisini almalisiniz:\n"
            "        python CORE/recover_vault.py --export\n"
            "\n"
            "Amaciniz KURTARMA ise (USB kaybi, kasa silinmesi) BU KOMUTU\n"
            "KULLANMAYIN. Bunun yerine:\n"
            "        python CORE/recover_vault.py --recover\n"
            "Bu komut master_key'i ve polinomu koruyarak vault'u yeniden kurar;\n"
            "dosyalariniz ve basili parcaniz gecerli kalir."
        )
        print("=" * 68)
        try:
            answer = input('  Veri kaybini kabul ediyorsaniz "SIFIRLA" yazin: ').strip()
        except (EOFError, KeyboardInterrupt):
            print("\nIptal edildi.")
            sys.exit(0)
        if answer != "SIFIRLA":
            print("Iptal edildi.")
            sys.exit(0)

        print("\nSifirlanıyor...")
        _do_reset(hwid, db)
        print("  Sifirlama tamamlandi.\n")
    else:
        # ── Normal kurulumda cakisma kontrolu ─────────────────────────────
        per_hwid = _VAULT_DIR / f"{hwid}.hclv"
        vault_exists = per_hwid.exists() or _VAULT_FILE.exists()
        if vault_exists:
            print()
            print("Uyari: Mevcut bir vault dosyasi bulundu.")
            try:
                answer = input("  Uzerine yazilsin mi? [e/H] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\nIptal edildi.")
                sys.exit(0)
            if answer != "e":
                print("Iptal edildi.")
                sys.exit(0)

    # ── 4. PIN girisi ─────────────────────────────────────────────────────────
    print("PIN belirleyin (girdi gizlidir, ekranda gorunmez):")
    pin = _prompt_pin()

    # ── 5. Vault olustur ──────────────────────────────────────────────────────
    print("\nVault olusturuluyor (Argon2id anahtar turetme -- birkas saniye)...")
    vault_path = create_vault(hwid, pin, role)

    # ── 6. Audit log ──────────────────────────────────────────────────────────
    action = "usb_reset_complete" if do_reset else "usb_setup_complete"
    db.log(action, detail=f"hwid={hwid} role={role}")

    # ── 7. Basari mesaji ──────────────────────────────────────────────────────
    sep = "-" * 52
    print()
    print(sep)
    print("  USB vault kurulumu tamamlandi.")
    print(sep)
    print(f"  Vault  : {vault_path}")
    print(f"  HWID   : {hwid}")
    print(f"  Rol    : {role}")
    print(sep)

    db.close()


if __name__ == "__main__":
    main()
