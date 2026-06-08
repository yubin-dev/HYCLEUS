"""
HYCLEUS — USB vault kurulum araci (komut satiri)

Kullanim:
    python CORE/setup_usb.py --role yonetici
    DEV_MODE=true python CORE/setup_usb.py --role kullanici

Yapilan islemler:
    1. USB cihazinin takili olup olmadigini kontrol eder
    2. HWID okur
    3. PIN girisi alir (getpass ile gizli, onaylamali)
    4. create_vault(hwid, pin, role) cagirir
    5. DB'ye audit kaydi duser
    6. Basari mesaji gosterir
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

from CORE.usb_manager import get_usb_hwid          # noqa: E402
from CORE.vault_manager import create_vault         # noqa: E402
from DB.db_manager import DBManager                 # noqa: E402

_PIN_MIN = 4
_PIN_MAX = 32

# vault_manager._VAULT_PATH ile ayni hesaplama — import etmeden yol kontrolu
_VAULT_FILE = Path(__file__).parent.parent / "data" / ".hcl_vault"


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
        epilog="Ornek: python CORE/setup_usb.py --role yonetici",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--role",
        required=True,
        metavar="ROL",
        help="Vault'a kaydedilecek rol (ornek: yonetici, kullanici)",
    )
    return p


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

        if len(pin) < _PIN_MIN:
            _warn(f"PIN en az {_PIN_MIN} karakter olmali.")
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
    role: str = args.role.strip()

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

    # ── 2. Vault cakisma kontrolu ─────────────────────────────────────────────
    if _VAULT_FILE.exists():
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

    # ── 3. PIN girisi ─────────────────────────────────────────────────────────
    print("\nPIN belirleyin (girdi gizlidir, ekranda gorunmez):")
    pin = _prompt_pin()

    # ── 4. DB baglantisi ──────────────────────────────────────────────────────
    db = DBManager()
    db.connect(hwid=hwid)

    # ── 5. Vault olustur ──────────────────────────────────────────────────────
    print("\nVault olusturuluyor (Argon2id anahtar turetme -- birkas saniye)...")
    vault_path = create_vault(hwid, pin, role)

    # ── 6. Audit log ──────────────────────────────────────────────────────────
    db.log("usb_setup_complete", detail=f"hwid={hwid} role={role}")

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
