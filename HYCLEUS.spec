# -*- mode: python ; coding: utf-8 -*-
#
# HYCLEUS — Windows (tek dosya EXE) PyInstaller yapılandırması.
# Linux karşılığı: HYCLEUS-linux.spec.
#
# Çalıştırma:  pyinstaller --noconfirm HYCLEUS.spec
# Doğrulama:   dist\HYCLEUS.exe --selftest      → "SELFTEST OK" ve 53/53
#
# ── B-024: iki bozukluk düzeltildi ────────────────────────────────────────────
#
# 1) `datas=[('data', 'data'), …]` KALDIRILDI.
#    `data/` .gitignore'da; temiz bir klonda PyInstaller
#    "Unable to find …\data" ile HİÇ BAŞLAMIYORDU. Satır ayrıca gereksizdi:
#    CORE/paths.py::data_dir() donmuş modda EXE'nin YANINDAKİ data/'yı
#    döndürüyor, pakete kopyalanan hiç okunmuyordu.
#
# 2) CORE/DB/UI artık VERİ olarak değil, hiddenimports olarak veriliyor.
#    Veri kopyası .py dosyalarını pakete koyar ama PyInstaller'ın onları
#    ANALİZ etmesini sağlamaz — dolayısıyla main.py'nin import etmediği her
#    modül kendi bağımlılıkları olmadan gidiyordu. ÖLÇÜLDÜ, 53 modülün
#    10'u yüklenemiyordu:
#
#        getpass            ← backup_cli, recover_vault, setup_usb
#        asn1crypto         ← timestamp, timestamp_verify (RFC 3161)
#        reportlab          ← inventory (KVKK envanter PDF'i)
#        qrcode.image.svg   ← recovery_share (kurtarma karekodu)
#
#    Hatanın biçimi en kötüsü: uygulama açılıyor ve normal görünüyordu.
#    Eksiklik ancak kullanıcı o özelliğe dokunduğunda — kurtarma
#    karekodunda, yani muhtemelen en kötü anda — ortaya çıkıyordu.
#
#    Modül listesi dizinden ÜRETİLİYOR. Elle yazılsaydı ilk yeni modülde
#    sessizce eskirdi ve bu hata aynen geri gelirdi.
#
# Windows'a ÖZGÜ ve korunan: wmi/pywin32 toplama, tek dosya EXE, upx=True.
# Bunların hiçbiri değişmedi.

import os

from PyInstaller.utils.hooks import collect_all, collect_submodules


def _uygulama_modulleri() -> list[str]:
    """CORE/ ve DB/ altındaki her modülün nokta ile yazılmış adı."""
    bulunan = []
    for paket in ("CORE", "DB"):
        for dosya in sorted(os.listdir(paket)):
            if dosya.endswith(".py") and dosya != "__init__.py":
                bulunan.append(f"{paket}.{dosya[:-3]}")
    return bulunan


wmi_datas, wmi_binaries, wmi_hiddenimports = collect_all('wmi')

# reportlab yalnızca CORE/inventory.py içinde, FONKSİYON GÖVDESİNDE import
# ediliyor. `collect_all` gerekli: paket saf Python değil, gömülü Type-1
# yazı tipleri (.pfb/.afm) taşıyor ve onlarsız PDF üretimi çalışma anında
# düşer — modül yüklenmiş görünürken.
rl_datas, rl_binaries, rl_hiddenimports = collect_all('reportlab')

# qrcode'un görüntü arka uçları çalışma anında seçiliyor
# (CORE/recovery_share.py `qrcode.image.svg`'yi fonksiyon içinde alıyor),
# yani statik analiz hiçbirini göremiyor.
qr_hiddenimports = collect_submodules('qrcode')

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=wmi_binaries + rl_binaries,
    datas=wmi_datas + rl_datas,
    hiddenimports=(
        ['wmi', 'pythoncom', 'win32api', 'win32con']
        + wmi_hiddenimports
        + _uygulama_modulleri()
        + rl_hiddenimports
        + qr_hiddenimports
    ),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='HYCLEUS',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
