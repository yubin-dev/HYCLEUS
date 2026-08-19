# -*- mode: python ; coding: utf-8 -*-
#
# HYCLEUS — Linux (AppImage) PyInstaller yapılandırması.
# Windows karşılığı: HYCLEUS.spec. Farklar ve gerekçeleri aşağıda.
#
# Çalıştırma:  pyinstaller --noconfirm HYCLEUS-linux.spec
# Tam akış:    packaging/linux/build-appimage.sh
#
# ── 1) pywin32/wmi YOK ────────────────────────────────────────────────────────
# Windows spec'i `collect_all('wmi')` yapıyor ve hiddenimports'a
# pythoncom/win32api/win32con ekliyor. Bu paketler Linux'ta KURULAMAZ —
# requirements.txt'te `wmi; sys_platform == "win32"` işaretçisi var.
# `excludes` ile açıkça eleniyorlar; duman testi çıktıda kalıntı olmadığını
# ayrıca denetliyor.
#
# ── 2) datas yerine hiddenimports ─────────────────────────────────────────────
# Windows spec'i CORE/DB/UI'yı VERİ olarak kopyalıyor. Bu, dosyaları pakete
# koyar ama PyInstaller'ın onları ANALİZ ETMESİNİ sağlamaz — ve fark
# ölçüldü: o yolla üretilen yapıda `main.py`'nin import etmediği her modül
# kendi bağımlılıkları olmadan gidiyordu.
#
#     CORE.backup_cli / recover_vault / setup_usb → getpass yok
#     CORE.timestamp  / timestamp_verify          → asn1crypto yok
#     CORE.inventory                              → reportlab yok
#     CORE.recovery_share                         → qrcode.image.svg yok
#
# Hatanın biçimi en kötüsü: uygulama açılıyor, hatta çalışıyor. Eksiklik
# ancak kullanıcı zaman damgası doğrulamaya, KVKK envanter PDF'i almaya ya
# da kurtarma karekodunu görmeye çalıştığında ortaya çıkıyor.
#
# Modüller `hiddenimports`'a girince PyInstaller bağımlılık grafiğini
# yürüyor ve getpass/asn1crypto/reportlab kendiliğinden geliyor. Liste
# dizinden ÜRETİLİYOR — elle tutulsaydı ilk yeni modülde sessizce eskirdi.
#
# Kaynak kopyaları artık gerekmiyor ve konmuyor: modüller PYZ arşivinde
# donmuş hâlde. Veri olarak da eklemek hem ~1 MB okunabilir kaynağı
# dağıtıma sokar hem de iki farklı kopyanın hangisinin yüklendiği
# sorusunu doğurur.
#
# ── 3) onedir, onefile DEĞİL ──────────────────────────────────────────────────
# Windows tarafı tek dosya EXE üretiyor. AppImage'ın kendisi zaten tek dosya
# dağıtımı; içine onefile koymak her açılışta İKİ KEZ açma demek (önce
# squashfs bağlanır, sonra PyInstaller kendini /tmp'ye çıkarır).
#
# ── 4) upx=False ──────────────────────────────────────────────────────────────
# Windows tarafında True. Burada kapalı: UPX koşucularda kurulu değil
# (PyInstaller sessizce atlıyor, yani True yazmak yanıltıcı olurdu) ve
# sıkıştırılmış ELF'ler AppImage runtime'ıyla zaman zaman sorun çıkarıyor.
# AppImage payload'ı zaten squashfs ile sıkıştırıyor.

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
    binaries=rl_binaries,
    datas=rl_datas,
    hiddenimports=_uygulama_modulleri() + rl_hiddenimports + qr_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['wmi', 'pythoncom', 'win32api', 'win32con', 'win32comext'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='HYCLEUS',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='HYCLEUS',
)
