# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files, collect_all

wmi_datas, wmi_binaries, wmi_hiddenimports = collect_all('wmi')

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=wmi_binaries,
    datas=[('data', 'data'), ('CORE', 'CORE'), ('DB', 'DB'), ('UI', 'UI')] + wmi_datas,
    hiddenimports=['wmi', 'pythoncom', 'win32api', 'win32con'] + wmi_hiddenimports,
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
