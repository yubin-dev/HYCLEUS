@echo off
rem HYCLEUS-STUB-MUTASYON-TESTI: bu bir gercek EXE DEGIL. B-154 duzeltmesi
rem OLMASAYDI paketlenmis bir yapinin nasil davranacagini taklit eder --
rem HYCLEUS_TEST_DATA_DIR'i SESSIZCE kabul eder, dizini olusturur, cikis
rem kodu 0 doner, stderr'e HICBIR sey yazmaz. smoke-test.ps1'in [6]
rem adiminin bunu YAKALADIGINI kanitlamak icindir. Yalnizca gecici bir
rem mutasyon kanit araci; smoke-test.ps1 -ExePath ile bu dosyaya
rem yonlendirilerek calistirilir, PyInstaller derlemesi ICERMEZ.
setlocal
if "%~1"=="--version" (
  echo HYCLEUS-STUB-MUTASYON 0.0.0
  exit /b 0
)
if "%~1"=="--selftest" (
  if defined HYCLEUS_TEST_DATA_DIR (
    mkdir "%HYCLEUS_TEST_DATA_DIR%" >nul 2>nul
  )
  echo SELFTEST OK
  echo Moduller: 50/50
  echo Platform moduller: win32 - wmi pythoncom win32api win32con
  echo data dizini: C:\stub\data
  exit /b 0
)
exit /b 0
