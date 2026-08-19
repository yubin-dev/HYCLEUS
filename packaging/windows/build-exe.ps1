<#
.SYNOPSIS
    HYCLEUS — Windows tek dosya EXE yapısı.

.DESCRIPTION
    Linux karşılığı: packaging/linux/build-appimage.sh. Orada AppDir kurmak
    gerektiği için betik uzun; burada asıl iş tek satır. Betiğin var olma
    sebebi o satır değil, ETRAFINDAKİ DENETİMLER:

      · yapı öncesi "temiz ağaç" koşulunun gerçekten sağlandığı,
      · yapı sonrası EXE'nin gerçekten üretildiği.

    B-024 tam olarak bu iki denetimin yokluğunda oluştu: spec `data/`
    dizinini istiyordu, o dizin .gitignore'daydı ve yapı yalnızca dizini
    zaten üretmiş makinelerde çalışıyordu. Hata kimsenin makinesinde
    görünmüyordu çünkü herkesin makinesinde `data/` vardı.

.PARAMETER TemizAgac
    `data/` dizini VARSA hata verip durur. CI bu anahtarı geçiyor; yerel
    geliştiricinin gerçek bir data/ dizini olması normal, o yüzden
    varsayılan kapalı.

.EXAMPLE
    .\packaging\windows\build-exe.ps1
    .\packaging\windows\build-exe.ps1 -TemizAgac
#>
[CmdletBinding()]
param(
    [switch]$TemizAgac
)

$ErrorActionPreference = 'Stop'

$Kok = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $Kok

$Surum = (& python -c 'from CORE.version import __version__; print(__version__)').Trim()
Write-Host "-- HYCLEUS $Surum (windows) ------------------------------------"

# ── 1) Temiz ağaç koşulu ──────────────────────────────────────────────────────
$DataDizini = Join-Path $Kok 'data'
if (Test-Path $DataDizini) {
    if ($TemizAgac) {
        throw "data/ dizini var. -TemizAgac ile B-024 senaryosu ölçülüyor: " +
              "yapı, o dizini zaten üretmiş bir makineye BAĞLI OLMAMALI."
    }
    Write-Host "[1/3] data/ var (yerel geliştirme) - temiz agac denetimi atlandi"
} else {
    Write-Host "[1/3] data/ yok - temiz agac"
}

# ── 2) PyInstaller ────────────────────────────────────────────────────────────
Write-Host "[2/3] PyInstaller"
Remove-Item -Recurse -Force (Join-Path $Kok 'build\HYCLEUS') -ErrorAction SilentlyContinue
Remove-Item -Force (Join-Path $Kok 'dist\HYCLEUS.exe') -ErrorAction SilentlyContinue

# --noconfirm: dist/ zaten varsa sormadan uzerine yazar (CI'da soru = takilma).
#
# $ErrorActionPreference NEDEN GECICI OLARAK GEVSETILIYOR:
# PyInstaller ilerlemesini stderr'e yaziyor. Windows PowerShell 5.1, bir
# yerli komutun stderr'i YONLENDIRILDIGINDE her satiri ErrorRecord'a
# sariyor (NativeCommandError) ve 'Stop' altinda betigi oldururyor —
# PyInstaller cikis kodu 0 dondurmus olsa bile. Olculdu: `2>&1` ile
# cagrildiginda yapi ilk INFO satirinda dusuyordu.
#
# pwsh 7 bunu yapmiyor, yani CI'da (shell: pwsh) sorun cikmazdi. Ama
# betik yerelde de calisiyor ve "hangi kabukta cagrildigina gore kirilan
# yapi betigi" en kotu turden bir kirilganlik. Basari olcutu tek yerde:
# $LASTEXITCODE.
$oncekiTercih = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & python -m PyInstaller --noconfirm --log-level=WARN HYCLEUS.spec
    $pyKod = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $oncekiTercih
}
if ($pyKod -ne 0) {
    throw "PyInstaller cikis kodu $pyKod"
}

# ── 3) Çıktı ──────────────────────────────────────────────────────────────────
$Exe = Join-Path $Kok 'dist\HYCLEUS.exe'
if (-not (Test-Path $Exe)) {
    throw "dist\HYCLEUS.exe uretilmedi"
}
$Mb = [math]::Round((Get-Item $Exe).Length / 1MB, 1)
Write-Host "[3/3] hazir: $Exe  ($Mb MB)"
