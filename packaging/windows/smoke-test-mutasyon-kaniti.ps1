<#
.SYNOPSIS
    smoke-test.ps1'in [6] adiminin (B-154) MUTASYON kaniti.

.DESCRIPTION
    Gercek EXE yerine _smoke_test_mutant_stub.bat calistirilir -- B-154
    duzeltmesi hic YAPILMAMIS olsaydi paketlenmis bir yapinin nasil
    davranacagini taklit eder: HYCLEUS_TEST_DATA_DIR'i sessizce kabul
    eder, dizini olusturur, cikis kodu 0 doner, stderr'e hicbir sey
    yazmaz. Gercek smoke-test.ps1'in TAMAMI calistirilir (kirpilmis bir
    kopya degil); diger adimlarin (1, 4, 5 gibi) stub'in trivial olmasi
    yuzunden de kirmizi cikmasi BEKLENIR ve onemsizdir -- kanitin odagi
    yalnizca [6]: uc ayri denetimin (cikis kodu / stderr mesaji / dizin)
    UCU DE kirmizi olmali. Yeniden derleme YAPMAZ; PyInstaller
    ICERMEZ.

.EXAMPLE
    .\packaging\windows\smoke-test-mutasyon-kaniti.ps1
#>
$Kok = $PSScriptRoot
$Stub = Join-Path $Kok '_smoke_test_mutant_stub.bat'

Write-Host "=== MUTASYON KANITI: $Stub ==="
& (Join-Path $Kok 'smoke-test.ps1') -ExePath $Stub
$kod = $LASTEXITCODE

Write-Host ''
if ($kod -ne 0) {
    Write-Host "KANIT OK: script mutant'a karsi KIRMIZI cikti (kod=$kod)."
    Write-Host "  Yukaridaki [6] bolumunde ucu de [-] olmali:"
    Write-Host "  'cikis kodu sifir DEGIL', 'stderrde ... mesaji var', 'hedef dizin OLUSTURULMADI'."
    exit 0
} else {
    Write-Host "KANIT BASARISIZ: script mutant'i YAKALAMADI (kod=0) -- bu bir regresyon olurdu."
    exit 1
}
