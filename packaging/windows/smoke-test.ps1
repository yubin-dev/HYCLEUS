<#
.SYNOPSIS
    HYCLEUS — üretilen Windows EXE'sinin duman testi.

.DESCRIPTION
    Linux karşılığı: packaging/linux/smoke-test.sh. Aynı mantık, aynı sıra.

    "Çalıştırılabilir mi" sorusu bir GUI uygulamasında doğrudan sorulamaz:
    main() USB bulamayınca modal bir QMessageBox açar ve başsız bir
    koşucuda o kutu sonsuza kadar bekler. Bu yüzden test, uygulamanın
    GUI'siz bayraklarını (--version / --selftest) kullanıyor; bkz. main.py.

    `Start-Process -Wait` KULLANILIYOR, `&` değil: HYCLEUS.exe GUI
    alt sistemine (console=False) derleniyor ve kabuk böyle bir süreci
    beklemeden dönebiliyor. Beklemeyen bir duman testi, yapı bozuk olsa
    bile yeşil geçerdi.

.PARAMETER ExePath
    Sınanacak EXE. Verilmezse dist\HYCLEUS.exe.

.EXAMPLE
    .\packaging\windows\smoke-test.ps1
    .\packaging\windows\smoke-test.ps1 -ExePath dist\HYCLEUS.exe
#>
[CmdletBinding()]
param(
    [string]$ExePath
)

$ErrorActionPreference = 'Stop'

$Kok = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $ExePath) { $ExePath = Join-Path $Kok 'dist\HYCLEUS.exe' }

#: --selftest'in denemesi gereken EN AZ modül sayısı. Kesin sayı BİLEREK
#: yazılmıyor: her yeni CORE/ modülü onu artırıyor ve sabit bir sayı, testi
#: gerçek bir bulgu olmadan kırardı. Asıl denetim "yüklenen == denenen".
#: Taban, listenin sessizce boşalmasına karşı.
$AsgariModul = 50

$gecti = 0
$kaldi = 0

function Kontrol {
    param([string]$Ad, [bool]$Sonuc, [string]$Ayrinti = '')
    if ($Sonuc) {
        Write-Host "  [+] $Ad $Ayrinti"
        $script:gecti++
    } else {
        Write-Host "  [-] $Ad $Ayrinti"
        $script:kaldi++
    }
}

function Calistir {
    <#
      EXE'yi çalıştırır, (ExitCode, Cikti, Hata) döndürür.
      Çıktı UTF-8: main.py ensure_utf8_console() ile akışı yeniden
      yapılandırıyor (Türkçe karakterler, bkz. B-013).

      `Cikti` (stdout) ve `Hata` (stderr) AYRI tutuluyor -- `--version`/
      `--selftest` stdout'a yazıyor, ama CORE/paths.py::
      reddet_paketlenmis_override() (B-154) reddi STDERR'e yazıyor.
      Yalnızca `Cikti` döndüren önceki sürüm [6] adımını YANLIŞ KIRMIZI
      yapıyordu (CI'da GERÇEKTEN ölçüldü, 2026-09-23: ret doğru çalışıyor
      -- kod=2, hedef dizin oluşmuyor -- ama "reddedildi" denetimi
      stderr'i hiç görmediği için KIRMIZI çıkıyordu). Linux karşılığı
      (`smoke-test.sh`) bu hataya hiç düşmedi çünkü `2>&1` ile ikisini
      zaten birleştiriyor.
    #>
    param([string]$Exe, [string[]]$Argumanlar, [hashtable]$Ortam = @{})

    $out = [System.IO.Path]::GetTempFileName()
    $err = [System.IO.Path]::GetTempFileName()
    $eski = @{}
    try {
        foreach ($anahtar in $Ortam.Keys) {
            $eski[$anahtar] = [Environment]::GetEnvironmentVariable($anahtar)
            [Environment]::SetEnvironmentVariable($anahtar, $Ortam[$anahtar])
        }
        $p = Start-Process -FilePath $Exe -ArgumentList $Argumanlar `
             -Wait -NoNewWindow -PassThru `
             -RedirectStandardOutput $out -RedirectStandardError $err
        $metin = ''
        if (Test-Path $out) { $metin = Get-Content $out -Raw -Encoding utf8 }
        if (-not $metin) { $metin = '' }
        $hataMetni = ''
        if (Test-Path $err) { $hataMetni = Get-Content $err -Raw -Encoding utf8 }
        if (-not $hataMetni) { $hataMetni = '' }
        return @{ Kod = $p.ExitCode; Cikti = $metin; Hata = $hataMetni }
    } finally {
        foreach ($anahtar in $eski.Keys) {
            [Environment]::SetEnvironmentVariable($anahtar, $eski[$anahtar])
        }
        Remove-Item $out, $err -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "EXE: $ExePath"

# ── 1) Dosyanın kendisi ───────────────────────────────────────────────────────
Write-Host '[1] dosya'
$varMi = Test-Path $ExePath -PathType Leaf
Kontrol 'dosya var' $varMi
if (-not $varMi) {
    Write-Host ''
    Write-Host "gecti: $gecti  kaldi: $kaldi"
    exit 1
}

$ExePath = (Resolve-Path $ExePath).Path
$boyutMb = (Get-Item $ExePath).Length / 1MB
Kontrol 'boyut makul' ($boyutMb -gt 10) ("({0:N1} MB)" -f $boyutMb)

# PE sihirli baytı. PyInstaller bir kabuk sarmalayıcısı ya da yarım dosya
# uretmis olsaydi asagidaki her sey yine "calisiyor" gorunurdu.
$ilkIki = [System.IO.File]::ReadAllBytes($ExePath)[0..1]
Kontrol 'PE basligi (MZ)' (($ilkIki[0] -eq 0x4D) -and ($ilkIki[1] -eq 0x5A))

# ── 2) Çalıştırma ─────────────────────────────────────────────────────────────
Write-Host '[2] calistirma'

$s = Calistir $ExePath @('--version')
$surum = $s.Cikti.Trim()
Kontrol '--version' (($s.Kod -eq 0) -and ($surum -ne '')) "-> $surum"

$s = Calistir $ExePath @('--selftest')
$cikti = $s.Cikti
$cikti -split "`n" | ForEach-Object { if ($_.Trim()) { Write-Host "      $($_.TrimEnd())" } }
Kontrol '--selftest cikis kodu 0' ($s.Kod -eq 0) "(kod=$($s.Kod))"
Kontrol '--selftest SELFTEST OK' ($cikti -match 'SELFTEST OK')

# ── 3) Modül sayimi ───────────────────────────────────────────────────────────
Write-Host '[3] modul sayimi'
$eslesme = [regex]::Match($cikti, 'Mod.ller\s*:\s*(\d+)/(\d+)')
if ($eslesme.Success) {
    $yuklenen = [int]$eslesme.Groups[1].Value
    $denenen  = [int]$eslesme.Groups[2].Value
    Kontrol 'her modul yuklendi' ($yuklenen -eq $denenen) "($yuklenen/$denenen)"
    Kontrol 'liste bosalmamis' ($denenen -ge $AsgariModul) "(>= $AsgariModul)"
} else {
    Kontrol 'modul sayimi satiri okunabildi' $false
}

# ── 4) wmi / pywin32 ──────────────────────────────────────────────────────────
# B-024'un ikinci yarisi. Linux spec'i bu paketleri `excludes` ile eliyor
# (Linux'ta kurulamiyorlar). O satirin Windows spec'ine kopyalanmasi HWID
# okumasini SESSIZCE bozardi: get_usb_hwid() her iki yontemi de
# `except Exception: pass` ile sariyor, yani eksik `wmi` bir hata degil
# "USB bulunamadi" olarak gorunur ve uygulama acilmayi reddeder.
#
# Uc numaradaki "her modul yuklendi" denetimi bunu zaten kapsiyor; asagidaki
# satir, wmi grubunun listeden TAMAMEN silinmesine karsi.
Write-Host '[4] wmi / pywin32 paketlenmis'
$platformSatiri = [regex]::Match($cikti, 'Platform mod.lleri:\s*win32\s*.\s*(.+)')
if ($platformSatiri.Success) {
    $liste = $platformSatiri.Groups[1].Value
    foreach ($modul in @('wmi', 'pythoncom', 'win32api', 'win32con')) {
        Kontrol "$modul denendi" ($liste -match [regex]::Escape($modul))
    }
} else {
    Kontrol 'platform modul satiri var' $false '(wmi grubu listeden silinmis olabilir)'
}

# ── 5) data dizini EXE'nin yaninda ────────────────────────────────────────────
# Windows'ta beklenen davranis bu (AppImage'da XDG'ye gidiyor, orada da
# ayni sekilde olculuyor). data_dir() donmus modda sys.executable'in
# yanina bakmali; baska bir yer, kasanin yerini degistirmek demek.
Write-Host '[5] data dizini EXE nin yaninda'
$veriSatiri = [regex]::Match($cikti, 'data dizini:\s*(.+)')
if ($veriSatiri.Success) {
    $veri = $veriSatiri.Groups[1].Value.Trim()
    $beklenen = Join-Path (Split-Path $ExePath -Parent) 'data'
    Kontrol 'data dizini dogru' ($veri -eq $beklenen) "-> $veri"
} else {
    Kontrol 'data dizini satiri okunabildi' $false
}

# ── 6) HYCLEUS_TEST_DATA_DIR paketlenmis yapida REDDEDILIYOR (B-154) ─────────
#
# DEV_MODE (CORE/usb_manager.py) sys.frozen ile kapatiliyordu, ama bu
# degisken oyle DEGILDI -- gercek paketlenmis bir EXE'yi, uretim denetim
# kaydina hic yazilmadan, dev ortamindaki gibi keyfi bir veri dizinine
# (DB/vault/TOTP/denetim cipasi/SafeZone) yonlendirebiliyordu. Bu adim
# kaynakta degil GERCEK, derlenmis EXE'de kanitliyor -- bir birim testinin
# sys.frozen monkeypatch'i CORE/paths.py::data_dir()'in kendisini
# dogruluyor, ama bu paketleme adiminin o duzeltmeyi son urune GERCEKTEN
# tasidigini kanitlamiyor.
Write-Host '[6] HYCLEUS_TEST_DATA_DIR paketlenmis yapida reddediliyor'
$sahte = Join-Path ([System.IO.Path]::GetTempPath()) "hycleus-sahte-izole-$PID"
if (Test-Path $sahte) { Remove-Item $sahte -Recurse -Force }
$s = Calistir $ExePath @('--selftest') @{ HYCLEUS_TEST_DATA_DIR = $sahte }

# Uc kosul AYRI AYRI ve UCU DE ZORUNLU denetleniyor -- tek basina stderr
# mesaj kontrolu YETERLI DEGIL: bir mutant/regresyon "gecersiz dizin"
# gibi zararsiz bir metin yazip cikis kodu 0 ile devam edebilir VE
# dizini yine de olusturabilirdi. Ucu birden gecmezse adim KIRMIZI --
# bkz. packaging/windows/smoke-test-mutasyon-kaniti.ps1 (mutasyon kaniti, stub
# "onceki/korumasiz" davranisi taklit ediyor: sessizce kabul + dizin
# olustur + cikis 0 + stderr'de ret mesaji YOK).
$cikisKoduReddetti = ($s.Kod -ne 0)
# reddet_paketlenmis_override() (CORE/paths.py, B-154) mesajı STDERR'e
# yazıyor, stdout'a değil -- `Cikti` DEĞİL `Hata` kontrol edilmeli.
$stderrMesajVar = ($s.Hata -match 'HYCLEUS_TEST_DATA_DIR')
$dizinOlusmadi = (-not (Test-Path $sahte))

Kontrol 'cikis kodu sifir DEGIL (reddetti)' $cikisKoduReddetti "(kod=$($s.Kod))"
Kontrol 'stderrde HYCLEUS_TEST_DATA_DIR mesaji var' $stderrMesajVar
Kontrol 'hedef dizin OLUSTURULMADI' $dizinOlusmadi

if (-not ($cikisKoduReddetti -and $stderrMesajVar -and $dizinOlusmadi)) {
    Write-Host '      -- stdout --'
    $s.Cikti -split "`n" | ForEach-Object { if ($_.Trim()) { Write-Host "      $($_.TrimEnd())" } }
    Write-Host '      -- stderr --'
    $s.Hata -split "`n" | ForEach-Object { if ($_.Trim()) { Write-Host "      $($_.TrimEnd())" } }
}

Write-Host ''
Write-Host "gecti: $gecti  kaldi: $kaldi"
if ($kaldi -gt 0) { exit 1 }
exit 0
