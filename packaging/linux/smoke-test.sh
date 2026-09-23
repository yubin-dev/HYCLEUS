#!/usr/bin/env bash
# HYCLEUS — üretilen AppImage'ın duman testi.
#
# "Çalıştırılabilir mi" sorusu bir GUI uygulamasında doğrudan sorulamaz:
# main() USB bulamayınca modal bir QMessageBox açar ve başsız bir koşucuda
# o kutu sonsuza kadar bekler. Bu yüzden test, uygulamanın GUI'siz
# bayraklarını (--version / --selftest) kullanıyor; bkz. main.py.
#
# AppImage FUSE olmadan da açılabiliyor: runtime'ın kendi
# `--appimage-extract` bayrağı squashfs'i dizine çıkarıyor. Koşucularda
# libfuse2 kurulu olmadığı için test bu yoldan gidiyor — ve bu aynı zamanda
# AppImage'ın İÇ YAPISINI da doğruluyor (AppRun, .DirIcon, .desktop).
#
# Çalıştırma: ./packaging/linux/smoke-test.sh dist/HYCLEUS-*.AppImage

set -euo pipefail

APPIMAGE="${1:?kullanım: smoke-test.sh <yol.AppImage>}"
APPIMAGE="$(readlink -f "${APPIMAGE}")"
CALISMA="$(mktemp -d)"
trap 'rm -rf "${CALISMA}"' EXIT

gecti=0
kaldi=0

kontrol() {
  if "$@" >/dev/null 2>&1; then
    echo "  ✓ $*"
    gecti=$((gecti + 1))
  else
    echo "  ✗ $*"
    kaldi=$((kaldi + 1))
  fi
}

echo "AppImage: ${APPIMAGE}"

# ── 1) Dosyanın kendisi ───────────────────────────────────────────────────────
echo "[1] dosya"
kontrol test -f "${APPIMAGE}"
kontrol test -x "${APPIMAGE}"
# ELF sihirli baytı: appimagetool bir kabuk betiği ya da yarım dosya
# üretmiş olsaydı buradaki her şey yine "çalışıyor" görünürdü.
kontrol sh -c "head -c4 '${APPIMAGE}' | od -An -tx1 | grep -q '7f 45 4c 46'"

# ── 2) İç yapı ────────────────────────────────────────────────────────────────
echo "[2] iç yapı"
cd "${CALISMA}"
"${APPIMAGE}" --appimage-extract >/dev/null
KOK="${CALISMA}/squashfs-root"
kontrol test -x "${KOK}/AppRun"
kontrol test -f "${KOK}/.DirIcon"
kontrol test -f "${KOK}/hycleus.desktop"
kontrol test -x "${KOK}/usr/bin/HYCLEUS"
kontrol grep -q "^Icon=hycleus$" "${KOK}/hycleus.desktop"

# Windows'a özgü hiçbir şey sızmamalı: spec `excludes` ile eliyor ama
# gerçekten elediğini ancak çıktıya bakarak bilebiliriz.
echo "[3] Windows kalıntısı yok"
kontrol sh -c "! find '${KOK}' -iname 'pythoncom*' -o -iname 'win32*' -o -iname 'wmi*' | grep -q ."

# ── 4) Çalıştırma ─────────────────────────────────────────────────────────────
# AppRun üzerinden: bağlama noktası çözümlemesi de test edilmiş oluyor.
echo "[4] çalıştırma"

surum="$("${KOK}/AppRun" --version 2>/dev/null | tr -d '\r')"
if [ -n "${surum}" ]; then
  echo "  ✓ --version → ${surum}"
  gecti=$((gecti + 1))
else
  echo "  ✗ --version çıktı vermedi"
  kaldi=$((kaldi + 1))
fi

cikti="$("${KOK}/AppRun" --selftest 2>&1)" && durum=0 || durum=$?
echo "${cikti}" | sed 's/^/      /'
if [ "${durum}" -eq 0 ] && echo "${cikti}" | grep -q "SELFTEST OK"; then
  echo "  ✓ --selftest"
  gecti=$((gecti + 1))
else
  echo "  ✗ --selftest (çıkış=${durum})"
  kaldi=$((kaldi + 1))
fi

# ── 5) AppImage veri dizini ───────────────────────────────────────────────────
# Asıl Linux'a özgü tuzak. AppImage salt okunur bağlanıyor; data_dir()
# "EXE'nin yanı" derse kasa hiç açılamaz. Çıkarılmış AppDir'de `APPIMAGE`
# değişkeni TANIMSIZ olduğu için burada elle veriliyor — runtime'ın
# gerçek çalıştırmada yaptığı şeyin aynısı.
echo "[5] AppImage veri dizini XDG'ye gidiyor"
xdg="${CALISMA}/xdg"
veri="$(APPIMAGE="${APPIMAGE}" XDG_DATA_HOME="${xdg}" "${KOK}/AppRun" --selftest 2>/dev/null \
        | sed -n 's/^data dizini: //p')"
if [ "${veri}" = "${xdg}/HYCLEUS" ]; then
  echo "  ✓ data dizini → ${veri}"
  gecti=$((gecti + 1))
else
  echo "  ✗ data dizini '${veri}' — beklenen '${xdg}/HYCLEUS'"
  kaldi=$((kaldi + 1))
fi

# ── 6) HYCLEUS_TEST_DATA_DIR paketlenmiş yapıda REDDEDİLİYOR (B-154) ──────────
#
# DEV_MODE (CORE/usb_manager.py) sys.frozen ile kapatılıyordu, ama bu
# değişken öyle DEĞİLDİ — gerçek paketlenmiş bir AppImage'ı, üretim
# denetim kaydına hiç yazılmadan, dev ortamındaki gibi keyfi bir veri
# dizinine (DB/vault/TOTP/denetim çıpası/SafeZone) yönlendirebiliyordu.
# Bu adım kaynakta değil GERÇEK, derlenmiş üründe kanıtlıyor — bir birim
# testinin sys.frozen monkeypatch'i CORE/paths.py::data_dir()'ın kendisini
# doğruluyor, ama bu paketleme adımlarının (excludes, hiddenimports) o
# düzeltmeyi son ürüne GERÇEKTEN taşıdığını kanıtlamıyor.
echo "[6] HYCLEUS_TEST_DATA_DIR paketlenmiş yapıda reddediliyor"
sahte="${CALISMA}/sahte-izole"
hata="$(HYCLEUS_TEST_DATA_DIR="${sahte}" "${KOK}/AppRun" --selftest 2>&1)" && durum=0 || durum=$?

# Üç koşul AYRI AYRI ve ÜÇÜ DE ZORUNLU denetleniyor -- tek başına mesaj
# kontrolü YETERLİ DEĞİL: bir mutant/regresyon "geçersiz dizin" gibi
# zararsız bir metin yazıp çıkış kodu 0 ile devam edebilir VE dizini
# yine de oluşturabilirdi. Üçü birden geçmezse adım KIRMIZI -- bkz.
# packaging/linux/smoke-test-mutasyon-kaniti.sh (mutasyon kanıtı, stub
# "önceki/korumasız" davranışı taklit ediyor: sessizce kabul + dizin
# oluştur + çıkış 0 + stderr'de ret mesajı YOK).
if [ "${durum}" -ne 0 ]; then
  echo "  ✓ çıkış kodu sıfır DEĞİL (reddetti) (çıkış=${durum})"
  gecti=$((gecti + 1))
else
  echo "  ✗ çıkış kodu sıfır DEĞİL (reddetti) (çıkış=${durum})"
  kaldi=$((kaldi + 1))
fi
if echo "${hata}" | grep -q "HYCLEUS_TEST_DATA_DIR"; then
  echo "  ✓ stderr/stdout'ta HYCLEUS_TEST_DATA_DIR mesajı var"
  gecti=$((gecti + 1))
else
  echo "  ✗ stderr/stdout'ta HYCLEUS_TEST_DATA_DIR mesajı var"
  kaldi=$((kaldi + 1))
fi
if [ "${durum}" -eq 0 ] || ! echo "${hata}" | grep -q "HYCLEUS_TEST_DATA_DIR"; then
  echo "${hata}" | sed 's/^/      /'
fi
kontrol sh -c "[ ! -e '${sahte}' ]"

echo
echo "geçti: ${gecti}  kaldı: ${kaldi}"
[ "${kaldi}" -eq 0 ]
