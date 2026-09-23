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

# ── 7) --help (B-037) ─────────────────────────────────────────────────────────
#
# Windows'un aksine Linux'ta İKİNCİ bir ikili YOK: AppRun bir terminalden
# çağrıldığında stdio'yu doğal olarak miras alıyor (bkz. AppRun'ın kendi
# yorumu), yani --recover/--takeover/--export AYNI AppRun'dan çalışıyor.
echo "[7] --help"
yardim_ciktisi="$("${KOK}/AppRun" --help 2>&1)" && yardim_durum=0 || yardim_durum=$?
if [ "${yardim_durum}" -eq 0 ] \
   && echo "${yardim_ciktisi}" | grep -q -- '--recover' \
   && echo "${yardim_ciktisi}" | grep -q -- '--export' \
   && echo "${yardim_ciktisi}" | grep -q -- '--takeover'; then
  echo "  ✓ --help (çıkış=0, --recover/--export/--takeover listeleniyor)"
  gecti=$((gecti + 1))
else
  echo "  ✗ --help (çıkış=${yardim_durum})"
  echo "${yardim_ciktisi}" | sed 's/^/      /'
  kaldi=$((kaldi + 1))
fi

# ── 8) --export — USB YOKKEN, gerçek hata yoluna kadar (B-037) ────────────────
#
# UÇTAN UCA bir kurtarma (gerçek pay/PIN'le master_key'i yeniden kurmak)
# BU KOŞUCUDA KOŞULAMAZ — gerçek bir donanım sınırı, eksiklik değil:
# `_require_hwid()` GERÇEK bir USB istiyor, CI koşucusunda hiçbiri takılı
# değil. Bilerek yeni bir HWID-baypas bayrağı EKLENMİYOR (B-154'ün aynı
# kararı). Ölçülen sınır "anahtar kasası" DEĞİL — Linux'ta `keyring`
# arka ucu (SecretService/kwallet ya da düz dosya) sorunsuz çalışıyor;
# asıl engel USB/HWID tespiti. Kod 1 VE beklenen "USB HWID eksik"
# mesajı BİRLİKTE, paketlenmiş AppImage'ın gerçek main.py ->
# _erken_komut() -> CORE.recover_vault.main() zincirinin SONUNA kadar
# ulaştığını kanıtlıyor.
#
# ÖLÇÜLDÜ (Windows tarafında ilk yazılan sürüm YANLIŞ tahmin ediyordu):
# hata `_cmd_export()`'un kendi `_require_hwid()`'inden DEĞİL, ondan
# ÖNCE — `recover_vault.main()`'in `DBManager().connect(hwid=hwid,
# key=None)` çağrısından geliyor (`hwid=None` olunca DB katmanı
# REDDEDİYOR, `DB/db_manager.py:266`).
echo "[8] --export (USB yok -- gerçek hata yoluna kadar)"
disa_ciktisi="$("${KOK}/AppRun" --export 2>&1)" && disa_durum=0 || disa_durum=$?
if [ "${disa_durum}" -eq 1 ] && echo "${disa_ciktisi}" | grep -q "USB HWID eksik"; then
  echo "  ✓ --export (çıkış=1, \"USB HWID eksik\" mesajı var)"
  gecti=$((gecti + 1))
else
  echo "  ✗ --export (çıkış=${disa_durum})"
  echo "${disa_ciktisi}" | sed 's/^/      /'
  kaldi=$((kaldi + 1))
fi

echo
echo "geçti: ${gecti}  kaldı: ${kaldi}"
[ "${kaldi}" -eq 0 ]
