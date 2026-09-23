#!/usr/bin/env bash
# HYCLEUS — smoke-test.sh'nin [6] adımının (B-154) MUTASYON kanıtı.
#
# Bu depoda gerçek bir AppImage inşa etmek appimagetool/squashfs-tools
# ister (Windows geliştirme makinesinde yok); bu yüzden gerçek bir
# AppImage'a karşı uçtan uca koşulamıyor. Onun yerine smoke-test.sh'nin
# [6] adımının KOD BLOĞU (satır 112-139, harfiyen kopyalandı — elle
# yeniden yazılmadı) burada, "${KOK}/AppRun" bir MUTANT stub'a
# (_smoke_test_mutant_stub.sh) işaret edecek şekilde çalıştırılıyor.
# Stub, B-154 düzeltmesi hiç YAPILMAMIŞ olsaydı paketlenmiş bir yapının
# nasıl davranacağını taklit ediyor: HYCLEUS_TEST_DATA_DIR'i sessizce
# kabul eder, dizini oluşturur, çıkış kodu 0 döner, stderr'e hiçbir şey
# yazmaz. [6] bunu yakalamalı — üç ayrı denetimin ÜÇÜ DE kırmızı olmalı.
#
# Çalıştırma: ./packaging/linux/smoke-test-mutasyon-kaniti.sh

set -euo pipefail

BURASI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALISMA="$(mktemp -d)"
trap 'rm -rf "${CALISMA}"' EXIT

KOK="${CALISMA}/squashfs-root"
mkdir -p "${KOK}"
cp "${BURASI}/_smoke_test_mutant_stub.sh" "${KOK}/AppRun"
chmod +x "${KOK}/AppRun"

gecti=0
kaldi=0

# ── smoke-test.sh satır 112-139'un HARFİYEN kopyası ──────────────────────────
echo "[6] HYCLEUS_TEST_DATA_DIR paketlenmiş yapıda reddediliyor"
sahte="${CALISMA}/sahte-izole"
hata="$(HYCLEUS_TEST_DATA_DIR="${sahte}" "${KOK}/AppRun" --selftest 2>&1)" && durum=0 || durum=$?

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
if [ ! -e "${sahte}" ]; then
  echo "  ✓ sh -c \"[ ! -e '${sahte}' ]\""
  gecti=$((gecti + 1))
else
  echo "  ✗ sh -c \"[ ! -e '${sahte}' ]\""
  kaldi=$((kaldi + 1))
fi
# ── kopya sonu ────────────────────────────────────────────────────────────────

echo
echo "geçti: ${gecti}  kaldı: ${kaldi}  (BEKLENEN: 0 geçti, 3 kaldı -- mutant TAMAMEN kırmızı olmalı)"
if [ "${kaldi}" -eq 3 ] && [ "${gecti}" -eq 0 ]; then
  echo "KANIT OK: [6] mutant'ı yakaladı."
  exit 0
else
  echo "KANIT BAŞARISIZ: [6] mutant'ı YAKALAMADI (bu bir regresyon olurdu)."
  exit 1
fi
