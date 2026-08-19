#!/usr/bin/env bash
# HYCLEUS — Linux AppImage yapısı.
#
# Windows karşılığı tek satır: `pyinstaller --noconfirm HYCLEUS.spec`.
# Linux'ta bir adım daha var, çünkü AppImage yalnızca bir ikili değil bir
# DİZİN AĞACI istiyor (AppDir) ve o ağacın biçimi katı: kökte çalıştırılabilir
# bir AppRun, bir .desktop dosyası ve .DirIcon.
#
# Bu betik ÇAPRAZ DERLEME YAPMAZ. PyInstaller çalıştığı platform için ikili
# üretir; dolayısıyla bu betik Linux'ta koşmak zorunda. Windows'tan
# çalıştırılamaz — CI'ın `appimage` işi tam olarak bu yüzden var.
#
# Çalıştırma:
#     ./packaging/linux/build-appimage.sh            # yapıyı üret
#     ./packaging/linux/build-appimage.sh --test     # üret + duman testi
#
# Çıktı: dist/HYCLEUS-<sürüm>-x86_64.AppImage

set -euo pipefail

KOK="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PAKET="${KOK}/packaging/linux"
APPDIR="${KOK}/build/HYCLEUS.AppDir"
ARAC_DIZINI="${KOK}/build/tools"

cd "${KOK}"

SURUM="$(python -c 'from CORE.version import __version__; print(__version__)')"
MIMARI="$(uname -m)"
CIKTI="${KOK}/dist/HYCLEUS-${SURUM}-${MIMARI}.AppImage"

echo "── HYCLEUS ${SURUM} (${MIMARI}) ─────────────────────────────────────────"

# ── 1) PyInstaller ────────────────────────────────────────────────────────────
# --noconfirm: dist/ zaten varsa sormadan üzerine yazar (CI'da soru = takılma).
echo "[1/4] PyInstaller"
rm -rf "${KOK}/build/HYCLEUS" "${KOK}/dist/HYCLEUS" "${APPDIR}"
pyinstaller --noconfirm --log-level=WARN HYCLEUS-linux.spec

test -x "${KOK}/dist/HYCLEUS/HYCLEUS" \
  || { echo "HATA: dist/HYCLEUS/HYCLEUS üretilmedi"; exit 1; }

# ── 2) AppDir ─────────────────────────────────────────────────────────────────
# Yerleşim AppImage'ın beklediği biçim: kökte AppRun/.desktop/.DirIcon,
# gerçek dosyalar usr/ altında. usr/share/ kopyaları masaüstü entegrasyonu
# için (appimaged, Gear Lever) — AppImage'ı sisteme kuran araçlar simgeyi
# ve girdiyi oradan alıyor.
echo "[2/4] AppDir"
mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/256x256/apps"

cp -a "${KOK}/dist/HYCLEUS/." "${APPDIR}/usr/bin/"

install -m 755 "${PAKET}/AppRun"        "${APPDIR}/AppRun"
install -m 644 "${PAKET}/hycleus.desktop" "${APPDIR}/hycleus.desktop"
install -m 644 "${PAKET}/hycleus.png"     "${APPDIR}/hycleus.png"

# .DirIcon SEMBOLİK BAĞ DEĞİL, kopya: bazı araçlar AppDir'i sembolik bağları
# izlemeden okuyor ve kırık bir .DirIcon yapıyı reddettiriyor.
cp "${PAKET}/hycleus.png" "${APPDIR}/.DirIcon"

cp "${PAKET}/hycleus.desktop" "${APPDIR}/usr/share/applications/hycleus.desktop"
cp "${PAKET}/hycleus.png" \
   "${APPDIR}/usr/share/icons/hicolor/256x256/apps/hycleus.png"

# ── 3) appimagetool ───────────────────────────────────────────────────────────
# `--appimage-extract-and-run`: appimagetool'un KENDİSİ bir AppImage ve
# çalışmak için FUSE istiyor. GitHub koşucularında (Ubuntu 24.04) libfuse2
# kurulu değil; bu bayrak aracı bağlamak yerine açıp çalıştırıyor.
echo "[3/4] appimagetool"
mkdir -p "${ARAC_DIZINI}"
ARAC="${ARAC_DIZINI}/appimagetool-${MIMARI}.AppImage"
if [ ! -x "${ARAC}" ]; then
  curl -fsSL -o "${ARAC}" \
    "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-${MIMARI}.AppImage"
  chmod +x "${ARAC}"
fi

mkdir -p "${KOK}/dist"

# ARCH: appimagetool mimariyi ikiliden tahmin etmeye çalışıyor ve
# belirsizlikte hata veriyor; açıkça vermek o yolu tamamen kapatıyor.
#
# `--no-appstream` İKİ KEZ deneniyor. Aracın eski C sürümü bu bayrağı
# tanıyor; `continuous` etiketi zamanla değişiyor ve bayrağın düştüğü bir
# sürüm gelirse "unrecognized option" ile kırılırdı. Yapı betiğinin bir
# yukarı akış bayrak değişikliği yüzünden durması gereksiz; hangi yoldan
# gidildiği yazdırılıyor ki sessiz kalmasın.
if ARCH="${MIMARI}" "${ARAC}" --appimage-extract-and-run --no-appstream \
     "${APPDIR}" "${CIKTI}"; then
  :
else
  echo "  not: --no-appstream kabul edilmedi, bayraksız yeniden deneniyor"
  ARCH="${MIMARI}" "${ARAC}" --appimage-extract-and-run "${APPDIR}" "${CIKTI}"
fi

test -x "${CIKTI}" || { echo "HATA: AppImage üretilmedi"; exit 1; }
echo "[4/4] hazır: ${CIKTI}  ($(du -h "${CIKTI}" | cut -f1))"

# ── Duman testi ───────────────────────────────────────────────────────────────
if [ "${1:-}" = "--test" ]; then
  echo
  echo "── duman testi ──────────────────────────────────────────────────────"
  "${PAKET}/smoke-test.sh" "${CIKTI}"
fi
