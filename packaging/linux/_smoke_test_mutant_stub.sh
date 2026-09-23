#!/usr/bin/env bash
# HYCLEUS-STUB-MUTASYON-TESTI: bu bir gercek AppRun DEGIL. B-154 duzeltmesi
# OLMASAYDI paketlenmis bir yapinin nasil davranacagini taklit eder --
# HYCLEUS_TEST_DATA_DIR'i SESSIZCE kabul eder, dizini olusturur, cikis
# kodu 0 doner, stderr'e HICBIR sey yazmaz. smoke-test.sh'nin [6] adiminin
# bunu YAKALADIGINI kanitlamak icindir. Gercek bir AppImage/appimagetool
# gerektirmez -- yalnizca gecici bir mutasyon kanit araci.
set -euo pipefail

if [ "${1:-}" = "--version" ]; then
  echo "HYCLEUS-STUB-MUTASYON 0.0.0"
  exit 0
fi

if [ "${1:-}" = "--selftest" ]; then
  if [ -n "${HYCLEUS_TEST_DATA_DIR:-}" ]; then
    mkdir -p "${HYCLEUS_TEST_DATA_DIR}"
  fi
  echo "SELFTEST OK"
  echo "data dizini: ${XDG_DATA_HOME:-/stub}/HYCLEUS"
  exit 0
fi

exit 0
