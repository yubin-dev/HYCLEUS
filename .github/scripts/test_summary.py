"""
HYCLEUS — pytest JUnit XML'ini GitHub iş özetine (job summary) çevirir.

Neden bu betik var
------------------
CI'ın `pytest` adımı yeşil yandığında yalnızca "çıkış kodu 0" bilgisi
görünüyordu. Kaç testin KOŞTUĞU görünmüyordu ve depo günlüklerini indirmek
yönetici yetkisi istiyor (API 403 veriyor). Aradaki boşluk teorik değil:
2.7 Faz 2'de `tests/test_lock_overlay.py` bir import hatası yüzünden
sessizce atlanmaya başlamış, 24 test yok olmuş ama paket yeşil kalmıştı.
Çıkış kodu bunu yakalayamaz; test SAYISI yakalar.

Bu yüzden sayılar Actions sekmesinde, günlüğe inmeden görünür oluyor.

Neden ayrı bir Python dosyası (satır içi kabuk değil)
-----------------------------------------------------
İki koşucu iki farklı kabuk kullanıyor ve satır içi bir betik test
EDİLEMEZ. Bu dosyanın kendi testleri var (tests/test_ci_summary.py) —
CI'ın kendi raporlama aracının sessizce bozulması, raporladığı sorunun
aynısı olurdu.

Kullanım:
    python .github/scripts/test_summary.py test-results.xml >> $GITHUB_STEP_SUMMARY
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

#: Özette listelenecek en fazla başarısız test. Yüzlerce hata varsa iş
#: özetini taşırmak yerine ilk birkaçını gösterip geri kalanı sayıyoruz.
_MAX_LISTED = 20


@dataclass(frozen=True)
class Totals:
    """Bir JUnit raporunun sayıları."""

    tests: int = 0
    failures: int = 0
    errors: int = 0
    skipped: int = 0
    time: float = 0.0

    @property
    def passed(self) -> int:
        """
        Geçen test sayısı.

        JUnit'te `tests` özniteliği atlananları DA içeriyor; geçen sayısı
        ayrı bir alan olarak yok, çıkarmayla bulunuyor.
        """
        return self.tests - self.failures - self.errors - self.skipped

    @property
    def ok(self) -> bool:
        return self.failures == 0 and self.errors == 0


def parse(path: Path) -> tuple[Totals, list[str]]:
    """
    JUnit XML'ini okur; (toplamlar, başarısız test adları) döndürür.

    pytest kök öğe olarak <testsuites> yazıyor ama tek bir <testsuite> de
    geçerli JUnit — ikisi de destekleniyor.
    """
    root = ET.parse(path).getroot()
    suites = (
        [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    )

    toplam = Totals()
    for suite in suites:
        toplam = Totals(
            tests=toplam.tests + int(suite.get("tests", 0)),
            failures=toplam.failures + int(suite.get("failures", 0)),
            errors=toplam.errors + int(suite.get("errors", 0)),
            skipped=toplam.skipped + int(suite.get("skipped", 0)),
            time=toplam.time + float(suite.get("time", 0.0)),
        )

    basarisiz: list[str] = []
    for case in root.iter("testcase"):
        if case.find("failure") is not None or case.find("error") is not None:
            sinif = case.get("classname", "")
            ad = case.get("name", "?")
            basarisiz.append(f"{sinif}::{ad}" if sinif else ad)

    return toplam, basarisiz


def render(totals: Totals, failed: list[str], *, title: str) -> str:
    """İş özetine yazılacak markdown."""
    isaret = "✅" if totals.ok else "❌"
    satirlar = [
        f"### {isaret} {title}",
        "",
        "| Toplam | Geçen | Atlanan | Başarısız | Hata | Süre |",
        "|---:|---:|---:|---:|---:|---:|",
        f"| **{totals.tests}** | {totals.passed} | {totals.skipped} |"
        f" {totals.failures} | {totals.errors} | {totals.time:.0f}s |",
    ]

    if failed:
        satirlar += ["", f"**Başarısız ({len(failed)}):**", ""]
        satirlar += [f"- `{ad}`" for ad in failed[:_MAX_LISTED]]
        if len(failed) > _MAX_LISTED:
            satirlar.append(f"- … ve {len(failed) - _MAX_LISTED} tane daha")

    return "\n".join(satirlar) + "\n"


def main(argv: list[str]) -> int:
    """
    Her zaman 0 döndürür — bu betik RAPORLAR, karar vermez.

    Sıfırdan farklı bir çıkış, zaten kırmızı olan bir adımın üstüne ikinci
    bir hata eklerdi ve asıl sebebi gölgeleyebilirdi. Testlerin geçip
    geçmediğine `pytest` adımının kendisi karar veriyor.
    """
    # Çıktı UTF-8 olmalı. Windows koşucusunda Python, yönlendirilmiş
    # stdout için yerel kod sayfasını (cp1252) seçiyor ve tablodaki ✅/❌
    # UnicodeEncodeError ile düşüyor — Türkçe başlıklar da aynı şekilde.
    # GITHUB_STEP_SUMMARY UTF-8 bekliyor, dolayısıyla zorluyoruz.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

    if len(argv) < 2:
        print("kullanım: test_summary.py <junit.xml> [başlık]", file=sys.stderr)
        return 0

    path = Path(argv[1])
    title = argv[2] if len(argv) > 2 else "Test sonuçları"

    if not path.exists():
        # pytest XML yazmadan çöktüyse (toplama hatası, segfault) özet yine
        # bir şey söylemeli — sessiz kalmak "sorun yok" gibi görünürdü.
        print(f"### ⚠️ {title}\n\n`{path}` bulunamadı — pytest rapor yazamadan düştü.\n")
        return 0

    try:
        totals, failed = parse(path)
    except ET.ParseError as exc:
        print(f"### ⚠️ {title}\n\n`{path}` ayrıştırılamadı: {exc}\n")
        return 0

    print(render(totals, failed, title=title))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
