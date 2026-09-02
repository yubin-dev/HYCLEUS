"""
K4-20 (B-087/B-106) — denetim raporu (PDF) RFC 3161 mührü.

`CORE/audit_report.py::export_pdf()`'in "MÜHÜRLENMEMİŞTİR" notu artık
gerçek bir mühre çevrilebiliyor: `export_sealed_pdf()` PDF'in ham
baytlarını `CORE.timestamp.request_token()` ile damgalatıyor (B-092/
B-099'a göre güncellenmiş, `timestamp_file()`/`timestamp_batch()` ile
AYNI TSA-istemci gövdesi — ikinci bir implementasyon YOK) ve token'ı bir
`<pdf>.tsr` yardımcı dosyasına yazıyor. `CORE/verify_report_seal_cli.py`
bunu `verify_timestamp_cli.py`'nin eşdeğeri: vault anahtarı/DB istemeden,
yalnızca PDF'in kendi SHA-256'sı ve token'la, B-105'in ikili dosyaya
gömdüğü freetsa.org köküne karşı bağımsız doğruluyor.

ASCII-güvenli alt dize araması
-------------------------------
`tests/test_audit_report.py`'nin ölçtüğü gibi Türkçe özel karakterler
(Ü/İ/Ş) reportlab'ın yazı tipi kodlamasında ham UTF-8 baytlarıyla
EŞLEŞMİYOR — bu yüzden metin-flip testleri BİLEREK ASCII alt dizeler
arıyor ("KANITLAMAZ", dosya adları, `verify_report_seal_cli.py`).
"""
from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest
from tsa_fixtures import FakeTSA, default_authority

from CORE.audit_report import (
    DenetimSatiri,
    ZincirRaporu,
    export_pdf,
    export_sealed_pdf,
    tsr_path_for,
    zincir_raporu,
)
from CORE.timestamp import TimestampError
from CORE.timestamp_verify import verify_token
from CORE.trusted_roots_builtin import gomulu_kokler
from CORE.verify_report_seal_cli import main as cli_main

KOK = Path(__file__).resolve().parent.parent


def _kayitlar(db, n: int = 3) -> None:
    for i in range(n):
        db.log("test_action", detail=f"n={i}")


def _satir(**kw: object) -> DenetimSatiri:
    varsayilan: dict[str, object] = dict(
        id=1, zaman="2026-08-30T12:00:00Z", islem="test_islem",
        kullanici="test.kullanici", kullanici_id=1,
        hwid="HWID-TAM-DEGERI-1234567890",
        detay="hwid=HWID-TAM-DEGERI-1234567890 role=Standart", halka="intact",
    )
    varsayilan.update(kw)
    return DenetimSatiri(**varsayilan)  # type: ignore[arg-type]


@pytest.fixture
def cipa(tmp_path: Path) -> Path:
    return tmp_path / "anchor.log"


@pytest.fixture
def rapor_saglam(db, cipa) -> ZincirRaporu:  # type: ignore[no-untyped-def]
    _kayitlar(db)
    return zincir_raporu(db, cipa_yolu=cipa)


def _hata_veren_transport(url: str, body: bytes, timeout: int) -> bytes:
    """TSA'ya ulaşılamadığını simüle eden taşıyıcı."""
    raise TimestampError("TSA'ya ulasilamadi (test)")


# ══════════════════════════════════════════════════════════════════════════════
# 1. Uyarı metni — mühürsüzden mühürlüye "MÜHÜRLENMEMİŞTİR" → "MÜHÜRLÜDÜR"
# ══════════════════════════════════════════════════════════════════════════════


def test_unsealed_pdf_says_not_sealed(rapor_saglam, tmp_path: Path) -> None:
    out = export_pdf([_satir()], rapor_saglam, tmp_path / "r.pdf", sealed=False)
    raw = out.read_bytes()
    assert b"KANITLAMAZ" in raw, "mühürsüz uyarı metni bulunamadı"
    assert b"verify_report_seal_cli.py" not in raw


def test_sealed_pdf_says_sealed_with_verification_info(
    rapor_saglam, tmp_path: Path,
) -> None:
    out = export_pdf([_satir()], rapor_saglam, tmp_path / "r.pdf", sealed=True)
    raw = out.read_bytes()
    assert b"verify_report_seal_cli.py" in raw, "dogrulama araci adi bulunamadi"
    assert b"r.pdf.tsr" in raw, "yardimci muhur dosyasinin adi bulunamadi"
    assert b"KANITLAMAZ" not in raw, (
        "MUTASYON: sealed=True hala muhursuz uyariyi tasiyor"
    )


def test_sealed_default_is_False(rapor_saglam, tmp_path: Path) -> None:
    """Varsayılan davranış değişmedi — `sealed` vermeyen mevcut çağıranlar
    (ör. `UI/AuditLogView.py::_export_pdf`) hâlâ mühürsüz metni üretiyor."""
    out = export_pdf([_satir()], rapor_saglam, tmp_path / "r.pdf")
    assert b"KANITLAMAZ" in out.read_bytes()


# ══════════════════════════════════════════════════════════════════════════════
# 2. tsr_path_for() — <pdf>.tsr, <pdf'in TSR'si DEĞİL>
# ══════════════════════════════════════════════════════════════════════════════


def test_tsr_path_for_appends_not_replaces() -> None:
    assert tsr_path_for("rapor.pdf") == Path("rapor.pdf.tsr")
    assert tsr_path_for(Path("/x/rapor.pdf")) == Path("/x/rapor.pdf.tsr")


# ══════════════════════════════════════════════════════════════════════════════
# 3. export_sealed_pdf() — mutlu yol (FakeTSA, gerçek imza, gerçek zincir)
# ══════════════════════════════════════════════════════════════════════════════


def test_export_sealed_pdf_writes_a_matching_tsr(
    rapor_saglam, tmp_path: Path,
) -> None:
    out_path, info = export_sealed_pdf(
        [_satir()], rapor_saglam, tmp_path / "r.pdf", transport=FakeTSA(),
    )
    assert info is not None
    tsr = tsr_path_for(out_path)
    assert tsr.is_file()
    assert tsr.read_bytes() == info.token_der


def test_export_sealed_pdf_token_covers_the_ACTUAL_final_bytes(
    rapor_saglam, tmp_path: Path,
) -> None:
    """Damgalanan özet, mühürlü metni İÇEREN nihai dosyanın SHA-256'sı
    olmalı — mühürsüz ARA sürümün özeti değil (döngüsellik kontrolü)."""
    out_path, info = export_sealed_pdf(
        [_satir()], rapor_saglam, tmp_path / "r.pdf", transport=FakeTSA(),
    )
    gercek = hashlib.sha256(out_path.read_bytes()).hexdigest()
    assert info.hashed_hex == gercek


def test_export_sealed_pdf_writes_sealed_text(
    rapor_saglam, tmp_path: Path,
) -> None:
    out_path, info = export_sealed_pdf(
        [_satir()], rapor_saglam, tmp_path / "r.pdf", transport=FakeTSA(),
    )
    assert info is not None
    assert b"verify_report_seal_cli.py" in out_path.read_bytes()


# ══════════════════════════════════════════════════════════════════════════════
# 4. export_sealed_pdf() — TSA başarısız → dürüst geri dönüş
# ══════════════════════════════════════════════════════════════════════════════


def test_export_sealed_pdf_falls_back_to_unsealed_on_tsa_failure(
    rapor_saglam, tmp_path: Path,
) -> None:
    out_path, info = export_sealed_pdf(
        [_satir()], rapor_saglam, tmp_path / "r.pdf",
        transport=_hata_veren_transport,
    )
    assert info is None, "TSA basarisizken bir TimestampInfo dondurulmemeli"
    raw = out_path.read_bytes()
    assert b"KANITLAMAZ" in raw, "basarisizlikta metin MUHURSUZ'e donmemis"
    assert b"verify_report_seal_cli.py" not in raw, (
        "basarisiz muhur icin dogrulama-arac referansi kalmis — yanlis iddia"
    )


def test_export_sealed_pdf_writes_no_tsr_on_failure(
    rapor_saglam, tmp_path: Path,
) -> None:
    out_path, _info = export_sealed_pdf(
        [_satir()], rapor_saglam, tmp_path / "r.pdf",
        transport=_hata_veren_transport,
    )
    assert not tsr_path_for(out_path).exists()


# ══════════════════════════════════════════════════════════════════════════════
# 5. Bağımsız doğrulama — CORE/verify_report_seal_cli.py (verify_timestamp_
#    cli.py'nin eşdeğeri, ama vault anahtarı/DB gerektirmiyor)
# ══════════════════════════════════════════════════════════════════════════════


def test_cli_verifies_with_an_explicit_trusted_root(
    rapor_saglam, tmp_path: Path, capsys: pytest.CaptureFixture,
) -> None:
    authority = default_authority()
    out_path, info = export_sealed_pdf(
        [_satir()], rapor_saglam, tmp_path / "r.pdf",
        transport=FakeTSA(authority=authority),
    )
    assert info is not None
    ca = tmp_path / "ca.der"
    ca.write_bytes(authority.ca_der)

    kod = cli_main(["--pdf", str(out_path), "--trusted-root", str(ca)])
    cikti = capsys.readouterr().out
    assert kod == 0
    assert "GECERLI" in cikti
    assert "GUVENILIR" in cikti


def test_cli_default_root_is_ENFORCED_not_merely_advisory(
    rapor_saglam, tmp_path: Path, capsys: pytest.CaptureFixture,
) -> None:
    """
    FakeTSA'nın test CA'sı GERÇEK freetsa.org köküyle eşleşmez. CLI
    --trusted-root VERİLMEDİĞİNDE HİÇBİR köksüz kalmıyor — varsayılan
    olarak gömülü (gerçek) kökü kullanıyor, ve `trusted_roots` VERİLDİĞİNDE
    eşleşmeyen kök `verify_timestamp_cli.py`/B-105'teki AYNI kuralla
    GEÇERSİZ üretir (yalnızca "doğrulanmadı" değil) — bu CLI köksüz bir
    "uyarılı geçerli" DURUMUNA hiç düşmüyor, çünkü varsayılanı boş değil.
    """
    out_path, info = export_sealed_pdf(
        [_satir()], rapor_saglam, tmp_path / "r.pdf", transport=FakeTSA(),
    )
    assert info is not None

    kod = cli_main(["--pdf", str(out_path)])  # --trusted-root YOK
    cikti = capsys.readouterr().out
    assert kod == 1, "varsayilan gomulu kok yanlis TSA'yi GECERSIZ saymali"
    assert "GECERSIZ" in cikti


def test_cli_uses_the_embedded_root_by_default(
    rapor_saglam, tmp_path: Path, capsys: pytest.CaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """B-105'in vaat ettiği asıl bağlantı: --trusted-root VERİLMEDİĞİNDE
    araç GERÇEKTEN `gomulu_kokler()`'e bakıyor mu — gerçek freetsa.org
    kökü test ortamında eşleşmeyeceği için burayı test CA'nın kökünü
    "gömülü" gibi göstererek ölçüyoruz."""
    import CORE.verify_report_seal_cli as cli_mod

    authority = default_authority()
    monkeypatch.setattr(cli_mod, "gomulu_kokler", lambda: [authority.ca_der])

    out_path, info = export_sealed_pdf(
        [_satir()], rapor_saglam, tmp_path / "r.pdf",
        transport=FakeTSA(authority=authority),
    )
    assert info is not None

    kod = cli_main(["--pdf", str(out_path)])
    cikti = capsys.readouterr().out
    assert kod == 0
    assert "GUVENILIR" in cikti, "varsayilan kok gomulu_kokler()'den gelmiyor"


def test_cli_detects_tampered_pdf(
    rapor_saglam, tmp_path: Path, capsys: pytest.CaptureFixture,
) -> None:
    authority = default_authority()
    out_path, info = export_sealed_pdf(
        [_satir()], rapor_saglam, tmp_path / "r.pdf",
        transport=FakeTSA(authority=authority),
    )
    assert info is not None
    ca = tmp_path / "ca.der"
    ca.write_bytes(authority.ca_der)

    with out_path.open("ab") as f:
        f.write(b"\x00KURCALANDI")

    kod = cli_main(["--pdf", str(out_path), "--trusted-root", str(ca)])
    cikti = capsys.readouterr().out
    assert kod == 1
    assert "GECERSIZ" in cikti


def test_cli_missing_token_file(
    rapor_saglam, tmp_path: Path,
) -> None:
    out = export_pdf([_satir()], rapor_saglam, tmp_path / "r.pdf", sealed=True)
    assert cli_main(["--pdf", str(out)]) == 1  # .tsr hiç yazılmadı


def test_cli_missing_pdf(tmp_path: Path) -> None:
    assert cli_main(["--pdf", str(tmp_path / "yok.pdf")]) == 1


def test_cli_default_token_path_is_the_dot_tsr_sibling(
    rapor_saglam, tmp_path: Path, capsys: pytest.CaptureFixture,
) -> None:
    authority = default_authority()
    ca = tmp_path / "ca.der"
    ca.write_bytes(authority.ca_der)
    out_path, info = export_sealed_pdf(
        [_satir()], rapor_saglam, tmp_path / "r.pdf",
        transport=FakeTSA(authority=authority),
    )
    assert info is not None
    # --token VERİLMEDİ — `tsr_path_for()`'un varsayılanına güveniyor.
    assert cli_main(["--pdf", str(out_path), "--trusted-root", str(ca)]) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 6. Yapısal — ikinci bir TSA-istemci implementasyonu açılmadı
# ══════════════════════════════════════════════════════════════════════════════


def _ast_of(dosya: str) -> ast.Module:
    return ast.parse((KOK / dosya).read_text(encoding="utf-8"))


def _importlar(agac: ast.Module) -> set[str]:
    isimler: set[str] = set()
    for d in ast.walk(agac):
        if isinstance(d, ast.Import):
            isimler.update(t.name.split(".")[0] for t in d.names)
        elif isinstance(d, ast.ImportFrom) and d.module:
            isimler.add(d.module.split(".")[0])
    return isimler


def test_audit_report_does_not_import_requests_directly() -> None:
    """
    Ham HTTP çağrısı yalnızca `CORE/timestamp.py::_http_post()`'ta —
    `export_sealed_pdf()` `request_token()` ÜZERİNDEN geçmeli, kendi
    ağ istemcisini AÇMAMALI.
    """
    assert "requests" not in _importlar(_ast_of("CORE/audit_report.py"))


def test_verify_report_seal_cli_does_not_import_requests() -> None:
    """Doğrulama ağa hiç çıkmıyor — token dosyadan okunuyor."""
    assert "requests" not in _importlar(_ast_of("CORE/verify_report_seal_cli.py"))


def test_export_sealed_pdf_calls_request_token() -> None:
    """`export_sealed_pdf()` TEK TSA-istemci gövdesini (`CORE.timestamp.
    request_token`) çağırıyor mu — `build_request`/`_http_post`'u
    DOĞRUDAN çağırmıyor mu (ikinci implementasyonun yapısal kanıtı)."""
    agac = _ast_of("CORE/audit_report.py")
    cagrilar = {
        (d.func.attr if isinstance(d.func, ast.Attribute) else
         d.func.id if isinstance(d.func, ast.Name) else "")
        for d in ast.walk(agac) if isinstance(d, ast.Call)
    }
    assert "request_token" in cagrilar
    assert "build_request" not in cagrilar
    assert "_http_post" not in cagrilar


def test_selftest_listesinde() -> None:
    kaynak = (KOK / "main.py").read_text(encoding="utf-8")
    assert '"CORE.verify_report_seal_cli"' in kaynak


def test_the_script_runs_as_a_real_process(
    rapor_saglam, tmp_path: Path,
) -> None:
    """`python CORE/verify_report_seal_cli.py ...` gerçekten çalışıyor mu
    — `main()`'i doğrudan çağırmak sys.path bootstrap'ını ve `__main__`
    bloğunu atlar; araç asıl bu şekilde kullanılacak (`tests/test_verify_
    timestamp_cli.py::test_the_script_runs_as_a_real_process` ile AYNI
    desen)."""
    authority = default_authority()
    out_path, info = export_sealed_pdf(
        [_satir()], rapor_saglam, tmp_path / "r.pdf",
        transport=FakeTSA(authority=authority),
    )
    assert info is not None
    ca = tmp_path / "ca.der"
    ca.write_bytes(authority.ca_der)
    script = KOK / "CORE" / "verify_report_seal_cli.py"

    sonuc = subprocess.run(
        [sys.executable, str(script), "--pdf", str(out_path),
         "--trusted-root", str(ca), "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert sonuc.returncode == 0, sonuc.stderr
    assert "GE" in sonuc.stdout  # GECERLI


# ══════════════════════════════════════════════════════════════════════════════
# 7. Kontrol — verify_token() gerçekten çağrılıyor, boş liste kör değil
# ══════════════════════════════════════════════════════════════════════════════


def test_the_embedded_root_really_matches_the_real_default_tsa() -> None:
    """B-105'in gömülü kökü ile K4-20'nin `export_sealed_pdf()`'in
    HER ZAMAN kullandığı `DEFAULT_TSA_URL` (freetsa.org) AYNI otorite mi
    — sabit değer testi değil, `verify_token()`'ın GERÇEK doğrulama
    yolundan geçerek: gerçek freetsa fixture token'ı gömülü köke karşı
    doğrulanabiliyor mu."""
    from asn1crypto import tsp

    fixture = KOK / "tests" / "data" / "freetsa_response.der"
    token_der = tsp.TimeStampResp.load(fixture.read_bytes())[
        "time_stamp_token"
    ].dump()
    token = tsp.TimeStampResp.load(fixture.read_bytes())["time_stamp_token"]
    imprint = bytes(
        token["content"]["encap_content_info"]["content"].parsed[
            "message_imprint"
        ]["hashed_message"].native
    )
    sonuc = verify_token(token_der, expected_digest=imprint, trusted_roots=gomulu_kokler())
    assert sonuc.valid is True
    assert sonuc.anchor_trusted is True
