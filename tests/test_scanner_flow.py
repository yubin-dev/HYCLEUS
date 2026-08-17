"""
`CORE/scanner.py` — motordan bağımsız tarama akışı.

Arka uçların kendi testleri `test_scanner_backends.py`'de. Burada ölçülen,
akışın arka uçtan gelen bilgiyi KAYBETMEDEN veritabanına taşıyıp
taşımadığı: karantina JSON'undaki `source`/`threat` ve denetim zincirindeki
eylem adı. Bu alanlar yanlışsa hata sessizdir — kayıt yine yazılır, sadece
başka bir motorun adıyla.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from CORE import scanner, scanner_backends as sb
from CORE.audit_chain import verify_audit_chain
from CORE.scanner_backends import ScanResult, clean_result, malicious_result, mock_result


@pytest.fixture(autouse=True)
def _onbellek_temiz():
    sb.reset_backend_cache()
    yield
    sb.reset_backend_cache()


class SahteArkaUc:
    """Testin tam olarak ne döndüreceğini söylediği arka uç."""

    def __init__(self, ad: str, audit_action: str, sonuc: ScanResult | None) -> None:
        self.ad = ad
        self.audit_action = audit_action
        self._sonuc = sonuc
        self.cagrilar: list[tuple[Path, str]] = []

    def available(self) -> bool:
        return self._sonuc is not None

    def scan(self, path: Path, sha256: str) -> ScanResult | None:
        self.cagrilar.append((path, sha256))
        return self._sonuc


@pytest.fixture
def arka_uc(monkeypatch):
    def kur(sonuc, ad="clamav", audit_action="clamav_scan"):
        sahte = SahteArkaUc(ad, audit_action, sonuc)
        monkeypatch.setattr(scanner, "select_backend", lambda: sahte)
        return sahte
    return kur


def _dosya(tmp_path: Path, icerik: bytes = b"merhaba") -> Path:
    yol = tmp_path / "ornek.hcl"
    yol.write_bytes(icerik)
    return yol


def _kayit(db, file_id: int) -> int:
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label, size_bytes)"
        " VALUES (?, ?, 'Genel', 10)",
        (f"f{file_id}.hcl", f"/vault/f{file_id}.hcl"),
    )
    return int(cur.lastrowid)


# ── Arka uca devir ────────────────────────────────────────────────────────────

def test_scan_file_arka_ucun_sonucunu_geciriyor(tmp_path, arka_uc):
    arka_uc(malicious_result("x" * 64, "clamav", "Eicar-Test-Signature"))
    sonuc = scanner.scan_file(_dosya(tmp_path))
    assert sonuc.verdict == "malicious"
    assert sonuc.engine == "clamav"
    assert sonuc.threat == "Eicar-Test-Signature"


def test_arka_uca_dosyanin_GERCEK_hashi_veriliyor(tmp_path, arka_uc):
    import hashlib

    icerik = b"HYCLEUS"
    sahte = arka_uc(clean_result("x" * 64, "clamav"))
    scanner.scan_file(_dosya(tmp_path, icerik))
    assert sahte.cagrilar[0][1] == hashlib.sha256(icerik).hexdigest()


def test_arka_uc_None_donunce_mock_ve_motor_adi_korunuyor(tmp_path, arka_uc):
    """
    Tarama yapılamadığında sonuç "unknown" olmalı — "clean" DEĞİL — ama
    hangi motorun denendiği bilgisi kaybolmamalı.
    """
    arka_uc(None, ad="clamav")
    sonuc = scanner.scan_file(_dosya(tmp_path))
    assert (sonuc.verdict, sonuc.mock, sonuc.engine) == ("unknown", True, "clamav")


def test_arka_uca_MUTLAK_yol_veriliyor(tmp_path, arka_uc, monkeypatch):
    """
    Göreli bir yol `-` ile başlasaydı clamscan onu seçenek sanabilirdi.
    Mutlak yol her zaman ayırıcıyla başlar.
    """
    sahte = arka_uc(clean_result("x" * 64, "clamav"))
    hedef = _dosya(tmp_path)
    monkeypatch.chdir(tmp_path)
    scanner.scan_file(Path(hedef.name))
    assert sahte.cagrilar[0][0].is_absolute()


# ── Veritabanına yazma ────────────────────────────────────────────────────────

def test_karantina_kaydi_motoru_ve_imzayi_saklıyor(db, tmp_path, arka_uc):
    arka_uc(malicious_result("x" * 64, "clamav", "Win.Test.EICAR_HDB-1"))
    fid = _kayit(db, 1)

    scanner.scan_file(_dosya(tmp_path), file_id=fid)

    satir = db.execute("SELECT reason FROM quarantine WHERE file_id = ?", (fid,)).fetchone()
    assert satir is not None
    kayit = json.loads(satir["reason"])
    assert kayit["source"] == "clamav"
    assert kayit["verdict"] == "malicious"
    assert kayit["threat"] == "Win.Test.EICAR_HDB-1"
    assert kayit["mock"] is False


def test_windows_kaydinin_source_alani_DEGISMEDI(db, tmp_path, arka_uc):
    """
    Defender tarafında hiçbir alan değişmemeli: eski kayıtlar
    `"source": "windows_defender"` taşıyor ve yenileri de öyle taşımalı,
    yoksa karantina geçmişi iki farklı adla ikiye bölünür.
    """
    arka_uc(clean_result("x" * 64, "windows_defender"),
            ad="windows_defender", audit_action="defender_scan")
    fid = _kayit(db, 2)

    scanner.scan_file(_dosya(tmp_path), file_id=fid)

    kayit = json.loads(
        db.execute("SELECT reason FROM quarantine WHERE file_id = ?", (fid,)).fetchone()["reason"]
    )
    assert kayit["source"] == "windows_defender"


def test_denetim_eylemi_arka_uctan_geliyor(db, tmp_path, arka_uc):
    """Bir ClamAV bulgusunu `defender_scan` diye kaydetmek yanlış olurdu."""
    arka_uc(clean_result("x" * 64, "clamav"))
    fid = _kayit(db, 3)

    scanner.scan_file(_dosya(tmp_path), file_id=fid)

    eylemler = [r["action"] for r in db.execute(
        "SELECT action FROM audit_log WHERE target_id = ? AND target_type = 'file'", (fid,)
    ).fetchall()]
    assert eylemler == ["clamav_scan"]


def test_denetim_kaydi_zinciri_bozmuyor(db, tmp_path, arka_uc):
    """`append_entry` kullanılıyor — düz INSERT zincirde delik bırakırdı."""
    arka_uc(malicious_result("x" * 64, "clamav", "Eicar-Test-Signature"))
    fid = _kayit(db, 4)

    scanner.scan_file(_dosya(tmp_path), file_id=fid)

    assert verify_audit_chain(db).ok


def test_ikinci_tarama_karantina_satirini_GUNCELLIYOR(db, tmp_path, arka_uc, monkeypatch):
    fid = _kayit(db, 5)
    arka_uc(clean_result("x" * 64, "clamav"))
    scanner.scan_file(_dosya(tmp_path), file_id=fid)
    arka_uc(malicious_result("x" * 64, "clamav", "Eicar-Test-Signature"))
    scanner.scan_file(_dosya(tmp_path), file_id=fid)

    satirlar = db.execute(
        "SELECT reason FROM quarantine WHERE file_id = ?", (fid,)
    ).fetchall()
    assert len(satirlar) == 1
    assert json.loads(satirlar[0]["reason"])["verdict"] == "malicious"


def test_db_hatasi_taramayi_dusurmuyor(tmp_path, arka_uc, monkeypatch):
    """Veritabanı yazılamasa bile çağıran bir ScanResult almalı."""
    arka_uc(clean_result("x" * 64, "clamav"))

    def patla(*a, **kw):
        raise RuntimeError("db kapalı")

    monkeypatch.setattr(scanner, "_save_to_db", patla)
    sonuc = scanner.scan_file(_dosya(tmp_path), file_id=99)
    assert sonuc.verdict == "clean"


# ── scan_by_hash ──────────────────────────────────────────────────────────────

def test_scan_by_hash_mock_ama_motoru_adlandiriyor(arka_uc):
    arka_uc(clean_result("x" * 64, "clamav"))
    sonuc = scanner.scan_by_hash("b" * 64)
    assert (sonuc.mock, sonuc.verdict, sonuc.engine) == (True, "unknown", "clamav")
    assert sonuc.sha256 == "b" * 64


# ── ScanResult sözleşmesi ─────────────────────────────────────────────────────

def test_yeni_alanlar_varsayilanli():
    """
    `engine`/`threat` sonradan eklendi. Varsayılansız eklenselerdi mevcut
    her `ScanResult(...)` çağrısı kırılırdı.
    """
    sonuc = ScanResult(
        sha256="x" * 64, malicious=0, suspicious=0, harmless=1,
        undetected=0, engines_total=1, verdict="clean", mock=False,
    )
    assert sonuc.engine == "mock"
    assert sonuc.threat is None


def test_mock_sonuc_clean_DEGIL():
    """En tehlikeli karışıklık: "taranamadı" ile "temiz" aynı şey değil."""
    assert mock_result("x" * 64).verdict == "unknown"
    assert mock_result("x" * 64).mock is True
    assert clean_result("x" * 64, "clamav").verdict == "clean"
