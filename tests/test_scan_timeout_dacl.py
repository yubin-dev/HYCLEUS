"""
2026-08-30 — `run_tool()`'un geçici stdout/stderr dosyalarının Windows
DACL'i gerçekten yalnızca mevcut kullanıcıya (+ SYSTEM'e) mı kısıtlanıyor,
testi.

Önceki turun denetimi (bkz. SECURITY.md §4.22, "geçici dosya güvenliği"
alt bölümü) dört başlıktan üçünün ("oluşturma API'si", "eşzamanlılık",
"süpürme yarış durumu") risk taşımadığını ama DÖRDÜNCÜSÜNÜN — dosya
izinleri — gerçek bir risk taşıdığını ölçtü: `tempfile.mkstemp()`'in
ürettiği dosya `%TEMP%`'in ACL'ini olduğu gibi devralıyordu ve bu ölçülen
ortamda yalnızca çalıştıran kullanıcıyla SINIRLI DEĞİLDİ (bir grup ve
çözülmemiş bir SID de erişime sahipti).

Bu test iki katmanda doğruluyor:

  1. `_gecici_dosyayi_kullaniciya_kisitla()`'nın KENDİSİ, gerçek bir dosya
     üzerinde, gerçek Windows API'siyle (`win32security.GetFileSecurity`)
     sorgulanan DACL'in TAM OLARAK {mevcut kullanıcı, SYSTEM} içerdiğini
     — önceki turun denetim yöntemiyle AYNI şekilde.
  2. `run_tool()`'un bu fonksiyonu GERÇEKTEN çağırdığını (her iki geçici
     dosya için de) — yalnızca yardımcı fonksiyonun kendisi doğru
     olması yetmez, `run_tool()`'un onu unutmadığını da ayrı doğrulamak
     gerekiyor.
"""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

from CORE import scanner_backends as sb

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="DACL sertleştirmesi Windows'a özgü — bkz. modül docstring'i",
)

win32security = pytest.importorskip(
    "win32security", reason="requirements.txt: wmi -> pywin32 (yalnızca Windows)"
)
win32api = pytest.importorskip("win32api")
win32con = pytest.importorskip("win32con")


def _dosyanin_sidleri(yol: str) -> set[str]:
    sd = win32security.GetFileSecurity(yol, win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    sidler = set()
    for i in range(dacl.GetAceCount()):
        ace = dacl.GetAce(i)
        sidler.add(win32security.ConvertSidToStringSid(ace[2]))
    return sidler


def _mevcut_kullanici_ve_system_sid() -> tuple[str, str]:
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    kullanici_sid, _ = win32security.GetTokenInformation(token, win32security.TokenUser)
    system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
    return (
        win32security.ConvertSidToStringSid(kullanici_sid),
        win32security.ConvertSidToStringSid(system_sid),
    )


def test_gecici_dosyayi_kullaniciya_kisitla_DACLi_yalnizca_kullanici_ve_systeme_daraltiyor(
    tmp_path,
):
    """
    Birim testi — asıl ölçüm: kısıtlamadan SONRA dosyanın gerçek DACL'i
    (Windows API'siyle sorgulanan) TAM OLARAK {mevcut kullanıcı, SYSTEM}
    olmalı — ne eksik (erişim kaybı, tarama çıktısını okuyamama) ne fazla
    (bir grup/başka bir hesabın hâlâ erişimi olması).
    """
    fd, yol = tempfile.mkstemp(prefix=f"{sb._GECICI_ONEK}dacl_test_", dir=str(tmp_path))
    os.close(fd)

    sb._gecici_dosyayi_kullaniciya_kisitla(yol)

    beklenen_kullanici, beklenen_system = _mevcut_kullanici_ve_system_sid()
    bulunan = _dosyanin_sidleri(yol)

    assert bulunan == {beklenen_kullanici, beklenen_system}, (
        f"DACL beklenenden farklı — bulunan SID'ler: {bulunan}, "
        f"beklenen: {{kullanıcı={beklenen_kullanici}, SYSTEM={beklenen_system}}}"
    )


def test_run_tool_HER_IKI_gecici_dosya_icin_de_DACL_kisitlamasini_cagiriyor(monkeypatch):
    """
    Entegrasyon testi — yardımcı fonksiyonun kendisi doğru olması
    yetmiyor: `run_tool()`'un onu GERÇEKTEN çağırdığını, hem stdout hem
    stderr dosyası için, ayrıca doğrulamak gerekiyor. Bir regresyon
    (çağrının run_tool()'dan silinmesi) yalnızca bu testle yakalanır —
    yukarıdaki birim testi `_gecici_dosyayi_kullaniciya_kisitla()`'yı
    DOĞRUDAN çağırdığı için böyle bir regresyonu göremez.
    """
    cagrilan_yollar: list[str] = []

    def sahte_kisitla(yol: str) -> None:
        cagrilan_yollar.append(yol)

    monkeypatch.setattr(sb, "_gecici_dosyayi_kullaniciya_kisitla", sahte_kisitla)

    sb.run_tool(["cmd", "/c", "echo merhaba"], timeout=5)

    assert len(cagrilan_yollar) == 2, (
        f"DACL kısıtlaması TAM OLARAK iki dosya (stdout+stderr) için "
        f"çağrılmalıydı, {len(cagrilan_yollar)} kez çağrıldı: {cagrilan_yollar}"
    )
    assert any("out" in yol for yol in cagrilan_yollar)
    assert any("err" in yol for yol in cagrilan_yollar)


def test_gecici_dosyayi_kullaniciya_kisitla_hata_durumunda_taramayi_DUSURMUYOR(monkeypatch):
    """
    Sertleştirme adımı BEST EFFORT olmalı: `SetFileSecurity` başarısız
    olsa bile (izin sorunu, pywin32 kurulumu bozuk, ...) tarama akışı
    kesilmemeli — dosya `%TEMP%`'in devrettiği (değişiklikten ÖNCEKİ)
    ACL'iyle kalır, bu bir gerileme değil.
    """
    def patlayan_setfilesecurity(*args, **kwargs):
        raise OSError("yapay hata — izin reddedildi")

    import win32security as gercek_win32security

    monkeypatch.setattr(gercek_win32security, "SetFileSecurity", patlayan_setfilesecurity)

    sonuc = sb.run_tool(["cmd", "/c", "echo hata-yolunda-bile-calisiyor"], timeout=5)
    assert sonuc.returncode == 0
    assert "hata-yolunda-bile-calisiyor" in sonuc.stdout
