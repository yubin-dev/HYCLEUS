"""
2026-08-30 — `run_tool()`'un zaman aşımı yolunda GERÇEK bir Windows
tanıtıcı/thread sızıntısı var mıydı, testi.

Bu, aynı günün `tests/test_scan_timeout_worker_pool.py` bulgusunun DEVAMI:
o test `run_tool()`'un `kill()`+sınırlı `wait()`'inin worker'ı ZAMANINDA
serbest bıraktığını kanıtlıyordu, ama "serbest bırakılan worker'ın ARKASINDA
kalıcı bir kaynak sızıntısı kalıp kalmadığını" HİÇ ölçmüyordu. Burada
ölçülen o.

Neden gerçek bir torun süreç gerekiyor
---------------------------------------
`CORE/scanner_backends.py::run_tool()`'un docstring'inde ayrıntılı anlatıldığı
gibi, sızıntı yalnızca ÖLDÜRÜLEN sürecin KENDİSİ pipe'ı elinde tutuyorsa
oluşmuyor — `kill()` o durumda pipe'ın son elindeki kopyasını da kapatıyor,
CPython'un arka plan okuyucu thread'i EOF'u görüp kendini kapatıyor,
sızıntı YOK. Sızıntı yalnızca bir TORUN süreç pipe'ın yazma ucunu MİRAS
ALIP tutmaya devam ederse oluşuyor — `kill()` yalnızca doğrudan çocuğu
öldürür, torunlara dokunmaz. Bu yüzden sahte/mock bir `Popen` ile ölçülemez;
gerçek bir işletim sistemi süreç ağacı gerekiyor.

`cmd /c "ping -n 9999 127.0.0.1 >nul"` bu ağacı en hafif şekilde kuruyor:
`run_tool()`'un doğrudan yönettiği süreç `cmd.exe`; `cmd.exe` kendi
`ping.exe`'sini KENDİ stdout/stderr'ini (yani `run_tool()`'un pipe'ını)
devrederek başlatıyor. `run_tool()` zaman aşımında `cmd.exe`'yi öldürünce
`ping.exe` YETİM kalıp pipe'ı elinde tutmaya devam ediyor — MpCmdRun.exe'nin
büyük bir arşivde bir yardımcı/alt süreç doğurup pipe'ı ona devretmesiyle
BİREBİR aynı yapı.

Ölçülen sonuç (bu test yazılırken, düzeltmeden ÖNCE — bkz. SECURITY.md
§4.22 ve `run_tool()` docstring'i): 30 tekrar → +153 Windows tanıtıcısı,
+60 thread, ikisi de tekrar sayısıyla BİREBİR ORANTILI. Düzeltmeden SONRA
(gerçek dosyalara yönlendirme, pipe yok): +2 tanıtıcı TOPLAM (orantılı
DEĞİL, tek seferlik), +0 thread.

Neden `psutil`
---------------
Windows'a özgü tanıtıcı sayısı (`num_handles()`) stdlib'de yok. Test bu
yüzden hem platformda hem `psutil` kurulu değilse ATLANIYOR — bkz.
requirements-dev.txt'teki gerekçe.
"""
from __future__ import annotations

import subprocess
import sys
import threading

import pytest

from CORE import scanner_backends as sb

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="sızıntı mekanizması Windows'a özgü (pipe okuyucu thread'leri, "
           "tanıtıcı miras alma) — bkz. modül docstring'i",
)

psutil = pytest.importorskip("psutil", reason="requirements-dev.txt: psutil>=7.0")

#: `cmd.exe`'nin doğurduğu, pipe'ı yetim kalarak elinde tutan `ping.exe`
#: torununu diğer sistem süreçlerinden ayırt etmek için kullanılan işaret.
_PING_ISARETI = "9999"

#: 50-100 arası istendi; CI'da makul sürede kalması için alt uca yakın —
#: sızıntı ORANTILI olduğu için (düzeltme öncesi ~5 tanıtıcı/thread ×
#: tekrar) 60 tekrar bile açık ayrımı görünür kılmaya fazlasıyla yetiyor.
_TEKRAR = 60

_TORUN_PIPE_TUTAN_ARGV = ["cmd", "/c", f"ping -n {_PING_ISARETI} 127.0.0.1 >nul"]


def _yetim_pingleri_temizle() -> int:
    """Testin yetim bıraktığı `ping.exe` torunlarını öldürür. Kaç tanesini
    öldürdüğünü döndürür — testin kendisi bunu doğrulamıyor (öldürülen
    sayı, ölçüme göre değişebilir), yalnızca hijyen için çağrılıyor."""
    n = 0
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmdline = p.info["cmdline"] or []
            if (p.info["name"] or "").lower().startswith("ping") and any(
                _PING_ISARETI in parca for parca in cmdline
            ):
                p.kill()
                n += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return n


def test_run_tool_torun_surec_pipe_tutsa_bile_tanitici_ve_thread_SIZDIRMIYOR():
    """
    Asıl iddia: art arda `_TEKRAR` kez, pipe'ı yetim bir torunun elinde
    tuttuğu bir zaman aşımı tetiklendiğinde, çağıran sürecin Windows
    tanıtıcı sayısı VE thread sayısı tekrar sayısıyla ORANTILI ARTMAMALI.

    Eşikler bilinçli GEVŞEK bırakıldı (`_TEKRAR * 2` tanıtıcı, `+4` thread):
    amaç sıfır toleranslı bir sayı yakalamak değil, düzeltme-öncesi ~5
    tanıtıcı+2 thread/tekrar'lık ORANTILI büyümeyle düzeltme-sonrası
    sabit/yakın-sıfır büyüme ARASINDAKİ AÇIK FARKI ayırt etmek — CI
    koşucusunun kendi arka plan gürültüsü (GC zamanlaması, işletim sistemi
    tanıtıcı önbelleği) birkaç tanıtıcılık oynama üretebilir.
    """
    try:
        proc = psutil.Process()
        baslangic_tanitici = proc.num_handles()
        baslangic_thread = threading.active_count()

        for _ in range(_TEKRAR):
            with pytest.raises(subprocess.TimeoutExpired):
                sb.run_tool(_TORUN_PIPE_TUTAN_ARGV, timeout=0.3)

        bitis_tanitici = proc.num_handles()
        bitis_thread = threading.active_count()

        tanitici_buyume = bitis_tanitici - baslangic_tanitici
        thread_buyume = bitis_thread - baslangic_thread

        assert tanitici_buyume < _TEKRAR * 2, (
            f"tanıtıcı sayısı {_TEKRAR} tekrarda {tanitici_buyume} arttı — "
            f"düzeltme öncesi ORANTILI büyüme (~5×tekrar) geri gelmiş olabilir"
        )
        assert thread_buyume <= 4, (
            f"thread sayısı {_TEKRAR} tekrarda {thread_buyume} arttı — "
            f"pipe okuyucu thread'leri yine sızdırıyor olabilir"
        )
    finally:
        _yetim_pingleri_temizle()
