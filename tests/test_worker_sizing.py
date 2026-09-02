"""
CORE.worker_sizing — düşük RAM'de toplu dosya-ekleme işçi sayısının küçülmesi.

İki ayrı iddia sınanıyor:
  1. `recommended_thread_count()` saf bir fonksiyon — RAM miktarı ne
     olursa olsun DOĞRU sayıyı hesaplıyor (`available_bytes` enjekte
     edilerek, gerçek bir bellek darlığı YARATMADAN).
  2. GERÇEK bir toplu şifrelemede (`psutil.Process().memory_info()`)
     bellek kullanımı, verinin TAMAMINI belleğe almadığımızı kanıtlayan
     bir tavanın ALTINDA kalıyor — CORE/crypto.py'nin 64 KB'lık akış
     tamponunun, iş parçacığı sayısı ne olursa olsun, GERÇEKTEN
     korunduğunu ölçüyor.
"""
from __future__ import annotations

import gc
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from CORE import worker_sizing
from CORE.crypto import encrypt_file, generate_key
from CORE.worker_sizing import DEFAULT_MAX_WORKERS, recommended_thread_count

psutil = pytest.importorskip("psutil", reason="requirements.txt: psutil>=7.0")

_MB = 1024 * 1024


# ══════════════════════════════════════════════════════════════════════════════
# 1. Saf hesap — enjekte edilen available_bytes
# ══════════════════════════════════════════════════════════════════════════════


def test_abundant_ram_keeps_the_default_worker_count() -> None:
    """RAM bol olduğunda davranış AYNI kalmalı — bugünkü sabit 6."""
    assert recommended_thread_count(available_bytes=16 * 1024 * _MB) == DEFAULT_MAX_WORKERS


def test_low_ram_shrinks_the_worker_count() -> None:
    """ASIL TEST — düşük RAM'de işçi sayısı GERÇEKTEN küçülüyor."""
    # 200 MB kullanılabilir × %50 tavan / 50 MB işçi bütçesi = 2 işçi.
    n = recommended_thread_count(available_bytes=200 * _MB)
    assert n < DEFAULT_MAX_WORKERS
    assert n == 2


def test_the_shrink_is_proportional_to_available_ram() -> None:
    """Daha az RAM → daha az (asla daha fazla) işçi — monoton olmalı."""
    cok_dusuk = recommended_thread_count(available_bytes=100 * _MB)
    orta = recommended_thread_count(available_bytes=500 * _MB)
    bol = recommended_thread_count(available_bytes=8 * 1024 * _MB)
    assert cok_dusuk <= orta <= bol


def test_worker_count_never_goes_below_min_count() -> None:
    """RAM ne kadar az olursa olsun en az BİR dosya işlenebilmeli."""
    assert recommended_thread_count(available_bytes=1) == 1
    assert recommended_thread_count(available_bytes=1, min_count=2) == 2


def test_worker_count_never_exceeds_max_count() -> None:
    """Astronomik RAM bile tavanı (`max_count`) aşmamalı."""
    devasa = 10 * 1024 * 1024 * _MB  # 10 PB
    assert recommended_thread_count(available_bytes=devasa) == DEFAULT_MAX_WORKERS
    assert recommended_thread_count(available_bytes=devasa, max_count=3) == 3


def test_psutil_failure_falls_back_to_the_fixed_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    `psutil` erişilemezse (bkz. modül docstring'i) sessizce max_count'a
    düşülmeli — bu bir güvenlik kontrolü değil, dünkü davranışa dönüş.
    """
    def _patla() -> int:
        raise OSError("bellek bilgisi okunamadı")

    monkeypatch.setattr(worker_sizing, "_kullanilabilir_ram_bytes", _patla)
    assert recommended_thread_count() == DEFAULT_MAX_WORKERS


# ══════════════════════════════════════════════════════════════════════════════
# 2. Gerçek toplu yükleme — ölçülen bellek kullanımı
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture(autouse=True)
def _izole(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from CORE import crypto
    q = tmp_path / "quarantine"
    q.mkdir()
    monkeypatch.setattr(crypto, "_QUARANTINE_DIR", q)


def _buyuk_dosyalar(tmp_path: Path, adet: int, boyut_mb: int) -> list[Path]:
    """`adet` tane `boyut_mb` MB'lık dosya üretir — sıfır değil, sıkışmaz."""
    yollar = []
    for i in range(adet):
        p = tmp_path / f"buyuk_{i}.bin"
        with open(p, "wb") as f:
            for _ in range(boyut_mb):
                f.write(os.urandom(_MB))
        yollar.append(p)
    return yollar


def test_a_large_batch_upload_stays_within_the_memory_ceiling(tmp_path: Path) -> None:
    """
    ASIL TEST — gerçek toplu yüklemede ölçülen bellek, toplam veri
    boyutunun ÇOK altında kalmalı; aksi hâlde `_FileRunnable` her
    dosyayı tamamen belleğe alıyor demektir.
    """
    ADET, BOYUT_MB = 6, 20
    dosyalar = _buyuk_dosyalar(tmp_path, ADET, BOYUT_MB)
    toplam_veri = ADET * BOYUT_MB * _MB
    key = generate_key()

    proc = psutil.Process()
    gc.collect()
    once = proc.memory_info().rss

    def _sifrele(p: Path) -> None:
        encrypt_file(p, key, user_id=1)

    with ThreadPoolExecutor(max_workers=recommended_thread_count()) as havuz:
        list(havuz.map(_sifrele, dosyalar))

    gc.collect()
    sonra = proc.memory_info().rss
    buyume = max(0, sonra - once)

    # Cömert bir tavan: toplam verinin dörtte biri. Akan (64 KB'lık
    # bloklarla) şifrelemede gerçek büyüme birkaç MB'ı geçmiyor —
    # tavan bunun onlarca katı, gürültülü CI koşucularında yanlış
    # alarm vermesin diye.
    tavan = toplam_veri // 4
    assert buyume < tavan, (
        f"Bellek büyümesi {buyume / _MB:.1f} MB, tavan {tavan / _MB:.1f} MB "
        f"(toplam veri {toplam_veri / _MB:.1f} MB) — dosyalar akmıyor, "
        "tamamen belleğe alınıyor olabilir."
    )


def test_a_simulated_low_ram_environment_actually_uses_fewer_workers(tmp_path: Path) -> None:
    """
    Düşük-RAM ortamı simüle edilip işçi sayısının GERÇEKTEN küçüldüğü
    ve o küçük havuzla bir toplu işlemin sorunsuz tamamlandığı ölçülüyor.
    """
    bol_ram = recommended_thread_count(available_bytes=8 * 1024 * _MB)
    dusuk_ram = recommended_thread_count(available_bytes=150 * _MB)
    assert dusuk_ram < bol_ram

    dosyalar = _buyuk_dosyalar(tmp_path, adet=dusuk_ram + 1, boyut_mb=2)
    key = generate_key()

    def _sifrele(p: Path) -> tuple:
        return encrypt_file(p, key, user_id=1)

    with ThreadPoolExecutor(max_workers=dusuk_ram) as havuz:
        sonuclar = list(havuz.map(_sifrele, dosyalar))

    assert len(sonuclar) == len(dosyalar)
    assert all(dst.is_file() for dst, _sha, _aad in sonuclar)
