"""HYCLEUS — Merkezi data dizini çözümleyici.

PyInstaller EXE olarak çalışırken __file__ geçici extraction dizinine işaret eder.
Bu modül her iki ortamda da doğru data/ yolunu döndürür.
"""
from __future__ import annotations

import sys
from pathlib import Path


def data_dir() -> Path:
    """data/ klasörünün mutlak yolunu döndürür.

    - EXE (sys.frozen): EXE'nin yanındaki data/ klasörü
    - Geliştirme:       proje kökündeki data/ klasörü
    """
    if hasattr(sys, "frozen"):
        return Path(sys.executable).parent / "data"
    return Path(__file__).parent.parent / "data"
