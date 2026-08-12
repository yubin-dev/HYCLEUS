"""Ortak pytest yapılandırması — proje kökünü sys.path'e ekler.

Uygulama importları (CORE.*, DB.*) HYCLEUS/ dizinini kök kabul eder;
testler tests/ altından çalıştığı için kökü elle eklemek gerekir.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
