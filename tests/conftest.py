"""Pytest configuration and fixtures."""

import sys
from pathlib import Path

# Ensure src is on path for tests
root = Path(__file__).resolve().parent.parent
src = root / "src"
if str(src) not in sys.path:
    sys.path.insert(0, str(src))
