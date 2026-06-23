"""
Pytest configuration for the IR Platform backend test suite.

The application code imports everything as `from app...`, so the `backend/`
directory (which contains the `app/` package) must be on sys.path. Running
`pytest` from the repo root or from `backend/` both work because of this.
"""
import sys
from pathlib import Path

# backend/ is the parent of this tests/ directory.
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
