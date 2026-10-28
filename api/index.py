"""Vercel entry point for the SentinelX FastAPI service."""
from pathlib import Path
import sys

# The application package lives in src/ in this repository.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sentinelx.api import app  # noqa: E402
