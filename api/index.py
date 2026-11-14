"""Vercel entrypoint: exposes the FastAPI app to the Python runtime."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if os.getenv("VERCEL"):
    # Vercel's filesystem is read-only except /tmp.
    os.environ.setdefault("TRIAGE_CACHE_DIR", "/tmp/triage-cache/llm")
    os.environ.setdefault("TRIAGE_FACTS_PATH", "/tmp/facts.json")

from triage.api import app  # noqa: E402

__all__ = ["app"]
