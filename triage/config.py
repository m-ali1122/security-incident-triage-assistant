"""Paths, environment and thresholds. Keys come from .env, never from code."""
from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv is optional at runtime
    load_dotenv = None

REPO_ROOT = Path(__file__).resolve().parent.parent
if load_dotenv is not None:
    load_dotenv(REPO_ROOT / ".env")


def _csv(name: str) -> list[str]:
    return [v.strip() for v in os.getenv(name, "").split(",") if v.strip()]


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


_data = Path(os.getenv("TRIAGE_DATA_DIR", "problem_c_data"))
DATA_DIR = _data if _data.is_absolute() else REPO_ROOT / _data
PACKAGE_DIR = REPO_ROOT / "triage"
PROFILES_DIR = PACKAGE_DIR / "profiles"
RULES_YAML = PACKAGE_DIR / "rules.yaml"
def _path(name: str, default: Path) -> Path:
    raw = os.getenv(name, "").strip()
    return Path(raw) if raw else default


FACTS_PATH = _path("TRIAGE_FACTS_PATH", REPO_ROOT / "facts.json")
CACHE_DIR = _path("TRIAGE_CACHE_DIR", REPO_ROOT / ".cache")

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free")

GEMINI_API_KEYS = _csv("GEMINI_API_KEYS")
GROQ_API_KEYS = _csv("GROQ_API_KEYS")
OPENROUTER_API_KEYS = _csv("OPENROUTER_API_KEYS")

LLM_ENABLED = _flag("LLM_ENABLED", True)
LLM_TIMEOUT_S = _float("LLM_TIMEOUT_S", 20.0)
REQUEST_TIMEOUT_S = _float("REQUEST_TIMEOUT_S", 30.0)
BREAKER_OPEN_S = _float("BREAKER_OPEN_S", 60.0)
