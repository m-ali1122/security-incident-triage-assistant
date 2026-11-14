"""Small, process-safe-enough disk cache for LLM completions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


def _normalise(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def cache_key(user: str, system: str, facts_hash: str = "", prompt_version: str = "") -> str:
    payload = "\x1f".join(
        (_normalise(user), _normalise(system), _normalise(facts_hash), _normalise(prompt_version))
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class DiskCache:
    def __init__(self, directory: str | os.PathLike[str] | None = None) -> None:
        self.directory = Path(directory) if directory is not None else None
        self.hits = 0
        self.misses = 0

    def _path(self, key: str) -> Path:
        directory = self.directory or Path(os.getenv("TRIAGE_CACHE_DIR", ".cache/llm"))
        return directory / f"{key}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        try:
            with self._path(key).open("r", encoding="utf-8") as handle:
                value = json.load(handle)
            if isinstance(value, dict) and isinstance(value.get("text"), str):
                self.hits += 1
                return value
        except (OSError, ValueError, TypeError):
            pass
        self.misses += 1
        return None

    def put(self, key: str, value: dict[str, Any]) -> None:
        target = self._path(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{key}.", suffix=".tmp", dir=target.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, separators=(",", ":"), ensure_ascii=False)
            os.replace(temporary, target)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
