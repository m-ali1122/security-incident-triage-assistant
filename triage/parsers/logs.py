"""P1: profile-driven log parsers (files 11-16, 19)."""
from __future__ import annotations

from pathlib import Path
from typing import Union

from triage.models import Event


def parse_all(data_dir: Union[str, Path]) -> list[Event]:
    """Parse every profiled log under data_dir into Event records (UTC times, file and line)."""
    raise NotImplementedError("P1")
