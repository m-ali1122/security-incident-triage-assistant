"""P2: coverage model (file 20): time zone, timestamp meaning, gaps, missing sources."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Union

from triage.models import Gap


def load_coverage() -> Any:
    """Coverage table (file 20) including gaps and non-collected sources."""
    raise NotImplementedError("P2")


def observable(source: str, t_utc: Union[str, datetime]) -> bool:
    """True if `source` was collecting at t_utc (outside any gap, source collected)."""
    raise NotImplementedError("P2")


def gaps_overlapping(from_utc: Union[str, datetime], to_utc: Union[str, datetime]) -> list[Gap]:
    """Gap records whose window overlaps [from_utc, to_utc]."""
    raise NotImplementedError("P2")
