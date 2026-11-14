"""P7: runbook action selector (files 06 to 10)."""
from __future__ import annotations

from typing import Any

from triage.models import Incident


def actions(incident: Incident) -> list[Any]:
    """Actions taken only from runbooks, each with runbook ID, step number and concrete values."""
    raise NotImplementedError("P7")
