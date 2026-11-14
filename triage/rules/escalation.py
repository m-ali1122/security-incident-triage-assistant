"""P7: escalation contacts from the escalation sheet (04)."""
from __future__ import annotations

from typing import Any

from triage.models import Incident


def escalation(severity: str, incident: Incident) -> list[Any]:
    """Every escalation row for `severity`; Legal only if finance, HR or customer data may be involved."""
    raise NotImplementedError("P7")
