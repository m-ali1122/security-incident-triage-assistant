"""P7: severity lookup from the matrix (03) with a step-by-step trace."""
from __future__ import annotations

from triage.models import Incident


def severity(incident: Incident) -> tuple[str, list[str]]:
    """Return (severity such as 'P1', numbered reasoning steps). No model decides this."""
    raise NotImplementedError("P7")
