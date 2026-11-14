"""P6: incident clustering over actor links only."""
from __future__ import annotations

from triage.models import Finding, Incident


def cluster(findings: list[Finding]) -> list[Incident]:
    """Group findings into incidents (connected components over actor links)."""
    raise NotImplementedError("P6")
