"""P7: rule engine detectors. Parameters come from triage/rules.yaml."""
from __future__ import annotations

from typing import Any

from triage.models import Event, Finding


def run_rules(graph: Any, events: list[Event], tables: Any, coverage: Any) -> list[Finding]:
    """Run every detector and return Findings with label, evidence and numbered steps."""
    raise NotImplementedError("P7")
