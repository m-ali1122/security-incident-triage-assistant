"""P6: evidence graph construction (networkx.MultiDiGraph)."""
from __future__ import annotations

from typing import Any

from triage.models import Event

Graph = Any  # networkx.MultiDiGraph wrapper, defined by P6


def build_graph(events: list[Event], tables: Any) -> Graph:
    """Build nodes, identity links (with validity windows) and activity edges."""
    raise NotImplementedError("P6")
