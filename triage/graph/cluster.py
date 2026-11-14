"""P6: incident clustering over actor links only (ARCHITECTURE section 7)."""
from __future__ import annotations

from typing import Callable, Optional

from triage.models import HARMLESS, Finding, Incident

ACTOR = "actor:"
_SEV = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


def actor_keys(f: Finding) -> list:
    return [e for e in f.entities if isinstance(e, str) and e.startswith(ACTOR)]


def _earliest(findings: list, graph=None):
    """Earliest evidence time (needs a graph to map file+line to a time), else '~'."""
    best = None
    if graph is not None:
        idx = {(e.source_file, e.line): e.ts_utc for e in graph.events}
        for f in findings:
            for c in f.evidence:
                t = idx.get((c.file, c.line))
                if t and (best is None or t < best):
                    best = t
    return best or "~"


def _default_key(graph):
    def key(findings: list):
        return (-len(findings), _earliest(findings, graph), min(f.finding_id for f in findings))
    return key


def cluster(findings: list, graph=None, order_key: Optional[Callable] = None) -> list:
    """Connected components over shared actor keys. order_key(list[Finding]) -> sortable."""
    fs = [f for f in findings if f.label != HARMLESS and actor_keys(f)]
    parent = list(range(len(fs)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict = {}
    for i, f in enumerate(fs):
        for k in actor_keys(f):
            if k in owner:
                parent[find(i)] = find(owner[k])
            else:
                owner[k] = i
    groups: dict = {}
    for i, f in enumerate(fs):
        groups.setdefault(find(i), []).append(f)
    comps = list(groups.values())
    comps.sort(key=order_key or _default_key(graph))
    incidents, anoms = [], []
    for comp in comps:
        if all(f.rule == "concurrent_use" for f in comp):
            anoms.append(Incident(incident_id=f"ANOM-{len(anoms) + 1}", findings=comp))
        else:
            incidents.append(Incident(incident_id=f"INC-{len(incidents) + 1}", findings=comp))
    return incidents + anoms


def renumber(incidents: list, graph=None) -> list:
    """Reorder real incidents by severity (P1 first) then earliest time; ANOM-n keep their order."""
    real = [i for i in incidents if not i.incident_id.startswith("ANOM")]
    anoms = [i for i in incidents if i.incident_id.startswith("ANOM")]
    order = {id(i): n for n, i in enumerate(real)}
    real.sort(key=lambda i: (_SEV.get(i.severity or "", 9), _earliest(i.findings, graph), order[id(i)]))
    for n, i in enumerate(real, 1):
        i.incident_id = f"INC-{n}"
    return real + anoms
