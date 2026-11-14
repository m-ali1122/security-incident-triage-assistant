"""P6: module-level helpers over a cached EvidenceGraph."""
from __future__ import annotations

from triage.graph.build import Chain, EvidenceGraph, build_graph

_CACHE: dict = {}


def get_graph(data_dir=None) -> EvidenceGraph:
    key = str(data_dir) if data_dir is not None else None
    if key not in _CACHE:
        from triage.parsers.logs import parse_all
        from triage.parsers.tables import load_tables
        _CACHE[key] = build_graph(parse_all(data_dir), load_tables(data_dir))
    return _CACHE[key]


def resolve(identifier, at_utc=None) -> Chain:
    return get_graph().resolve(identifier, at_utc)


def touched(entity, from_utc=None, to_utc=None) -> list:
    return get_graph().touched(entity, from_utc, to_utc)
