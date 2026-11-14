"""Contracts from ARCHITECTURE section 5. Field names match the JSON exactly."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

CONFIRMED = "confirmed"
SUSPECTED = "suspected"
NOT_ENOUGH_EVIDENCE = "not_enough_evidence"
HARMLESS = "harmless"
LABELS = (CONFIRMED, SUSPECTED, NOT_ENOUGH_EVIDENCE, HARMLESS)

PKT = timezone(timedelta(hours=5), "PKT")


# ---------------------------------------------------------------- time helpers
def to_utc_iso(dt: datetime) -> str:
    """datetime -> 'YYYY-MM-DDTHH:MM:SSZ'. Naive datetimes are taken as UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(s: str) -> datetime:
    """ISO-8601 string ending in Z (or with an offset) -> aware UTC datetime."""
    s = s.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_utc_pkt(t: Union[str, datetime]) -> str:
    """'06:03:12 UTC [11:03:12 PKT]'."""
    dt = parse_utc(t) if isinstance(t, str) else t
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    u = dt.astimezone(timezone.utc)
    p = dt.astimezone(PKT)
    return f"{u:%H:%M:%S} UTC [{p:%H:%M:%S} PKT]"


# ------------------------------------------------------------------ dataclasses
@dataclass
class Cite:
    """One of: file+line, file+row, file+runbook+step."""
    file: str
    line: Optional[int] = None
    row: Optional[str] = None
    runbook: Optional[str] = None
    step: Optional[int] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}

    @classmethod
    def from_dict(cls, d: dict) -> "Cite":
        return cls(file=d["file"], line=d.get("line"), row=d.get("row"),
                   runbook=d.get("runbook"), step=d.get("step"))


def _cites(items: list) -> list:
    return [c.to_dict() if isinstance(c, Cite) else c for c in items]


def _load_cites(items: Optional[list]) -> list:
    return [Cite.from_dict(c) for c in (items or [])]


@dataclass
class Event:
    event_id: str
    kind: str
    ts_utc: str
    source_file: str
    line: int
    raw: str
    ts_end_utc: Optional[str] = None
    fields: dict = field(default_factory=dict)
    untrusted_fields: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"event_id": self.event_id, "kind": self.kind, "ts_utc": self.ts_utc,
                "ts_end_utc": self.ts_end_utc, "source_file": self.source_file,
                "line": self.line, "raw": self.raw, "fields": dict(self.fields),
                "untrusted_fields": list(self.untrusted_fields)}

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        return cls(event_id=d["event_id"], kind=d["kind"], ts_utc=d["ts_utc"],
                   ts_end_utc=d.get("ts_end_utc"), source_file=d["source_file"],
                   line=d["line"], raw=d.get("raw", ""), fields=dict(d.get("fields") or {}),
                   untrusted_fields=list(d.get("untrusted_fields") or []))


@dataclass
class Link:
    a: str
    b: str
    type: str
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    basis: str = "direct"  # direct | inferred
    assumption: Optional[str] = None
    evidence: list = field(default_factory=list)  # list[Cite]

    def to_dict(self) -> dict:
        return {"a": self.a, "b": self.b, "type": self.type,
                "valid_from": self.valid_from, "valid_to": self.valid_to,
                "basis": self.basis, "assumption": self.assumption,
                "evidence": _cites(self.evidence)}

    @classmethod
    def from_dict(cls, d: dict) -> "Link":
        return cls(a=d["a"], b=d["b"], type=d["type"], valid_from=d.get("valid_from"),
                   valid_to=d.get("valid_to"), basis=d.get("basis", "direct"),
                   assumption=d.get("assumption"), evidence=_load_cites(d.get("evidence")))


@dataclass
class Gap:
    source: str
    from_utc: Optional[str]
    to_utc: Optional[str]
    reason: str
    evidence: list = field(default_factory=list)  # list[Cite]

    def to_dict(self) -> dict:
        return {"source": self.source, "from_utc": self.from_utc, "to_utc": self.to_utc,
                "reason": self.reason, "evidence": _cites(self.evidence)}

    @classmethod
    def from_dict(cls, d: dict) -> "Gap":
        return cls(source=d["source"], from_utc=d.get("from_utc"), to_utc=d.get("to_utc"),
                   reason=d.get("reason", ""), evidence=_load_cites(d.get("evidence")))


@dataclass
class Finding:
    finding_id: str
    rule: str
    cites_rule: str
    label: str  # confirmed | suspected | not_enough_evidence | harmless
    statement: str
    assumption: Optional[str] = None  # required when suspected
    steps: list = field(default_factory=list)
    evidence: list = field(default_factory=list)  # list[Cite]
    entities: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"finding_id": self.finding_id, "rule": self.rule, "cites_rule": self.cites_rule,
                "label": self.label, "statement": self.statement,
                "assumption": self.assumption, "steps": list(self.steps),
                "evidence": _cites(self.evidence), "entities": list(self.entities)}

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(finding_id=d["finding_id"], rule=d["rule"], cites_rule=d.get("cites_rule", ""),
                   label=d["label"], statement=d.get("statement", ""),
                   assumption=d.get("assumption"), steps=list(d.get("steps") or []),
                   evidence=_load_cites(d.get("evidence")), entities=list(d.get("entities") or []))


@dataclass
class Incident:
    incident_id: str
    parts: list = field(default_factory=list)  # [{"type","asset","severity","steps"}]
    severity: Optional[str] = None
    findings: list = field(default_factory=list)  # list[Finding]
    timeline: list = field(default_factory=list)  # list[event_id]
    actions: list = field(default_factory=list)
    notify: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"incident_id": self.incident_id, "parts": [dict(p) for p in self.parts],
                "severity": self.severity,
                "findings": [f.to_dict() if isinstance(f, Finding) else f for f in self.findings],
                "timeline": list(self.timeline),
                "actions": [dict(a) for a in self.actions],
                "notify": [dict(n) for n in self.notify]}

    @classmethod
    def from_dict(cls, d: dict) -> "Incident":
        return cls(incident_id=d["incident_id"], parts=[dict(p) for p in d.get("parts") or []],
                   severity=d.get("severity"),
                   findings=[Finding.from_dict(f) for f in d.get("findings") or []],
                   timeline=list(d.get("timeline") or []),
                   actions=[dict(a) for a in d.get("actions") or []],
                   notify=[dict(n) for n in d.get("notify") or []])


def _empty_structured() -> dict:
    return {"labels": {"confirmed": [], "suspected": [], "not_enough_evidence": []},
            "severity": None, "severity_steps": [], "citations": [], "entities": [],
            "actions": [], "notify": []}


def _empty_meta() -> dict:
    return {"path": "template", "provider": "none", "route": "rules", "cached": False}


@dataclass
class Answer:
    answer: str
    structured: dict = field(default_factory=_empty_structured)  # citations: Cite or dict
    meta: dict = field(default_factory=_empty_meta)

    def to_dict(self) -> dict:
        s = dict(self.structured)
        s["citations"] = _cites(s.get("citations", []))
        return {"answer": self.answer, "structured": s, "meta": dict(self.meta)}

    @classmethod
    def from_dict(cls, d: dict) -> "Answer":
        s = dict(d.get("structured") or _empty_structured())
        s["citations"] = [Cite.from_dict(c) if isinstance(c, dict) else c
                          for c in s.get("citations", [])]
        return cls(answer=d["answer"], structured=s, meta=dict(d.get("meta") or _empty_meta()))
