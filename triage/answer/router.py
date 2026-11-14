"""Deterministic question routing for the answer pipeline.

The router deliberately knows identifier shapes and intent language, but gets all
data-pack vocabulary (assets, users, alerts, changes and runbooks) from Tables.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from triage.parsers.tables import load_tables


INTENTS = [
    "injection", "out_of_scope", "data_theft", "incident_relation", "missing_data",
    "alert_harmless", "severity", "timeline", "entity_match", "history", "actions",
    "notify", "report",
]
ENTITY_KEYS = [
    "ips", "hostnames", "asset_tags", "usernames", "alert_ids", "change_ids",
    "runbook_ids", "session_ids", "msg_ids", "domains", "incident_ids", "cves", "topics",
]


@dataclass
class Route:
    intents: list[str] = field(default_factory=list)
    entities: dict[str, list[str]] = field(default_factory=dict)
    times_utc: list[str] = field(default_factory=list)
    dates: list[str] = field(default_factory=list)
    other_date: bool = False
    injection: bool = False
    out_of_scope: bool = False
    route: str = "none"
    confidence: float = 0.0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "intents": self.intents,
            "entities": self.entities,
            "times_utc": self.times_utc,
            "dates": self.dates,
            "other_date": self.other_date,
            "injection": self.injection,
            "out_of_scope": self.out_of_scope,
            "route": self.route,
            "confidence": self.confidence,
            "notes": self.notes,
        }


def _uniq(values: list[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def _field(obj: Any, name: str, default: Any = "") -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        nxt = [i]
        for j, cb in enumerate(b, 1):
            nxt.append(min(nxt[-1] + 1, row[j] + 1, row[j - 1] + (ca != cb)))
        row = nxt
    return row[-1]


def _vocabulary(tables: Any) -> dict[str, Any]:
    assets = list(_field(tables, "inventory", []) or [])
    users = list(_field(tables, "users", []) or [])
    alerts = list(_field(tables, "alerts", []) or [])
    changes = list(_field(tables, "changes", []) or [])
    runbooks = _field(tables, "runbooks", {}) or {}
    hosts: dict[str, str] = {}
    asset_tags: set[str] = set()
    type_aliases: dict[str, str] = {}
    for a in assets:
        host = str(_field(a, "hostname", ""))
        tag = str(_field(a, "tag", ""))
        if host:
            hosts[host.lower()] = host
            short = host.split("-")[-1]
            hosts.setdefault(short.lower(), host)
        if tag:
            asset_tags.add(tag.lower())
        typ = str(_field(a, "type", "")).lower()
        for phrase in ("file server", "domain controller", "web server", "database", "vpn gateway"):
            if phrase in typ and host:
                type_aliases[phrase] = host
    usernames = {str(_field(u, "username", "")).lower(): str(_field(u, "username", "")) for u in users}
    names: list[tuple[str, str]] = []
    for u in users:
        username = str(_field(u, "username", ""))
        full = str(_field(u, "full_name", ""))
        if username and full:
            names.append((full, username))
            for first in full.split()[:1]:
                names.append((first, username))
    return {
        "hosts": hosts, "type_aliases": type_aliases, "asset_tags": asset_tags,
        "usernames": usernames, "names": names,
        "alert_ids": [str(_field(x, "alert_id", "")) for x in alerts],
        "change_ids": [str(_field(x, "change_id", "")) for x in changes],
        "runbook_ids": [str(k) for k in runbooks],
    }


def _extract_entities(q: str, tables: Any, entities: dict[str, list[str]]) -> None:
    v = _vocabulary(tables)
    def add(key: str, value: str) -> None:
        if value and value not in entities[key]:
            entities[key].append(value)

    for ip in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", q):
        add("ips", ip)
    for d in re.findall(r"(?i)(?<![\w@])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?![\w-])", q):
        add("domains", d)
    for pattern, key in ((r"\bALT-\d+\b", "alert_ids"), (r"\bCHG-[A-Za-z0-9-]+\b", "change_ids"),
                         (r"\bRB-[A-Za-z0-9-]+\b", "runbook_ids"), (r"\bVS-\d+\b", "session_ids"),
                         (r"\bM-\d+\b", "msg_ids"), (r"\bINC-\d+\b", "incident_ids"),
                         (r"\bCVE-\d{4}-\d{4,}\b", "cves")):
        for x in re.findall(pattern, q, re.I):
            add(key, x.upper() if key != "cves" else x.upper())
    for tag in v["asset_tags"]:
        if re.search(r"(?<![\w-])" + re.escape(tag) + r"(?![\w-])", q, re.I):
            add("asset_tags", next((str(_field(a, "tag", "")) for a in _field(tables, "inventory", [])
                                     if str(_field(a, "tag", "")).lower() == tag), tag))
    for given, canonical in v["hosts"].items():
        if re.search(r"(?<![\w.-])" + re.escape(given) + r"(?![\w.-])", q, re.I):
            add("hostnames", canonical)
    for phrase, host in v["type_aliases"].items():
        if re.search(r"\b" + re.escape(phrase) + r"\b", q, re.I):
            add("hostnames", host)
    for username, canonical in v["usernames"].items():
        if re.search(r"(?<![\w])" + re.escape(username) + r"(?![\w])", q, re.I):
            add("usernames", canonical)
    # Domain-qualified Windows names are normalized to the directory username.
    for m in re.finditer(r"(?i)\b(?:orbit\\)?([a-z][a-z0-9._-]{2,})\b", q):
        candidate = m.group(1).lower()
        if candidate in v["usernames"]:
            add("usernames", v["usernames"][candidate])
    for name, username in v["names"]:
        words = [re.escape(x) for x in name.split()]
        exact = re.search(r"(?i)(?<![a-z])" + r"\s+".join(words) + r"(?![a-z])", q)
        first = re.search(r"(?i)(?<![a-z])" + re.escape(name.split()[0]) + r"(?![a-z])", q)
        if exact or first:
            add("usernames", username)
            continue
        # Apply the one-edit allowance only to name tokens of length >= 5.
        for token in re.findall(r"[A-Za-z]+", q):
            if len(token) >= 5 and any(_levenshtein(token.lower(), part.lower()) <= 1
                                       for part in name.split() if len(part) >= 5):
                add("usernames", username)
                break
    topic_phrases = {
        "vpn_foreign_login": ("romanian login",), "large_transfer": ("big transfer", "large transfer"),
        "scan": ("the scan", "port scan", "external scan", "recon"), "sqli": ("sql injection", "sqlmap"),
        "phishing": ("phishing email", "phishing mail", "phishing link"), "rdp": ("remote desktop", "rdp"),
    }
    for topic, phrases in topic_phrases.items():
        if any(re.search(r"\b" + re.escape(p) + r"\b", q, re.I) for p in phrases):
            add("topics", topic)


def _times(q: str, notes: list[str]) -> list[str]:
    out = []
    for m in re.finditer(r"(?<![\d:])(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(UTC|PKT)?\b", q, re.I):
        h, mi, sec = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
        if h > 23 or mi > 59 or sec > 59:
            continue
        if m.group(4) and m.group(4).upper() == "PKT":
            dt = datetime(2000, 1, 1, h, mi, sec) - timedelta(hours=5)
        else:
            dt = datetime(2000, 1, 1, h, mi, sec)
            # In a range such as "06:32 and 07:12 UTC", the trailing zone
            # qualifies the first time as well.
            inherited_zone = bool(re.match(
                r"\s*(?:and|to|[-–])\s*\d{1,2}:\d{2}(?::\d{2})?\s*UTC\b",
                q[m.end():], re.I))
            if not m.group(4) and not inherited_zone:
                notes.append("bare time assumed UTC")
        out.append(dt.strftime("%H:%M:%S"))
    return _uniq(out)


def _dates(q: str, tables: Any, notes: list[str]) -> tuple[list[str], bool]:
    coverage = _field(tables, "coverage", None)
    covered = str(_field(coverage, "date", "")) or None
    year = int(covered[:4]) if covered and covered[:4].isdigit() else datetime.now().year
    found: list[str] = []
    for x in re.findall(r"\b\d{4}-\d{2}-\d{2}\b", q):
        found.append(x)
    months = "January February March April May June July August September October November December"
    mon = r"(?:" + "|".join(months.split()) + r")"
    for m in re.finditer(r"\b(\d{1,2})\s+(" + mon + r")(?:\s+(\d{4}))?\b", q, re.I):
        month = datetime.strptime(m.group(2)[:3].title(), "%b").month
        found.append(f"{int(m.group(3) or year):04d}-{month:02d}-{int(m.group(1)):02d}")
    for m in re.finditer(r"\b(" + mon + r")\s+(\d{1,2})(?:,?\s+(\d{4}))?\b", q, re.I):
        month = datetime.strptime(m.group(1)[:3].title(), "%b").month
        found.append(f"{int(m.group(3) or year):04d}-{month:02d}-{int(m.group(2)):02d}")
    found = _uniq(found)
    return found, bool(covered and any(d != covered for d in found))


def route(question: str, tables=None) -> Route:
    tables = tables if tables is not None else load_tables()
    q = question or ""
    low = q.lower()
    entities = {k: [] for k in ENTITY_KEYS}
    notes: list[str] = []
    _extract_entities(q, tables, entities)
    times = _times(q, notes)
    dates, other_date = _dates(q, tables, notes)
    injection = bool(re.search(r"ignore\s+(?:your|the)\s+rules|write\s+that|you\s+are\s+now|system\s+prompt|pretend|say\s+that\s+data\s+was\s+(?:leaked|stolen)", low))
    outscope = bool(re.search(r"\bCVE(?:[- ]?\d{4})?|threat actor|attribution|APT\b|other companies?|general security trivia|what is (?:a|the) (?:firewall|malware|sql injection)\b|\bsqlmap\b", q, re.I))
    rules = {
        "data_theft": r"\b(?:stolen|leaked|exfiltrat\w*|cop(?:y|ied)|which files|what was read|data theft)\b",
        "incident_relation": r"\b(?:same incident|separate incident|part of the same|one incident|share evidence)\b",
        "missing_data": r"\b(?:missing|no logs?|not enough evidence|file audit|EDR|proxy log|DB01 logs?|gap|what happened during|which files|database|malware|read the .*database)\b",
        "alert_harmless": r"\b(?:harmless|approved|approve|legitimate|suspicious)\b",
        "severity": r"\b(?:severity|priority|P[1-4])\b",
        "timeline": r"\b(?:when|what time|start|close|end|timeline|first|last|success(?:ful)?|kab)\b",
        "entity_match": r"\b(?:who owns?|owner|resolve|what asset|which host|who is|kis ne|kaun|why|reason|what evidence)\b",
        "history": r"\b(?:history|always|owned|lease|activity|at \d{1,2}:\d{2})\b",
        "actions": r"\b(?:actions?|response|what should|should we|do with|disable|block|reboot|wipe|reset|preserve|open .*runbook|kya karna)\b",
        "notify": r"\b(?:inform|notify|escalat|receiv(?:e|es)|who must|who to)\b",
        "report": r"\b(?:full report|summari[sz]e|report|kya hua)\b",
    }
    found = [name for name in INTENTS if name == "injection" and injection]
    if outscope:
        found.append("out_of_scope")
    for intent in INTENTS:
        if intent in ("injection", "out_of_scope"):
            continue
        if re.search(rules.get(intent, r"(?!)"), low, re.I):
            found.append(intent)
    if re.search(r"\b(?:ALT-\d+|alert)\b", q, re.I) and re.search(r"\b(?:attack|escalat)\w*\b", q, re.I):
        found.append("alert_harmless")
    if re.search(r"\b(?:kitna|kitni)\b", low) and re.search(r"\b(?:data|file|transfer)\w*\b", low):
        found.extend(["data_theft", "missing_data"])
    if times and not any(x in found for x in ("timeline", "history", "report")):
        found.append("timeline")
    if times and re.search(r"\b(?:between|during|what happened|what did)\b", low):
        found.append("missing_data")
    if dates and not any(x in found for x in ("timeline", "history", "report", "missing_data")):
        found.append("missing_data")
    # Questions such as "who clicked?" or "is this timestamp...?" can be
    # answered by entity resolution even when they contain no special verb.
    if any(entities.values()) and not found:
        found.append("entity_match")
    if any(entities.values()) and re.search(r"\bsuspicious\b", low):
        found.append("entity_match")
    # Preserve the public priority order and avoid duplicate additions.
    intents = [x for x in INTENTS if x in found]
    if injection:
        notes.append("question contains instruction-like text")
    if outscope:
        notes.append("outside the data pack scope")
    return Route(intents=intents, entities=entities, times_utc=times, dates=dates,
                 other_date=other_date, injection=injection, out_of_scope=outscope,
                 route="rules" if intents else "none",
                 confidence=round(min(0.99, 0.72 + 0.05 * len(intents) + (0.08 if any(entities.values()) else 0)), 2)
                 if intents else 0.0, notes=notes)
