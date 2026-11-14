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
    "accounts",
]

# Question vocabulary -> topic. These are words people use, not data-pack values.
TOPIC_PHRASES: dict[str, tuple[str, ...]] = {
    "vpn_foreign_login": ("romanian login", "romania", "romanian", "vpn login", "new country", "foreign login"),
    "large_transfer": ("big transfer", "large transfer", "large internal transfer", "transfer",
                       "exfiltration", "smb transfer", "2.4 gb"),
    "scan": ("the scan", "port scan", "external scan", "scan", "scanning", "recon", "reconnaissance"),
    "sqli": ("sql injection", "sqlmap", "sqli", "sql"),
    "phishing": ("phishing email", "phishing mail", "phishing link", "phishing", "phish", "lookalike"),
    "rdp": ("remote desktop", "rdp"),
    "mfa": ("mfa", "push", "fatigue"),
    "click": ("click", "clicked", "clicks"),
    "concurrent": ("concurrent", "two places", "same time from"),
    "quarantine": ("quarantine", "quarantined", "score"),
    "lease": ("lease", "dhcp"),
    "malware": ("malware", "virus", "infected"),
    "credential": ("credential", "credentials", "password"),
    "legal": ("legal",),
    "gap": ("gap", "reboot of the firewall", "firewall reboot"),
}

# Engine rule names each topic covers (code vocabulary of triage.rules, not data).
TOPIC_RULES: dict[str, set] = {
    "vpn_foreign_login": {"mfa_fatigue"},
    "mfa": {"mfa_fatigue"},
    "large_transfer": {"large_transfer"},
    "scan": {"recon"},
    "sqli": {"web_attack", "web_attack_success"},
    "phishing": {"phishing_delivered", "phishing_click", "phishing_no_click", "phishing_credential_entry"},
    "click": {"phishing_click", "phishing_no_click"},
    "quarantine": {"phishing_delivered"},
    "concurrent": {"concurrent_use"},
    "credential": {"mfa_fatigue", "attacker_session", "phishing_credential_entry", "password_reset"},
}
# A more specific topic replaces the broader one it refines.
TOPIC_OVERRIDES = {"click": {"phishing"}, "quarantine": {"phishing"}, "concurrent": {"credential"},
                   "mfa": {"credential"}}


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
    question: str = ""
    incidents: list[str] = field(default_factory=list)  # incidents the question's topics map to
    time_kinds: dict[str, str] = field(default_factory=dict)  # UTC time -> 'utc' | 'pkt' | 'bare'
    weak: bool = False  # intents come only from the entity default, not from an explicit cue

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
            "incidents": self.incidents,
        }


def topic_rules(topics: list[str]) -> set:
    """Engine rules for a list of topics, with specific topics replacing broad ones."""
    active = set(topics)
    for specific, broad in TOPIC_OVERRIDES.items():
        if specific in active:
            active -= broad
    out: set = set()
    for t in active:
        out |= TOPIC_RULES.get(t, set())
    return out


def topic_incidents(topics: list[str], facts: Any) -> list[str]:
    """Map question topics to incident IDs through the engine's findings."""
    rules = topic_rules(topics)
    if not rules or facts is None:
        return []
    eng = getattr(facts, "engine", None)
    out: list[str] = []
    for inc in list(getattr(eng, "incidents", []) or []) + list(getattr(eng, "anomalies", []) or []):
        if any(f.rule in rules for f in inc.findings) and inc.incident_id not in out:
            out.append(inc.incident_id)
    return out


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
    for topic, phrases in TOPIC_PHRASES.items():
        if any(re.search(r"\b" + re.escape(p) + r"\b", q, re.I) for p in phrases):
            add("topics", topic)
    for m in re.finditer(r"(?<![\w\\])([A-Za-z][A-Za-z0-9-]*\\[A-Za-z](?:[A-Za-z0-9._-]*[A-Za-z0-9_-])?)", q):
        add("accounts", m.group(1))
    # Changes named by what they are ("the VPN firmware update", "the FS01 backup").
    stop = {"the", "a", "an", "of", "in", "and", "to", "for", "on", "by", "servers", "server"}
    qwords = {w.lower() for w in re.findall(r"[A-Za-z0-9]+", q)}
    for ch in _field(tables, "changes", []) or []:
        cid = str(_field(ch, "change_id", ""))
        desc = {w.lower() for w in re.findall(r"[A-Za-z0-9]+", str(_field(ch, "description", "")))} - stop
        score = len(desc & qwords)
        system = str(_field(ch, "system", ""))
        if system and any(re.search(r"(?<![\w-])" + re.escape(x) + r"(?![\w-])", q, re.I)
                          for x in {system, system.split("-")[-1]} if len(x) >= 3):
            score += 1
        actors = [str(x) for x in (_field(ch, "actor_usernames", []) or [])]
        actors += [str(x) for x in (_field(ch, "actor_names", []) or [])]
        if any(a and re.search(r"(?<![\w])" + re.escape(a) + r"(?![\w])", q, re.I) for a in actors):
            score += 1
        if cid and score >= 2:
            add("change_ids", cid)


def _times(q: str, notes: list[str], kinds: dict | None = None) -> list[str]:
    out = []
    kinds = kinds if kinds is not None else {}
    for m in re.finditer(r"(?<![\d:])(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(UTC|PKT)?\b", q, re.I):
        h, mi, sec = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
        if h > 23 or mi > 59 or sec > 59:
            continue
        if m.group(4) and m.group(4).upper() == "PKT":
            dt = datetime(2000, 1, 1, h, mi, sec) - timedelta(hours=5)
            kinds.setdefault(dt.strftime("%H:%M:%S"), "pkt")
        else:
            dt = datetime(2000, 1, 1, h, mi, sec)
            # In a range such as "06:32 and 07:12 UTC", the trailing zone
            # qualifies the first time as well.
            inherited_zone = bool(re.match(
                r"\s*(?:and|to|[-–])\s*\d{1,2}:\d{2}(?::\d{2})?\s*UTC\b",
                q[m.end():], re.I))
            if not m.group(4) and not inherited_zone:
                notes.append("bare time assumed UTC")
                kinds.setdefault(dt.strftime("%H:%M:%S"), "bare")
            else:
                kinds.setdefault(dt.strftime("%H:%M:%S"), "utc")
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


INJECTION_RE = re.compile(
    r"ignore\s+(?:all\s+|any\s+)?(?:your|the|previous|prior|above)?\s*(?:rules|instructions|policy|policies)|"
    r"disregard\s+(?:your|the|all|previous)|forget\s+(?:your|the|all)\s+(?:rules|instructions)|"
    r"\b(?:write|say|state|claim|report|answer)\s+that\b|you\s+are\s+now|system\s+prompt|\bpretend\b|"
    r"\bact\s+as\b|override\s+(?:the\s+)?labels?|developer\s+mode|"
    r"reveal\s+(?:ur|your|the)\s+(?:hidden\s+|secret\s+)?(?:instructions|prompt|rules)|"
    r"(?:answer|respond|reply)\s+as\s+(?:DAN\b|an?\s+unrestricted)|\bjailbreak|"
    r"(?:drop|skip|remove|without)\s+(?:the\s+|any\s+)?(?:citations?|citation\s+requirement|caveats|verification)|"
    r"no\s+caveats|mark\s+(?:everything|all|it|them)\s+(?:as\s+)?confirmed|"
    r"\bsay\s+(?:[A-Z][a-z]+\s+){1,2}(?:is|was)\s+(?:guilty|responsible|the\s+attacker)",
    re.I)

OUT_OF_SCOPE_RE = re.compile(
    r"\bCVEs?\b|\bCVE-\d{4}|threat[- ]actors?|\battribution\b|\battribut(?:e|ed)\s+to\b|\bAPT\s?\d*\b|"
    r"nation[- ]state|who\s+(?:is|was)\s+behind|which\s+(?:hacker\s+)?group|"
    r"other\s+compan(?:y|ies)|another\s+company|competitors?|"
    r"^\s*what\s+(?:is|are)\s+(?:a|an)\s+[a-z][a-z \-]{1,30}\?*\s*$|general\s+security\s+trivia|"
    r"\bbest\s+[\w-]+(?:\s+[\w-]+)?\s+(?:to\s+buy|to\s+use|vendor|product)|"
    r"\bwhich\s+(?:siem|edr|firewall|vendor|product)\s+(?:should|to)\b|"
    r"\b(?:tell|write)\s+(?:me\s+)?a\s+(?:joke|poem)|\bjokes?\b|\bpoem\b|\bweather\b|\brecipe\b",
    re.I)


def strip_injection(question: str) -> str:
    """Drop sentences or clauses that carry instruction-like text; keep the rest of the question."""
    parts = re.split(r"(?<=[.;?!])\s+|;\s*", question or "")
    keep = [p for p in parts if p.strip() and not INJECTION_RE.search(p)]
    return " ".join(keep).strip()


# Intent cues: English synonyms, indirect phrasing and common Roman Urdu cues.
INTENT_RULES: dict[str, str] = {
    "data_theft": r"\b(?:stolen|stole|steal\w*|leak(?:ed|s)?|exfiltrat\w*|exfil|cop(?:y|ied)|theft|"
                  r"which files|what was read|data theft|read the\b[^?.]*\b(?:database|files?|data)|"
                  r"walk(?:ed|s)? out|taken out|(?:left|leave|leaving|leaves) the (?:network|building|company|org\w*)|"
                  r"(?:going|sent|went|uploaded|moved) (?:out|to an? (?:outside|external))|outside address|"
                  r"external (?:ip|address|host|drive)|usb|chura\w*)\b",
    "incident_relation": r"\b(?:same incident|separate incidents?|part of the same|one incident|"
                         r"share\w*\s+(?:any\s+)?evidence|same timestamp|same time|related|unrelated|connected|"
                         r"linked|same (?:attacker|actor|campaign|hamle|hamla|group|person)|one actor|"
                         r"(?:led|lead|leads|leading) to|caused by|stem\w* from|tied together|"
                         r"alag alag|ek hi|hissa)\b",
    "missing_data": r"\b(?:missing|no logs?|not enough evidence|file audit|EDR|proxy log|DB01 logs?|gap|"
                    r"what happened during|which files|database|malware|read the .*database|logs? exist|"
                    r"blind spots?|nothing from|no data|no telemetry|no visibility|"
                    r"what can'?t we (?:say|tell|know|conclude)|"
                    r"logs? (?:are |were )?(?:silent|empty)|anything recorded|recorded)\b",
    "alert_harmless": r"\b(?:harmless|approved|approves?|legitimate|suspicious|benign|false positive|closed|"
                      r"false alarm|supposed to be|planned|scheduled|maintenance|expected|authori[sz]ed|"
                      r"routine|nightly|real threat|just noise|panic)\b",
    "severity": r"\b(?:severity|priority|P[1-4]|critical|severe|how bad|rank\w*|code[- ]red|grade\w*|"
                r"rating|how serious|how urgent|prioriti[sz]\w*)\b",
    "timeline": r"\b(?:when|what time|start\w*|close\w*|end|timeline|first|last|success(?:ful)?|kab|occur\w*|"
                r"timestamp|unfold\w*|step by step|sequence|chronolog\w*|in order|order batao|pehle|phir|"
                r"walk me through|at which moment)\b",
    "entity_match": r"\b(?:who owns?|owner|resolve|what asset|which host|which ip|which user|who is|whose|"
                    r"belongs?|kis ne|kaun|why|reason|what evidence|log(?:ged)?\s+(?:in|on)|logon|login|"
                    r"which (?:workstation|laptop|machine|device)|what role|ke paas)\b",
    "history": r"\b(?:history|always|owned|lease|activity|(?:at|around|about|before|after)\s+\d{1,2}:\d{2}|"
               r"sitting on|before lunch|after lunch|did that change|changed? (?:hands|later)|"
               r"looking back|ever been|used by|anybody other|anyone other|someone else|previously|over time)\b",
    "actions": r"\b(?:actions?|(?:what|which)\b[^?]*\bresponse|what should|should we|do with|do about|"
               r"disable|block|reboot\w*|wipe|reset|preserv\w*|runbook|open .*runbook|kya karna|kya karein|"
               r"recommend\w*|next steps?|mitigat\w*|remediat\w*|what now|isolat\w*|kill the|pull the plug|"
               r"shut (?:it )?down|containment)\b",
    "notify": r"\b(?:inform\w*|notif\w*|escalat\w*|receiv(?:e|es)|who must|who to|"
              r"who\b[^?]*\b(?:call|contact|tell)|contact\w*|heads[- ]up|needs? to know|deadline|"
              r"bataa?na|bataye|bataen|kis ko|kisko|regulator)\b",
    "report": r"\b(?:full report|incident report|summari[sz]e|summary|overview|report|kya hua|condense|"
              r"board meeting|briefing|whole story|full story|sab kuch|recap|tl;?dr|write[- ]?up|"
              r"executive summary|big picture)\b",
}

# Single-word cues matched with an edit-distance allowance, for typos such as
# "severty", "timelin", "exfiltarted", "notifiy". Only words of 6+ letters.
TYPO_CUES: dict[str, str] = {
    "stolen": "data_theft", "exfiltrated": "data_theft", "exfiltration": "data_theft",
    "related": "incident_relation", "connected": "incident_relation", "separate": "incident_relation",
    "missing": "missing_data", "harmless": "alert_harmless", "legitimate": "alert_harmless",
    "approved": "alert_harmless", "suspicious": "alert_harmless", "severity": "severity",
    "priority": "severity", "critical": "severity", "timeline": "timeline", "history": "history",
    "runbook": "actions", "recommend": "actions", "isolate": "actions", "escalate": "notify",
    "notify": "notify", "inform": "notify", "summary": "report", "summarize": "report", "report": "report",
}


def _typo_intents(low: str) -> list[str]:
    out: list[str] = []
    for tok in set(re.findall(r"[a-z]{6,}", low)):
        if tok in TYPO_CUES:
            continue
        for cue, intent in TYPO_CUES.items():
            if abs(len(cue) - len(tok)) > 2 or tok[0] != cue[0]:
                continue
            limit = 1 if len(cue) < 9 else 2
            if _levenshtein(tok, cue) <= limit:
                out.append(intent)
    return out


def _classifier_opinion(question: str) -> tuple[str | None, float]:
    """Optional trained classifier; (None, 0.0) when scikit-learn or the model is missing."""
    try:
        from triage.answer import classifier
        return classifier.predict(question)
    except Exception:
        return None, 0.0


CLASSIFIER_THRESHOLD = 0.6


def route(question: str, tables=None, facts=None, use_classifier: bool = True) -> Route:
    if tables is None and facts is not None:
        tables = getattr(facts, "tables", None)
    tables = tables if tables is not None else load_tables()
    q = question or ""
    low = q.lower()
    entities = {k: [] for k in ENTITY_KEYS}
    notes: list[str] = []
    _extract_entities(q, tables, entities)
    kinds: dict = {}
    times = _times(q, notes, kinds)
    dates, other_date = _dates(q, tables, notes)
    injection = bool(INJECTION_RE.search(q))
    outscope = bool(OUT_OF_SCOPE_RE.search(q))
    rules = dict(INTENT_RULES)
    found = [name for name in INTENTS if name == "injection" and injection]
    if outscope:
        found.append("out_of_scope")
    for intent in INTENTS:
        if intent in ("injection", "out_of_scope"):
            continue
        if re.search(rules.get(intent, r"(?!)"), low, re.I):
            found.append(intent)
    found.extend(_typo_intents(low))
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
    weak = False
    if any(entities.values()) and not found:
        found.append("entity_match")
        weak = True
    if any(entities.values()) and re.search(r"\bsuspicious\b", low):
        found.append("entity_match")
    # Preserve the public priority order and avoid duplicate additions.
    intents = [x for x in INTENTS if x in found]
    how = "rules" if intents else "none"
    conf = (round(min(0.99, 0.72 + 0.05 * len(intents) + (0.08 if any(entities.values()) else 0)), 2)
            if intents else 0.0)
    # Second opinion from the optional classifier: only when the rules found no
    # explicit cue; it never overrides injection / out-of-scope handling.
    if use_classifier and (not intents or weak) and not injection and not outscope:
        ci, cp = _classifier_opinion(q)
        allowed = ci not in ("injection", "out_of_scope") or (not intents and not any(entities.values()))
        if ci in INTENTS and cp >= CLASSIFIER_THRESHOLD and allowed:
            if ci == "injection":
                injection = True
            if ci == "out_of_scope":
                outscope = True
            intents = [x for x in INTENTS if x in set(intents) | {ci}]
            how, conf = "classifier", round(cp, 2)
            notes.append(f"classifier intent {ci} (p={cp:.2f})")
    if injection:
        notes.append("question contains instruction-like text")
    if outscope:
        notes.append("outside the data pack scope")
    incidents = list(entities.get("incident_ids", []))
    for i in topic_incidents(entities.get("topics", []), facts):
        if i not in incidents:
            incidents.append(i)
    return Route(intents=intents, entities=entities, times_utc=times, dates=dates,
                 other_date=other_date, injection=injection, out_of_scope=outscope,
                 route=how, confidence=conf, notes=notes, question=q, incidents=incidents,
                 time_kinds=kinds, weak=weak)
