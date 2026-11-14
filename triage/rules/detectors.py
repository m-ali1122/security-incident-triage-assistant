"""P7: rule engine detectors. Parameters come from triage/rules.yaml.

Every detector is a generic predicate over events, tables, coverage and the evidence
graph. No identifier from the data pack is written here: values are read from the data.

Clustering contract (P6): actor keys go in Finding.entities with the prefix `actor:`.
Other entities use node IDs (`user:`, `asset:`, `ip:`, `ext_ip:`, `alert:`, ...).
Each Finding also carries a `data` attribute (plain dict, not serialised) that the
severity, escalation and runbook modules read for concrete values.
"""
from __future__ import annotations

import ipaddress
import math
import re
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import unquote_plus

import yaml

from triage import config
from triage.models import (CONFIRMED, HARMLESS, NOT_ENOUGH_EVIDENCE, PKT, SUSPECTED, Cite, Event,
                           Finding, parse_utc, to_utc_iso)
from triage.rules.calendar import ChangeMatch, match_change

# ------------------------------------------------------------------ rules.yaml
_RULES_CACHE: dict = {}


def load_rules(path: Union[str, Path, None] = None) -> dict:
    p = Path(path or config.RULES_YAML)
    key = (str(p.resolve()), p.stat().st_mtime_ns)
    if key not in _RULES_CACHE:
        _RULES_CACHE[key] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return _RULES_CACHE[key]


# ------------------------------------------------------------------ small helpers
def _dt(t: Union[str, datetime, None]) -> Optional[datetime]:
    if t is None or t == "":
        return None
    if isinstance(t, datetime):
        return t.replace(tzinfo=timezone.utc) if t.tzinfo is None else t.astimezone(timezone.utc)
    return parse_utc(t)


def hms(t: Union[str, datetime, None]) -> str:
    d = _dt(t)
    return d.strftime("%H:%M:%S") if d else "?"


def hms_pkt(t: Union[str, datetime, None]) -> str:
    d = _dt(t)
    return d.astimezone(PKT).strftime("%H:%M:%S") if d else "?"


def when(t) -> str:
    """'HH:MM:SS UTC [HH:MM:SS PKT]'."""
    return f"{hms(t)} UTC [{hms_pkt(t)} PKT]"


def span(a, b) -> str:
    """'HH:MM:SS to HH:MM:SS UTC [HH:MM:SS to HH:MM:SS PKT]'."""
    return f"{hms(a)} to {hms(b)} UTC [{hms_pkt(a)} to {hms_pkt(b)} PKT]"


def num(n: Any) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def numbered(steps: list) -> list:
    return [f"{i}. {s}" for i, s in enumerate(steps, 1)]


def ecite(e: Event) -> Cite:
    return Cite(file=e.source_file, line=e.line)


def ref(e: Event) -> str:
    """'f15 L6'."""
    m = re.match(r"(\d+)_", e.source_file)
    return f"f{m.group(1) if m else e.source_file} L{e.line}"


def refs(evs: list) -> str:
    if not evs:
        return ""
    by: dict = {}
    for e in evs:
        by.setdefault(e.source_file, []).append(e.line)
    out = []
    for f, lines in by.items():
        m = re.match(r"(\d+)_", f)
        lines = sorted(set(lines))
        out.append(f"f{m.group(1) if m else f} L" + ", L".join(str(x) for x in lines))
    return "; ".join(out)


def tref(c: Cite) -> str:
    m = re.match(r"(\d+)_", c.file)
    f = f"f{m.group(1)}" if m else c.file
    if c.row:
        return f"{f} {c.row}"
    if c.runbook:
        return f"{c.runbook} step {c.step}"
    return f"{f} L{c.line}" if c.line else f


def rbref(ctx: Any, keyword: str, step: Optional[int] = None) -> str:
    """'<runbook id> step n' for the runbook whose title contains `keyword` (read from the tables)."""
    rbs = getattr(getattr(ctx, "tables", None), "runbooks", {}) or {}
    rid = next((r for r, rb in rbs.items() if keyword.lower() in rb.title.lower()), None)
    rid = rid or f"{keyword} runbook"
    return f"{rid} step {step}" if step is not None else rid


def norm_account(v: Any) -> Optional[str]:
    if not v:
        return None
    s = str(v).strip()
    if "\\" in s:
        s = s.split("\\")[-1]
    if "@" in s:
        s = s.split("@")[0]
    return s.lower() or None


def actor_keys(f: Finding) -> list:
    return [e for e in f.entities if e.startswith("actor:")]


def fdata(f: Finding) -> dict:
    return getattr(f, "data", None) or {}


def _dedupe(items: list) -> list:
    out, seen = [], set()
    for x in items:
        k = x.to_dict() if isinstance(x, Cite) else x
        k = tuple(sorted(k.items())) if isinstance(k, dict) else k
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out


# ------------------------------------------------------------------ context
@dataclass
class Sess:
    session_id: str
    user: str
    src_ip: Optional[str]
    geo: Optional[str]
    assigned_ip: Optional[str]
    start: Optional[datetime]
    end: Optional[datetime]
    login_cite: Optional[Cite]
    end_cite: Optional[Cite]
    bytes_to_client: Optional[int]
    bytes_from_client: Optional[int]
    duration_s: Optional[int]
    mfa: Optional[str]

    def contains(self, t: datetime) -> bool:
        return bool(self.start and self.start <= t and (self.end is None or t <= self.end))


def _as_cite(c: Any) -> Optional[Cite]:
    if c is None:
        return None
    if isinstance(c, Cite):
        return c
    if isinstance(c, dict):
        return Cite.from_dict(c)
    return None


def _int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


class Ctx:
    """Everything a detector needs, with the graph preferred and table fallbacks."""

    def __init__(self, graph: Any, events: list, tables: Any, coverage: Any, rules: dict):
        self.graph, self.tables, self.rules = graph, tables, rules
        self.cov = coverage if coverage is not None else getattr(tables, "coverage", None)
        src = rules.get("sources", {})
        self.role_kinds = {k: set(v) for k, v in src.items() if isinstance(v, list)}
        known = set().union(*self.role_kinds.values()) if self.role_kinds else set()
        evs = [e for e in events if e.kind in known]
        self.events = sorted(evs, key=lambda e: (self.start(e), e.source_file, e.line))
        self.by_cite = {(e.source_file, e.line): e for e in self.events}
        self.nets = [ipaddress.ip_network(n) for n in
                     rules.get("network", {}).get("internal_networks", [])]
        self.calendar_log: list = []  # [(label, activity, ChangeMatch)]
        self.alert_checks: dict = {}
        self.sessions = self._sessions()
        self.log_date = getattr(self.cov, "date", None)

    # ---- events
    def role(self, name: str) -> list:
        kinds = self.role_kinds.get(name, set())
        return [e for e in self.events if e.kind in kinds]

    def role_of(self, e: Event) -> Optional[str]:
        for r, ks in self.role_kinds.items():
            if e.kind in ks:
                return r
        return None

    def source_file(self, role: str) -> Optional[str]:
        evs = self.role(role)
        return evs[0].source_file if evs else None

    @staticmethod
    def start(e: Event) -> datetime:
        return parse_utc(e.ts_utc)

    @staticmethod
    def end(e: Event) -> datetime:
        return parse_utc(e.ts_end_utc) if e.ts_end_utc else parse_utc(e.ts_utc)

    @staticmethod
    def src(e: Event) -> Optional[str]:
        f = e.fields
        return f.get("src_ip") or f.get("client")

    @staticmethod
    def dst(e: Event) -> Optional[str]:
        return e.fields.get("dst_ip")

    @staticmethod
    def user(e: Event) -> Optional[str]:
        f = e.fields
        return norm_account(f.get("user") or f.get("account"))

    def window(self, a: datetime, b: datetime) -> list:
        return [e for e in self.events if self.start(e) <= b and self.end(e) >= a]

    # ---- sessions
    def _sessions(self) -> list:
        g = self.graph
        if g is not None and hasattr(g, "sessions"):
            try:
                out = []
                for s in g.sessions():
                    out.append(Sess(
                        s.session_id, norm_account(s.user), getattr(s, "src_ip", None),
                        getattr(s, "geo", None), getattr(s, "assigned_ip", None),
                        _dt(getattr(s, "start_utc", None)), _dt(getattr(s, "end_utc", None)),
                        _as_cite(getattr(s, "login_cite", None)), _as_cite(getattr(s, "end_cite", None)),
                        _int(getattr(s, "bytes_to_client", None)),
                        _int(getattr(s, "bytes_from_client", None)),
                        _int(getattr(s, "duration_s", None)), getattr(s, "mfa", None)))
                if out:
                    return sorted(out, key=lambda s: (s.start or datetime.min.replace(tzinfo=timezone.utc)))
            except Exception:
                pass
        return self._local_sessions()

    def _local_sessions(self) -> list:
        starts: dict = {}
        for e in self.role("vpn"):
            f = e.fields
            sid = f.get("session")
            if not sid:
                continue
            if str(f.get("result", "")).upper() == "SUCCESS" and f.get("assigned_ip"):
                starts[sid] = Sess(sid, norm_account(f.get("user")), f.get("src_ip"), f.get("geo"),
                                   f.get("assigned_ip"), self.start(e), None, ecite(e), None,
                                   None, None, None, f.get("mfa"))
            elif "result" not in f and sid in starts:
                s = starts[sid]
                s.end, s.end_cite = self.start(e), ecite(e)
                s.bytes_to_client = _int(f.get("bytes_server_to_client", f.get("bytes_to_client")))
                s.bytes_from_client = _int(f.get("bytes_client_to_server", f.get("bytes_from_client")))
                s.duration_s = _int(f.get("duration_s", f.get("duration")))
        return sorted(starts.values(), key=lambda s: s.start)

    def session(self, sid: str) -> Optional[Sess]:
        return next((s for s in self.sessions if s.session_id == sid), None)

    def session_for_ip(self, ip: str, t: datetime) -> Optional[Sess]:
        return next((s for s in self.sessions if s.assigned_ip == ip and s.contains(t)), None)

    # ---- tables
    def asset_by_ip(self, ip: Optional[str]):
        if not ip:
            return None
        g = self.graph
        if g is not None and hasattr(g, "asset_for_ip"):
            try:
                r = g.asset_for_ip(ip)
                if r is not None:
                    if hasattr(r, "tag"):
                        return r
                    if getattr(r, "asset", None) is not None:
                        return r.asset
            except Exception:
                pass
        return next((a for a in self.tables.inventory if a.ip == ip or a.public_ip == ip), None)

    def asset_by_host(self, name: Optional[str]):
        if not name:
            return None
        n = name.strip().lower()
        for a in self.tables.inventory:
            if a.hostname.lower() == n or a.tag.lower() == n:
                return a
        try:
            return self.tables.inventory_notes.resolve_fqdn(name, self.tables.inventory)
        except Exception:
            return None

    def asset_by_tag(self, tag: str):
        return next((a for a in self.tables.inventory if a.tag == tag), None)

    def user_row(self, username: Optional[str]):
        u = norm_account(username)
        return next((r for r in self.tables.users if r.username.lower() == u), None) if u else None

    def user_by_email(self, email: str):
        e = (email or "").lower()
        return next((r for r in self.tables.users if r.email.lower() == e), None)

    def laptop(self, username: str):
        u = self.user_row(username)
        return self.asset_by_tag(u.laptop_tag) if u else None

    def laptop_ips(self, username: str) -> set:
        a = self.laptop(username)
        if not a:
            return set()
        ips = {a.ip} if a.ip else set()
        for e in self.role("dhcp"):
            if str(e.fields.get("hostname", "")).lower() == a.hostname.lower() and e.fields.get("ip"):
                ips.add(e.fields["ip"])
        return ips

    def is_internal(self, ip: Optional[str]) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            return False
        return any(a in n for n in self.nets)

    def is_external(self, ip: Optional[str]) -> bool:
        if not ip or self.is_internal(ip):
            return False
        return not any(a.public_ip == ip for a in self.tables.inventory)

    def in_vpn_pool(self, ip: Optional[str]) -> bool:
        pool = getattr(self.tables.inventory_notes, "vpn_pool", None)
        if not pool or not ip:
            return False
        try:
            a, lo, hi = (ipaddress.ip_address(x) for x in (ip, pool[0], pool[1]))
        except ValueError:
            return False
        return lo <= a <= hi

    def vpn_gateway(self):
        """Asset the VPN log belongs to: perimeter flows from VPN client IPs land on it."""
        vpn_src = {s.src_ip for s in self.sessions if s.src_ip}
        vpn_src |= {e.fields.get("src_ip") for e in self.role("vpn") if e.fields.get("src_ip")}
        for e in self.role("perimeter_fw"):
            if self.src(e) in vpn_src:
                a = self.asset_by_ip(self.dst(e))
                if a:
                    return a
        return next((a for a in self.tables.inventory if "vpn" in a.type.lower()), None)

    def file_asset(self, source_file: str):
        """Asset whose hostname appears in the first heading line of a log file."""
        try:
            p = Path(config.DATA_DIR) / source_file
            if hasattr(self.tables, "_data_dir"):
                p = Path(self.tables._data_dir) / source_file
            head = p.read_text(encoding="utf-8").splitlines()[0]
        except Exception:
            return None
        for a in self.tables.inventory:
            if re.search(r"\b" + re.escape(a.hostname) + r"\b", head):
                return a
        return None

    def alerts_with(self, *, ips=(), users=(), domains=(), near: Optional[datetime] = None,
                    within_s: Optional[float] = None) -> list:
        out = []
        for a in self.tables.alerts:
            hit = (set(ips) & set(a.ips)) or ({u.lower() for u in users} & {u.lower() for u in a.usernames}) \
                or ({d.lower() for d in domains} & {d.lower() for d in a.domains})
            if not hit:
                continue
            if near is not None and within_s is not None and a.ts_utc:
                if abs((parse_utc(a.ts_utc) - near).total_seconds()) > within_s:
                    continue
            out.append(a)
        return out

    def not_collected(self, *keywords: str) -> list:
        out = []
        for n in getattr(self.cov, "not_collected", []) or []:
            name = n["name"].lower()
            if any(re.search(r"\b" + re.escape(k.lower()) + r"\b", name) or k.lower() in name
                   for k in keywords if k):
                out.append(n)
        return out

    def missing_for_asset(self, asset) -> list:
        """Not-collected sources about this asset: by hostname, else by first word of its type."""
        out = []
        for n in getattr(self.cov, "not_collected", []) or []:
            name = n["name"]
            if re.search(r"\b" + re.escape(asset.hostname) + r"\b", name, re.I):
                out.append(n)
        if out:
            return out
        first = (asset.type.split() or [""])[0]
        if first:
            for n in getattr(self.cov, "not_collected", []) or []:
                if re.match(r"^\s*" + re.escape(first) + r"\b", n["name"], re.I):
                    out.append(n)
        return out

    def coverage_row(self, source_file: Optional[str]):
        if not source_file or self.cov is None:
            return None
        return next((s for s in self.cov.sources if s.file == source_file), None)

    def gaps(self, source_file: Optional[str], a: datetime, b: datetime) -> list:
        out = []
        for g in getattr(self.cov, "gaps", []) or []:
            if source_file and g.source != source_file:
                continue
            ga, gb = _dt(g.from_utc), _dt(g.to_utc)
            if ga <= b and gb >= a:
                out.append(g)
        return out


# ------------------------------------------------------------------ finding collector
class _Out:
    def __init__(self, rules: dict):
        self.rules = rules
        self.items: list = []

    def add(self, rule: str, label: str, statement: str, steps: list, evidence: list,
            entities: list, assumption: Optional[str] = None, data: Optional[dict] = None,
            cites_rule: Optional[str] = None) -> Finding:
        if label == SUSPECTED and not assumption:
            raise ValueError(f"{rule}: a suspected finding needs an assumption")
        f = Finding(finding_id="", rule=rule,
                    cites_rule=cites_rule or (self.rules.get(rule) or {}).get("cites", ""),
                    label=label, statement=statement, assumption=assumption,
                    steps=numbered(steps), evidence=_dedupe([c for c in evidence if c]),
                    entities=_dedupe(entities))
        f.data = dict(data or {})
        self.items.append(f)
        return f


# ------------------------------------------------------------------ alerts vs calendar
_ACTOR_WORDS = {"from", "by", "source", "host", "for"}
_TARGET_WORDS = {"to", "against", "on", "in"}


def _direction(desc: str, token: str) -> str:
    i = desc.find(token)
    if i < 0:
        return "target"
    before = re.findall(r"[A-Za-z]+", desc[:i])[-4:]
    for w in reversed(before):
        lw = w.lower()
        if lw in _ACTOR_WORDS:
            return "actor"
        if lw in _TARGET_WORDS:
            return "target"
    return "target"


def alert_activity(ctx: Ctx, alert: Any) -> dict:
    """Turn an IDS alert plus the log lines around it into a calendar activity."""
    desc = alert.description
    cidrs = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b", desc)
    cidr_bases = {c.split("/")[0] for c in cidrs}
    actor = {"ips": [], "users": [], "hosts": [], "names": []}
    targets = {"ips": [], "hosts": [], "cidrs": list(cidrs)}
    for ip in alert.ips:
        if ip in cidr_bases:
            continue
        (actor if _direction(desc, ip) == "actor" else targets)["ips"].append(ip)
    for h in alert.hostnames:
        (actor if _direction(desc, h) == "actor" else targets)["hosts"].append(h)
    for u in alert.usernames:
        if ctx.user_row(u):
            actor["users"].append(u)
    t = parse_utc(alert.ts_utc)
    p = ctx.rules.get("change_approval", {})
    a, b = t - timedelta(seconds=p.get("alert_lookback_s", 900)), t + timedelta(seconds=p.get("alert_lookahead_s", 60))
    a_ips = set(actor["ips"])
    for h in actor["hosts"]:
        asset = ctx.asset_by_host(h)
        if asset and asset.ip:
            a_ips.add(asset.ip)
    a_users = {u.lower() for u in actor["users"]}
    for u in a_users:
        s = next((s for s in ctx.sessions if s.user == u and s.contains(t)), None)
        if s and s.assigned_ip:
            a_ips.add(s.assigned_ip)
    all_ips = a_ips | set(targets["ips"])
    related = []
    for e in ctx.window(a, b):
        if ctx.role_of(e) == "dhcp":
            continue
        s, d, u = ctx.src(e), ctx.dst(e), ctx.user(e)
        if a_ips or a_users:
            if s in a_ips or u in a_users or (d in a_ips and s in all_ips):
                related.append(e)
        elif s in all_ips or d in all_ips:
            related.append(e)
    for e in related:
        d = ctx.dst(e)
        if d and d not in a_ips and d not in targets["ips"]:
            targets["ips"].append(d)
        tgt = e.fields.get("target")
        if tgt and ctx.role_of(e) == "dc" and "\\" not in str(tgt):
            asset = ctx.asset_by_host(str(tgt))
            if asset and asset.hostname not in targets["hosts"]:
                targets["hosts"].append(asset.hostname)
    if related:
        start = min(ctx.start(e) for e in related)
        end = max(ctx.end(e) for e in related)
    else:
        start = end = t
    return {"label": alert.alert_id, "start_utc": to_utc_iso(start), "end_utc": to_utc_iso(end),
            "actor": actor, "targets": targets, "events": [e.event_id for e in related],
            "evidence": [alert.cite] + [ecite(e) for e in related]}


def check_alerts(ctx: Ctx) -> dict:
    p = ctx.rules.get("change_approval", {})
    out = {}
    for al in ctx.tables.alerts:
        act = alert_activity(ctx, al)
        m = match_change(act, ctx.tables, p)
        ctx.calendar_log.append((al.alert_id, act, m))
        out[al.alert_id] = (act, m)
    ctx.alert_checks = out
    return out


def calendar_steps(m: ChangeMatch) -> list:
    if m.approved:
        return [f"Change calendar: {m.change_id} matches. " + "; ".join(m.reasons) + "."]
    near = m.near_misses()
    if not near:
        return ["Change calendar: no change lists this system, actor or window (01 rule 3.1). Not approved."]
    return ["Change calendar: no change approves it (01 rule 3.1 needs system AND actor AND window). "
            + " | ".join(f"{c.change_id}: " + "; ".join(c.reasons) for c in near) + "."]


# ------------------------------------------------------------------ helpers for phishing
def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _label_core(domain: str) -> str:
    first = domain.lower().split(".")[0]
    return re.sub(r"[^a-z0-9]", "", first)


def lookalike(domain: str, company: str, max_d: int) -> Optional[int]:
    """Edit distance between the first labels (ignoring hyphens) if it is a lookalike."""
    if not domain or not company or domain.lower() == company.lower():
        return None
    d = _lev(_label_core(domain), _label_core(company))
    return d if d <= max_d else None


# ------------------------------------------------------------------ detectors
def detect_phishing(ctx: Ctx, out: _Out) -> list:
    p = ctx.rules.get("phishing", {})
    company = getattr(ctx.tables, "company_domain", None)
    thr = getattr(ctx.cov, "quarantine_threshold", None) or p.get("quarantine_threshold_default")
    delivered = set(p.get("delivered_actions", ["delivered"]))
    msgs: dict = {}
    for e in ctx.role("email"):
        f = e.fields
        dom = f.get("from_domain") or (str(f.get("from", "")).split("@")[-1] if f.get("from") else "")
        dist = lookalike(dom, company, p.get("lookalike_max_distance", 2))
        if dist is None or str(f.get("action", "")).lower() not in delivered:
            continue
        msgs.setdefault(f.get("msgid") or e.event_id, []).append((e, dom, dist))
    results = []
    cov_row = ctx.coverage_row(ctx.source_file("email"))
    for msgid, rows in msgs.items():
        evs = [r[0] for r in rows]
        dom, dist = rows[0][1], rows[0][2]
        f0 = evs[0].fields
        recips = []
        for e in evs:
            u = norm_account(e.fields.get("to_user")) or (ctx.user_by_email(e.fields.get("to", "")) or None)
            if hasattr(u, "username"):
                u = u.username
            if u and u not in recips:
                recips.append(u)
        score = f0.get("score")
        link = f0.get("url_host")
        steps = [
            f"Email gateway lines {refs(evs)} show message {msgid} from {f0.get('from')} "
            f"delivered to {', '.join(recips)} at {when(ctx.start(evs[0]))}"
            + (f" to {when(ctx.start(evs[-1]))}" if ctx.start(evs[-1]) != ctx.start(evs[0]) else "") + ".",
            f"Sender domain {dom} is a lookalike of the company domain {company} (from the user "
            f"directory emails): edit distance {dist} after removing hyphens.",
            f"spf={f0.get('spf')}, dkim={f0.get('dkim')}.",
        ]
        if score is not None and thr is not None:
            steps.append(f"Score {score} is below the quarantine threshold {thr} "
                         f"({tref(cov_row.cite) if cov_row else 'f20'}), so it was delivered.")
        if link:
            steps.append(f"The message carries a link to {link}.")
        steps.append("Delivery is shown directly by the log lines: confirmed (01 rule 2.1).")
        ents = [f"actor:msg:{msgid}", f"msg:{msgid}", f"domain:{dom}"] + \
               ([f"domain:{link}"] if link else []) + [f"user:{u}" for u in recips]
        st = (f"Phishing mail {msgid} from lookalike domain {dom} was delivered to "
              f"{', '.join(recips)} (spf={f0.get('spf')}, score {score}"
              + (f", below the {thr} quarantine threshold" if thr is not None and score is not None
                 and float(score) < float(thr) else "") + ").")
        fnd = out.add("phishing_delivered", CONFIRMED, st, steps,
                      [ecite(e) for e in evs] + ([cov_row.cite] if cov_row else []), ents,
                      data={"msgid": msgid, "sender": f0.get("from"), "sender_domain": dom,
                            "link_host": link, "recipients": recips, "score": score,
                            "threshold": thr, "delivered_utc": evs[0].ts_utc,
                            "company_domain": company})
        results.append(fnd)
        detect_clicks(ctx, out, fnd, evs)
    return results


def detect_clicks(ctx: Ctx, out: _Out, delivered: Finding, mail_events: list) -> None:
    d = fdata(delivered)
    link = d.get("link_host")
    msgid = d["msgid"]
    if not link:
        return
    alerts = ctx.alerts_with(domains=[link])
    link_ips = []
    for a in alerts:
        for ip in a.ips:
            if ctx.is_external(ip) and ip not in link_ips:
                link_ips.append(ip)
    t0 = min(ctx.start(e) for e in mail_events)
    fw_row = ctx.coverage_row(ctx.source_file("perimeter_fw"))
    for u in d["recipients"]:
        lap = ctx.laptop(u)
        ips = ctx.laptop_ips(u)
        conns = [e for e in ctx.role("perimeter_fw")
                 if ctx.src(e) in ips and ctx.dst(e) in link_ips and ctx.start(e) >= t0
                 and str(e.fields.get("action", "")).upper() != "DENY"]
        urow = ctx.user_row(u)
        mail = next((e for e in mail_events if norm_account(e.fields.get("to_user")) == u), mail_events[0])
        lap_txt = f"{lap.hostname} ({lap.tag}, {', '.join(sorted(ips))})" if lap else "no laptop on record"
        if conns:
            c = conns[0]
            mins = int((ctx.start(c) - ctx.start(mail)).total_seconds() // 60)
            al = [a for a in alerts if ctx.src(c) in a.ips or ctx.dst(c) in a.ips]
            steps = [
                f"{u}'s laptop from the user directory is {lap_txt} ({tref(urow.cite)}, "
                f"{tref(lap.cite) if lap else ''}).",
                f"Perimeter firewall {ref(c)}: {ctx.src(c)} connected to {ctx.dst(c)}:{c.fields.get('dst_port')} "
                f"at {when(ctx.start(c))}, {num(c.fields.get('bytes'))} bytes, {mins} minutes after delivery ({ref(mail)}).",
                f"{', '.join(a.alert_id for a in al)} says {ctx.dst(c)} hosts the link domain {link}.",
                f"A recipient device connecting to the link host's IP is a click seen ({rbref(ctx, 'phishing', 4)}): confirmed.",
            ]
            st = (f"{u}'s laptop {lap.hostname if lap else ''} connected to {ctx.dst(c)} at {when(ctx.start(c))}. "
                  f"The IDS says that IP hosts the link domain {link} ({', '.join(a.alert_id for a in al)}). "
                  f"Click seen for {u}.")
            ents = [f"actor:msg:{msgid}", f"actor:ext_ip:{ctx.dst(c)}", f"user:{u}",
                    f"ext_ip:{ctx.dst(c)}", f"ip:{ctx.src(c)}", f"domain:{link}"] + \
                   ([f"asset:{lap.tag}"] if lap else []) + [f"alert:{a.alert_id}" for a in al]
            data = {"user": u, "laptop_host": lap.hostname if lap else None,
                    "laptop_tag": lap.tag if lap else None, "laptop_ip": ctx.src(c),
                    "link_ip": ctx.dst(c), "link_host": link, "msgid": msgid, "time": c.ts_utc,
                    "alerts": [a.alert_id for a in al]}
            out.add("phishing_click", CONFIRMED, st, steps,
                    [ecite(c), ecite(mail), urow.cite if urow else None, lap.cite if lap else None]
                    + [a.cite for a in al], ents, data=data)
            ents2 = [f"actor:msg:{msgid}", f"actor:ext_ip:{ctx.dst(c)}", f"user:{u}"]
            out.add("phishing_credential_entry", SUSPECTED,
                    f"Credentials may have been entered on the phishing page after {u}'s click.",
                    [f"A click is seen for {u} at {when(ctx.start(c))} ({ref(c)}).",
                     "No log shows what was typed on the page (no proxy or endpoint log).",
                     "The matrix note handles a phishing click as credential compromise (03 rule note).",
                     "Linking the click to a stolen password needs a guess: suspected (01 rule 2.2)."],
                    [ecite(c), ctx.tables.matrix.cite], ents2,
                    assumption="The click led to the password being typed into the phishing page.",
                    data={"user": u})
        else:
            p = ctx.rules.get("phishing_no_click", {})
            miss = ctx.not_collected(*p.get("missing_source_keywords", ["proxy"]))
            mtxt = "; ".join(f"{m['name']}: {m['reason']}" for m in miss) or "no other source"
            st = (f"Whether {u} opened the link by another path is not shown: the firewall shows no "
                  f"connection from {u}'s laptop to {', '.join(link_ips) or link}, and {mtxt}.")
            steps = [
                f"{u}'s laptop is {lap_txt} ({tref(urow.cite) if urow else ''}).",
                f"No perimeter firewall line from {', '.join(sorted(ips)) or 'that laptop'} to "
                f"{', '.join(link_ips) or link} after delivery ({ref(mail)}); the perimeter firewall covers the full day"
                + (f" ({tref(fw_row.cite)})" if fw_row else "") + ".",
                f"Missing source: {mtxt} ({', '.join(tref(m['cite']) for m in miss)}).",
                "No click is seen; another path cannot be ruled out: not enough evidence in the logs (01 rule 2.3).",
            ]
            out.add("phishing_no_click", NOT_ENOUGH_EVIDENCE, st, steps,
                    [ecite(mail), urow.cite if urow else None, fw_row.cite if fw_row else None]
                    + [m["cite"] for m in miss],
                    [f"actor:msg:{msgid}", f"user:{u}"] + ([f"asset:{lap.tag}"] if lap else []),
                    data={"user": u, "missing": [m["name"] for m in miss], "msgid": msgid})


def detect_mfa_fatigue(ctx: Ctx, out: _Out) -> list:
    p = ctx.rules.get("mfa_fatigue", {})
    fail_reasons = set(p.get("fail_reasons", []))
    approved = set(p.get("approved_mfa", ["push_approved"]))
    win = p.get("window_s", 900)
    vpn = ctx.role("vpn")
    succ = [e for e in vpn if str(e.fields.get("result", "")).upper() == "SUCCESS"]
    geos = [e.fields.get("geo") for e in succ if e.fields.get("geo")]
    found = []
    by_user: dict = {}
    for e in vpn:
        u = ctx.user(e)
        if u:
            by_user.setdefault(u, []).append(e)
    gw = ctx.vpn_gateway()
    for u, evs in by_user.items():
        fails: list = []
        for e in evs:
            f = e.fields
            res = str(f.get("result", "")).upper()
            if res == "FAIL" and str(f.get("reason", "")) in fail_reasons:
                fails = [x for x in fails if (ctx.start(e) - ctx.start(x)).total_seconds() <= win]
                fails.append(e)
                continue
            if res != "SUCCESS":
                continue
            if f.get("mfa") not in approved or len(fails) < p.get("min_rejected", 2):
                fails = []
                continue
            if p.get("require_same_source", True):
                same = [x for x in fails if x.fields.get("src_ip") == f.get("src_ip")]
            else:
                same = fails
            if len(same) < p.get("min_rejected", 2):
                fails = []
                continue
            prev_geos = {x.fields.get("geo") for x in succ if ctx.user(x) == u and ctx.start(x) < ctx.start(e)}
            if prev_geos:
                baseline, basis = prev_geos, f"{u}'s earlier successful logins"
            else:
                others = [g for x, g in ((x, x.fields.get("geo")) for x in succ) if ctx.user(x) != u and g]
                common = statistics.multimode(others) if others else []
                baseline, basis = set(common), "the usual country of successful VPN logins in the log (no earlier login by this user)"
            new_geo = f.get("geo") not in baseline
            if p.get("require_new_geo", True) and not new_geo:
                fails = []
                continue
            sid = f.get("session")
            s = ctx.session(sid) if sid else None
            reasons = ", ".join(x.fields.get("reason", "") for x in same)
            al = ctx.alerts_with(users=[u], ips=[f.get("src_ip")], near=ctx.start(e), within_s=600)
            steps = [
                f"{len(same)} rejected or timed-out MFA pushes for {u} from {f.get('src_ip')} ({f.get('geo')}) "
                f"between {hms(ctx.start(same[0]))} and {hms(ctx.start(same[-1]))} UTC ({refs(same)}): {reasons}.",
                f"Then an approved push from the same IP at {when(ctx.start(e))} ({ref(e)}), session {sid}, "
                f"assigned {f.get('assigned_ip')}.",
                f"Country {f.get('geo')} is new: not in {', '.join(sorted(baseline)) or 'none'} ({basis}).",
                "Rule 6.1: several rejected pushes followed by an approved push from a new country is a sign "
                "of a stolen password. The log lines show the pattern directly: confirmed.",
            ]
            if al:
                steps.append(f"{', '.join(a.alert_id for a in al)} corroborates the login from a new country.")
            if gw:
                steps.append(f"The login is a confirmed session on {gw.hostname} ({gw.tag}, {gw.criticality}).")
            st = (f"{len(same)} rejected or timed-out MFA pushes for {u}, then an approved push from "
                  f"{f.get('src_ip')} ({f.get('geo')}), same IP, at {when(ctx.start(e))}: session {sid}. "
                  f"Rule 6.1 treats this as a sign of a stolen password.")
            ents = [f"actor:ext_ip:{f.get('src_ip')}"] + ([f"actor:session:{sid}"] if sid else []) + \
                   [f"user:{u}", f"ext_ip:{f.get('src_ip')}"] + ([f"session:{sid}"] if sid else []) + \
                   ([f"ip:{f.get('assigned_ip')}"] if f.get("assigned_ip") else []) + \
                   ([f"asset:{gw.tag}"] if gw else []) + [f"alert:{a.alert_id}" for a in al]
            fw = [x for x in ctx.role("perimeter_fw") if ctx.src(x) == f.get("src_ip")
                  and abs((ctx.start(x) - ctx.start(e)).total_seconds()) <= win]
            data = {"user": u, "src_ip": f.get("src_ip"), "geo": f.get("geo"), "session_id": sid,
                    "assigned_ip": f.get("assigned_ip"), "time": e.ts_utc,
                    "reach": [{"tag": gw.tag, "time": e.ts_utc, "kerberos_only": False}] if gw else [],
                    "alerts": [a.alert_id for a in al]}
            fnd = out.add("mfa_fatigue", CONFIRMED, st, steps,
                          [ecite(x) for x in same] + [ecite(e)] + [ecite(x) for x in fw]
                          + [a.cite for a in al] + ([gw.cite] if gw else []), ents, data=data)
            found.append((fnd, s))
            fails = []
    return found


def detect_attacker_session(ctx: Ctx, out: _Out, sess: Sess, outliers: set) -> None:
    p = ctx.rules.get("attacker_session", {})
    ap = ctx.rules.get("asset_session", {})
    if not sess or not sess.assigned_ip or not sess.start:
        return
    ip, u, sid = sess.assigned_ip, sess.user, sess.session_id
    end = sess.end or datetime.max.replace(tzinfo=timezone.utc)
    inside = [e for e in ctx.events if ctx.src(e) == ip and sess.start <= ctx.start(e) <= end]
    chain = (f"{ip} is {u} only inside {sid} ({tref(sess.login_cite) if sess.login_cite else ''}"
             f"{' to ' + tref(sess.end_cite) if sess.end_cite else ''})")
    base_ents = [f"actor:session:{sid}", f"user:{u}", f"session:{sid}", f"ip:{ip}"]
    # Kerberos tickets
    kerb = [e for e in inside if ctx.role_of(e) == "dc"
            and re.search(p.get("kerberos_pattern", "kerberos"), str(e.fields.get("description", "")))]
    if kerb:
        services, assets = [], []
        for e in kerb:
            svc = e.fields.get("service")
            if svc:
                services.append(svc)
                host = re.sub(r":\d+$", "", svc.split("/", 1)[-1])
                a = ctx.asset_by_host(host)
                if a:
                    assets.append(a)
        items = [f"{e.fields.get('description')} at {hms(ctx.start(e))}"
                 + (f" for {e.fields['service']}" if e.fields.get("service") else "")
                 + (f" (workstation {e.fields['workstation']})" if e.fields.get("workstation") else "")
                 + f" [{ref(e)}]" for e in kerb]
        st = (f"From {ip} ({u} only inside {sid}): " + "; ".join(
            f"{e.fields.get('description')} at {hms(ctx.start(e))} UTC"
            + (f" for {e.fields['service']}" if e.fields.get("service") else "") for e in kerb) + ".")
        out.add("attacker_session", CONFIRMED, st,
                [chain + ".", "Domain controller lines with that client IP inside the session window: "
                 + "; ".join(items) + ".",
                 "Tickets show the account asked for access; a ticket alone is not a session on the server.",
                 "Shown directly by the log lines: confirmed."],
                [ecite(e) for e in kerb] + [sess.login_cite, sess.end_cite],
                base_ents + [f"asset:{a.tag}" for a in assets],
                data={"user": u, "session_id": sid, "services": services,
                      "service_assets": [a.tag for a in assets]})
    # Interactive logons on a host (e.g. remote desktop to the DC)
    for e in inside:
        if ctx.role_of(e) != "dc" or not e.fields.get("target") or "\\" in str(e.fields.get("target")):
            continue
        if not re.search(p.get("interactive_logon_pattern", "logon type"), str(e.fields.get("description", ""))):
            continue
        a = ctx.asset_by_host(str(e.fields["target"]))
        if not a:
            continue
        out.add("interactive_logon", CONFIRMED,
                f"{u} logged on to {a.hostname} from {ip} at {when(ctx.start(e))} ({e.fields.get('description')}).",
                [chain + ".", f"{ref(e)}: {e.fields.get('description')} with target {e.fields['target']}.",
                 "A logon event with the host as target is a confirmed login on it (01 rule 4.1)."],
                [ecite(e), a.cite], base_ents + [f"asset:{a.tag}"],
                data={"reach": [{"tag": a.tag, "time": e.ts_utc, "kerberos_only": False}]})
    # Network sessions to assets
    kports = set(ap.get("kerberos_ports", [88]))
    per_asset: dict = {}
    for e in inside:
        if ctx.role_of(e) != "internal_fw" or e.event_id in outliers:
            continue
        if str(e.fields.get("action", "")).upper() == "DENY":
            continue
        a = ctx.asset_by_ip(ctx.dst(e))
        if a:
            per_asset.setdefault(a.tag, (a, []))[1].append(e)
    for tag, (a, evs) in per_asset.items():
        ports = sorted({int(e.fields.get("dst_port")) for e in evs if e.fields.get("dst_port") is not None})
        k_only = bool(ports) and set(ports) <= kports
        desc = "; ".join(f"{a.hostname}:{e.fields.get('dst_port')} {span(ctx.start(e), ctx.end(e))}, "
                         f"{num(e.fields.get('bytes_server_to_client') or e.fields.get('bytes_total'))} bytes, "
                         f"{e.fields.get('duration_s')} s [{ref(e)}]" for e in evs)
        steps = [chain + ".",
                 f"Internal firewall sessions from {ip} to {a.hostname} ({a.tag}, {a.criticality}): {desc}.",
                 "Internal firewall times are session close in PKT; start = close minus duration (f20).",
                 "Shown directly by the log lines: confirmed."]
        if k_only:
            steps.append(f"Only Kerberos traffic (port {', '.join(map(str, ports))}): this is not a logon on "
                         f"{a.hostname} (ARCHITECTURE section 11).")
        tot = sum(int(e.fields.get("bytes_server_to_client") or e.fields.get("bytes_total") or 0) for e in evs)
        st = (f"From {ip} ({u} inside {sid}): session(s) to {a.hostname}:{', '.join(map(str, ports))}, "
              f"{span(ctx.start(evs[0]), ctx.end(evs[-1]))}, {num(tot)} bytes.")
        out.add("asset_session", CONFIRMED, st, steps, [ecite(e) for e in evs] + [a.cite],
                base_ents + [f"asset:{a.tag}"] + [f"port:{x}" for x in ports],
                data={"reach": [{"tag": a.tag, "time": evs[0].ts_utc, "kerberos_only": k_only}],
                      "events": [e.event_id for e in evs], "bytes": tot, "ports": ports,
                      "duration_s": sum(int(e.fields.get("duration_s") or 0) for e in evs)})
    # Password reset of the account from the session IP
    resets = [e for e in inside if ctx.role_of(e) == "dc"
              and re.search(p.get("password_reset_pattern", "password"), str(e.fields.get("description", "")))
              and norm_account(e.fields.get("target") or e.fields.get("account")) == u]
    for e in resets:
        mails = [m for m in ctx.role("email") if norm_account(m.fields.get("to_user")) == u
                 and 0 <= (ctx.start(m) - ctx.start(e)).total_seconds() <= p.get("notice_mail_window_s", 300)
                 and lookalike(m.fields.get("from_domain", ""), ctx.tables.company_domain, 0) is None]
        steps = [chain + ".",
                 f"{ref(e)}: {e.fields.get('description')} of {e.fields.get('target')} by "
                 f"{e.fields.get('caller')} from {ip} at {when(ctx.start(e))}, result {e.fields.get('result')}."]
        if mails:
            steps.append(f"A notice mail to {u} follows at {hms(ctx.start(mails[0]))} UTC ({ref(mails[0])}).")
        steps.append("Shown directly by the log line: confirmed.")
        out.add("password_reset", CONFIRMED,
                f"Password reset of {u} by {u} from {ip} (inside {sid}) at {when(ctx.start(e))}.",
                steps, [ecite(e)] + [ecite(m) for m in mails], base_ents,
                data={"user": u, "time": e.ts_utc, "event": e.event_id})
        # Later lockout of the real user (from a client other than the session IP)
        later = [x for x in ctx.role("dc") if ctx.user(x) == u and ctx.start(x) > ctx.start(e)
                 and ctx.src(x) != ip
                 and (re.search(p.get("lockout_pattern", "lock"), str(x.fields.get("description", "")))
                      or re.search(p.get("failed_logon_pattern", "failed"), str(x.fields.get("description", ""))))]
        locks = [x for x in later if re.search(p.get("lockout_pattern", "lock"), str(x.fields.get("description", "")))]
        if locks:
            lk = locks[0]
            ws = {x.fields.get("workstation") or x.fields.get("caller") for x in later} - {None}
            lap = ctx.laptop(u)
            al = ctx.alerts_with(users=[u], near=ctx.start(lk), within_s=p.get("lockout_alert_window_s", 300))
            fails = [x for x in later if x is not lk and ctx.start(x) <= ctx.start(lk)]
            steps = [f"After the reset at {hms(ctx.start(e))} UTC ({ref(e)}), logons for {u} fail from "
                     f"{', '.join(sorted(ws))} ({refs(fails)}): "
                     + ", ".join(str(x.fields.get("reason") or x.fields.get("description")) for x in fails) + ".",
                     f"Account locked out at {when(ctx.start(lk))} ({ref(lk)})."]
            if lap and lap.hostname in ws:
                steps.append(f"{lap.hostname} is {u}'s own laptop ({tref(lap.cite)}): the real user, not the session.")
            if al:
                steps.append(f"{', '.join(a.alert_id for a in al)} reports the lockout.")
            steps.append("Shown directly by the log lines: confirmed. It follows the password reset made from the session.")
            out.add("account_lockout", CONFIRMED,
                    f"After the password reset from {ip}, the real user {u} failed to log on at "
                    f"{', '.join(sorted(ws))} and was locked out at {when(ctx.start(lk))}.",
                    steps, [ecite(x) for x in fails] + [ecite(lk)] + [a.cite for a in al]
                    + ([lap.cite] if lap else []),
                    base_ents + ([f"asset:{lap.tag}"] if lap else []) + [f"alert:{a.alert_id}" for a in al],
                    data={"user": u, "time": lk.ts_utc, "alerts": [a.alert_id for a in al]})


def _transfer_bytes(e: Event) -> Optional[int]:
    f = e.fields
    v = f.get("bytes_server_to_client")
    if v is None:
        v = f.get("bytes_total", f.get("bytes"))
    return _int(v)


def transfer_outliers(ctx: Ctx) -> list:
    """Internal firewall sessions whose byte count is an outlier (median and MAD)."""
    p = ctx.rules.get("large_transfer", {})
    evs = [e for e in ctx.role("internal_fw") if _transfer_bytes(e)]
    if len(evs) < 3:
        return []
    log = p.get("scale", "log10") == "log10"
    vals = [math.log10(_transfer_bytes(e)) if log else float(_transfer_bytes(e)) for e in evs]
    med = statistics.median(vals)
    mad = statistics.median([abs(v - med) for v in vals])
    out = []
    for e, v in zip(evs, vals):
        z = 0.6745 * (v - med) / mad if mad > 0 else (math.inf if v > med else 0.0)
        if z >= p.get("modified_z_threshold", 3.5) and _transfer_bytes(e) >= p.get("min_bytes", 0):
            out.append((e, z, med, mad, len(evs)))
    return out


def detect_large_transfer(ctx: Ctx, out: _Out) -> list:
    res = []
    p = ctx.rules.get("large_transfer", {})
    for e, z, med, mad, n in transfer_outliers(ctx):
        b = _transfer_bytes(e)
        src_asset = ctx.asset_by_ip(ctx.dst(e))  # server side of the session
        dest = ctx.src(e)
        s = ctx.session_for_ip(dest, ctx.start(e))
        al = [a for a in ctx.alerts_with(ips=[dest]) if re.search(r"(?i)transfer|smb|large", a.description)]
        steps = [
            f"Internal firewall {ref(e)}: {dest}:{e.fields.get('src_port')} -> {ctx.dst(e)}:{e.fields.get('dst_port')}"
            f" ({src_asset.hostname if src_asset else '?'}), {num(b)} bytes server to client, "
            f"{e.fields.get('duration_s')} s.",
            f"The log time is the session close in PKT ({hms_pkt(ctx.end(e))} PKT); start = close minus duration: "
            f"{span(ctx.start(e), ctx.end(e))} (f20 Internal firewall row).",
            f"Outlier: modified z-score {z:.1f} of log10(bytes) against the median and MAD of {n} internal "
            f"firewall sessions (threshold {p.get('modified_z_threshold', 3.5)}, {rbref(ctx, 'exfiltration', 1)}).",
        ]
        ents = [f"ip:{dest}"]
        data = {"bytes": b, "start": e.ts_utc, "end": e.ts_end_utc or e.ts_utc, "dest_ip": dest,
                "source_tag": src_asset.tag if src_asset else None,
                "source_host": src_asset.hostname if src_asset else None,
                "event": e.event_id, "duration_s": e.fields.get("duration_s"),
                "reach": [{"tag": src_asset.tag, "time": e.ts_utc, "kerberos_only": False}] if src_asset else []}
        ev = [ecite(e)] + ([src_asset.cite] if src_asset else [])
        if s:
            ents = [f"actor:session:{s.session_id}", f"user:{s.user}", f"session:{s.session_id}"] + ents
            data.update(session_id=s.session_id, user=s.user, session_bytes=s.bytes_to_client)
            ev += [x for x in (s.login_cite, s.end_cite) if x]
            if s.bytes_to_client:
                ok = s.bytes_to_client >= b
                steps.append(f"{dest} belongs to {s.user} only inside {s.session_id}; that session sent "
                             f"{num(s.bytes_to_client)} bytes to the client "
                             f"({tref(s.end_cite) if s.end_cite else 'VPN log'}): "
                             + ("consistent with the transfer." if ok else "smaller than the transfer, not consistent."))
        else:
            ents = [f"actor:ip:{dest}"] + ents
        if src_asset:
            ents.append(f"asset:{src_asset.tag}")
        for a in al:
            m = re.search(r"(\d+(?:\.\d+)?)\s*(GB|MB|TB)", a.description)
            if m:
                size = float(m.group(1)) * {"MB": 1e6, "GB": 1e9, "TB": 1e12}[m.group(2)]
                ok = abs(size - b) / b <= p.get("alert_size_tolerance", 0.15)
                steps.append(f"{a.alert_id} reports about {m.group(1)} {m.group(2)}: "
                             + ("consistent." if ok else "not consistent."))
            else:
                steps.append(f"{a.alert_id} reports the transfer.")
            ents.append(f"alert:{a.alert_id}")
            ev.append(a.cite)
        act = {"label": f"transfer {ref(e)}", "start_utc": e.ts_utc, "end_utc": e.ts_end_utc or e.ts_utc,
               "actor": {"ips": [dest], "users": [s.user] if s else [], "hosts": [], "names": []},
               "targets": {"ips": [ctx.dst(e)], "hosts": [], "cidrs": []}}
        m = match_change(act, ctx.tables, ctx.rules.get("change_approval", {}))
        ctx.calendar_log.append((act["label"], act, m))
        steps += calendar_steps(m)
        steps.append("A large transfer is evidence of a transfer, not of which files were read (01 rule 2.4). "
                     "The transfer itself is shown by the log line: confirmed.")
        st = (f"A transfer of {num(b)} bytes from {src_asset.hostname if src_asset else ctx.dst(e)} to {dest}"
              + (f" (inside {s.session_id})" if s else "")
              + f", {span(ctx.start(e), ctx.end(e))}."
              + (f" Consistent with the VPN session total of {num(s.bytes_to_client)} bytes" if s and s.bytes_to_client
                 and s.bytes_to_client >= b else "")
              + (f" and {', '.join(a.alert_id for a in al)}." if al else ".")
              + " It shows a transfer, not which files were read.")
        res.append(out.add("large_transfer", CONFIRMED, st, steps, ev, ents, data=data))
    return res


def _office_activity(ctx: Ctx, user: str, exclude_ips: set) -> list:
    roles = set(ctx.rules.get("concurrent_use", {}).get("activity_roles", ["dc", "perimeter_fw", "internal_fw"]))
    lap = ctx.laptop(user)
    ips = ctx.laptop_ips(user)
    out = []
    for e in ctx.events:
        r = ctx.role_of(e)
        if r not in roles:
            continue
        s = ctx.src(e)
        if s in exclude_ips or ctx.in_vpn_pool(s):
            continue
        if r == "dc":
            ws = e.fields.get("workstation") or e.fields.get("caller")
            if ctx.user(e) == user and (s in ips or (lap and ws == lap.hostname) or (s and not ctx.in_vpn_pool(s))):
                out.append(e)
        elif s in ips:
            out.append(e)
    return out


def detect_concurrent_use(ctx: Ctx, out: _Out, attacker_sessions: list) -> list:
    res = []
    att_ids = {s.session_id for s in attacker_sessions if s}
    for s in ctx.sessions:
        if not s.start:
            continue
        end = s.end or datetime.max.replace(tzinfo=timezone.utc)
        session_ips = {x.assigned_ip for x in ctx.sessions if x.user == s.user and x.assigned_ip}
        act = _office_activity(ctx, s.user, session_ips)
        inside = [e for e in act if s.start <= ctx.start(e) <= end]
        lap = ctx.laptop(s.user)
        urow = ctx.user_row(s.user)
        lap_txt = f"{lap.hostname} ({lap.tag})" if lap else "the office laptop"
        sess_txt = (f"VPN session {s.session_id} for {s.user} from {s.src_ip} ({s.geo}) runs "
                    f"{span(s.start, s.end) if s.end else when(s.start) + ' onward'} "
                    f"({', '.join(tref(c) for c in (s.login_cite, s.end_cite) if c)}).")
        ev = [c for c in (s.login_cite, s.end_cite) if c] + ([lap.cite] if lap else []) + ([urow.cite] if urow else [])
        ents = [f"actor:session:{s.session_id}", f"user:{s.user}", f"session:{s.session_id}"] + \
               ([f"asset:{lap.tag}"] if lap else [])
        if inside:
            steps = [sess_txt,
                     f"Office laptop {lap_txt} is {s.user}'s laptop in the user directory"
                     f"{' (' + tref(urow.cite) + ')' if urow else ''}.",
                     "Activity from the office side inside the session window: " + "; ".join(
                         f"{e.fields.get('description') or 'connection to ' + str(ctx.dst(e))} at "
                         f"{hms(ctx.start(e))} UTC [{ref(e)}]" for e in inside) + ".",
                     "The overlap itself is confirmed by these lines (01 rule 2.1).",
                     "Rule 6.2: the same user active from two places at the same time is a sign of account "
                     "misuse. That the two are different people is a guess: suspected.",
                     "DHCP leases are not counted as activity."]
            mails = [m for m in ctx.role("email") if norm_account(m.fields.get("to_user")) == s.user
                     and lookalike(m.fields.get("from_domain", ""), ctx.tables.company_domain,
                                   ctx.rules.get("phishing", {}).get("lookalike_max_distance", 2)) is not None]
            for m in mails:
                if ctx.start(m) > s.start:
                    steps.append(f"{s.user} received {m.fields.get('msgid')} at {hms(ctx.start(m))} UTC ({ref(m)}), "
                                 f"after the VPN login at {hms(s.start)} UTC, so the mail did not cause the session.")
            st = (f"{s.user}'s VPN session {s.session_id} from {s.src_ip} ({s.geo}), "
                  f"{span(s.start, s.end) if s.end else when(s.start)}, overlaps activity on office laptop "
                  f"{lap_txt} at {hms(ctx.start(inside[0]))} UTC ({ref(inside[0])}). The overlap is confirmed; "
                  f"account misuse is suspected (01 rule 6.2).")
            res.append(out.add("concurrent_use", SUSPECTED, st, steps, ev + [ecite(e) for e in inside], ents,
                               assumption="The VPN session and the office laptop are not used by the same person.",
                               data={"user": s.user, "session_id": s.session_id, "weak": False,
                                     "overlap_events": [e.event_id for e in inside]}))
            _session_coverage(ctx, out, s, rule="concurrent_use", ents=ents)
        elif s.session_id in att_ids and act:
            before = [e for e in act if ctx.start(e) < s.start]
            after = [e for e in act if ctx.start(e) > end]
            steps = [sess_txt,
                     f"Office laptop {lap_txt} is {s.user}'s laptop"
                     f"{' (' + tref(urow.cite) + ')' if urow else ''}; it is active the same day"
                     + (f" before the session ({hms(ctx.start(before[-1]))} UTC, {ref(before[-1])})" if before else "")
                     + (f" and after it ({hms(ctx.start(after[0]))} UTC, {ref(after[0])})" if after else "") + ".",
                     "No log line shows the office laptop active inside the session window.",
                     "Rule 6.2 would need both places active at the same time; that is a guess here: suspected, "
                     "weaker than an overlap seen in the logs."]
            st = (f"Possible concurrent use of {s.user}: session {s.session_id} from {s.src_ip} ({s.geo}) while the "
                  f"real user works from {lap_txt} the same day. No log shows the laptop active during the session.")
            res.append(out.add("concurrent_use", SUSPECTED, st, steps,
                               ev + [ecite(x) for x in (before[-1:] + after[:1])], ents,
                               assumption="The real user was active on the office laptop during the attacker's "
                                          "session. No log shows it.",
                               data={"user": s.user, "session_id": s.session_id, "weak": True}))
    return res


def _session_coverage(ctx: Ctx, out: _Out, s: Sess, rule: str, ents: list) -> None:
    """Not-enough-evidence findings for gaps inside a flagged session and silent sources."""
    end = s.end or datetime.max.replace(tzinfo=timezone.utc)
    for role in ("dc", "internal_fw"):
        sf = ctx.source_file(role)
        row = ctx.coverage_row(sf)
        for g in ctx.gaps(sf, s.start, end):
            a, b = max(s.start, _dt(g.from_utc)), min(end, _dt(g.to_utc))
            hidden = [e for e in ctx.events if ctx.src(e) == s.assigned_ip and a <= ctx.start(e) <= b
                      and ctx.role_of(e) != role]
            src_name = row.source if row else sf
            if role == "dc":
                st = (f"{src_name} activity between {hms(a)} and {hms(b)} UTC (inside {s.session_id}) is not in the "
                      f"logs: coverage is {row.coverage if row else 'partial'}.")
            else:
                st = (f"Any session from {s.assigned_ip} closing between {hms(a)} and {hms(b)} UTC "
                      f"[{hms_pkt(a)} to {hms_pkt(b)} PKT] is not in the {src_name.lower()} log ({g.reason}).")
            if hidden:
                st += " " + "; ".join(f"The {hms(ctx.start(e))} UTC {str(e.fields.get('description') or e.kind).lower()} "
                                     f"from {s.assigned_ip} has no {src_name.lower()} record for this reason"
                                     for e in hidden) + "."
            steps = [f"{s.session_id} runs {span(s.start, s.end) if s.end else when(s.start)}.",
                     f"Coverage sheet ({tref(g.evidence[0]) if g.evidence else 'f20'}): {src_name} gap "
                     f"{hms(g.from_utc)} to {hms(g.to_utc)} UTC: {g.reason}.",
                     f"Overlap with the session: {hms(a)} to {hms(b)} UTC.",
                     "The logs are silent there: not enough evidence in the logs (01 rule 2.3). No guess is made."]
            out.add(rule, NOT_ENOUGH_EVIDENCE, st, steps,
                    list(g.evidence) + [ecite(e) for e in hidden] + [c for c in (s.login_cite,) if c],
                    ents, data={"gap_source": sf, "from": to_utc_iso(a), "to": to_utc_iso(b),
                                "kind": "gap", "session_id": s.session_id},
                    cites_rule=f"{(ctx.rules.get(rule) or {}).get('cites', '')}; 20 coverage")
    fw = ctx.source_file("internal_fw")
    if fw and s.assigned_ip and not [e for e in ctx.role("internal_fw") if ctx.src(e) == s.assigned_ip
                                     and s.start <= ctx.start(e) <= end]:
        row = ctx.coverage_row(fw)
        out.add(rule, NOT_ENOUGH_EVIDENCE,
                f"No {(row.source if row else 'internal firewall').lower()} line shows traffic from {s.assigned_ip} "
                f"during {s.session_id}: what the session reached is not in the logs.",
                [f"{s.session_id} was assigned {s.assigned_ip} ({tref(s.login_cite) if s.login_cite else 'VPN log'}).",
                 f"No line in {fw} has source {s.assigned_ip} inside the session window.",
                 "The logs are silent: not enough evidence in the logs (01 rule 2.3)."],
                [c for c in (s.login_cite, row.cite if row else None) if c], ents,
                data={"kind": "silent", "session_id": s.session_id},
                cites_rule=f"{(ctx.rules.get(rule) or {}).get('cites', '')}; 20 coverage")


def detect_web_attack(ctx: Ctx, out: _Out) -> list:
    p = ctx.rules.get("web_attack", {})
    ps = ctx.rules.get("web_attack_success", {})
    pats = [re.compile(x) for x in p.get("attack_patterns", [])]
    uas = [re.compile(x) for x in p.get("attack_user_agents", [])]
    groups: dict = {}
    for e in ctx.role("web"):
        path = unquote_plus(str(e.fields.get("path", "")))
        ua = str(e.fields.get("user_agent", ""))
        if any(r.search(path) for r in pats) or any(r.search(ua) for r in uas):
            groups.setdefault(ctx.src(e), []).append(e)
    res = []
    for ip, evs in groups.items():
        if not ctx.is_external(ip):
            continue
        fw = [x for x in ctx.role("perimeter_fw") if ctx.src(x) == ip]
        asset = next((ctx.asset_by_ip(ctx.dst(x)) for x in fw if ctx.asset_by_ip(ctx.dst(x))), None) \
            or ctx.file_asset(evs[0].source_file)
        al = ctx.alerts_with(ips=[ip])
        paths = sorted({str(e.fields.get("path", "")).split("?")[0] for e in evs})
        statuses = [int(e.fields.get("status") or 0) for e in evs]
        errs = [e for e in evs if int(e.fields.get("status") or 0) >= 400]
        tools = sorted({m.group(0) for e in evs for r in uas for m in [r.search(str(e.fields.get("user_agent", "")))] if m})
        ents = [f"actor:ext_ip:{ip}", f"ext_ip:{ip}"] + ([f"asset:{asset.tag}"] if asset else []) + \
               [f"alert:{a.alert_id}" for a in al]
        host = asset.hostname if asset else "the web server"
        steps = [f"Web server lines {refs(evs)}: {len(evs)} requests from {ip} to {', '.join(paths)} match "
                 f"attack patterns (rules.yaml web_attack)" + (f", user agent {', '.join(tools)}" if tools else "") + ".",
                 f"Status codes: {', '.join(map(str, statuses))}. A 4xx or 5xx response is an attempt ({rbref(ctx, 'web', 3)})."]
        if fw:
            steps.append(f"Perimeter firewall {refs(fw)} allowed {ip} to {ctx.dst(fw[0])}:{fw[0].fields.get('dst_port')}"
                         + (f" ({host}, {asset.tag}, {asset.criticality})" if asset else "") + ".")
        if al:
            steps.append(f"{', '.join(a.alert_id for a in al)} reports the same source.")
        steps.append("The requests are shown directly by the log lines: confirmed.")
        st = (f"{ip} sent {len(evs)} attack requests"
              + (f" ({', '.join(tools)})" if tools else "") + f" to {', '.join(paths)} on {host}, "
              f"{span(ctx.start(evs[0]), ctx.start(evs[-1]))}.")
        data = {"src_ip": ip, "asset_tag": asset.tag if asset else None, "host": host, "paths": paths,
                "count": len(evs), "statuses": statuses, "alerts": [a.alert_id for a in al],
                "reach": [{"tag": asset.tag, "time": (fw[0] if fw else evs[0]).ts_utc, "kerberos_only": False}] if asset else []}
        res.append(out.add("web_attack", CONFIRMED, st, steps,
                           [ecite(e) for e in evs] + [ecite(x) for x in fw] + [a.cite for a in al]
                           + ([asset.cite] if asset else []), ents, data=data))
        err_size = int(statistics.median([int(e.fields.get("size") or 0) for e in errs])) if errs else None
        wins = [e for e in evs if int(e.fields.get("status") or 0) == ps.get("success_status", 200)
                and err_size and int(e.fields.get("size") or 0) >= ps.get("min_size_ratio", 3) * err_size]
        for w in wins:
            ratio = int(w.fields.get("size")) / err_size
            out.add("web_attack_success", SUSPECTED,
                    f"Success of the attack is suspected: the request at {when(ctx.start(w))} ({ref(w)}) returned "
                    f"{w.fields.get('status')} with {num(w.fields.get('size'))} bytes, while the others returned "
                    f"errors of {num(err_size)} bytes.",
                    [f"{ref(w)}: status {w.fields.get('status')}, {num(w.fields.get('size'))} bytes to an attack request.",
                     f"The error responses ({refs(errs)}) are {num(err_size)} bytes (median); this one is "
                     f"{ratio:.0f} times larger (rules.yaml min_size_ratio {ps.get('min_size_ratio', 3)}).",
                     f"{rbref(ctx, 'web', 3)}: a large 200 response to an attack request may mean success.",
                     "No log shows what the response contained: suspected, not confirmed."],
                    [ecite(w)] + [ecite(e) for e in errs], [f"actor:ext_ip:{ip}"] + ents[1:],
                    assumption="The large 200 response carried data returned by the injected query.",
                    data={"src_ip": ip, "event": w.event_id, "size": int(w.fields.get("size")),
                          "error_size": err_size})
        miss = ctx.not_collected(*p.get("db_missing_source_keywords", ["query"]))
        for m in miss:
            out.add("coverage_missing", NOT_ENOUGH_EVIDENCE,
                    f"Whether any database rows were returned, or which ones, is not in the logs: "
                    f"{m['name']}: {m['reason']}.",
                    [f"The attack targets {', '.join(paths)} on {host}.",
                     f"{rbref(ctx, 'web', 5)} asks for the database server logs; {m['name']} ({tref(m['cite'])}): {m['reason']}.",
                     "The logs are silent: not enough evidence in the logs (01 rule 2.3)."],
                    [m["cite"]], [f"actor:ext_ip:{ip}"] + ([f"asset:{asset.tag}"] if asset else []),
                    data={"missing": m["name"], "kind": "not_collected"})
    return res


def detect_recon(ctx: Ctx, out: _Out) -> list:
    p = ctx.rules.get("recon", {})
    res = []
    by_src: dict = {}
    for e in ctx.role("perimeter_fw"):
        if ctx.is_external(ctx.src(e)):
            by_src.setdefault(ctx.src(e), []).append(e)
    for ip, evs in by_src.items():
        denied = [e for e in evs if str(e.fields.get("action", "")).upper() == "DENY"]
        if len({e.fields.get("dst_port") for e in denied}) < p.get("min_denied_ports", 3):
            continue
        t0 = ctx.start(denied[0])
        if (ctx.start(denied[-1]) - t0).total_seconds() > p.get("window_s", 300):
            continue
        tend = ctx.start(denied[-1]) + timedelta(seconds=p.get("probe_window_s", 300))
        allowed = [e for e in evs if e not in denied and t0 <= ctx.start(e) <= tend]
        probes = [e for e in ctx.role("web") if ctx.src(e) == ip and t0 <= ctx.start(e) <= tend]
        tgt = ctx.asset_by_ip(ctx.dst(denied[0]))
        al = ctx.alerts_with(ips=[ip])
        logins = [e for e in ctx.events if ctx.role_of(e) in ("vpn", "dc") and ctx.src(e) == ip]
        act = {"label": f"scan from {ip}", "start_utc": denied[0].ts_utc,
               "end_utc": to_utc_iso(max(ctx.end(e) for e in denied + allowed + probes)),
               "actor": {"ips": [ip], "users": [], "hosts": [], "names": []},
               "targets": {"ips": sorted({ctx.dst(e) for e in evs}), "hosts": [], "cidrs": []}}
        m = None
        for a in al:
            if a.alert_id in ctx.alert_checks:
                m = ctx.alert_checks[a.alert_id][1]
        if m is None:
            m = match_change(act, ctx.tables, ctx.rules.get("change_approval", {}))
            ctx.calendar_log.append((act["label"], act, m))
        if m.approved:
            continue  # approved scans are closed by the alert check
        dports = [str(e.fields.get("dst_port")) for e in denied]
        aports = [str(e.fields.get("dst_port")) for e in allowed]
        pstat = [f"{e.fields.get('path')} {e.fields.get('status')}" for e in probes]
        tname = f"{tgt.hostname} ({tgt.tag}, {tgt.criticality})" if tgt else ctx.dst(denied[0])
        steps = [f"Perimeter firewall {refs(denied)}: {ip} denied on ports {', '.join(dports)} at "
                 f"{ctx.dst(denied[0])} ({tname}), {span(t0, ctx.start(denied[-1]))}."]
        if allowed:
            steps.append(f"Then allowed on {', '.join(aports)} ({refs(allowed)}).")
        if probes:
            steps.append(f"Web probes ({refs(probes)}): {', '.join(pstat)}.")
        steps.append(f"{ip} is external (not in the internal networks or the inventory).")
        steps += calendar_steps(m)
        steps.append("No VPN or domain logins from this source follow." if not logins
                     else f"Logins from this source follow: {refs(logins)}.")
        if al:
            steps.append(f"{', '.join(a.alert_id for a in al)} reports a scan from the same source.")
        all404 = probes and all(int(e.fields.get("status") or 0) >= 400 for e in probes)
        steps.append(f"Many denied ports then probes is the scan pattern of {rbref(ctx, 'scan')}: confirmed, unapproved "
                     "reconnaissance. Alternate reading: web application attack, attempts only"
                     + (" (all probes returned errors)." if all404 else "."))
        st = (f"External reconnaissance from {ip}: {len(denied)} denied ports ({', '.join(dports)}), "
              + (f"{', '.join(aports)} allowed, " if aports else "")
              + (f"{len(probes)} web probes{' all ' + str(probes[0].fields.get('status')) if all404 and len({e.fields.get('status') for e in probes}) == 1 else ''}, " if probes else "")
              + f"against {tgt.hostname if tgt else ctx.dst(denied[0])}. Not in the change calendar.")
        ents = [f"actor:ext_ip:{ip}", f"ext_ip:{ip}"] + ([f"asset:{tgt.tag}"] if tgt else []) + \
               [f"alert:{a.alert_id}" for a in al]
        reach = []
        if tgt and allowed:
            reach = [{"tag": tgt.tag, "time": allowed[0].ts_utc, "kerberos_only": False}]
        res.append(out.add("recon", CONFIRMED, st, steps,
                           [ecite(e) for e in denied + allowed + probes] + [a.cite for a in al]
                           + ([tgt.cite] if tgt else []), ents,
                           data={"src_ip": ip, "asset_tag": tgt.tag if tgt else None, "external": True,
                                 "approved": False, "denied_ports": dports, "allowed_ports": aports,
                                 "probes": pstat, "logins_followed": bool(logins), "reach": reach,
                                 "near_misses": [c.change_id for c in m.near_misses()],
                                 "alerts": [a.alert_id for a in al]}))
    return res


def detect_missing_sources(ctx: Ctx, out: _Out) -> None:
    """not_enough_evidence for each not-collected source about an asset an actor reached."""
    seen = set()
    reach_rules = set(ctx.rules.get("severity", {}).get("reach", {}).get("rules", []))
    order = {"large_transfer": 0, "phishing_click": 1}
    for f in sorted(out.items, key=lambda x: order.get(x.rule, 2)):
        keys = actor_keys(f)
        if not keys or f.label not in (CONFIRMED, SUSPECTED):
            continue
        tags = []
        if f.rule in reach_rules:
            tags = [r["tag"] for r in fdata(f).get("reach", []) if not r.get("kerberos_only")]
        elif f.rule == "phishing_click" and fdata(f).get("laptop_tag"):
            tags = [fdata(f)["laptop_tag"]]
        for tag in tags:
            a = ctx.asset_by_tag(tag)
            if not a:
                continue
            for m in ctx.missing_for_asset(a):
                k = (m["name"], keys[0])
                if k in seen:
                    continue
                seen.add(k)
                d = fdata(f)
                if f.rule == "phishing_click":
                    st = (f"Whether {a.hostname} has malware is not in the logs: {m['name']}: {m['reason']}.")
                elif f.rule == "large_transfer":
                    st = (f"Which files were read on {a.hostname} is not known: {m['name']}: {m['reason']}.")
                else:
                    st = (f"Whether anything was read on {a.hostname} is not in the logs: {m['name']}: "
                          f"{m['reason']}. Only the network session(s) are shown"
                          + (f" ({num(d.get('bytes'))} bytes, {d.get('duration_s')} s)" if d.get("bytes") else "") + ".")
                out.add("coverage_missing", NOT_ENOUGH_EVIDENCE, st,
                        [f"{f.statement}",
                         f"Coverage sheet ({tref(m['cite'])}): {m['name']}: {m['reason']}.",
                         "The logs are silent: not enough evidence in the logs (01 rule 2.3). No guess is made."],
                        [m["cite"], a.cite] + list(f.evidence[:1]), keys[:1] + [f"asset:{a.tag}"],
                        data={"missing": m["name"], "kind": "not_collected", "asset_tag": a.tag})


def harmless_from_alerts(ctx: Ctx, out: _Out) -> list:
    res = []
    for al in ctx.tables.alerts:
        act, m = ctx.alert_checks.get(al.alert_id, (None, None))
        if not m or not m.approved:
            continue
        ch = next(c for c in ctx.tables.changes if c.change_id == m.change_id)
        evs = [e for e in ctx.events if e.event_id in set(act.get("events", []))]
        steps = [f"{al.alert_id} at {when(al.ts_utc)}: {al.description} ({tref(al.cite)}).",
                 f"Log lines around it ({refs(evs)}): activity {span(act['start_utc'], act['end_utc'])}.",
                 f"{ch.change_id} ({tref(ch.cite)}): {ch.system}, by {ch.performed_by}, "
                 f"{ch.date} {ch.window_pkt} PKT, status {ch.status}."] + \
                [r[0].upper() + r[1:] + "." for r in m.reasons] + \
                ["System, actor and window all match and the change is in effect: approved activity "
                 "(01 rule 3.1). Closed as harmless, not escalated (01 rule 3.2)."]
        st = (f"{al.alert_id} is approved activity under {ch.change_id}: {ch.system}, {ch.performed_by}, "
              f"window {ch.window_pkt} PKT all match ({span(act['start_utc'], act['end_utc'])}). Closed as harmless.")
        res.append(out.add("change_approved", HARMLESS, st, steps,
                           [al.cite, ch.cite] + [ecite(e) for e in evs],
                           [f"alert:{al.alert_id}", f"change:{ch.change_id}"],
                           data={"alert": al.alert_id, "change_id": ch.change_id,
                                 "why": f"{', '.join(r for r in m.reasons)}"}))
    return res


# ------------------------------------------------------------------ entry point
def run_rules_ctx(graph: Any, events: list, tables: Any, coverage: Any = None,
                  rules: Optional[dict] = None) -> tuple:
    rules = rules or load_rules()
    ctx = Ctx(graph, events, tables, coverage, rules)
    out = _Out(rules)
    check_alerts(ctx)
    detect_phishing(ctx, out)
    mfa = detect_mfa_fatigue(ctx, out)
    outliers = {e.event_id for e, *_ in transfer_outliers(ctx)}
    att = []
    for f, s in mfa:
        if s and s not in att:
            att.append(s)
            detect_attacker_session(ctx, out, s, outliers)
    detect_large_transfer(ctx, out)
    detect_concurrent_use(ctx, out, att)
    for s in att:
        _session_coverage(ctx, out, s, rule="coverage_gap",
                          ents=[f"actor:session:{s.session_id}", f"session:{s.session_id}", f"user:{s.user}"])
    detect_missing_sources(ctx, out)
    detect_web_attack(ctx, out)
    detect_recon(ctx, out)
    harmless_from_alerts(ctx, out)
    for i, f in enumerate(out.items, 1):
        f.finding_id = f"F-{i:03d}"
    return out.items, ctx


def run_rules(graph: Any, events: list, tables: Any, coverage: Any = None) -> list:
    """Run every detector and return Findings with label, evidence and numbered steps."""
    return run_rules_ctx(graph, events, tables, coverage)[0]
