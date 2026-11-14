"""P7: change-calendar matcher (01 rule 3.1): system AND actor AND window must all match.

An activity is a plain dict:

    {"label": "<alert id>", "start_utc": iso, "end_utc": iso,
     "actor":   {"ips": [], "users": [], "hosts": [], "names": []},
     "targets": {"ips": [], "hosts": [], "cidrs": []},
     "evidence": [Cite]}

`match_change` checks it against every change in the calendar and returns the best
ChangeMatch, which says which of system / actor / window / status / date matched, so a
near-miss or a decoy can be explained.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from triage.models import PKT, Cite, parse_utc


@dataclass
class ChangeCheck:
    change_id: str
    system: bool
    actor: bool
    window: bool
    effective: bool
    date_ok: bool
    approved: bool
    reasons: list
    cite: Cite

    @property
    def score(self) -> int:
        return int(self.system) + int(self.actor) + int(self.window)

    def to_dict(self) -> dict:
        return {"change_id": self.change_id, "system": self.system, "actor": self.actor,
                "window": self.window, "effective": self.effective, "date_ok": self.date_ok,
                "approved": self.approved, "reasons": list(self.reasons),
                "cite": self.cite.to_dict()}


@dataclass
class ChangeMatch:
    approved: bool
    change_id: Optional[str]
    system: bool = False
    actor: bool = False
    window: bool = False
    effective: bool = False
    date_ok: bool = False
    reasons: list = field(default_factory=list)
    checks: list = field(default_factory=list)  # list[ChangeCheck], calendar order
    activity: dict = field(default_factory=dict)
    cite: Optional[Cite] = None

    @property
    def matched(self) -> list:
        return [k for k in ("system", "actor", "window") if getattr(self, k)]

    def near_misses(self) -> list:
        return [c for c in self.checks if not c.approved and c.score > 0]

    def explain(self) -> str:
        if self.approved:
            return (f"{self.change_id} approves it: system, actor and window all match, "
                    f"status is effective and the date matches.")
        if not self.checks:
            return "The change calendar has no entries."
        best = [c for c in self.checks if c.score > 0]
        if not best:
            return "No change in the calendar matches its system, actor or time window."
        parts = []
        for c in best:
            parts.append(f"{c.change_id}: " + "; ".join(c.reasons))
        return "No change approves it. Closest: " + " | ".join(parts)

    def to_dict(self) -> dict:
        return {"approved": self.approved, "change_id": self.change_id, "system": self.system,
                "actor": self.actor, "window": self.window, "effective": self.effective,
                "date_ok": self.date_ok, "reasons": list(self.reasons),
                "checks": [c.to_dict() for c in self.checks],
                "cite": self.cite.to_dict() if self.cite else None}


# ------------------------------------------------------------------ helpers
def _ip(s: str):
    try:
        return ipaddress.ip_address(s.strip())
    except ValueError:
        return None


def _net(s: str):
    try:
        return ipaddress.ip_network(s.strip(), strict=False)
    except ValueError:
        return None


def _asset_by_host(name: str, tables: Any):
    n = (name or "").strip().lower()
    if not n:
        return None
    for a in tables.inventory:
        if a.hostname.lower() == n or a.tag.lower() == n:
            return a
    notes = getattr(tables, "inventory_notes", None)
    if notes is not None:
        try:
            return notes.resolve_fqdn(name, tables.inventory)
        except Exception:
            return None
    return None


def _asset_by_ip(ip: str, tables: Any):
    for a in tables.inventory:
        if ip and (a.ip == ip or a.public_ip == ip):
            return a
    return None


def _fmt(t) -> str:
    return parse_utc(t).strftime("%H:%M:%S") if t else "?"


def _status_ignored(change: Any, rules: dict) -> bool:
    if not getattr(change, "is_effective", True):
        return True
    pats = (rules or {}).get("ignore_status_patterns") or []
    return any(re.search(p, change.status or "") for p in pats)


# ------------------------------------------------------------------ components
def _system_match(change: Any, act: dict, tables: Any) -> tuple:
    nets = [n for n in (_net(s) for s in change.systems if "/" in s) if n]
    hosts = {s.lower() for s in change.systems if "/" not in s}
    host_ips = set()
    for h in hosts:
        a = _asset_by_host(h, tables)
        if a:
            hosts.add(a.hostname.lower())
            host_ips.update(x for x in (a.ip, a.public_ip) if x)
    tg = act.get("targets") or {}
    items = []  # (label, ok)
    for ip in tg.get("ips") or []:
        a = _asset_by_ip(ip, tables)
        cands = [ip] + ([a.ip] if a and a.ip else [])
        ok = any(c in host_ips for c in cands) or any(
            _ip(c) is not None and any(_ip(c) in n for n in nets) for c in cands)
        if a and a.hostname.lower() in hosts:
            ok = True
        items.append((f"{ip}" + (f" ({a.hostname})" if a else ""), ok))
    for h in tg.get("hosts") or []:
        a = _asset_by_host(h, tables)
        ok = h.lower() in hosts or bool(a and a.hostname.lower() in hosts)
        if not ok and a and a.ip:
            ok = any(_ip(a.ip) in n for n in nets) if _ip(a.ip) else False
        items.append((h, ok))
    for c in tg.get("cidrs") or []:
        n = _net(c)
        ok = bool(n) and any(n.subnet_of(m) for m in nets if m.version == n.version)
        items.append((c, ok))
    if not items:
        return False, "activity has no known target"
    ok = all(o for _, o in items)
    bad = [l for l, o in items if not o]
    if ok:
        return True, f"system matches ({change.system})"
    return False, f"system does not match (calendar: {change.system}; activity: {', '.join(bad)})"


def _actor_match(change: Any, act: dict, tables: Any) -> tuple:
    a = act.get("actor") or {}
    ips, users = set(a.get("ips") or []), {u.lower() for u in a.get("users") or []}
    hosts = {h.lower() for h in a.get("hosts") or []}
    names = {n.lower() for n in a.get("names") or []}
    for ip in list(ips):
        asset = _asset_by_ip(ip, tables)
        if asset:
            hosts.add(asset.hostname.lower())
    for h in list(hosts):
        asset = _asset_by_host(h, tables)
        if asset and asset.ip:
            ips.add(asset.ip)
    for u in tables.users:
        if u.username.lower() in users:
            names.add(u.full_name.lower())
        if u.full_name.lower() in names:
            users.add(u.username.lower())
    c_ips = set(change.actor_ips)
    c_users = {u.lower() for u in change.actor_usernames}
    c_hosts = {h.lower() for h in change.actor_hosts}
    c_names = {n.lower() for n in change.actor_names}
    for h in list(c_hosts):
        asset = _asset_by_host(h, tables)
        if asset and asset.ip:
            c_ips.add(asset.ip)
    hit = (ips & c_ips) or (users & c_users) or (hosts & c_hosts) or (names & c_names) \
        or (users & {n for n in c_names}) or (names & c_users)
    shown = sorted(set(a.get("users") or []) | set(a.get("ips") or []) | set(a.get("hosts") or []))
    if hit:
        return True, f"actor matches ({change.performed_by})"
    return False, (f"actor does not match (calendar: {change.performed_by}; "
                   f"activity: {', '.join(shown) or 'unknown'})")


def _window_match(change: Any, act: dict) -> tuple:
    s, e = act.get("start_utc"), act.get("end_utc") or act.get("start_utc")
    if not (change.window_start_utc and change.window_end_utc):
        return False, "change has no time window"
    if not s:
        return False, "activity has no time"
    ws, we = parse_utc(change.window_start_utc), parse_utc(change.window_end_utc)
    ok = ws <= parse_utc(s) and parse_utc(e) <= we
    win = (f"{_fmt(change.window_start_utc)} to {_fmt(change.window_end_utc)} UTC "
           f"({change.window_pkt} PKT)")
    act_t = f"{_fmt(s)} to {_fmt(e)} UTC" if e != s else f"{_fmt(s)} UTC"
    if ok:
        return True, f"window {win} contains {act_t}"
    return False, f"window {win} does not contain {act_t}"


def _date_ok(change: Any, act: dict) -> tuple:
    s = act.get("start_utc")
    if not s or not change.date:
        return False, "no date"
    d = parse_utc(s).astimezone(PKT).strftime("%Y-%m-%d")
    if d == change.date:
        return True, f"date {change.date} matches"
    return False, f"dated {change.date}, activity is on {d}"


# ------------------------------------------------------------------ public
def check_change(change: Any, activity: dict, tables: Any, rules: Optional[dict] = None) -> ChangeCheck:
    sys_ok, sys_r = _system_match(change, activity, tables)
    act_ok, act_r = _actor_match(change, activity, tables)
    win_ok, win_r = _window_match(change, activity)
    date_ok, date_r = _date_ok(change, activity)
    effective = not _status_ignored(change, rules or {})
    reasons = [sys_r, act_r, win_r]
    if not date_ok:
        reasons.append(date_r)
    if not effective:
        reasons.append(f"status '{change.status}': approves nothing")
    req = (rules or {}).get("require") or ["system", "actor", "window"]
    comp = {"system": sys_ok, "actor": act_ok, "window": win_ok}
    approved = effective and date_ok and all(comp.get(k, False) for k in req)
    return ChangeCheck(change.change_id, sys_ok, act_ok, win_ok, effective, date_ok, approved,
                       reasons, change.cite)


def match_change(activity: dict, tables: Any, rules: Optional[dict] = None) -> ChangeMatch:
    """Best ChangeMatch for `activity` (approved one if any, else the closest near-miss)."""
    if rules is None:
        try:
            from triage.rules.detectors import load_rules
            rules = load_rules().get("change_approval", {})
        except Exception:
            rules = {}
    checks = [check_change(c, activity, tables, rules) for c in tables.changes]
    approved = [c for c in checks if c.approved]
    if approved:
        best = approved[0]
    elif checks:
        best = max(checks, key=lambda c: (c.score, c.effective, c.date_ok))
        if best.score == 0:
            best = None
    else:
        best = None
    if best is None:
        return ChangeMatch(False, None, checks=checks, activity=activity,
                           reasons=["no change matches its system, actor or window"])
    return ChangeMatch(best.approved, best.change_id, best.system, best.actor, best.window,
                       best.effective, best.date_ok, list(best.reasons), checks, activity,
                       best.cite)
