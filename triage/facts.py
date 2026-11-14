"""P8: fact store. Builds and loads facts.json, keyed by a hash of the input files.

Everything here is derived from the parsed data pack at run time. Nothing is
specific to one data pack: no IDs, names or times are written in this file.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from triage import config
from triage.models import Cite, Event, Finding, Gap, Incident, fmt_utc_pkt, parse_utc

_HMS = re.compile(r"T(\d\d:\d\d:\d\d)")


def _hms(iso: Optional[str]) -> Optional[str]:
    m = _HMS.search(iso or "")
    return m.group(1) if m else None


def input_hash(data_dir: Path) -> str:
    """sha256 over the data files, rules.yaml and the profiles (names and bytes, sorted)."""
    h = hashlib.sha256()
    files = sorted(p for p in Path(data_dir).iterdir() if p.is_file())
    files.append(Path(config.RULES_YAML))
    files += sorted(Path(config.PROFILES_DIR).glob("*"))
    for p in files:
        if not p.is_file():
            continue
        h.update(p.name.encode("utf-8") + b"\0")
        h.update(p.read_bytes() + b"\0")
    return h.hexdigest()


def _num(v) -> str:
    try:
        return f"{int(v):,}"
    except (TypeError, ValueError):
        return str(v)


class FactStore:
    def __init__(self, data_dir: Path):
        from triage.graph.build import build_graph
        from triage.parsers.logs import parse_all
        from triage.parsers.tables import load_tables
        from triage.rules.engine import build_incidents

        self.data_dir = Path(data_dir)
        self.hash = input_hash(self.data_dir)
        self.built_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.events: list[Event] = parse_all(self.data_dir)
        self.tables = load_tables(self.data_dir)
        self.coverage = self.tables.coverage
        self.date: str = self.coverage.date or ""
        self.graph = build_graph(self.events, self.tables)
        self.engine = build_incidents(self.graph, self.events, self.tables, self.coverage)
        self._engine_dict = self.engine.to_dict()
        self._index()

    @property
    def short_hash(self) -> str:
        return self.hash[:12]

    # ------------------------------------------------------------ indexes
    def _index(self) -> None:
        self._by_id = {e.event_id: e for e in self.events}
        self._by_cite = {(e.source_file, e.line): e for e in self.events}
        self._findings = {f.finding_id: f for f in self.engine.findings}
        self._alerts = {a.alert_id: a for a in self.tables.alerts}
        self._alert_file = self.tables.alerts[0].cite.file if self.tables.alerts else ""
        # event / alert -> incident
        self._ev_inc: dict = {}
        self._alert_inc: dict = {}
        for inc in self.engine.incidents + self.engine.anomalies:
            for eid in inc.timeline:
                self._ev_inc.setdefault(eid, inc.incident_id)
            for f in inc.findings:
                for c in f.evidence:
                    if c.line is not None:
                        e = self._by_cite.get((c.file, c.line))
                        if e:
                            self._ev_inc.setdefault(e.event_id, inc.incident_id)
                    elif c.row and c.row in self._alerts:
                        self._alert_inc.setdefault(c.row, inc.incident_id)
            cs = self._engine_dict_extra(inc.incident_id).get("clock_start")
            if cs and cs.get("alert"):
                self._alert_inc.setdefault(cs["alert"], inc.incident_id)
        for h in self.engine.harmless:
            if h.get("alert"):
                self._alert_inc.setdefault(h["alert"], "HARMLESS")
            for c in h.get("evidence", []):
                if c.get("line") is not None:
                    e = self._by_cite.get((c["file"], c["line"]))
                    if e:
                        self._ev_inc.setdefault(e.event_id, "HARMLESS")
        # row ids per file (lower-case)
        rows: dict = {}

        def add(file, row):
            if file and row:
                rows.setdefault(file.lower(), set()).add(str(row).lower())

        for a in self.tables.inventory:
            add(a.cite.file, a.tag)
        for c in self.tables.changes:
            add(c.cite.file, c.change_id)
        for a in self.tables.alerts:
            add(a.cite.file, a.alert_id)
        for u in self.tables.users:
            add(u.cite.file, u.username)
        for s in self.coverage.sources:
            add(s.cite.file, s.source)
            add(s.cite.file, s.cite.row)
        for n in self.coverage.not_collected:
            add(n["cite"].file, n["name"])
            add(n["cite"].file, n["cite"].row)
        for r in self.tables.escalation:
            add(r.cite.file, r.cite.row)
        if self.tables.matrix.rows:
            mfile = self.tables.matrix.cite_for(self.tables.matrix.rows[0]).file
            for r in self.tables.matrix.rows:
                add(mfile, r)
        self._rows = rows
        times: set = set()
        for e in self.events:
            times.update(t for t in (_hms(e.ts_utc), _hms(e.ts_end_utc)) if t)
        for a in self.tables.alerts:
            times.add(_hms(a.ts_utc))
        for g in self.coverage.gaps:
            times.update(t for t in (_hms(g.from_utc), _hms(g.to_utc)) if t)
        for s in self.graph.sessions():
            times.update(t for t in (_hms(s.start_utc), _hms(s.end_utc)) if t)
        for c in self.tables.changes:
            times.update(t for t in (_hms(c.window_start_utc), _hms(c.window_end_utc)) if t)
        for s in self.coverage.sources:
            for a, b in s.windows_utc or []:
                times.update(t for t in (_hms(a), _hms(b)) if t)
        times.discard(None)
        self._times = times

    def _engine_dict_extra(self, incident_id: str) -> dict:
        return self.engine.extras.get(incident_id, {})

    # ------------------------------------------------------------ lookups
    def event(self, event_id) -> Optional[Event]:
        return self._by_id.get(event_id)

    def events_by_cite(self, file, line) -> Optional[Event]:
        try:
            return self._by_cite.get((file, int(line)))
        except (TypeError, ValueError):
            return None

    def finding(self, finding_id) -> Optional[Finding]:
        return self._findings.get(finding_id)

    def incident(self, incident_id) -> Optional[Incident]:
        return self.engine.incident(incident_id)

    def incident_dict(self, incident_id) -> Optional[dict]:
        for d in self._engine_dict["incidents"] + self._engine_dict["anomalies"]:
            if d["incident_id"] == incident_id:
                return d
        return None

    def incident_of_event(self, event_id) -> Optional[str]:
        return self._ev_inc.get(event_id)

    def gaps(self) -> list:
        return list(self.coverage.gaps)

    def missing_sources(self) -> list:
        return [{"source": n["name"], "name": n["name"], "from_utc": None, "to_utc": None,
                 "reason": n["reason"], "evidence": [n["cite"].to_dict()], "cite": n["cite"].to_dict()}
                for n in self.coverage.not_collected]

    # ------------------------------------------------------------ timeline
    def _who(self, ip: Optional[str], at: str) -> str:
        if not ip:
            return "unknown"
        a = self.graph.asset_for_ip(ip)
        if a is not None and not self.graph.is_pool_ip(ip):
            return f"{ip} ({a.hostname})"
        s = self.graph.session_for_ip(ip, at)
        if s is not None:
            return f"{ip} ({s.user}, session {s.session_id})"
        return ip

    def _dst(self, ip: Optional[str], port) -> str:
        a = self.graph.asset_for_ip(ip) if ip else None
        base = a.hostname if a is not None else str(ip)
        return f"{base}:{port}" if port not in (None, "") else base

    def event_text(self, e: Event) -> str:
        f, k = e.fields, e.kind
        if k == "firewall_session" or k == "firewall_connection":
            verb = f.get("action", "")
            s = f"{self._who(f.get('src_ip'), e.ts_utc)} to {self._dst(f.get('dst_ip'), f.get('dst_port'))}"
            if k == "firewall_session" or f.get("bytes_total") is not None:
                if f.get("bytes_server_to_client") is not None:
                    s += f", {_num(f['bytes_server_to_client'])} bytes server to client"
                elif f.get("bytes_total") is not None:
                    s += f", {_num(f['bytes_total'])} bytes"
                if f.get("duration_s") is not None:
                    s += f", {f['duration_s']} s"
            if verb and verb.upper() != "ALLOW":
                s += f", {verb.lower()}"
            if f.get("rule"):
                s += f" (rule {f['rule']})"
            return s
        if k == "vpn_auth":
            if "result" in f:
                s = (f"VPN login {str(f['result']).lower()} for {f.get('user')} from {f.get('src_ip')}"
                     f" ({f.get('geo')})")
                if f.get("assigned_ip"):
                    s += f", assigned {f['assigned_ip']}"
                if f.get("session"):
                    s += f", session {f['session']}"
                if f.get("mfa"):
                    s += f", MFA {f['mfa']}"
                return s
            s = f"VPN session {f.get('session')} ended"
            if f.get("bytes_server_to_client") is not None:
                s += f", {_num(f['bytes_server_to_client'])} bytes server to client"
            if f.get("bytes_client_to_server") is not None:
                s += f", {_num(f['bytes_client_to_server'])} bytes client to server"
            return s
        if k == "windows_auth":
            s = f"{f.get('description', 'Windows event')} for {f.get('user') or f.get('account')}"
            if f.get("workstation") or f.get("client"):
                s += f" from {f.get('workstation') or f.get('client')}"
            if f.get("result"):
                s += f", {str(f['result']).lower()}"
            return s
        if k == "web_request":
            return (f"{f.get('src_ip')} requested {f.get('method')} {f.get('path')} on the web server, "
                    f"status {f.get('status')}")
        if k == "email_message":
            return (f"Mail {f.get('msgid')} from {f.get('from')} to {f.get('to')} {f.get('action')}, "
                    f"SPF {f.get('spf')}, score {f.get('score')}")
        if k == "dhcp_lease":
            return f"DHCP {f.get('action')} {f.get('ip')} to {f.get('hostname') or f.get('mac')}"
        return e.raw.strip()

    def _item(self, e: Event) -> dict:
        d = e.to_dict()
        t = fmt_utc_pkt(e.ts_utc)
        if e.ts_end_utc:
            t += f" to {fmt_utc_pkt(e.ts_end_utc)}"
        d.update(text=self.event_text(e), time=t, incident=self.incident_of_event(e.event_id),
                 cite=Cite(e.source_file, line=e.line).to_dict())
        return d

    def _alert_item(self, a) -> dict:
        return {"event_id": a.alert_id, "kind": "ids_alert", "ts_utc": a.ts_utc, "ts_end_utc": None,
                "source_file": a.cite.file, "line": None, "row": a.alert_id,
                "raw": f"{a.alert_id} | {a.ts_utc} | {a.sensor} | {a.description}",
                "fields": {"sensor": a.sensor, "description": a.description, "ips": list(a.ips),
                           "hostnames": list(a.hostnames), "usernames": list(a.usernames)},
                "untrusted_fields": [],
                "text": f"{a.sensor} alert {a.alert_id}: {a.description}",
                "time": fmt_utc_pkt(a.ts_utc),
                "incident": self._alert_inc.get(a.alert_id),
                "cite": a.cite.to_dict()}

    def timeline(self, incident_id=None, from_utc=None, to_utc=None) -> list:
        items = [self._item(e) for e in self.events] + [self._alert_item(a) for a in self.tables.alerts]
        items.sort(key=lambda d: (parse_utc(d["ts_utc"]), d["source_file"], d["line"] or 0, d["event_id"]))
        if incident_id:
            items = [i for i in items if i["incident"] == incident_id]
        lo = parse_utc(from_utc) if from_utc else None
        hi = parse_utc(to_utc) if to_utc else None
        if lo:
            items = [i for i in items if parse_utc(i["ts_end_utc"] or i["ts_utc"]) >= lo]
        if hi:
            items = [i for i in items if parse_utc(i["ts_utc"]) <= hi]
        return items

    # ------------------------------------------------------------ validate.Facts protocol
    def has_line(self, file, line) -> bool:
        return self.events_by_cite(file, line) is not None

    def line_text(self, file, line) -> Optional[str]:
        e = self.events_by_cite(file, line)
        return e.raw if e else None

    def has_row(self, file, row) -> bool:
        if file is None or row is None:
            return False
        return str(row).strip().lower() in self._rows.get(str(file).strip().lower(), set())

    def runbook_step(self, runbook, step) -> Optional[str]:
        rb = self.tables.runbooks.get(str(runbook).upper()) if runbook else None
        try:
            s = rb.step(int(step)) if rb else None
        except (TypeError, ValueError):
            return None
        return s.text if s else None

    def known_times_utc(self) -> set:
        return set(self._times)

    def incident_severity(self, incident_id) -> Optional[str]:
        i = self.incident(incident_id)
        return i.severity if i else None

    # ------------------------------------------------------------ vocabulary
    def known_entities(self) -> dict:
        t = self.tables
        users = [u.username for u in t.users if u.username]
        names = [u.full_name for u in t.users if u.full_name]
        emails = [u.email for u in t.users if u.email]
        phones = [u.phone for u in t.users if u.phone]
        phones += [r.contact for r in t.escalation if r.contact]
        names += [r.name for r in t.escalation if r.name]
        ips = {a.ip for a in t.inventory if a.ip} | {a.public_ip for a in t.inventory if a.public_ip}
        hosts = {a.hostname for a in t.inventory if a.hostname}
        ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        for e in self.events:
            for k, v in e.fields.items():
                if isinstance(v, str) and k.endswith("ip") and ip_re.fullmatch(v):
                    ips.add(v)
            if e.fields.get("hostname"):
                hosts.add(e.fields["hostname"])
            if e.fields.get("workstation"):
                hosts.add(e.fields["workstation"])
        for a in t.alerts:
            ips.update(a.ips)
        dedup = lambda xs: sorted({x for x in xs if x})
        return {"user": dedup(users), "name": dedup(names), "email": dedup(emails),
                "phone": dedup(phones), "ip": dedup(ips), "host": dedup(hosts)}

    # ------------------------------------------------------------ export
    def to_dict(self) -> dict:
        d = self._engine_dict
        return {"facts_hash": self.short_hash, "facts_hash_full": self.hash, "built_at": self.built_at,
                "date": self.date,
                "events": [e.to_dict() for e in self.events],
                "gaps": [g.to_dict() for g in self.gaps()],
                "missing_sources": self.missing_sources(),
                "findings": d["findings"], "incidents": d["incidents"], "anomalies": d["anomalies"],
                "closed_as_harmless": d["harmless"], "decoys": d["decoys"],
                "entities": self.known_entities()}

    def save(self, path=None) -> Path:
        p = Path(path) if path else Path(config.FACTS_PATH)
        p.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False, default=str),
                     encoding="utf-8")
        return p


def build_facts(data_dir=None) -> FactStore:
    return FactStore(Path(data_dir) if data_dir else Path(config.DATA_DIR))


_CACHE: dict = {}


def get_facts(data_dir=None, refresh: bool = False) -> FactStore:
    d = Path(data_dir) if data_dir else Path(config.DATA_DIR)
    key = str(d.resolve())
    cur = _CACHE.get(key)
    if cur is not None and not refresh and cur.hash == input_hash(d):
        return cur
    _CACHE[key] = build_facts(d)
    return _CACHE[key]
