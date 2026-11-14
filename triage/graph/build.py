"""P6: evidence graph (networkx.MultiDiGraph) with identity resolution chains."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Union

import networkx as nx

from triage.models import Cite, Event, Link, parse_utc

PREFIXES = ("ip", "ext_ip", "user", "asset", "host", "domain", "session", "msg", "alert", "change")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
MAC_RE = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
_RFC1918 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
HOSTING_WORDS = re.compile(r"\b(hosts?|hosting|hosted)\b", re.I)


def _ts(t: Union[str, datetime, None]) -> Optional[datetime]:
    if t is None:
        return None
    if isinstance(t, str):
        return parse_utc(t)
    return t if t.tzinfo else parse_utc(t.isoformat())


def _hhmmss(s: Optional[str]) -> str:
    return s[11:19] + "Z" if s else "open"


def fmt_cite(c: Optional[Cite]) -> str:
    if c is None:
        return ""
    if c.line is not None:
        return f"{c.file} line {c.line}"
    if c.row is not None:
        return f"{c.file} row {c.row}"
    if c.runbook:
        return f"{c.file} {c.runbook} step {c.step}"
    return c.file


@dataclass
class VpnSession:
    session_id: str
    user: str
    src_ip: Optional[str]
    geo: Optional[str]
    assigned_ip: Optional[str]
    start_utc: str
    end_utc: Optional[str]
    login_cite: Cite
    end_cite: Optional[Cite] = None
    bytes_to_client: Optional[int] = None
    bytes_from_client: Optional[int] = None
    duration_s: Optional[int] = None
    mfa: Optional[str] = None

    def holds(self, at: datetime) -> bool:
        if at < parse_utc(self.start_utc):
            return False
        return self.end_utc is None or at <= parse_utc(self.end_utc)

    def to_dict(self) -> dict:
        return {"session_id": self.session_id, "user": self.user, "src_ip": self.src_ip,
                "geo": self.geo, "assigned_ip": self.assigned_ip, "start_utc": self.start_utc,
                "end_utc": self.end_utc, "login_cite": self.login_cite.to_dict(),
                "end_cite": self.end_cite.to_dict() if self.end_cite else None,
                "bytes_to_client": self.bytes_to_client, "bytes_from_client": self.bytes_from_client,
                "duration_s": self.duration_s, "mfa": self.mfa}


@dataclass
class ChainStep:
    text: str
    cite: Optional[Cite] = None

    def to_dict(self) -> dict:
        return {"text": self.text, "cite": self.cite.to_dict() if self.cite else None}


@dataclass
class Chain:
    identifier: str
    kind: str = "unknown"
    node: Optional[str] = None
    asset: Any = None
    user: Any = None
    session: Optional[VpnSession] = None
    hostname: Optional[str] = None
    is_external: bool = False
    steps: list = field(default_factory=list)
    links: list = field(default_factory=list)
    note: Optional[str] = None

    @property
    def text(self) -> str:
        return " -> ".join(f"{s.text} ({fmt_cite(s.cite)})" if s.cite else s.text for s in self.steps)

    def to_dict(self) -> dict:
        return {"identifier": self.identifier, "kind": self.kind, "node": self.node,
                "asset": self.asset.to_dict() if self.asset else None,
                "user": self.user.to_dict() if self.user else None,
                "session": self.session.to_dict() if self.session else None,
                "hostname": self.hostname, "is_external": self.is_external,
                "steps": [s.to_dict() for s in self.steps],
                "links": [l.to_dict() for l in self.links], "note": self.note, "text": self.text}


def strip_prefix(identifier: str) -> str:
    s = str(identifier).strip()
    m = re.match(r"^(" + "|".join(PREFIXES) + r"):(.+)$", s, re.I)
    if m:
        s = m.group(2).strip()
    return s


class EvidenceGraph:
    def __init__(self, events: list, tables: Any):
        self.events = sorted(events, key=lambda e: (e.ts_utc, e.source_file, e.line))
        self.tables = tables
        self.g = nx.MultiDiGraph()
        self.links: list = []
        self._sessions: list = []
        self._ent: dict = {}
        self._domain_ip: dict = {}   # domain -> (ip, alert)
        self._ip_domains: dict = {}  # ip -> [(domain, alert)]
        self._build()

    # ------------------------------------------------------------ lookups
    @property
    def assets(self):
        return self.tables.inventory

    def is_pool_ip(self, ip: str) -> bool:
        p = getattr(self.tables.inventory_notes, "vpn_pool", None)
        if not p:
            return False
        try:
            return ipaddress.ip_address(p[0]) <= ipaddress.ip_address(ip) <= ipaddress.ip_address(p[1])
        except ValueError:
            return False

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in ipaddress.ip_network(n) for n in _RFC1918)

    def _user(self, key: Optional[str]):
        if not key:
            return None
        k = key.strip().lower()
        for u in self.tables.users:
            if k in (u.username.lower(), u.email.lower(), u.full_name.lower(), (u.phone or "").lower()):
                return u
        return None

    def _asset_by_tag(self, tag: str):
        for a in self.assets:
            if a.tag and a.tag.lower() == tag.lower():
                return a
        return None

    def _asset_by_name(self, name: str):
        """hostname, tag, FQDN or short name."""
        n = name.strip().lower()
        for a in self.assets:
            if a.hostname.lower() == n or a.tag.lower() == n:
                return a
        if re.match(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9-]+)*$", name):
            if "." in name:
                dom = (self.tables.inventory_notes.domain or "").lower()
                if not dom or not n.endswith("." + dom):
                    return None
            return self.tables.inventory_notes.resolve_fqdn(name, self.assets)
        return None

    def asset_for_ip(self, ip: str):
        for a in self.assets:
            if ip and (a.ip == ip or a.public_ip == ip):
                return a
        return None

    def _owner_user(self, asset):
        for u in self.tables.users:
            if asset.tag and u.laptop_tag == asset.tag:
                return u
        return self._user(asset.owner_person)

    def _laptop_of(self, user):
        return self._asset_by_tag(user.laptop_tag) if user.laptop_tag else None

    # ------------------------------------------------------------ sessions
    def sessions(self) -> list:
        return list(self._sessions)

    def _load_sessions(self):
        by_id: dict = {}
        for e in self.events:
            f = e.fields
            if e.kind == "vpn_auth" and f.get("session") and (f.get("result") == "SUCCESS" or "assigned_ip" in f):
                by_id[f["session"]] = VpnSession(
                    session_id=f["session"], user=f.get("user", ""), src_ip=f.get("src_ip"),
                    geo=f.get("geo"), assigned_ip=f.get("assigned_ip"), start_utc=e.ts_utc, end_utc=None,
                    login_cite=Cite(e.source_file, line=e.line), mfa=f.get("mfa"))
        for e in self.events:
            f = e.fields
            if e.kind == "vpn_auth" and f.get("session") in by_id and "result" not in f:
                s = by_id[f["session"]]
                s.end_utc = e.ts_utc
                s.end_cite = Cite(e.source_file, line=e.line)
                s.bytes_to_client = f.get("bytes_server_to_client")
                s.bytes_from_client = f.get("bytes_client_to_server")
                s.duration_s = f.get("duration_s")
        self._sessions = sorted(by_id.values(), key=lambda s: s.start_utc)

    def sessions_for_ip(self, ip: str) -> list:
        return [s for s in self._sessions if s.assigned_ip == ip]

    def session_for_ip(self, ip, at_utc):
        at = _ts(at_utc)
        if at is None:
            return None
        for s in self.sessions_for_ip(ip):
            if s.holds(at):
                return s
        return None

    def _session_by_id(self, sid: str):
        for s in self._sessions:
            if s.session_id.lower() == sid.lower():
                return s
        return None

    def user_for_ip(self, ip, at_utc):
        a = self.asset_for_ip(ip)
        if a is not None and not self.is_pool_ip(ip):
            return self._owner_user(a)
        s = self.session_for_ip(ip, at_utc)
        return self._user(s.user) if s else None

    # ------------------------------------------------------------ build
    def _node(self, nid: str, **attrs):
        if nid not in self.g:
            self.g.add_node(nid, type=nid.split(":", 1)[0], label=nid.split(":", 1)[1], **attrs)

    def _link(self, a, b, typ, ev, valid_from=None, valid_to=None, basis="direct", assumption=None):
        l = Link(a=a, b=b, type=typ, valid_from=valid_from, valid_to=valid_to, basis=basis,
                 assumption=assumption, evidence=list(ev))
        self.links.append(l)
        self._node(a)
        self._node(b)
        self.g.add_edge(a, b, key=f"link:{len(self.links)}", kind="identity", type=typ,
                        valid_from=valid_from, valid_to=valid_to, basis=basis)

    def _ip_prefix(self, ip: str) -> str:
        return "ip" if self._is_private(ip) or self.asset_for_ip(ip) else "ext_ip"

    def _build(self):
        inv_note = self.tables.inventory_notes
        for a in self.assets:
            self._node(f"asset:{a.tag}")
            self.g.nodes[f"asset:{a.tag}"]["label"] = a.hostname
            if a.ip:
                self._link(f"ip:{a.ip}", f"asset:{a.tag}", "ip_of_asset", [a.cite])
            if a.public_ip:
                self._link(f"ip:{a.public_ip}", f"asset:{a.tag}", "public_ip_of_asset", [a.cite])
            if inv_note.fqdn_example and inv_note.fqdn_example[1].lower() == a.hostname.lower():
                self._link(f"host:{inv_note.fqdn_example[0]}", f"asset:{a.tag}", "fqdn", [inv_note.cite])
        for u in self.tables.users:
            self._node(f"user:{u.username}")
            self.g.nodes[f"user:{u.username}"]["label"] = u.full_name
            lap = self._laptop_of(u)
            if lap:
                self._link(f"user:{u.username}", f"asset:{lap.tag}", "owns_laptop", [u.cite, lap.cite])
        self._load_sessions()
        for s in self._sessions:
            sn = f"session:{s.session_id}"
            self._link(sn, f"user:{s.user}", "session_user", [s.login_cite], s.start_utc, s.end_utc)
            ev = [s.login_cite] + ([s.end_cite] if s.end_cite else [])
            if s.assigned_ip:
                self._link(f"ip:{s.assigned_ip}", sn, "vpn_assignment", ev, s.start_utc, s.end_utc)
            if s.src_ip:
                self._link(f"{self._ip_prefix(s.src_ip)}:{s.src_ip}", sn, "session_source", [s.login_cite],
                           s.start_utc, s.end_utc)
        for al in self.tables.alerts:
            self._node(f"alert:{al.alert_id}", ts_utc=al.ts_utc)
            if al.ips and al.domains and HOSTING_WORDS.search(al.description):
                ext = [i for i in al.ips if not self._is_private(i)] or al.ips
                for d in al.domains:
                    ip = ext[0]
                    self._domain_ip[d.lower()] = (ip, al)
                    self._ip_domains.setdefault(ip, []).append((d, al))
                    self._link(f"{self._ip_prefix(ip)}:{ip}", f"domain:{d}", "hosts_domain", [al.cite])
        for c in self.tables.changes:
            self._node(f"change:{c.change_id}")
        seen_acc = set()
        for e in self.events:
            f = e.fields
            cite = Cite(e.source_file, line=e.line)
            if e.kind == "dhcp_lease" and f.get("ip"):
                a = self.asset_for_ip(f["ip"])
                if a and a.hostname.lower() == str(f.get("hostname", "")).lower():
                    self._link(f"ip:{a.ip}", f"asset:{a.tag}", "dhcp_lease", [cite], valid_from=e.ts_utc)
            acc = str(f.get("account", ""))
            if "\\" in acc and acc.lower() not in seen_acc:
                u = self._user(acc.split("\\")[-1])
                if u:
                    seen_acc.add(acc.lower())
                    self._link(f"user:{u.username}", f"account:{acc}", "account", [cite])
        for e in self.events:
            self._add_event(e)

    def _node_for_ip(self, ip: Optional[str], at: Optional[datetime]) -> Optional[str]:
        if not ip:
            return None
        a = self.asset_for_ip(ip)
        if a:
            return f"asset:{a.tag}"
        if self.is_pool_ip(ip):
            s = self.session_for_ip(ip, at)
            return f"session:{s.session_id}" if s else f"ip:{ip}"
        return f"{self._ip_prefix(ip)}:{ip}"

    def _endpoints(self, e: Event) -> dict:
        f = e.fields
        src = f.get("src_ip") or f.get("client") or (f.get("ip") if e.kind == "dhcp_lease" else None)
        dst = f.get("dst_ip")
        if e.kind in ("vpn_auth", "windows_auth") and f.get("device") and not dst:
            a = self._asset_by_name(f["device"])
            dst = a.ip if a else None
        if e.kind == "web_request" and not dst:
            dst = next((a.ip for a in self.assets if "web" in a.type.lower()), None)
        src_id, dst_id = src, dst
        if e.kind == "email_message":
            src_id, dst_id = f.get("from_domain"), f.get("to_user")
        return {"src": src_id, "dst": dst_id, "at": parse_utc(e.ts_utc), "src_ip": src, "dst_ip": dst}

    def _add_event(self, e: Event):
        f = e.fields
        ep = self._endpoints(e)
        at = ep["at"]
        ents: set = set()
        if e.kind == "email_message":
            src_n = f"domain:{f['from_domain']}" if f.get("from_domain") else None
            u = self._user(f.get("to_user"))
            dst_n = f"user:{u.username}" if u else None
            for k, p in (("msgid", "msg"), ("url_host", "domain"), ("from_domain", "domain")):
                if f.get(k):
                    ents.add(f"{p}:{f[k]}")
                    self._node(f"{p}:{f[k]}")
        else:
            src_n = self._node_for_ip(ep["src_ip"], at)
            dst_n = self._node_for_ip(ep["dst_ip"], at)
        for ip in (ep["src_ip"], ep["dst_ip"]):
            if not ip:
                continue
            ents.add(f"{self._ip_prefix(ip)}:{ip}")
            a = self.asset_for_ip(ip)
            if a:
                ents.add(f"asset:{a.tag}")
            if self.is_pool_ip(ip):
                s = self.session_for_ip(ip, at)
                if s:
                    ents.add(f"session:{s.session_id}")
                    ents.add(f"user:{s.user}")
        for key in ("device", "workstation", "hostname", "target"):
            if f.get(key):
                a = self._asset_by_name(str(f[key]))
                if a:
                    ents.add(f"asset:{a.tag}")
                    if key == "device" and e.kind in ("vpn_auth", "windows_auth"):
                        dst_n = dst_n or f"asset:{a.tag}"
        for key in ("user", "account", "to_user"):
            u = self._user(str(f[key]).split("\\")[-1]) if f.get(key) else None
            if u:
                ents.add(f"user:{u.username}")
        if f.get("session"):
            ents.add(f"session:{f['session']}")
            src_n = src_n or f"session:{f['session']}"
        self._ent[e.event_id] = ents
        if src_n and dst_n:
            self._node(src_n)
            self._node(dst_n)
            self.g.add_edge(src_n, dst_n, key=f"ev:{e.event_id}", kind="activity", event_id=e.event_id,
                            event_kind=e.kind, ts_utc=e.ts_utc, ts_end_utc=e.ts_end_utc)

    # ------------------------------------------------------------ queries
    def touched(self, entity: str, from_utc=None, to_utc=None) -> list:
        keys = {strip_prefix(entity)}
        c = self.resolve(entity)
        if c.node:
            keys.add(c.node)
        if c.kind == "vpn_ip":
            keys.add(f"ip:{strip_prefix(entity)}")
        lo, hi = _ts(from_utc), _ts(to_utc)
        out = []
        for e in self.events:
            if not (keys & self._ent.get(e.event_id, set())):
                continue
            s = parse_utc(e.ts_utc)
            t = parse_utc(e.ts_end_utc) if e.ts_end_utc else s
            if (hi is not None and s > hi) or (lo is not None and t < lo):
                continue
            out.append(e)
        return out

    def events_for(self, event: Event) -> dict:
        ep = self._endpoints(event)
        out = {}
        for side in ("src", "dst"):
            ident = ep[side]
            out[side] = self.resolve(ident, ep["at"]) if ident else Chain(
                identifier="", kind="unknown", note=f"event has no {side}")
        return out

    def to_json(self) -> dict:
        nodes = [{"id": n, "type": d.get("type"), "label": d.get("label", n)} for n, d in self.g.nodes(data=True)]
        edges = [{"source": a, "target": b, "key": k, "kind": d.get("kind"), "type": d.get("type"),
                  "event_id": d.get("event_id"), "event_kind": d.get("event_kind"),
                  "ts_utc": d.get("ts_utc"), "ts_end_utc": d.get("ts_end_utc"),
                  "valid_from": d.get("valid_from"), "valid_to": d.get("valid_to"), "basis": d.get("basis")}
                 for a, b, k, d in self.g.edges(keys=True, data=True)]
        return {"nodes": nodes, "edges": edges}

    # ------------------------------------------------------------ resolve
    def _domain_names(self) -> set:
        names = set(self._domain_ip)
        for e in self.events:
            for k in ("url_host", "from_domain"):
                if e.fields.get(k):
                    names.add(str(e.fields[k]).lower())
        return names

    def resolve(self, identifier: str, at_utc=None) -> Chain:
        raw = str(identifier)
        s = strip_prefix(raw)
        at = _ts(at_utc)
        if "\\" in s:
            u = self._user(s.split("\\")[-1])
            if u:
                return self._user_chain(raw, u, account=s)
        if IP_RE.match(s):
            return self._ip_chain(raw, s, at)
        sess = self._session_by_id(s)
        if sess:
            return self._session_chain(raw, sess)
        if MAC_RE.match(s):
            return self._mac_chain(raw, s)
        u = self._user(s)
        if u:
            return self._user_chain(raw, u)
        a = self._asset_by_name(s)
        if a:
            return self._asset_chain(raw, a, via=s)
        if s.lower() in self._domain_names():
            return self._domain_chain(raw, s)
        return Chain(identifier=raw, kind="unknown", steps=[ChainStep(s)], note="no matching identity in the data")

    def _owner_steps(self, c: Chain, a):
        u = self._owner_user(a)
        if u:
            c.steps.append(ChainStep(f"owner {a.owner_person or u.full_name}", a.cite))
            c.steps.append(ChainStep(f"user {u.username} ({u.full_name})", u.cite))
            c.user = u
            c.links.append(Link(a=f"asset:{a.tag}", b=f"user:{u.username}", type="owner", basis="direct",
                                evidence=[a.cite, u.cite]))

    def _asset_chain(self, raw, a, via=None, ip=None) -> Chain:
        c = Chain(identifier=raw, kind="asset", node=f"asset:{a.tag}", asset=a, hostname=a.hostname)
        if ip:
            c.steps.append(ChainStep(ip))
            what = "public IP" if ip == a.public_ip else "IP"
            c.steps.append(ChainStep(f"asset {a.tag} {a.hostname} ({what} in inventory)", a.cite))
            c.links.append(Link(a=f"ip:{ip}", b=f"asset:{a.tag}", type="ip_of_asset", basis="direct",
                                evidence=[a.cite]))
        else:
            c.steps.append(ChainStep(via or a.hostname))
            if via and "." in via:
                note = self.tables.inventory_notes
                c.steps.append(ChainStep(f"hostname {a.hostname} (FQDN rule)", note.cite))
                c.links.append(Link(a=f"host:{via}", b=f"asset:{a.tag}", type="fqdn", basis="direct",
                                    evidence=[note.cite]))
            c.steps.append(ChainStep(f"asset {a.tag} {a.hostname}", a.cite))
        self._owner_steps(c, a)
        return c

    def _ip_chain(self, raw, ip, at) -> Chain:
        a = self.asset_for_ip(ip)
        if a is not None:
            c = self._asset_chain(raw, a, ip=ip)
            for e in self.events:
                if e.kind == "dhcp_lease" and e.fields.get("ip") == ip:
                    late = at is not None and at < parse_utc(e.ts_utc)
                    c.steps.append(ChainStep(
                        f"DHCP lease {e.fields.get('hostname')} at {_hhmmss(e.ts_utc)} corroborates"
                        + (" (lease line is later than the traffic; the inventory row is the basis)" if late else ""),
                        Cite(e.source_file, line=e.line)))
                    break
            return c
        if self.is_pool_ip(ip):
            return self._pool_chain(raw, ip, at)
        if self._is_private(ip):
            return Chain(identifier=raw, kind="unknown", node=f"ip:{ip}", steps=[ChainStep(ip)],
                         note="internal address not in the asset inventory")
        c = Chain(identifier=raw, kind="ext_ip", node=f"ext_ip:{ip}", is_external=True, steps=[ChainStep(ip)])
        for d, al in self._ip_domains.get(ip, []):
            c.steps.append(ChainStep(f"hosts domain {d}", al.cite))
            c.links.append(Link(a=f"ext_ip:{ip}", b=f"domain:{d}", type="hosts_domain", basis="direct",
                                evidence=[al.cite]))
        for s in self._sessions:
            if s.src_ip == ip:
                c.steps.append(ChainStep(
                    f"source of VPN session {s.session_id} (user {s.user}, geo {s.geo})", s.login_cite))
        return c

    def _pool_chain(self, raw, ip, at) -> Chain:
        c = Chain(identifier=raw, kind="vpn_ip", node=f"ip:{ip}", steps=[ChainStep(ip)])
        held = self.sessions_for_ip(ip)

        def add(s):
            u = self._user(s.user)
            c.steps.append(ChainStep(f"session {s.session_id}", s.login_cite))
            c.steps.append(ChainStep(f"user {s.user}"))
            if u:
                c.steps.append(ChainStep(u.full_name, u.cite))
            c.links.append(Link(a=f"ip:{ip}", b=f"session:{s.session_id}", type="vpn_assignment",
                                valid_from=s.start_utc, valid_to=s.end_utc, basis="direct",
                                evidence=[s.login_cite] + ([s.end_cite] if s.end_cite else [])))
            c.links.append(Link(a=f"session:{s.session_id}", b=f"user:{s.user}", type="session_user",
                                valid_from=s.start_utc, valid_to=s.end_utc, basis="direct",
                                evidence=[s.login_cite]))
            return u

        if at is not None:
            s = self.session_for_ip(ip, at)
            if s:
                c.session = s
                c.user = add(s)
                c.node = f"session:{s.session_id}"
            else:
                wins = ", ".join(f"{x.session_id} {_hhmmss(x.start_utc)} to {_hhmmss(x.end_utc)}" for x in held)
                c.note = "no VPN session holds this address at that time" + (
                    f" (it was held by: {wins})" if wins else "")
            return c
        for s in held:
            add(s)
        if len(held) == 1:
            c.session = held[0]
        users = {s.user for s in held}
        if len(users) == 1:
            c.user = self._user(next(iter(users)))
        c.note = ("this address maps to a user only inside the session windows listed "
                  "(login line to session_end line)" if held else "no VPN session assigned this address")
        return c

    def _session_chain(self, raw, s) -> Chain:
        c = Chain(identifier=raw, kind="session", node=f"session:{s.session_id}", session=s)
        c.steps.append(ChainStep(f"session {s.session_id}", s.login_cite))
        c.steps.append(ChainStep(f"user {s.user}"))
        u = self._user(s.user)
        if u:
            c.user = u
            c.steps.append(ChainStep(u.full_name, u.cite))
        if s.assigned_ip:
            c.steps.append(ChainStep(f"assigned {s.assigned_ip} ({_hhmmss(s.start_utc)} to {_hhmmss(s.end_utc)})",
                                     s.end_cite or s.login_cite))
        c.links.append(Link(a=f"session:{s.session_id}", b=f"user:{s.user}", type="session_user",
                            valid_from=s.start_utc, valid_to=s.end_utc, evidence=[s.login_cite]))
        return c

    def _user_chain(self, raw, u, account=None) -> Chain:
        c = Chain(identifier=raw, kind="user", node=f"user:{u.username}", user=u)
        if account:
            cite = next((l.evidence[0] for l in self.links
                         if l.type == "account" and l.b.lower() == f"account:{account}".lower()), None)
            c.steps.append(ChainStep(account, cite))
            c.links.append(Link(a=f"account:{account}", b=f"user:{u.username}", type="account", basis="direct",
                                evidence=[cite] if cite else []))
        c.steps.append(ChainStep(f"user {u.username}"))
        c.steps.append(ChainStep(u.full_name, u.cite))
        lap = self._laptop_of(u)
        if lap:
            c.asset = lap
            c.hostname = lap.hostname
            c.steps.append(ChainStep(f"laptop {lap.tag} {lap.hostname} ({lap.ip})", lap.cite))
        return c

    def _mac_chain(self, raw, mac) -> Chain:
        m = mac.lower().replace("-", ":")
        for e in self.events:
            if e.kind == "dhcp_lease" and str(e.fields.get("mac", "")).lower() == m:
                a = self.asset_for_ip(e.fields.get("ip", "")) or self._asset_by_name(e.fields.get("hostname", ""))
                if a:
                    cite = Cite(e.source_file, line=e.line)
                    c = self._asset_chain(raw, a)
                    c.steps.insert(0, ChainStep(f"MAC {mac} -> {e.fields.get('hostname')}", cite))
                    c.links.append(Link(a=f"mac:{mac}", b=f"asset:{a.tag}", type="mac", evidence=[cite]))
                    return c
        return Chain(identifier=raw, kind="unknown", steps=[ChainStep(mac)], note="MAC not seen in the DHCP log")

    def _domain_chain(self, raw, d) -> Chain:
        c = Chain(identifier=raw, kind="domain", node=f"domain:{d}", is_external=True, steps=[ChainStep(d)])
        hit = self._domain_ip.get(d.lower())
        if hit:
            ip, al = hit
            c.steps.append(ChainStep(f"hosted at {ip}", al.cite))
            c.links.append(Link(a=f"ext_ip:{ip}", b=f"domain:{d}", type="hosts_domain", basis="direct",
                                evidence=[al.cite]))
        return c


def build_graph(events: list, tables: Any) -> EvidenceGraph:
    return EvidenceGraph(events, tables)
