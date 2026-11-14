"""P2: typed loaders for the Markdown tables (02, 03, 04, 05, 06-10, 17, 18) and rules (01).

Every value is parsed from the files at call time. Nothing here knows a specific name,
ID or time; the loaders only know the layout (column headers, bracket conventions).
"""
from __future__ import annotations

import dataclasses
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, Union

from triage import config
from triage.models import PKT, Cite, Gap, parse_utc, to_utc_iso

# ------------------------------------------------------------------ plumbing
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
HOST_RE = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*\d[A-Z0-9]*(?:-[A-Z0-9]+)*\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,}\b")
PHONE_RE = re.compile(r"\+?\d[\d\- ]{7,}\d")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _to_dict(x: Any) -> Any:
    if isinstance(x, _Dict):
        return {f.name: _to_dict(getattr(x, f.name)) for f in dataclasses.fields(x)}
    if hasattr(x, "to_dict") and callable(x.to_dict):
        return x.to_dict()
    if isinstance(x, dict):
        return {k: _to_dict(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_to_dict(v) for v in x]
    return x


class _Dict:
    def to_dict(self) -> dict:
        return _to_dict(self)


def data_path(data_dir: Union[str, Path, None] = None) -> Path:
    return Path(data_dir) if data_dir is not None else Path(config.DATA_DIR)


def find_file(prefix: Union[int, str], data_dir: Union[str, Path, None] = None) -> Path:
    """Find '<prefix>_*.md' in the data dir."""
    p = f"{int(prefix):02d}" if str(prefix).isdigit() else str(prefix)
    hits = sorted(data_path(data_dir).glob(f"{p}_*.md"))
    if not hits:
        raise FileNotFoundError(f"no file {p}_*.md in {data_path(data_dir)}")
    return hits[0]


# ------------------------------------------------------------------ markdown reader
@dataclass
class Table(_Dict):
    headers: list
    rows: list  # list[dict header -> cell text]
    lines: list  # 1-based file line of each row
    start_line: int = 0
    title: str = ""  # nearest heading above the table

    def row(self, n: int) -> dict:
        """1-based row access."""
        return self.rows[n - 1]


@dataclass
class TextLine(_Dict):
    line: int
    text: str
    kind: str  # heading | bullet | numbered | prose
    section: str = ""  # last heading or 'Label:' line above this one


def _split_row(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def _is_sep(cells: list[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-{2,}:?", c) or c == "" for c in cells) and any(cells)


def read_md_tables(path: Union[str, Path]) -> list[Table]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    tables: list[Table] = []
    title = ""
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("#"):
            title = s.lstrip("#").strip()
        if s.startswith("|") and i + 1 < len(lines) and _is_sep(_split_row(lines[i + 1])):
            headers = _split_row(lines[i])
            rows, nums = [], []
            j = i + 2
            while j < len(lines) and lines[j].strip().startswith("|"):
                cells = _split_row(lines[j])
                cells += [""] * (len(headers) - len(cells))
                rows.append(dict(zip(headers, cells[: len(headers)])))
                nums.append(j + 1)
                j += 1
            tables.append(Table(headers, rows, nums, i + 1, title))
            i = j
            continue
        i += 1
    return tables


def read_text_blocks(path: Union[str, Path]) -> list[TextLine]:
    """Everything outside tables: headings, bullets, numbered lines, prose."""
    out: list[TextLine] = []
    section = ""
    for n, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("|") or s.startswith("```"):
            continue
        if s.startswith("#"):
            section = s.lstrip("#").strip()
            out.append(TextLine(n, section, "heading", section))
        elif re.match(r"^[-*]\s+", s):
            out.append(TextLine(n, re.sub(r"^[-*]\s+", "", s), "bullet", section))
        elif re.match(r"^\d+\.\s+", s) and not re.match(r"^\d+\.\d+", s):
            out.append(TextLine(n, re.sub(r"^\d+\.\s+", "", s), "numbered", section))
        else:
            out.append(TextLine(n, s, "prose", section))
            if s.endswith(":"):
                section = s.rstrip(":")
    return out


def read_bullets(path: Union[str, Path]) -> list[TextLine]:
    return [t for t in read_text_blocks(path) if t.kind == "bullet"]


def read_prose(path: Union[str, Path]) -> list[TextLine]:
    return [t for t in read_text_blocks(path) if t.kind == "prose"]


def _main_table(path: Path) -> Table:
    tabs = read_md_tables(path)
    if not tabs:
        raise ValueError(f"no table in {path}")
    return tabs[0]


def _col(row: dict, *keywords: str) -> str:
    """Cell whose header contains any keyword (case-insensitive)."""
    for h, v in row.items():
        hl = h.lower()
        if any(k in hl for k in keywords):
            return v
    return ""


# ------------------------------------------------------------------ inventory (02)
@dataclass
class Asset(_Dict):
    tag: str
    hostname: str
    type: str
    ip: str
    public_ip: Optional[str]
    owner: str
    owner_person: Optional[str]
    data_owner: Optional[str]
    criticality: str
    holds_sensitive_data: bool
    cite: Cite


@dataclass
class InventoryNotes(_Dict):
    vpn_pool: Optional[tuple]  # (start_ip, end_ip)
    domain: Optional[str]
    fqdn_example: Optional[tuple]  # (fqdn, hostname)
    notes: list
    cite: Cite

    def short_name(self, fqdn: str) -> str:
        name = fqdn.strip().rstrip(".")
        if self.domain and name.lower().endswith("." + self.domain.lower()):
            name = name[: -(len(self.domain) + 1)]
        return name.split(".")[0]

    def resolve_fqdn(self, fqdn: str, assets: list) -> Optional[Asset]:
        """'FS01.orbit.local' -> asset whose hostname ends with 'FS01'."""
        short = self.short_name(fqdn).lower()
        if not short:
            return None
        exact = [a for a in assets if a.hostname.lower() == short]
        if exact:
            return exact[0]
        ends = [a for a in assets if a.hostname.lower().endswith(short)]
        bounded = [a for a in ends if re.search(r"[-_.]" + re.escape(short) + "$", a.hostname.lower())]
        hits = bounded or ends
        return hits[0] if len(hits) >= 1 else None


_NAME_RE = re.compile(r"^[A-Z][a-z]+(?: [A-Z][a-z]+)+$")


def _parse_owner(owner: str, type_text: str) -> tuple:
    bracket = re.search(r"\(([^)]*)\)", owner)
    person = data_owner = None
    if bracket:
        inner = bracket.group(1)
        m = re.search(r"data owner:\s*([^,)]+)", inner, re.I)
        if m:
            data_owner = person = m.group(1).strip()
        elif _NAME_RE.match(inner.strip()):
            person = inner.strip()
    elif _NAME_RE.match(owner.strip()):
        person = owner.strip()
    return person, data_owner


def load_inventory(data_dir=None) -> list[Asset]:
    path = find_file(2, data_dir)
    tab = _main_table(path)
    out = []
    for row in tab.rows:
        tag = _col(row, "tag")
        ip_text = _col(row, "ip")
        ips = IP_RE.findall(ip_text)
        pub = re.search(r"public\s+((?:\d{1,3}\.){3}\d{1,3})", ip_text)
        typ = _col(row, "type")
        owner = _col(row, "owner")
        person, downer = _parse_owner(owner, typ)
        out.append(Asset(
            tag=tag, hostname=_col(row, "hostname"), type=typ,
            ip=ips[0] if ips else "", public_ip=pub.group(1) if pub else None,
            owner=owner, owner_person=person, data_owner=downer,
            criticality=_col(row, "critical"),
            holds_sensitive_data=bool(re.search(r"\b(finance|HR|customer)\b", typ, re.I)),
            cite=Cite(file=path.name, row=tag)))
    return out


def load_inventory_notes(data_dir=None) -> InventoryNotes:
    path = find_file(2, data_dir)
    bullets = [b.text for b in read_bullets(path)]
    pool = domain = example = None
    for b in bullets:
        m = re.search(r"pool\s+((?:\d{1,3}\.){3}\d{1,3})\s+to\s+((?:\d{1,3}\.){3}\d{1,3})", b)
        if m:
            pool = (m.group(1), m.group(2))
        m = re.search(r"Domain name[^:]*:\s*([\w.-]+)", b)
        if m:
            domain = m.group(1).rstrip(".")
        m = re.search(r"example\s+([\w.-]+)\s+is\s+([\w-]+)", b)
        if m:
            example = (m.group(1), m.group(2))
    return InventoryNotes(pool, domain, example, bullets, Cite(file=path.name))


# ------------------------------------------------------------------ severity matrix (03)
@dataclass
class SeverityMatrix(_Dict):
    rows: list  # exact incident-type strings
    columns: list  # criticality names
    cells: dict  # row -> {column -> severity}
    notes: list
    cites: dict  # row -> Cite
    cite: Cite

    def _norm(self, s: str) -> str:
        return re.sub(r"\s+", " ", s.strip().lower())

    def match_rows(self, keyword: str) -> list:
        """Rows matching keyword: exact, then prefix, then all words contained."""
        k = self._norm(keyword)
        if not k:
            return []
        for test in (lambda r: r == k,
                     lambda r: r.startswith(k),
                     lambda r: all(w in r for w in re.findall(r"\w+", k))):
            hits = [r for r in self.rows if test(self._norm(r))]
            if hits:
                return hits
        return []

    def match_row(self, keyword: str) -> Optional[str]:
        hits = self.match_rows(keyword)
        return hits[0] if hits else None

    def lookup(self, incident_type: str, criticality: str) -> str:
        hits = self.match_rows(incident_type)
        if not hits:
            raise KeyError(f"no severity row matches {incident_type!r}")
        if len(hits) > 1:
            raise ValueError(f"{incident_type!r} is ambiguous: {hits}")
        col = next((c for c in self.columns if c.lower() == criticality.strip().lower()), None)
        if col is None:
            raise KeyError(f"no severity column {criticality!r}")
        return self.cells[hits[0]][col]

    def cite_for(self, incident_type: str) -> Cite:
        row = self.match_row(incident_type)
        return self.cites[row] if row else self.cite


def load_matrix(data_dir=None) -> SeverityMatrix:
    path = find_file(3, data_dir)
    tab = _main_table(path)
    first = tab.headers[0]
    cols = tab.headers[1:]
    rows, cells, cites = [], {}, {}
    for r in tab.rows:
        name = r[first]
        rows.append(name)
        cells[name] = {c: r[c] for c in cols}
        cites[name] = Cite(file=path.name, row=name)
    notes = [b.text for b in read_bullets(path)]
    return SeverityMatrix(rows, cols, cells, notes, cites, Cite(file=path.name))


# ------------------------------------------------------------------ escalation (04)
@dataclass
class EscalationRow(_Dict):
    severity: str
    who: str
    role: str
    name: Optional[str]
    contact: Optional[str]
    limit: str
    limit_minutes: Optional[int]
    how: str
    condition: Optional[str]
    needs_lookup: Optional[str]  # data_owner | system_owner | None
    cite: Cite


def _limit_minutes(text: str) -> Optional[int]:
    m = re.match(r"\s*(\d+)\s*(minute|hour|day)", text, re.I)
    if not m:
        return None
    return int(m.group(1)) * {"minute": 1, "hour": 60, "day": 1440}[m.group(2).lower()]


def load_escalation(data_dir=None) -> list[EscalationRow]:
    path = find_file(4, data_dir)
    tab = _main_table(path)
    out, seen = [], Counter()
    for r in tab.rows:
        sev, who = _col(r, "severity"), _col(r, "who")
        limit, how = _col(r, "limit"), _col(r, "how")
        contact = None
        bm = re.search(r"\(([^)]*)\)", who)
        if bm:
            inner = bm.group(1)
            if EMAIL_RE.fullmatch(inner.strip()) or PHONE_RE.fullmatch(inner.strip()):
                contact = inner.strip()
        base = re.sub(r"\s*\([^)]*\)", "", who).strip()
        if " - " in base:
            role, name = [x.strip() for x in base.split(" - ", 1)]
        else:
            role, name = base, None
        condition = None
        cm = re.search(r",\s*if\s+(.+)$", how, re.I)
        if cm:
            condition = cm.group(1).strip()
            how = how[: cm.start()].strip()
        lookup = None
        m = re.match(r"\s*(data|system) owner", who, re.I)
        if m:
            lookup = m.group(1).lower() + "_owner"
        seen[sev] += 1
        out.append(EscalationRow(sev, who, role, name, contact, limit, _limit_minutes(limit), how,
                                 condition, lookup,
                                 Cite(file=path.name, row=f"{sev} {role}")))
    return out


def load_escalation_note(data_dir=None) -> Optional[str]:
    """The note about when the clock starts (prose line outside the table)."""
    path = find_file(4, data_dir)
    for t in read_prose(path):
        if re.match(r"note\b", t.text, re.I):
            return re.sub(r"^note:\s*", "", t.text, flags=re.I)
    return None


# ------------------------------------------------------------------ change calendar (05)
@dataclass
class Change(_Dict):
    change_id: str
    date: str
    window_start_utc: Optional[str]
    window_end_utc: Optional[str]
    window_pkt: str
    system: str
    systems: list  # hostnames and CIDR networks
    performed_by: str
    actor_names: list
    actor_usernames: list
    actor_ips: list
    actor_hosts: list
    description: str
    status: str
    is_effective: bool
    cite: Cite

    def covers(self, t_utc: Union[str, datetime]) -> bool:
        if not (self.window_start_utc and self.window_end_utc):
            return False
        t = parse_utc(t_utc) if isinstance(t_utc, str) else t_utc
        return parse_utc(self.window_start_utc) <= t <= parse_utc(self.window_end_utc)


def _pkt_to_utc(date: str, hhmm: str, plus_days: int = 0) -> str:
    parts = [int(x) for x in hhmm.split(":")]
    h, m = parts[0], parts[1]
    s = parts[2] if len(parts) > 2 else 0
    d = datetime.strptime(date, "%Y-%m-%d").replace(hour=h, minute=m, second=s, tzinfo=PKT)
    return to_utc_iso(d + timedelta(days=plus_days))


def _parse_actor(text: str) -> tuple:
    names, users, ips, hosts = [], [], [], []
    for br in re.findall(r"\(([^)]*)\)", text):
        br = br.strip()
        if IP_RE.fullmatch(br):
            ips.append(br)
        elif br:
            users.append(br)
    base = re.sub(r"\s*\([^)]*\)", "", text).strip()
    if base:
        (hosts if HOST_RE.fullmatch(base) else names).append(base)
    return names, users, ips, hosts


def load_changes(data_dir=None) -> list[Change]:
    path = find_file(5, data_dir)
    tab = _main_table(path)
    out = []
    for r in tab.rows:
        cid, date = _col(r, "change id"), _col(r, "date")
        win = _col(r, "window")
        m = re.search(r"(\d{1,2}:\d{2}(?::\d{2})?)\s*[-\u2013to]+\s*(\d{1,2}:\d{2}(?::\d{2})?)", win)
        start = end = None
        if m and date:
            plus = 1 if m.group(2) < m.group(1) else 0
            start = _pkt_to_utc(date, m.group(1))
            end = _pkt_to_utc(date, m.group(2), plus)
        system = _col(r, "system")
        systems = CIDR_RE.findall(system)
        for h in HOST_RE.findall(re.sub(CIDR_RE, "", system)):
            if h not in systems:
                systems.append(h)
        by = _col(r, "performed")
        names, users, ips, hosts = _parse_actor(by)
        status = _col(r, "status")
        out.append(Change(
            change_id=cid, date=date, window_start_utc=start, window_end_utc=end,
            window_pkt=win, system=system, systems=systems, performed_by=by,
            actor_names=names, actor_usernames=users, actor_ips=ips, actor_hosts=hosts,
            description=_col(r, "description"), status=status,
            is_effective=not re.search(r"postponed|not performed|cancel", status, re.I),
            cite=Cite(file=path.name, row=cid)))
    return out


# ------------------------------------------------------------------ runbooks (06-10)
@dataclass
class RunbookStep(_Dict):
    number: int
    text: str
    cite: Cite


@dataclass
class Runbook(_Dict):
    runbook_id: str
    title: str
    file: str
    incident_type: Optional[str]
    steps: list  # list[RunbookStep]

    def step(self, n: int) -> Optional[RunbookStep]:
        return next((s for s in self.steps if s.number == n), None)


_RB_HEAD = re.compile(r"^#\s*Runbook\s+(RB-[A-Za-z0-9-]+)\s*[-\u2013\u2014:]\s*(.+?)\s*$")


def load_runbooks(data_dir=None) -> dict:
    out: dict = {}
    for path in sorted(data_path(data_dir).glob("*.md")):
        lines = path.read_text(encoding="utf-8").splitlines()
        head = next((_RB_HEAD.match(l.strip()) for l in lines if l.lstrip().startswith("#")
                     and _RB_HEAD.match(l.strip())), None)
        if not head:
            continue
        rid, title = head.group(1), head.group(2)
        steps, itype = [], None
        for l in lines:
            m = re.match(r"^\s*(\d+)\.\s+(.*\S)\s*$", l)
            if m:
                n = int(m.group(1))
                steps.append(RunbookStep(n, m.group(2), Cite(file=path.name, runbook=rid, step=n)))
                continue
            m = re.match(r"^\s*(?:incident type|applies to)\s*:\s*(.+)$", l, re.I)
            if m:
                itype = m.group(1).strip()
        out[rid] = Runbook(rid, title, path.name, itype, steps)
    return out


# ------------------------------------------------------------------ alerts (17)
@dataclass
class Alert(_Dict):
    alert_id: str
    ts_utc: str
    sensor: str
    description: str
    ips: list
    hostnames: list
    usernames: list
    domains: list
    cite: Cite


_USER_RE = re.compile(r"\b(?:by|for|user|account)\s+([a-z][a-z0-9._]{2,})\b")
_USER_STOP = {"the", "new", "any", "all", "this", "that", "and", "from", "outside"}


def extract_entities(text: str) -> dict:
    ips = list(dict.fromkeys(IP_RE.findall(text)))
    hosts = list(dict.fromkeys(HOST_RE.findall(re.sub(IP_RE, "", text))))
    users = [u for u in dict.fromkeys(_USER_RE.findall(text)) if u not in _USER_STOP]
    domains = [d for d in dict.fromkeys(DOMAIN_RE.findall(text)) if not IP_RE.fullmatch(d)]
    return {"ips": ips, "hostnames": hosts, "usernames": users, "domains": domains}


def parse_stamp(text: str) -> Optional[str]:
    """'2026-11-04 03:10:22 UTC' (zone UTC/Z/PKT, default UTC) -> ISO Z."""
    m = re.search(r"(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d)\s*(UTC|Z|PKT)?", text)
    if not m:
        return None
    tz = PKT if m.group(3) == "PKT" else timezone.utc
    dt = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)
    return to_utc_iso(dt)


def load_alerts(data_dir=None) -> list[Alert]:
    path = find_file(17, data_dir)
    tab = _main_table(path)
    out = []
    for r in tab.rows:
        aid = _col(r, "alert id")
        desc = _col(r, "description")
        ent = extract_entities(desc)
        out.append(Alert(aid, parse_stamp(_col(r, "time")) or "", _col(r, "sensor"), desc,
                         ent["ips"], ent["hostnames"], ent["usernames"], ent["domains"],
                         Cite(file=path.name, row=aid)))
    return out


# ------------------------------------------------------------------ users (18)
@dataclass
class User(_Dict):
    username: str
    full_name: str
    email: str
    role: str
    laptop_tag: str
    phone: str
    manager: str
    cite: Cite


def load_users(data_dir=None) -> list[User]:
    path = find_file(18, data_dir)
    tab = _main_table(path)
    return [User(_col(r, "username"), _col(r, "full name"), _col(r, "email"), _col(r, "role"),
                 _col(r, "laptop"), _col(r, "phone"), _col(r, "manager"),
                 Cite(file=path.name, row=_col(r, "username"))) for r in tab.rows]


def company_domain(users: list) -> Optional[str]:
    doms = Counter(u.email.split("@", 1)[1].lower() for u in users if "@" in u.email)
    return doms.most_common(1)[0][0] if doms else None


# ------------------------------------------------------------------ rules text (01)
def load_rules_text(data_dir=None) -> dict:
    """{'6.1': text, ...}. A section with unnumbered prose (e.g. 7) is keyed by its number."""
    path = find_file(1, data_dir)
    rules: dict = {}
    sec_no = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s:
            continue
        h = re.match(r"^#+\s*(\d+)\.\s*(.*)$", s)
        if h:
            sec_no = h.group(1)
            continue
        if s.startswith("#"):
            continue
        m = re.match(r"^(\d+\.\d+)\s+(.*)$", s)
        if m:
            rules[m.group(1)] = m.group(2)
        elif sec_no:
            rules[sec_no] = (rules[sec_no] + " " + s) if sec_no in rules else s
    return rules


def load_rule_sections(data_dir=None) -> dict:
    """{'6': 'VPN', ...} section titles."""
    path = find_file(1, data_dir)
    out = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        h = re.match(r"^#+\s*(\d+)\.\s*(.*\S)\s*$", raw.strip())
        if h:
            out[h.group(1)] = h.group(2)
    return out


@dataclass
class ReportSection(_Dict):
    title: str
    qualifier: Optional[str]  # text in brackets, e.g. 'UTC, with file and line'


def report_sections(data_dir=None) -> list[ReportSection]:
    """Ordered report sections from the rule that lists them (the report-format rule)."""
    rules = load_rules_text(data_dir)
    titles = load_rule_sections(data_dir)
    key = next((k for k, v in titles.items() if "report" in v.lower()), None)
    text = rules.get(key or "", "")
    if ":" in text:
        text = text.split(":", 1)[1]
    out = []
    for part in re.split(r";\s*", text.strip().rstrip(".")):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"^(.*?)\s*\((.*)\)$", part)
        out.append(ReportSection(m.group(1).strip(), m.group(2).strip()) if m
                   else ReportSection(part, None))
    return out


# ------------------------------------------------------------------ bundle
@dataclass
class Tables(_Dict):
    inventory: list
    inventory_notes: InventoryNotes
    matrix: SeverityMatrix
    escalation: list
    escalation_note: Optional[str]
    changes: list
    runbooks: dict
    alerts: list
    users: list
    company_domain: Optional[str]
    rules: dict
    rule_sections: dict
    report_sections: list
    coverage: Any


def load_tables(data_dir=None) -> Tables:
    from triage.parsers.coverage import load_coverage
    users = load_users(data_dir)
    return Tables(
        inventory=load_inventory(data_dir), inventory_notes=load_inventory_notes(data_dir),
        matrix=load_matrix(data_dir), escalation=load_escalation(data_dir),
        escalation_note=load_escalation_note(data_dir), changes=load_changes(data_dir),
        runbooks=load_runbooks(data_dir), alerts=load_alerts(data_dir), users=users,
        company_domain=company_domain(users), rules=load_rules_text(data_dir),
        rule_sections=load_rule_sections(data_dir), report_sections=report_sections(data_dir),
        coverage=load_coverage(data_dir))
