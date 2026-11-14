"""P7: runbook action selector (files 06 to 10).

Actions come only from runbook files, in runbook order, each with its runbook ID and
step number (01 rule 5.1). Concrete values from the incident go into `detail`. A step
that says to open another runbook pulls it in when its condition holds. A conditional
step ("If it is approved, ...") is kept only when the incident fact holds.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Optional

from triage.models import CONFIRMED, NOT_ENOUGH_EVIDENCE, SUSPECTED, Incident
from triage.rules.severity import _rules, _tables, reached_assets

_RB_ID = re.compile(r"\bRB-[A-Z]+-\d+\b")


def _fdata(f) -> dict:
    return getattr(f, "data", None) or {}


def _ents(incident: Incident, prefix: str) -> list:
    out = []
    for f in incident.findings:
        for e in f.entities:
            if e.startswith(prefix):
                v = e[len(prefix):]
                if v not in out:
                    out.append(v)
    return out


def _by_rule(incident: Incident, rule: str, labels=(CONFIRMED, SUSPECTED)) -> list:
    return [f for f in incident.findings if f.rule == rule and f.label in labels]


def _tref(c) -> str:
    d = c.to_dict() if hasattr(c, "to_dict") else dict(c)
    m = re.match(r"(\d+)_", d.get("file", ""))
    f = f"f{m.group(1)}" if m else d.get("file", "")
    if d.get("row"):
        return f"{f} {d['row']}"
    return f"{f} L{d['line']}" if d.get("line") else f


def incident_context(incident: Incident, tables: Any = None, rules: Any = None) -> dict:
    """Concrete values (users, IPs, domains, assets, missing sources) drawn from the findings."""
    tables, rules = _tables(tables), _rules(rules)
    c: dict = {"incident_id": incident.incident_id}
    deliv = _by_rule(incident, "phishing_delivered")
    c["msgid"] = _fdata(deliv[0]).get("msgid") if deliv else None
    c["recipients"] = [u for f in deliv for u in _fdata(f).get("recipients", [])]
    c["sender_domain"] = _fdata(deliv[0]).get("sender_domain") if deliv else None
    c["link_host"] = _fdata(deliv[0]).get("link_host") if deliv else None
    clicks = _by_rule(incident, "phishing_click", (CONFIRMED,))
    c["clickers"] = [_fdata(f).get("user") for f in clicks]
    c["click_laptops"] = [(_fdata(f).get("user"), _fdata(f).get("laptop_host"), _fdata(f).get("laptop_ip"))
                          for f in clicks]
    c["link_ips"] = sorted({_fdata(f).get("link_ip") for f in clicks if _fdata(f).get("link_ip")})
    c["no_click"] = [_fdata(f).get("user") for f in incident.findings if f.rule == "phishing_no_click"]
    mfa = _by_rule(incident, "mfa_fatigue")
    conc = _by_rule(incident, "concurrent_use")
    comp = []
    for f in mfa + _by_rule(incident, "attacker_session") + conc:
        u = _fdata(f).get("user")
        if u and u not in comp:
            comp.append(u)
    c["compromised"] = comp or [u for u in c["clickers"] if u]
    c["attacker_ips"] = []
    for f in mfa:
        ip = _fdata(f).get("src_ip")
        if ip and ip not in c["attacker_ips"]:
            c["attacker_ips"].append(ip)
    for ip in c["link_ips"]:
        if ip not in c["attacker_ips"]:
            c["attacker_ips"].append(ip)
    c["sessions"] = _ents(incident, "session:")
    c["session_ips"] = {}
    for f in mfa:
        d = _fdata(f)
        if d.get("session_id"):
            c["session_ips"][d["session_id"]] = d.get("assigned_ip")
    reached, excluded = reached_assets(incident, tables, rules)
    c["reached"] = [a for a, *_ in reached]
    c["excluded"] = excluded
    tr = _by_rule(incident, "large_transfer")
    c["transfer"] = _fdata(tr[0]) if tr else None
    c["transfer_finding"] = tr[0] if tr else None
    web = _by_rule(incident, "web_attack")
    c["web"] = _fdata(web[0]) if web else None
    c["web_success"] = [_fdata(f) for f in _by_rule(incident, "web_attack_success")]
    rec = _by_rule(incident, "recon")
    c["recon"] = _fdata(rec[0]) if rec else None
    c["missing"] = []
    for f in incident.findings:
        m = _fdata(f).get("missing")
        if f.label != NOT_ENOUGH_EVIDENCE or not m:
            continue
        for n in (m if isinstance(m, list) else [m]):
            if n not in [x for x, _ in c["missing"]]:
                c["missing"].append((n, f))
    c["files"] = sorted({ev.file for f in incident.findings for ev in f.evidence
                         if re.match(r"1\d_|20_", ev.file) and getattr(ev, "line", None)})
    c["alerts"] = _ents(incident, "alert:")
    c["finding_ids"] = [f.finding_id for f in incident.findings]
    c["sensitive"] = [a for a in c["reached"] if a.holds_sensitive_data]
    c["facts"] = {
        "click_found": bool(clicks),
        "phishing_source": bool(clicks or deliv),
        "large_transfer": bool(tr),
        "approved": bool(c["recon"] and c["recon"].get("approved")),
        "not_approved": bool(c["recon"] and not c["recon"].get("approved")),
        "external_source": bool((c["recon"] and c["recon"].get("external")) or c["web"]),
        "internal_source": bool(c["recon"] and not c["recon"].get("external")),
        "sensitive": bool(c["sensitive"]),
    }
    c["tables"] = tables
    return c


def _rbref(c: dict, keyword: str, step: int) -> str:
    rb = _runbook_for(c["tables"], keyword)
    return f"{rb.runbook_id} step {step}" if rb else f"the {keyword} runbook step {step}"


def _user(tables, u):
    return next((r for r in tables.users if r.username == u), None)


def _missing(c: dict, *kw: str) -> list:
    return [(n, f) for n, f in c["missing"] if n and any(k in n.lower() for k in kw)]


# ------------------------------------------------------------------ detail fillers
def _d_recipients(c, rb, s):
    return (f"Recipients of {c['msgid']}: {', '.join(c['recipients'])}." if c["msgid"] else "")


def _d_remove(c, rb, s):
    return f"Remove {c['msgid']} from the mailboxes of {', '.join(c['recipients'])}." if c["msgid"] else ""


def _d_block_domains(c, rb, s):
    doms = [d for d in (c["sender_domain"], c["link_host"]) if d]
    return f"Block {' and '.join(doms)} at the email gateway and the perimeter firewall." if doms else ""


def _d_who_clicked(c, rb, s):
    parts = [f"{u}: {h} ({ip}) connected to {', '.join(c['link_ips'])}, click seen"
             for u, h, ip in c["click_laptops"]]
    parts += [f"{u}: no connection to {', '.join(c['link_ips']) or 'the link address'}" for u in c["no_click"]]
    return "; ".join(parts) + "." if parts else ""


def _d_open_cred(c, rb, s):
    ids = _RB_ID.findall(s.text)
    if c["clickers"]:
        return f"Click found for {', '.join(c['clickers'])}: open {', '.join(ids)} for {', '.join(c['clickers'])}."
    return "No click found: not opened."


def _d_warn(c, rb, s):
    t = c["tables"]
    em = [(_user(t, u).email if _user(t, u) else u) for u in c["recipients"]]
    return f"Warn {', '.join(em)}." if em else ""


def _d_record(c, rb, s):
    return f"Record findings {', '.join(c['finding_ids'])} in the ticket for {c['incident_id']}."


def _d_call(c, rb, s):
    t = c["tables"]
    out = []
    for u in c["compromised"]:
        r = _user(t, u)
        if r:
            out.append(f"Call {r.full_name} on {r.phone} ({_tref(r.cite)}) and ask if the login was theirs.")
    return " ".join(out)


def _d_disable(c, rb, s):
    if not c["compromised"]:
        return ""
    ss = [f"{sid}" + (f" ({c['session_ips'][sid]})" if c["session_ips"].get(sid) else "") for sid in c["sessions"]]
    return (f"Disable {', '.join(c['compromised'])} in the directory"
            + (f" and end VPN session {', '.join(ss)}." if ss else "."))


def _d_block_ip(c, rb, s):
    title = rb.title.lower()
    if "web" in title and c["web"]:
        ips = [c["web"]["src_ip"]]
    elif ("scan" in title or "recon" in title) and c["recon"]:
        ips = [c["recon"]["src_ip"]]
    else:
        ips = c["attacker_ips"]
    return f"Block {', '.join(ips)} at the perimeter firewall." if ips else ""


def _d_reset(c, rb, s):
    return (f"Reset the password of {', '.join(c['compromised'])} only after step 2 is done, through the "
            f"helpdesk with identity checks, then new MFA enrollment." if c["compromised"] else "")


def _d_review(c, rb, s):
    if not c["reached"]:
        return ""
    txt = (f"Systems reached by {', '.join(c['compromised'])}: "
           + ", ".join(f"{a.hostname} ({a.criticality})" for a in c["reached"]) + ".")
    if c["excluded"]:
        txt += " Also Kerberos traffic only: " + ", ".join(a.hostname for a, _ in c["excluded"]) + "."
    return txt


def _d_disconnect(c, rb, s):
    laps = [f"{h} ({ip}, {u}'s laptop)" for u, h, ip in c["click_laptops"] if h]
    return f"Phishing was the source: disconnect {', '.join(laps)}." if laps else ""


def _d_every_system(c, rb, s):
    ids = _RB_ID.findall(s.text)
    t = c["transfer"]
    if t:
        return (f"Large transfer seen: {t['bytes']:,} bytes from {t.get('source_host')} to {t['dest_ip']}; "
                f"open {', '.join(ids)}.")
    return f"No large transfer seen: {', '.join(ids)} not opened." if ids else ""


def _d_keep_logs(c, rb, s):
    return f"Keep unchanged: {', '.join(c['files'])}." if c["files"] else ""


def _d_find_transfer(c, rb, s):
    from triage.rules.detectors import span
    t = c["transfer"]
    if not t:
        return ""
    return (f"{t['bytes']:,} bytes, {span(t['start'], t['end'])}, from {t.get('source_host')} to {t['dest_ip']}"
            + (f" ({t.get('user')} inside {t.get('session_id')})" if t.get("session_id") else "") + ".")


def _d_block_dest(c, rb, s):
    t = c["transfer"]
    if not t:
        return ""
    return (f"Block {t['dest_ip']}" + (f", a VPN pool address that is {t.get('user')} only inside "
                                         f"{t.get('session_id')}; ending that session is "
                                         f"{_rbref(c, 'credential', 2)}"
                                         if t.get("session_id") else "") + ".")


def _d_no_reboot(c, rb, s):
    t = c["transfer"]
    return f"Copy the logs. Do not reboot {t.get('source_host')}." if t else ""


def _d_ask_owner(c, rb, s):
    t = c["transfer"]
    if not t:
        return ""
    a = next((x for x in c["tables"].inventory if x.tag == t.get("source_tag")), None)
    return f"Ask {a.owner} what data {a.hostname} ({a.type}) holds." if a else ""


def _d_audit(c, rb, s):
    m = _missing(c, "audit", "file access")
    if m:
        return f"{m[0][0]}: not collected. Record that it is unknown which files were read."
    return "File-level audit log available: check it."


def _d_legal(c, rb, s):
    if not c["sensitive"]:
        return "No reached system holds finance, HR or customer data: not needed."
    t = c["tables"]
    row = next((r for r in t.escalation if r.condition and re.search(r"(?i)legal", r.role)), None)
    who = f"{row.role} ({row.name}, {row.contact})" if row else "Legal and Compliance"
    return f"{', '.join(a.hostname + ' (' + a.type + ')' for a in c['sensitive'])}: inform {who}."


def _d_web_requests(c, rb, s):
    w = c["web"]
    return (f"{w['src_ip']}: {w['count']} requests to {', '.join(w['paths'])} on {w['host']}." if w else "")


def _d_web_codes(c, rb, s):
    w = c["web"]
    if not w:
        return ""
    txt = f"Status codes {', '.join(map(str, w['statuses']))}."
    for x in c["web_success"]:
        txt += (f" A {x['size']:,}-byte 200 against {x['error_size']:,}-byte errors: success suspected.")
    return txt


def _d_web_team(c, rb, s):
    w = c["web"]
    return f"Review the code of {', '.join(w['paths'])} on {w['host']}." if w else ""


def _d_db_logs(c, rb, s):
    m = _missing(c, "query", "database")
    if m:
        return f"Cannot be completed: {m[0][0]} is not available (not forwarded to the SOC)."
    return ""


def _d_sqli_rule(c, rb, s):
    w = c["web"]
    if not w:
        return ""
    al = [a for a in c["tables"].alerts if a.alert_id in (w.get("alerts") or [])]
    return (f"Check the SQL injection rule on the web server filter; {', '.join(a.alert_id + ' (' + a.sensor + ')' for a in al)} "
            f"shows a pattern was detected." if al else "Check the SQL injection rule on the web server filter.")


def _d_calendar(c, rb, s):
    r = c["recon"]
    if not r:
        return ""
    if r.get("approved"):
        return "An approved scan matches."
    nm = r.get("near_misses") or []
    return ("No approved scan matches the source, target and window"
            + (f" (closest: {', '.join(nm)}, not a match)" if nm else "") + ".")


def _d_ports(c, rb, s):
    r = c["recon"]
    if not r:
        return ""
    return (f"Denied: {', '.join(r['denied_ports'])}. Answered: {', '.join(r['allowed_ports']) or 'none'}"
            + (f" (probes {', '.join(r['probes'])})" if r.get("probes") else "")
            + (". No login attempts followed." if not r.get("logins_followed") else ". Login attempts followed."))


def _d_watch(c, rb, s):
    r = c["recon"]
    return f"Watch {r['src_ip']} for the next 24 hours." if r else ""


def _d_owner(c, rb, s):
    r = c["recon"]
    return f"Find the owner of {r['src_ip']}." if r else ""


FILLERS: list = [
    (r"(?i)find every recipient", _d_recipients),
    (r"(?i)remove or quarantine", _d_remove),
    (r"(?i)block the sender domain", _d_block_domains),
    (r"(?i)for each recipient.*firewall", _d_who_clicked),
    (r"(?i)if a click is found", _d_open_cred),
    (r"(?i)warning notice", _d_warn),
    (r"(?i)record all findings", _d_record),
    (r"(?i)call the real user", _d_call),
    (r"(?i)disable the account", _d_disable),
    (r"(?i)reset the password", _d_reset),
    (r"(?i)review all logins", _d_review),
    (r"(?i)disconnect the user's laptop", _d_disconnect),
    (r"(?i)for every system reached", _d_every_system),
    (r"(?i)keep all logs", _d_keep_logs),
    (r"(?i)unusually large transfer", _d_find_transfer),
    (r"(?i)block the destination", _d_block_dest),
    (r"(?i)do not reboot", _d_no_reboot),
    (r"(?i)ask the system owner", _d_ask_owner),
    (r"(?i)file-level audit", _d_audit),
    (r"(?i)inform legal", _d_legal),
    (r"(?i)find the attacker ip and all its requests", _d_web_requests),
    (r"(?i)response codes", _d_web_codes),
    (r"(?i)web team", _d_web_team),
    (r"(?i)database server logs", _d_db_logs),
    (r"(?i)sql injection rule", _d_sqli_rule),
    (r"(?i)check the change calendar", _d_calendar),
    (r"(?i)which scanned ports", _d_ports),
    (r"(?i)watch the source", _d_watch),
    (r"(?i)find the device owner", _d_owner),
    (r"(?i)block the .*ip", _d_block_ip),
]


def _detail(c: dict, rb: Any, s: Any) -> str:
    for pat, fn in FILLERS:
        if re.search(pat, s.text):
            try:
                return fn(c, rb, s) or ""
            except Exception:
                return ""
    return ""


def _runbook_for(tables: Any, keyword: str):
    k = keyword.lower()
    for rid, rb in tables.runbooks.items():
        if k in rb.title.lower():
            return rb
    return None


def _step_ok(text: str, facts: dict, conds: list) -> bool:
    for c in conds:
        if re.search(c["pattern"], text) and not facts.get(c["fact"], False):
            return False
    return True


def _action(rb, s, c) -> dict:
    return {"runbook": rb.runbook_id, "step": s.number, "text": s.text, "detail": _detail(c, rb, s),
            "cite": s.cite.to_dict()}


def actions(incident: Incident, tables: Any = None, rules: Any = None) -> list:
    """Actions taken only from runbooks, each with runbook ID, step number and concrete values."""
    tables, rules = _tables(tables), _rules(rules)
    ac = rules.get("actions", {})
    c = incident_context(incident, tables, rules)
    facts = c["facts"]
    if incident.incident_id.startswith("ANOM") or (
            incident.findings and all(f.rule == "concurrent_use" for f in incident.findings)):
        spec = ac.get("anomaly", {})
        rb = _runbook_for(tables, spec.get("runbook_keyword", "credential"))
        if not rb:
            return []
        return [_action(rb, s, c) for s in rb.steps if s.number in set(spec.get("steps", [1]))]
    present = {f.rule for f in incident.findings if f.label in (CONFIRMED, SUSPECTED)}
    triggered = []
    for e in ac.get("entry", []):
        if present & set(e.get("rules", [])):
            rb = _runbook_for(tables, e["runbook_keyword"])
            if rb and rb.runbook_id not in triggered:
                triggered.append(rb.runbook_id)
    refs = {rid: [r for s in tables.runbooks[rid].steps for r in _RB_ID.findall(s.text)
                  if r != rid] for rid in triggered}
    roots = [r for r in triggered if not any(r in refs[o] for o in triggered if o != r)]
    order: list = []
    conds = ac.get("conditions", [])
    oconds = ac.get("open_conditions", [])

    def visit(rid: str) -> None:
        if rid in order:
            return
        order.append(rid)
        for s in tables.runbooks[rid].steps:
            if not _step_ok(s.text, facts, conds):
                continue
            for r in _RB_ID.findall(s.text):
                if r in triggered and r != rid and _step_ok(s.text, facts, oconds):
                    visit(r)

    for r in roots or triggered[:1]:
        visit(r)
    for r in triggered:
        visit(r)
    out = []
    for rid in order:
        rb = tables.runbooks[rid]
        for s in rb.steps:
            if _step_ok(s.text, facts, conds):
                out.append(_action(rb, s, c))
    return out
