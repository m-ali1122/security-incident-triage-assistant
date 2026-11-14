"""P7: rule engine entry point.

build_incidents runs every detector, clusters findings into incidents over actor keys
(P6), then computes severity, escalation and runbook actions for each incident and
renumbers them (P1 first). Harmless alerts and decoy changes are reported with why.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from triage.models import HARMLESS, Finding, Incident
from triage.rules.detectors import (fdata, load_rules, refs, run_rules_ctx, span, tref, when)
from triage.rules.escalation import clock_start, escalation
from triage.rules.runbooks import actions, incident_context
from triage.rules.severity import reached_assets, severity


@dataclass
class EngineResult:
    findings: list = field(default_factory=list)  # list[Finding]
    incidents: list = field(default_factory=list)  # list[Incident], INC-n
    anomalies: list = field(default_factory=list)  # list[Incident], ANOM-n
    harmless: list = field(default_factory=list)  # [{alert, why, change_id, finding_id, steps, evidence}]
    decoys: list = field(default_factory=list)  # [{change_id, why, status, date, cite, near_misses}]
    extras: dict = field(default_factory=dict)  # incident_id -> {title, summary, ...}
    calendar: list = field(default_factory=list)  # [{label, approved, change_id, reasons}]

    def incident(self, incident_id: str) -> Optional[Incident]:
        return next((i for i in self.incidents + self.anomalies if i.incident_id == incident_id), None)

    def _inc(self, i: Incident) -> dict:
        d = i.to_dict()
        d.update(self.extras.get(i.incident_id, {}))
        return d

    def to_dict(self) -> dict:
        return {"findings": [f.to_dict() for f in self.findings],
                "incidents": [self._inc(i) for i in self.incidents],
                "anomalies": [self._inc(i) for i in self.anomalies],
                "harmless": [dict(h) for h in self.harmless],
                "decoys": [dict(d) for d in self.decoys],
                "calendar": [dict(c) for c in self.calendar]}


def _cluster(findings: list, graph: Any) -> list:
    try:
        from triage.graph.cluster import cluster
        return cluster(findings, graph=graph)
    except NotImplementedError:
        pass
    # fallback: same contract as P6 (union over actor keys)
    fs = [f for f in findings if f.label != HARMLESS and any(e.startswith("actor:") for e in f.entities)]
    comps: list = []
    for f in fs:
        keys = {e for e in f.entities if e.startswith("actor:")}
        hit = [c for c in comps if c[0] & keys]
        merged = [keys, [f]]
        for c in hit:
            merged[0] |= c[0]
            merged[1] = c[1] + merged[1]
            comps.remove(c)
        comps.append(merged)
    out, n, m = [], 0, 0
    for keys, fl in sorted(comps, key=lambda c: min(f.finding_id for f in c[1])):
        fl.sort(key=lambda f: f.finding_id)
        if all(f.rule == "concurrent_use" for f in fl):
            m += 1
            out.append(Incident(f"ANOM-{m}", findings=fl))
        else:
            n += 1
            out.append(Incident(f"INC-{n}", findings=fl))
    return out


def _renumber(incidents: list, graph: Any) -> list:
    try:
        from triage.graph.cluster import renumber
        return renumber(incidents, graph)
    except (NotImplementedError, TypeError):
        sev = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
        real = [i for i in incidents if not i.incident_id.startswith("ANOM")]
        an = [i for i in incidents if i.incident_id.startswith("ANOM")]
        real.sort(key=lambda i: (sev.get(i.severity or "", 9), min(f.finding_id for f in i.findings)))
        for k, i in enumerate(real, 1):
            i.incident_id = f"INC-{k}"
        return real + an


def _timeline(inc: Incident, ctx: Any) -> list:
    evs = []
    for f in inc.findings:
        for c in f.evidence:
            e = ctx.by_cite.get((c.file, c.line)) if c.line else None
            if e is not None and e not in evs:
                evs.append(e)
    evs.sort(key=lambda e: (ctx.start(e), e.source_file, e.line))
    return [e.event_id for e in evs]


_TITLES = [("phishing_delivered", "Phishing"), ("mfa_fatigue", "credential compromise"),
           ("large_transfer", "large transfer"), ("web_attack", "web application attack"),
           ("recon", "external reconnaissance"), ("concurrent_use", "concurrent sessions")]


def _extras(inc: Incident, ctx: Any, tables: Any) -> dict:
    rules = {f.rule for f in inc.findings}
    c = incident_context(inc, tables)
    names = [t for r, t in _TITLES if r in rules]
    if "concurrent sessions" in names and len(names) > 1:
        names.remove("concurrent sessions")
    title = ", ".join(names) if names else inc.incident_id
    title = title[0].upper() + title[1:]
    if c["web"]:
        title += f" on {c['web']['host']}"
    if c["recon"]:
        title += f" from {c['recon']['src_ip']}"
    if not c["web"] and not c["recon"] and c["compromised"] and inc.incident_id.startswith("ANOM"):
        title += f": {', '.join(c['compromised'])}"
    assets = []
    for t in [e.split(":", 1)[1] for f in inc.findings for e in f.entities if e.startswith("asset:")]:
        a = next((x for x in tables.inventory if x.tag == t), None)
        if a and a.tag not in [x["tag"] for x in assets]:
            assets.append({"tag": a.tag, "hostname": a.hostname, "type": a.type,
                           "criticality": a.criticality, "cite": a.cite.to_dict()})
    reached, _ = reached_assets(inc, tables)
    rtags = {a.tag for a, *_ in reached}
    for a in assets:
        a["reached"] = a["tag"] in rtags
    accounts = []
    for u in [e.split(":", 1)[1] for f in inc.findings for e in f.entities if e.startswith("user:")]:
        r = next((x for x in tables.users if x.username == u), None)
        if u not in [x["username"] for x in accounts]:
            accounts.append({"username": u, "full_name": r.full_name if r else None,
                             "compromised": u in c["compromised"], "cite": r.cite.to_dict() if r else None})
    first = clock_start(inc, tables)
    times = [ctx.start(ctx.by_cite[(cc.file, cc.line)]) for f in inc.findings for cc in f.evidence
             if cc.line and (cc.file, cc.line) in ctx.by_cite]
    lab = {}
    for f in inc.findings:
        lab.setdefault(f.label, []).append(f.finding_id)
    sev = inc.severity
    summary = (f"{inc.incident_id} ({sev or 'no severity, anomaly'}): {title[0].lower() + title[1:]}. "
               + (f"Activity {span(min(times), max(times))}. " if times else "")
               + f"{len(lab.get('confirmed', []))} confirmed, {len(lab.get('suspected', []))} suspected, "
               f"{len(lab.get('not_enough_evidence', []))} not enough evidence in the logs."
               + (f" Accounts: {', '.join(a['username'] for a in accounts)}." if accounts else "")
               + (f" Reached: {', '.join(a.hostname for a, *_ in reached)}." if reached else ""))
    return {"title": title, "summary": summary, "affected_assets": assets, "affected_accounts": accounts,
            "clock_start": ({"alert": first.alert_id, "ts_utc": first.ts_utc, "text": when(first.ts_utc),
                             "cite": first.cite.to_dict(),
                             "assumption": "The escalation clock starts at the first IDS alert of the incident "
                                           "(04 note: the limit starts when the SOC first sees the incident)."}
                            if first else None),
            "severity_steps": list(getattr(inc, "_severity_steps", [])),
            "first_utc": min(times).strftime("%Y-%m-%dT%H:%M:%SZ") if times else None,
            "last_utc": max(times).strftime("%Y-%m-%dT%H:%M:%SZ") if times else None}


def _decoys(ctx: Any, tables: Any) -> list:
    approved = {m.change_id for _, _, m in ctx.calendar_log if m.approved}
    out = []
    for ch in tables.changes:
        if ch.change_id in approved:
            continue
        near = []
        for label, act, m in ctx.calendar_log:
            chk = next((c for c in m.checks if c.change_id == ch.change_id), None)
            if chk and chk.score > 0:
                near.append({"activity": label,
                             "matched": [k for k in ("system", "actor", "window") if getattr(chk, k)],
                             "reasons": list(chk.reasons)})
        if not ch.is_effective:
            why = f"Status '{ch.status}': the change was not performed, so it approves nothing."
        elif ctx.log_date and ch.date != ctx.log_date:
            why = f"Dated {ch.date}; the logs cover only {ctx.log_date}. It approves nothing on {ctx.log_date}."
        else:
            why = ("No logged activity matches its system, actor and window, so it approves nothing.")
            if near:
                why += " Closest: " + "; ".join(f"{n['activity']} matched only {', '.join(n['matched'])}"
                                                for n in near) + "."
        out.append({"change_id": ch.change_id, "why": why, "status": ch.status, "date": ch.date,
                    "window_pkt": ch.window_pkt, "system": ch.system, "performed_by": ch.performed_by,
                    "cite": ch.cite.to_dict(), "near_misses": near})
    return out


def build_incidents(graph: Any, events: list, tables: Any, coverage: Any = None,
                    rules: Optional[dict] = None) -> EngineResult:
    rules = rules or load_rules()
    if graph is None:
        try:
            from triage.graph.build import build_graph
            graph = build_graph(events, tables)
        except Exception:
            graph = None
    findings, ctx = run_rules_ctx(graph, events, tables, coverage, rules)
    comps = _cluster(findings, graph)
    by_id = {f.finding_id: f for f in findings}
    for inc in comps:  # keep the detector objects (they carry `data`)
        inc.findings = sorted((by_id.get(f.finding_id, f) for f in inc.findings), key=lambda f: f.finding_id)
    for inc in comps:
        anomaly = inc.incident_id.startswith("ANOM")
        if anomaly:
            inc.severity, steps = None, ["1. Anomaly: suspected misuse only, not scored as an incident "
                                         "(no attack pattern links it to an incident, 01 rule 4.3)."]
            inc.parts = []
        else:
            inc.severity, steps = severity(inc, tables, graph, rules)
        inc._severity_steps = steps
        inc.notify = escalation(inc.severity, inc, tables, rules) if inc.severity else []
        inc.actions = actions(inc, tables, rules)
        inc.timeline = _timeline(inc, ctx)
    comps = _renumber(comps, graph)
    res = EngineResult(findings=findings)
    res.incidents = [i for i in comps if not i.incident_id.startswith("ANOM")]
    res.anomalies = [i for i in comps if i.incident_id.startswith("ANOM")]
    for inc in comps:
        res.extras[inc.incident_id] = _extras(inc, ctx, tables)
    for f in findings:
        if f.label != HARMLESS:
            continue
        d = fdata(f)
        res.harmless.append({"alert": d.get("alert"), "why": f.statement, "change_id": d.get("change_id"),
                             "finding_id": f.finding_id, "steps": list(f.steps),
                             "evidence": [c.to_dict() for c in f.evidence]})
    res.decoys = _decoys(ctx, tables)
    res.calendar = [{"activity": label, "approved": m.approved, "change_id": m.change_id,
                     "reasons": list(m.reasons), "explain": m.explain()} for label, _, m in ctx.calendar_log]
    return res
