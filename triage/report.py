"""P8: rule 7 incident report, Markdown and JSON, no LLM call.

The section titles come from the rules file (tables.report_sections); the content
comes from the fact store. Nothing here writes a data-pack specific value.
"""
from __future__ import annotations

from typing import Optional

from triage.models import fmt_utc_pkt

GENERATED_BY = "template (no LLM call)"
# report-section keys, in rule 7 order; titles are read from the rules file.
_KEYS = ["summary", "timeline", "affected", "severity", "confirmed", "suspected",
         "not_enough_evidence", "missing_sources", "closed_as_harmless", "actions", "notify"]


def _store(facts):
    if facts is not None:
        return facts
    from triage.facts import get_facts
    return get_facts()


def cite_str(c: dict) -> str:
    if c.get("runbook"):
        return f"{c['file']} {c['runbook']} step {c.get('step')}"
    if c.get("line") is not None:
        return f"{c['file']} line {c['line']}"
    if c.get("row") is not None:
        return f"{c['file']} row {c['row']}"
    return c["file"]


def _cites(cs: list) -> str:
    seen, out = set(), []
    for c in cs or []:
        s = cite_str(c)
        if s not in seen:
            seen.add(s)
            out.append(s)
    return "; ".join(out)


def _rows(cites: list) -> set:
    return {(c.get("file"), (c.get("row") or "").lower()) for c in cites or [] if c.get("row")}


def _relevant_gaps(facts, inc: dict) -> list:
    """Gaps and not-collected sources that one of this incident's findings cites."""
    cited = _rows([c for f in inc["findings"] for c in f["evidence"]])
    out = []
    for g in facts.gaps():
        gd = g.to_dict()
        if _rows(gd["evidence"]) & cited:
            out.append(gd)
    for m in facts.missing_sources():
        if _rows(m["evidence"]) & cited:
            out.append(m)
    return out


def _incident_report(facts, inc: dict) -> dict:
    iid = inc["incident_id"]
    by = {"confirmed": [], "suspected": [], "not_enough_evidence": []}
    for f in inc["findings"]:
        if f["label"] in by:
            by[f["label"]].append(f)
    clock = inc.get("clock_start") or {}
    assets = inc.get("affected_assets", [])
    accounts = inc.get("affected_accounts", [])
    return {
        "incident_id": iid,
        "title": inc.get("title", iid),
        "summary": inc.get("summary", ""),
        "timeline": facts.timeline(iid),
        "affected": {"assets": [f"{a['tag']} {a['hostname']}" for a in assets],
                     "accounts": [a["username"] for a in accounts],
                     "assets_detail": assets, "accounts_detail": accounts},
        "severity": {"value": inc.get("severity"), "steps": list(inc.get("severity_steps", [])),
                     "parts": [{k: v for k, v in p.items() if k != "rules"} for p in inc.get("parts", [])],
                     "clock_start_assumption": clock.get("assumption")},
        "confirmed": by["confirmed"], "suspected": by["suspected"],
        "not_enough_evidence": by["not_enough_evidence"],
        "missing_sources": _relevant_gaps(facts, inc),
        "closed_as_harmless": [dict(h) for h in facts.engine.harmless],
        "actions": [dict(a) for a in inc.get("actions", [])],
        "notify": [dict(n) for n in inc.get("notify", [])],
    }


def build_report(facts=None, incident_id: Optional[str] = None) -> dict:
    facts = _store(facts)
    d = facts._engine_dict
    incs = [_incident_report(facts, i) for i in d["incidents"]
            if incident_id in (None, i["incident_id"])]
    anomalies, note = [], None
    for a in d["anomalies"]:
        if incident_id not in (None, a["incident_id"]):
            continue
        anomalies += [dict(f, incident_id=a["incident_id"]) for f in a["findings"]]
        note = note or {"incident_id": a["incident_id"], "title": a.get("title", a["incident_id"]),
                        "summary": a.get("summary", ""), "actions": [dict(x) for x in a.get("actions", [])]}
    return {"facts_hash": facts.short_hash, "date": facts.date, "generated_by": GENERATED_BY,
            "sections": [s.title for s in facts.tables.report_sections],
            "incidents": incs, "anomalies": anomalies, "anomaly_note": note,
            "closed_as_harmless": [dict(h) for h in facts.engine.harmless],
            "missing_sources": facts.missing_sources(),
            "decoys": [dict(x) for x in facts.engine.decoys]}


# ---------------------------------------------------------------- Markdown
def _finding_md(f: dict) -> list:
    out = [f"- {f['statement']} [{f['finding_id']}] ({_cites(f['evidence'])})"]
    if f.get("assumption"):
        out.append(f"  - Assumption (the guess): {f['assumption']}")
    return out


def _gap_md(g: dict) -> str:
    if g.get("from_utc") or g.get("to_utc"):
        win = f"{fmt_utc_pkt(g['from_utc'])} to {fmt_utc_pkt(g['to_utc'])}"
    else:
        win = "no log exists, whole source"
    return f"- {g['source']}: {win}. {g.get('reason', '')} ({_cites(g.get('evidence', []))})"


def _timeline_md(items: list) -> list:
    if not items:
        return ["None."]
    out = []
    for t in items:
        where = f"{t['source_file']} row {t['row']}" if t.get("row") else f"{t['source_file']} line {t['line']}"
        out.append(f"- {t['time']}: {t['text']} ({where})")
    return out


def _actions_md(actions: list) -> list:
    out = []
    for a in actions:
        line = f"- {a['runbook']} step {a['step']}: {a['text']}"
        if a.get("detail"):
            line += f" {a['detail']}"
        if a.get("cite"):
            line += f" ({cite_str(a['cite'])})"
        out.append(line)
    return out or ["None."]


def _notify_md(people: list) -> list:
    out = []
    for n in people:
        line = f"- {n['name']} ({n.get('role') or 'role not listed'})"
        if n.get("contact"):
            line += f", {n['contact']}"
        line += f". Limit: {n.get('limit')}. How: {n.get('how')}."
        if n.get("deadline_utc"):
            line += f" Deadline {fmt_utc_pkt(n['deadline_utc'])}."
        if n.get("note"):
            line += f" {n['note']}"
        if n.get("cite"):
            line += f" ({cite_str(n['cite'])})"
        out.append(line)
    return out or ["None."]


def render_markdown(report: dict) -> str:
    titles = report["sections"]
    L = [f"# Incident report for {report['date']}", "",
         f"Facts {report['facts_hash']}. Generated by {report['generated_by']}. "
         "Times are UTC with Pakistan time (PKT) in brackets.", ""]
    parts = ", ".join(f"{i['incident_id']} {i['severity']['value']}: {i['title']}" for i in report["incidents"])
    L += ["## Overall summary", "",
          f"{len(report['incidents'])} incident(s): {parts}. "
          f"{len(report['closed_as_harmless'])} alert(s) closed as harmless, "
          f"{len(report['missing_sources'])} log source(s) not collected, "
          f"{len(report['anomalies'])} anomaly finding(s) kept separate.", ""]
    for inc in report["incidents"]:
        sev = inc["severity"]
        L += [f"## {inc['incident_id']}: {inc['title']} ({sev['value']})", ""]
        body = {}
        body["summary"] = [inc["summary"] or "None."]
        body["timeline"] = _timeline_md(inc["timeline"])
        a = inc["affected"]
        body["affected"] = [f"- Assets: {', '.join(a['assets']) or 'none'}",
                            f"- Accounts: {', '.join(a['accounts']) or 'none'}"]
        sv = [f"- {sev['value']}"] + [f"  - {p['severity']}: {p['type']} ({p['asset']})" for p in sev["parts"]]
        sv += [f"  - {s}" for s in sev["steps"]]
        if sev.get("clock_start_assumption"):
            sv.append(f"- Assumption: {sev['clock_start_assumption']}")
        body["severity"] = sv
        for k in ("confirmed", "suspected", "not_enough_evidence"):
            lines = []
            for f in inc[k]:
                lines += _finding_md(f)
            body[k] = lines or ["None."]
        body["missing_sources"] = [_gap_md(g) for g in inc["missing_sources"]] or ["None for this incident."]
        hl = [f"- {h['alert']} closed as harmless under {h['change_id']}. {h['why']} "
              f"({_cites(h['evidence'])})" for h in inc["closed_as_harmless"]]
        body["closed_as_harmless"] = hl or ["None."]
        body["actions"] = _actions_md(inc["actions"])
        body["notify"] = _notify_md(inc["notify"])
        for key, title in zip(_KEYS, titles):
            L += [f"### {title}", ""] + body[key] + [""]
    if report["anomalies"]:
        note = report.get("anomaly_note") or {}
        L += [f"## Related anomaly, not merged: {note.get('title', '')}", ""]
        if note.get("summary"):
            L += [note["summary"], ""]
        for f in report["anomalies"]:
            L += _finding_md(f)
        L += ["", "Recommended actions:", ""] + _actions_md(note.get("actions", [])) + [""]
    L += ["## Missing log sources (not collected)", ""]
    L += [_gap_md(m) for m in report["missing_sources"]] + [""]
    return "\n".join(L)


def report_markdown(facts=None) -> str:
    return render_markdown(build_report(facts))
