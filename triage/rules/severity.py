"""P7: severity lookup from the matrix (03) with a step-by-step trace. No model decides this.

Row = incident type from the incident's parts (rules.yaml `severity.parts`).
Column = criticality of the most critical asset reached by a confirmed login or session
(01 rule 4.1). Each part is reported; the incident gets the highest (01 rule 4.2).
"""
from __future__ import annotations

import re
from typing import Any, Optional

from triage.models import CONFIRMED, Incident

_ORDER = None


def _tables(tables):
    if tables is not None:
        return tables
    from triage.parsers.tables import load_tables
    return load_tables()


def _rules(rules):
    if rules is not None:
        return rules
    from triage.rules.detectors import load_rules
    return load_rules()


def _fdata(f) -> dict:
    return getattr(f, "data", None) or {}


def _asset(tables, tag):
    return next((a for a in tables.inventory if a.tag == tag), None)


def _crit_rank(tables, crit: str) -> int:
    cols = [c.lower() for c in tables.matrix.columns]
    return cols.index(crit.lower()) if crit and crit.lower() in cols else -1


def _sev_rank(s: Optional[str]) -> int:
    m = re.match(r"P(\d+)", s or "")
    return int(m.group(1)) if m else 99


def reached_assets(incident: Incident, tables: Any = None, rules: Any = None,
                   count_kerberos: Optional[bool] = None) -> tuple:
    """([(asset, first_time, finding_id)], [(asset, reason)]) in first-reach order."""
    tables, rules = _tables(tables), _rules(rules)
    rc = rules.get("severity", {}).get("reach", {})
    reach_rules = set(rc.get("rules", []))
    if count_kerberos is None:
        count_kerberos = bool(rc.get("count_kerberos_as_reach", False))
    io_types = [t.lower() for t in rc.get("interactive_only_types", [])]
    interactive = set()
    for f in incident.findings:
        if f.rule == rc.get("interactive_rule", "interactive_logon") and f.label == CONFIRMED:
            interactive |= {r["tag"] for r in _fdata(f).get("reach", [])}
            interactive |= {e.split(":", 1)[1] for e in f.entities if e.startswith("asset:")}
    hits: dict = {}
    excluded: dict = {}
    for f in incident.findings:
        if f.rule not in reach_rules or f.label != CONFIRMED:
            continue
        reach = _fdata(f).get("reach")
        if reach is None:  # rebuilt from a dict: fall back to entities
            k_only = any(e.startswith("port:") for e in f.entities) and all(
                e.split(":", 1)[1] in {str(p) for p in rules.get("asset_session", {}).get("kerberos_ports", [88])}
                for e in f.entities if e.startswith("port:"))
            reach = [{"tag": e.split(":", 1)[1], "time": None, "kerberos_only": k_only}
                     for e in f.entities if e.startswith("asset:")]
        for r in reach:
            a = _asset(tables, r["tag"])
            if not a:
                continue
            is_io = any(t in a.type.lower() for t in io_types)
            if (r.get("kerberos_only") or is_io) and a.tag not in interactive and not count_kerberos:
                why = ("only Kerberos traffic to it" if r.get("kerberos_only") else "no logon on it")
                excluded.setdefault(a.tag, (a, why, f.finding_id))
                continue
            t = r.get("time") or ""
            if a.tag not in hits or (t and t < hits[a.tag][1]):
                hits[a.tag] = (a, t, f.finding_id)
    excl = [(a, why) for tag, (a, why, _) in excluded.items() if tag not in hits]
    order = sorted(hits.values(), key=lambda x: (x[1] or "~", x[2]))
    return order, excl


def most_critical(tables: Any, reached: list):
    """Most critical reached asset; ties prefer one holding sensitive data, then a data owner."""
    if not reached:
        return None
    best = max(_crit_rank(tables, a.criticality) for a, *_ in reached)
    tied = [a for a, *_ in reached if _crit_rank(tables, a.criticality) == best]
    tied.sort(key=lambda a: (not a.holds_sensitive_data, a.data_owner is None))
    return tied[0]


def _present(incident: Incident, labels: set) -> dict:
    out: dict = {}
    for f in incident.findings:
        if f.label in labels:
            out.setdefault(f.rule, []).append(f)
    return out


def _actor(incident: Incident) -> Optional[str]:
    for f in incident.findings:
        u = _fdata(f).get("user")
        if u:
            return u
    return None


def severity(incident: Incident, tables: Any = None, graph: Any = None,
             rules: Any = None) -> tuple:
    """Return (severity such as 'P1', numbered reasoning steps). Also sets incident.parts."""
    tables, rules = _tables(tables), _rules(rules)
    sc = rules.get("severity", {})
    m = tables.matrix
    present = _present(incident, set(sc.get("trigger_labels", ["confirmed", "suspected"])))
    steps: list = []
    # 1. matrix note: phishing with a click
    click_row = None
    click_rule = sc.get("click_rule", "phishing_click")
    clicks = [f for f in present.get(click_rule, []) if f.label == CONFIRMED]
    if clicks:
        for note in m.notes:
            mm = re.search(sc.get("click_note_pattern", r"handled as (.+?)\.?$"), note)
            if mm:
                click_row = m.match_row(mm.group(1))
                if click_row:
                    steps.append(f"Phishing with a click is handled as {mm.group(1).strip().rstrip('.').lower()} "
                                 f"(03 rule note).")
                break
    # 2. assets reached
    reached, excluded = reached_assets(incident, tables, rules)
    if reached:
        steps.append("Assets reached by a confirmed login or session: "
                     + ", ".join(f"{a.hostname} ({a.criticality})" for a, *_ in reached) + ".")
    else:
        steps.append("No asset is reached by a confirmed login or session.")
    top = most_critical(tables, reached)
    col = top.criticality if top else m.columns[0]
    # 3. parts
    parts = []
    for spec in sc.get("parts", []):
        trig = [r for r in spec.get("when", []) if r in present]
        if spec.get("click_counts") and click_row and m.match_row(spec["row"]) == click_row:
            trig = trig or [click_rule]
        if not trig or any(r in present for r in spec.get("unless", [])):
            continue
        row = m.match_row(spec["row"])
        if not row:
            continue
        sev = m.lookup(row, col)
        succ = ""
        if "success" in row.lower() and any(f.label == "suspected" for r in trig for f in present.get(r, [])):
            succ = " (success suspected)"
        pst = f"{row}{succ}, {col} column ({top.hostname + ', ' + top.tag if top else 'no asset reached'}): {sev}."
        steps.append(pst)
        part = {"type": row, "asset": top.tag if top else None, "severity": sev, "steps": [pst],
                "rules": trig}
        if spec.get("alternate"):
            alt = m.match_row(spec["alternate"])
            if alt:
                asev = m.lookup(alt, col)
                astep = f"Alternate reading ({alt.lower()}), {col} column: {asev}."
                steps.append(astep)
                part["alternate"] = {"type": alt, "severity": asev}
                part["steps"].append(astep)
        parts.append(part)
    if not parts:
        incident.parts = []
        steps.append("No severity row applies (approved activity or anomaly only).")
        return None, [f"{i}. {s}" for i, s in enumerate(steps, 1)]
    best = min(parts, key=lambda p: _sev_rank(p["severity"]))["severity"]
    if len(parts) > 1:
        steps.append(f"Incident takes the highest part: {best} (01 rule 4.2).")
    else:
        steps.append(f"Incident severity: {best} (01 rules 4.1 and 4.2).")
    # 4. the other reading for an asset not counted (ARCHITECTURE section 11)
    for a, why in excluded:
        if _crit_rank(tables, a.criticality) <= _crit_rank(tables, col):
            continue
        who = _actor(incident)
        alts = [f"{p['type'].split(' (')[0].lower()} would be {m.lookup(p['type'], a.criticality)}"
                for p in parts]
        alt_best = min((m.lookup(p["type"], a.criticality) for p in parts), key=_sev_rank)
        steps.append(f"{a.hostname} ({a.criticality}) is not counted: {why} and no logon on it"
                     f"{' by ' + who if who else ''} (rules.yaml severity.reach, ARCHITECTURE section 11). "
                     f"If it were counted, {', '.join(alts)}. Incident "
                     + (f"stays {best}." if alt_best == best else f"would be {alt_best}."))
    incident.parts = parts
    return best, [f"{i}. {s}" for i, s in enumerate(steps, 1)]
