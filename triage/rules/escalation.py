"""P7: escalation contacts from the escalation sheet (04).

Every row for the severity is returned. A conditional row (Legal) is kept only if a
reached asset holds finance, HR or customer data. "Data owner" and "system owner" rows
are resolved from the inventory row of the most critical reached asset.
"""
from __future__ import annotations

import re
from datetime import timedelta
from typing import Any, Optional

from triage.models import Incident, parse_utc, to_utc_iso
from triage.rules.severity import _rules, _tables, most_critical, reached_assets


def _owner_parts(asset) -> tuple:
    """(name, title) of the data owner from 'Finance (data owner: Name, Title)'."""
    m = re.search(r"data owner:\s*([^,)]+)(?:,\s*([^)]+))?", asset.owner or "", re.I)
    if m:
        return m.group(1).strip(), (m.group(2) or "").strip() or None
    return asset.data_owner or asset.owner_person, None


def clock_start(incident: Incident, tables: Any) -> Optional[Any]:
    """First IDS alert referenced by the incident (the SOC first sees it then)."""
    ids = {e.split(":", 1)[1] for f in incident.findings for e in f.entities if e.startswith("alert:")}
    al = [a for a in tables.alerts if a.alert_id in ids and a.ts_utc]
    return min(al, key=lambda a: a.ts_utc) if al else None


def escalation(severity: str, incident: Incident, tables: Any = None, rules: Any = None) -> list:
    """Every escalation row for `severity`; Legal only if finance, HR or customer data may be involved."""
    tables, rules = _tables(tables), _rules(rules)
    if not severity:
        return []
    kw = [k.lower() for k in rules.get("escalation", {}).get("sensitive_condition_keywords",
                                                                ["finance", "hr", "customer"])]
    reached, _ = reached_assets(incident, tables, rules)
    top = most_critical(tables, reached)
    sensitive = [a for a, *_ in reached if a.holds_sensitive_data]
    first = clock_start(incident, tables)
    out = []
    for r in tables.escalation:
        if r.severity != severity:
            continue
        note = None
        name, role, contact = r.name, r.role, r.contact
        if r.condition:
            words = re.findall(r"[a-z]+", r.condition.lower())
            if any(k in words for k in kw):
                if not sensitive:
                    continue
                note = (f"{', '.join(f'{a.hostname} ({a.type})' for a in sensitive)}: "
                        f"{r.condition}.")
            else:
                note = f"Condition: {r.condition}."
        if r.needs_lookup and top is not None:
            if r.needs_lookup == "data_owner":
                tgt = next((a for a, *_ in reached if a.data_owner and
                            a.criticality == top.criticality), None) or top
                nm, title = _owner_parts(tgt)
                name = nm or tgt.owner
                role = "Data owner" + (f" ({title})" if title else "")
                note = f"Data owner of {tgt.hostname} ({tgt.tag}) from the asset inventory: {tgt.owner}."
                cite_row = tgt.cite
            else:
                name = top.owner_person or top.owner
                role = "System owner"
                note = f"System owner of {top.hostname} ({top.tag}) from the asset inventory: {top.owner}."
                cite_row = top.cite
        else:
            cite_row = None
        if name is None:
            name = role
        d = {"name": name, "role": role, "contact": contact, "limit": r.limit, "how": r.how,
             "cite": r.cite.to_dict(), "note": note}
        if cite_row is not None:
            d["asset_cite"] = cite_row.to_dict()
        if first is not None and r.limit_minutes:
            d["deadline_utc"] = to_utc_iso(parse_utc(first.ts_utc) + timedelta(minutes=r.limit_minutes))
            d["clock_start"] = {"alert": first.alert_id, "ts_utc": first.ts_utc,
                                "assumption": "The clock starts at the first IDS alert of the incident "
                                              "(04 note: when the SOC first sees the incident)."}
        out.append(d)
    return out
