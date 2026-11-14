"""Deterministic answers written only from a Bundle (works with zero LLM calls)."""
from __future__ import annotations

from typing import Any

from triage.answer.bundle import Bundle, cite_text


def render(route: Any, bundle: Bundle) -> str:
    b = bundle
    out: list[str] = []
    if b.injection and b.notes:
        out.append(b.notes[0])
        notes = b.notes[1:]
    else:
        notes = list(b.notes)
    if b.direct:
        out.append(" ".join(b.direct))
    for key, head in (("confirmed", "Confirmed:"), ("suspected", "Suspected:"),
                      ("not_enough_evidence", "Not enough evidence in the logs:")):
        items = b.labels.get(key) or []
        if items:
            out.append(head + "\n" + "\n".join(f"- {x}" for x in items))
    if b.severity and b.incident_ids:
        lines = [f"Severity: {b.incident_ids[0]} is {b.severity}."]
        lines += [f"- {s}" for s in b.severity_steps]
        out.append("\n".join(lines))
    elif b.severity_steps and b.incident_ids:
        out.append("Severity: " + " ".join(b.severity_steps))
    if b.severities and not b.severity:
        out.append("Scored separately: " + ", ".join(f"{k} {v}" for k, v in b.severities.items()) + ".")
    if b.actions:
        lines = ["Recommended actions (runbook and step):"]
        for a in b.actions:
            c = cite_text(a["cite"]) if a.get("cite") else ""
            detail = f" {a['detail']}" if a.get("detail") else ""
            lines.append(f"- {a['runbook']} step {a['step']}: {a['text']}{detail} {c}".rstrip())
        out.append("\n".join(lines))
    if b.notify:
        lines = ["People to inform:"]
        for n in b.notify:
            who = n["name"] if n["role"] in (None, "", n["name"]) else f"{n['role']} {n['name']}"
            contact = f" ({n['contact']})" if n.get("contact") else ""
            note = f" {n['note']}" if n.get("note") else ""
            lines.append(f"- {who}{contact}: time limit {n['limit']}, {n['how']}.{note}")
        out.append("\n".join(lines))
    if notes:
        out.append("\n".join(notes))
    text = "\n\n".join(x for x in out if x.strip())
    return text or "There is not enough evidence in the logs to answer this question."
