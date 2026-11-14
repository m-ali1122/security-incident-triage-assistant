from datetime import datetime, timezone

from fastapi.testclient import TestClient

from triage.api import app
from triage.models import (Answer, Cite, Event, Finding, Gap, Incident, Link,
                           fmt_utc_pkt, parse_utc, to_utc_iso)


def test_time_helpers():
    dt = parse_utc("2026-11-04T06:03:12Z")
    assert dt == datetime(2026, 11, 4, 6, 3, 12, tzinfo=timezone.utc)
    assert to_utc_iso(dt) == "2026-11-04T06:03:12Z"
    assert fmt_utc_pkt("2026-11-04T06:03:12Z") == "06:03:12 UTC [11:03:12 PKT]"
    assert fmt_utc_pkt(dt) == "06:03:12 UTC [11:03:12 PKT]"
    # PKT rolls past midnight
    assert fmt_utc_pkt("2026-11-04T19:30:00Z") == "19:30:00 UTC [00:30:00 PKT]"


def test_cite_variants_drop_none():
    assert Cite("11_vpn_auth_log.md", line=7).to_dict() == {"file": "11_vpn_auth_log.md", "line": 7}
    assert Cite("02_asset_inventory.md", row="A-1005").to_dict() == {
        "file": "02_asset_inventory.md", "row": "A-1005"}
    d = {"file": "07_runbook_credential_compromise.md", "runbook": "RB-CRED-02", "step": 2}
    assert Cite.from_dict(d).to_dict() == d


def test_event_roundtrip():
    d = {"event_id": "E-0042", "kind": "firewall_session", "ts_utc": "2026-11-04T06:03:12Z",
         "ts_end_utc": "2026-11-04T06:21:19Z", "source_file": "15_firewall_internal_log.md",
         "line": 6, "raw": "x", "fields": {"dst_port": 445}, "untrusted_fields": ["url"]}
    assert Event.from_dict(d).to_dict() == d


def test_link_gap_roundtrip():
    c = {"file": "11_vpn_auth_log.md", "line": 7}
    link = {"a": "ip:10.10.3.45", "b": "user:amalik", "type": "ASSIGNED_TO",
            "valid_from": "2026-11-04T05:49:12Z", "valid_to": "2026-11-04T07:12:44Z",
            "basis": "direct", "assumption": None, "evidence": [c]}
    assert Link.from_dict(link).to_dict() == link
    gap = {"source": "15_firewall_internal_log.md", "from_utc": "2026-11-04T06:32:00Z",
           "to_utc": "2026-11-04T07:28:59Z", "reason": "reboot", "evidence": [c]}
    assert Gap.from_dict(gap).to_dict() == gap


def test_finding_incident_answer_roundtrip():
    c = {"file": "11_vpn_auth_log.md", "line": 7}
    f = {"finding_id": "F-012", "rule": "mfa_fatigue", "cites_rule": "01 rule 6.1",
         "label": "confirmed", "statement": "s", "assumption": None,
         "steps": ["1. a"], "evidence": [c], "entities": ["user:amalik"]}
    assert Finding.from_dict(f).to_dict() == f
    inc = {"incident_id": "INC-1",
           "parts": [{"type": "x", "asset": "A-1005", "severity": "P1", "steps": ["1"]}],
           "severity": "P1", "findings": [f], "timeline": ["E-0001"],
           "actions": [{"runbook": "RB-CRED-02"}], "notify": [{"name": "n"}]}
    assert Incident.from_dict(inc).to_dict() == inc
    ans = {"answer": "text", "structured": {
        "labels": {"confirmed": [], "suspected": [], "not_enough_evidence": []},
        "severity": "P1", "severity_steps": [], "citations": [c], "entities": [],
        "actions": [], "notify": []},
        "meta": {"path": "template", "provider": "none", "route": "rules", "cached": False}}
    assert Answer.from_dict(ans).to_dict() == ans


def test_health():
    r = TestClient(app).get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
