"""P7 rule engine tests on the real data pack (answer key: docs/GROUND_TRUTH.md)."""
from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

from triage import config
from triage.graph.build import build_graph
from triage.models import CONFIRMED, HARMLESS, NOT_ENOUGH_EVIDENCE, SUSPECTED
from triage.parsers.logs import parse_all
from triage.parsers.tables import load_tables
from triage.rules.calendar import match_change
from triage.rules.detectors import load_rules, run_rules
from triage.rules.engine import build_incidents
from triage.rules.escalation import escalation
from triage.rules.runbooks import actions
from triage.rules.severity import severity


def _run(data_dir):
    events = parse_all(data_dir)
    tables = load_tables(data_dir)
    graph = build_graph(events, tables)
    return events, tables, graph, build_incidents(graph, events, tables, tables.coverage)


@pytest.fixture(scope="module")
def world():
    return _run(config.DATA_DIR)


@pytest.fixture(scope="module")
def res(world):
    return world[3]


def _inc(res, rule):
    return next(i for i in res.incidents if any(f.rule == rule for f in i.findings))


def _by(res, rule, label=None):
    return [f for f in res.findings if f.rule == rule and (label is None or f.label == label)]


def _users(fs):
    return {e.split(":", 1)[1] for f in fs for e in f.entities if e.startswith("user:")}


# ------------------------------------------------------------------ shape
def test_run_rules_returns_findings_with_contract_fields(world):
    events, tables, graph, _ = world
    fs = run_rules(graph, events, tables, tables.coverage)
    assert [f.finding_id for f in fs] == [f"F-{i:03d}" for i in range(1, len(fs) + 1)]
    for f in fs:
        assert f.rule and f.cites_rule and f.statement and f.evidence and f.steps
        assert f.label in (CONFIRMED, SUSPECTED, NOT_ENOUGH_EVIDENCE, HARMLESS)
        assert all(re.match(r"^\d+\. ", s) for s in f.steps)
        if f.label == SUSPECTED:
            assert f.assumption
    # stable order
    assert [f.statement for f in fs] == [f.statement for f in run_rules(graph, events, tables, tables.coverage)]


def test_three_incidents_and_one_anomaly(res):
    assert [i.incident_id for i in res.incidents] == ["INC-1", "INC-2", "INC-3"]
    assert [i.incident_id for i in res.anomalies] == ["ANOM-1"]
    assert all(f.rule == "concurrent_use" for f in res.anomalies[0].findings)
    d = res.to_dict()
    assert set(d) >= {"findings", "incidents", "anomalies", "harmless", "decoys"}
    for i in d["incidents"]:
        assert {"title", "summary", "affected_assets", "affected_accounts", "clock_start"} <= set(i)


def test_utariq_not_in_inc1(res):
    inc1 = res.incident("INC-1")
    assert not any("actor:session:VS-20411" in f.entities for f in inc1.findings)
    assert any("actor:session:VS-20411" in f.entities for f in res.anomalies[0].findings)
    assert "actor:session:VS-20433" in {e for f in inc1.findings for e in f.entities}


def test_timeline_in_time_order(res, world):
    events = {e.event_id: e for e in world[0]}
    for inc in res.incidents + res.anomalies:
        ts = [events[x].ts_utc for x in inc.timeline]
        assert ts and ts == sorted(ts)


# ------------------------------------------------------------------ calendar
def test_harmless_alerts_name_the_change(res):
    got = {h["alert"]: h["change_id"] for h in res.harmless}
    assert got == {"ALT-9006": "CHG-2026-1104-02", "ALT-9007": "CHG-2026-1104-03"}
    for f in _by(res, "change_approved"):
        assert f.label == HARMLESS
        assert f.data["change_id"] in f.statement
        assert not [e for e in f.entities if e.startswith("actor:")]


def test_decoy_changes_approve_nothing(res):
    decoys = {d["change_id"]: d["why"] for d in res.decoys}
    assert "CHG-2026-1104-05" in decoys and re.search(r"(?i)postponed", decoys["CHG-2026-1104-05"])
    assert "CHG-2026-1105-01" in decoys and "2026-11-05" in decoys["CHG-2026-1105-01"]
    assert "CHG-2026-1104-01" in decoys
    approved = {c["change_id"] for c in res.calendar if c["approved"]}
    assert approved == {"CHG-2026-1104-02", "CHG-2026-1104-03"}


def test_match_change_requires_all_three(world):
    _, tables, _, _ = world
    act = {"start_utc": "2026-11-04T16:05:10Z", "end_utc": "2026-11-04T16:05:27Z",
           "actor": {"ips": ["10.10.9.50"], "users": [], "hosts": [], "names": []},
           "targets": {"ips": ["10.10.1.20", "10.10.2.10"], "hosts": [], "cidrs": []}}
    m = match_change(act, tables)
    assert m.approved and m.change_id == "CHG-2026-1104-02"
    late = dict(act, start_utc="2026-11-04T19:05:10Z", end_utc="2026-11-04T19:05:27Z")
    m2 = match_change(late, tables)
    assert not m2.approved and m2.system and m2.actor and not m2.window
    other = dict(act, actor={"ips": ["192.0.2.88"], "users": [], "hosts": [], "names": []})
    m3 = match_change(other, tables)
    assert not m3.approved and not m3.actor


# ------------------------------------------------------------------ detectors
def test_mfa_fatigue_for_amalik_only(res):
    fs = _by(res, "mfa_fatigue")
    assert len(fs) == 1 and _users(fs) == {"amalik"} and fs[0].label == CONFIRMED
    assert {"actor:ext_ip:198.51.100.77", "actor:session:VS-20433"} <= set(fs[0].entities)


def test_click_seen_for_amalik_only(res):
    clicks = _by(res, "phishing_click", CONFIRMED)
    assert _users(clicks) == {"amalik"}
    assert "actor:ext_ip:198.51.100.77" in clicks[0].entities
    assert "actor:msg:M-55187" in clicks[0].entities
    nc = _by(res, "phishing_no_click", NOT_ENOUGH_EVIDENCE)
    assert _users(nc) == {"sraheel", "utariq"}
    assert all(any("proxy" in (c.row or "").lower() for c in f.evidence) for f in nc)
    cred = _by(res, "phishing_credential_entry")
    assert cred and cred[0].label == SUSPECTED and cred[0].assumption


def test_phishing_delivered(res):
    f = _by(res, "phishing_delivered")[0]
    assert f.label == CONFIRMED
    assert "orbit-logistlcs.example" in f.statement and "6.2" in f.statement and "8.0" in f.statement
    assert _users([f]) == {"amalik", "sraheel", "utariq"}
    assert f.entities[0] == "actor:msg:M-55187"


def test_concurrent_use(res):
    fs = _by(res, "concurrent_use", SUSPECTED)
    by_user = {}
    for f in fs:
        by_user.setdefault(next(e for e in f.entities if e.startswith("user:")), []).append(f)
    assert set(by_user) == {"user:utariq", "user:amalik"}
    ut = by_user["user:utariq"][0]
    assert "overlap is confirmed" in ut.statement.lower()
    assert [e for e in ut.entities if e.startswith("actor:")] == ["actor:session:VS-20411"]
    am = by_user["user:amalik"][0]
    assert "no log shows" in am.statement.lower() and "no log shows" in am.assumption.lower()
    assert not any("braza" in e for f in _by(res, "concurrent_use") for e in f.entities)


def test_attacker_session_activity(res):
    inc1 = res.incident("INC-1")
    rules = {f.rule for f in inc1.findings}
    assert {"attacker_session", "asset_session", "password_reset", "account_lockout"} <= rules
    hosts = {e for f in _by(res, "asset_session") for e in f.entities if e.startswith("asset:")}
    assert hosts == {"asset:A-1001", "asset:A-1005", "asset:A-1007"}
    assert "06:42:17" in _by(res, "password_reset")[0].statement
    assert "alert:ALT-9008" in _by(res, "account_lockout")[0].entities


def test_big_transfer(res):
    f = _by(res, "large_transfer")
    assert len(f) == 1
    st = f[0].statement
    assert "06:03:12 to 06:21:19 UTC" in st
    assert "2,411,724,800 bytes" in st and "2,418,331,648" in st and "ALT-9005" in st
    assert "actor:session:VS-20433" in f[0].entities


def test_no_statement_asserts_data_stolen(res):
    bad = re.compile(r"(?i)\b(stolen|leaked|exfiltrated)\b(?! password)")
    for f in res.findings:
        assert not bad.search(f.statement), f.statement


def test_sqli_success_suspected_not_confirmed(res):
    s = _by(res, "web_attack_success")
    assert len(s) == 1 and s[0].label == SUSPECTED and s[0].assumption
    assert "48,213" in s[0].statement
    assert _by(res, "web_attack")[0].label == CONFIRMED
    assert [e for e in s[0].entities if e.startswith("actor:")] == ["actor:ext_ip:192.0.2.150"]


def test_recon_external_not_approved(res):
    f = _by(res, "recon")
    assert len(f) == 1 and "192.0.2.88" in f[0].statement
    assert [e for e in f[0].entities if e.startswith("actor:")] == ["actor:ext_ip:192.0.2.88"]
    assert any("Alternate reading" in s for s in f[0].steps)


def test_coverage_findings(res):
    inc1 = res.incident("INC-1")
    nee = [f.statement for f in inc1.findings if f.label == NOT_ENOUGH_EVIDENCE]
    joined = " ".join(nee)
    assert "Which files were read on SRV-FS01" in joined
    assert "SRV-DB01" in joined and "EDR" in joined
    gap = [s for s in nee if "06:32:00" in s]
    assert gap and "07:12:44" in gap[0] and "06:42:17" in gap[0]
    inc2 = res.incident("INC-2")
    assert any(f.label == NOT_ENOUGH_EVIDENCE and "query log" in f.statement for f in inc2.findings)
    an = [f.statement for f in res.anomalies[0].findings if f.label == NOT_ENOUGH_EVIDENCE]
    assert any("10.10.3.12" in s for s in an) and any("02:58:41" in s for s in an)


# ------------------------------------------------------------------ severity / escalation / actions
def test_severities(res):
    assert {i.incident_id: i.severity for i in res.incidents} == {"INC-1": "P1", "INC-2": "P2", "INC-3": "P4"}


def test_inc1_severity_steps(res, world):
    _, tables, graph, _ = world
    inc1 = res.incident("INC-1")
    sev, steps = severity(inc1, tables, graph)
    assert sev == "P1"
    txt = "\n".join(steps)
    assert "handled as credential compromise" in steps[0]
    assert "SRV-VPN01 (Medium), SRV-FS01 (High), SRV-DB01 (High)" in steps[1]
    assert re.search(r"Credential compromise.*High column.*P2", txt)
    assert re.search(r"Data exfiltration.*High column.*P1", txt)
    assert "highest part: P1" in txt
    assert "SRV-DC01 (Critical) is not counted" in txt and "stays P1" in txt
    types = {p["type"].split(" (")[0]: p["severity"] for p in inc1.parts}
    assert types == {"Credential compromise": "P2", "Data exfiltration": "P1"}


def test_inc3_alternate_reading(res):
    p = res.incident("INC-3").parts[0]
    assert p["severity"] == "P4" and p["alternate"]["severity"] == "P3"


def test_p1_escalation_four_people(res, world):
    _, tables, _, _ = world
    inc1 = res.incident("INC-1")
    rows = escalation("P1", inc1, tables)
    names = [r["name"] for r in rows]
    assert len(rows) == 4
    assert names == ["Hamza Qureshi", "Farhan Ali", "Mariam Chaudhry", "Saima Noor"]
    for r in rows:
        assert {"name", "role", "contact", "limit", "how", "cite", "note"} <= set(r)
    assert inc1.notify == rows


def test_inc2_and_inc3_notify(res):
    n2 = res.incident("INC-2").notify
    assert [n["name"] for n in n2] == ["Noman Javed", "Applications team"]
    n3 = res.incident("INC-3").notify
    assert [n["name"] for n in n3] == ["SOC queue"]


def test_every_action_has_real_runbook_step(res, world):
    _, tables, _, _ = world
    for inc in res.incidents + res.anomalies:
        assert inc.actions
        for a in inc.actions:
            rb = tables.runbooks[a["runbook"]]
            assert rb.step(a["step"]) is not None and rb.step(a["step"]).text == a["text"]
            assert a["cite"]["runbook"] == a["runbook"] and a["cite"]["step"] == a["step"]


def _steps(inc, rid):
    return [a["step"] for a in inc.actions if a["runbook"] == rid]


def test_inc1_actions(res):
    inc1 = res.incident("INC-1")
    assert _steps(inc1, "RB-PHISH-01") == list(range(1, 8))
    assert _steps(inc1, "RB-CRED-02") == list(range(1, 9))
    assert 3 in _steps(inc1, "RB-EXFIL-04")
    order = [a["runbook"] for a in inc1.actions]
    assert order.index("RB-PHISH-01") < order.index("RB-CRED-02") < order.index("RB-EXFIL-04")
    det = {(a["runbook"], a["step"]): a["detail"] for a in inc1.actions}
    assert "+92-300-5550114" in det[("RB-CRED-02", 1)] and "Ayesha Malik" in det[("RB-CRED-02", 1)]
    assert "amalik" in det[("RB-CRED-02", 2)] and "198.51.100.77" in det[("RB-CRED-02", 3)]
    assert "LT-FIN-014" in det[("RB-CRED-02", 6)]
    assert "orbit-logistlcs.example" in det[("RB-PHISH-01", 3)] and "orbit-payroll-verify.example" in det[("RB-PHISH-01", 3)]
    assert "SRV-FS01" in det[("RB-EXFIL-04", 3)]
    assert "unknown which files" in det[("RB-EXFIL-04", 5)]


def test_inc2_inc3_anomaly_actions(res):
    inc2 = res.incident("INC-2")
    assert _steps(inc2, "RB-WEB-03") == list(range(1, 8))
    det = {a["step"]: a["detail"] for a in inc2.actions}
    assert "192.0.2.150" in det[2] and "Cannot be completed" in det[5]
    inc3 = res.incident("INC-3")
    assert _steps(inc3, "RB-SCAN-05") == [1, 3, 5, 6]
    an = res.anomalies[0]
    assert [(a["runbook"], a["step"]) for a in an.actions] == [("RB-CRED-02", 1)]
    assert "Usman Tariq" in an.actions[0]["detail"] and "+92-300-5550121" in an.actions[0]["detail"]


def test_clock_start_is_first_alert(res):
    cs = res.to_dict()["incidents"][0]["clock_start"]
    assert cs["alert"] == "ALT-9002" and cs["assumption"]


# ------------------------------------------------------------------ policy is data
def _copy_data(tmp_path) -> Path:
    dst = tmp_path / "data"
    shutil.copytree(config.DATA_DIR, dst)
    return dst


def test_policy_matrix_cell_changes_severity(tmp_path):
    d = _copy_data(tmp_path)
    p = d / "03_severity_matrix.md"
    lines = p.read_text(encoding="utf-8").splitlines()
    for i, l in enumerate(lines):
        if l.startswith("| Data exfiltration"):
            cells = l.split("|")
            cells[4] = " P2 "  # High column
            lines[i] = "|".join(cells)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _, tables, _, r = _run(d)
    assert tables.matrix.lookup("Data exfiltration", "High") == "P2"
    inc = _inc(r, "large_transfer")
    assert inc.severity == "P2"
    assert any(n["name"] == "Noman Javed" for n in inc.notify)


def test_policy_postponed_change_still_wrong_actor(tmp_path):
    d = _copy_data(tmp_path)
    p = d / "05_change_calendar.md"
    p.write_text(p.read_text(encoding="utf-8").replace("Postponed, not performed", "Approved by IT Director"),
                 encoding="utf-8")
    _, tables, _, r = _run(d)
    ch = next(c for c in tables.changes if c.change_id == "CHG-2026-1104-05")
    assert ch.is_effective
    vpn = next(c for c in r.calendar if c["activity"] == "ALT-9003")
    assert not vpn["approved"]
    from triage.rules.detectors import Ctx, alert_activity
    ctx = Ctx(None, parse_all(d), tables, tables.coverage, load_rules())
    al = next(a for a in tables.alerts if a.alert_id == "ALT-9003")
    mm = match_change(alert_activity(ctx, al), tables)
    chk = next(c for c in mm.checks if c.change_id == ch.change_id)
    assert chk.system and not chk.actor and not chk.approved
    assert {i.severity for i in r.incidents} == {"P1", "P2", "P4"}
