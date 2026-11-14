"""P8 tests: fact store and report on the real data pack."""
from __future__ import annotations

import json
import shutil

import pytest

from triage import config
from triage.answer.validate import check_wording
from triage.facts import build_facts, get_facts, input_hash
from triage.models import parse_utc
from triage.report import build_report, render_markdown, report_markdown


@pytest.fixture(scope="module")
def facts():
    return get_facts()


@pytest.fixture(scope="module")
def report(facts):
    return build_report(facts)


@pytest.fixture(scope="module")
def md(facts):
    return report_markdown(facts)


def test_hash_stable_and_sensitive(tmp_path, facts):
    assert input_hash(config.DATA_DIR) == facts.hash
    assert facts.short_hash == facts.hash[:12]
    d = tmp_path / "data"
    shutil.copytree(config.DATA_DIR, d)
    assert input_hash(d) == facts.hash
    p = d / "05_change_calendar.md"
    p.write_text(p.read_text(encoding="utf-8") + "\nextra\n", encoding="utf-8")
    assert input_hash(d) != facts.hash


def test_get_facts_cached():
    assert get_facts() is get_facts()


def test_facts_protocol(facts):
    f15 = "15_firewall_internal_log.md"
    assert facts.has_line(f15, 6)
    assert "2411724800" in facts.line_text(f15, 6)
    assert not facts.has_line(f15, 9999)
    assert facts.has_row("02_asset_inventory.md", "A-1005")
    assert facts.has_row("02_asset_inventory.md", "a-1005")
    assert facts.has_row("17_ids_alert_summary.md", "ALT-9001")
    assert facts.has_row("20_log_source_coverage.md", "Email gateway")
    assert not facts.has_row("02_asset_inventory.md", "A-9999")
    assert facts.runbook_step("RB-CRED-02", 2)
    assert facts.runbook_step("RB-CRED-02", 99) is None
    assert "06:03:12" in facts.known_times_utc()
    assert facts.incident_severity("INC-1") == "P1"
    assert facts.incident_severity("INC-2") == "P2"
    assert facts.incident_severity("INC-3") == "P4"
    assert facts.incident_severity("INC-99") is None
    assert facts.incident("INC-1").incident_id == "INC-1"
    assert facts.incident_dict("ANOM-1")["incident_id"] == "ANOM-1"
    e = facts.events_by_cite(f15, 6)
    assert facts.event(e.event_id) is e
    assert facts.incident_of_event(e.event_id) == "INC-1"
    assert facts.finding("F-001").rule == "phishing_delivered"
    assert set(facts.known_entities()) == {"user", "name", "email", "phone", "ip", "host"}


def test_timeline(facts):
    tl = facts.timeline()
    assert len([t for t in tl if t["kind"] != "ids_alert"]) == 74
    alerts = [t for t in tl if t["kind"] == "ids_alert"]
    assert len(alerts) == 8
    times = [parse_utc(t["ts_utc"]) for t in tl]
    assert times == sorted(times)
    for t in tl:
        assert t["text"] and t["time"].endswith("PKT]") or " to " in t["time"]
        assert t["source_file"] and (t["line"] is not None or t["row"])
        assert t["cite"]["file"] == t["source_file"]
    big = next(t for t in tl if t["source_file"].startswith("15") and t["line"] == 6)
    assert "2,411,724,800 bytes server to client" in big["text"]
    assert "amalik" in big["text"] and "SRV-FS01:445" in big["text"]
    assert big["time"].startswith("06:03:12 UTC [11:03:12 PKT]")
    assert {t["incident"] for t in facts.timeline("INC-2")} == {"INC-2"}
    win = facts.timeline(from_utc="2026-11-04T06:00:00Z", to_utc="2026-11-04T06:10:00Z")
    assert win and all(t["ts_utc"] <= "2026-11-04T06:10:00Z" for t in win)


def test_report_structure(report):
    assert report["generated_by"] == "template (no LLM call)"
    assert len(report["sections"]) == 11
    assert [i["incident_id"] for i in report["incidents"]] == ["INC-1", "INC-2", "INC-3"]
    assert [i["severity"]["value"] for i in report["incidents"]] == ["P1", "P2", "P4"]
    assert report["anomalies"] and report["anomaly_note"]
    assert len(report["closed_as_harmless"]) == 2
    assert len(report["missing_sources"]) == 4
    for i in report["incidents"]:
        assert i["timeline"] and i["actions"] and i["notify"]
        for t in i["timeline"]:
            assert t["line"] is not None or t["row"]
        for f in i["suspected"]:
            assert f["assumption"]


def test_markdown_sections_in_order(report, md):
    titles = report["sections"]
    assert titles[0] == "Summary" and titles[-1] == "People to inform"
    for inc in report["incidents"]:
        start = md.index(f"## {inc['incident_id']}:")
        nxt = md.find("\n## ", start + 5)
        block = md[start:nxt if nxt > 0 else None]
        pos = -1
        for t in titles:
            p = block.find(f"### {t}\n")
            assert p > pos, (inc["incident_id"], t)
            pos = p
    assert "INC-1" in md and "(P1)" in md and "(P2)" in md and "(P4)" in md


def test_markdown_content(facts, md):
    for h in facts.engine.harmless:
        assert h["alert"] in md and h["change_id"] in md
    for m in facts.coverage.not_collected:
        assert m["name"] in md
    assert "UTC [" in md and "PKT]" in md
    assert "15_firewall_internal_log.md line 6" in md
    assert "17_ids_alert_summary.md row ALT-9005" in md
    assert "RB-CRED-02 step" in md
    assert "Hamza Qureshi" in md and "15 minutes" in md and "Phone call" in md
    assert "Assumption" in md


def test_wording(md):
    assert check_wording(md) == []


def test_render_markdown_from_report(report):
    assert render_markdown(report).startswith("# Incident report")


def test_save_valid_json(facts, tmp_path):
    p = facts.save(tmp_path / "facts.json")
    d = json.loads(p.read_text(encoding="utf-8"))
    for k in ("facts_hash", "built_at", "date", "events", "gaps", "missing_sources", "findings",
              "incidents", "anomalies", "closed_as_harmless", "decoys", "entities"):
        assert k in d
    assert len(d["events"]) == 74 and d["events"][0]["raw"]


def test_build_facts_fresh():
    assert build_facts().hash == get_facts().hash
