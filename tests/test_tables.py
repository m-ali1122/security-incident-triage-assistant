import re
import shutil

import pytest

from triage import config
from triage.parsers import coverage as cov
from triage.parsers import tables as T


def test_generic_table_reader():
    path = T.find_file(2)
    tab = T.read_md_tables(path)[0]
    assert tab.headers[0] == "Asset tag"
    assert tab.row(1)["Asset tag"] == "A-1001"
    assert T.read_bullets(path)


def test_matrix_lookup_prefix():
    m = T.load_matrix()
    assert m.lookup("Data exfiltration", "High") == "P1"
    assert m.lookup("Credential compromise", "critical") == "P1"
    assert any(r.startswith("Data exfiltration") and len(r) > 17 for r in m.rows)
    assert m.columns == ["Low", "Medium", "High", "Critical"]
    assert m.notes
    assert m.match_row("scanning").startswith("Unapproved scanning")
    with pytest.raises(ValueError):
        m.lookup("Web application attack", "High")  # two rows share the prefix
    assert m.lookup("Web application attack, attempts only", "High") == "P2"


def test_change_window_utc():
    ch = {c.change_id: c for c in T.load_changes()}
    c3 = ch["CHG-2026-1104-03"]
    assert c3.window_start_utc == "2026-11-04T17:00:00Z"
    assert c3.window_end_utc == "2026-11-04T18:30:00Z"
    assert c3.actor_usernames == ["braza"] and c3.actor_names == ["Bilal Raza"]
    assert c3.systems == ["SRV-DC01"] and c3.covers("2026-11-04T17:31:05Z")
    c2 = ch["CHG-2026-1104-02"]
    assert c2.systems == ["10.10.1.0/24", "10.10.2.0/24"]
    assert c2.actor_ips == ["10.10.9.50"] and c2.actor_hosts == ["SCAN01"]


def test_postponed_change_not_effective():
    ch = {c.change_id: c for c in T.load_changes()}
    assert ch["CHG-2026-1104-05"].is_effective is False
    assert ch["CHG-2026-1104-03"].is_effective is True


def test_observable_gaps():
    assert cov.observable("15_firewall_internal_log.md", "2026-11-04T06:42:17Z") is False
    assert cov.observable("12_windows_dc_auth_log.md", "2026-11-04T02:58:41Z") is False
    assert cov.observable("12_windows_dc_auth_log.md", "2026-11-04T03:00:00Z") is True
    assert cov.observable("Internal firewall", "2026-11-04T07:29:00Z") is True
    assert cov.observable("11_vpn_auth_log.md", "2026-11-04T02:58:41Z") is True
    assert cov.observable("11_vpn_auth_log.md", "2026-11-05T02:58:41Z") is False
    assert cov.observable("SRV-FS01 file access (audit) log", "2026-11-04T06:00:00Z") is False


def test_not_collected_four():
    c = cov.load_coverage()
    assert len(c.not_collected) == 4
    assert all(n["reason"] and n["cite"].row == n["name"] for n in c.not_collected)
    assert "2026-11-04" in c.other_dates_note
    assert c.date == "2026-11-04"


def test_runbook_steps():
    rb = T.load_runbooks()
    assert len(rb["RB-CRED-02"].steps) == 8
    assert len(rb["RB-EXFIL-04"].steps) == 6
    assert len(rb) == 5
    s = rb["RB-CRED-02"].step(2)
    assert s.cite.to_dict() == {"file": "07_runbook_credential_compromise.md",
                                "runbook": "RB-CRED-02", "step": 2}


def test_internal_firewall_gap():
    gaps = cov.gaps_overlapping("2026-11-04T06:40:00Z", "2026-11-04T06:50:00Z")
    assert len(gaps) == 1
    g = gaps[0]
    assert g.source == "15_firewall_internal_log.md"
    assert (g.from_utc, g.to_utc) == ("2026-11-04T06:32:00Z", "2026-11-04T07:28:59Z")
    assert "firmware" in g.reason.lower()
    assert g.evidence[0].row == "Internal firewall"
    dc = cov.gaps_overlapping("2026-11-04T00:00:00Z", "2026-11-04T23:59:59Z",
                              source="12_windows_dc_auth_log.md")
    assert len(dc) == 2 and dc[0].to_utc == "2026-11-04T02:59:59Z"
    assert cov.gaps_overlapping("2026-11-04T08:00:00Z", "2026-11-04T09:00:00Z") == []


def test_coverage_profile_fields():
    c = cov.load_coverage()
    by = {s.file: s for s in c.sources}
    assert by["15_firewall_internal_log.md"].timezone == "PKT"
    assert by["15_firewall_internal_log.md"].ts_means == "close"
    assert by["14_firewall_perimeter_log.md"].ts_means == "start"
    assert by["14_firewall_perimeter_log.md"].timezone == "UTC"
    assert by["13_web_server_log.md"].timezone == "offset_in_line"
    assert by["16_email_gateway_log.md"].timezone == "PKT"
    assert by["11_vpn_auth_log.md"].ts_means == "event"
    assert c.quarantine_threshold == 8.0
    texts = " ".join(s["text"] for s in c.scope_notes).lower()
    assert "office network only" in texts and "quarantine" in texts
    assert cov.load_coverage() is c  # cached


def test_inventory():
    inv = {a.hostname: a for a in T.load_inventory()}
    assert inv["SRV-WEB01"].public_ip == "203.0.113.10" and inv["SRV-WEB01"].ip == "10.10.2.10"
    fs = inv["SRV-FS01"]
    assert fs.data_owner == "Saima Noor" and fs.owner_person == "Saima Noor"
    assert fs.tag == "A-1005" and fs.holds_sensitive_data
    assert fs.cite.row == "A-1005"
    assert inv["SRV-DC01"].owner_person == "Imran Siddiqui" and inv["SRV-DC01"].data_owner is None
    assert not inv["SRV-DB01"].holds_sensitive_data
    assert inv["LT-IT-003"].owner_person == "Bilal Raza"


def test_inventory_notes_and_fqdn():
    n = T.load_inventory_notes()
    assert n.vpn_pool == ("10.10.3.10", "10.10.3.99")
    assert n.domain == "orbit.local"
    inv = T.load_inventory()
    assert n.resolve_fqdn("FS01.orbit.local", inv).hostname == "SRV-FS01"
    assert n.resolve_fqdn("DB01.orbit.local", inv).hostname == "SRV-DB01"
    assert n.resolve_fqdn("NOPE.orbit.local", inv) is None


def test_escalation_p1():
    rows = [r for r in T.load_escalation() if r.severity == "P1"]
    assert len(rows) == 4
    legal = next(r for r in rows if "Legal" in r.role)
    assert legal.condition and "finance" in legal.condition
    assert legal.contact.endswith("@orbitlogistics.example")
    assert legal.how == "Email and phone"
    ciso = rows[0]
    assert ciso.name and ciso.contact.startswith("+92") and ciso.limit_minutes == 15
    assert next(r for r in rows if r.needs_lookup == "data_owner")
    assert "SOC first sees" in T.load_escalation_note()
    p2 = [r for r in T.load_escalation() if r.severity == "P2"]
    assert any(r.needs_lookup == "system_owner" for r in p2)


def test_alerts_and_users():
    al = {a.alert_id: a for a in T.load_alerts()}
    assert len(al) == 8 and al["ALT-9003"].ts_utc == "2026-11-04T05:49:13Z"
    assert "198.51.100.77" in al["ALT-9002"].ips
    assert "orbit-payroll-verify.example" in al["ALT-9002"].domains
    assert al["ALT-9003"].usernames == ["amalik"]
    assert "SRV-FS01" in al["ALT-9005"].hostnames
    assert al["ALT-9007"].usernames == ["braza"] and "SRV-DC01" in al["ALT-9007"].hostnames
    users = T.load_users()
    assert users[0].username == "amalik" and users[0].phone.startswith("+92")
    assert T.company_domain(users) == "orbitlogistics.example"


def test_rules_text():
    rules = T.load_rules_text()
    assert rules["6.1"].startswith("Several rejected MFA")
    assert "3.1" in rules and T.load_rule_sections()["6"] == "VPN"
    secs = T.report_sections()
    names = [s.title for s in secs]
    assert names[0] == "Summary" and len(names) == 11
    assert "Closed as harmless" in names and secs[1].qualifier


def test_tables_bundle():
    t = T.load_tables()
    d = t.to_dict()
    assert d["matrix"]["rows"] and d["coverage"]["gaps"] and len(d["runbooks"]) == 5
    assert d["inventory"][0]["cite"] == {"file": "02_asset_inventory.md", "row": "A-1001"}


def test_edit_matrix_cell_changes_lookup(tmp_path):
    dst = tmp_path / "data"
    shutil.copytree(config.DATA_DIR, dst)
    f = next(dst.glob("03_*.md"))
    text = f.read_text(encoding="utf-8")
    new = re.sub(r"(\| Data exfiltration[^|]*\| P3 \| P2 \| )P1", r"\1P4", text)
    assert new != text
    f.write_text(new, encoding="utf-8")
    assert T.load_matrix(dst).lookup("Data exfiltration", "High") == "P4"
    assert T.load_matrix().lookup("Data exfiltration", "High") == "P1"
