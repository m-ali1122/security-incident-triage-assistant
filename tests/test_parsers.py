from __future__ import annotations

import shutil
from collections import Counter
from pathlib import Path

from triage.parsers.logs import load_profiles, parse_all


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "problem_c_data"


def events():
    return parse_all(DATA)


def by_file_line(file: str, line: int):
    return next(e for e in events() if e.source_file == file and e.line == line)


def test_done_when_times_fields_and_counts():
    parsed = events()
    counts = Counter(e.source_file for e in parsed)
    assert counts == {"11_vpn_auth_log.md": 12, "12_windows_dc_auth_log.md": 13,
                      "13_web_server_log.md": 13, "14_firewall_perimeter_log.md": 12,
                      "15_firewall_internal_log.md": 14, "16_email_gateway_log.md": 6,
                      "19_dhcp_lease_log.md": 4}
    assert by_file_line("15_firewall_internal_log.md", 6).ts_utc == "2026-11-04T06:03:12Z"
    assert by_file_line("15_firewall_internal_log.md", 6).ts_end_utc == "2026-11-04T06:21:19Z"
    assert by_file_line("15_firewall_internal_log.md", 14).ts_utc == "2026-11-04T17:31:05Z"
    assert by_file_line("15_firewall_internal_log.md", 14).ts_end_utc == "2026-11-04T18:24:12Z"
    web = by_file_line("13_web_server_log.md", 9)
    assert web.ts_utc == "2026-11-04T06:06:02Z"
    assert web.fields["status"] == 200 and web.fields["size"] == 48213
    assert by_file_line("14_firewall_perimeter_log.md", 8).ts_utc == "2026-11-04T04:19:40Z"
    assert by_file_line("16_email_gateway_log.md", 2).ts_utc == "2026-11-04T04:12:07Z"
    assert by_file_line("19_dhcp_lease_log.md", 1).ts_utc == "2026-11-04T03:20:11Z"


def test_line_numbers_and_cross_source_fields():
    vpn = by_file_line("11_vpn_auth_log.md", 7)
    assert vpn.fields["assigned_ip"] == "10.10.3.45"
    assert vpn.fields["session"] == "VS-20433"
    dc = by_file_line("12_windows_dc_auth_log.md", 6)
    assert dc.fields["user"] == "amalik"
    assert dc.fields["account"] == r"ORBIT\amalik"
    assert dc.fields["client"] == "10.10.3.45"
    assert by_file_line("11_vpn_auth_log.md", 1).line == 1
    assert by_file_line("11_vpn_auth_log.md", 1).raw.startswith("2026-11-04T02:58:41Z")


def test_profile_schema_and_untrusted_fields():
    profiles = load_profiles()
    assert set(profiles) == {"11_vpn_auth_log.md", "12_windows_dc_auth_log.md", "13_web_server_log.md",
                              "14_firewall_perimeter_log.md", "15_firewall_internal_log.md",
                              "16_email_gateway_log.md", "19_dhcp_lease_log.md"}
    required = {"file", "kind", "line_regex", "kv_rest", "ts_format", "timezone", "ts_means",
                "duration_field", "untrusted_fields"}
    assert all(required <= set(profile) for profile in profiles.values())
    assert "user_agent" in by_file_line("13_web_server_log.md", 9).untrusted_fields
    assert "subject" in by_file_line("16_email_gateway_log.md", 2).untrusted_fields
    assert not any(e.kind == "unprofiled" for e in events())


def test_unprofiled_line_is_kept_and_flagged(tmp_path):
    root = tmp_path / "data"
    shutil.copytree(DATA, root)
    (root / "99_extra_log.md").write_text("# Extra\n\n```\n2026-11-04T00:00:00Z note=hello subject=\"quoted value\"\n```\n", encoding="utf-8")
    extra = [e for e in parse_all(root) if e.source_file == "99_extra_log.md"]
    assert len(extra) == 1
    assert extra[0].kind == "unprofiled"
    assert extra[0].fields["unprofiled"] is True
    assert extra[0].fields["subject"] == "quoted value"


def test_file20_row_controls_file15_timezone(tmp_path):
    root = tmp_path / "data"
    shutil.copytree(DATA, root)
    coverage = root / "20_log_source_coverage.md"
    coverage.write_text(coverage.read_text(encoding="utf-8").replace("Local time PKT, UTC+5 (no zone written)", "UTC (no zone written)"), encoding="utf-8")
    changed = next(e for e in parse_all(root) if e.source_file == "15_firewall_internal_log.md" and e.line == 6)
    assert changed.ts_utc == "2026-11-04T11:03:12Z"
    assert changed.ts_end_utc == "2026-11-04T11:21:19Z"
