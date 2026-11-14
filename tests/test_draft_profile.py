"""A1 profile drafting: no network; the LLM is a fake callable."""
import json
from pathlib import Path

import pytest
import yaml

from triage import config
from triage.parsers import draft_profile as dp, logs

DATA = config.DATA_DIR
FILES = sorted(logs.load_profiles())


def _llm_reply(profile: dict):
    return lambda system, user: json.dumps(profile)


def _hand(name):
    return dict(logs.load_profiles()[name])


def test_good_candidate_accepted(tmp_path):
    name = "14_firewall_perimeter_log.md"
    prof = _hand(name)
    prof.pop("file")
    cand = dp.draft(DATA / name, llm=_llm_reply(prof))
    assert cand.source == "llm"
    res = dp.validate_candidate(cand, DATA / name)
    assert res.ok, res.reasons
    out = dp.accept(cand, profiles_dir=tmp_path)
    assert out.accepted and out.path == tmp_path / "drafted" / "14_firewall_perimeter_log.yaml"
    written = yaml.safe_load(out.path.read_text(encoding="utf-8"))
    assert written["drafted"] is True and written["drafted_by"] == "llm"
    assert written["file"] == name
    # not picked up by the normal loader
    assert logs.load_profiles(tmp_path) == {}


def test_regex_missing_one_line_rejected(tmp_path):
    name = "14_firewall_perimeter_log.md"
    prof = _hand(name)
    prof["line_regex"] = prof["line_regex"].replace(r"(?P<action>\S+)", "(?P<action>DENY)")
    lines = dp.read_file(DATA / name)[1]
    first_allow = next(i for i, ln in enumerate(lines, 1) if " ALLOW " in ln)
    cand = dp.draft(DATA / name, llm=_llm_reply(prof))
    res = dp.validate_candidate(cand, DATA / name)
    assert not res.ok
    assert any(i.line == first_allow and i.check == "match" for i in res.issues)
    out = dp.accept(cand, profiles_dir=tmp_path)
    assert not out.accepted and out.status == "present but unparsed" and out.reasons
    assert not (tmp_path / "drafted").exists()


def test_wrong_timezone_outside_coverage_rejected(tmp_path):
    name = "12_windows_dc_auth_log.md"  # covered 03:00-19:00 UTC only
    prof = _hand(name)
    prof["timezone"] = "PKT"
    cand = dp.draft(DATA / name, llm=_llm_reply(prof))
    res = dp.validate_candidate(cand, DATA / name)
    assert not res.ok
    windows = [i for i in res.issues if i.check == "window"]
    assert windows and all(i.line for i in windows)
    assert not dp.accept(cand, profiles_dir=tmp_path).accepted


@pytest.mark.parametrize("reply", ["not json: [unclosed", "just some prose about logs", "", "[1, 2, 3]"])
def test_unusable_llm_reply_rejected_cleanly(reply, tmp_path):
    name = "11_vpn_auth_log.md"
    cand = dp.draft(DATA / name, llm=lambda s, u: reply)
    assert cand.source == "llm" and cand.parse_error
    res = dp.validate_candidate(cand, DATA / name)
    assert not res.ok and res.reasons
    assert not dp.accept(cand, profiles_dir=tmp_path).accepted


def test_invalid_regex_rejected():
    name = "11_vpn_auth_log.md"
    cand = dp.draft(DATA / name, llm=_llm_reply({"kind": "x", "line_regex": "^(?P<ts>(", "ts_format": "%Y"}))
    res = dp.validate_candidate(cand, DATA / name)
    assert not res.ok and res.issues[0].check == "regex"


def test_no_entity_rejected():
    name = "11_vpn_auth_log.md"
    prof = {"kind": "x", "line_regex": r"^(?P<ts>\S+) (?P<rest>.*)$", "kv_rest": False,
            "ts_format": "%Y-%m-%dT%H:%M:%SZ", "timezone": "UTC", "ts_means": "event"}
    res = dp.validate_candidate(dp.draft(DATA / name, llm=_llm_reply(prof)), DATA / name)
    assert not res.ok and any(i.check == "fields" for i in res.issues)


@pytest.mark.parametrize("name", ["11_vpn_auth_log.md", "12_windows_dc_auth_log.md", "13_web_server_log.md",
                                  "16_email_gateway_log.md"])
def test_samples_sent_to_llm_are_anonymised(name):
    seen = {}

    def fake(system, user):
        seen["user"] = user
        return None

    dp.draft(DATA / name, llm=fake)
    sent = seen["user"]
    text = "\n".join(dp.read_file(DATA / name)[1])
    import re
    for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)):
        assert ip not in sent
    for user in ("amalik", "utariq", "braza", "sraheel"):
        assert user not in sent
    assert "orbitlogistics.example" not in sent or "@" not in sent


def test_llm_none_falls_back_to_heuristic():
    cand = dp.draft(DATA / "15_firewall_internal_log.md", llm=lambda s, u: None)
    assert cand.source == "heuristic"
    assert dp.validate_candidate(cand, DATA / "15_firewall_internal_log.md").ok


def test_heuristic_marked_in_yaml(tmp_path):
    name = "19_dhcp_lease_log.md"
    cand = dp.draft(DATA / name, use_llm=False)
    out = dp.accept(cand, profiles_dir=tmp_path)
    assert out.accepted
    assert yaml.safe_load(out.path.read_text(encoding="utf-8"))["drafted_by"] == "heuristic"


# ------------------------------------------------------------------ Done when
# Heuristic drafter, existing profile removed (temp profiles dir holds only drafts),
# must reproduce the hand-written profile's events.
# Known field-name differences per file (hand-written fields are all reproduced):
#   11_vpn_auth_log.md: draft adds `event` (auth / session_end) where the hand profile uses two
#       literal-token regexes. Event kind name is derived from the file name for every file
#       (e.g. windows_dc_auth vs windows_auth); kind is not compared.
EXTRA_FIELDS = {"11_vpn_auth_log.md": {"event"}}


@pytest.mark.parametrize("name", FILES)
def test_heuristic_reproduces_hand_profile(name, tmp_path):
    profiles = logs.load_profiles()
    row = logs._coverage_rows(DATA).get(name)
    ref = logs.parse_file(DATA / name, profiles[name], row)
    cand = dp.draft(DATA / name, use_llm=False)
    assert dp.validate_candidate(cand, DATA / name).ok
    assert dp.accept(cand, profiles_dir=tmp_path).accepted
    drafted = yaml.safe_load((tmp_path / "drafted" / (Path(name).stem + ".yaml")).read_text(encoding="utf-8"))
    assert logs.load_profiles(tmp_path) == {}  # the hand profile is not present in this dir
    got = logs.parse_file(DATA / name, drafted, row)
    cmp = dp.compare_events(ref, got)
    assert cmp["count_ref"] == cmp["count_draft"]
    assert cmp["ts_mismatch"] == []
    assert cmp["missing_fields"] == [] and cmp["value_diff"] == []
    assert set(cmp["extra_fields"]) <= EXTRA_FIELDS.get(name, set())
    for a, b in zip(ref, got):
        assert (a.ts_utc, a.ts_end_utc, a.line) == (b.ts_utc, b.ts_end_utc, b.line)
