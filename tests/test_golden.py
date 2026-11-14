"""Ground-truth contract tests and the shared Answer assertion checker."""
from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SUPPORTED_CHECKS = {
    "severity", "severity_steps_min", "citations_include", "citations_exclude",
    "labels", "entities_include", "entities_exclude", "actions_include",
    "actions_exclude", "notify_include", "notify_exclude", "answer_contains_any",
    "answer_excludes", "answer_must_not_assert_theft", "route_in",
}


def _dict(answer: Any) -> dict:
    if hasattr(answer, "to_dict"):
        answer = answer.to_dict()
    return answer if isinstance(answer, dict) else dict(answer)


def _structured(answer: Any) -> tuple[dict, dict]:
    a = _dict(answer)
    return a, a.get("structured", {}) or {}


def _contains(items: Any, wanted: str) -> bool:
    return any(wanted.casefold() in str(x).casefold() for x in (items or []))


def _citation_matches(c: dict, expected: dict) -> bool:
    return all(c.get(k) == v for k, v in expected.items())


def check_answer(answer: Any, expect: dict) -> list[str]:
    """Return specific failures for an Answer and an expect block."""
    a, s = _structured(answer)
    failures: list[str] = []
    labels = s.get("labels", {}) or {}
    citations = s.get("citations", []) or []
    actions = s.get("actions", []) or []
    notify = s.get("notify", []) or []
    entities = s.get("entities", []) or []
    text = str(a.get("answer", ""))

    if "severity" in expect and s.get("severity") != expect["severity"]:
        failures.append(f"severity expected {expect['severity']!r}, got {s.get('severity')!r}")
    if "severity_steps_min" in expect and len(s.get("severity_steps", []) or []) < expect["severity_steps_min"]:
        failures.append(f"severity_steps_min expected {expect['severity_steps_min']}")
    for key, should_exist in (("citations_include", True), ("citations_exclude", False)):
        for wanted in expect.get(key, []) or []:
            found = any(_citation_matches(c, wanted) for c in citations)
            if found != should_exist:
                failures.append(f"{key}: {wanted}")
    for field, wanted in (expect.get("labels", {}) or {}).items():
        if field.endswith("_contains"):
            bucket = field[:-9]
            for item in wanted:
                if not _contains(labels.get(bucket), item):
                    failures.append(f"labels.{bucket} missing substring {item!r}")
        elif field == "confirmed_excludes":
            for item in wanted:
                if _contains(labels.get("confirmed"), item):
                    failures.append(f"labels.confirmed contains excluded {item!r}")
        else:
            failures.append(f"unsupported labels check {field}")
    for key, should_exist in (("entities_include", True), ("entities_exclude", False)):
        for item in expect.get(key, []) or []:
            found = _contains(entities, item)
            if found != should_exist:
                failures.append(f"{key}: {item}")
    for key, should_exist in (("actions_include", True), ("actions_exclude", False)):
        for wanted in expect.get(key, []) or []:
            found = any(all(x.get(k) == v for k, v in wanted.items()) for x in actions)
            if found != should_exist:
                failures.append(f"{key}: {wanted}")
    for key, should_exist in (("notify_include", True), ("notify_exclude", False)):
        for wanted in expect.get(key, []) or []:
            found = any(wanted.casefold() in str(n.get("name", n)).casefold() for n in notify)
            if found != should_exist:
                failures.append(f"{key}: {wanted}")
    wanted_any = [str(x) for x in (expect.get("answer_contains_any", []) or [])]
    if wanted_any and not any(x.casefold() in text.casefold() for x in wanted_any):
        failures.append(f"answer missing any of {wanted_any!r}")
    for item in expect.get("answer_excludes", []) or []:
        if str(item).casefold() in text.casefold():
            failures.append(f"answer contains excluded {item!r}")
    if expect.get("answer_must_not_assert_theft"):
        import re
        assertion = re.compile(r"\b(data|files?|records?)\s+(?:was|were|has been|have been)\s+(?:stolen|leaked|exfiltrated)\b", re.I)
        allowed_negation = re.compile(r"\b(?:not|no|never|does not|do not|did not|cannot|can't)\b[^.]{0,35}\b(?:stolen|leaked|exfiltrated)\b", re.I)
        sentences = re.split(r"(?<=[.!?])\s+", text)
        if any(assertion.search(sentence) and not allowed_negation.search(sentence) for sentence in sentences):
            failures.append("answer asserts theft/leak/exfiltration")
    if "route_in" in expect and a.get("meta", {}).get("route") not in expect["route_in"]:
        failures.append(f"route {a.get('meta', {}).get('route')!r} not in {expect['route_in']!r}")
    return failures


def _cases(name: str) -> list[dict]:
    with (ROOT / "tests" / name).open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_schema_and_unique_ids():
    seen = set()
    for name in ("golden.yaml", "redteam.yaml"):
        cases = _cases(name)
        assert isinstance(cases, list) and cases
        for case in cases:
            assert set(case) >= {"id", "question", "expect"}
            assert case["id"] not in seen
            seen.add(case["id"])
            assert set(case["expect"]) <= SUPPORTED_CHECKS
            if "labels" in case["expect"]:
                assert set(case["expect"]["labels"]) <= {
                    "confirmed_contains", "suspected_contains",
                    "not_enough_evidence_contains", "confirmed_excludes",
                }


@pytest.mark.parametrize("expect,answer,should_pass", [
    ({"severity": "P1"}, {"structured": {"severity": "P1"}}, True),
    ({"severity": "P1"}, {"structured": {"severity": "P2"}}, False),
    ({"severity_steps_min": 3}, {"structured": {"severity_steps": [1, 2, 3]}}, True),
    ({"severity_steps_min": 3}, {"structured": {"severity_steps": [1]}}, False),
    ({"citations_include": [{"file": "x", "line": 2}]}, {"structured": {"citations": [{"file": "x", "line": 2}]}}, True),
    ({"citations_include": [{"file": "x", "line": 2}]}, {"structured": {"citations": []}}, False),
    ({"citations_exclude": [{"file": "x", "line": 2}]}, {"structured": {"citations": []}}, True),
    ({"citations_exclude": [{"file": "x", "line": 2}]}, {"structured": {"citations": [{"file": "x", "line": 2}]}}, False),
    ({"labels": {"confirmed_contains": ["CLICK"]}}, {"structured": {"labels": {"confirmed": ["click seen"]}}}, True),
    ({"labels": {"confirmed_contains": ["CLICK"]}}, {"structured": {"labels": {"confirmed": []}}}, False),
    ({"entities_include": ["user:amalik"]}, {"structured": {"entities": ["user:amalik"]}}, True),
    ({"entities_include": ["user:amalik"]}, {"structured": {"entities": []}}, False),
    ({"entities_exclude": ["user:amalik"]}, {"structured": {"entities": ["user:utariq"]}}, True),
    ({"entities_exclude": ["user:amalik"]}, {"structured": {"entities": ["user:amalik"]}}, False),
    ({"actions_include": [{"runbook": "RB-X", "step": 2}]}, {"structured": {"actions": [{"runbook": "RB-X", "step": 2}]}}, True),
    ({"actions_include": [{"runbook": "RB-X", "step": 2}]}, {"structured": {"actions": []}}, False),
    ({"actions_exclude": [{"runbook": "RB-X", "step": 2}]}, {"structured": {"actions": []}}, True),
    ({"actions_exclude": [{"runbook": "RB-X", "step": 2}]}, {"structured": {"actions": [{"runbook": "RB-X", "step": 2}]}}, False),
    ({"notify_include": ["Hamza Qureshi"]}, {"structured": {"notify": [{"name": "Hamza Qureshi"}]}}, True),
    ({"notify_include": ["Hamza Qureshi"]}, {"structured": {"notify": []}}, False),
    ({"notify_exclude": ["Mariam Chaudhry"]}, {"structured": {"notify": [{"name": "Hamza Qureshi"}]}}, True),
    ({"notify_exclude": ["Mariam Chaudhry"]}, {"structured": {"notify": [{"name": "Mariam Chaudhry"}]}}, False),
    ({"labels": {"confirmed_excludes": ["attack"]}}, {"structured": {"labels": {"confirmed": ["harmless"]}}}, True),
    ({"labels": {"confirmed_excludes": ["attack"]}}, {"structured": {"labels": {"confirmed": ["attack"]}}}, False),
    ({"answer_contains_any": ["06:03:12"]}, {"answer": "started 06:03:12"}, True),
    ({"answer_contains_any": ["06:03:12"]}, {"answer": "started later"}, False),
    ({"answer_excludes": ["11:21:19"]}, {"answer": "06:03:12"}, True),
    ({"answer_excludes": ["11:21:19"]}, {"answer": "11:21:19"}, False),
    ({"answer_must_not_assert_theft": True}, {"answer": "The logs do not show data was stolen."}, True),
    ({"answer_must_not_assert_theft": True}, {"answer": "Finance data was stolen."}, False),
    ({"route_in": ["rules"]}, {"meta": {"route": "rules"}}, True),
    ({"route_in": ["rules"]}, {"meta": {"route": "llm"}}, False),
])
def test_checker_unit(expect, answer, should_pass):
    assert (check_answer(answer, expect) == []) is should_pass


@pytest.mark.parametrize("filename", ["golden.yaml", "redteam.yaml"])
def test_pipeline_cases(filename):
    try:
        pipeline = importlib.import_module("triage.answer.pipeline")
        answer = pipeline.answer
    except (ImportError, ModuleNotFoundError, NotImplementedError) as exc:
        pytest.skip(f"pipeline unavailable: {exc}")
    for case in _cases(filename):
        try:
            result = answer(case["question"])
        except NotImplementedError as exc:
            pytest.skip(f"pipeline not implemented: {exc}")
        failures = check_answer(result, case["expect"])
        assert not failures, f"{case['id']}: {'; '.join(failures)}"
