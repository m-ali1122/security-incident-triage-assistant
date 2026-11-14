"""Pre-warmed seed answer cache."""
import copy

import pytest

from triage.answer import pipeline
from triage.facts import get_facts
from triage.llm import pool as llm_pool

Q = "Who owns 10.10.3.45?"


@pytest.fixture(scope="module")
def facts():
    return get_facts()


@pytest.fixture
def seed(monkeypatch, facts):
    monkeypatch.delenv("TRIAGE_SEED_CACHE", raising=False)
    a = pipeline.answer(Q, facts=facts, use_llm=False).to_dict()
    cache = {pipeline.normalise_question(Q): a}
    monkeypatch.setattr(pipeline, "_SEED", cache)

    def boom(*a, **k):
        raise AssertionError("pool called")
    monkeypatch.setattr(llm_pool, "complete", boom)
    return cache


def test_hit_is_cached_without_pool(seed, facts):
    a = pipeline.answer("  who OWNS 10.10.3.45 ?? ", facts=facts, use_llm=True)
    assert a.meta["cached"] is True
    assert a.meta["facts_hash"] == facts.short_hash
    assert a.answer == seed[pipeline.normalise_question(Q)]["answer"]


def test_tampered_entry_ignored(seed, facts):
    e = seed[pipeline.normalise_question(Q)]
    e["answer"] = "Data was stolen and exfiltrated from the file server."
    a = pipeline.answer(Q, facts=facts, use_llm=True)
    assert a.meta["cached"] is False


def test_missing_file_harmless(monkeypatch, tmp_path, facts):
    monkeypatch.setattr(pipeline, "_SEED", None)
    monkeypatch.setattr(pipeline, "_SEED_PATH", tmp_path / "nope.json")
    a = pipeline.answer(Q, facts=facts, use_llm=False)
    assert a.answer and a.meta["cached"] is False
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(pipeline, "_SEED", None)
    monkeypatch.setattr(pipeline, "_SEED_PATH", tmp_path / "bad.json")
    assert pipeline.answer(Q, facts=facts, use_llm=False).answer


def test_use_llm_false_bypasses(seed, facts):
    seed[pipeline.normalise_question(Q)]["meta"] = dict(seed[pipeline.normalise_question(Q)]["meta"], marker="seed")
    a = pipeline.answer(Q, facts=facts, use_llm=False)
    assert "marker" not in a.meta and a.meta["cached"] is False


def test_env_disables(seed, facts, monkeypatch):
    monkeypatch.setenv("TRIAGE_SEED_CACHE", "0")
    monkeypatch.setattr(llm_pool, "complete", lambda *a, **k: None)
    assert pipeline.answer(Q, facts=facts, use_llm=True).meta["cached"] is False
