from pathlib import Path

from triage.llm.cache import DiskCache
from triage.llm.pool import Pool, ProviderError


class Clock:
    def __init__(self): self.now = 0.0
    def __call__(self): return self.now
    def sleep(self, seconds): self.now += seconds


class Fake:
    def __init__(self, name, keys, outcomes, model="fake"):
        self.name, self.keys, self.model, self.outcomes, self.calls = name, keys, model, list(outcomes), []
    def complete(self, key, system, user, json_mode):
        self.calls.append(key)
        outcome = self.outcomes.pop(0) if self.outcomes else "ok"
        if isinstance(outcome, Exception): raise outcome
        return outcome


def make_pool(tmp_path, providers, clock=None):
    clock = clock or Clock()
    return Pool(providers, clock=clock, sleep=clock.sleep, jitter=lambda: 0, cache=DiskCache(tmp_path))


def test_429_moves_to_next_key(tmp_path):
    gemini = Fake("gemini", ["secret-a", "secret-b"], [ProviderError(429), "answer"])
    result = make_pool(tmp_path, [gemini]).complete("s", "u")
    assert result and result.text == "answer" and gemini.calls == ["secret-a", "secret-b"]


def test_all_gemini_keys_failing_moves_to_groq(tmp_path):
    gemini = Fake("gemini", ["a", "b"], [ProviderError(500), ProviderError(500), ProviderError(500), ProviderError(500)])
    groq = Fake("groq", ["c"], ["groq answer"])
    result = make_pool(tmp_path, [gemini, groq]).complete("s", "u")
    assert result and result.provider == "groq"


def test_everything_failing_returns_none(tmp_path):
    providers = [Fake("gemini", ["a"], [ProviderError(500), ProviderError(500)]), Fake("groq", ["b"], [ProviderError(500), ProviderError(500)])]
    assert make_pool(tmp_path, providers).complete("s", "u") is None


def test_repeated_prompt_hits_cache_without_calls(tmp_path):
    provider = Fake("groq", ["a"], ["cached answer"])
    pool = make_pool(tmp_path, [provider])
    assert pool.complete(" s ", "u  x").cached is False
    assert pool.complete("s", "u x").cached is True
    assert len(provider.calls) == 1


def test_cooldown_and_breaker_are_honoured(tmp_path):
    clock = Clock()
    provider = Fake("gemini", ["a", "b"], [ProviderError(429, retry_after=10), "ok"])
    pool = make_pool(tmp_path, [provider], clock)
    assert pool.complete("s", "first").text == "ok"
    assert pool.complete("s", "second").text == "ok"
    assert provider.calls == ["a", "b", "b"]


def test_status_never_exposes_key_values(tmp_path):
    provider = Fake("groq", ["do-not-return-this"], [ProviderError(429)])
    pool = make_pool(tmp_path, [provider])
    pool.complete("s", "u")
    assert "do-not-return-this" not in repr(pool.status())


def test_env_timeout_and_breaker_read_at_call_time(tmp_path, monkeypatch):
    from triage.llm.pool import HTTPProvider
    monkeypatch.delenv("LLM_TIMEOUT_S", raising=False)
    provider = HTTPProvider("groq", "m", ["k"])
    assert provider.timeout == 20.0
    monkeypatch.setenv("LLM_TIMEOUT_S", "7")
    assert provider.timeout == 7.0

    clock = Clock()
    monkeypatch.setenv("BREAKER_OPEN_S", "5")
    pool = make_pool(tmp_path, [Fake("groq", ["a"], [ProviderError(500)] * 2)], clock)
    assert pool.complete("s", "u") is None
    assert pool._state["groq"]["breaker"] == clock.now + 5.0
