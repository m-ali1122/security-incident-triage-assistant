"""Fallback pool for the configured LLM providers."""

from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx

from .cache import DiskCache, cache_key


@dataclass
class LLMResult:
    text: str
    provider: str
    model: str
    cached: bool
    key_index: int | None
    latency_ms: float


class ProviderError(Exception):
    def __init__(self, status: int | None = None, retry_after: float | None = None, message: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class HTTPProvider:
    def __init__(self, name: str, model: str, keys: list[str], timeout: float = 20.0) -> None:
        self.name, self.model, self.keys, self.timeout = name, model, keys, timeout

    def complete(self, key: str, system: str, user: str, json_mode: bool) -> str:
        if self.name == "gemini":
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
            body: dict[str, Any] = {"contents": [{"role": "user", "parts": [{"text": f"{system}\n\n{user}"}]}], "generationConfig": {"temperature": 0}}
            if json_mode:
                body["generationConfig"]["responseMimeType"] = "application/json"
            headers = {"x-goog-api-key": key}
        else:
            url = "https://api.groq.com/openai/v1/chat/completions" if self.name == "groq" else "https://openrouter.ai/api/v1/chat/completions"
            body = {"model": self.model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}], "temperature": 0}
            if json_mode:
                body["response_format"] = {"type": "json_object"}
            headers = {"Authorization": f"Bearer {key}"}
            if self.name == "openrouter":
                headers["HTTP-Referer"] = "triage-assistant"
        try:
            response = httpx.post(url, headers=headers, json=body, timeout=self.timeout)
        except httpx.TimeoutException as exc:
            raise ProviderError(message="timeout") from exc
        except httpx.HTTPError as exc:
            raise ProviderError(message=str(exc)) from exc
        retry_after = _retry_after(response)
        if response.status_code >= 400:
            message = response.text.lower()
            if response.status_code == 429 or "quota" in message or "rate limit" in message:
                raise ProviderError(response.status_code, retry_after, response.text)
            if response.status_code >= 500:
                raise ProviderError(response.status_code, retry_after, response.text)
            raise ProviderError(response.status_code, message=response.text)
        try:
            data = response.json()
            if self.name == "gemini":
                return data["candidates"][0]["content"]["parts"][0]["text"]
            return data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError(message="malformed provider response") from exc


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None


class Pool:
    def __init__(self, providers: list[Any] | None = None, clock: Callable[[], float] | None = None, sleep: Callable[[float], None] | None = None, cache: DiskCache | None = None, jitter: Callable[[], float] | None = None) -> None:
        self.providers = providers
        self.clock = clock or time.monotonic
        self.sleep = sleep or time.sleep
        self.jitter = jitter or (lambda: random.uniform(0.0, 0.25))
        self.cache = cache or DiskCache()
        self._state: dict[str, dict[str, Any]] = {}
        self._events: list[dict[str, Any]] = []
        self._last_signature: tuple[Any, ...] | None = None

    def _event(self, kind: str, provider: str, key_index: int | None = None, **extra: Any) -> None:
        event = {"event": kind, "provider": provider}
        if key_index is not None:
            event["key_index"] = key_index
        event.update(extra)
        self._events.append(event)
        del self._events[:-100]

    def _configured(self) -> list[Any]:
        if self.providers is not None:
            return self.providers
        values = []
        for name, key_env, model_env in (("gemini", "GEMINI_API_KEYS", "GEMINI_MODEL"), ("groq", "GROQ_API_KEYS", "GROQ_MODEL"), ("openrouter", "OPENROUTER_API_KEYS", "OPENROUTER_MODEL")):
            keys = [key.strip() for key in os.getenv(key_env, "").split(",") if key.strip()]
            if keys:
                values.append(HTTPProvider(name, os.getenv(model_env, ""), keys))
        return values

    def complete(self, system: str, user: str, json_mode: bool = False, *, facts_hash: str = "", prompt_version: str = "") -> LLMResult | None:
        if os.getenv("LLM_ENABLED", "1") == "0":
            return None
        key = cache_key(user, system, facts_hash, prompt_version)
        cached = self.cache.get(key)
        if cached:
            return LLMResult(cached["text"], cached.get("provider", "cache"), cached.get("model", ""), True, cached.get("key_index"), float(cached.get("latency_ms", 0)))
        providers = self._configured()
        signature = tuple((getattr(p, "name", ""), tuple(getattr(p, "keys", ())), getattr(p, "model", "")) for p in providers)
        if signature != self._last_signature:
            self._state.clear()
            self._last_signature = signature
        for provider in providers:
            name = getattr(provider, "name", provider.__class__.__name__.lower())
            keys = list(getattr(provider, "keys", []))
            state = self._state.setdefault(name, {"cooldowns": {}, "breaker": 0.0, "next": 0})
            now = self.clock()
            if state["breaker"] > now:
                self._event("breaker_skipped", name, until=state["breaker"])
                continue
            available = [i for i in range(len(keys)) if state["cooldowns"].get(i, 0) <= now]
            if not available:
                self._open_breaker(name, state)
                continue
            ordered = sorted(available, key=lambda i: (i - state["next"]) % len(keys))
            exhausted = True
            for index in ordered:
                try:
                    started = self.clock()
                    text = self._call(provider, keys[index], system, user, json_mode, name, index)
                    latency = (self.clock() - started) * 1000
                    state["next"] = (index + 1) % len(keys)
                    record = {"text": text, "provider": name, "model": getattr(provider, "model", ""), "key_index": index, "latency_ms": latency}
                    self.cache.put(key, record)
                    return LLMResult(text, record["provider"], record["model"], False, index, latency)
                except ProviderError as error:
                    if error.status == 429 or error.status is not None and error.status < 500 and ("quota" in str(error).lower() or "rate limit" in str(error).lower()):
                        cooldown = error.retry_after if error.retry_after is not None else 30.0
                        state["cooldowns"][index] = self.clock() + cooldown
                        self._event("cooldown", name, index, seconds=cooldown)
                        continue
                    if error.status is None or error.status >= 500:
                        self._event("fallback_retry", name, index)
                        self.sleep(0.25 + self.jitter())
                        try:
                            started = self.clock()
                            text = self._call(provider, keys[index], system, user, json_mode, name, index)
                            latency = (self.clock() - started) * 1000
                            state["next"] = (index + 1) % len(keys)
                            record = {"text": text, "provider": name, "model": getattr(provider, "model", ""), "key_index": index, "latency_ms": latency}
                            self.cache.put(key, record)
                            return LLMResult(text, name, record["model"], False, index, latency)
                        except ProviderError:
                            continue
                    self._event("fallback", name, index)
            if exhausted:
                self._open_breaker(name, state)
        return None

    def _call(self, provider: Any, key: str, system: str, user: str, json_mode: bool, name: str, index: int) -> str:
        method = getattr(provider, "complete", None) or getattr(provider, "call")
        try:
            return method(key, system, user, json_mode)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(message=str(exc)) from exc

    def _open_breaker(self, name: str, state: dict[str, Any]) -> None:
        state["breaker"] = self.clock() + 60.0
        self._event("breaker_open", name, seconds=60)

    def status(self) -> dict[str, Any]:
        providers = self._configured()
        now = self.clock()
        result: dict[str, Any] = {"providers": {}, "events": list(self._events), "cache": {"hits": self.cache.hits, "misses": self.cache.misses}}
        for provider in providers:
            name = getattr(provider, "name", provider.__class__.__name__.lower())
            state = self._state.get(name, {"cooldowns": {}, "breaker": 0.0})
            result["providers"][name] = {"key_count": len(getattr(provider, "keys", [])), "cooldowns": {str(i): max(0.0, until - now) for i, until in state.get("cooldowns", {}).items() if until > now}, "breaker": max(0.0, state.get("breaker", 0.0) - now)}
        return result


_POOL = Pool()


def complete(system: str, user: str, json_mode: bool = False, *, facts_hash: str = "", prompt_version: str = "") -> LLMResult | None:
    return _POOL.complete(system, user, json_mode, facts_hash=facts_hash, prompt_version=prompt_version)


def pool_status() -> dict[str, Any]:
    return _POOL.status()
