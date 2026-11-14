"""P9: answer pipeline (router, bundle, anonymizer, LLM phrasing, validators, template fallback)."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional

from triage.models import Answer, _empty_structured

SAFE_TEXT = ("There is not enough evidence in the logs to answer this question. Ask about the timeline, "
             "an address, an alert, the severity, actions or who to inform.")
_UNTRUSTED_TOKEN = re.compile(r"UNTRUSTED_\d+")


def _llm_default() -> bool:
    try:
        from triage import config
        return bool(config.LLM_ENABLED and (config.GEMINI_API_KEYS or config.GROQ_API_KEYS
                                            or config.OPENROUTER_API_KEYS))
    except Exception:
        return False


def _meta(path="template", provider="none", route="rules", cached=False, facts_hash="", **extra) -> dict:
    m = {"path": path, "provider": provider, "route": route, "cached": cached, "facts_hash": facts_hash}
    m.update(extra)
    return m


def _route(question: str, facts: Any):
    from triage.answer.router import route, strip_injection
    r = route(question, facts=facts)
    if r.injection:
        rest = strip_injection(question)
        if rest:
            r2 = route(rest, facts=facts)
            if r2.intents:
                r2.injection = True
                if "injection" not in r2.intents:
                    r2.intents.insert(0, "injection")
                r2.question = rest
                return r2
        # pure instruction: answer the topic it names from the facts
    return r


def _classify(question: str, r: Any, facts: Any) -> bool:
    from triage.answer.router import INTENTS
    from triage.llm import pool as llm_pool
    from triage.llm.prompts import PROMPT_VERSION, SYSTEM_CLASSIFY, build_classify_prompt
    res = llm_pool.complete(SYSTEM_CLASSIFY, build_classify_prompt(question, INTENTS), json_mode=True,
                            facts_hash=facts.short_hash, prompt_version=PROMPT_VERSION)
    if res is None:
        return False
    try:
        data = json.loads(re.search(r"\{.*\}", res.text, re.S).group(0))
        intents = [i for i in data.get("intents", []) if i in INTENTS]
    except Exception:
        return False
    if not intents:
        return False
    r.intents = [i for i in INTENTS if i in intents]
    r.out_of_scope = "out_of_scope" in r.intents
    r.route = "llm"
    return True


def _phrase(question: str, bundle: Any, structured: dict, facts: Any) -> tuple[Optional[str], dict]:
    """LLM phrasing with validation; returns (text or None, meta extras)."""
    from triage.answer.anonymize import Anonymizer
    from triage.answer.validate import validate
    from triage.llm import pool as llm_pool
    from triage.llm.prompts import PROMPT_VERSION, SYSTEM_PHRASING, build_phrasing_prompt, build_retry_prompt

    payload = bundle.to_llm()
    refs: dict = {}
    untrusted = payload.pop("untrusted", {})
    blob = json.dumps(payload, ensure_ascii=False)
    for vals in untrusted.values():
        for v in vals.values():
            if len(v) >= 6 and v in blob:
                tok = refs.setdefault(v, f"UNTRUSTED_{len(refs) + 1}")
                blob = blob.replace(json.dumps(v, ensure_ascii=False)[1:-1], tok)
    payload = json.loads(blob)
    payload["untrusted"] = untrusted
    payload["untrusted_refs"] = {t: v for v, t in refs.items()}
    anon = Anonymizer(facts.known_entities())
    payload_a = anon.anonymize(payload)
    q_a = anon.anonymize(question)
    user = build_phrasing_prompt(q_a, payload_a)
    back = {t: v for v, t in refs.items()}
    errors: list = []
    provider, cached = "none", False
    for attempt in range(2):
        prompt = user if attempt == 0 else user + "\n\n" + build_retry_prompt(prev, errors)
        res = llm_pool.complete(SYSTEM_PHRASING, prompt, facts_hash=facts.short_hash, prompt_version=PROMPT_VERSION)
        if res is None:
            return None, {"provider": provider, "validator_errors": errors or ["llm unavailable"]}
        provider, cached = res.provider, res.cached
        prev = res.text
        errors = [f"token: unmapped anonymizer token {t}" for t in anon.unmapped_tokens(res.text)]
        text = anon.deanonymize(res.text)
        text = _UNTRUSTED_TOKEN.sub(lambda m: back.get(m.group(0), m.group(0)), text)
        errors += [f"token: unmapped untrusted ref {t}" for t in _UNTRUSTED_TOKEN.findall(text)]
        errors += validate(text, structured, facts)
        if not errors:
            return text, {"provider": provider, "cached": cached}
    return None, {"provider": provider, "cached": cached, "validator_errors": errors}


_SEED_PATH = Path(__file__).with_name("seed_cache.json")
_SEED: Optional[dict] = None


def normalise_question(q: str) -> str:
    q = re.sub(r"\s+", " ", str(q or "").lower()).strip()
    return q.rstrip(" .?!;:,").strip()


def _seed_cache() -> dict:
    global _SEED
    if _SEED is None:
        try:
            data = json.loads(_SEED_PATH.read_text(encoding="utf-8"))
            _SEED = data if isinstance(data, dict) else {}
        except Exception:
            _SEED = {}
    return _SEED


def _seed_lookup(question: str, facts: Any, fh: str) -> Optional[Answer]:
    """Return a pre-warmed answer if it still validates against the current facts."""
    try:
        entry = _seed_cache().get(normalise_question(question))
        if not entry:
            return None
        from triage.answer.validate import validate
        a = Answer.from_dict(entry)
        if validate(a.answer, a.structured, facts):
            return None
        a.meta = dict(a.meta)
        a.meta.update(cached=True, facts_hash=fh)
        return a
    except Exception:
        return None


def answer(question: str, facts=None, use_llm=None) -> Answer:
    """Answer a question from the fact store. Never raises; works with the LLM disabled."""
    fh = ""
    try:
        from triage.answer.bundle import build_bundle
        from triage.answer.templates import render
        if facts is None:
            from triage.facts import get_facts
            facts = get_facts()
        fh = getattr(facts, "short_hash", "")
        if use_llm is None:
            use_llm = _llm_default()
        question = str(question or "")
        if use_llm is not False and os.environ.get("TRIAGE_SEED_CACHE", "1") != "0":
            hit = _seed_lookup(question, facts, fh)
            if hit is not None:
                return hit
        r = _route(question, facts)
        route_step = "rules"
        if r.route == "none":
            if use_llm and question.strip() and _classify(question, r, facts):
                route_step = "llm"
            else:
                route_step = "full_store"
        if "report" in r.intents and not ({"severity", "notify", "actions", "timeline", "entity_match"}
                                          & set(r.intents)):
            try:
                from triage.report import report_markdown
                md = report_markdown(facts)
                b = build_bundle(r, facts)
                return Answer(answer=md, structured=b.structured(), meta=_meta(route=route_step, facts_hash=fh))
            except Exception:
                pass
        b = build_bundle(r, facts)
        structured = b.structured()
        text = render(r, b)
        meta = _meta(route=route_step, facts_hash=fh)
        if use_llm:
            try:
                llm_text, extra = _phrase(r.question or question, b, structured, facts)
            except Exception as exc:  # noqa: BLE001
                llm_text, extra = None, {"validator_errors": [f"llm error: {exc}"]}
            if llm_text:
                meta.update(path="llm", provider=extra.get("provider", "none"), cached=extra.get("cached", False))
                text = llm_text
            else:
                meta.update(provider=extra.get("provider", "none"),
                            validator_errors=extra.get("validator_errors", []))
        return Answer(answer=text, structured=structured, meta=meta)
    except Exception as exc:  # noqa: BLE001
        return Answer(answer=SAFE_TEXT, structured=_empty_structured(),
                      meta=_meta(route="full_store", facts_hash=fh, error=f"{type(exc).__name__}: {exc}"))
