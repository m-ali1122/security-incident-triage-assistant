"""P9: answer pipeline (router, bundle, anonymizer, LLM phrasing, validators, template fallback)."""
from __future__ import annotations

from triage.models import Answer


def answer(question: str) -> Answer:
    """Answer a question from the fact store. Must work with the LLM disabled (template path)."""
    raise NotImplementedError("P9")
