"""Reversible anonymizer for fact bundles (ARCHITECTURE 9.3).

Sensitive values become stable tokens (USER_1, NAME_1, EMAIL_1, PHONE_1, IP_3,
HOST_2). Known entity strings per category come from the fact store; IPs,
emails and phone numbers are also found by regex. File names, runbook IDs,
alert IDs, change IDs, session IDs and asset tags are never touched because
they are needed for citations.
"""
from __future__ import annotations

import re
from typing import Any, Optional

CATEGORIES = ("user", "name", "email", "phone", "ip", "host")

TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])(?:USER|NAME|EMAIL|PHONE|IP|HOST)_\d+(?![A-Za-z0-9_])")

_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
_PHONE_RE = re.compile(
    r"(?<![\w+])(?:\+\d{1,3}(?:[-\s]?\d{2,5}){2,4}|0\d{2,3}[-\s]\d{6,8})(?!\d)"
)


def _bounded(s: str) -> re.Pattern:
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(s) + r"(?![A-Za-z0-9_])", re.IGNORECASE)


class Anonymizer:
    def __init__(self, known: Optional[dict] = None):
        self._known: list[tuple[str, str, re.Pattern]] = []  # (category, value, pattern)
        seen = set()
        for cat, values in (known or {}).items():
            cat = cat.lower()
            if cat not in CATEGORIES:
                continue
            for v in values or []:
                v = str(v).strip()
                if len(v) < 2 or (cat, v.lower()) in seen:
                    continue
                seen.add((cat, v.lower()))
                self._known.append((cat, v, _bounded(v)))
        self._known.sort(key=lambda t: -len(t[1]))
        self._counters: dict[str, int] = {}
        self._by_value: dict[tuple[str, str], str] = {}
        self._to_original: dict[str, str] = {}

    # ------------------------------------------------------------- internals
    def _token(self, cat: str, value: str) -> str:
        key = (cat, value.lower())
        tok = self._by_value.get(key)
        if tok is None:
            n = self._counters.get(cat, 0) + 1
            self._counters[cat] = n
            tok = f"{cat.upper()}_{n}"
            self._by_value[key] = tok
            self._to_original[tok] = value
        return tok

    def _candidates(self, text: str) -> list[tuple[int, int, str]]:
        cands = []
        for cat, _v, pat in self._known:
            for m in pat.finditer(text):
                cands.append((m.start(), m.end(), cat))
        for m in _EMAIL_RE.finditer(text):
            cands.append((m.start(), m.end(), "email"))
        for m in _IP_RE.finditer(text):
            if all(int(p) <= 255 for p in m.group().split(".")):
                cands.append((m.start(), m.end(), "ip"))
        for m in _PHONE_RE.finditer(text):
            cands.append((m.start(), m.end(), "phone"))
        return cands

    def _anon_str(self, text: str) -> str:
        cands = self._candidates(text)
        if not cands:
            return text
        # longest first; ties broken by position, then known-before-regex order
        cands.sort(key=lambda c: (-(c[1] - c[0]), c[0]))
        taken: list[tuple[int, int, str]] = []
        for s, e, cat in cands:
            if any(s < te and ts < e for ts, te, _ in taken):
                continue
            taken.append((s, e, cat))
        taken.sort()
        out, pos = [], 0
        for s, e, cat in taken:
            out.append(text[pos:s])
            out.append(self._token(cat, text[s:e]))
            pos = e
        out.append(text[pos:])
        return "".join(out)

    # ----------------------------------------------------------------- public
    def anonymize(self, obj: Any) -> Any:
        """Walk str / dict / list / tuple and tokenise values. Dict keys are kept."""
        if isinstance(obj, str):
            return self._anon_str(obj)
        if isinstance(obj, dict):
            return {k: self.anonymize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.anonymize(v) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self.anonymize(v) for v in obj)
        return obj

    def deanonymize(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return TOKEN_RE.sub(lambda m: self._to_original.get(m.group(), m.group()), obj)
        if isinstance(obj, dict):
            return {k: self.deanonymize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.deanonymize(v) for v in obj]
        return obj

    def unmapped_tokens(self, text: str) -> list[str]:
        """Token-shaped strings in text that this instance never issued."""
        out = []
        for m in TOKEN_RE.finditer(text):
            if m.group() not in self._to_original and m.group() not in out:
                out.append(m.group())
        return out

    @property
    def mapping(self) -> dict:
        return dict(self._to_original)
