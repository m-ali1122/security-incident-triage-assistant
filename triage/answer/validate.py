"""Answer validators (ARCHITECTURE 9.5). Pure functions returning error lists.

The checks that need the fact store are written against this duck-typed
interface, so any object with these methods works (the real FactStore adapter
or a test fake):

    class Facts(Protocol):
        has_line(file, line) -> bool
        line_text(file, line) -> str | None
        has_row(file, row) -> bool
        runbook_step(runbook, step) -> str | None   # step text, None if absent
        known_times_utc() -> set[str]               # 'HH:MM:SS'
        incident_severity(incident_id) -> str | None
"""
from __future__ import annotations

import re
from typing import Any, Optional, Protocol

from .anonymize import TOKEN_RE


class Facts(Protocol):
    def has_line(self, file: str, line: int) -> bool: ...
    def line_text(self, file: str, line: int) -> Optional[str]: ...
    def has_row(self, file: str, row: str) -> bool: ...
    def runbook_step(self, runbook: str, step: int) -> Optional[str]: ...
    def known_times_utc(self) -> set: ...
    def incident_severity(self, incident_id: str) -> Optional[str]: ...


# ------------------------------------------------------------------ wording
_RUNBOOK_ID = re.compile(r"\bRB-[A-Z]+-\d+\b")
_FILENAME = re.compile(r"\b[\w-]+\.(?:md|csv|json|log|txt|yaml|yml)\b", re.I)
_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z(\"'\d\[])|\n+")
_CLAUSE_SPLIT = re.compile(
    r"[;:]|,\s*(?:but|however|yet|although|though|whereas|while|and)\b|"
    r"\b(?:but|however|although|though|whereas)\b"
)

_HEDGE = re.compile(
    r"\b(?:not|no|never|none|nothing|neither|nor|cannot|without|unclear|unknown|"
    r"unconfirmed|unverified|unproven|whether|if|might|may|could|would|possible|possibly|"
    r"potential|potentially|suspect(?:ed|s)?|allegedly|alleged|claims?|claimed|asks?|asked|"
    r"instructs?|instructed|instruction|insufficient|lack(?:s|ing)?|rule[sd]? out)\b|n't|"
    r"\bno evidence\b|\bnot enough evidence\b",
    re.I,
)

_CRED = r"(?:password|passwords|passcode|credential|credentials|creds|token|tokens|cookie|cookies|session|sessions|mfa|secret|secrets|key|keys|login|logins)"
_DATA = (r"(?:data|files?|documents?|records?|information|database|databases|dump|archive|"
         r"contents?|payroll|customer|customers|folders?|spreadsheets?|backups?)")

_STOLE_VERB = re.compile(r"\b(stolen|stole|steals?|stealing)\b")
_LEAK_VERB = re.compile(r"\b(leaked|leaks|leaking)\b")
_EXFIL_VERB = re.compile(r"\bexfiltrat(?:ed|es|ing|e)\b")
_DATA_THEFT = re.compile(r"\b(?:data|file|files|information|document|documents)\s+(?:theft|leak|breach|loss)\b")
_COPIED_OUT = re.compile(
    rf"(?:\b{_DATA}\b[^.]{{0,40}}\b(?:was|were|has been|have been|had been|got|is|are|being)\s+"
    rf"(?:taken|copied|moved|carried|pulled|downloaded|sent|uploaded|transferred)\s+(?:out|off|away|outside)\b)|"
    rf"(?:\b(?:took|taken|take|copied|copy|copies|copying|moved|pulled|carried|walked)\b[^.]{{0,40}}\b{_DATA}\b"
    rf"[^.]{{0,30}}\b(?:out|off|away|outside)\b)"
)
# noun forms: asserted only in "is / was / occurred / evidence of" shapes
_NOUN = r"(?:data\s+)?(?:exfiltration|theft|leak|breach)"
_NOUN_ASSERT = [
    re.compile(rf"\b(?:is|was|are|were|constitutes?|represents?|indicates?|shows?|confirms?|proves?|demonstrates?)\s+"
               rf"(?:a\s+|an\s+|the\s+|clear\s+|confirmed\s+|case\s+of\s+|instance\s+of\s+)*{_NOUN}\b"),
    re.compile(rf"\b{_NOUN}\s+(?:occurred|happened|took place|has occurred|has happened|is confirmed|was confirmed|did occur)\b"),
    re.compile(rf"\bevidence\s+of\s+{_NOUN}\b"),
]
_TYPE_NAME_CTX = re.compile(
    r"\b(?:type|types|category|class|classified|label|labelled|labeled|named|titled|called|runbook|row|matrix|rule)\b"
)
_CRED_AFTER = re.compile(rf"^\W*(?:\w+\W+){{0,2}}?{_CRED}\b")
_CRED_BEFORE = re.compile(rf"\b{_CRED}\b(?:\W+\w+){{0,4}}\W*$")


def _clauses(sentence: str):
    for c in _CLAUSE_SPLIT.split(sentence):
        c = c.strip()
        if c:
            yield c


def _clause_asserts(clause_orig: str) -> Optional[str]:
    """Return a reason string if the (unhedged) clause asserts data loss as fact."""
    c = clause_orig.lower()
    if _HEDGE.search(c):
        return None
    for m in _STOLE_VERB.finditer(c):
        after = c[m.end():]
        before = c[:m.start()]
        if _CRED_AFTER.match(after):
            continue
        if m.group(1) == "stolen" and _CRED_BEFORE.search(before) and not re.search(rf"\b{_DATA}\b", before):
            continue
        return f"asserts theft ('{m.group(0)}')"
    for pat, label in ((_LEAK_VERB, "leak"), (_EXFIL_VERB, "exfiltration"),
                       (_DATA_THEFT, "data theft"), (_COPIED_OUT, "data copied out")):
        m = pat.search(c)
        if m:
            return f"asserts {label} ('{m.group(0)}')"
    for pat in _NOUN_ASSERT:
        m = pat.search(c)
        if m:
            tail = c[m.end():]
            if re.match(r"\s*\(", tail) or _TYPE_NAME_CTX.search(c):
                continue  # incident-type name used as a label
            return f"asserts data loss ('{m.group(0)}')"
    return None


def check_wording(text: str) -> list:
    """Fail text that states data/files were stolen, leaked, exfiltrated or copied out."""
    errors = []
    cleaned = _RUNBOOK_ID.sub("RUNBOOK", text or "")
    cleaned = _FILENAME.sub("FILE", cleaned)
    for sent in _SENT_SPLIT.split(cleaned):
        sent = sent.strip()
        if not sent or sent.endswith("?"):
            continue
        for clause in _clauses(sent):
            why = _clause_asserts(clause)
            if why:
                errors.append(f"wording: {why} in sentence: {sent[:160]!r}")
                break
    return errors


# ------------------------------------------------------------------- labels
_LABEL_PHRASES = {"confirmed", "suspected", "not enough evidence in the logs", "harmless"}
_LABEL_FIELD = re.compile(r"\b(?:label|status|verdict|classification)\s*[:=]\s*\**([A-Za-z_ ]+?)\**\s*(?:[.,;\n)]|$)", re.I)
_BAD_SYNONYMS = re.compile(r"\b(?:unconfirmed|inconclusive|probable|probably (?:malicious|compromised))\b", re.I)
_NEE_BAD = re.compile(r"not enough evidence(?! in the logs)", re.I)


def check_labels(answer_text: str, structured: dict) -> list:
    errors = []
    text = answer_text or ""
    low = text.lower()
    for m in _LABEL_FIELD.finditer(text):
        val = m.group(1).strip().lower()
        if val not in _LABEL_PHRASES:
            errors.append(f"labels: '{m.group(1).strip()}' is not one of confirmed / suspected / "
                          f"not enough evidence in the logs")
    for m in _BAD_SYNONYMS.finditer(text):
        errors.append(f"labels: non-standard label word '{m.group(0)}'")
    if _NEE_BAD.search(text):
        errors.append("labels: 'not enough evidence' must read 'not enough evidence in the logs'")
    labels = (structured or {}).get("labels") or {}
    if labels.get("not_enough_evidence") and "not enough evidence in the logs" not in low:
        errors.append("labels: text lacks the phrase 'not enough evidence in the logs'")
    if labels.get("suspected") and not re.search(r"\bsuspected\b", low):
        errors.append("labels: text lacks the word 'suspected'")
    if labels.get("confirmed") and not re.search(r"\bconfirmed\b", low):
        errors.append("labels: text lacks the word 'confirmed'")
    return errors


# ------------------------------------------------------------------- tokens
def check_tokens(text: str) -> list:
    return [f"token: leftover anonymizer token {t}" for t in dict.fromkeys(TOKEN_RE.findall(text or ""))]


# ---------------------------------------------------------------- citations
def _get(c: Any, key: str):
    return c.get(key) if isinstance(c, dict) else getattr(c, key, None)


def check_citations(structured: dict, facts: Facts, require_entities: bool = False) -> list:
    """Every cited line/row/runbook step exists. With require_entities, every entity
    must also appear in at least one cited line's text."""
    errors = []
    cited_texts = []
    for c in (structured or {}).get("citations") or []:
        f, line, row = _get(c, "file"), _get(c, "line"), _get(c, "row")
        rb, step = _get(c, "runbook"), _get(c, "step")
        if rb is not None and step is not None:
            if facts.runbook_step(rb, step) is None:
                errors.append(f"citation: runbook {rb} step {step} does not exist")
        elif line is not None:
            if not facts.has_line(f, line):
                errors.append(f"citation: {f} line {line} does not exist")
            else:
                t = facts.line_text(f, line)
                if t:
                    cited_texts.append(t.lower())
        elif row is not None:
            if not facts.has_row(f, row):
                errors.append(f"citation: {f} row {row} does not exist")
        else:
            errors.append(f"citation: malformed citation for {f}")
    if require_entities and cited_texts:
        blob = "\n".join(cited_texts)
        for e in (structured or {}).get("entities") or []:
            val = str(e).split(":", 1)[-1].lower()
            if val and val not in blob:
                errors.append(f"citation: entity {e} not found in any cited line")
    return errors


def check_actions(structured: dict, facts: Facts) -> list:
    errors = []
    for a in (structured or {}).get("actions") or []:
        rb, step = _get(a, "runbook"), _get(a, "step")
        if not rb or step is None:
            errors.append(f"action: missing runbook or step in {a!r}")
        elif facts.runbook_step(rb, step) is None:
            errors.append(f"action: runbook {rb} step {step} does not exist")
    return errors


# -------------------------------------------------------------------- times
_TIME_UTC = re.compile(r"(?<![\d:])(\d{2}:\d{2}:\d{2})\s*UTC\b")
_TIME_PKT = re.compile(r"(?<![\d:])(\d{2}:\d{2}:\d{2})\s*PKT\b")
_TIME_ANY = re.compile(r"(?<![\d:])(\d{2}:\d{2}:\d{2})(?![\d:])")


def _shift(t: str, hours: int) -> str:
    h, m, s = t.split(":")
    return f"{(int(h) + hours) % 24:02d}:{m}:{s}"


def check_times(text: str, facts: Facts) -> list:
    errors = []
    known = set(facts.known_times_utc())
    known_pkt = {_shift(t, 5) for t in known}
    text = text or ""
    for m in _TIME_UTC.finditer(text):
        if m.group(1) not in known:
            errors.append(f"time: {m.group(1)} UTC is not in the fact store")
    for m in _TIME_PKT.finditer(text):
        if m.group(1) not in known_pkt:
            errors.append(f"time: {m.group(1)} PKT does not match any UTC time in the fact store")
    labelled = {m.start(1) for m in _TIME_UTC.finditer(text)} | {m.start(1) for m in _TIME_PKT.finditer(text)}
    for m in _TIME_ANY.finditer(text):
        if m.start(1) not in labelled:
            errors.append(f"time: {m.group(1)} has no UTC label")
    return errors


# ----------------------------------------------------------------- severity
_SEV = re.compile(r"\bP[0-4]\b")


def check_severity(text: str, structured: dict, facts: Facts) -> list:
    """structured may carry 'incident_id' (with 'severity') or 'severities'
    ({incident_id: severity}). Each is compared with the calculator via facts.
    P-levels in the text must be among those, or appear in severity_steps."""
    errors = []
    s = structured or {}
    claimed = dict(s.get("severities") or {})
    if s.get("incident_id") and s.get("severity"):
        claimed.setdefault(s["incident_id"], s["severity"])
    allowed = set()
    for inc, sev in claimed.items():
        truth = facts.incident_severity(inc)
        if truth is None:
            errors.append(f"severity: unknown incident {inc}")
        elif truth != sev:
            errors.append(f"severity: {inc} claimed {sev} but calculator says {truth}")
        if truth:
            allowed.add(truth)
    if not claimed and s.get("severity"):
        allowed.add(s["severity"])
    for step in s.get("severity_steps") or []:
        allowed.update(_SEV.findall(step if isinstance(step, str) else str(step)))
    if allowed or claimed or s.get("severity"):
        for p in dict.fromkeys(_SEV.findall(text or "")):
            if p not in allowed:
                errors.append(f"severity: text mentions {p} which does not match the calculator")
    return errors


# ---------------------------------------------------------------------- all
def validate(answer_text: str, structured: dict, facts: Facts) -> list:
    errors = []
    errors += check_wording(answer_text)
    errors += check_labels(answer_text, structured)
    errors += check_tokens(answer_text)
    errors += check_citations(structured, facts)
    errors += check_actions(structured, facts)
    errors += check_times(answer_text, facts)
    errors += check_severity(answer_text, structured, facts)
    return errors
