"""P2: coverage model (file 20): time zone, timestamp meaning, gaps, missing sources."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

from triage.models import PKT, Cite, Gap, parse_utc, to_utc_iso
from triage.parsers.tables import (_Dict, _col, _main_table, find_file, read_bullets,
                                   read_md_tables)

_TIME_WIN = re.compile(
    r"(\d{1,2}:\d{2}(?::\d{2})?)\s*(?:to|-)\s*(\d{1,2}:\d{2}(?::\d{2})?)\s*(UTC|PKT)?", re.I)
_FORMAT_NOTE = re.compile(r"^(logged when|duration|messages with|summary only)", re.I)


@dataclass
class SourceCoverage(_Dict):
    source: str
    file: str
    tz_text: str
    timezone: str  # UTC | PKT | offset_in_line
    ts_means: str  # start | close | event
    coverage: str
    windows_utc: list  # [(from_iso, to_iso)] covered on the date
    notes: str
    cite: Cite


@dataclass
class Coverage(_Dict):
    sources: list
    gaps: list  # list[Gap]
    not_collected: list  # [{name, reason, cite}]
    other_dates_note: Optional[str]
    date: Optional[str]
    quarantine_threshold: Optional[float]
    scope_notes: list  # [{source, text, cite}]

    def find_source(self, name: str) -> Optional[SourceCoverage]:
        q = _norm(name)
        if not q:
            return None
        for test in (lambda s: q in (_norm(s.file), _norm(s.source)),
                     lambda s: _norm(s.file).startswith(q) or _norm(s.source).startswith(q),
                     lambda s: q in _norm(s.file) or q in _norm(s.source)):
            hits = [s for s in self.sources if test(s)]
            if hits:
                return hits[0]
        m = re.match(r"^(\d+)_", name.strip())
        if m:
            return next((s for s in self.sources if s.file.startswith(m.group(1) + "_")), None)
        return None

    def is_not_collected(self, name: str) -> bool:
        q = _norm(name)
        return any(q and (q in _norm(n["name"]) or _norm(n["name"]) in q) for n in self.not_collected)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def _tz_kind(text: str) -> str:
    t = text.lower()
    if "offset" in t:
        return "offset_in_line"
    if "pkt" in t or "utc+5" in t:
        return "PKT"
    return "UTC"


def _ts_means(notes: str) -> str:
    n = notes.lower()
    if re.search(r"when the (?:connection|session|request)\s+start", n):
        return "start"
    if re.search(r"when the (?:connection|session|request)\s+(?:close|end)", n):
        return "close"
    return "event"


def _at(date: str, hms: str, tz) -> datetime:
    p = [int(x) for x in hms.split(":")]
    p += [0] * (3 - len(p))
    d = datetime.strptime(date, "%Y-%m-%d")
    return d.replace(hour=p[0], minute=p[1], second=p[2], tzinfo=tz)


def _iso(dt: datetime) -> str:
    return to_utc_iso(dt)


def _build(data_dir) -> Coverage:
    path = find_file(20, data_dir)
    tab = _main_table(path)
    cov_hdr = next((h for h in tab.headers if "coverage" in h.lower()), "")
    dm = re.search(r"\d{4}-\d\d-\d\d", cov_hdr)
    date = dm.group(0) if dm else None
    sec = timedelta(seconds=1)
    day_start = _at(date, "00:00:00", timezone.utc) if date else None
    day_end = _at(date, "23:59:59", timezone.utc) if date else None

    sources, gaps, scope = [], [], []
    thr = None
    for r in tab.rows:
        name = _col(r, "source")
        fname = _col(r, "file")
        tz_text = _col(r, "time zone", "format")
        kind = _tz_kind(tz_text)
        cov = _col(r, "coverage")
        notes = _col(r, "notes")
        cite = Cite(file=path.name, row=name)
        tz = PKT if kind == "PKT" else timezone.utc
        windows = []
        reason_parts = [s.strip() for s in re.split(r"\.\s+|\.$", notes)
                        if s.strip() and not _FORMAT_NOTE.match(s.strip())]
        reason = ". ".join(reason_parts)
        tm = _TIME_WIN.search(cov)
        low = cov.lower()
        if date and tm:
            wtz = {"UTC": timezone.utc, "PKT": PKT}.get((tm.group(3) or "").upper(), tz)
            a, b = _at(date, tm.group(1), wtz), _at(date, tm.group(2), wtz)
            if "except" in low:
                windows = [(day_start, a - sec), (b + sec, day_end)]
                gaps.append(Gap(fname, _iso(a), _iso(b), reason or cov, [cite]))
            else:
                windows = [(a, b)]
                if a > day_start:
                    gaps.append(Gap(fname, _iso(day_start), _iso(a - sec), reason or cov, [cite]))
                if b < day_end:
                    gaps.append(Gap(fname, _iso(b + sec), _iso(day_end), reason or cov, [cite]))
        elif date:
            windows = [(day_start, day_end)]
            if "only" in low:
                scope.append({"source": name, "text": cov, "cite": cite})
        for s in re.split(r"\.\s+|\.$", notes):
            s = s.strip()
            if re.search(r"not part of|not in\b|not on\b", s, re.I):
                scope.append({"source": name, "text": s, "cite": cite})
        m = re.search(r"score\s+([\d.]+)\s+or higher", notes, re.I)
        if m:
            thr = float(m.group(1))
        sources.append(SourceCoverage(name, fname, tz_text, kind, _ts_means(notes), cov,
                                      [(_iso(a), _iso(b)) for a, b in windows], notes, cite))

    not_collected, other = [], None
    for b in read_bullets(path):
        if re.search(r"dates? other than|other dates", b.text, re.I):
            other = b.text
        elif "NOT collected" in b.section or "do not exist" in b.section.lower():
            if ":" in b.text:
                nm, why = [x.strip() for x in b.text.split(":", 1)]
                not_collected.append({"name": nm, "reason": why.rstrip("."),
                                      "cite": Cite(file=path.name, row=nm)})
    return Coverage(sources, gaps, not_collected, other, date, thr, scope)


_CACHE: dict = {}


def clear_cache() -> None:
    _CACHE.clear()


def load_coverage(data_dir=None) -> Coverage:
    path = find_file(20, data_dir)
    key = (str(path.resolve()), path.stat().st_mtime_ns)
    if key not in _CACHE:
        _CACHE[key] = _build(data_dir)
    return _CACHE[key]


def _dt(t: Union[str, datetime]) -> datetime:
    if isinstance(t, str):
        return parse_utc(t)
    return t.replace(tzinfo=timezone.utc) if t.tzinfo is None else t.astimezone(timezone.utc)


def observable(source: str, t_utc: Union[str, datetime], data_dir=None) -> bool:
    """True if `source` was collecting at t_utc (outside any gap, source collected)."""
    cov = load_coverage(data_dir)
    t = _dt(t_utc)
    src = cov.find_source(source)
    if src is None:
        return False  # unknown or not collected
    if cov.date and t.strftime("%Y-%m-%d") != cov.date:
        return False
    for g in cov.gaps:
        if g.source == src.file and _dt(g.from_utc) <= t <= _dt(g.to_utc):
            return False
    return any(_dt(a) <= t <= _dt(b) for a, b in src.windows_utc)


def gaps_overlapping(from_utc: Union[str, datetime], to_utc: Union[str, datetime],
                     source: Optional[str] = None, data_dir=None) -> list[Gap]:
    """Gap records whose window overlaps [from_utc, to_utc]."""
    cov = load_coverage(data_dir)
    a, b = _dt(from_utc), _dt(to_utc)
    if b < a:
        a, b = b, a
    fname = None
    if source is not None:
        s = cov.find_source(source)
        fname = s.file if s else source
    return [g for g in cov.gaps
            if (fname is None or g.source == fname)
            and _dt(g.from_utc) <= b and _dt(g.to_utc) >= a]
