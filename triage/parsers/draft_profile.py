"""A1: drafted source profiles for log files that have no hand-written profile.

The LLM (or, without one, a deterministic heuristic) only proposes the *format*
of a log: a line regex with named groups, the timestamp format, the zone. It
never supplies facts. Code then accepts the candidate only if it matches every
line of the file, every timestamp parses, every UTC time lies inside the
source's coverage window (file 20), and a time plus at least one entity exist.

Nothing here is imported by the existing pipeline; drafted profiles are written
under ``triage/profiles/drafted/`` which ``load_profiles`` does not read.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional, Union

import yaml

from triage import config
from triage.answer.anonymize import Anonymizer
from triage.models import parse_utc
from triage.parsers import logs
from triage.parsers.coverage import load_coverage

_PKT = timezone(timedelta(hours=5), "PKT")
SCHEMA_KEYS = ("kind", "line_regex", "ts_format", "timezone", "ts_means", "duration_field",
               "untrusted_fields", "int_fields", "kv_rest", "strip_suffix")
ENTITY_KEYS = {"src_ip", "dst_ip", "ip", "client", "assigned_ip", "user", "account", "host",
               "hostname", "device", "workstation", "to", "from", "target", "caller", "mac"}
_UNTRUSTED = ("user_agent", "path", "url", "subject", "from", "url_host")


@dataclass
class Issue:
    check: str
    message: str
    line: Optional[int] = None

    def __str__(self) -> str:
        return f"line {self.line}: {self.message}" if self.line else self.message


@dataclass
class ValidationResult:
    ok: bool
    issues: list[Issue] = field(default_factory=list)
    lines_checked: int = 0

    @property
    def reasons(self) -> list[str]:
        return [str(i) for i in self.issues]


@dataclass
class ProfileCandidate:
    name: str
    file: str
    source: str  # 'llm' | 'heuristic'
    profile: dict
    file_path: Optional[Path] = None
    parse_error: Optional[str] = None
    samples_sent: list[str] = field(default_factory=list)
    validation: Optional[ValidationResult] = None

    def to_dict(self, drafted: bool = True) -> dict:
        out = dict(self.profile)
        out["file"] = self.file
        if drafted:
            out["drafted"] = True
            out["drafted_by"] = self.source
        return out

    def to_yaml(self, drafted: bool = True) -> str:
        return yaml.safe_dump(self.to_dict(drafted), sort_keys=False, allow_unicode=True)


@dataclass
class AcceptResult:
    accepted: bool
    path: Optional[Path]
    reasons: list[str]
    status: str  # 'accepted' | 'present but unparsed'


# --------------------------------------------------------------------- reading
def read_file(file_path: Union[str, Path]) -> tuple[list[str], list[str]]:
    """(header lines before the first fence, lines inside fenced blocks)."""
    src = Path(file_path).read_text(encoding="utf-8").splitlines()
    header, block, in_block, seen = [], [], False, False
    for line in src:
        if line.strip().startswith("```"):
            in_block, seen = not in_block, True
            continue
        if in_block:
            block.append(line)
        elif not seen:
            header.append(line)
    if not block:  # same fallback as logs.parse_file
        block = [line for line in src if line.strip() and not line.startswith("#")]
    return header, block


def _known_entities(lines: list[str]) -> dict:
    known: dict[str, set] = {"user": set(), "host": set(), "email": set()}
    for line in lines:
        for key, val in logs._kv_tokens(line).items():
            k = key.lower()
            if k in {"user", "account", "target", "caller", "username"}:
                known["user"].add(val.split("\\")[-1])
            elif k in {"hostname", "workstation", "host"} and val.lower() != "unknown":
                known["host"].add(val)
            elif k in {"to", "from"} and "@" in val:
                known["user"].add(val.split("@", 1)[0])
    return {k: sorted(v) for k, v in known.items()}


def _pick_samples(lines: list[str], n: int = 5) -> list[str]:
    lines = [ln for ln in lines if ln.strip()]
    if len(lines) <= n:
        return lines
    idx = sorted({round(i * (len(lines) - 1) / (n - 1)) for i in range(n)})
    return [lines[i] for i in idx]


def anonymised_samples(file_path: Union[str, Path]) -> tuple[list[str], list[str]]:
    header, block = read_file(file_path)
    anon = Anonymizer(_known_entities(block))
    head = [anon.anonymize(h) for h in header if h.strip()][:3]
    return head, [anon.anonymize(s) for s in _pick_samples(block)]


# ------------------------------------------------------------------- LLM path
SYSTEM_PROMPT = (
    "You infer the line format of a log file. You only propose the FORMAT; you never state facts about "
    "events. Reply with one JSON object and nothing else, with keys: kind (short snake_case name), "
    "line_regex (a Python regex, or list of regexes, anchored with ^ and $, that matches each whole log line; "
    "use named groups; the timestamp must be in group 'ts'; put trailing key=value text in group 'rest'), "
    "kv_rest (true if rest holds key=value pairs), ts_format (strptime format of group ts), "
    "timezone (UTC, PKT or offset), ts_means (event, start or close), duration_field, "
    "untrusted_fields (list of attacker-controllable field names), int_fields (list of numeric field names). "
    "Values in the samples were replaced by tokens such as IP_1 or USER_1; keep the regex general."
)


def _user_prompt(name: str, header: list[str], samples: list[str], tz_hint: str) -> str:
    return ("File: %s\nHeader:\n%s\nCoverage sheet time-zone note: %s\nSample lines:\n%s\n"
            % (name, "\n".join(header), tz_hint or "(none)", "\n".join(samples)))


def _default_llm(system: str, user: str):
    from triage.llm import pool
    return pool.complete(system, user, json_mode=True)


def parse_llm_reply(text: str) -> dict:
    """JSON or YAML mapping from an LLM reply; raises ValueError otherwise."""
    t = (text or "").strip()
    t = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", t).strip()
    if not t:
        raise ValueError("empty reply")
    try:
        data = json.loads(t)
    except ValueError:
        try:
            data = yaml.safe_load(t)
        except yaml.YAMLError as exc:
            raise ValueError(f"reply is neither JSON nor YAML: {exc}") from None
    if not isinstance(data, dict):
        raise ValueError("reply is not a mapping")
    return data


def _clean_profile(data: dict) -> dict:
    prof = {k: data[k] for k in SCHEMA_KEYS if k in data}
    prof.setdefault("kind", "unprofiled")
    prof.setdefault("duration_field", "duration_s")
    return prof


# ------------------------------------------------------------- heuristic path
_ISO_Z = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
_PLAIN = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
_COMBINED = (r'^(?P<src_ip>\S+) - - \[(?P<ts>[^]]+)\] "(?P<method>\S+) (?P<path>\S+) HTTP/[^"]+" '
             r'(?P<status>\d+) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"$')


def _kind_from_name(name: str) -> str:
    stem = re.sub(r"^\d+_", "", Path(name).stem)
    return re.sub(r"_log$", "", stem)


def _tz_from_coverage(src) -> tuple[Optional[str], Optional[str]]:
    if src is None:
        return None, None
    tz = {"offset_in_line": "offset"}.get(src.timezone, src.timezone)
    return tz, src.ts_means


def _detect_shape(lines: list[str]) -> Optional[dict]:
    """Timestamp shape from the first line, confirmed on all lines."""
    first = lines[0]
    shapes = [
        ("combined", re.compile(_COMBINED), None, "%d/%b/%Y:%H:%M:%S %z", "offset"),
        ("bracket", re.compile(r"^\[(" + _PLAIN + r") (UTC|PKT)\](?= )"), None, "%Y-%m-%d %H:%M:%S", None),
        ("iso_z", re.compile("^(" + _ISO_Z + ")(?= )"), None, "%Y-%m-%dT%H:%M:%SZ", "UTC"),
        ("iso_off", re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2})(?= )"), None,
         "%Y-%m-%dT%H:%M:%S%z", "offset"),
        ("plain_off", re.compile(r"^(" + _PLAIN + r" [+-]\d{2}:\d{2})(?= )"), None, "%Y-%m-%d %H:%M:%S %z", "offset"),
        ("plain", re.compile(r"^(" + _PLAIN + r")(?: (UTC|PKT))?(?= )"), None, "%Y-%m-%d %H:%M:%S", None),
    ]
    for name, rx, _x, fmt, tz in shapes:
        if rx.match(first) and all(rx.match(ln) for ln in lines):
            zone = rx.match(first).group(2) if rx.groups >= 2 and name != "combined" else None
            if name != "combined" and zone and not all((rx.match(ln).group(2) == zone) for ln in lines):
                zone = None
            return {"name": name, "rx": rx, "fmt": fmt, "tz": zone or tz, "zone_word": zone}
    return None


def _leading_tokens(rem: str) -> list[str]:
    out = []
    for tok in rem.split(" "):
        if "=" in tok:
            break
        out.append(tok)
    return out


def _heuristic_regex(lines: list[str], shape: dict) -> Optional[tuple[list[str], bool]]:
    if shape["name"] == "combined":
        return [_COMBINED], False
    ts_pat = {"bracket": _PLAIN, "iso_z": _ISO_Z, "plain": _PLAIN,
              "iso_off": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2}",
              "plain_off": _PLAIN + r" [+-]\d{2}:\d{2}"}[shape["name"]]
    zone = r" " + shape["zone_word"] if shape["zone_word"] else ""
    ts = f"(?P<ts>{ts_pat})"
    if shape["name"] == "bracket":
        prefix, sep = r"^\[" + ts + zone + r"\]", " "
    else:
        prefix, sep = "^" + ts + zone, None
    rems = [ln[shape['rx'].match(ln).end():] for ln in lines]
    pipe = all(r.startswith(" | ") for r in rems)
    if not pipe and not all(r.startswith(" ") for r in rems):
        return None
    if pipe:
        segs = [r[3:].split(" | ") for r in rems]
        first, parts, i = segs[0], [], 0
        if i < len(first) and "=" not in first[i]:
            parts.append(r"(?P<device>[^|]+)")
            i += 1
        if i < len(first) and re.fullmatch(r"[^\s=]+=[^\s]*", first[i]):
            parts.append(r"(?P<cells>[^|]+?)")
            i += 1
        if i < len(first) and "=" not in first[i]:
            parts.append(r"(?P<description>[^|]+?)")
            i += 1
        parts.append(r"(?P<rest>.*)")
        return [prefix + r" \| " + r" \| ".join(parts) + "$"], True
    toks = [_leading_tokens(r[1:]) for r in rems]
    n = min(len(t) for t in toks)
    parts, seen_ip = [], 0
    for i in range(n):
        col = [t[i] for t in toks]
        if all(re.fullmatch(r"\d+\.\d+\.\d+\.\d+:\d+", c) for c in col):
            side = "src" if seen_ip == 0 else "dst"
            seen_ip += 1
            parts.append(rf"(?P<{side}_ip>[^: ]+):(?P<{side}_port>\d+)")
        elif all(c == "->" for c in col):
            parts.append("->")
        elif all(c.lower() in {"tcp", "udp", "icmp"} for c in col):
            parts.append(r"(?P<proto>\S+)")
        elif i == 0 and not all(c.isalpha() and c.isupper() for c in col):
            parts.append(r"(?P<device>\S+)")
        elif all(c.isupper() for c in col):
            parts.append(r"(?P<action>\S+)")
        elif len(set(col)) > 1:
            parts.append(r"(?P<event>\S+)")
        else:
            parts.append(re.escape(col[0]))
    body = (" " + " ".join(parts) if parts else "") + " (?P<rest>.*)"
    return [prefix + body + "$"], True


def _int_fields(lines: list[str], regexes: list[str]) -> list[str]:
    seen: dict[str, list[bool]] = {}
    for ln in lines:
        m = logs._line_match(ln, {"line_regex": regexes})
        if not m:
            continue
        g = m.groupdict()
        items = {k: v for k, v in g.items() if k not in {"ts", "rest", "cells", "description"} and v is not None}
        for part in ("rest", "cells"):
            if g.get(part):
                items.update(logs._kv_tokens(g[part]))
        for k, v in items.items():
            seen.setdefault(k, []).append(bool(re.fullmatch(r"\d+", v)))
    return sorted(k for k, flags in seen.items() if flags and all(flags))


def draft_heuristic(file_path: Union[str, Path], coverage=None) -> ProfileCandidate:
    path = Path(file_path)
    _, lines = read_file(path)
    lines = [ln for ln in lines if ln.strip()]
    cand = ProfileCandidate(_kind_from_name(path.name), path.name, "heuristic", {}, path)
    if not lines:
        cand.parse_error = "no lines in file"
        return cand
    shape = _detect_shape(lines)
    if shape is None:
        cand.parse_error = "no known timestamp shape on every line"
        return cand
    built = _heuristic_regex(lines, shape)
    if built is None:
        cand.parse_error = "could not split the line after the timestamp"
        return cand
    regexes, kv_rest = built
    if coverage is None:
        try:
            coverage = load_coverage(path.parent)
        except Exception:
            coverage = None
    cov_tz, cov_means = _tz_from_coverage(coverage.find_source(path.name) if coverage else None)
    all_text = " ".join(lines)
    names = set(re.findall(r"\(\?P<(\w+)>", regexes[0])) | set(logs._kv_tokens(all_text))
    prof = {
        "kind": cand.name,
        "line_regex": regexes[0] if len(regexes) == 1 else regexes,
        "kv_rest": kv_rest,
        "ts_format": shape["fmt"],
        "timezone": cov_tz or shape["tz"] or "UTC",
        "ts_means": cov_means or "event",
        "duration_field": "duration_s",
        "untrusted_fields": [k for k in _UNTRUSTED if k in names],
    }
    ints = _int_fields(lines, regexes)
    if ints:
        prof["int_fields"] = ints
    cand.profile = prof
    return cand


# ----------------------------------------------------------------------- draft
def draft(file_path: Union[str, Path], llm: Optional[Callable] = None, coverage=None,
          use_llm: bool = True) -> ProfileCandidate:
    """Draft a profile. `llm(system, user)` returns text, an LLMResult or None."""
    path = Path(file_path)
    if coverage is None:
        try:
            coverage = load_coverage(path.parent)
        except Exception:
            coverage = None
    if use_llm:
        call = llm or _default_llm
        header, samples = anonymised_samples(path)
        src = coverage.find_source(path.name) if coverage else None
        user = _user_prompt(path.name, header, samples, src.tz_text if src else "")
        try:
            reply = call(SYSTEM_PROMPT, user)
        except Exception as exc:  # provider failure: treat as no LLM
            reply = None
            _ = exc
        if reply is not None:
            text = reply if isinstance(reply, str) else getattr(reply, "text", "")
            cand = ProfileCandidate(_kind_from_name(path.name), path.name, "llm", {}, path,
                                    samples_sent=header + samples)
            try:
                cand.profile = _clean_profile(parse_llm_reply(text))
            except ValueError as exc:
                cand.parse_error = f"LLM reply not usable: {exc}"
            return cand
    return draft_heuristic(path, coverage)


# ------------------------------------------------------------------ validation
def _to_utc(value: str, profile: dict) -> datetime:
    fmt = profile.get("ts_format")
    value = value.strip()
    try:
        dt = datetime.strptime(value, fmt) if fmt else datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        if str(profile.get("timezone", "UTC")).lower() == "offset":
            raise ValueError("timezone is 'offset' but the timestamp carries no offset")
        dt = dt.replace(tzinfo=_PKT if str(profile.get("timezone")).upper() == "PKT" else timezone.utc)
    return dt.astimezone(timezone.utc)


def validate_candidate(candidate: ProfileCandidate, file_path: Union[str, Path, None] = None,
                       coverage=None) -> ValidationResult:
    path = Path(file_path or candidate.file_path)
    issues: list[Issue] = []

    def done(lines_checked: int = 0) -> ValidationResult:
        res = ValidationResult(not issues, issues, lines_checked)
        candidate.validation = res
        return res

    if candidate.parse_error:
        issues.append(Issue("reply", candidate.parse_error))
        return done()
    prof = candidate.profile
    exprs = prof.get("line_regex")
    exprs = [exprs] if isinstance(exprs, str) else exprs
    if not exprs or not all(isinstance(e, str) for e in exprs):
        issues.append(Issue("regex", "line_regex missing or not a string/list of strings"))
        return done()
    for e in exprs:
        try:
            compiled = re.compile(e)
        except re.error as exc:
            issues.append(Issue("regex", f"regex does not compile: {exc}"))
            return done()
        if "ts" not in compiled.groupindex and "timestamp" not in compiled.groupindex:
            issues.append(Issue("fields", "regex has no named group 'ts' (no time field)"))
    if issues:
        return done()
    if not prof.get("ts_format") and not prof.get("timezone"):
        issues.append(Issue("timestamp", "ts_format and timezone missing"))
        return done()

    _, lines = read_file(path)
    if coverage is None:
        try:
            coverage = load_coverage(path.parent)
        except Exception:
            coverage = None
    src = coverage.find_source(path.name) if coverage else None
    if src is None:
        issues.append(Issue("coverage", f"no coverage entry for {path.name} in file 20"))
    else:
        cov_tz = {"offset_in_line": "offset"}.get(src.timezone, src.timezone)
        if str(prof.get("timezone", "UTC")).lower() != cov_tz.lower():
            issues.append(Issue("coverage", f"timezone {prof.get('timezone')!r} disagrees with coverage sheet ({cov_tz})"))
    windows = [(parse_utc(a), parse_utc(b)) for a, b in (src.windows_utc if src else [])]
    date = coverage.date if coverage else None

    matched_all = True
    for n, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        m = logs._line_match(raw, prof)
        if m is None:
            issues.append(Issue("match", f"regex does not match: {raw[:100]}", n))
            matched_all = False
            continue
        g = m.groupdict()
        ts = g.get("ts") or g.get("timestamp")
        if not ts:
            issues.append(Issue("fields", "no timestamp captured", n))
            continue
        try:
            t = _to_utc(ts, prof)
        except (ValueError, TypeError) as exc:
            issues.append(Issue("timestamp", f"timestamp {ts!r} does not parse: {exc}", n))
            continue
        if src is not None:
            if date and t.strftime("%Y-%m-%d") != date:
                issues.append(Issue("window", f"{t.isoformat()} is not on the covered date {date}", n))
            elif not any(a <= t <= b for a, b in windows):
                issues.append(Issue("window", f"{t.isoformat()} is outside the coverage window of {src.file}", n))
    if matched_all:
        row = logs._coverage_rows(path.parent).get(path.name)
        try:
            events = logs.parse_file(path, prof, row)
        except Exception as exc:
            issues.append(Issue("fields", f"profile fails to parse the file: {exc}"))
            events = []
        for ev in events:
            if not any(k in ENTITY_KEYS and str(v).strip() for k, v in ev.fields.items()):
                issues.append(Issue("fields", "no entity field (ip, user or host) extracted", ev.line))
    return done(len([x for x in lines if x.strip()]))


# ---------------------------------------------------------------------- accept
def drafted_dir(profiles_dir: Union[str, Path, None] = None) -> Path:
    return (Path(profiles_dir) if profiles_dir is not None else config.PROFILES_DIR) / "drafted"


def accept(candidate: ProfileCandidate, profiles_dir: Union[str, Path, None] = None,
           file_path: Union[str, Path, None] = None, coverage=None) -> AcceptResult:
    res = candidate.validation or validate_candidate(candidate, file_path or candidate.file_path, coverage)
    if not res.ok:
        return AcceptResult(False, None, res.reasons, "present but unparsed")
    out = drafted_dir(profiles_dir)
    out.mkdir(parents=True, exist_ok=True)
    target = out / f"{Path(candidate.file).stem}.yaml"
    target.write_text(candidate.to_yaml(), encoding="utf-8")
    return AcceptResult(True, target, [], "accepted")


# ------------------------------------------------------------------ comparison
def compare_events(reference: list, drafted: list) -> dict:
    """Event-for-event comparison; reference is the hand-written profile's output."""
    out: dict[str, Any] = {"count_ref": len(reference), "count_draft": len(drafted),
                           "ts_mismatch": [], "missing_fields": set(), "value_diff": set(),
                           "extra_fields": set(), "kind_ref": None, "kind_draft": None}
    if reference:
        out["kind_ref"], out["kind_draft"] = reference[0].kind, drafted[0].kind if drafted else None
    for a, b in zip(reference, drafted):
        if (a.ts_utc, a.ts_end_utc) != (b.ts_utc, b.ts_end_utc):
            out["ts_mismatch"].append(a.line)
        for k, v in a.fields.items():
            if k not in b.fields:
                out["missing_fields"].add(k)
            elif b.fields[k] != v:
                out["value_diff"].add(k)
        out["extra_fields"] |= set(b.fields) - set(a.fields)
    out["identical"] = (out["count_ref"] == out["count_draft"] and not out["ts_mismatch"]
                        and not out["missing_fields"] and not out["value_diff"])
    for k in ("missing_fields", "value_diff", "extra_fields"):
        out[k] = sorted(out[k])
    return out
