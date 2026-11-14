"""Profile-driven parsers for the collected line-oriented log sources."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Union

import yaml

from triage import config
from triage.models import Event, parse_utc, to_utc_iso

_PKT = timezone(timedelta(hours=5), "PKT")
_UNTRUSTED = {"user_agent", "path", "url", "subject", "from", "url_host"}
_ALIASES = {"bytes_to_client": "bytes_server_to_client", "bytes_from_client": "bytes_client_to_server", "duration": "duration_s", "EventID": "event_id_win"}
_INT_FIELDS = {"bytes_total", "bytes_server_to_client", "bytes_client_to_server", "bytes", "dst_port", "src_port", "status", "size", "duration_s", "event_id_win"}


def load_profiles(profiles_dir: Union[str, Path, None] = None) -> dict[str, dict]:
    directory = Path(profiles_dir) if profiles_dir is not None else config.PROFILES_DIR
    profiles: dict[str, dict] = {}
    for path in sorted(directory.glob("*.yaml")):
        with path.open(encoding="utf-8") as fh:
            profile = yaml.safe_load(fh) or {}
        if profile.get("file"):
            profiles[str(profile["file"])] = profile
    return profiles


def _coverage_rows(data_dir: Path) -> dict[str, dict]:
    path = data_dir / "20_log_source_coverage.md"
    rows: dict[str, dict] = {}
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|") or line.startswith("|---") or "Source" in line:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 5:
            rows[cells[1]] = {"source": cells[0], "file": cells[1], "timezone": cells[2], "coverage": cells[3], "notes": cells[4]}
    return rows


def _coverage_timezone(row: dict | None, profile: dict) -> str:
    values = row or {}
    raw = values.get("timezone", values.get("time_zone", values.get("Time zone / format", "")))
    if not raw:
        raw = next((v for k, v in values.items() if "zone" in str(k).lower()), "")
    text = str(raw).lower()
    if "offset" in text:
        return "offset"
    if "pkt" in text or "utc+5" in text:
        return "PKT"
    if "utc" in text:
        return "UTC"
    return str(profile.get("timezone", "UTC"))


def _coverage_means(row: dict | None, profile: dict) -> str:
    text = " ".join(str(v) for v in (row or {}).values()).lower()
    if "close" in text:
        return "close"
    if "start" in text:
        return "start"
    return str(profile.get("ts_means", "event"))


def _parse_time(value: str, profile: dict, row: dict | None) -> datetime:
    value = value.strip()
    tz_kind = _coverage_timezone(row, profile)
    fmt = profile.get("ts_format")
    try:
        dt = datetime.strptime(value, fmt) if fmt else datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_PKT if tz_kind == "PKT" else timezone.utc)
    return dt.astimezone(timezone.utc)


def _convert_value(key: str, value: Any, profile: dict) -> tuple[str, Any]:
    key = _ALIASES.get(key, key)
    if isinstance(value, bool):
        return key, value
    value = value.strip()
    suffixes = profile.get("strip_suffix", {}) or {}
    if key in suffixes:
        value = value.removesuffix(str(suffixes[key]))
    elif key == "duration_s":
        value = value.removesuffix("s")
    if key in (_INT_FIELDS | set(profile.get("int_fields", []) or [])):
        try:
            return key, int(value)
        except ValueError:
            pass
    if key == "score":
        try:
            return key, float(value)
        except ValueError:
            pass
    return key, value


def _kv_tokens(text: str) -> dict[str, Any]:
    pattern = re.compile(r"(?P<key>[A-Za-z_][\w-]*)=(?:\"(?P<quoted>[^\"]*)\"|'(?P<single>[^']*)'|(?P<bare>[^\s|]+))")
    return {m.group("key"): (m.group("quoted") or m.group("single") or m.group("bare")) for m in pattern.finditer(text)}


def _line_match(raw: str, profile: dict) -> re.Match[str] | None:
    alternatives = profile.get("line_regex", [])
    if isinstance(alternatives, str):
        alternatives = [alternatives]
    for expression in alternatives:
        match = re.match(expression, raw)
        if match:
            return match
    return None


def _generic_timestamp(raw: str) -> str | None:
    for pattern in (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})", r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: [A-Z]+| [+-]\d{2}:?\d{2})?"):
        match = re.search(pattern, raw)
        if match:
            return match.group(0)
    return None


def parse_file(path: Union[str, Path], profile: dict, coverage_row: dict | None = None) -> list[Event]:
    path = Path(path)
    source_lines = path.read_text(encoding="utf-8").splitlines()
    in_block = False
    lines: list[str] = []
    for line in source_lines:
        if line.strip().startswith("```"):
            in_block = not in_block
            continue
        if in_block:
            lines.append(line)
    if not lines:
        lines = [line for line in source_lines if line.strip() and not line.startswith("#")]
    events: list[Event] = []
    for line_no, raw in enumerate(lines, 1):
        match = _line_match(raw, profile)
        unprofiled = match is None
        if unprofiled:
            ts_value = _generic_timestamp(raw) or "1970-01-01T00:00:00Z"
            kind, fields = "unprofiled", {"unprofiled": True}
            tokens = _kv_tokens(raw)
            tokens.pop("unprofiled", None)
            fields.update(tokens)
        else:
            groups = match.groupdict()
            kind, ts_value = profile.get("kind", "unprofiled"), groups.pop("ts", None) or groups.pop("timestamp", None)
            fields = {k: v for k, v in groups.items() if k not in {"rest", "cells", "description"} and v is not None}
            if groups.get("description") is not None:
                fields["description"] = groups["description"]
            if profile.get("kv_rest"):
                fields.update(_kv_tokens(groups.get("rest", "")))
            if groups.get("cells"):
                fields.update(_kv_tokens(groups["cells"]))
        fields = dict(_convert_value(k, v, profile) for k, v in fields.items())
        # DC records use account=, target=, or caller= depending on EventID.
        # Preserve the original identifier in account and expose its normalized user.
        if "account" not in fields:
            for identity_key in ("target", "caller"):
                if str(fields.get(identity_key, "")).startswith("ORBIT\\"):
                    fields["account"] = fields[identity_key]
                    break
        if "account" in fields and str(fields["account"]).startswith("ORBIT\\"):
            fields["user"] = str(fields["account"]).split("\\")[-1]
        if "from" in fields and "@" in str(fields["from"]):
            fields["from_domain"] = str(fields["from"]).split("@", 1)[1]
        if "to" in fields and "@" in str(fields["to"]):
            fields["to_user"] = str(fields["to"]).split("@", 1)[0]
        try:
            ts = _parse_time(ts_value or "1970-01-01 00:00:00", profile, coverage_row)
        except (ValueError, TypeError):
            ts = datetime(1970, 1, 1, tzinfo=timezone.utc)
        ts_end = None
        if not unprofiled and _coverage_means(coverage_row, profile) == "close":
            duration = fields.get(profile.get("duration_field", "duration_s"))
            if duration is not None:
                ts_end, ts = to_utc_iso(ts), ts - timedelta(seconds=int(duration))
        events.append(Event(event_id="", kind=kind, ts_utc=to_utc_iso(ts), ts_end_utc=ts_end, source_file=path.name, line=line_no, raw=raw, fields=fields, untrusted_fields=[k for k in ("user_agent", "path", "url", "subject", "from", "url_host") if k in fields]))
    return events


def parse_all(data_dir: Union[str, Path, None] = None) -> list[Event]:
    root = Path(data_dir) if data_dir is not None else config.DATA_DIR
    profiles, coverage, events = load_profiles(), _coverage_rows(root), []
    for source_file, profile in profiles.items():
        path = root / source_file
        if path.exists():
            events.extend(parse_file(path, profile, coverage.get(source_file)))
    for path in sorted(root.glob("*.md")):
        # Markdown tables/rules are not line logs.  The coverage sheet itself and
        # numbered table documents (including the IDS summary) stay with P2.
        log_like = path.name.lower().endswith("_log.md") or "log" in path.name.lower()
        if path.name not in profiles and log_like and path.name != "20_log_source_coverage.md":
            events.extend(parse_file(path, {"kind": "unprofiled", "timezone": "UTC"}, coverage.get(path.name)))
    events.sort(key=lambda event: (parse_utc(event.ts_utc), event.source_file, event.line))
    for index, event in enumerate(events, 1):
        event.event_id = f"E-{index:04d}"
    return events
