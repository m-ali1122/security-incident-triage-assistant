"""Draft a source profile for a log file (add-on A1).

usage: python scripts/draft_profile.py <file> [--accept] [--no-llm]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triage.parsers import draft_profile as dp, logs  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("file")
    ap.add_argument("--accept", action="store_true", help="write profiles/drafted/<name>.yaml if valid")
    ap.add_argument("--no-llm", action="store_true", help="use the heuristic drafter only")
    args = ap.parse_args(argv)
    path = Path(args.file)

    cand = dp.draft(path, use_llm=not args.no_llm)
    print(f"# source: {cand.source}")
    if cand.parse_error:
        print(f"# no usable profile: {cand.parse_error}")
    else:
        print(cand.to_yaml())
    res = dp.validate_candidate(cand, path)
    print("validation:", "OK" if res.ok else "REJECTED")
    for reason in res.reasons:
        print("  -", reason)

    existing = logs.load_profiles().get(path.name)
    if existing and res.ok:
        row = logs._coverage_rows(path.parent).get(path.name)
        cmp = dp.compare_events(logs.parse_file(path, existing, row), logs.parse_file(path, cand.profile, row))
        print("comparison with existing profile:")
        print(f"  events: {cmp['count_ref']} vs {cmp['count_draft']}; ts mismatches: {len(cmp['ts_mismatch'])}")
        print(f"  fields missing in draft: {cmp['missing_fields']}; differing values: {cmp['value_diff']}; extra in draft: {cmp['extra_fields']}")
        print(f"  kind: {cmp['kind_ref']} vs {cmp['kind_draft']}; identical: {cmp['identical']}")
    elif existing:
        print("an existing profile is present for this file; no comparison because the draft was rejected")

    if args.accept:
        out = dp.accept(cand, file_path=path)
        if out.accepted:
            print(f"written: {out.path}")
        else:
            print(f"{path.name}: present but unparsed (nothing written)")
    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
