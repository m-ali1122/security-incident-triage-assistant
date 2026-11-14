"""Line-oriented batch runner for triage questions."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _records(path: Path):
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".json", ".jsonl"):
        values = json.loads(text) if path.suffix.lower() == ".json" else [json.loads(x) for x in text.splitlines() if x.strip() and not x.lstrip().startswith("#")]
        values = values if isinstance(values, list) else [values]
        for n, value in enumerate(values, 1):
            if isinstance(value, str):
                yield str(n), value
            elif isinstance(value, dict) and value.get("question"):
                yield str(value.get("id", n)), str(value["question"])
        return
    n = 0
    for line in text.splitlines():
        question = line.strip()
        if not question or question.startswith("#"):
            continue
        n += 1
        yield str(n), question


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Answer triage questions as JSONL")
    parser.add_argument("input", type=Path)
    parser.add_argument("--no-llm", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        from triage.facts import get_facts
        from triage.answer.pipeline import answer
        facts = get_facts()
    except (ImportError, NotImplementedError) as exc:
        facts, answer, unavailable = None, None, f"{type(exc).__name__}: not built yet"
    stream = args.out.open("w", encoding="utf-8") if args.out else sys.stdout
    try:
        for qid, question in _records(args.input):
            print(f"processing {qid}", file=sys.stderr, flush=True)
            record = {"id": qid, "question": question}
            try:
                if answer is None:
                    raise RuntimeError(unavailable)
                try:
                    result = answer(question, facts=facts, use_llm=not args.no_llm)
                except TypeError:
                    result = answer(question)
                data = result.to_dict() if hasattr(result, "to_dict") else result
                record.update({"answer": data.get("answer", ""), "structured": data.get("structured", {}), "meta": data.get("meta", {})})
            except Exception as exc:
                record.update({"answer": "", "structured": {}, "meta": {"error": str(exc)}})
            stream.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            stream.flush()
    finally:
        if args.out:
            stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
