"""Generate triage/answer/seed_cache.json with real pipeline answers (run with PYTHONPATH=.)."""
import json
import os
import sys
import time
from pathlib import Path

os.environ["TRIAGE_SEED_CACHE"] = "0"
from triage.answer.pipeline import answer, normalise_question  # noqa: E402

D = Path(__file__).resolve().parents[1] / "triage" / "answer"


def main() -> int:
    qs = [l.strip() for l in (D / "seed_questions.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
    out, n_llm = {}, 0
    for q in qs:
        t0 = time.time()
        a = answer(q, use_llm=True)
        if a.meta.get("path") != "llm":
            time.sleep(1.5)
            b = answer(q, use_llm=True)
            if b.meta.get("path") == "llm":
                a = b
        a.meta["cached"] = False
        n_llm += a.meta.get("path") == "llm"
        out[normalise_question(q)] = a.to_dict()
        print(f"{a.meta.get('path')}\t{a.meta.get('provider')}\t{time.time() - t0:.1f}s\t{q}", flush=True)
        time.sleep(1.5)
    (D / "seed_cache.json").write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"{n_llm}/{len(qs)} llm")
    return 0


if __name__ == "__main__":
    sys.exit(main())
