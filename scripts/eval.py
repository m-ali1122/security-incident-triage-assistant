from __future__ import annotations
import argparse, json, sys
from collections import defaultdict
import importlib.util
from pathlib import Path
import httpx, yaml

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("golden_checker", ROOT / "tests" / "test_golden.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
check_answer = _mod.check_answer

def load_sets(which):
    names = ["golden", "redteam"] if which == "all" else [which]
    out = []
    for n in names:
        with (ROOT / "tests" / f"{n}.yaml").open(encoding="utf-8") as f:
            out.append((n, yaml.safe_load(f)))
    return out

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--set", choices=["golden", "redteam", "all"], default="all")
    p.add_argument("--json")
    p.add_argument("--fail-under", type=float, default=0.9)
    p.add_argument("--in-process", action="store_true")
    args = p.parse_args()
    fn = None
    if args.in_process:
        from triage.answer.pipeline import answer as fn
    results, total, passed = [], 0, 0
    for setname, cases in load_sets(args.set):
        bytag = defaultdict(lambda: [0, 0])
        setpass = 0
        for case in cases:
            total += 1
            try:
                ans = fn(case["question"]) if fn else httpx.post(args.base_url.rstrip("/") + "/ask", json={"question": case["question"]}, timeout=30).json()
                failures = check_answer(ans, case["expect"])
            except Exception as exc:
                failures = [f"request/error: {exc}"]
            ok = not failures
            passed += ok; setpass += ok
            tags = case.get("tags", []) or []
            for tag in tags:
                bytag[tag][0] += ok; bytag[tag][1] += 1
            print(f"{setname}/{case['id']}: {'PASS' if ok else 'FAIL ' + ' | '.join(failures)}")
            results.append({"set": setname, "id": case["id"], "pass": ok, "failures": failures})
        print(f"{setname}: {setpass}/{len(cases)} = {setpass/len(cases):.3f}")
        for tag, (n, d) in sorted(bytag.items()): print(f"  tag {tag}: {n}/{d} = {n/d:.3f}")
    score = passed / total if total else 0
    print(f"overall: {passed}/{total} = {score:.3f}")
    if args.json:
        Path(args.json).write_text(json.dumps({"score": score, "passed": passed, "total": total, "results": results}, indent=2), encoding="utf-8")
    return 0 if score >= args.fail_under else 1

if __name__ == "__main__": raise SystemExit(main())
