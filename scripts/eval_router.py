"""Evaluate rules-only, classifier-only and rules+classifier routers (add-on A5)."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from triage.answer import classifier  # noqa: E402
from triage.answer.router import INTENTS, route  # noqa: E402
from triage.parsers.tables import load_tables  # noqa: E402

TAG_TO_INTENT = {
    "injection": "injection", "out-of-scope": "out_of_scope", "theft": "data_theft",
    "clustering": "incident_relation", "missing": "missing_data", "harmless": "alert_harmless",
    "severity": "severity", "timeline": "timeline", "entity": "entity_match",
    "actions": "actions", "notify": "notify",
}


def load_jsonl(p: Path) -> list[dict]:
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def load_cases(tables) -> list[dict]:
    cases = []
    for name in ("golden.yaml", "redteam.yaml"):
        for c in yaml.safe_load((ROOT / "tests" / name).read_text(encoding="utf-8")):
            gold = sorted({TAG_TO_INTENT[t] for t in c.get("tags", []) if t in TAG_TO_INTENT})
            cases.append({"id": c["id"], "text": c["question"], "gold": gold, "file": name})
    return cases


def run_routers(q: str, tables) -> dict:
    a = route(q, tables)
    ci, cp = classifier.predict(q)
    c = classifier.route_with_classifier(q, tables)
    return {"rules": a.intents, "rules_route": a.route, "clf": [ci] if ci else [], "clf_p": cp,
            "combined": c.intents, "combined_route": c.route}


def evaluate(items: list[dict], tables) -> dict:
    """items: {text, gold:[intents]}; correct if any gold intent is in predicted intents."""
    res = {"n": len(items), "rules": 0, "clf": 0, "combined": 0, "unrouted": 0, "rescued_correct": 0,
           "rescued_wrong": 0, "broken": [], "improved": [], "rows": []}
    for it in items:
        r = run_routers(it["text"], tables)
        gold = set(it["gold"])
        ok = {k: bool(gold & set(r[k])) for k in ("rules", "clf", "combined")}
        for k in ok:
            res[k] += ok[k]
        if r["rules_route"] == "none" or not r["rules"]:
            res["unrouted"] += 1
            if r["combined_route"] == "classifier":
                res["rescued_correct" if ok["combined"] else "rescued_wrong"] += 1
        if ok["rules"] and not ok["combined"]:
            res["broken"].append(it["text"])
        if ok["combined"] and not ok["rules"]:
            res["improved"].append(it["text"])
        res["rows"].append({"text": it["text"], "gold": it["gold"], **r, "ok": ok})
    return res


def confusion(items: list[dict]) -> dict:
    m: dict[str, Counter] = {i: Counter() for i in INTENTS}
    for it in items:
        pred, _ = classifier.predict(it["text"])
        # multi-gold cases: credit the predicted intent if it is one of the golds, else the first gold
        gold = pred if pred in it["gold"] else it["gold"][0]
        m[gold][pred or "None"] += 1
    return {k: dict(v) for k, v in m.items() if v}


def main() -> int:
    tables = load_tables()
    hold = [{"text": r["text"], "gold": [r["intent"]]} for r in load_jsonl(ROOT / "data" / "router_holdout.jsonl")]
    cases = load_cases(tables)
    mapped = [c for c in cases if c["gold"]]
    out = {"classifier_model_loaded": classifier.predict("test")[0] is not None, "threshold": classifier.THRESHOLD,
           "gold_mapping": "golden/redteam tags -> intent; a case is correct if ANY mapped intent is predicted",
           "golden_redteam_total": len(cases), "golden_redteam_mapped": len(mapped)}
    if not out["classifier_model_loaded"]:
        print("classifier model not available; train it first (scripts/train_router.py)")
        return 1
    h = evaluate(hold, tables)
    g = evaluate(mapped, tables)
    out["holdout"] = h
    out["golden_redteam"] = g
    out["holdout_confusion_classifier"] = confusion(hold)
    out["golden_redteam_confusion_classifier"] = confusion(mapped)
    # train/eval leakage check
    train = {r["text"].lower() for r in load_jsonl(ROOT / "data" / "intents.jsonl")}
    out["leak_check"] = {"holdout_in_train": sum(x["text"].lower() in train for x in hold),
                         "golden_redteam_in_train": sum(c["text"].lower() in train for c in cases)}
    (ROOT / "data" / "router_eval.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    for name, r in (("hold-out", h), ("golden/redteam (mapped)", g)):
        n = r["n"]
        print(f"[{name}] n={n}  rules={r['rules']}/{n}  classifier-only={r['clf']}/{n}  rules+classifier={r['combined']}/{n}")
        print(f"   rules could not route: {r['unrouted']}; classifier rescued correct={r['rescued_correct']} wrong={r['rescued_wrong']}; broken={len(r['broken'])}")
    print(f"golden/redteam: {len(mapped)} of {len(cases)} cases mapped to an intent via tags")
    print("classifier confusion on hold-out (gold -> predicted counts):")
    for k, v in out["holdout_confusion_classifier"].items():
        print(f"   {k:18s} {v}")
    print("leak check:", out["leak_check"])
    d = h["combined"] - h["rules"]
    print(f"VERDICT: on the hold-out set rules+classifier {'beats' if d > 0 else 'does not beat'} rules-only by {d} question(s) "
          f"({h['rules']}->{h['combined']} of {h['n']}); broke {len(h['broken'])} question(s) rules got right.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
