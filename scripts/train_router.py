"""Train the A5 intent classifier (TF-IDF word+char n-grams + logistic regression)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "intents.jsonl"
MODEL = ROOT / "data" / "router_model.joblib"
SEED = 7


def build_pipeline():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline

    feats = FeatureUnion([
        ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), lowercase=True, sublinear_tf=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), lowercase=True, sublinear_tf=True)),
    ])
    return Pipeline([("tfidf", feats), ("lr", LogisticRegression(C=10.0, max_iter=2000, random_state=SEED))])


def main() -> int:
    import joblib
    from sklearn.model_selection import StratifiedKFold, cross_val_score

    rows = [json.loads(line) for line in DATA.read_text(encoding="utf-8").splitlines() if line.strip()]
    X = [r["text"] for r in rows]
    y = [r["intent"] for r in rows]
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    scores = cross_val_score(build_pipeline(), X, y, cv=cv, scoring="accuracy")
    print(f"rows={len(rows)} classes={len(set(y))}")
    print(f"5-fold CV accuracy: {scores.mean():.3f} (+/- {scores.std():.3f}) folds={[round(s, 3) for s in scores]}")
    print("note: CV on templated data is optimistic; see eval_router.py for the hand-written hold-out.")
    model = build_pipeline().fit(X, y)
    joblib.dump(model, MODEL, compress=3)
    print(f"saved {MODEL} ({MODEL.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
