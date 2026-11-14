"""Optional trained intent classifier (add-on A5), step 2 of the routing ladder.

Works without scikit-learn or the model file: predict() then returns (None, 0.0).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from triage.answer.router import Route, route

MODEL_PATH = Path(__file__).resolve().parents[2] / "data" / "router_model.joblib"
THRESHOLD = 0.6
_MODEL: Any = None
_TRIED = False


def _load() -> Any:
    global _MODEL, _TRIED
    if _TRIED:
        return _MODEL
    _TRIED = True
    try:
        import joblib
        if MODEL_PATH.exists():
            _MODEL = joblib.load(MODEL_PATH)
    except Exception:
        _MODEL = None
    return _MODEL


def predict(question: str) -> tuple[str | None, float]:
    model = _load()
    if model is None or not (question or "").strip():
        return None, 0.0
    try:
        probs = model.predict_proba([question])[0]
        i = int(probs.argmax())
        return str(model.classes_[i]), float(probs[i])
    except Exception:
        return None, 0.0


def route_with_classifier(question: str, tables: Any = None) -> Route:
    """Integrated router: rules first, this classifier as a second opinion (see router.route)."""
    return route(question, tables, use_classifier=True)
