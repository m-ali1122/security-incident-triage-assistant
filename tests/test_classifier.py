import pytest

pytest.importorskip("sklearn")
pytest.importorskip("joblib")

from triage.answer import classifier  # noqa: E402
from triage.answer.router import route  # noqa: E402

pytestmark = pytest.mark.skipif(not classifier.MODEL_PATH.exists(), reason="router model not trained")


def test_model_loads():
    intent, p = classifier.predict("who needs to be informed about the incident")
    assert intent is not None and 0.0 < p <= 1.0


def test_predictions_deterministic():
    q = "kya hua, poora report do"
    assert classifier.predict(q) == classifier.predict(q)


def test_empty_question_returns_none():
    assert classifier.predict("   ") == (None, 0.0)


@pytest.mark.parametrize("q", [
    "Who owns 10.10.3.45?",
    "Should we wipe and reboot SRV-FS01 right now?",
    "Was finance data stolen from the file server?",
    "What time did the big transfer start?",
])
def test_fallback_never_overrides_rules(q):
    base = route(q)
    assert base.route == "rules"
    out = classifier.route_with_classifier(q)
    assert out.route == "rules"
    assert out.intents == base.intents


def test_fallback_marks_classifier_route(monkeypatch):
    monkeypatch.setattr(classifier, "predict", lambda q: ("report", 0.9))
    r = classifier.route_with_classifier("zzzz qqqq")
    if route("zzzz qqqq").route == "none":
        assert r.route == "classifier" and r.intents == ["report"]


def test_low_probability_not_used(monkeypatch):
    monkeypatch.setattr(classifier, "predict", lambda q: ("report", 0.3))
    assert classifier.route_with_classifier("zzzz qqqq").route == route("zzzz qqqq").route
