import json

import pytest
from fastapi.testclient import TestClient

from triage.api import app

client = TestClient(app)


def test_health_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.parametrize("payload", [{}, {"question": ""}, {"question": " "}, {"question": "x" * 2001}])
def test_ask_validation(payload):
    assert client.post("/ask", json=payload).status_code == 422


def test_unknown_finding_404():
    response = client.get("/findings/does-not-exist")
    if response.status_code == 503:
        pytest.skip("parallel package not built yet")
    assert response.status_code == 404


def test_unknown_whatif_kind_422():
    response = client.post("/whatif", json={"overrides": [{"kind": "nope"}]})
    if response.status_code == 503:
        pytest.skip("parallel package not built yet")
    assert response.status_code == 422


def test_static_page_served():
    response = client.get("/app/")
    assert response.status_code == 200
    assert "<" in response.text


def _built_or_skip(response):
    if response.status_code == 503:
        pytest.skip("parallel package not built yet")
    return response


def test_answer_shape_when_built():
    data = _built_or_skip(client.post("/ask", json={"question": "What happened?", "use_llm": False})).json()
    assert "answer" in data and "structured" in data and "labels" in data["structured"]


def test_report_has_sections_when_built():
    data = _built_or_skip(client.post("/report", json={})).json()
    text = data.get("markdown", "")
    for title in ("Summary", "Timeline", "Affected assets", "Severity", "Confirmed", "Suspected", "Not enough", "Missing", "harmless", "Recommended", "People"):
        assert title.lower() in text.lower()


def test_timeline_has_citations_when_built():
    data = _built_or_skip(client.get("/timeline")).json()
    assert "events" in data
    assert all(e.get("source_file") and (e.get("line") or e.get("row")) for e in data["events"])


def test_incidents_when_built():
    data = _built_or_skip(client.get("/incidents")).json()
    inc = next(i for i in data if i["incident_id"] == "INC-1")
    assert inc["severity"] == "P1"


def test_whatif_when_built():
    data = _built_or_skip(client.post("/whatif", json={"overrides": [{"kind": "severity_cell", "row": "Data exfiltration", "column": "High", "value": "P2"}]})).json()
    assert data["hypothetical"] is True
    by_id = {i["incident_id"]: i for i in data["incidents"]}
    assert by_id["INC-1"]["severity_before"] == "P1"
    assert by_id["INC-1"]["severity_after"] == "P2"
    assert by_id["INC-2"]["severity_after"] == "P2"
    assert by_id["INC-3"]["severity_after"] == "P4"


def test_batch_when_built(tmp_path):
    source = tmp_path / "questions.txt"
    source.write_text("What happened?\n", encoding="utf-8")
    out = tmp_path / "answers.jsonl"
    import triage.batch as batch
    batch.main([str(source), "--no-llm", "--out", str(out)])
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    if rows and "error" in rows[0].get("meta", {}):
        pytest.skip("parallel package not built yet")
    assert len(rows) == 1 and rows[0]["question"] == "What happened?"


def test_entities_non_empty_when_built():
    data = _built_or_skip(client.get("/entities")).json()
    ents = data["entities"]
    assert ents
    kinds = {e["kind"] for e in ents}
    assert {"asset", "user", "session"} <= kinds
    assert all({"id", "kind", "label", "links"} <= set(e) for e in ents)
    assert any(e["id"].startswith("asset:") for e in ents)
    assert any(e["id"].startswith("user:") for e in ents)
    assert any(e["id"].startswith("session:") for e in ents)


def test_slow_ask_times_out_with_504(monkeypatch):
    import time
    import triage.api as api

    def slow_answer(*args, **kwargs):
        time.sleep(3)
        return {"answer": "late"}

    monkeypatch.setattr(api, "_answer", slow_answer)
    monkeypatch.setattr(api, "_load_facts", lambda refresh=False: object())
    monkeypatch.setattr(api.config, "REQUEST_TIMEOUT_S", 0.1)
    started = time.monotonic()
    response = client.post("/ask", json={"question": "What happened?"})
    assert response.status_code == 504
    assert time.monotonic() - started < 1.5
