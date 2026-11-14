import io
import shutil
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from triage import config
from triage import packs


DATA = Path(__file__).parents[1] / "problem_c_data"


def _copy(tmp_path, name="pack"):
    target = tmp_path / name
    shutil.copytree(DATA, target)
    return target


def _zip(root):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        for path in root.glob("*.md"):
            zf.writestr(path.name, path.read_bytes())
    return out.getvalue()


def _changed_pack(tmp_path):
    root = _copy(tmp_path)
    path = root / "03_severity_matrix.md"
    text = path.read_text(encoding="utf-8")
    text = text.replace("| Data exfiltration (large transfer, confirmed or suspected) | P3 | P2 | P1 | P1 |",
                        "| Data exfiltration (large transfer, confirmed or suspected) | P3 | P2 | P2 | P1 |")
    path.write_text(text, encoding="utf-8")
    return root


def test_changed_matrix_pack_changes_incident_without_code_change(tmp_path):
    default = packs.get_pack(packs.list_packs()[0].facts_hash)
    loaded = packs.load_pack(_changed_pack(tmp_path))
    assert loaded.facts_hash != default.facts_hash
    assert loaded.facts.incident_severity("INC-1") != default.facts.incident_severity("INC-1")
    packs.activate(default.facts_hash)


def test_zip_round_trip(tmp_path):
    loaded = packs.load_pack(_zip(_copy(tmp_path, "zip-pack")))
    assert loaded.files
    assert loaded.facts.hash == packs.load_pack(_copy(tmp_path, "directory-pack")).facts.hash
    packs.activate(next(p for p in packs.list_packs() if p.is_default).facts_hash)


def test_zip_traversal_is_rejected(tmp_path):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("../escape.md", "not safe")
    with pytest.raises(ValueError, match="unsafe"):
        packs.load_pack(out.getvalue())


def test_broken_pack_does_not_change_active_store(tmp_path):
    before = packs.current_facts()
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "01_company_security_rules.md").write_text("broken", encoding="utf-8")
    with pytest.raises(ValueError, match="could not build"):
        packs.load_pack(broken)
    assert packs.current_facts() is before


def test_default_hash_can_be_reactivated_after_loading(tmp_path):
    default = next(p for p in packs.list_packs() if p.is_default)
    original_hash = default.facts_hash
    packs.load_pack(_changed_pack(tmp_path))
    packs.activate(original_hash)
    assert packs.current_facts().hash == original_hash
    assert next(p for p in packs.list_packs() if p.is_default).facts_hash == original_hash


def test_pack_api_routes(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "REPO_ROOT", tmp_path)
    root = _changed_pack(tmp_path)
    # The route's path policy is server-side-root based; the test uses a
    # temporary root so it never writes to the checked-in data pack.
    from triage.api import app
    response = TestClient(app).post("/load", json={"path": str(root)})
    assert response.status_code == 200
    body = response.json()
    assert body["active"] is True and body["facts_hash"]
    assert any(i["incident_id"] == "INC-1" for i in body["incidents"])
    listed = TestClient(app).get("/packs")
    assert listed.status_code == 200
    assert any(p["facts_hash"] == body["facts_hash"] for p in listed.json()["packs"])
    assert TestClient(app).post(f"/packs/{body['facts_hash']}/activate").status_code == 200
