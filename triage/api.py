"""HTTP API for the triage assistant."""
from __future__ import annotations

import copy
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from contextlib import asynccontextmanager
from threading import RLock
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import config

log = logging.getLogger(__name__)
_facts: Any = None
_facts_lock = RLock()
_last_provider: Optional[str] = None


def _not_built(exc: BaseException) -> HTTPException:
    return HTTPException(status_code=503, detail=f"{type(exc).__name__}: not built yet")


def _load_facts(refresh: bool = False) -> Any:
    global _facts
    with _facts_lock:
        try:
            from triage.facts import get_facts
            if _facts is None or refresh:
                _facts = get_facts(refresh=refresh)
            return _facts
        except (ImportError, NotImplementedError) as exc:
            raise _not_built(exc) from exc


def _dict(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, list):
        return [_dict(x) for x in value]
    if isinstance(value, dict):
        return {k: _dict(v) for k, v in value.items()}
    return value


def _engine_dict(facts: Any) -> dict:
    return _dict(facts.engine.to_dict())


_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="triage-request")


def _run_with_timeout(fn, *args, **kwargs):
    # Module-level executor: a timed-out call keeps running in its worker but
    # the request returns 504 immediately instead of waiting for it.
    future = _executor.submit(fn, *args, **kwargs)
    try:
        return future.result(timeout=config.REQUEST_TIMEOUT_S)
    except FutureTimeout as exc:
        future.cancel()
        raise HTTPException(status_code=504, detail="request timed out") from exc
    except NotImplementedError as exc:
        raise _not_built(exc) from exc


class AskBody(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000)
    use_llm: Optional[bool] = None


class ReportBody(BaseModel):
    incident_id: Optional[str] = None


class WhatIfBody(BaseModel):
    overrides: list[dict] = Field(default_factory=list)


def _answer(question: str, use_llm: Optional[bool], facts: Any):
    from triage.answer.pipeline import answer
    try:
        result = answer(question, facts=facts, use_llm=use_llm)
    except TypeError:
        try:
            result = answer(question, facts=facts)
        except TypeError:
            result = answer(question)
    global _last_provider
    data = _dict(result)
    _last_provider = (data.get("meta") or {}).get("provider")
    return data


@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        _load_facts()
    except Exception:
        log.exception("fact store warm-up failed")
    yield


app = FastAPI(title="Triage Assistant", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"])


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError):
    return JSONResponse({"error": "invalid request", "detail": str(exc)}, status_code=422)


@app.exception_handler(StarletteHTTPException)
async def http_error(_: Request, exc: StarletteHTTPException):
    return JSONResponse({"error": str(exc.detail), "detail": str(exc.detail)}, status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    log.exception("unhandled API error")
    return JSONResponse({"error": "internal server error", "detail": str(exc)}, status_code=500)


@app.get("/health")
def health() -> dict:
    try:
        facts = _load_facts()
        fact_hash = getattr(facts, "hash", None)
        built = getattr(facts, "built_at", None)
    except HTTPException:
        fact_hash = built = None
    try:
        from triage.llm.pool import pool_status
        pool = pool_status()
    except (ImportError, NotImplementedError):
        pool = None
    return {"status": "ok", "facts_hash": fact_hash, "facts_built_at": _dict(built), "last_provider": _last_provider, "llm_enabled": config.LLM_ENABLED, "pool": pool}


@app.post("/ask")
def ask(body: AskBody):
    if not body.question.strip():
        raise HTTPException(422, "question must not be empty")
    return _run_with_timeout(_answer, body.question.strip(), body.use_llm, _load_facts())


def _make_report(facts, incident_id=None):
    try:
        from triage.report import build_report, render_markdown
        report = _dict(build_report(facts=facts, incident_id=incident_id))
        report["markdown"] = render_markdown(report)
        return report
    except (ImportError, NotImplementedError) as exc:
        raise _not_built(exc) from exc


@app.post("/report")
def report(body: ReportBody = ReportBody()):
    return _make_report(_load_facts(), body.incident_id)


@app.get("/report.md", response_class=PlainTextResponse)
def report_markdown():
    return _make_report(_load_facts()).get("markdown", "")


@app.get("/timeline")
def timeline(incident: Optional[str] = None, from_: Optional[str] = Query(None, alias="from"), to: Optional[str] = None):
    facts = _load_facts()
    return {"events": _dict(facts.timeline(incident_id=incident, from_utc=from_, to_utc=to)), "gaps": _dict(facts.gaps())}


@app.get("/incidents")
def incidents():
    data = _engine_dict(_load_facts())
    return data.get("incidents", []) + data.get("anomalies", [])


@app.get("/incidents/{incident_id}")
def incident(incident_id: str):
    result = _load_facts().incident_dict(incident_id)
    if result is None:
        raise HTTPException(404, "unknown incident")
    return _dict(result)


@app.get("/findings")
def findings():
    return _engine_dict(_load_facts()).get("findings", [])


@app.get("/findings/{finding_id}")
def finding(finding_id: str):
    result = _load_facts().finding(finding_id)
    if result is None:
        raise HTTPException(404, "unknown finding")
    return _dict(result)


@app.get("/entities")
def entities():
    facts = _load_facts()
    graph = facts.graph
    links_by_node: dict = {}
    for link in graph.links:
        for node in {link.a, link.b}:
            links_by_node.setdefault(node, []).append(link.to_dict())
    labels: dict = {}
    for a in facts.tables.inventory:
        labels[f"asset:{a.tag}"] = f"{a.hostname} ({a.type})"
    for u in facts.tables.users:
        labels[f"user:{u.username}"] = u.full_name or u.username
    items = []
    seen = set()
    for node, data in graph.g.nodes(data=True):
        kind = data.get("type")
        if kind not in ("asset", "user", "session", "ext_ip"):
            continue
        seen.add(node)
        items.append({"id": node, "kind": kind, "label": labels.get(node, data.get("label", node)), "links": links_by_node.get(node, [])})
    for node, label in labels.items():
        if node not in seen:
            items.append({"id": node, "kind": node.split(":", 1)[0], "label": label, "links": links_by_node.get(node, [])})
    return {"entities": items}


@app.get("/resolve")
def resolve(identifier: str = Query(...), at: Optional[str] = None):
    chain = _load_facts().graph.resolve(identifier, at_utc=at)
    if chain is None:
        raise HTTPException(404, "entity not found")
    return _dict(chain)


@app.get("/facts")
def facts():
    return _dict(_load_facts().to_dict())


@app.get("/graph")
def graph(incident: Optional[str] = None):
    value = _dict(_load_facts().graph.to_json())
    if incident:
        value["incident"] = incident
    return value


def _apply_override(tables: Any, override: dict, rules: Optional[dict] = None) -> dict:
    kind = override.get("kind")
    if kind == "severity_cell":
        row, column, value = override.get("row"), override.get("column"), override.get("value")
        actual = tables.matrix.match_row(row) or row
        before = tables.matrix.cells[actual][column]
        tables.matrix.cells[actual][column] = value
        return {"what": f"severity matrix {actual}/{column}", "before": before, "after": value, "note": "hypothetical matrix cell"}
    if kind == "change_status":
        change = next((c for c in tables.changes if c.change_id == override.get("change_id")), None)
        if change is None:
            raise HTTPException(422, "unknown change_id")
        before = change.status
        change.status = override.get("status", before)
        change.is_effective = not any(x in change.status.lower() for x in ("postponed", "not performed", "cancel"))
        return {"what": f"change {change.change_id} status", "before": before, "after": change.status, "note": "hypothetical calendar row"}
    if kind == "rule_param":
        rule, param, value = override.get("rule"), override.get("param"), override.get("value")
        if not isinstance(rules, dict) or rule not in rules or not isinstance(rules[rule], dict):
            raise HTTPException(422, "unknown rule")
        if param not in rules[rule]:
            raise HTTPException(422, "unknown rule parameter")
        before = rules[rule][param]
        rules[rule][param] = value
        return {"what": f"rule {rule}.{param}", "before": before, "after": value, "note": "hypothetical rule parameter"}
    raise HTTPException(422, f"unknown override kind: {kind}")


@app.post("/whatif")
def whatif(body: WhatIfBody):
    facts = _load_facts()
    try:
        from triage.rules.engine import build_incidents
    except (ImportError, NotImplementedError) as exc:
        raise _not_built(exc) from exc
    tables = copy.deepcopy(facts.tables)
    rules = None
    if any(o.get("kind") == "rule_param" for o in body.overrides):
        try:
            from triage.rules.detectors import load_rules
            rules = copy.deepcopy(load_rules())
        except (ImportError, NotImplementedError) as exc:
            raise _not_built(exc) from exc
    diff = [_apply_override(tables, o, rules) for o in body.overrides]
    result = build_incidents(copy.deepcopy(facts.graph), copy.deepcopy(facts.events), tables, copy.deepcopy(facts.coverage), rules=rules)
    real, hypothetical = _engine_dict(facts), _dict(result.to_dict())
    def incident_id(item):
        return item.get("incident_id", item.get("id"))

    def incident_severity(item):
        value = item.get("severity")
        if isinstance(value, dict):
            return value.get("value", value.get("severity"))
        return value

    before = {incident_id(i): incident_severity(i) for i in real.get("incidents", []) if incident_id(i)}
    after = {incident_id(i): incident_severity(i) for i in hypothetical.get("incidents", []) if incident_id(i)}
    all_ids = list(dict.fromkeys([*before.keys(), *after.keys()]))
    changes = [{"incident_id": k, "severity_before": before.get(k), "severity_after": after.get(k)} for k in all_ids]
    return {"hypothetical": True, "overrides": body.overrides, "diff": diff, "incidents": changes, "harmless_before": real.get("harmless", []), "harmless_after": hypothetical.get("harmless", [])}


@app.post("/reload")
def reload_facts():
    return _dict(_load_facts(refresh=True).to_dict())


@app.get("/")
def root():
    return RedirectResponse("/app/")


_web = config.REPO_ROOT / "web"
if _web.exists():
    app.mount("/app", StaticFiles(directory=str(_web), html=True), name="web")
