# MVP build plan (parallel work packages)

Each package is sized for one agent. Give the agent this file, `ARCHITECTURE.md`, `GROUND_TRUTH.md` and its package ID.

## Rules for every agent

- Write only inside the files your package owns. Never edit `problem_c_data/`.
- Import contracts from `triage/models.py`. Do not change a contract without telling the others.
- No knowledge from outside the 20 files. No hardcoded answers: every value comes from parsing the data.
- Keys come from `.env`. Never commit one.
- Every package ships its own unit tests. `make test` must pass before a push.
- Commit small, with a message that says what changed. Commit history is scored.
- All code is written fresh in this repo during the session. Ideas from past projects are fine, their code is not.

## Wave 0: one agent, blocks everything else

### P0 Scaffold and contracts
- **Owns:** `triage/models.py`, `triage/config.py`, `Makefile`, `requirements.txt`, `.gitignore`, `.env.example`, `Dockerfile`, `docker-compose.yml`, empty package folders.
- **Does:** dataclasses for Event, Cite, Link, Gap, Finding, Incident, Answer exactly as in ARCHITECTURE section 5. Stub function signatures for every interface listed below so other agents can import them.
- **Done when:** `make test` runs, `uvicorn triage.api:app` starts, `GET /health` returns ok, first deploy is live.

## Wave 1: five agents in parallel (depend only on P0)

### P1 Log parsers
- **Owns:** `triage/parsers/logs.py`, `triage/profiles/*.yaml`, `tests/test_parsers.py`.
- **Does:** profile-driven parser for files 11, 12, 13, 14, 15, 16, 19. Reads time zone and start/close meaning from file 20 (via P2's coverage loader, or a local read until P2 lands). Computes `ts_utc` and `ts_end_utc`. Generic `key=value` fallback for unprofiled lines.
- **Interface:** `parse_all(data_dir) -> list[Event]`.
- **Done when:** these pass.
  - f15 L6 gives start 06:03:12Z, end 06:21:19Z.
  - f15 L14 gives start 17:31:05Z, end 18:24:12Z.
  - f13 L9 gives 06:06:02Z, status 200, size 48213.
  - f14 L8 gives 04:19:40Z with no zone in the raw line.
  - f16 L2 gives 04:12:07Z.
  - Line numbers start at the first line inside the code block.
  - Event counts per file: 11 has 12, 12 has 13, 13 has 13, 14 has 12, 15 has 14, 16 has 6, 19 has 4.

### P2 Table loaders and coverage
- **Owns:** `triage/parsers/tables.py`, `triage/parsers/coverage.py`, `tests/test_tables.py`.
- **Does:** generic Markdown table reader, then typed loaders for 02, 03, 04, 05, 06 to 10, 17, 18, 20. Change calendar windows converted from PKT to UTC. Coverage gaps and missing sources as Gap records.
- **Interface:** `load_inventory()`, `load_matrix()`, `load_escalation()`, `load_changes()`, `load_runbooks()`, `load_alerts()`, `load_users()`, `load_coverage()`, `observable(source, t_utc) -> bool`, `gaps_overlapping(from_utc, to_utc) -> list[Gap]`.
- **Done when:** these pass.
  - Matrix lookup ("Data exfiltration", "High") is P1.
  - CHG-2026-1104-03 window is 17:00 to 18:30 UTC.
  - `observable("15_firewall_internal_log.md", 06:42:17Z)` is false.
  - `observable("12_windows_dc_auth_log.md", 02:58:41Z)` is false.
  - Four non-collected sources are returned.
  - RB-CRED-02 has 8 steps, RB-EXFIL-04 has 6.

### P3 LLM pool
- **Owns:** `triage/llm/pool.py`, `triage/llm/cache.py`, `tests/test_llm_pool.py`.
- **Does:** the fallback loop in ARCHITECTURE section 9.2. Gemini key pool, then Groq key pool, then OpenRouter. Per-key cooldown, backoff with jitter, circuit breaker, disk cache, event log.
- **Interface:** `complete(system, user, json_mode=False) -> LLMResult | None`, `pool_status() -> dict`.
- **Done when:** tests with fake providers show: a 429 moves to the next key, all Gemini keys failing moves to Groq, everything failing returns None, a repeated prompt hits the cache with zero calls.

### P4 Frontend
- **Owns:** `web/*`.
- **Does:** one static page. Chat box, report view, timeline table (each row shows file and line), "closed as harmless" panel, "missing log sources" panel, a "why?" expander that shows a finding's steps. Builds against a mock JSON file shaped like the Answer and Incident contracts until the API lands.
- **Done when:** the page renders the mock data and switches to the live API by changing one base URL.

### P5 Tests from ground truth
- **Owns:** `tests/golden.yaml`, `tests/redteam.yaml`, `tests/test_golden.py`, `scripts/eval.py`.
- **Does:** 40 or more golden cases and 15 or more red-team cases from `GROUND_TRUTH.md`. Each case checks facts in `structured` (severity, IDs, citations, labels), not wording. `eval.py` runs both sets against a live endpoint and prints a score.
- **Done when:** the runner works against a stub endpoint and reports failures clearly.

## Wave 2: two agents in parallel (need P1 and P2)

### P6 Evidence graph
- **Owns:** `triage/graph/*`, `tests/test_graph.py`.
- **Does:** build the graph, identity links with validity windows, resolution chains, clustering over actor links only (ARCHITECTURE section 7).
- **Interface:** `build_graph(events, tables) -> Graph`, `resolve(identifier, at_utc=None) -> Chain`, `touched(entity, from_utc, to_utc) -> list[Event]`, `cluster(findings) -> list[Incident]`.
- **Done when:** these pass.
  - `resolve("10.10.3.45", 06:10Z)` returns amalik with the chain through VS-20433.
  - `resolve("10.10.3.45", 09:00Z)` returns no user.
  - `resolve("FS01.orbit.local")` returns A-1005.
  - `resolve("203.0.113.10")` returns SRV-WEB01.
  - `resolve("10.20.5.22", 03:55Z)` returns LT-FIN-022 from the inventory row.
  - Clustering yields INC-1, INC-2, INC-3 as three separate incidents and keeps the utariq anomaly out of INC-1.

### P7 Rule engine
- **Owns:** `triage/rules/*`, `triage/rules.yaml`, `tests/test_rules.py`.
- **Does:** every rule in ARCHITECTURE section 8. Each returns Findings with label, evidence and steps. Parameters come from `rules.yaml`.
- **Interface:** `run_rules(graph, events, tables, coverage) -> list[Finding]`, `severity(incident) -> (str, steps)`, `escalation(severity, incident) -> list`, `actions(incident) -> list`.
- **Done when:** these pass.
  - ALT-9006 and ALT-9007 are harmless with the right change IDs.
  - CHG-2026-1104-05 and CHG-2026-1105-01 approve nothing.
  - MFA fatigue fires for amalik only.
  - Click seen for amalik only.
  - Concurrent use: suspected for utariq, suspected (weaker, no activity shown) for amalik, nothing for braza.
  - SQLi success is suspected, not confirmed.
  - Severities: INC-1 P1, INC-2 P2, INC-3 P4.
  - P1 escalation returns four people including Legal and Saima Noor.
  - Every action carries a real runbook ID and step.

## Wave 3: three agents in parallel (need P6 and P7)

### P8 Fact store and report
- **Owns:** `triage/facts.py`, `triage/report.py`, `tests/test_report.py`.
- **Does:** build `facts.json` at startup, keyed by a hash of the input files. Generate the incident report in the exact rule 7 section order, Markdown and JSON, with no LLM call.
- **Done when:** the report has all 11 sections in order, every timeline row has a file and line, and the content matches `GROUND_TRUTH.md`.

### P9 Answer pipeline
- **Owns:** `triage/answer/*`, `triage/llm/prompts.py`, `tests/test_answer.py`.
- **Does:** routing ladder, fact bundles, anonymizer, phrasing prompt, validators, template answers (ARCHITECTURE section 9). The template path must work with P3 returning None.
- **Interface:** `answer(question) -> Answer`.
- **Done when:** golden and red-team sets pass with the LLM disabled, then again with it enabled. An injected question does not change any label. An answer asserting data theft is rejected by the validator, and "stolen password" is allowed.

### P10 API and batch
- **Owns:** `triage/api.py`, `triage/batch.py`, `tests/test_api.py`.
- **Does:** every endpoint in ARCHITECTURE section 10, CORS, error handling, request timeouts. Batch CLI.
- **Done when:** all endpoints return the contract shapes and `scripts/eval.py` runs against it.

## Wave 4: finish

### P11 Deploy, README, video
- **Owns:** `README.md`, deploy config.
- **Does:** live link, working `docker-compose up`, README with: what it does, architecture diagram, why facts in code, time zone table, one worked entity chain, labelling rules, severity method, fallback handling, how to run, API reference, test and eval scores, red-team questions and results, known failure cases, limits.
- **Done when:** a clean clone runs with `docker-compose up` and the live link answers a question.

## Dependency map

```
P0 -> P1, P2, P3, P4, P5
P1 + P2 -> P6, P7
P6 + P7 -> P8, P9 (also needs P3), P10
P8 + P9 + P10 -> P11
```

## Checkpoints

- **After wave 1:** a clean UTC timeline with file and line for every event. If this is not true, stop adding and fix it.
- **After wave 2:** three incidents with correct severities and two alerts closed as harmless.
- **After wave 3:** golden and red-team pass with the LLM off.

## If time runs short, cut in this order

1. Graph view in the UI.
2. Trained intent router (ADDONS A5).
3. Batch CLI.
4. Anonymizer (keep the injection defences).

Never cut: parsers, graph, rules, report, `/ask` with the template path, validators, deploy.
