# Add-ons (after the core passes golden and red-team tests)

Each section stands alone. Hand one section plus `ARCHITECTURE.md` to one agent. Time-box each to 20 minutes. None of them may change a label, a severity or a citation decided by the core.

Suggested order: A5, A2, A3, A4, A6, A1, A7, A8.

---

## A1 LLM-drafted source profiles

**What:** for a log file with no profile, the LLM sees the header and five sample lines and proposes a profile YAML (regex, field names, timestamp format, zone).

**Why judges care:** answers "what if the schema changes?" without letting the LLM read the logs for facts.

**How:**
- `triage/parsers/draft_profile.py`: `draft(file_path) -> ProfileCandidate`.
- Code accepts the candidate only if all of these hold: the regex matches every line in the code block, every timestamp parses, every time falls inside that source's coverage window, and required fields (time, at least one entity) are present.
- Accepted profiles are written to `profiles/drafted/` and marked `drafted: true`. Findings built on them carry that flag.
- Rejected: the file is reported under "Missing log sources" as "present but unparsed".

**Cons:** sample lines go to the LLM, so run them through the anonymizer first. A regex that matches every line can still name a field wrongly. The `drafted` flag keeps that visible.

**Done when:** deleting one profile and running the drafter reproduces the same events for that file.

---

## A2 "Why?" trace view

**What:** every finding, severity and entity match in the UI expands into its numbered steps, with each step linking to the file and line.

**How:** `GET /findings/{id}` returns the Finding. The page renders `steps` and `evidence`, and shows the raw line on click (from `GET /facts`).

**Cons:** none for scoring. Pure UI work.

**Done when:** clicking INC-1's P1 badge shows the six severity steps from `GROUND_TRUTH.md`.

---

## A3 Graph view

**What:** the evidence graph drawn in the browser. Direct links solid, inferred links dashed, each incident a colour, approved activity grey.

**How:** `GET /graph` returns nodes and edges as JSON. Use one small client-side library loaded from a CDN. Clicking an edge shows its evidence and validity window. A time slider filters edges by validity.

**Cons:** the full graph is noisy. Default to one incident at a time.

**Done when:** the INC-1 view shows the path from 198.51.100.77 through VS-20433 and 10.10.3.45 to SRV-FS01.

---

## A4 What-if policy editor

**What:** edit a severity matrix cell, a rule parameter or a change-calendar row in the UI and watch severities and labels recompute.

**Why judges care:** live proof that policies are data.

**How:** `POST /whatif {overrides}` rebuilds findings in memory with the overrides applied and returns a diff against the real fact store. Nothing is written to `problem_c_data/`. The response is marked `hypothetical: true` and never cached as a real answer.

**Cons:** a judge may confuse a what-if result with the real one. Keep a banner on screen while overrides are active.

**Done when:** changing CHG-2026-1104-05 from postponed to approved still does not approve the Romanian VPN login (wrong actor), and changing ("Data exfiltration", "High") to P2 makes INC-1 P2.

---

## A5 Trained intent router (built in-session)

**What:** a small classifier that maps a question to intents, used as step 2 of the routing ladder.

**How:**
1. `scripts/gen_intents.py`: ask the LLM for 30 to 50 paraphrases per intent, including typos, Roman Urdu mixes, and questions that name things by IP, hostname, tag or full name. Fixed seed. Save to `data/intents.jsonl`.
2. `scripts/train_router.py`: TF-IDF (word and character n-grams) plus logistic regression in scikit-learn. Save the model.
3. Hold out 30 to 40 hand-written questions. Report accuracy and a confusion matrix in the README.
4. Runtime: use the classifier when top probability is 0.6 or higher, otherwise fall through to LLM classification.

**Cons:**
- It learns from LLM-written paraphrases, so real phrasing may differ.
- It predicts one intent. Multi-part questions still need the rule layer to add intents by keyword.
- scikit-learn may be too heavy for a serverless host. If so, run it only in Docker and local mode.
- Commit the generator, dataset, training script and eval output so history shows it was trained during the session.

**Done when:** held-out accuracy is reported and the routing ladder logs which step answered each golden question.

---

## A6 Lookalike domain and outlier signals

**What:** two cheap, explainable signals shown next to the rule findings.

- **Lookalike domain:** edit distance and confusable characters between each sender domain and the company domain from the user directory. `orbit-logistlcs.example` vs `orbitlogistics.example` is flagged.
- **Transfer outlier:** median and MAD across internal firewall sessions. The 2.4 GB session scores far above the rest.

**How:** `triage/rules/signals.py`, each returning `(score, explanation)`. Shown in the UI and the report's Summary as supporting signals.

**Cons:** with about 14 sessions the statistics are thin. They support a rule finding and never set a label.

**Done when:** both signals appear on INC-1 with their explanation strings.

---

## A7 Report export and analyst handoff

**What:** download the incident report as Markdown and PDF, plus a per-person notification sheet (who, how, by when) with deadlines computed from the first alert time.

**How:** `GET /report.md`, `GET /report.pdf`. Deadlines shown with the stated assumption that the clock starts at the first IDS alert of the incident.

**Cons:** the clock-start assumption is ours. Print it on the sheet.

**Done when:** the exported report has the 11 rule 7 sections in order.

---

## A8 Upload a different data pack

**What:** point the app at another folder with the same kinds of files and rebuild the fact store.

**How:** `POST /load {path or zip}` rebuilds into a separate fact store keyed by the input hash. Unprofiled files go through A1 if it is built, otherwise they are listed as unparsed.

**Cons:** the detectors assume the entity kinds in this pack. A pack with new log types will parse but may produce few findings. Say so in the UI.

**Done when:** loading a copy of `problem_c_data/` with one severity cell changed gives a different severity with no code change.
