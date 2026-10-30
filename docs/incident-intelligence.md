# Cyvanta incident intelligence — engineering handoff

## 1. Repository findings and baseline

The application uses Flask, vanilla HTML/CSS/JavaScript, and Chart.js for the existing overview charts. Its entry points are `app.py`, `templates/index.html`, and `static/script.js`. `window.CyvantaAnalysis` shares the completed upload across overview, alerts, and investigation results. Existing flow inspection uses the `alertDrawer` dialog.

The existing `ml/pipeline.py` loads the saved eight-column `SimpleImputer`/Isolation Forest pipeline and the calibrated anomaly-severity policy. The authoritative cutoff remains **-0.04045090522184547**, with deviation `max(0, cutoff - decision_score)`. The required model fields, feature order, input validation, original prediction/score meanings, severity thresholds, and model files are unchanged by this expansion. See [anomaly severity](anomaly-severity.md) for the original model contract.

At the start of this task, 24 Python tests and 10 JavaScript tests passed. The preceding severity implementation was uncommitted; those changes were preserved. There was no AI provider, incident database, or timeline implementation in this checkout. The brief's assertion that a timeline already existed did not match the source. A timeline was therefore added inside the existing investigation area; no existing timeline was replaced.

## 2. Implemented feature groups

**Explanation, summaries, and reports.** Selected anomalous flows can request AI explanations, executive/technical incident summaries, and a real downloadable printable HTML report. The UI and reports distinguish measured evidence from AI interpretation and hypotheses. Feature comparisons use actual input values and saved benign-training imputer medians; these are descriptive comparisons, not causal feature attribution. Exact feature attribution remains unavailable. Reports retain factual evidence, notes, status, and recorded recommendation history if AI is not configured or fails.

**Defensive recommendations.** On-demand AI suggestions include category, triage priority, rationale, supporting event IDs, prerequisites, expected benefit, and operational caution. Analysts can record suggested/reviewed/planned/recorded-completed states and notes. Recorded completion is explicitly **not technically verified**. No infrastructure actions, firewall changes, host isolation, commands, or external security integrations execute.

**Timeline and correlation.** A deterministic backend groups anomalies only when all members share a valid source or destination address in the same role and fit within a fixed window anchored at the first event. The default window is 300 seconds. This avoids unbounded chains and port/protocol-only groupings. Each record remains individually traceable. Missing or unnormalizable traffic times retain source-row order and cannot establish chronology. Optional AI interpretation explains these established relationships without adding unseen events or attack stages. MITRE technique mapping is explicitly unsupported by this telemetry.

**Investigation workspace.** The existing Investigation Results section now provides selected/saved analysis access, incident selection, evidence exploration, timeline selection, correlation reasons, AI insights and questions, notes/status/conclusion editing, recommendation reviews, and reports. Saved snapshots can be reopened after page reload without reuploading. Existing overview metrics, charts, filters, tables, exports, alert priority, and navigation remain available.

## 3. Files changed

| File | Purpose |
| --- | --- |
| `app.py` | Save an optional investigation snapshot after successful inference; register additive routes |
| `incident_evidence.py` | Normalize actual evidence, descriptive baselines, timestamps, aggregate counts, fixed-window correlations |
| `incident_store.py` | SQLite snapshots, ownership, retention, notes, revisions, recommendation history, AI cache, chat history |
| `incident_routes.py` | Evidence, pagination, saved analyses, metadata validation, session setup |
| `incident_ai.py` | Server-only provider adapter, context bounds, validation, caching, rate/concurrency guards, factual queries |
| `incident_prompts.py` | Shared grounding instructions, task prompts, and strict output schema |
| `incident_ai_routes.py` | ID-based AI and HTML attachment routes; safe errors |
| `incident_reports.py` | Escaped, standalone, printable evidence reports and factual fallback |
| `templates/index.html` | Add workspace controls and flow-drawer actions using existing components |
| `static/investigation.js` | Workspace API/state, evidence/timeline interactions, AI, editing, and report download |
| `static/investigation-data.js` | Testable display/reference/stale-response helpers |
| `static/investigation.css` | Scoped light-theme and responsive styles for new components |
| `static/script.js`, `static/alerts.js` | Small shared-state/inspection integration hooks; existing chart styling preserved |
| `.env.example`, `.gitignore` | Placeholder configuration and ignored local secrets/evidence |
| `tests/test_incidents.py` | Correlation, storage, ownership, metadata, and API checks |
| `tests/test_incident_ai.py`, `tests/test_incident_reports.py` | Provider failures, schema/grounding, cache/chat, report checks |
| `tests/test_incident_workflow.py`, `tests/fixtures/incident_flows.csv` | Cross-feature real saved-model upload checks; isolated synthetic test fixture |
| `tests/investigation.test.js` | Frontend evidence/timeline/request-isolation helpers |

There is no new production package dependency, frontend framework, model fitting, or replacement model.

## 4. API, evidence, and persistence contracts

Existing `GET /`, `GET /api/health`, and `POST /api/analyze` retain their methods, accepted uploads, and existing response keys. Analysis adds optional `investigation: {status, analysis_id, incident_count?, reason?, policy?}`. A snapshot failure reports `unavailable` while returning the successful original model analysis. Uploads never call the LLM.

| Additive endpoint | Contract |
| --- | --- |
| `GET /api/investigations/analyses` | This browser's retained analyses and storage policy |
| `GET /api/investigations/analyses/<analysis_id>/incidents` | Paginated incident summaries; optional `event_id` lookup |
| `GET /api/investigations/incidents/<incident_id>` | Authoritative detail, paginated evidence, aggregates, correlation/timeline policy, current metadata and insight cache |
| `GET /api/investigations/incidents/<incident_id>/events/<event_id>` | An actual event belonging to the selected incident |
| `PATCH /api/investigations/incidents/<incident_id>` | JSON `revision` plus bounded `notes`, `status`, `conclusion`, or `recommendation_states` |
| `GET /api/ai/status` | Safe availability/model information; no key or credential values |
| `POST /api/investigations/incidents/<incident_id>/ai` | JSON `task`, optional `event_id`, `question` for chat, and boolean `regenerate` |
| `POST /api/investigations/incidents/<incident_id>/report` | JSON `format: "html"`, optional boolean `include_ai`; actual HTML attachment |

AI tasks are `explain`, `summary`, `recommendations`, `timeline`, `chat`, and report narrative generation. The frontend never supplies authoritative event objects to these routes. All context is fetched from the server-owned snapshot after browser-session ownership checks. Invalid requests, unknown/expired/wrong-owner records, optimistic-lock conflicts, unavailable AI, rate limits, and timeouts return explicit JSON errors with suitable HTTP statuses.

Event IDs are the actual existing analysis-specific alert IDs. Incident IDs bind the analysis to their constituent event IDs, so a new upload cannot accidentally reuse the prior incident's notes. Canonical evidence includes record index, actual predictions/scores/severity, normalized available network fields, raw/normalized traffic time, actual feature values, and input warnings. Absent values remain null. Authoritative totals are computed across the incident, independently of visible pages or the bounded LLM sample.

SQLite lives in ignored `instance/investigations.sqlite3`; a local signing secret lives in ignored `instance/session-secret`. Browser ownership uses an HttpOnly, SameSite=Lax signed cookie with a seven-day duration. The local secret survives server restarts. This is local-development session isolation, **not a production multi-user authentication system**. Protect the local `instance` directory and retain it to preserve saved investigations.

Retention is seven days and the latest three analyses per browser session. Snapshot limits are 100,000 anomalies and 64 MB each; active analysis data has a 128 MB global logical budget, with a separate 32 MB auxiliary-data budget. SQLite physical file allocation and index overhead can exceed logical payload size. AI results, chat, notes, and action history also have explicit per-record limits. Expired/evicted IDs become unavailable. Storage is transactional; failures cannot modify model outputs or disable detection.

Metadata saves require the latest integer revision and return HTTP 409 on conflict. Evidence hashes bind raw snapshots, notes, investigation status, and conclusion. Editing those makes prior AI content stale. Administrative recommendation-review changes keep advice valid while preserving optimistic locking. Registered action history retains its originating hash so old advice remains clearly identified after substantive edits.

## 5. AI configuration and provider behavior

Configuration uses **process environment variables**. `.env.example` is a reference; `.env` is ignored but is not automatically loaded. No actual key is stored in tracked code, sent to the browser, or logged.

| Variable | Meaning/default |
| --- | --- |
| `AI_API_KEY` | Required server credential for AI generation |
| `AI_MODEL` | Required compatible model ID; `gpt-4.1-mini` is a documented example |
| `AI_BASE_URL` | Optional HTTPS OpenAI-compatible API root, including `/v1`; defaults to `https://api.openai.com/v1` |
| `AI_ENABLED` | `true` by default; `false` disables external AI calls |
| `AI_TIMEOUT_SECONDS` | Total provider request/retry deadline; default 30 seconds |
| `AI_MAX_RETRIES` | Bounded retries for retryable failures; default 2; authentication failures are not retried |
| `CORRELATION_WINDOW_SECONDS` | Default 300; permitted range 1–86,400 |
| `TRAFFIC_TIMEZONE` | Optional IANA timezone for naive traffic timestamps; absent means unknown, not assumed UTC |
| `TRAFFIC_TIMESTAMP_FORMAT` | Optional explicit `datetime.strptime` format; absent accepts ISO timestamps |
| `CYVANTA_SESSION_SECRET` | Optional operator-managed signing secret instead of generated local secret |

The adapter uses the documented Chat Completions REST endpoint with strict JSON-schema output and server-side validation. An alternative `AI_BASE_URL` must implement that protocol and structured-output format; arbitrary providers are not automatically compatible. Redirects are rejected to avoid forwarding credentials to another destination. No live provider call occurs unless enabled, key, and model are configured.

Official implementation references: [Chat Completions](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create), [structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=chat), and the [GPT-4.1 mini model](https://developers.openai.com/api/docs/models/gpt-4.1-mini). Account access and other providers' compatibility still require verification.

Requests use compact selected evidence, global locally computed aggregates, bounded notes, and bounded incident-specific conversation. They never send the full uploaded CSV. The service limits context/output size, concurrent generation, per-browser request frequency, and duplicate work; cache identity includes evidence, task/focus/question, provider/model configuration, and prompt/schema version. AI is always on demand. Structured references/entities/counts and known unsafe claim forms are checked; free-form prose cannot be exhaustively verified. All AI text remains labeled interpretation requiring analyst review.

Example setup in the same PowerShell process that launches Flask:

```powershell
$aiKeyInput = Read-Host "AI API key" -AsSecureString
$env:AI_API_KEY = [System.Net.NetworkCredential]::new("", $aiKeyInput).Password
$env:AI_MODEL = "gpt-4.1-mini"
$env:AI_ENABLED = "true"
.\.venv\Scripts\python.exe app.py
```

For factual-only use, run without a key or set `$env:AI_ENABLED = "false"`. Core analysis, saved evidence, deterministic correlation, notes, local aggregate questions, and factual reports remain usable.

## 6. Verification

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
node --test tests/frontend.test.js tests/investigation.test.js
node --check static/script.js
node --check static/alerts.js
node --check static/investigation.js
node --check static/investigation-data.js
git diff --check
```

Automated tests use actual saved-model inference for uploads and isolated mocked provider responses only inside tests. Checks cover the fixed baseline model scores, no fitting during requests, privacy/ownership, same/different/missing/ambiguous timestamps, fixed-window grouping, stable event identities, persisted notes, revision conflicts, current versus stale advice, safe missing-provider behavior, factual HTML reports, malformed/unsupported AI data, prompt-injection boundaries, and request/evidence isolation. Tests and sample filenames explicitly identify synthetic fixtures.

No AI key was configured for implementation. Successful live external narrative generation cannot be claimed from mock-provider tests. Verification outcomes and browser limits are recorded in the delivery response.

## 7. Regression protection

No ML source, fitted model, feature artifact, or severity policy changes are required for this expansion. Existing response keys remain intact. SQLite snapshots are an optional additional step; storage exceptions are contained. The new AI service is not in the detection path. Existing charts retain their original configuration; new CSS is scoped to the workspace. Tables and drawers are extended through existing state and selection hooks instead of introducing a competing application.

## 8. Limitations

- AI narrative quality and live provider compatibility require a real configured key/model and external evaluation. Free-form interpretation is not a detection fact or a proof of compromise.
- Exact causal feature attribution and validated attack/MITRE classification are not available. Median comparisons do not explain model causality.
- Missing identities or usable timestamps prevent address/time correlation. The system does not reconstruct missing traffic or hidden attack stages.
- Only anomalous observations enter investigation snapshots. Core upload results and CSV export still contain all analyzed flows.
- Evidence and reports use explicit bounded selection/appendices for large incidents; global counts remain authoritative. The original full-batch analysis API can still be memory intensive.
- Reports are downloadable printable HTML. No PDF generator or PDF download is advertised.
- Analyst states and conclusions are recorded assertions, not verified infrastructure changes. This app does not execute suggested defensive actions.
- Persistence is local and retention-limited. Clearing the browser ownership cookie or deleting/losing `instance` storage can make saved records inaccessible. Public/multi-user deployment needs an appropriate authentication and operational security design.

## 9. Usage

1. Start the existing application with `.\.venv\Scripts\python.exe app.py` and open `http://127.0.0.1:5000`.
2. Upload the same supported CSV as before. Overview, charts, prioritized alerts, and results behave as before.
3. Open Investigations and expand the incident workspace, or use Open investigation from a flow drawer. Select the current or a saved analysis, then an actual anomaly group.
4. Inspect evidence and timeline entries; use correlation reasons and event references to navigate the underlying records. Chronology is labeled unavailable when timestamps do not support it.
5. Use Explain with AI for a selected flow, or request an executive/technical summary, recommendations, or timeline interpretation. These require configured external AI and send only bounded selected context.
6. Ask incident-specific questions. Supported factual aggregate questions are answered locally from the full incident; interpretive follow-ups use the configured AI. Switching incidents separates context.
7. Save notes, status, and conclusion. Review generated recommendations and record advisory follow-up states; completed means analyst-recorded, not technically verified.
8. Generate Incident Report to download the actual printable HTML file. Without AI, the report still contains real evidence, correlation policy, saved notes, and limitations.
9. Reload the page and select a retained analysis to reopen saved investigations. The newest upload remains the source for overview KPIs; selecting historical evidence does not silently replace those detection results.

## 10. Final status

All four feature groups have additive implementation paths and explicit degraded states. Deterministic evidence, correlation, metadata, and factual reports work without external AI. AI success and failure behavior are tested with isolated provider responses; live generation requires operator configuration and was not exercised without a real key. No model retraining, design replacement, fabricated events, or automatic defensive execution is part of this implementation.
