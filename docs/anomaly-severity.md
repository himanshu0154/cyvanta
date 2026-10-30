# Anomaly severity and alert prioritization

The existing Flask endpoint, model artifacts, saved median imputer, feature order, prediction cutoff, upload workflow, dashboard sections, and light visual theme are preserved. Threat Alerts is an additional section in the existing dashboard. No frontend framework or new production JavaScript dependency is required.

## Scoring and classification

Cyvanta already uses a custom decision-function cutoff selected in its training notebook:

```text
decision_threshold = -0.04045090522184547
Anomaly when decision_score < decision_threshold; otherwise Normal.
deviation_strength = max(0, decision_threshold - decision_score)
```

The saved scikit-learn pipeline is `SimpleImputer(strategy="median")` followed by a fitted `IsolationForest` with 200 trees. The serialized model records scikit-learn 1.7.2; requirements pin this version. Requests never fit or retrain either component. The application's custom cutoff is intentionally used rather than the forest's default zero boundary. A negative decision score above the custom cutoff remains normal.

Only anomalies receive severity:

| Deviation strength | Severity |
| --- | --- |
| Below 0.08618907798089082 | LOW |
| At least 0.08618907798089082 and below 0.10478438947187885 | MEDIUM |
| At least 0.10478438947187885 | HIGH |

These are fixed 1/3 and 2/3 quantiles of a documented reference anomaly distribution. They are an initial ordinal heuristic, not a validated operational risk score. Scores and deviation strengths are in model score units, never attack probabilities.

`ml/models/severity_policy.json` binds the thresholds to a SHA256 version covering both model files, external preprocessing version, and decision cutoff. Missing, invalid, degenerate, or incompatible policies leave anomalies **Uncalibrated** while retaining genuine scores and anomaly predictions. Normal records always have null severity.

Alerts sort by HIGH, MEDIUM, LOW, then descending deviation strength and original zero-based record index. Uncalibrated anomalies sort by deviation strength and record index. Each alert has an analysis-specific identifier, source record index, and one-based priority. Equal inputs get equal classifications in different uploads; alert identifiers intentionally identify a specific analysis.

## Calibration provenance and limits

The existing notebook `ml/01_network_traffic_analysis.ipynb` documents the final model split and cutoff. The offline reconstruction checks the exact SHA256s of the two included zipped source datasets and reproduces:

- 831,135 combined, deduplicated records.
- 305,617 benign records used for fitting.
- 166,227 records each in validation and final test partitions, using the original stratified 60/20/20 seed-42 split.
- Saved imputer medians, forest parameters, validation cutoff and F1, and notebook test confusion counts, without fitting a model.

The reference selects Wednesday records from the final test partition. It excludes model inputs also found in benign training, cutoff validation, or Friday data used during earlier feature selection. Overlap is checked after saved imputation and float32 conversion, matching forest inputs. This excludes 24,038 candidates, leaving **97,555 reference records and 39,461 anomalies** with 12,873 distinct anomaly strengths.

The source data was explored during model development, and the notebook's final test partition had already been evaluated. Using part of it for severity calibration means it is no longer a fresh severity evaluation set. This is a fixed statistical reference, not evidence of external generalization, attack impact, or operational effectiveness. Future analyst assessment and an independent external evaluation are still needed. These limitations are also stored in the policy artifact.

Reproduce calibration offline from the repository root:

```powershell
.\.venv\Scripts\python.exe -m ml.reconstruct_reference
```

This explicitly replaces only the policy JSON after all provenance and compatibility checks pass. It never trains or replaces a model. To compare without replacing the active policy:

```powershell
.\.venv\Scripts\python.exe -m ml.reconstruct_reference --output reference-check.json
```

The two archives under `ml/data` and the existing fitted model files are required. A model or preprocessing change requires a separately reviewed compatible reference and policy; the current reconstruction deliberately refuses changed inputs. Ordinary CSV uploads never derive or modify thresholds.

## API contract

`POST /api/analyze` continues to accept a multipart `file` field containing CSV. Existing `results`, `prediction`, `anomaly_score`, and summary fields remain available. The whole analysis is returned; the browser paginates rendering in pages of 50 without recalculating authoritative counts.

| New field | Meaning |
| --- | --- |
| `analysis_id`, `analyzed_at` | Unique analysis identifier and UTC processing time |
| `dataset_name`, `data_source` | Uploaded basename and CSV batch source |
| `model_version`, `model_name`, `model_status` | Bound artifact identity and inference status |
| `severity_policy` | Calibration status, explanation, cutoff, thresholds, transformation, and reference provenance |
| `alerts` | All anomalous rows in deterministic priority order |
| `input_warnings` | Record indices and fields processed by the existing fitted imputer |
| `summary.severity_counts` | Authoritative HIGH, MEDIUM, LOW counts |
| `summary.classified_anomalies`, `summary.uncalibrated_count` | Classified and unclassified anomaly totals |
| `summary.total_records`, `analyzed_records`, `excluded_records` | Record-accounting fields; successful requests do not exclude rows |
| `summary.highest_deviation_strength`, `imputed_records` | Observed anomaly strength and number of rows with imputations |

Each result and alert includes `record_index` (zero-based), `decision_score`, `deviation_strength`, `model_prediction` (-1/1 under Cyvanta's existing cutoff), `status` (ANOMALY/NORMAL), nullable `severity`, `severity_status`, nullable `alert_id`, and nullable `priority`. Original uploaded optional network fields are preserved. Missing flow timestamps remain null; `analyzed_at` describes processing time and is not substituted for traffic time.

CSV validation rejects missing/duplicate headers, missing model features, malformed or empty data, batches exceeding 750,000 records, and rows with no usable features. The existing fitted imputer handles partially missing/invalid feature cells, with explicit per-record warnings and no row shifts. Fully invalid batches fail atomically. Nonfinite optional values serialize as null. HTTP 400 covers invalid uploads, 413 the existing 300 MB upload limit, and 503 unavailable/incompatible model inference. Responses omit stack traces and server paths.

## Frontend behavior

- Existing overview totals and charts remain, with a compact synchronized severity summary.
- Threat Alerts adds metadata, keyboard-operable severity filter cards, counts and percentages of classified anomalies, an uncalibrated count, and policy details.
- Actual severity counts, anomaly deviation histogram, and top anomalous flows drive the visualizations. Their display modules can be replaced independently.
- Alerts support search, severity filters, numeric score sorting, deterministic default priority, reset, and pagination.
- Flow inspection uses a modal drawer with keyboard focus handling, network fields when available, model evidence, thresholds, validation warnings, policy explanation, and an explicit absence of feature attribution.
- The drawer can export a selected flow or open its exact record in Investigation Results. CSV export retains all analyzed records and fires once with standard quote escaping and spreadsheet-formula protection.
- Initial, loading, validation/server error, no-anomaly, empty-filter, and missing-calibration states are explicit. Previous completed results remain labeled and visible if a later upload fails.
- The existing light tokens, sidebar, cards, charts, and anchors remain. New grids stack on small screens; wide technical tables scroll within their panels. Reduced-motion settings are respected. The new severity visualizations do not require Chart.js; existing Chart.js panels degrade gracefully if its CDN is unavailable.

Analysis state remains in browser memory for the current page, consistent with the existing application. No persistence, streaming/live claims, analyst note storage, incident correlation, feature attribution, or speculative attack labels are introduced. Full results and alerts are returned in memory; very large uploads can still be constrained by browser/server memory despite paginated DOM rendering. The Flask development server remains a local development entry point.

## Files and checks

Backend: `app.py`, `ml/pipeline.py`, `ml/severity.py`, `ml/reconstruct_reference.py`, `ml/models/severity_policy.json`.

Frontend: `templates/index.html`, `static/style.css`, `static/script.js`, `static/analysis-data.js`, `static/alerts.js`.

Setup and verification: `requirements.txt`, `tests/test_severity.py`, `tests/test_analysis.py`, `tests/frontend.test.js`.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
node --test tests/frontend.test.js
```

Tests exercise actual saved-model/API inference, preservation of original scores and custom cutoff, all-normal/all-anomalous inputs, cross-batch consistency, exact severity boundaries, stable priorities, missing/mismatched/degenerate policies, row alignment and imputation warnings, strict JSON, invalid uploads, safe errors, numeric filtering/sorting, large/degenerate histograms, and CSV escaping.

The included five-row synthetic sample is a smoke-test fixture, **not** the calibration source. Actual inference yields three normal records and two anomalies, classified LOW and HIGH by the saved policy.

Verification in this workspace: 24 Python tests and 10 JavaScript tests pass, all JavaScript syntax checks pass, and `git diff --check` is clean. Browser checks covered initial desktop and 390 px mobile layouts, no page overflow, keyboard severity-card activation and reset, and no JavaScript console errors. Automated file selection was blocked by the browser extension's local-file-access setting; the complete real upload/inference response was verified through Flask's test client. Loaded-result drawer interactions and export downloads were not verified in a browser.
