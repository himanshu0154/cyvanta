# Cyvanta

Network-flow anomaly detection using the existing saved Isolation Forest pipeline.

Run locally from the repository root (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000 and upload a network CSV. The eight required model columns are listed in [ml/README.md](ml/README.md). The fitted model and its original anomaly cutoff are retained.

Threat Alerts displays calibrated **Anomaly Severity**, prioritized anomalies, filters, pagination, and flow inspection. Overview and Investigation Results use the same completed analysis. Severity measures statistical deviation, not confirmed attack impact or probability.

See [the severity feature documentation](docs/anomaly-severity.md) for calibration provenance, API additions, limitations, and verification.

The incident workspace adds saved evidence, deterministic correlation and timelines, notes/status, optional server-side AI explanations and recommendations, contextual questions, and downloadable HTML reports. It extends the existing investigation table and flow drawer. See [the incident intelligence handoff](docs/incident-intelligence.md) for all four feature groups, API contracts, environment configuration, persistence, and verification limits. No AI key is required for normal detection or factual reports; AI narrative generation requires server-side configuration.

Run checks:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
node --test tests/frontend.test.js tests/investigation.test.js
```
