"""Escaped, standalone HTML incident reports with honest factual-only fallback."""

from datetime import datetime, timezone
from html import escape
import json
from uuid import uuid4


def _text(value):
    if value is None or value == "":
        return "Unavailable"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return escape(str(value), quote=True)


def _table(headers, rows):
    return "<div class='table-wrap'><table><thead><tr>" + "".join("<th>" + _text(item) + "</th>" for item in headers) + "</tr></thead><tbody>" + "".join("<tr>" + "".join("<td>" + _text(item) + "</td>" for item in row) + "</tr>" for row in rows) + "</tbody></table></div>"


def _list(values):
    return "<ul>" + "".join("<li>" + _text(value) + "</li>" for value in values) + "</ul>" if values else "<p class='muted'>None recorded.</p>"


def _claims(values):
    return _list([claim.get("text", "") + " [" + ", ".join(claim.get("supporting_event_ids", [])) + "]" for claim in values])


def build_incident_report(incident, ai_result=None, ai_unavailable_reason=None):
    report_id = "report-" + uuid4().hex
    generated_at = datetime.now(timezone.utc).isoformat()
    events = incident.get("events", [])
    total = incident.get("event_total", len(events))
    overview = incident.get("overview", {})
    timeline = incident.get("timeline", {})
    correlations = incident.get("correlations", {})
    analysis = incident.get("analysis", {})
    ai_content = (ai_result or {}).get("content", {})
    has_ai = bool(ai_content) and (ai_result or {}).get("evidence_hash") == incident.get("evidence_hash")
    status = "AI-assisted narrative with factual evidence" if has_ai else "Factual evidence report; AI narrative unavailable"
    summary = ai_content.get("executive_summary") if has_ai else None
    if not summary:
        summary = f"This investigation contains {total} recorded anomalous observation(s) from the saved Isolation Forest analysis. Statistical anomalies and correlation candidates do not establish a confirmed attack or its impact."
    metadata = [
        ["Application", "Cyvanta"], ["Report identifier", report_id], ["Generated at (UTC)", generated_at],
        ["Report status", status], ["Investigation", incident.get("incident_id")],
        ["Analysis", incident.get("analysis_id")], ["Evidence snapshot", incident.get("evidence_hash")],
        ["Investigation status", incident.get("status")], ["Revision", incident.get("revision")],
        ["Dataset", analysis.get("dataset_name")], ["Model", analysis.get("model_name", "Isolation Forest")],
        ["Model version", analysis.get("model_version")], ["Observed anomalies", total],
        ["First observed", overview.get("first_observed")], ["Last observed", overview.get("last_observed")],
        ["Recorded severity", overview.get("severity") or overview.get("severity_counts")],
        ["Timeline ordering", timeline.get("ordering")],
    ]
    parts = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width,initial-scale=1'>",
             "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">",
             "<title>Cyvanta incident report — " + _text(incident.get("incident_id")) + "</title>",
             """<style>
             *{box-sizing:border-box}body{margin:0;background:#f5f6f8;color:#202833;font:14px/1.6 Arial,sans-serif}
             main{max-width:1120px;margin:30px auto;padding:38px;background:white;border:1px solid #e2e5e9}
             h1{font-size:27px;margin:0 0 8px}h2{font-size:19px;border-bottom:1px solid #e2e5e9;padding-bottom:7px;margin-top:30px}
             h3{font-size:15px;margin-top:22px}p,li,td{overflow-wrap:anywhere;white-space:pre-wrap}.muted{color:#64748b}
             .eyebrow{font-size:11px;letter-spacing:2px;font-weight:bold;color:#486581}.notice{background:#f1f5f9;padding:15px;border-left:3px solid #486581}
             .table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:11px;margin:14px 0}th,td{border:1px solid #e2e5e9;text-align:left;padding:9px;vertical-align:top}
             th{background:#f1f5f9;font-weight:bold}th:first-child{min-width:110px}code{font-family:Consolas,monospace}footer{margin-top:32px;border-top:1px solid #e2e5e9;padding-top:15px;font-size:11px;color:#64748b}
             @page{size:A4 landscape;margin:14mm}@media print{body{background:white}main{margin:0;padding:0;border:0;max-width:none}.table-wrap{overflow:visible}thead{display:table-header-group}tr{break-inside:avoid}h2,h3{break-after:avoid}p,li{orphans:3;widows:3}table{font-size:9px}th,td{padding:5px}}
             </style></head><body><main>""",
             "<p class='eyebrow'>CYVANTA · INCIDENT INTELLIGENCE</p><h1>Incident Investigation Report</h1>",
             "<p class='muted'>" + _text(report_id) + " · " + _text(generated_at) + "</p>",
             "<p class='notice'>" + _text(status) + ". AI text is interpretation requiring analyst review. No defensive infrastructure actions are executed by this application.</p>",
             "<h2>Executive summary</h2><p>" + _text(summary) + "</p>",
             "<h2>Incident overview</h2>", _table(["Field", "Recorded value"], metadata),
             "<h3>Server-computed overview</h3>", _table(["Metric", "Value"], sorted(overview.items())),
             "<h2>Technical evidence</h2>",
             "<p>Included " + _text(len(events)) + " of " + _text(total) + " stored anomalous observations. " + ("Some records are omitted from this report's bounded evidence appendix; use the investigation's paginated evidence explorer for the remaining records." if len(events) < total else "No event records are omitted from this evidence appendix.") + "</p>",
             _table(["Event ID", "Source row (1-based)", "Timestamp from input", "Normalized event time", "Decision score", "Deviation", "Severity"],
                    [[event.get("event_id"), event.get("record_index", -1) + 1, event.get("timestamp"), event.get("observed_at"),
                      event.get("decision_score"), event.get("deviation_strength"), event.get("severity")]
                     for event in events]),
             "<h3>Observed feature values and validation warnings</h3>",
             _table(["Event ID", "Recorded input features", "Input validation"], [[event.get("event_id"), event.get("features"), event.get("input_warnings")] for event in events]),
             "<p class='muted'>Observed values and saved-imputer median comparisons are descriptive evidence. Exact causal feature attribution is not available for these predictions.</p>",
             "<h2>Timeline and deterministic correlations</h2>",
             "<p>Ordering: " + _text(timeline.get("ordering")) + ". Processing time is not traffic event time.</p>",
             _list(timeline.get("limitations", [])),
             "<h3>Correlation rules and reasons</h3>",
             _table(["Field", "Value"], [["Window seconds", correlations.get("window_seconds")], ["Rules", correlations.get("rules")], ["Reasons", correlations.get("reasons")]]),
             _table(["Relationship evidence"], [[relationship] for relationship in correlations.get("relationships", [])]),
             "<p class='muted'>These relationships are candidate associations, not confirmation of coordinated malicious activity. Insufficient evidence for MITRE technique mapping.</p>",
             "<h2>Analysis and interpretation</h2>"]
    if has_ai:
        parts += ["<p class='notice'>AI-generated narrative · " + _text(ai_result.get("model")) + " · " + _text(ai_result.get("generated_at")) + "</p>",
                  "<h3>Technical summary</h3><p>" + _text(ai_content.get("technical_summary")) + "</p>",
                  "<h3>Observed evidence as described by AI</h3>", _claims(ai_content.get("observations", [])),
                  "<h3>AI interpretations</h3>", _claims(ai_content.get("interpretations", [])),
                  "<h3>Unconfirmed hypotheses</h3>", _claims(ai_content.get("hypotheses", [])),
                  "<h3>Unknowns</h3>", _list(ai_content.get("unknowns", []))]
    else:
        parts += ["<p>AI-generated narrative was unavailable. The report retains recorded measurements, deterministic correlation, and saved analyst metadata.</p>",
                  "<p class='muted'>" + _text(ai_unavailable_reason or "No current AI narrative is available for this evidence snapshot.") + "</p>"]
    actions = ai_content.get("recommended_actions", []) if has_ai else []
    parts += ["<h2>Recommended defensive actions</h2>"]
    if actions:
        states = incident.get("recommendation_states", {})
        rows = []
        for action in actions:
            recorded = states.get(action["action_id"], {})
            state = recorded.get("status", "suggested") if isinstance(recorded, dict) else recorded
            state_label = "Analyst recorded as completed; not technically verified" if state == "recorded_completed" else state
            rows.append([action["action_id"], action["title"], action["category"], action["priority"], action["rationale"],
                         ", ".join(action["supporting_event_ids"]), action["prerequisites"], action["expected_benefit"],
                         action["operational_caution"], state_label, recorded.get("note") if isinstance(recorded, dict) else None])
        parts += [_table(["Action", "Title", "Category", "Triage priority", "Rationale", "Evidence", "Prerequisites", "Benefit", "Caution", "Analyst state", "Analyst note"], rows)]
    else:
        parts += ["<p>No current AI recommendations are available. No recommendations or completed actions have been fabricated.</p>"]
    registered = incident.get("registered_recommendations", [])
    if registered:
        history_rows = []
        for item in registered:
            action = item.get("action", item)
            recorded = item.get("analyst_state", {})
            state = recorded.get("status", "suggested") if isinstance(recorded, dict) else recorded
            label = "Analyst recorded as completed; not technically verified" if state == "recorded_completed" else state
            history_rows.append([action.get("action_id"), action.get("title"), action.get("category"),
                                 action.get("rationale"), action.get("supporting_event_ids"),
                                 "Current snapshot" if item.get("is_current") else "Historical advice; evidence or notes changed",
                                 item.get("evidence_hash"), label, recorded.get("note") if isinstance(recorded, dict) else None])
        parts += ["<h3>Saved recommendation review history</h3>",
                  "<p class='muted'>This history persists independently of AI availability. Recorded completion is an analyst statement, not a verified infrastructure change. Historical advice is not presented as current analysis.</p>",
                  _table(["Action ID", "Title", "Category", "Rationale", "Supporting records", "Snapshot relevance", "Originating evidence hash", "Analyst state", "Analyst note"], history_rows)]
    parts += ["<h2>Investigation information</h2>",
              _table(["Field", "Analyst-recorded value"], [["Status", incident.get("status")], ["Notes", incident.get("notes")], ["Conclusion", incident.get("conclusion")]]),
              "<h2>Limitations</h2>", _list([
                  "Isolation Forest anomaly scores measure statistical unusualness, not attack probability or confirmed security impact.",
                  "No exact model feature attribution, packet capture, hidden event sequence, confirmed attack classification, or technically verified containment is inferred.",
                  "Missing source data remains unavailable. Row ordering is not substituted for chronology.",
                  "AI free text cannot be exhaustively verified; evidence references and structured fields are validated and all interpretations require human review.",
              ] + (ai_content.get("limitations", []) if has_ai else [])),
              "<footer>Cyvanta · Evidence snapshot " + _text(incident.get("evidence_hash")) + " · Printable HTML report. Use your browser's print command to print this document.</footer></main></body></html>"]
    return "".join(parts), report_id
