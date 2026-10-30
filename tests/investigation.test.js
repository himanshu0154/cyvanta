const test = require("node:test");
const assert = require("node:assert/strict");
const helpers = require("../static/investigation-data.js");

test("late responses cannot cross a selected incident, analysis upload, or request epoch", () => {
    const ticket = { epoch: 3, analysisId: "analysis-a", incidentId: "incident-a" };
    assert.equal(helpers.currentRequest(ticket, { ...ticket }), true);
    for (const changed of [{ epoch: 4 }, { analysisId: "analysis-b" }, { incidentId: "incident-b" }]) {
        assert.equal(helpers.currentRequest(ticket, { ...ticket, ...changed }), false);
    }
});

test("AI insights require the owning incident, current evidence hash, and requested event", () => {
    const detail = { incident_id: "a", evidence_hash: "current" };
    const response = { incident_id: "a", evidence_hash: "current", task: "explain", focus_event_id: "event-a", content: { answer: "Observation" } };
    assert.equal(helpers.validInsight(response, detail, "event-a"), true);
    assert.equal(helpers.validInsight(response, detail, "event-b"), false);
    assert.equal(helpers.validInsight({ ...response, evidence_hash: "stale" }, detail), false);
    assert.equal(helpers.validInsight({ ...response, incident_id: "b" }, detail), false);
    assert.equal(helpers.validInsight({ ...response, task: "execute" }, detail), false);
    assert.equal(helpers.validInsight({ ...response, content: null }, detail), false);
});

test("timestamp timeline uses real normalized times and breaks equal times by original row", () => {
    const rows = [
        { event_id: "later", record_index: 0, observed_at: "2026-01-02T01:00:00+00:00" },
        { event_id: "equal-b", record_index: 8, observed_at: "2026-01-02T00:00:00+00:00" },
        { event_id: "equal-a", record_index: 3, observed_at: "2026-01-02T00:00:00+00:00" },
        { event_id: "missing", record_index: 1, observed_at: null },
    ];
    const before = structuredClone(rows);
    assert.deepEqual(helpers.timelineRows(rows, "chronological").map(row => row.event_id), ["equal-a", "equal-b", "later", "missing"]);
    assert.deepEqual(rows, before);
});

test("missing-timestamp timelines retain source-row ordering without substituting processing time", () => {
    const events = [{ event_id: "b", record_index: 2, timestamp: null, observed_at: null }, { event_id: "a", record_index: 0, timestamp: null, observed_at: null }];
    const sorted = helpers.timelineRows(events, "source_row");
    assert.deepEqual(sorted.map(event => event.record_index), [0, 2]);
    assert.ok(sorted.every(event => event.timestamp === null && event.observed_at === null));
});

test("saved evidence adapts to the existing drawer without changing authoritative model values", () => {
    const event = { event_id: "actual-alert", record_index: 19, decision_score: -.12, deviation_strength: .08, severity: "MEDIUM", model_prediction: -1, timestamp: null, observed_at: null, source_ip: null, features: { "Flow Duration": 125, "Packet Length Mean": 42 } };
    const before = structuredClone(event);
    const row = helpers.evidenceRow(event);
    assert.equal(row.alert_id, event.event_id);
    assert.equal(row.anomaly_score, event.decision_score);
    assert.equal(row["Flow Duration"], 125);
    assert.equal(row.severity, "MEDIUM");
    assert.equal(row.Timestamp, null);
    assert.equal(row["Source IP"], null);
    assert.deepEqual(event, before);
});

test("report download names strip path components and reject injected or non-HTML names", () => {
    assert.equal(helpers.downloadFilename('attachment; filename="cyvanta-report.html"', "fallback.html"), "cyvanta-report.html");
    assert.equal(helpers.downloadFilename('attachment; filename="../../report.html"', "fallback.html"), "report.html");
    assert.equal(helpers.downloadFilename('attachment; filename="unsafe.exe"', "fallback.html"), "fallback.html");
    assert.equal(helpers.downloadFilename('attachment; filename="<script>.html"', "fallback.html"), "fallback.html");
    assert.equal(helpers.downloadFilename(null, "fallback.html"), "fallback.html");
});

test("large entity lists display bounded exact counts without rewriting the source aggregate", () => {
    const counts = Object.fromEntries(Array.from({ length: 1000 }, (_, i) => [`source-${i}`, i]));
    const before = structuredClone(counts), text = helpers.countSummary(counts);
    assert.match(text, /^source-999: 999/);
    assert.match(text, /990 further entities/);
    assert.ok(text.length < 500);
    assert.deepEqual(counts, before);
    assert.equal(helpers.countSummary({}), "None recorded");
});
