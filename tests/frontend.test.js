"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { searchRows, sortAlerts, histogram, toCsv, formatNumber, finite } = require("../static/analysis-data.js");

const flows = [
    { record_index: 0, prediction: "Normal", status: "NORMAL", severity: null, priority: null, source_ip: "192.0.2.1", deviation_strength: 0, decision_score: 0.08 },
    { record_index: 1, prediction: "Anomaly", status: "ANOMALY", severity: "HIGH", priority: 1, source_ip: "192.0.2.2", deviation_strength: 0.12, decision_score: -0.16 },
    { record_index: 2, prediction: "Anomaly", status: "ANOMALY", severity: "MEDIUM", priority: 2, source_ip: "198.51.100.2", deviation_strength: 0.08, decision_score: -0.12 },
    { record_index: 3, prediction: "Anomaly", status: "ANOMALY", severity: "LOW", priority: 3, source_ip: "198.51.100.3", deviation_strength: 0.01, decision_score: -0.05 },
    { record_index: 4, prediction: "Anomaly", status: "ANOMALY", severity: null, priority: 4, source_ip: "203.0.113.4", deviation_strength: 0.2, decision_score: -0.24 }
];

test("severity filters use backend categories and do not classify normal or uncalibrated flows", () => {
    for (const [severity, index] of [["HIGH", 1], ["MEDIUM", 2], ["LOW", 3], ["UNCALIBRATED", 4]]) {
        assert.deepEqual(searchRows(flows, "", severity).map(row => row.record_index), [index]);
    }
    assert.equal(searchRows(flows, "", "ALL").length, 5);
    assert.deepEqual(searchRows(flows, "", "ALL", "Normal").map(row => row.record_index), [0]);
});

test("search and prediction/severity filters combine, and resetting restores loaded records", () => {
    assert.deepEqual(searchRows(flows, "  198.51.100  ", "MEDIUM", "Anomaly").map(row => row.record_index), [2]);
    assert.equal(searchRows(flows, "no-such-source").length, 0);
    assert.equal(searchRows(flows, "normal", "HIGH").length, 0);
    assert.equal(searchRows(flows, "", "ALL", "All").length, flows.length);
});

test("default priority preserves server ordering, independent of arrival order", () => {
    const alerts = [...flows.slice(1)].reverse();
    assert.deepEqual(sortAlerts(alerts).map(row => row.priority), [1, 2, 3, 4]);
    assert.deepEqual(alerts.map(row => row.priority), [4, 3, 2, 1], "sorting must not mutate the shared analysis");
});

test("scores sort numerically, preserve exact ties by backend priority, and put absent scores last", () => {
    const alerts = [
        { record_index: 2, priority: 3, deviation_strength: "2", decision_score: -0.1 },
        { record_index: 1, priority: 2, deviation_strength: "10", decision_score: -0.2 },
        { record_index: 0, priority: 1, deviation_strength: "10", decision_score: -0.2 },
        { record_index: 3, priority: 4, deviation_strength: null, decision_score: null }
    ];
    assert.deepEqual(sortAlerts(alerts, "deviation_strength", "desc").map(row => row.record_index), [0, 1, 2, 3]);
    assert.deepEqual(sortAlerts(alerts, "decision_score", "asc").map(row => row.record_index), [0, 1, 2, 3]);
    assert.deepEqual(sortAlerts(flows.slice(1), "severity", "desc").map(row => row.severity), ["HIGH", "MEDIUM", "LOW", null]);
});

test("ML model features sort numerically and fall back to priority", () => {
    const alerts = [
        { record_index: 0, priority: 1, "Flow Duration": 50000 },
        { record_index: 1, priority: 2, "Flow Duration": 100 },
        { record_index: 2, priority: 3, "Flow Duration": 80000 },
        { record_index: 3, priority: 4, "Flow Duration": null }
    ];
    assert.deepEqual(sortAlerts(alerts, "Flow Duration", "desc").map(row => row.record_index), [2, 0, 1, 3]);
    assert.deepEqual(sortAlerts(alerts, "Flow Duration", "asc").map(row => row.record_index), [1, 0, 2, 3]);
});

test("histograms account for every finite score including upper-bound scores and zero", () => {
    const result = histogram([0, 0.05, 0.1, 0.15, 0.2, null, undefined, NaN, Infinity, -Infinity], 4);
    assert.equal(result.min, 0);
    assert.equal(result.max, 0.2);
    assert.equal(result.bins.reduce((sum, bin) => sum + bin.count, 0), 5);
    assert.ok(result.bins.at(-1).count > 0, "the maximum must remain in the last bin");
});

test("empty and repeated-score distributions display honestly without fabricated ranges", () => {
    assert.deepEqual(histogram([]), { bins: [], min: null, max: null });
    assert.deepEqual(histogram([null, "", NaN]), { bins: [], min: null, max: null });
    assert.deepEqual(histogram([0.04, 0.04, 0.04]), { bins: [{ start: 0.04, end: 0.04, count: 3 }], min: 0.04, max: 0.04 });
});

test("large-batch histograms avoid argument-count limits and retain global totals", () => {
    const values = Array.from({ length: 250000 }, (_, index) => index / 1000000);
    const result = histogram(values);
    assert.equal(result.bins.length, 10);
    assert.equal(result.bins.reduce((sum, bin) => sum + bin.count, 0), values.length);
    assert.equal(result.max, 0.249999);
});

test("CSV export quotes delimiters, embedded quotes, and newlines with real CSV escaping", () => {
    assert.equal(toCsv([{ "Flow ID": 'flow,"A"', note: "first\nsecond", decision_score: -0.12 }]),
        '"Flow ID","note","decision_score"\r\n"flow,""A""","first\nsecond","-0.12"');
    assert.equal(toCsv([]), "");
    assert.equal(toCsv([{ a: 1 }, { b: 2 }]), '"a","b"\r\n"1",""\r\n"","2"');
});

test("CSV export neutralizes spreadsheet formulas in uploaded strings and column names", () => {
    const csv = toCsv([{ "=header": "=1+1", note: "  @SUM(A1:A2)", command: "+cmd", negative: "-cmd", score: -0.12 }]);
    assert.equal(csv,
        '"\'=header","note","command","negative","score"\r\n"\'=1+1","\'  @SUM(A1:A2)","\'+cmd","\'-cmd","-0.12"');
});

test("missing and invalid values remain unavailable instead of appearing as zero", () => {
    for (const value of [null, undefined, "", " ", false, [], {}, NaN, Infinity, "NaN"]) {
        assert.equal(finite(value), false);
        assert.equal(formatNumber(value), "—");
    }
    assert.equal(formatNumber(0), "0");
    assert.equal(formatNumber(-0.12), "-0.12");
});
