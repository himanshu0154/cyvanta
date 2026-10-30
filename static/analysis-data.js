/* Pure display helpers. Authoritative severity and priority come from Flask. */
(function (root) {
    "use strict";
    const severityRank = { HIGH: 3, MEDIUM: 2, LOW: 1 };
    const finite = value => (typeof value === "number" || (typeof value === "string" && value.trim() !== "")) && Number.isFinite(Number(value));
    const isAnomaly = row => row.prediction === "Anomaly" || row.status === "ANOMALY";
    function matchesSeverity(row, severity) {
        return severity === "ALL" || (severity === "UNCALIBRATED"
            ? isAnomaly(row) && !row.severity : row.severity === severity);
    }
    function searchRows(rows, query, severity = "ALL", prediction = "All") {
        const term = query.trim().toLowerCase();
        return rows.filter(row => matchesSeverity(row, severity)
            && (prediction === "All" || row.prediction === prediction)
            && (!term || Object.values(row).some(value => String(value ?? "").toLowerCase().includes(term))));
    }
    function sortAlerts(rows, key = "priority", direction = "asc") {
        const sign = direction === "asc" ? 1 : -1;
        return [...rows].sort((a, b) => {
            const x = key === "severity" ? (severityRank[a.severity] || 0) : a[key];
            const y = key === "severity" ? (severityRank[b.severity] || 0) : b[key];
            if (!finite(x) && finite(y)) return 1;
            if (finite(x) && !finite(y)) return -1;
            const difference = finite(x) && finite(y) ? Number(x) - Number(y) : 0;
            return difference * sign || (Number(a.priority) - Number(b.priority)) || Number(a.record_index) - Number(b.record_index);
        });
    }
    function histogram(values, count = 10) {
        const scores = values.filter(finite).map(Number);
        if (!scores.length) return { bins: [], min: null, max: null };
        let min = Infinity, max = -Infinity;
        for (const score of scores) { min = Math.min(min, score); max = Math.max(max, score); }
        if (min === max) return { bins: [{ start: min, end: max, count: scores.length }], min, max };
        const width = (max - min) / count;
        const bins = Array.from({ length: count }, (_, i) => ({ start: min + i * width, end: min + (i + 1) * width, count: 0 }));
        for (const score of scores) bins[Math.min(Math.floor((score - min) / width), count - 1)].count++;
        return { bins, min, max };
    }
    function csvCell(value) {
        let text = String(value ?? "");
        if (/^[\s]*[=+@-]/.test(text) && !finite(value)) text = "'" + text;
        return '"' + text.replace(/"/g, '""') + '"';
    }
    function toCsv(rows) {
        if (!rows.length) return "";
        const headers = [...new Set(rows.flatMap(row => Object.keys(row)))];
        return [headers.map(csvCell).join(","), ...rows.map(row => headers.map(key => csvCell(row[key])).join(","))].join("\r\n");
    }
    function formatNumber(value, decimals = 6) {
        return finite(value) ? Number(value).toLocaleString("en-US", { maximumFractionDigits: decimals }) : "—";
    }
    const api = { finite, isAnomaly, matchesSeverity, searchRows, sortAlerts, histogram, toCsv, formatNumber };
    root.CyvantaData = api;
    if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
