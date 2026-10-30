/* Pure, replaceable investigation display helpers; detection remains server-owned. */
(function (root) {
    "use strict";
    const tasks = ["summary", "explain", "recommendations", "timeline", "chat"];
    function currentRequest(ticket, state) {
        return ticket.epoch === state.epoch && ticket.analysisId === state.analysisId
            && ticket.incidentId === state.incidentId;
    }
    function validInsight(response, detail, focusEventId) {
        return Boolean(response && detail && response.incident_id === detail.incident_id
            && response.evidence_hash === detail.evidence_hash && tasks.includes(response.task)
            && (focusEventId === undefined || response.focus_event_id === focusEventId)
            && response.content && typeof response.content === "object");
    }
    function timelineRows(events, ordering) {
        return [...events].sort((a, b) => {
            if (ordering === "chronological") {
                const x = Date.parse(a.observed_at), y = Date.parse(b.observed_at);
                const validX = Number.isFinite(x), validY = Number.isFinite(y);
                if (validX && validY && x !== y) return x - y;
                if (validX !== validY) return validX ? -1 : 1;
            }
            return Number(a.record_index) - Number(b.record_index)
                || String(a.event_id).localeCompare(String(b.event_id));
        });
    }
    function evidenceRow(event) {
        return { ...(event.features || {}), ...event,
            alert_id: event.event_id, Timestamp: event.timestamp ?? event.observed_at ?? null,
            "Source IP": event.source_ip ?? null, "Destination IP": event.destination_ip ?? null,
            "Source Port": event.source_port ?? null, "Destination Port": event.destination_port ?? null,
            Protocol: event.protocol ?? null, anomaly_score: event.decision_score,
            prediction: event.prediction || "Anomaly", status: event.status || "ANOMALY" };
    }
    function downloadFilename(header, fallback) {
        const match = /filename="?([^";\r\n]+)"?/i.exec(header || "");
        const candidate = match ? match[1].split(/[\\/]/).pop() : fallback;
        return /^[a-zA-Z0-9_.-]+\.html$/.test(candidate) ? candidate : fallback;
    }
    function humanValue(value) {
        if (value === null || value === undefined || value === "") return "Unavailable";
        if (Array.isArray(value)) return value.length ? value.map(humanValue).join(", ") : "None recorded";
        if (typeof value === "object") return Object.entries(value).map(([key, count]) => `${key}: ${count}`).join(" · ") || "None recorded";
        return String(value);
    }
    function countSummary(counts, maximum = 10) {
        const entries = Object.entries(counts || {}).sort((a, b) => Number(b[1]) - Number(a[1]) || a[0].localeCompare(b[0]));
        if (!entries.length) return "None recorded";
        return entries.slice(0, maximum).map(([key, count]) => `${key}: ${count}`).join(" · ")
            + (entries.length > maximum ? ` · ${entries.length - maximum} further entities; ask the assistant for exact counts.` : "");
    }
    const api = { currentRequest, validInsight, timelineRows, evidenceRow, downloadFilename, humanValue, countSummary };
    root.CyvantaInvestigationData = api;
    if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
